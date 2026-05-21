//! Issue #1 phase 2: trusted runtime registry integration coverage.
//!
//! The production registry intentionally starts empty until official runtime
//! hashes are curated. This test supplies a YAML registry in-process so it can
//! verify the T1 promotion contract without adding synthetic trust entries to
//! production data.

use sentinel_hook::macho_scan::{BinaryTier, classify_path_with_registry};
use sentinel_hook::trusted_runtime::TrustedRuntimeRegistry;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;

const MH_MAGIC_64: u32 = 0xfeedfacf;
const LC_SEGMENT_64: u32 = 0x19;

#[cfg(target_arch = "aarch64")]
const NATIVE_CPU_TYPE: u32 = 0x0100_000c;
#[cfg(target_arch = "x86_64")]
const NATIVE_CPU_TYPE: u32 = 0x0100_0007;

#[test]
fn trusted_runtime_hash_promotes_syscall_binary_to_t1() {
    let data = thin_macho_with_syscall_bytes();
    let hash = Sha256::digest(&data);
    let registry_yaml = format!(
        "runtimes:\n  - sha256: \"{}\"\n    name: sentinel-e2e-runtime\n    version: \"0.0.0\"\n    source: e2e\n",
        hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let registry = TrustedRuntimeRegistry::parse(&registry_yaml);
    let file = write_temp(&data);
    let path = CString::new(file.path().as_os_str().as_bytes()).expect("path cstring");

    assert_eq!(
        classify_path_with_registry(path.as_ptr(), &registry),
        BinaryTier::T1TrustedRuntime
    );
}

fn thin_macho_with_syscall_bytes() -> Vec<u8> {
    let payload: &[u8] = if cfg!(target_arch = "aarch64") {
        &[0xaa, 0x01, 0x10, 0x00, 0xd4]
    } else {
        &[0xaa, 0x0f, 0x05]
    };
    let fileoff = 0x100u64;
    let filesize = payload.len() as u64;
    let mut data = vec![0u8; fileoff as usize + payload.len()];
    data[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
    data[4..8].copy_from_slice(&NATIVE_CPU_TYPE.to_le_bytes());
    data[16..20].copy_from_slice(&1u32.to_le_bytes());
    data[20..24].copy_from_slice(&72u32.to_le_bytes());

    let pos = 32usize;
    data[pos..pos + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    data[pos + 4..pos + 8].copy_from_slice(&72u32.to_le_bytes());
    data[pos + 8..pos + 14].copy_from_slice(b"__TEXT");
    data[pos + 40..pos + 48].copy_from_slice(&fileoff.to_le_bytes());
    data[pos + 48..pos + 56].copy_from_slice(&filesize.to_le_bytes());
    data[fileoff as usize..].copy_from_slice(payload);
    data
}

fn write_temp(contents: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(contents).expect("write temp file");
    file
}

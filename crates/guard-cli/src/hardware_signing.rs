//! OS-backed rule signing for production persistent user rules.
//!
//! macOS production support uses an OS Keychain-backed P-256 signing key in the
//! invoking user's keychain. The system installer enrolls/locates that key and
//! registers the public half with the daemon's trusted signer registry. Later
//! rule approvals sign the canonical rule payload through Security.framework;
//! the daemon can verify but cannot forge those signatures.

use guard_core::{
    ManagementActionPayloadV1, RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256, RuleSignaturePayloadV1,
    RuleSignatureV1, SIGNER_KIND_MACOS_KEYCHAIN, SnapshotSignaturePayloadV1, SnapshotSignatureV1,
    canonical_management_action_payload_bytes, canonical_rule_payload_bytes,
    canonical_snapshot_payload_bytes, sha256_hex,
};

use crate::CliError;

const KEY_TAG: &str = "com.stentorian-guard.rule-signing.v1";
#[cfg(target_os = "macos")]
const KEY_LABEL: &str = "Stentorian Guard Rule Signing Key";
const DISABLE_HARDWARE_SIGNER_ENV: &str = "STT_GUARD_DISABLE_HARDWARE_SIGNER";

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct HardwareSignerEnrollment {
    pub signer_kind: String,
    pub public_key_x963: Vec<u8>,
    pub public_key_sha256: String,
    pub label: String,
    pub created: bool,
}

/// Enroll or locate the init user's macOS Keychain signing key.
///
/// # Errors
///
/// Returns an error when OS-backed signing is disabled or Security.framework
/// cannot enroll/export the device-local key.
pub fn enroll_keychain_signer_for_init() -> Result<HardwareSignerEnrollment, CliError> {
    #[cfg(feature = "test-signer")]
    {
        return enroll_test_simulator_for_init();
    }

    #[cfg(not(feature = "test-signer"))]
    {
        enroll_keychain_signer_for_init_impl()
    }
}

#[cfg(not(feature = "test-signer"))]
fn enroll_keychain_signer_for_init_impl() -> Result<HardwareSignerEnrollment, CliError> {
    if hardware_signer_disabled() {
        return Err(unavailable_error());
    }

    let enrollment = macos_keychain::enroll_key_for_init(KEY_TAG)?;
    let public_key_x963 = enrollment.public_key_x963;
    let created = enrollment.created;
    let public_key_sha256 = sha256_hex(&public_key_x963);

    Ok(HardwareSignerEnrollment {
        signer_kind: SIGNER_KIND_MACOS_KEYCHAIN.to_string(),
        public_key_x963,
        public_key_sha256,
        label: init_user_label(),
        created,
    })
}

#[cfg(feature = "test-signer")]
fn enroll_test_simulator_for_init() -> Result<HardwareSignerEnrollment, CliError> {
    let (public_key_sha256, signer_kind, public_key_x963) =
        guard_core::rule_signature::test_support::test_simulator_public_signer()
            .map_err(|e| CliError::Other(format!("test signer enrollment failed: {e}")))?;

    Ok(HardwareSignerEnrollment {
        signer_kind,
        public_key_x963,
        public_key_sha256,
        label: "macOS test-signer simulator".to_string(),
        created: false,
    })
}

/// Delete the init user's macOS Keychain signing key created by this install.
///
/// # Errors
///
/// Returns an error when the platform helper cannot remove the key.
pub fn delete_keychain_signer_for_init() -> Result<(), CliError> {
    #[cfg(feature = "test-signer")]
    {
        return Ok(());
    }

    #[cfg(not(feature = "test-signer"))]
    {
        macos_keychain::delete_key_for_init(KEY_TAG)
    }
}

/// Sign a persistent rule payload with the OS-backed key.
///
/// # Errors
///
/// Returns an error when OS-backed signing is disabled, payload canonicalization
/// fails, or Security.framework cannot sign with the device-local key.
pub fn sign_rule_payload(payload: &RuleSignaturePayloadV1) -> Result<RuleSignatureV1, CliError> {
    if hardware_signer_disabled() {
        return Err(unavailable_error());
    }
    let payload_bytes = canonical_rule_payload_bytes(payload)
        .map_err(|e| CliError::Other(format!("canonical rule payload encode failed: {e}")))?;
    let signed_payload = macos_keychain::sign_payload_with_prompt(KEY_TAG, &payload_bytes)?;

    Ok(RuleSignatureV1 {
        scheme: RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256.to_string(),
        signer_kind: SIGNER_KIND_MACOS_KEYCHAIN.to_string(),
        public_key_sha256: sha256_hex(&signed_payload.public_key_x963),
        public_key_x963: signed_payload.public_key_x963,
        signature_der: signed_payload.signature_der,
        signed_payload_sha256: sha256_hex(&payload_bytes),
        signature_created_at_unix_ms: payload.created_at_unix_ms,
    })
}

/// Sign a snapshot payload with the OS-backed key.
///
/// # Errors
///
/// Returns an error when OS-backed signing is disabled, payload canonicalization
/// fails, or Security.framework cannot sign with the device-local key.
pub fn sign_snapshot_payload(
    payload: &SnapshotSignaturePayloadV1,
) -> Result<SnapshotSignatureV1, CliError> {
    if hardware_signer_disabled() {
        return Err(unavailable_error());
    }
    let payload_bytes = canonical_snapshot_payload_bytes(payload)
        .map_err(|e| CliError::Other(format!("canonical snapshot payload encode failed: {e}")))?;
    let signed_payload =
        macos_keychain::sign_payload_without_prompt(KEY_TAG, &payload_bytes).map_err(|e| {
            CliError::Other(format!(
                "snapshot signing requires repaired macOS Keychain access; run `sudo stt-guard install-system -y`: {e}"
            ))
        })?;

    Ok(SnapshotSignatureV1 {
        scheme: RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256.to_string(),
        signer_kind: SIGNER_KIND_MACOS_KEYCHAIN.to_string(),
        public_key_sha256: sha256_hex(&signed_payload.public_key_x963),
        public_key_x963: signed_payload.public_key_x963,
        signature_der: signed_payload.signature_der,
        signed_payload_sha256: sha256_hex(&payload_bytes),
        signature_created_at_unix_ms: payload.generated_at_unix_ms,
    })
}

/// Sign a management action payload with the OS-backed key.
///
/// # Errors
///
/// Returns an error when OS-backed signing is disabled, payload canonicalization
/// fails, or Security.framework cannot sign with the device-local key.
pub fn sign_management_action_payload(
    payload: &ManagementActionPayloadV1,
) -> Result<RuleSignatureV1, CliError> {
    if hardware_signer_disabled() {
        return Err(unavailable_error());
    }
    let payload_bytes = canonical_management_action_payload_bytes(payload).map_err(|e| {
        CliError::Other(format!(
            "canonical management-action payload encode failed: {e}"
        ))
    })?;
    let signed_payload = macos_keychain::sign_payload_with_prompt(KEY_TAG, &payload_bytes)?;

    Ok(RuleSignatureV1 {
        scheme: RULE_SIGNATURE_SCHEME_ECDSA_P256_SHA256.to_string(),
        signer_kind: SIGNER_KIND_MACOS_KEYCHAIN.to_string(),
        public_key_sha256: sha256_hex(&signed_payload.public_key_x963),
        public_key_x963: signed_payload.public_key_x963,
        signature_der: signed_payload.signature_der,
        signed_payload_sha256: sha256_hex(&payload_bytes),
        signature_created_at_unix_ms: payload.created_at_unix_ms,
    })
}

fn hardware_signer_disabled() -> bool {
    std::env::var_os(DISABLE_HARDWARE_SIGNER_ENV).is_some()
}

fn unavailable_error() -> CliError {
    CliError::Other(
        "OS-backed signing key unavailable; software-only rule signing is unsupported".into(),
    )
}

#[cfg(not(feature = "test-signer"))]
fn init_user_label() -> String {
    if unsafe { libc::geteuid() } == 0 {
        if let Ok(user) = std::env::var("SUDO_USER") {
            if user != "root" {
                return format!("macOS Keychain ({user})");
            }
        }
    }
    "macOS Keychain".to_string()
}

#[cfg(test)]
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg_attr(feature = "test-signer", allow(dead_code))]
pub(crate) mod macos_keychain {
    use crate::CliError;

    #[cfg(target_os = "macos")]
    pub(super) const INTERACTIVE_SIGNING_PROMPT: &str =
        "sign this Stentorian Guard rule with your Keychain key";

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct KeychainEnrollment {
        pub(crate) public_key_x963: Vec<u8>,
        pub(crate) created: bool,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct KeychainSignature {
        pub(crate) public_key_x963: Vec<u8>,
        pub(crate) signature_der: Vec<u8>,
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum KeychainFailureKind {
        AuthenticationDenied,
        InteractionUnavailable,
        MissingEntitlementOrSession,
        SecurityFrameworkUnavailable,
        Other,
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn classify_os_status(status: i32) -> KeychainFailureKind {
        match status {
            -25_293 | -128 => KeychainFailureKind::AuthenticationDenied,
            -25_308 => KeychainFailureKind::InteractionUnavailable,
            -34_018 => KeychainFailureKind::MissingEntitlementOrSession,
            -25_291 => KeychainFailureKind::SecurityFrameworkUnavailable,
            _ => KeychainFailureKind::Other,
        }
    }

    #[cfg(target_os = "macos")]
    mod macos {
        use std::ffi::{CStr, c_char, c_long, c_void};
        use std::marker::PhantomData;
        use std::ptr;

        use super::{
            INTERACTIVE_SIGNING_PROMPT, KeychainEnrollment, KeychainFailureKind, KeychainSignature,
            classify_os_status,
        };
        use crate::CliError;

        const ERR_SEC_SUCCESS: i32 = 0;
        const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;
        const K_CF_NUMBER_INT_TYPE: i32 = 9;
        const K_SEC_KEY_OPERATION_TYPE_SIGN: u32 = 0;
        type CFIndex = c_long;
        type CFAllocatorRef = *const c_void;
        type CFArrayRef = *const c_void;
        type CFDataRef = *const c_void;
        type CFDictionaryRef = *const c_void;
        type CFErrorRef = *const c_void;
        type CFMutableDictionaryRef = *mut c_void;
        type CFNumberRef = *const c_void;
        type CFStringRef = *const c_void;
        type CFTypeRef = *const c_void;
        type OSStatus = i32;
        type SecAccessRef = *const c_void;
        type SecKeyAlgorithm = CFStringRef;
        type SecKeyRef = *const c_void;

        #[repr(C)]
        struct CFDictionaryKeyCallBacks {
            version: CFIndex,
            retain: *const c_void,
            release: *const c_void,
            copy_description: *const c_void,
            equal: *const c_void,
            hash: *const c_void,
        }

        #[repr(C)]
        struct CFDictionaryValueCallBacks {
            version: CFIndex,
            retain: *const c_void,
            release: *const c_void,
            copy_description: *const c_void,
            equal: *const c_void,
        }

        #[link(name = "CoreFoundation", kind = "framework")]
        unsafe extern "C" {
            static kCFBooleanTrue: CFTypeRef;
            static kCFBooleanFalse: CFTypeRef;
            static kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
            static kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;

            fn CFDataCreate(
                allocator: CFAllocatorRef,
                bytes: *const u8,
                length: CFIndex,
            ) -> CFDataRef;
            fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
            fn CFDataGetLength(data: CFDataRef) -> CFIndex;
            fn CFDictionarySetValue(
                dictionary: CFMutableDictionaryRef,
                key: *const c_void,
                value: *const c_void,
            );
            fn CFDictionaryCreateMutable(
                allocator: CFAllocatorRef,
                capacity: CFIndex,
                key_callbacks: *const CFDictionaryKeyCallBacks,
                value_callbacks: *const CFDictionaryValueCallBacks,
            ) -> CFMutableDictionaryRef;
            fn CFErrorGetCode(error: CFErrorRef) -> CFIndex;
            fn CFNumberCreate(
                allocator: CFAllocatorRef,
                number_type: i32,
                value_ptr: *const c_void,
            ) -> CFNumberRef;
            fn CFRelease(object: CFTypeRef);
            fn CFCopyDescription(object: CFTypeRef) -> CFStringRef;
            fn CFStringGetCString(
                string: CFStringRef,
                buffer: *mut c_char,
                buffer_size: CFIndex,
                encoding: u32,
            ) -> bool;
        }

        #[link(name = "Security", kind = "framework")]
        unsafe extern "C" {
            static kSecAttrApplicationTag: CFStringRef;
            static kSecAttrIsPermanent: CFStringRef;
            static kSecAttrIsExtractable: CFStringRef;
            static kSecAttrKeySizeInBits: CFStringRef;
            static kSecAttrKeyType: CFStringRef;
            static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
            static kSecAttrAccess: CFStringRef;
            static kSecAttrLabel: CFStringRef;
            static kSecClass: CFStringRef;
            static kSecClassKey: CFStringRef;
            static kSecPrivateKeyAttrs: CFStringRef;
            static kSecReturnRef: CFStringRef;
            static kSecUseAuthenticationUI: CFStringRef;
            static kSecUseAuthenticationUIFail: CFStringRef;
            static kSecUseOperationPrompt: CFStringRef;
            static kSecKeyAlgorithmECDSASignatureMessageX962SHA256: SecKeyAlgorithm;

            fn SecAccessCreate(
                descriptor: CFStringRef,
                trustedlist: CFArrayRef,
                access_ref: *mut SecAccessRef,
            ) -> OSStatus;
            fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
            fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;
            fn SecKeyCopyExternalRepresentation(
                key: SecKeyRef,
                error: *mut CFErrorRef,
            ) -> CFDataRef;
            fn SecKeyCopyPublicKey(key: SecKeyRef) -> SecKeyRef;
            fn SecKeyCreateRandomKey(
                parameters: CFDictionaryRef,
                error: *mut CFErrorRef,
            ) -> SecKeyRef;
            fn SecKeyCreateSignature(
                key: SecKeyRef,
                algorithm: SecKeyAlgorithm,
                data_to_sign: CFDataRef,
                error: *mut CFErrorRef,
            ) -> CFDataRef;
            fn SecKeyIsAlgorithmSupported(
                key: SecKeyRef,
                operation: u32,
                algorithm: SecKeyAlgorithm,
            ) -> bool;
        }

        pub(super) fn enroll_key_for_init(key_tag: &str) -> Result<KeychainEnrollment, CliError> {
            let identity_guard = InitUserIdentityGuard::enter()?;

            let old_key_existed = delete_key(key_tag)?;
            let key = create_private_key(key_tag)?;
            let enrollment = KeychainEnrollment {
                public_key_x963: export_public_key_x963(key.as_ptr())?,
                created: !old_key_existed,
            };

            identity_guard.restore()?;

            Ok(enrollment)
        }

        pub(super) fn delete_key_for_init(key_tag: &str) -> Result<(), CliError> {
            let identity_guard = InitUserIdentityGuard::enter()?;
            delete_key(key_tag)?;
            identity_guard.restore()?;

            Ok(())
        }

        fn delete_key(key_tag: &str) -> Result<bool, CliError> {
            let query = key_item_query(key_tag)?;
            let status = unsafe { SecItemDelete(query.as_ptr()) };

            match status {
                ERR_SEC_SUCCESS => Ok(true),
                ERR_SEC_ITEM_NOT_FOUND => Ok(false),
                other => Err(security_status_error(
                    "delete macOS Keychain signing key",
                    other,
                )),
            }
        }

        pub(super) fn sign_payload_with_prompt(
            key_tag: &str,
            payload: &[u8],
        ) -> Result<KeychainSignature, CliError> {
            sign_payload(key_tag, payload, SigningInteraction::WithPrompt)
        }

        pub(super) fn sign_payload_without_prompt(
            key_tag: &str,
            payload: &[u8],
        ) -> Result<KeychainSignature, CliError> {
            sign_payload(key_tag, payload, SigningInteraction::WithoutPrompt)
        }

        fn sign_payload(
            key_tag: &str,
            payload: &[u8],
            signing_interaction: SigningInteraction,
        ) -> Result<KeychainSignature, CliError> {
            let key = find_private_key(key_tag, signing_interaction)?.ok_or_else(|| {
                CliError::Other(
                    "OS-backed signing key unavailable; run the installer to enroll macOS Keychain signing"
                        .into(),
                )
            })?;

            let algorithm = unsafe { kSecKeyAlgorithmECDSASignatureMessageX962SHA256 };
            let supports_signing = unsafe {
                SecKeyIsAlgorithmSupported(key.as_ptr(), K_SEC_KEY_OPERATION_TYPE_SIGN, algorithm)
            };
            if !supports_signing {
                return Err(CliError::Other(
                    "macOS Keychain key does not support ECDSA P-256 SHA-256 signing".into(),
                ));
            }

            let data_to_sign = cf_data(payload)?;
            let mut error = ptr::null();
            let signature = unsafe {
                SecKeyCreateSignature(
                    key.as_ptr(),
                    algorithm,
                    data_to_sign.as_ptr(),
                    &raw mut error,
                )
            };
            if signature.is_null() {
                return Err(cf_error_or_message("macOS Keychain signing", error));
            }
            let signature = OwnedCf::<CFDataRef>::new(signature, signature);

            Ok(KeychainSignature {
                public_key_x963: export_public_key_x963(key.as_ptr())?,
                signature_der: cf_data_bytes(signature.as_ptr())?,
            })
        }

        fn find_private_key(
            key_tag: &str,
            signing_interaction: SigningInteraction,
        ) -> Result<Option<OwnedCf<SecKeyRef>>, CliError> {
            let query = key_lookup_query(key_tag, true, signing_interaction)?;
            let mut item = ptr::null();
            let status = unsafe { SecItemCopyMatching(query.as_ptr(), &raw mut item) };

            match status {
                ERR_SEC_SUCCESS => Ok(Some(OwnedCf::<SecKeyRef>::new(item, item))),
                ERR_SEC_ITEM_NOT_FOUND => Ok(None),
                other => Err(security_status_error(
                    "look up macOS Keychain signing key",
                    other,
                )),
            }
        }

        fn create_private_key(key_tag: &str) -> Result<OwnedCf<SecKeyRef>, CliError> {
            let key_size_bits: i32 = 256;
            let key_size = cf_number_int(key_size_bits)?;
            let tag = cf_data(key_tag.as_bytes())?;

            let private_attrs = cf_dictionary()?;
            cf_dictionary_set(
                private_attrs.as_ptr(),
                unsafe { kSecAttrIsPermanent },
                unsafe { kCFBooleanTrue },
            );
            cf_dictionary_set(
                private_attrs.as_ptr(),
                unsafe { kSecAttrIsExtractable },
                unsafe { kCFBooleanFalse },
            );
            cf_dictionary_set(
                private_attrs.as_ptr(),
                unsafe { kSecAttrApplicationTag },
                tag.as_ptr(),
            );
            let label = cf_string(super::super::KEY_LABEL)?;
            cf_dictionary_set(
                private_attrs.as_ptr(),
                unsafe { kSecAttrLabel },
                label.as_ptr(),
            );
            let access = create_key_access()?;
            cf_dictionary_set(
                private_attrs.as_ptr(),
                unsafe { kSecAttrAccess },
                access.as_ptr(),
            );

            let attrs = cf_dictionary()?;
            cf_dictionary_set(attrs.as_ptr(), unsafe { kSecAttrKeyType }, unsafe {
                kSecAttrKeyTypeECSECPrimeRandom
            });
            cf_dictionary_set(
                attrs.as_ptr(),
                unsafe { kSecAttrKeySizeInBits },
                key_size.as_ptr(),
            );
            cf_dictionary_set(
                attrs.as_ptr(),
                unsafe { kSecPrivateKeyAttrs },
                private_attrs.as_ptr(),
            );

            let mut error = ptr::null();
            let key = unsafe { SecKeyCreateRandomKey(attrs.as_ptr(), &raw mut error) };
            if key.is_null() {
                return Err(cf_error_or_message(
                    "create macOS Keychain signing key",
                    error,
                ));
            }

            Ok(OwnedCf::<SecKeyRef>::new(key, key))
        }

        fn key_item_query(key_tag: &str) -> Result<OwnedCf<CFMutableDictionaryRef>, CliError> {
            let tag = cf_data(key_tag.as_bytes())?;
            let query = cf_dictionary()?;

            cf_dictionary_set(query.as_ptr(), unsafe { kSecClass }, unsafe {
                kSecClassKey
            });
            cf_dictionary_set(
                query.as_ptr(),
                unsafe { kSecAttrApplicationTag },
                tag.as_ptr(),
            );
            cf_dictionary_set(query.as_ptr(), unsafe { kSecAttrKeyType }, unsafe {
                kSecAttrKeyTypeECSECPrimeRandom
            });

            Ok(query)
        }

        fn key_lookup_query(
            key_tag: &str,
            return_ref: bool,
            signing_interaction: SigningInteraction,
        ) -> Result<OwnedCf<CFMutableDictionaryRef>, CliError> {
            let query = key_item_query(key_tag)?;

            if signing_interaction == SigningInteraction::WithPrompt {
                let prompt = cf_string(INTERACTIVE_SIGNING_PROMPT)?;

                cf_dictionary_set(
                    query.as_ptr(),
                    unsafe { kSecUseOperationPrompt },
                    prompt.as_ptr(),
                );
            } else {
                cf_dictionary_set(query.as_ptr(), unsafe { kSecUseAuthenticationUI }, unsafe {
                    kSecUseAuthenticationUIFail
                });
            }

            if return_ref {
                cf_dictionary_set(query.as_ptr(), unsafe { kSecReturnRef }, unsafe {
                    kCFBooleanTrue
                });
            }

            Ok(query)
        }

        fn create_key_access() -> Result<OwnedCf<SecAccessRef>, CliError> {
            let descriptor = cf_string(super::super::KEY_LABEL)?;
            let mut access = ptr::null();
            let status =
                unsafe { SecAccessCreate(descriptor.as_ptr(), ptr::null(), &raw mut access) };
            if status != ERR_SEC_SUCCESS {
                return Err(security_status_error(
                    "create macOS Keychain signing key access policy",
                    status,
                ));
            }

            Ok(OwnedCf::<SecAccessRef>::new(access, access))
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum SigningInteraction {
            WithPrompt,
            WithoutPrompt,
        }

        fn export_public_key_x963(private_key: SecKeyRef) -> Result<Vec<u8>, CliError> {
            let public_key = unsafe { SecKeyCopyPublicKey(private_key) };
            if public_key.is_null() {
                return Err(CliError::Other(
                    "macOS Keychain key has no public key".into(),
                ));
            }
            let public_key = OwnedCf::<SecKeyRef>::new(public_key, public_key);

            let mut error = ptr::null();
            let data =
                unsafe { SecKeyCopyExternalRepresentation(public_key.as_ptr(), &raw mut error) };
            if data.is_null() {
                return Err(cf_error_or_message(
                    "export macOS Keychain public key",
                    error,
                ));
            }
            let data = OwnedCf::<CFDataRef>::new(data, data);

            cf_data_bytes(data.as_ptr())
        }

        fn cf_dictionary() -> Result<OwnedCf<CFMutableDictionaryRef>, CliError> {
            let dictionary = unsafe {
                CFDictionaryCreateMutable(
                    ptr::null(),
                    0,
                    &raw const kCFTypeDictionaryKeyCallBacks,
                    &raw const kCFTypeDictionaryValueCallBacks,
                )
            };
            if dictionary.is_null() {
                return Err(CliError::Other(
                    "create Core Foundation dictionary failed".into(),
                ));
            }

            Ok(OwnedCf::<CFMutableDictionaryRef>::new(
                dictionary,
                dictionary.cast_const(),
            ))
        }

        fn cf_dictionary_set(dictionary: CFMutableDictionaryRef, key: CFTypeRef, value: CFTypeRef) {
            // The dictionary is created with Core Foundation retain callbacks,
            // so borrowed key/value references remain valid after wrappers drop.
            unsafe { CFDictionarySetValue(dictionary, key, value) };
        }

        fn cf_data(bytes: &[u8]) -> Result<OwnedCf<CFDataRef>, CliError> {
            let byte_count = CFIndex::try_from(bytes.len()).map_err(|e| {
                CliError::Other(format!("Core Foundation data length is too large: {e}"))
            })?;
            let data = unsafe { CFDataCreate(ptr::null(), bytes.as_ptr(), byte_count) };
            if data.is_null() {
                return Err(CliError::Other("create Core Foundation data failed".into()));
            }

            Ok(OwnedCf::<CFDataRef>::new(data, data))
        }

        fn cf_data_bytes(data: CFDataRef) -> Result<Vec<u8>, CliError> {
            let len = unsafe { CFDataGetLength(data) };
            let len = usize::try_from(len).map_err(|e| {
                CliError::Other(format!("Core Foundation data length is invalid: {e}"))
            })?;
            let bytes = unsafe { CFDataGetBytePtr(data) };

            // CFData owns this buffer; copy it before the owning wrapper drops.
            Ok(unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec())
        }

        fn cf_number_int(value: i32) -> Result<OwnedCf<CFNumberRef>, CliError> {
            let number = unsafe {
                CFNumberCreate(
                    ptr::null(),
                    K_CF_NUMBER_INT_TYPE,
                    (&raw const value).cast::<c_void>(),
                )
            };
            if number.is_null() {
                return Err(CliError::Other(
                    "create Core Foundation number failed".into(),
                ));
            }

            Ok(OwnedCf::<CFNumberRef>::new(number, number))
        }

        fn cf_string(value: &str) -> Result<OwnedCf<CFStringRef>, CliError> {
            let data = cf_data(value.as_bytes())?;
            let string = unsafe {
                CFStringCreateFromExternalRepresentation(
                    ptr::null(),
                    data.as_ptr(),
                    K_CF_STRING_ENCODING_UTF8,
                )
            };
            if string.is_null() {
                return Err(CliError::Other(
                    "create Core Foundation string failed".into(),
                ));
            }

            Ok(OwnedCf::<CFStringRef>::new(string, string))
        }

        const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

        #[link(name = "CoreFoundation", kind = "framework")]
        unsafe extern "C" {
            fn CFStringCreateFromExternalRepresentation(
                allocator: CFAllocatorRef,
                data: CFDataRef,
                encoding: u32,
            ) -> CFStringRef;
        }

        fn cf_error_or_message(action: &str, error: CFErrorRef) -> CliError {
            let message = if error.is_null() {
                format!("{action} failed")
            } else if let Some(description) = actionable_cf_error_description(error) {
                format!("{action} failed: {description}; {}", cf_description(error))
            } else {
                format!("{action} failed: {}", cf_description(error))
            };

            CliError::Other(message)
        }

        fn actionable_cf_error_description(error: CFErrorRef) -> Option<String> {
            let code = unsafe { CFErrorGetCode(error) };
            let code = i32::try_from(code).ok()?;

            if classify_os_status(code) == KeychainFailureKind::Other {
                return None;
            }

            Some(describe_os_status(code))
        }

        fn security_status_error(action: &str, status: OSStatus) -> CliError {
            CliError::Other(format!("{action} failed: {}", describe_os_status(status)))
        }

        fn describe_os_status(status: OSStatus) -> String {
            match classify_os_status(status) {
                KeychainFailureKind::AuthenticationDenied => {
                    format!("user authentication was cancelled or denied (OSStatus {status})")
                }
                KeychainFailureKind::InteractionUnavailable => {
                    format!(
                        "keychain interaction is not available in this session (OSStatus {status})"
                    )
                }
                KeychainFailureKind::MissingEntitlementOrSession => {
                    format!(
                        "keychain access is missing a required entitlement or session binding (OSStatus {status})"
                    )
                }
                KeychainFailureKind::SecurityFrameworkUnavailable => {
                    format!(
                        "Security.framework or the keychain is unavailable in this session (OSStatus {status})"
                    )
                }
                KeychainFailureKind::Other => {
                    format!("Security.framework returned OSStatus {status}")
                }
            }
        }

        fn cf_description(value: CFTypeRef) -> String {
            let description = unsafe { CFCopyDescription(value) };
            if description.is_null() {
                return "Core Foundation did not provide error details".to_string();
            }
            let description = OwnedCf::<CFStringRef>::new(description, description);
            let mut buffer = vec![0; 2048];
            let copied = unsafe {
                CFStringGetCString(
                    description.as_ptr(),
                    buffer.as_mut_ptr(),
                    2048,
                    K_CF_STRING_ENCODING_UTF8,
                )
            };
            if !copied {
                return "Core Foundation error details were not UTF-8".to_string();
            }

            unsafe { CStr::from_ptr(buffer.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        }

        struct OwnedCf<T: Copy> {
            object: T,
            cf_object: CFTypeRef,
            _marker: PhantomData<T>,
        }

        impl<T> OwnedCf<T>
        where
            T: Copy,
        {
            fn new(object: T, cf_object: CFTypeRef) -> Self {
                Self {
                    object,
                    cf_object,
                    _marker: PhantomData,
                }
            }

            fn as_ptr(&self) -> T {
                self.object
            }
        }

        impl<T> Drop for OwnedCf<T>
        where
            T: Copy,
        {
            fn drop(&mut self) {
                // `OwnedCf` only wraps Core Foundation create/copy results with
                // +1 ownership; constants and borrowed references are not wrapped.
                unsafe { CFRelease(self.cf_object) };
            }
        }

        struct InitUserIdentityGuard {
            restore_uid: Option<u32>,
            restore_gid: Option<u32>,
        }

        impl InitUserIdentityGuard {
            fn enter() -> Result<Self, CliError> {
                if unsafe { libc::geteuid() } != 0 {
                    return Ok(Self {
                        restore_uid: None,
                        restore_gid: None,
                    });
                }

                let target_user_id = sudo_id("SUDO_UID")?;
                let target_group_id = sudo_id("SUDO_GID")?;
                if target_user_id == 0 {
                    return Err(CliError::Other(
                        "Keychain enrollment requires running the system install via sudo from the target user; refusing to enroll a root-owned signing key"
                            .into(),
                    ));
                }

                let installer_user_id = unsafe { libc::geteuid() };
                let installer_group_id = unsafe { libc::getegid() };

                set_effective_gid(
                    target_group_id,
                    "switch to sudo user's group for Keychain enrollment",
                )?;
                set_effective_uid(
                    target_user_id,
                    "switch to sudo user for Keychain enrollment",
                )?;

                Ok(Self {
                    restore_uid: Some(installer_user_id),
                    restore_gid: Some(installer_group_id),
                })
            }

            fn restore(self) -> Result<(), CliError> {
                let user_id_to_restore = self.restore_uid;
                let group_id_to_restore = self.restore_gid;
                std::mem::forget(self);

                if let Some(uid) = user_id_to_restore {
                    set_effective_uid(uid, "restore root user after Keychain enrollment")?;
                }

                if let Some(gid) = group_id_to_restore {
                    set_effective_gid(gid, "restore root group after Keychain enrollment")?;
                }

                Ok(())
            }
        }

        impl Drop for InitUserIdentityGuard {
            fn drop(&mut self) {
                // Early returns still restore the root installer identity. The
                // explicit restore path reports restoration errors on normal exit.
                if let Some(uid) = self.restore_uid.take() {
                    let _ = unsafe { libc::seteuid(uid) };
                }

                if let Some(gid) = self.restore_gid.take() {
                    let _ = unsafe { libc::setegid(gid) };
                }
            }
        }

        fn sudo_id(name: &str) -> Result<u32, CliError> {
            std::env::var(name)
                .map_err(|_| {
                    CliError::Other(
                        "Keychain enrollment requires SUDO_UID/SUDO_GID from the target install user"
                            .into(),
                    )
                })?
                .parse::<u32>()
                .map_err(|e| CliError::Other(format!("{name} contains an invalid uid/gid: {e}")))
        }

        fn set_effective_uid(uid: u32, action: &str) -> Result<(), CliError> {
            if unsafe { libc::seteuid(uid) } != 0 {
                return Err(CliError::Other(format!(
                    "{action} failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            Ok(())
        }

        fn set_effective_gid(gid: u32, action: &str) -> Result<(), CliError> {
            if unsafe { libc::setegid(gid) } != 0 {
                return Err(CliError::Other(format!(
                    "{action} failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            Ok(())
        }
    }

    #[cfg(not(target_os = "macos"))]
    mod macos {
        use super::{KeychainEnrollment, KeychainSignature};
        use crate::CliError;

        pub(super) fn enroll_key_for_init(_key_tag: &str) -> Result<KeychainEnrollment, CliError> {
            Err(super::super::unavailable_error())
        }

        pub(super) fn delete_key_for_init(_key_tag: &str) -> Result<(), CliError> {
            Err(super::super::unavailable_error())
        }

        pub(super) fn sign_payload_with_prompt(
            _key_tag: &str,
            _payload: &[u8],
        ) -> Result<KeychainSignature, CliError> {
            Err(super::super::unavailable_error())
        }

        pub(super) fn sign_payload_without_prompt(
            _key_tag: &str,
            _payload: &[u8],
        ) -> Result<KeychainSignature, CliError> {
            Err(super::super::unavailable_error())
        }
    }

    pub(crate) fn enroll_key_for_init(key_tag: &str) -> Result<KeychainEnrollment, CliError> {
        macos::enroll_key_for_init(key_tag)
    }

    pub(crate) fn delete_key_for_init(key_tag: &str) -> Result<(), CliError> {
        macos::delete_key_for_init(key_tag)
    }

    pub(crate) fn sign_payload_with_prompt(
        key_tag: &str,
        payload: &[u8],
    ) -> Result<KeychainSignature, CliError> {
        macos::sign_payload_with_prompt(key_tag, payload)
    }

    pub(crate) fn sign_payload_without_prompt(
        key_tag: &str,
        payload: &[u8],
    ) -> Result<KeychainSignature, CliError> {
        macos::sign_payload_without_prompt(key_tag, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_lower_encodes_bytes() {
        assert_eq!(hex_lower(&[0, 1, 254, 255]), "0001feff");
    }

    #[test]
    fn keychain_os_status_classification_names_actionable_failures() {
        assert_eq!(
            macos_keychain::classify_os_status(-34_018),
            macos_keychain::KeychainFailureKind::MissingEntitlementOrSession
        );
        assert_eq!(
            macos_keychain::classify_os_status(-25_308),
            macos_keychain::KeychainFailureKind::InteractionUnavailable
        );
        assert_eq!(
            macos_keychain::classify_os_status(-25_293),
            macos_keychain::KeychainFailureKind::AuthenticationDenied
        );
        assert_eq!(
            macos_keychain::classify_os_status(-25_291),
            macos_keychain::KeychainFailureKind::SecurityFrameworkUnavailable
        );
        assert_eq!(
            macos_keychain::classify_os_status(-1),
            macos_keychain::KeychainFailureKind::Other
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_interactive_prompt_reads_after_macos_prefix() {
        assert_eq!(
            macos_keychain::INTERACTIVE_SIGNING_PROMPT,
            "sign this Stentorian Guard rule with your Keychain key"
        );
        assert!(!macos_keychain::INTERACTIVE_SIGNING_PROMPT.ends_with('.'));
    }

    #[cfg(all(not(target_os = "macos"), not(feature = "test-signer")))]
    #[test]
    fn production_keychain_signer_fails_closed_without_macos_security_framework() {
        let err = macos_keychain::enroll_key_for_init("test").unwrap_err();
        assert!(
            err.to_string()
                .contains("OS-backed signing key unavailable")
        );
    }
}

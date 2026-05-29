//! Tests for the fixed-size C-string copy helper used by the exec hooks.
//! `copy_cstr_to_buf` is a hot-path helper: no allocation, bounded copy,
//! safe on null pointer.

use guard_hook::ipc_client::copy_cstr_to_buf;
use std::ffi::CString;

fn copy_test_cstr_to_buf(s: &CString, buf: &mut [u8]) -> usize {
    // SAFETY: `CString` always exposes a valid NUL-terminated C string pointer.
    unsafe { copy_cstr_to_buf(s.as_ptr(), buf) }
}

fn copy_null_cstr_to_buf(buf: &mut [u8]) -> usize {
    // SAFETY: the helper explicitly accepts null pointers.
    unsafe { copy_cstr_to_buf(std::ptr::null(), buf) }
}

#[test]
fn copies_short_string_with_correct_length() {
    let s = CString::new("hello").unwrap();
    let mut buf = [0u8; 32];
    let n = copy_test_cstr_to_buf(&s, &mut buf);
    assert_eq!(n, 5);
    assert_eq!(&buf[..n], b"hello");
}

#[test]
fn truncates_at_buffer_length() {
    let long = "a".repeat(2000);
    let s = CString::new(long).unwrap();
    let mut buf = [0u8; 1024];
    let n = copy_test_cstr_to_buf(&s, &mut buf);
    assert_eq!(n, 1024);
    assert!(buf.iter().all(|&b| b == b'a'));
}

#[test]
fn null_pointer_returns_zero() {
    let mut buf = [0u8; 16];
    let n = copy_null_cstr_to_buf(&mut buf);
    assert_eq!(n, 0);
}

#[test]
fn empty_string_returns_zero() {
    let s = CString::new("").unwrap();
    let mut buf = [0u8; 16];
    let n = copy_test_cstr_to_buf(&s, &mut buf);
    assert_eq!(n, 0);
}

#[test]
fn does_not_write_past_first_nul() {
    let s = CString::new("abc").unwrap();
    let mut buf = [0xFFu8; 8];
    let n = copy_test_cstr_to_buf(&s, &mut buf);
    assert_eq!(n, 3);
    assert_eq!(&buf[..n], b"abc");
    // Beyond n the buffer is undisturbed.
    assert_eq!(buf[n], 0xFF);
}

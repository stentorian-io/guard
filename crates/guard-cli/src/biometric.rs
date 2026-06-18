//! Touch ID / password gating via macOS `LocalAuthentication` framework.
//!
//! Fail-closed: if the native authentication framework is unavailable,
//! authentication is denied.

/// Prompt the user for Touch ID or password authentication.
/// Returns `true` if authentication succeeded, `false` otherwise.
#[cfg(feature = "test-signer")]
#[must_use]
pub fn authenticate(reason: &str) -> bool {
    let _ = reason;
    true
}

/// Prompt the user for Touch ID or password authentication.
/// Returns `true` if authentication succeeded, `false` otherwise.
#[cfg(all(not(feature = "test-signer"), not(target_os = "macos")))]
#[must_use]
pub fn authenticate(reason: &str) -> bool {
    let _ = reason;
    tracing::error!("biometric auth is only available on macOS; denying");
    false
}

#[cfg(all(not(feature = "test-signer"), target_os = "macos"))]
#[must_use]
pub fn authenticate(reason: &str) -> bool {
    macos_local_authentication::authenticate(reason)
}

#[cfg(all(not(feature = "test-signer"), target_os = "macos"))]
mod macos_local_authentication {
    use std::ffi::{CString, c_char, c_schar, c_void};
    use std::ptr;
    use std::sync::{Condvar, Mutex};

    type Id = *mut c_void;
    type Sel = *mut c_void;
    type Class = *mut c_void;
    type Bool = c_schar;

    const YES: Bool = 1;
    const DEVICE_OWNER_AUTHENTICATION_POLICY: isize = 2;
    const NS_UTF8_STRING_ENCODING: usize = 4;
    const BLOCK_HAS_SIGNATURE: i32 = 1 << 30;

    struct AuthenticationState {
        result: Mutex<Option<bool>>,
        completed: Condvar,
    }

    #[repr(C)]
    struct BlockLiteral {
        isa: *const c_void,
        flags: i32,
        reserved: i32,
        invoke: extern "C" fn(*mut AuthenticationReplyBlock, Bool, Id),
        descriptor: *const BlockDescriptor,
    }

    #[repr(C)]
    struct BlockDescriptor {
        reserved: usize,
        size: usize,
        signature: *const c_char,
    }

    // The descriptor points only at immutable static bytes required by the
    // Objective-C Blocks ABI.
    unsafe impl Sync for BlockDescriptor {}

    #[repr(C)]
    struct AuthenticationReplyBlock {
        literal: BlockLiteral,
        state: *const AuthenticationState,
    }

    #[link(name = "objc")]
    unsafe extern "C" {
        static _NSConcreteStackBlock: [*const c_void; 32];

        fn objc_getClass(name: *const c_char) -> Class;
        fn objc_autoreleasePoolPop(pool: *mut c_void);
        fn objc_autoreleasePoolPush() -> *mut c_void;
        fn sel_registerName(name: *const c_char) -> Sel;

        fn objc_msgSend();
    }

    #[link(name = "System", kind = "dylib")]
    unsafe extern "C" {
        fn _Block_copy(block: *const c_void) -> *mut c_void;
        fn _Block_release(block: *const c_void);
    }

    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {}

    #[link(name = "LocalAuthentication", kind = "framework")]
    unsafe extern "C" {}

    static AUTHENTICATION_REPLY_SIGNATURE: &[u8] = b"v@?B@\0";

    static AUTHENTICATION_REPLY_DESCRIPTOR: BlockDescriptor = BlockDescriptor {
        reserved: 0,
        size: size_of::<AuthenticationReplyBlock>(),
        signature: AUTHENTICATION_REPLY_SIGNATURE.as_ptr().cast(),
    };

    pub(super) fn authenticate(reason: &str) -> bool {
        if let Some(authenticated) = evaluate_device_owner_authentication(reason) {
            authenticated
        } else {
            tracing::error!("native biometric auth failed to start; denying");
            false
        }
    }

    fn evaluate_device_owner_authentication(reason: &str) -> Option<bool> {
        let _pool = AutoreleasePool::push();
        let context = new_object("LAContext")?;
        let Some(reason) = ns_string_from_str(reason) else {
            release_object(context);

            return None;
        };

        let state = AuthenticationState {
            result: Mutex::new(None),
            completed: Condvar::new(),
        };

        let block = authentication_reply_block(&state);
        let block = unsafe { _Block_copy(ptr::addr_of!(block).cast()) };
        if block.is_null() {
            release_object(reason);
            release_object(context);

            return None;
        }

        let Some(evaluate_policy) = selector("evaluatePolicy:localizedReason:reply:") else {
            release_authentication_resources(block, reason, context);

            return None;
        };

        unsafe {
            objc_msg_send_evaluate_policy(
                context,
                evaluate_policy,
                DEVICE_OWNER_AUTHENTICATION_POLICY,
                reason,
                block,
            );
        }

        let Ok(mut result_guard) = state.result.lock() else {
            release_authentication_resources(block, reason, context);

            return None;
        };

        while result_guard.is_none() {
            result_guard = if let Ok(result_guard) = state.completed.wait(result_guard) {
                result_guard
            } else {
                release_authentication_resources(block, reason, context);

                return None;
            };
        }
        let authenticated = (*result_guard).unwrap_or(false);
        drop(result_guard);

        release_authentication_resources(block, reason, context);

        Some(authenticated)
    }

    fn authentication_reply_block(state: &AuthenticationState) -> AuthenticationReplyBlock {
        AuthenticationReplyBlock {
            literal: BlockLiteral {
                isa: ptr::addr_of!(_NSConcreteStackBlock).cast(),
                flags: BLOCK_HAS_SIGNATURE,
                reserved: 0,
                invoke: authentication_reply,
                descriptor: ptr::addr_of!(AUTHENTICATION_REPLY_DESCRIPTOR),
            },
            state,
        }
    }

    fn release_authentication_resources(block: *const c_void, reason: Id, context: Id) {
        unsafe {
            _Block_release(block);
        }
        release_object(reason);
        release_object(context);
    }

    extern "C" fn authentication_reply(
        block: *mut AuthenticationReplyBlock,
        success: Bool,
        _error: Id,
    ) {
        if block.is_null() {
            return;
        }

        let state = unsafe { (*block).state.as_ref() };
        let Some(state) = state else {
            return;
        };

        if let Ok(mut result_guard) = state.result.lock() {
            *result_guard = Some(success == YES);
            state.completed.notify_one();
        }
    }

    fn new_object(class_name: &str) -> Option<Id> {
        let class = class(class_name)?;
        let alloc = selector("alloc")?;
        let init = selector("init")?;

        let object = unsafe { objc_msg_send_id(class.cast(), alloc) };
        if object.is_null() {
            return None;
        }

        let object = unsafe { objc_msg_send_id(object, init) };
        if object.is_null() { None } else { Some(object) }
    }

    fn ns_string_from_str(contents: &str) -> Option<Id> {
        let class = class("NSString")?;
        let alloc = selector("alloc")?;
        let init = selector("initWithBytes:length:encoding:")?;

        let object = unsafe { objc_msg_send_id(class.cast(), alloc) };
        if object.is_null() {
            return None;
        }

        let string = unsafe {
            objc_msg_send_init_with_bytes(
                object,
                init,
                contents.as_ptr().cast(),
                contents.len(),
                NS_UTF8_STRING_ENCODING,
            )
        };

        if string.is_null() { None } else { Some(string) }
    }

    fn release_object(object: Id) {
        let Some(release) = selector("release") else {
            return;
        };

        unsafe {
            objc_msg_send_id(object, release);
        }
    }

    unsafe fn objc_msg_send_id(receiver: Id, selector: Sel) -> Id {
        type MessageSend = unsafe extern "C" fn(Id, Sel) -> Id;
        let send: MessageSend = unsafe { std::mem::transmute(objc_msgSend as *const c_void) };

        unsafe { send(receiver, selector) }
    }

    unsafe fn objc_msg_send_init_with_bytes(
        receiver: Id,
        selector: Sel,
        bytes: *const c_void,
        length: usize,
        encoding: usize,
    ) -> Id {
        type MessageSend = unsafe extern "C" fn(Id, Sel, *const c_void, usize, usize) -> Id;
        let send: MessageSend = unsafe { std::mem::transmute(objc_msgSend as *const c_void) };

        unsafe { send(receiver, selector, bytes, length, encoding) }
    }

    unsafe fn objc_msg_send_evaluate_policy(
        receiver: Id,
        selector: Sel,
        policy: isize,
        localized_reason: Id,
        reply: *mut c_void,
    ) {
        type MessageSend = unsafe extern "C" fn(Id, Sel, isize, Id, *mut c_void);
        let send: MessageSend = unsafe { std::mem::transmute(objc_msgSend as *const c_void) };

        unsafe {
            send(receiver, selector, policy, localized_reason, reply);
        }
    }

    fn class(name: &str) -> Option<Class> {
        let name = CString::new(name).ok()?;
        let class = unsafe { objc_getClass(name.as_ptr()) };

        if class.is_null() { None } else { Some(class) }
    }

    fn selector(name: &str) -> Option<Sel> {
        let name = CString::new(name).ok()?;
        let selector = unsafe { sel_registerName(name.as_ptr()) };

        if selector.is_null() {
            None
        } else {
            Some(selector)
        }
    }

    struct AutoreleasePool {
        pool: *mut c_void,
    }

    impl AutoreleasePool {
        fn push() -> Self {
            let pool = unsafe { objc_autoreleasePoolPush() };

            Self { pool }
        }
    }

    impl Drop for AutoreleasePool {
        fn drop(&mut self) {
            if self.pool.is_null() {
                return;
            }

            unsafe {
                objc_autoreleasePoolPop(self.pool);
            }
        }
    }
}

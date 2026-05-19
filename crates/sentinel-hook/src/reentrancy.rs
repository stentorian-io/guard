//! Thread-local in-hook guard (D-11).
//!
//! Every replacement function starts with:
//!
//! ```text
//! if IN_HOOK.with(|c| c.replace(true)) {
//!   // already inside a hook on this thread — pass through
//!   return real(...);
//! }
//! ```
//!
//! and clears the flag on every exit path.
//!
//! # BL-04 fix (canonical reference) — RAII guard pattern
//!
//! WARNING-02 (v0.2 review): the BL-04 explanation moved here from
//! `replace_libc.rs` so all hooks (`replace_libc`, `replace_fork`,
//! `replace_exec`, `replace_nw`) reference the SAME canonical
//! description. Each hook file's `InHookGuard` struct is a copy of the
//! pattern below; if you change one, change them all.
//!
//! ## The bug (original v0.1 BL-04)
//!
//! The previous pattern cleared `IN_HOOK` BEFORE dispatching the real
//! syscall:
//!
//! ```text
//! set_guard();
//! decide();
//! CLEAR_GUARD();          // <-- bug: cleared too early
//! if deny { return -1; }
//! real_call();            // <-- guard already cleared
//! ```
//!
//! That left the dispatch window completely unguarded. If any code path
//! between the clear and the return re-entered a hook (Network.framework
//! ARC retain/release on async callbacks, dyld late-binding triggered by
//! a libc internal helper, etc.), `IN_HOOK` was false and the hook would
//! re-evaluate policy rather than passing through. Worst case: an
//! unbounded recursion when a hook's allow path itself made a connect
//! call.
//!
//! ## The fix (RAII)
//!
//! The guard is held for the entire function scope and drops AFTER the
//! real dispatch. An RAII `InHookGuard` achieves this automatically:
//!
//! ```text
//! let _g = InHookGuard::enter()?; // sets IN_HOOK=true; None on
//!                                 //   reentry → caller passes through
//! decide();
//! real_call();
//! // _g drops here — IN_HOOK cleared AFTER the real call returns
//! ```
//!
//! `InHookGuard::enter()` returns:
//!   - `None` when already in a hook on this thread (caller MUST pass
//!     through immediately to the real syscall — no policy check, no
//!     IPC, no allocation).
//!   - `Some(guard)` when we successfully transitioned `IN_HOOK` from
//!     false to true. The guard's `Drop` clears `IN_HOOK` back to false.
//!
//! `replace.rs::sentinel_fork` and `sentinel_vfork` ALSO explicitly
//! reset `IN_HOOK` in the child path — `raw_fork()`/`raw_vfork()` share
//! the parent's thread-local cell across the fork; the RAII guard alone
//! cannot recover from that. `posix_spawn` does NOT need that reset
//! because the libc atomic forks-and-execs in a single call (see
//! BLOCKER-05 in the v0.2 review for the explicit assumption).

use core::cell::Cell;

thread_local! {
    pub static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

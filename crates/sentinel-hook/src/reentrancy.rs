//! Thread-local in-hook guard (D-11).
//!
//! Every replacement function starts with:
//!   if IN_HOOK.with(|c| c.replace(true)) {
//!     // already inside a hook on this thread — pass through
//!     return real(...);
//!   }
//! and clears the flag on every exit path.

use core::cell::Cell;

thread_local! {
    pub static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

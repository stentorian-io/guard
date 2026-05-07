//! Spike A2: validate `panic = "unwind"` per-target override viability.
//!
//! Resolves Open Question 1 + RESEARCH.md A2 (LOW confidence).
//!
//! Outcome (recorded in 04-SPIKE-RESULTS.md): cargo REJECTS per-package
//! panic settings with the error
//!
//!   `panic` may not be specified in a `package` profile
//!
//! so the workspace stays at `panic = "abort"` and `catch_unwind` is a no-op
//! for the daemon. Test 1 is gated `#[ignore]` under abort mode (the panic
//! would abort the test binary before the assertion runs); test 2 captures
//! the observed mode for plan 02 to read.

#[test]
#[cfg_attr(panic = "abort", ignore)]
fn spike_catch_unwind_intercepts_panic_when_unwind() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let result = catch_unwind(AssertUnwindSafe(|| {
        panic!("simulated gix panic");
    }));
    assert!(
        result.is_err(),
        "catch_unwind must Err — panic mode must be unwind for this test"
    );
}

#[test]
fn spike_test_runner_panic_mode_consistent() {
    let panic_strategy = if cfg!(panic = "unwind") {
        "unwind"
    } else {
        "abort"
    };
    eprintln!("PANIC-MODE-OBSERVED: {}", panic_strategy);
    // Test always passes; the eprintln captures observed mode for SPIKE-RESULTS.md.
}

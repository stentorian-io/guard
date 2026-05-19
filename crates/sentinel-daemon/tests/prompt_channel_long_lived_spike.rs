//! Wave-0 spike (v0.3): verifies A4 from RESEARCH.md.
//! Spawning 32 concurrent OS threads (one per "prompt channel") does not exhaust
//! pthread limits on a developer Mac; all 32 threads enter their main bodies
//! within 1 second of spawn.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn spawn_32_long_lived_threads_within_1s() {
    let counter = Arc::new(AtomicU32::new(0));
    let release = Arc::new(std::sync::Mutex::new(false));
    let release_cv = Arc::new(std::sync::Condvar::new());

    let mut handles = Vec::with_capacity(32);
    let start = Instant::now();
    for i in 0..32u32 {
        let counter = Arc::clone(&counter);
        let release = Arc::clone(&release);
        let release_cv = Arc::clone(&release_cv);
        let h = std::thread::Builder::new()
            .name(format!("sentineld-prompt-spike-{i}"))
            .spawn(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut g = release.lock().unwrap();
                while !*g {
                    g = release_cv.wait(g).unwrap();
                }
            })
            .expect("thread::Builder::spawn must not return EAGAIN at N=32");
        handles.push(h);
    }

    // All 32 threads should enter their main body within 1s.
    let deadline = Instant::now() + Duration::from_secs(1);
    while counter.load(Ordering::SeqCst) < 32 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let elapsed = start.elapsed();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        32,
        "only {} of 32 long-lived threads started in {:?}",
        counter.load(Ordering::SeqCst),
        elapsed,
    );

    // Release all so the test exits cleanly.
    {
        let mut g = release.lock().unwrap();
        *g = true;
        release_cv.notify_all();
    }
    for h in handles {
        h.join().expect("thread join");
    }
}

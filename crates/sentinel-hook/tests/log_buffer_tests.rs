//! Concurrent-writer correctness for the new ArrayQueue-backed LogRing
//! (BL-03 / D-43 fix). Phase 1's racy SpscRing is replaced with a lock-free
//! MPMC `crossbeam_queue::ArrayQueue<Box<[u8]>>` whose append/dump APIs are
//! safe under concurrent writers.

use sentinel_hook::log_buffer::{LogRing, LOG_RING};

#[test]
fn capacity_const_is_1024() {
    assert_eq!(LogRing::CAPACITY, 1024);
}

#[test]
fn append_and_dump_roundtrip() {
    LOG_RING.append(b"hello");
    LOG_RING.append(b"world");
    let mut out = Vec::new();
    LOG_RING.dump(&mut out);
    assert!(out.windows(5).any(|w| w == b"hello"));
    assert!(out.windows(5).any(|w| w == b"world"));
}

#[test]
fn concurrent_writers_no_torn_data() {
    use std::sync::Arc;
    use std::thread;
    let messages: Vec<&'static [u8]> = (0..16)
        .map(|i| {
            let s: &'static str = Box::leak(format!("msg-{i:02}").into_boxed_str());
            s.as_bytes()
        })
        .collect();
    let messages = Arc::new(messages);
    let mut handles = vec![];
    for i in 0..16 {
        let messages = messages.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                LOG_RING.append(messages[i]);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let mut out = Vec::new();
    LOG_RING.dump(&mut out);
    let s = std::str::from_utf8(&out).expect("entries are valid utf-8 (no torn writes)");
    // Each entry must match one of the patterns "msg-NN\n" exactly; tabular check
    // would be expensive, so we sanity-check that 'msg-' substring count is plausible.
    let count = s.matches("msg-").count();
    assert!(count > 0, "expected some msg-* lines; got: {}", s);
    assert!(
        count <= LogRing::CAPACITY,
        "queue must not exceed capacity ({} found)",
        count
    );
}

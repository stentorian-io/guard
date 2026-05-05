use sentinel_hook::cache::{Cache, CAPACITY};

#[test]
fn insert_and_lookup() {
    let mut c = Cache::new();
    c.insert(b"sockaddr1", b"foo.example.com");
    assert_eq!(c.lookup(b"sockaddr1"), Some(b"foo.example.com" as &[u8]));
    assert_eq!(c.lookup(b"sockaddr-other"), None);
}

#[test]
fn lru_evicts_oldest_after_capacity() {
    let mut c = Cache::new();
    // Fill to capacity with distinct keys.
    for i in 0..CAPACITY {
        let key = vec![i as u8];
        let host = format!("host{i}.example.com");
        c.insert(&key, host.as_bytes());
    }
    // All present.
    for i in 0..CAPACITY {
        assert!(c.lookup(&[i as u8]).is_some(), "entry {i} should be present");
    }
    // Insert one more — evicts LRU which is now [0] (since lookup bumped them all to MRU
    // in order, but lookup for 0 was first and other lookups happened later, so 0 is LRU).
    c.insert(b"NEW", b"new.example.com");
    // The newly inserted entry is found.
    assert_eq!(c.lookup(b"NEW"), Some(b"new.example.com" as &[u8]));
    // Total entries still == CAPACITY (not CAPACITY+1).
    let mut count = 0;
    for i in 0..=CAPACITY {
        let key = if i == CAPACITY {
            b"NEW".to_vec()
        } else {
            vec![i as u8]
        };
        if c.lookup(&key).is_some() {
            count += 1;
        }
    }
    assert_eq!(count, CAPACITY, "cache must not exceed CAPACITY");
}

#[test]
fn lookup_bumps_to_most_recently_used() {
    let mut c = Cache::new();
    for i in 0..CAPACITY {
        c.insert(&[i as u8], format!("h{i}").as_bytes());
    }
    // Touch entry 0 — it becomes MRU.
    c.lookup(&[0u8]);
    // Insert a new entry — should evict the now-LRU (which is entry 1).
    c.insert(b"ZZZ", b"z");
    assert!(c.lookup(&[0u8]).is_some(), "0 was bumped, must survive");
    assert!(c.lookup(&[1u8]).is_none(), "1 was LRU after bumping 0, evicted");
}

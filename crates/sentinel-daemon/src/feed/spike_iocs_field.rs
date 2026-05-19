//! Spike A4: validate the empirical `database_specific.iocs` host-IoC
//! field shape against inline OSV-shaped fixtures.
//!
//! Resolves Pitfall 4 in 04-RESEARCH.md (originally speculated wrong
//! field names — `malicious_hosts`, `c2`, `exfil_hosts` — but empirical
//! sampling of 200 malicious-packages records found 0 occurrences of any
//! of those keys; the actual signal is `database_specific.iocs.{domains,
//! urls, ips}` in 84/200 records). PATTERNS.md correction #3 prescribed
//! the empirical key.
//!
//! These tests pin the empirical conclusion as code so plan 02's parser
//! ships with the correct key from day one.

#[test]
fn spike_extracts_hosts_from_database_specific_iocs_domains() {
    let osv_record = r#"{
        "schema_version": "1.7.4",
        "id": "MAL-2026-FIXTURE-1",
        "modified": "2026-01-15T00:00:00Z",
        "published": "2026-01-15T00:00:00Z",
        "affected": [{"package": {"ecosystem": "npm", "name": "evil-pkg"}, "versions": ["1.0.0"]}],
        "database_specific": {
            "iocs": {
                "domains": ["honey.zakura-int.workers.dev", "exfil.example.com"],
                "urls": [],
                "ips": []
            }
        }
    }"#;
    let parsed: serde_json::Value = serde_json::from_str(osv_record).unwrap();
    let iocs = parsed
        .get("database_specific")
        .and_then(|d| d.get("iocs"))
        .expect(
            "database_specific.iocs is the empirically-correct path per RESEARCH.md Pitfall 4",
        );
    let domains: Vec<String> = iocs
        .get("domains")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        domains,
        vec![
            "honey.zakura-int.workers.dev".to_string(),
            "exfil.example.com".to_string()
        ]
    );
}

#[test]
fn spike_url_host_extraction_via_url_crate() {
    use url::Url;

    let raw_urls = [
        "https://discord.com/api/webhooks/123",
        "https://cdn.discordapp.com/attachments/foo",
        "https://dl.dropbox.com/s/abc/payload.zip",
    ];

    let hosts: Vec<String> = raw_urls
        .iter()
        .filter_map(|u| Url::parse(u).ok())
        .filter_map(|u| u.host_str().map(String::from))
        .collect();

    assert_eq!(
        hosts,
        vec!["discord.com", "cdn.discordapp.com", "dl.dropbox.com"]
    );
}

#[test]
fn spike_speculative_field_names_are_absent() {
    // Originally speculated `malicious_hosts`, `c2`, `exfil_hosts` —
    // empirical sampling (RESEARCH.md Pitfall 4) shows zero occurrences across
    // 200 records. PATTERNS.md correction #3 corrects the field name to
    // `iocs`. This test pins the empirical conclusion: a parser looking ONLY
    // for the speculative names extracts nothing useful from a real record
    // shape.
    let osv_record = r#"{
        "schema_version": "1.7.4",
        "id": "MAL-2026-FIXTURE-2",
        "database_specific": {
            "iocs": {"domains": ["x.example.com"], "urls": [], "ips": []}
        }
    }"#;
    let parsed: serde_json::Value = serde_json::from_str(osv_record).unwrap();
    let dbspec = parsed.get("database_specific").unwrap();

    // Negative assertions on the speculative names:
    assert!(
        dbspec.get("malicious_hosts").is_none(),
        "speculative key absent in real data"
    );
    assert!(
        dbspec.get("c2").is_none(),
        "speculative key absent in real data"
    );
    assert!(
        dbspec.get("exfil_hosts").is_none(),
        "speculative key absent in real data"
    );

    // Positive assertion on the empirical key:
    assert!(
        dbspec.get("iocs").is_some(),
        "iocs is the empirical key per PATTERNS.md correction #3"
    );
}

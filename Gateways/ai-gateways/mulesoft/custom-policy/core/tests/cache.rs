use prisma_airs_core::airs::Leg;
use prisma_airs_core::cache::VerdictCache;
use prisma_airs_core::settings::ProfileRef;

const EP: &str = "https://service.api.aisecurity.paloaltonetworks.com";

fn name(n: &str) -> ProfileRef {
    ProfileRef::Name(n.into())
}

fn key(text: &str) -> [u8; 32] {
    VerdictCache::key("tenant-key", EP, &name("p"), Leg::Prompt, 20000, true, "", text)
}

#[test]
fn cache_hit_within_ttl_miss_after() {
    let mut c = VerdictCache::new(60_000, 1024);
    c.put_allow(key("hello"), "scan-1".into(), 1_000);
    assert_eq!(c.get(&key("hello"), 1_000).as_deref(), Some("scan-1"));
    assert_eq!(c.get(&key("hello"), 60_999).as_deref(), Some("scan-1"));
    assert_eq!(c.get(&key("hello"), 61_000), None, "expired at put + ttl");
    assert_eq!(c.get(&key("other"), 1_000), None);
}

#[test]
fn cache_key_differs_by_leg_profile_endpoint_tenant() {
    let base = VerdictCache::key("t", EP, &name("p"), Leg::Prompt, 20000, true, "", "x");
    let variants = [
        VerdictCache::key("t2", EP, &name("p"), Leg::Prompt, 20000, true, "", "x"),
        VerdictCache::key("t", "https://service-de.api.aisecurity.paloaltonetworks.com", &name("p"), Leg::Prompt, 20000, true, "", "x"),
        VerdictCache::key("t", EP, &name("p2"), Leg::Prompt, 20000, true, "", "x"),
        VerdictCache::key("t", EP, &ProfileRef::Id("p".into()), Leg::Prompt, 20000, true, "", "x"),
        VerdictCache::key("t", EP, &name("p"), Leg::Response, 20000, true, "", "x"),
        VerdictCache::key("t", EP, &name("p"), Leg::Prompt, 10000, true, "", "x"),
        VerdictCache::key("t", EP, &name("p"), Leg::Prompt, 20000, false, "", "x"),
        VerdictCache::key("t", EP, &name("p"), Leg::Prompt, 20000, true, "context", "x"),
        VerdictCache::key("t", EP, &name("p"), Leg::Prompt, 20000, true, "", "y"),
    ];
    for (i, v) in variants.iter().enumerate() {
        assert_ne!(&base, v, "variant {i} must not share an entry");
    }
    assert_eq!(base, VerdictCache::key("t", EP, &name("p"), Leg::Prompt, 20000, true, "", "x"));
}

#[test]
fn cache_key_fields_cannot_run_into_each_other() {
    let a = VerdictCache::key("t", EP, &name("p"), Leg::Prompt, 20000, true, "ab", "c");
    let b = VerdictCache::key("t", EP, &name("p"), Leg::Prompt, 20000, true, "a", "bc");
    assert_ne!(a, b);
}

#[test]
fn cache_evicts_oldest_at_capacity() {
    let mut c = VerdictCache::new(60_000, 2);
    c.put_allow(key("a"), "1".into(), 0);
    c.put_allow(key("b"), "2".into(), 1);
    c.put_allow(key("c"), "3".into(), 2);
    assert_eq!(c.get(&key("a"), 3), None, "the oldest entry went first");
    assert_eq!(c.get(&key("b"), 3).as_deref(), Some("2"));
    assert_eq!(c.get(&key("c"), 3).as_deref(), Some("3"));
    assert!(c.len() <= 2);
}

#[test]
fn putting_an_existing_key_refreshes_it() {
    let mut c = VerdictCache::new(10_000, 2);
    c.put_allow(key("a"), "1".into(), 0);
    c.put_allow(key("b"), "2".into(), 1);
    c.put_allow(key("a"), "1b".into(), 9_000);
    c.put_allow(key("c"), "3".into(), 9_001);
    assert_eq!(c.get(&key("a"), 9_002).as_deref(), Some("1b"), "a was refreshed, so b is now the oldest");
    assert_eq!(c.get(&key("b"), 9_002), None);
}

#[test]
fn cache_has_no_way_to_store_a_block() {
    // The cache's only writer is put_allow: a cached block would freeze a false positive for the whole TTL.
    let mut c = VerdictCache::new(60_000, 4);
    c.put_allow(key("x"), "scan".into(), 0);
    assert_eq!(c.get(&key("x"), 1).as_deref(), Some("scan"));
}

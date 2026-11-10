//! An optional verdict cache, off by default. It stores allow verdicts only: a cached block would freeze a false
//! positive for the whole TTL, and a block is the cheap case anyway. A profile change in Strata Cloud Manager takes
//! effect for cached content only when its entry expires, so the TTL is the worst-case staleness.
//!
//! The key is SHA-256 over every input that can change a verdict, each field length-prefixed so two fields can never
//! run into each other. The API key is one of those inputs (two tenants never share an entry); it is hashed, never
//! stored.

use std::collections::{HashMap, VecDeque};

use sha2::{Digest, Sha256};

use crate::airs::Leg;
use crate::settings::ProfileRef;

pub struct VerdictCache {
    ttl_ms: u64,
    capacity: usize,
    entries: HashMap<[u8; 32], Entry>,
    order: VecDeque<([u8; 32], u64)>,
    next_seq: u64,
}

struct Entry {
    scan_id: String,
    expires_ms: u64,
    seq: u64,
}

impl VerdictCache {
    pub fn new(ttl_ms: u64, capacity: usize) -> VerdictCache {
        VerdictCache { ttl_ms, capacity: capacity.max(1), entries: HashMap::new(), order: VecDeque::new(), next_seq: 0 }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn key(
        tenant: &str,
        endpoint: &str,
        profile: &ProfileRef,
        leg: Leg,
        max_chars: usize,
        truncation_fail_closed: bool,
        context: &str,
        text: &str,
    ) -> [u8; 32] {
        let profile = match profile {
            ProfileRef::Name(name) => format!("name:{name}"),
            ProfileRef::Id(id) => format!("id:{id}"),
        };
        let mut hash = Sha256::new();
        for field in [
            tenant,
            endpoint,
            profile.as_str(),
            leg.name(),
            max_chars.to_string().as_str(),
            if truncation_fail_closed { "closed" } else { "open" },
            context,
            text,
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        hash.finalize().into()
    }

    /// The scan ID of a cached allow for this key, if it has not expired.
    pub fn get(&self, key: &[u8; 32], now_ms: u64) -> Option<String> {
        self.entries.get(key).filter(|e| now_ms < e.expires_ms).map(|e| e.scan_id.clone())
    }

    pub fn put_allow(&mut self, key: [u8; 32], scan_id: String, now_ms: u64) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.insert(key, Entry { scan_id, expires_ms: now_ms.saturating_add(self.ttl_ms), seq });
        self.order.push_back((key, seq));
        while self.entries.len() > self.capacity {
            let Some((oldest, oldest_seq)) = self.order.pop_front() else { break };
            if self.entries.get(&oldest).is_some_and(|e| e.seq == oldest_seq) {
                self.entries.remove(&oldest);
            }
        }
        // Drop queue records of keys that were refreshed since, so the queue cannot grow without bound.
        if self.order.len() > self.capacity.saturating_mul(4) {
            let entries = &self.entries;
            self.order.retain(|(k, s)| entries.get(k).is_some_and(|e| e.seq == *s));
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

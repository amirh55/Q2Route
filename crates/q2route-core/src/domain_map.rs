//! IP -> domain names learned from DNS answers, so domain rules can decide
//! without waiting for an SNI peek.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const MAP_MAX_IPS: usize = 65_536;
pub const NAMES_PER_IP: usize = 8;
const TTL_MIN: u32 = 60;
const TTL_MAX: u32 = 3600;

struct Entry {
    seq: u64,
    /// Oldest first: (name, expiry).
    names: VecDeque<(String, Instant)>,
}

#[derive(Default)]
struct Inner {
    map: HashMap<IpAddr, Entry>,
    seq: u64,
}

/// Thread-safe IP -> names map; one short lock per call.
#[derive(Default)]
pub struct DomainMap {
    inner: Mutex<Inner>,
}

impl DomainMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, ip: IpAddr, name: &str, ttl_secs: u32, now: Instant) {
        let exp = now + Duration::from_secs(u64::from(ttl_secs.clamp(TTL_MIN, TTL_MAX)));
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let inn = &mut *g;
        if !inn.map.contains_key(&ip) && inn.map.len() >= MAP_MAX_IPS {
            inn.map.retain(|_, e| e.names.iter().any(|(_, x)| *x > now));
            if inn.map.len() >= MAP_MAX_IPS {
                if let Some(oldest) = inn.map.iter().min_by_key(|(_, e)| e.seq).map(|(k, _)| *k) {
                    inn.map.remove(&oldest);
                }
            }
        }
        inn.seq += 1;
        let seq = inn.seq;
        let e = inn.map.entry(ip).or_insert_with(|| Entry {
            seq,
            names: VecDeque::new(),
        });
        e.names.retain(|(n, _)| *n != name);
        e.names.push_back((name, exp));
        while e.names.len() > NAMES_PER_IP {
            e.names.pop_front();
        }
    }

    /// Unexpired names for `ip`, most recent first.
    pub fn names(&self, ip: IpAddr, now: Instant) -> Vec<String> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.map.get(&ip).map_or_else(Vec::new, |e| {
            e.names
                .iter()
                .rev()
                .filter(|(_, x)| *x > now)
                .map(|(n, _)| n.clone())
                .collect()
        })
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

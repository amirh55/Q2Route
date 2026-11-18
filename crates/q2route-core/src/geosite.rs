//! v2ray `geosite.dat` reader: list code -> set of domain rules.
//!
//! Protobuf `GeoSiteList { repeated GeoSite entry = 1; }`,
//! `GeoSite { string country_code = 1; repeated Domain domain = 2; }`,
//! `Domain { Type type = 1; string value = 2; repeated Attribute attribute = 3; }`
//! with `Type { Plain = 0 (keyword), Regex = 1, RootDomain = 2, Full = 3 }` and
//! `Attribute { string key = 1; ... }`. Only the codes asked for are decoded;
//! the rest are skipped by length. Regex (and unknown types) are not supported
//! and are counted as skipped.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::geoip::{Field, GeoIpError, Reader};

#[derive(Debug, thiserror::Error)]
#[error("malformed geosite.dat: {0}")]
pub struct GeoSiteError(&'static str);

impl From<GeoIpError> for GeoSiteError {
    fn from(e: GeoIpError) -> Self {
        GeoSiteError(e.0)
    }
}

/// Domain rules of one list: exact names, root domains and keywords.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DomainSet {
    full: HashSet<String>,
    roots: HashSet<String>,
    keywords: Vec<String>,
    skipped_regex: usize,
}

impl DomainSet {
    pub fn contains(&self, host: &str) -> bool {
        let lower = host.to_lowercase();
        let h = lower.strip_suffix('.').unwrap_or(&lower);
        if h.is_empty() {
            return false;
        }
        if self.full.contains(h) {
            return true;
        }
        let mut s = h;
        loop {
            if self.roots.contains(s) {
                return true;
            }
            match s.split_once('.') {
                Some((_, rest)) => s = rest,
                None => break,
            }
        }
        self.keywords.iter().any(|k| h.contains(k.as_str()))
    }

    pub fn len(&self) -> usize {
        self.full.len() + self.roots.len() + self.keywords.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn from_entries(full: &[&str], roots: &[&str], keywords: &[&str]) -> DomainSet {
        DomainSet {
            full: full.iter().map(|s| s.to_lowercase()).collect(),
            roots: roots.iter().map(|s| s.to_lowercase()).collect(),
            keywords: keywords.iter().map(|s| s.to_lowercase()).collect(),
            skipped_regex: 0,
        }
    }
}

/// Domain lists loaded from a `geosite.dat`, keyed by lowercase `code` or `code@attr`.
#[derive(Debug, Default, Clone)]
pub struct GeoSite {
    sets: HashMap<String, Arc<DomainSet>>,
}

struct Domain<'a> {
    ty: u64,
    value: &'a [u8],
    attrs: Vec<String>,
}

fn decode_domain(b: &[u8]) -> Result<Domain<'_>, GeoSiteError> {
    let mut r = Reader { b };
    let mut d = Domain {
        ty: 0,
        value: &[],
        attrs: Vec::new(),
    };
    while !r.done() {
        match r.field()? {
            (1, Field::Varint(t)) => d.ty = t,
            (2, Field::Bytes(v)) => d.value = v,
            (3, Field::Bytes(a)) => {
                let mut ar = Reader { b: a };
                while !ar.done() {
                    if let (1, Field::Bytes(k)) = ar.field()? {
                        d.attrs.push(String::from_utf8_lossy(k).to_lowercase());
                    }
                }
            }
            _ => {}
        }
    }
    Ok(d)
}

fn entry_code(entry: &[u8]) -> Result<Option<String>, GeoSiteError> {
    let mut r = Reader { b: entry };
    while !r.done() {
        if let (1, Field::Bytes(s)) = r.field()? {
            return Ok(Some(String::from_utf8_lossy(s).to_lowercase()));
        }
    }
    Ok(None)
}

impl GeoSite {
    /// Decode only the lists in `wanted` (`code` or `code@attr`, case-insensitive).
    pub fn parse(data: &[u8], wanted: &[String]) -> Result<GeoSite, GeoSiteError> {
        // code -> [(key, attr filter)]
        let mut by_code: HashMap<String, Vec<(String, Option<String>)>> = HashMap::new();
        for w in wanted {
            let key = w.to_lowercase();
            let (code, attr) = match key.split_once('@') {
                Some((c, a)) => (c.to_string(), Some(a.to_string())),
                None => (key.clone(), None),
            };
            by_code.entry(code).or_default().push((key, attr));
        }
        let mut sets = HashMap::new();
        let mut r = Reader { b: data };
        while !r.done() {
            let (num, f) = r.field()?;
            let (1, Field::Bytes(entry)) = (num, f) else {
                continue;
            };
            let Some(code) = entry_code(entry)? else {
                continue;
            };
            let Some(keys) = by_code.get(&code) else {
                continue;
            };
            let mut built: Vec<DomainSet> = keys.iter().map(|_| DomainSet::default()).collect();
            let mut er = Reader { b: entry };
            while !er.done() {
                let (2, Field::Bytes(db)) = er.field()? else {
                    continue;
                };
                let d = decode_domain(db)?;
                let value = String::from_utf8_lossy(d.value).to_lowercase();
                for ((_, attr), set) in keys.iter().zip(built.iter_mut()) {
                    if let Some(a) = attr {
                        if !d.attrs.iter().any(|x| x == a) {
                            continue;
                        }
                    }
                    match d.ty {
                        0 => set.keywords.push(value.clone()),
                        2 => {
                            set.roots.insert(value.clone());
                        }
                        3 => {
                            set.full.insert(value.clone());
                        }
                        _ => set.skipped_regex += 1,
                    }
                }
            }
            for ((key, _), set) in keys.iter().zip(built) {
                sets.insert(key.clone(), Arc::new(set));
            }
        }
        Ok(GeoSite { sets })
    }

    pub fn from_sets(sets: impl IntoIterator<Item = (String, DomainSet)>) -> GeoSite {
        GeoSite {
            sets: sets
                .into_iter()
                .map(|(k, v)| (k.to_lowercase(), Arc::new(v)))
                .collect(),
        }
    }

    pub fn get(&self, key: &str) -> Option<Arc<DomainSet>> {
        self.sets.get(&key.to_lowercase()).cloned()
    }

    /// Number of regex / unsupported-type rules dropped from list `key`.
    pub fn skipped_regex(&self, key: &str) -> usize {
        self.sets
            .get(&key.to_lowercase())
            .map_or(0, |s| s.skipped_regex)
    }
}

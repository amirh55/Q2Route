//! v2ray `geoip.dat` reader: country code -> set of CIDR ranges.
//!
//! The file is a protobuf `GeoIPList { repeated GeoIP entry = 1; }` with
//! `GeoIP { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3; }`
//! and `CIDR { bytes ip = 1; uint32 prefix = 2; }`. Only the codes asked for
//! are decoded; the rest are skipped by length.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
#[error("malformed geoip.dat: {0}")]
pub struct GeoIpError(pub(crate) &'static str);

/// Sorted, merged, inclusive address ranges.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

fn merge<T: Copy + Ord + num_like::Succ>(mut r: Vec<(T, T)>) -> Vec<(T, T)> {
    r.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(r.len());
    for (lo, hi) in r {
        match out.last_mut() {
            Some(last) if lo <= last.1.succ_sat() => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

mod num_like {
    pub trait Succ {
        fn succ_sat(self) -> Self;
    }
    impl Succ for u32 {
        fn succ_sat(self) -> Self {
            self.saturating_add(1)
        }
    }
    impl Succ for u128 {
        fn succ_sat(self) -> Self {
            self.saturating_add(1)
        }
    }
}

fn find<T: Copy + Ord>(ranges: &[(T, T)], x: T) -> bool {
    let i = ranges.partition_point(|r| r.0 <= x);
    i > 0 && x <= ranges[i - 1].1
}

impl IpSet {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => find(&self.v4, u32::from(a)),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) => find(&self.v4, u32::from(v4)),
                None => find(&self.v6, u128::from(a)),
            },
        }
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Build from `(ip, prefix)` pairs; invalid entries are skipped.
    pub fn from_cidrs(cidrs: &[(IpAddr, u8)]) -> IpSet {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for &(ip, prefix) in cidrs {
            match ip {
                IpAddr::V4(a) if prefix <= 32 => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - prefix)
                    };
                    let lo = u32::from(a) & mask;
                    v4.push((lo, lo | !mask));
                }
                IpAddr::V6(a) if prefix <= 128 => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - prefix)
                    };
                    let lo = u128::from(a) & mask;
                    v6.push((lo, lo | !mask));
                }
                _ => {}
            }
        }
        IpSet {
            v4: merge(v4),
            v6: merge(v6),
        }
    }
}

/// Country sets loaded from a `geoip.dat`, keyed by lowercase code.
#[derive(Debug, Default, Clone)]
pub struct GeoIp {
    sets: HashMap<String, Arc<IpSet>>,
}

pub(crate) struct Reader<'a> {
    pub(crate) b: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn done(&self) -> bool {
        self.b.is_empty()
    }

    fn varint(&mut self) -> Result<u64, GeoIpError> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = self.b.split_first().ok_or(GeoIpError("truncated varint"))?;
            self.b = rest;
            v |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(GeoIpError("varint too long"))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], GeoIpError> {
        if n > self.b.len() {
            return Err(GeoIpError("truncated field"));
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }

    /// Next field: (number, wire type, payload for length-delimited / varint value).
    pub(crate) fn field(&mut self) -> Result<(u64, Field<'a>), GeoIpError> {
        let key = self.varint()?;
        let f = match key & 7 {
            0 => Field::Varint(self.varint()?),
            1 => {
                self.take(8)?;
                Field::Other
            }
            2 => {
                let n = self.varint()? as usize;
                Field::Bytes(self.take(n)?)
            }
            5 => {
                self.take(4)?;
                Field::Other
            }
            _ => return Err(GeoIpError("unsupported wire type")),
        };
        Ok((key >> 3, f))
    }
}

pub(crate) enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Other,
}

fn entry_code(entry: &[u8]) -> Result<Option<String>, GeoIpError> {
    let mut r = Reader { b: entry };
    while !r.done() {
        if let (1, Field::Bytes(s)) = r.field()? {
            return Ok(Some(String::from_utf8_lossy(s).to_lowercase()));
        }
    }
    Ok(None)
}

fn decode_entry(entry: &[u8]) -> Result<Option<IpSet>, GeoIpError> {
    let mut r = Reader { b: entry };
    let mut cidrs = Vec::new();
    let mut reverse = false;
    while !r.done() {
        match r.field()? {
            (2, Field::Bytes(c)) => {
                let mut cr = Reader { b: c };
                let (mut ip, mut prefix) = (None, 0u64);
                while !cr.done() {
                    match cr.field()? {
                        (1, Field::Bytes(b)) => {
                            ip = match b.len() {
                                4 => Some(IpAddr::from(<[u8; 4]>::try_from(b).unwrap())),
                                16 => Some(IpAddr::from(<[u8; 16]>::try_from(b).unwrap())),
                                _ => None,
                            }
                        }
                        (2, Field::Varint(p)) => prefix = p,
                        _ => {}
                    }
                }
                if let Some(ip) = ip {
                    cidrs.push((ip, prefix.min(255) as u8));
                }
            }
            (3, Field::Varint(v)) => reverse = v != 0,
            _ => {}
        }
    }
    // A reversed set means "everything except"; not supported, so it is
    // treated as unknown (matches nothing) rather than guessed.
    Ok((!reverse).then(|| IpSet::from_cidrs(&cidrs)))
}

impl GeoIp {
    /// Decode only the country codes in `wanted` (case-insensitive).
    pub fn parse(data: &[u8], wanted: &[String]) -> Result<GeoIp, GeoIpError> {
        let wanted: Vec<String> = wanted.iter().map(|w| w.to_lowercase()).collect();
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
            if wanted.contains(&code) {
                if let Some(set) = decode_entry(entry)? {
                    sets.insert(code, Arc::new(set));
                }
            }
        }
        Ok(GeoIp { sets })
    }

    pub fn from_sets(sets: impl IntoIterator<Item = (String, IpSet)>) -> GeoIp {
        GeoIp {
            sets: sets
                .into_iter()
                .map(|(k, v)| (k.to_lowercase(), Arc::new(v)))
                .collect(),
        }
    }

    pub fn get(&self, code: &str) -> Option<Arc<IpSet>> {
        self.sets.get(&code.to_lowercase()).cloned()
    }

    pub fn codes(&self) -> impl Iterator<Item = &str> {
        self.sets.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    fn bytes_field(num: u64, payload: &[u8], out: &mut Vec<u8>) {
        varint(num << 3 | 2, out);
        varint(payload.len() as u64, out);
        out.extend_from_slice(payload);
    }

    fn entry(code: &str, cidrs: &[(&[u8], u64)], reverse: bool) -> Vec<u8> {
        let mut e = Vec::new();
        bytes_field(1, code.as_bytes(), &mut e);
        for (ip, prefix) in cidrs {
            let mut c = Vec::new();
            bytes_field(1, ip, &mut c);
            varint(2 << 3, &mut c);
            varint(*prefix, &mut c);
            bytes_field(2, &c, &mut e);
        }
        if reverse {
            varint(3 << 3, &mut e);
            varint(1, &mut e);
        }
        e
    }

    fn file(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut f = Vec::new();
        for e in entries {
            bytes_field(1, e, &mut f);
        }
        f
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_wanted_codes_only() {
        let data = file(&[
            entry("US", &[(&[8, 8, 8, 0], 24)], false),
            entry(
                "IR",
                &[(&[185, 188, 104, 0], 22), (&[2, 189, 58, 0], 24)],
                false,
            ),
        ]);
        let g = GeoIp::parse(&data, &["ir".into()]).unwrap();
        assert!(g.get("us").is_none());
        let ir = g.get("IR").unwrap();
        assert!(ir.contains(ip("185.188.107.12")));
        assert!(ir.contains(ip("2.189.58.63")));
        assert!(!ir.contains(ip("185.188.108.1")));
        assert!(!ir.contains(ip("8.8.8.8")));
    }

    #[test]
    fn ipv6_and_mapped() {
        let v6: [u8; 16] = "2a01:5ec0::"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets();
        let data = file(&[entry("ir", &[(&v6, 29), (&[5, 160, 0, 0], 16)], false)]);
        let ir = GeoIp::parse(&data, &["ir".into()])
            .unwrap()
            .get("ir")
            .unwrap();
        assert!(ir.contains(ip("2a01:5ec0:1::1")));
        assert!(!ir.contains(ip("2a01:5ec8::1")));
        assert!(ir.contains(ip("::ffff:5.160.1.1")));
    }

    #[test]
    fn reverse_match_entries_are_ignored() {
        let data = file(&[entry("ir", &[(&[1, 0, 0, 0], 8)], true)]);
        assert!(GeoIp::parse(&data, &["ir".into()])
            .unwrap()
            .get("ir")
            .is_none());
    }

    #[test]
    fn overlapping_ranges_merge() {
        let s = IpSet::from_cidrs(&[
            (ip("10.0.0.0"), 8),
            (ip("10.1.0.0"), 16),
            (ip("11.0.0.0"), 8),
        ]);
        assert_eq!(s.len(), 1);
        assert!(s.contains(ip("11.255.255.255")));
        assert!(!s.contains(ip("12.0.0.0")));
    }

    #[test]
    fn truncated_file_errors() {
        let mut data = file(&[entry("ir", &[(&[1, 2, 3, 0], 24)], false)]);
        data.truncate(data.len() - 2);
        assert!(GeoIp::parse(&data, &["ir".into()]).is_err());
    }

    /// Reads the real file when present (v2rayN's copy on the dev machine).
    #[test]
    fn real_file_has_ir() {
        let p = std::path::Path::new(r"C:\v2rayN\bin\geoip.dat");
        let Ok(data) = std::fs::read(p) else { return };
        let ir = GeoIp::parse(&data, &["ir".into()])
            .unwrap()
            .get("ir")
            .unwrap();
        assert!(ir.len() > 100, "only {} ranges", ir.len());
        assert!(ir.contains(ip("185.188.107.12")), "digikala");
        assert!(!ir.contains(ip("8.8.8.8")));
    }
}

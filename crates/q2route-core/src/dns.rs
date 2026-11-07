//! Minimal hand-written DNS wire helpers. Everything here treats its input as
//! hostile: no indexing that can panic, bounded loops, `None`/empty on any problem.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const HEADER: usize = 12;
const MAX_NAME: usize = 255;
const MAX_HOPS: usize = 16;
/// CNAME records considered per response; further ones are ignored.
pub const MAX_CNAMES: usize = 32;

/// A parsed client query (first question only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query<'a> {
    pub id: u16,
    /// Lowercase, no trailing dot.
    pub name: String,
    pub qtype: u16,
    pub raw: &'a [u8],
}

fn u16_at(m: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*m.get(i)?, *m.get(i + 1)?]))
}

/// Reads a name at `pos`, following compression pointers when `compress` is
/// set. Returns the lowercase dotted name and the offset just past the name's
/// in-place encoding.
fn read_name(m: &[u8], pos: usize, compress: bool) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut p = pos;
    let mut end: Option<usize> = None;
    let mut hops = 0;
    let mut wire_len = 1; // terminating root label
    loop {
        let len = *m.get(p)? as usize;
        match len & 0xc0 {
            0 => {
                if len == 0 {
                    return Some((out, end.unwrap_or(p + 1)));
                }
                let label = m.get(p + 1..p + 1 + len)?;
                wire_len += len + 1;
                if wire_len > MAX_NAME {
                    return None;
                }
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(std::str::from_utf8(label).ok()?);
                p += 1 + len;
            }
            0xc0 if compress => {
                hops += 1;
                if hops > MAX_HOPS {
                    return None;
                }
                let target = ((len & 0x3f) << 8) | *m.get(p + 1)? as usize;
                end.get_or_insert(p + 2);
                p = target;
            }
            _ => return None,
        }
    }
}

/// End offset of the first question, and its (name, qtype).
fn first_question(m: &[u8]) -> Option<(String, u16, usize)> {
    if m.len() < HEADER || u16_at(m, 4)? != 1 {
        return None;
    }
    let (name, p) = read_name(m, HEADER, false)?;
    let qtype = u16_at(m, p)?;
    u16_at(m, p + 2)?; // qclass must be present
    Some((name.to_ascii_lowercase(), qtype, p + 4))
}

/// Parses a client query: QR=0, QDCOUNT == 1 (anything else is malformed). Compressed
/// names in the question and names over 255 bytes are rejected.
pub fn parse_query(msg: &[u8]) -> Option<Query<'_>> {
    if msg.get(2)? & 0x80 != 0 {
        return None;
    }
    let (name, qtype, _) = first_question(msg)?;
    Some(Query {
        id: u16_at(msg, 0)?,
        name,
        qtype,
        raw: msg,
    })
}

/// Response skeleton: header + first question only, no records.
fn reply(query: &[u8], tc: bool, rcode: u8) -> Option<Vec<u8>> {
    let (_, _, end) = first_question(query)?;
    let mut r = query.get(..end)?.to_vec();
    // QR=1, keep opcode and RD; clear AA/TC then set TC if asked.
    r[2] = ((r[2] | 0x80) & !0x06) | if tc { 0x02 } else { 0 };
    r[3] = 0x80 | rcode; // RA + RCODE
    r[4..12].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    Some(r)
}

/// REFUSED (RCODE 5) answer to `query`.
pub fn refused(query: &[u8]) -> Option<Vec<u8>> {
    reply(query, false, 5)
}

/// Empty NOERROR answer with TC=1 (tells the client to retry over TCP).
pub fn truncated(query: &[u8]) -> Option<Vec<u8>> {
    reply(query, true, 0)
}

/// Copy of `msg` with the transaction id replaced (unchanged if too short).
pub fn with_id(msg: &[u8], id: u16) -> Vec<u8> {
    let mut v = msg.to_vec();
    if v.len() >= 2 {
        v[..2].copy_from_slice(&id.to_be_bytes());
    }
    v
}

/// Transaction id of a response (QR=1) message.
pub fn response_id(msg: &[u8]) -> Option<u16> {
    if msg.len() < HEADER || msg[2] & 0x80 == 0 {
        return None;
    }
    u16_at(msg, 0)
}

/// `(question name, [(address, ttl secs)])` for every A/AAAA in the answer
/// section attributed to the first question's name: CNAME chains are followed
/// by attribution and compression pointers (16-hop limit). The list is empty
/// on any parse problem.
pub fn answers(msg: &[u8]) -> (Option<String>, Vec<(IpAddr, u32)>) {
    match parse_answers(msg) {
        Some((name, v)) => (Some(name), v),
        None => (None, Vec::new()),
    }
}

fn parse_answers(m: &[u8]) -> Option<(String, Vec<(IpAddr, u32)>)> {
    if m.len() < HEADER || m[2] & 0x80 == 0 {
        return None;
    }
    let qd = u16_at(m, 4)?;
    let an = u16_at(m, 6)?;
    let (qname, _) = read_name(m, HEADER, true)?;
    let qname = qname.to_ascii_lowercase();
    // Skip every question.
    let mut p = HEADER;
    for _ in 0..qd {
        let (_, e) = read_name(m, p, true)?;
        p = e.checked_add(4)?;
    }
    if qd == 0 {
        return None;
    }
    // (owner, cname target) and (owner, ip, ttl).
    let mut cnames: Vec<(String, String)> = Vec::new();
    let mut addrs: Vec<(String, IpAddr, u32)> = Vec::new();
    for _ in 0..an {
        let (owner, e) = read_name(m, p, true)?;
        let owner = owner.to_ascii_lowercase();
        let ty = u16_at(m, e)?;
        let ttl = u32::from_be_bytes(m.get(e + 4..e + 8)?.try_into().ok()?);
        let rdlen = u16_at(m, e + 8)? as usize;
        let rd = e + 10;
        let data = m.get(rd..rd.checked_add(rdlen)?)?;
        match ty {
            1 if rdlen == 4 => {
                let a: [u8; 4] = data.try_into().ok()?;
                addrs.push((owner, IpAddr::V4(Ipv4Addr::from(a)), ttl));
            }
            28 if rdlen == 16 => {
                let a: [u8; 16] = data.try_into().ok()?;
                addrs.push((owner, IpAddr::V6(Ipv6Addr::from(a)), ttl));
            }
            5 if cnames.len() < MAX_CNAMES => {
                let (target, _) = read_name(m, rd, true)?;
                cnames.push((owner, target.to_ascii_lowercase()));
            }
            _ => {}
        }
        p = rd + rdlen;
    }
    // Names that belong to the question: follow CNAMEs to a fixpoint.
    let mut names = vec![qname.clone()];
    loop {
        let before = names.len();
        for (owner, target) in &cnames {
            if names.contains(owner) && !names.contains(target) {
                names.push(target.clone());
            }
        }
        if names.len() == before {
            break;
        }
    }
    let out = addrs
        .into_iter()
        .filter(|(o, _, _)| names.contains(o))
        .map(|(_, ip, ttl)| (ip, ttl))
        .collect();
    Some((qname, out))
}

/// Well-known DNS-over-HTTPS endpoints.
pub const DOH_HOSTS: &[&str] = &[
    "dns.google",
    "dns.google.com",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "chrome.cloudflare-dns.com",
    "one.one.one.one",
    "1dot1dot1dot1.cloudflare-dns.com",
    "dns.quad9.net",
    "dns9.quad9.net",
    "doh.opendns.com",
    "dns.adguard-dns.com",
    "doh.cleanbrowsing.org",
    "dns.nextdns.io",
];

/// Exact match against [`DOH_HOSTS`], case-insensitive, trailing dot ignored.
pub fn is_doh_host(name: &str) -> bool {
    let n = name.strip_suffix('.').unwrap_or(name);
    DOH_HOSTS.iter().any(|h| h.eq_ignore_ascii_case(n))
}

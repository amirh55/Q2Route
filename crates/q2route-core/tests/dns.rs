use q2route_core::dns::*;
use std::net::IpAddr;

fn qname(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for l in name.trim_end_matches('.').split('.') {
        v.push(l.len() as u8);
        v.extend_from_slice(l.as_bytes());
    }
    v.push(0);
    v
}

fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = vec![
        (id >> 8) as u8,
        id as u8,
        0x01,
        0x00,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    m.extend(qname(name));
    m.extend([(qtype >> 8) as u8, qtype as u8, 0, 1]);
    m
}

#[test]
fn parse_query_basic() {
    let m = query(0xabcd, "WWW.Digikala.COM.", 1);
    let q = parse_query(&m).unwrap();
    assert_eq!(q.id, 0xabcd);
    assert_eq!(q.name, "www.digikala.com");
    assert_eq!(q.qtype, 1);
    assert_eq!(q.raw, &m[..]);
}

#[test]
fn parse_query_rejects() {
    let good = query(1, "a.example", 1);
    let mut resp = good.clone();
    resp[2] |= 0x80;
    assert!(parse_query(&resp).is_none());
    let mut zero = good.clone();
    zero[5] = 0;
    assert!(parse_query(&zero).is_none());
    assert!(parse_query(&good[..11]).is_none());
    assert!(parse_query(&[]).is_none());
    // compressed qname
    let mut comp = good[..12].to_vec();
    comp.extend([0xc0, 0x0c, 0, 1, 0, 1]);
    assert!(parse_query(&comp).is_none());
    // label > 63
    let mut long = good[..12].to_vec();
    long.push(64);
    long.extend(vec![b'a'; 64]);
    long.extend([0, 0, 1, 0, 1]);
    assert!(parse_query(&long).is_none());
    // truncated question
    assert!(parse_query(&good[..good.len() - 3]).is_none());
    // name > 255 bytes
    let mut big = good[..12].to_vec();
    for _ in 0..5 {
        big.push(60);
        big.extend(vec![b'a'; 60]);
    }
    big.extend([0, 0, 1, 0, 1]);
    assert!(parse_query(&big).is_none());
}

#[test]
fn refused_and_truncated_shape() {
    let mut m = query(0x1234, "a.example", 1);
    m[9] = 1; // NSCOUNT junk
    m[11] = 1; // ARCOUNT junk
    let r = refused(&m).unwrap();
    assert_eq!(&r[..2], &[0x12, 0x34]);
    assert_eq!(&r[2..4], &[0x81, 0x85]); // QR RD, RA RCODE=5
    assert_eq!(&r[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&r[12..], &m[12..]);
    let t = truncated(&m).unwrap();
    assert_eq!(&t[2..4], &[0x83, 0x80]); // QR TC RD, RA RCODE=0
    assert_eq!(&t[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&t[12..], &r[12..]);
    assert!(refused(&m[..5]).is_none());
    assert!(truncated(&[]).is_none());
}

#[test]
fn with_id_and_response_id() {
    let m = query(1, "a.example", 1);
    let n = with_id(&m, 0xbeef);
    assert_eq!(&n[..2], &[0xbe, 0xef]);
    assert_eq!(&n[2..], &m[2..]);
    assert_eq!(with_id(&[7], 9), vec![7]);
    assert_eq!(response_id(&m), None);
    let r = refused(&n).unwrap();
    assert_eq!(response_id(&r), Some(0xbeef));
    assert_eq!(response_id(&r[..1]), None);
}

fn rr(name: &[u8], t: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut v = name.to_vec();
    v.extend([(t >> 8) as u8, t as u8, 0, 1]);
    v.extend(ttl.to_be_bytes());
    v.extend((rdata.len() as u16).to_be_bytes());
    v.extend(rdata);
    v
}

#[test]
fn answers_follow_cname() {
    let mut m = query(5, "a.example", 1);
    m[2] = 0x81;
    m[3] = 0x80;
    m[7] = 3; // ANCOUNT
    let b_cdn = qname("b.cdn");
    m.extend(rr(&[0xc0, 0x0c], 5, 60, &b_cdn));
    let b_off = (m.len() - b_cdn.len()) as u8; // offset of the rdata name
    m.extend(rr(&[0xc0, b_off], 1, 300, &[1, 2, 3, 4]));
    let mut v6 = [0u8; 16];
    v6[15] = 1;
    m.extend(rr(&[0xc0, b_off], 28, 120, &v6));
    let (name, ans) = answers(&m);
    assert_eq!(name.as_deref(), Some("a.example"));
    assert_eq!(
        ans,
        vec![
            ("1.2.3.4".parse::<IpAddr>().unwrap(), 300),
            ("::1".parse::<IpAddr>().unwrap(), 120)
        ]
    );
}

#[test]
fn answers_compression_loop_is_empty() {
    let mut m = query(5, "a.example", 1);
    m[2] = 0x81;
    m[7] = 1;
    let off = m.len() as u8;
    m.extend(rr(&[0xc0, off], 1, 10, &[1, 1, 1, 1]));
    let (_, ans) = answers(&m);
    assert!(ans.is_empty());
    // truncations never panic
    for n in 0..m.len() {
        let _ = answers(&m[..n]);
    }
}

#[test]
fn doh_hosts() {
    assert!(is_doh_host("DNS.Google."));
    assert!(is_doh_host("cloudflare-dns.com"));
    assert!(!is_doh_host("google.com"));
    assert!(!is_doh_host("www.dns.google"));
    assert_eq!(DOH_HOSTS.len(), 13);
}

#[test]
fn qdcount_must_be_one() {
    let mut m = query(1, "a.example", 1);
    m[5] = 2;
    assert!(parse_query(&m).is_none());
    assert!(refused(&m).is_none());
    assert!(truncated(&m).is_none());
}

#[test]
fn many_cnames_are_capped() {
    let mut m = query(5, "c0.example", 1);
    m[2] = 0x81;
    let n = 1000usize;
    m[6] = ((n + 2) >> 8) as u8;
    m[7] = (n + 2) as u8;
    for i in 0..n {
        m.extend(rr(
            &qname(&format!("c{i}.example")),
            5,
            60,
            &qname(&format!("c{}.example", i + 1)),
        ));
    }
    m.extend(rr(&qname("c5.example"), 1, 10, &[5, 5, 5, 5]));
    m.extend(rr(&qname("c999.example"), 1, 10, &[9, 9, 9, 9]));
    let t = std::time::Instant::now();
    let (_, ans) = answers(&m);
    assert!(t.elapsed().as_secs() < 1);
    assert_eq!(ans, vec![("5.5.5.5".parse::<IpAddr>().unwrap(), 10)]);
    assert_eq!(MAX_CNAMES, 32);
}

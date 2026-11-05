use q2route_core::peek::{peek_host, PeekResult};

fn u16be(v: usize) -> [u8; 2] {
    (v as u16).to_be_bytes()
}

fn ext(ty: u16, body: &[u8]) -> Vec<u8> {
    let mut e = ty.to_be_bytes().to_vec();
    e.extend(u16be(body.len()));
    e.extend(body);
    e
}

/// Deterministic TLS 1.3-style ClientHello record. SNI is the LAST extension.
fn build_client_hello(sni: &str) -> Vec<u8> {
    let mut exts = Vec::new();
    exts.extend(ext(0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03])); // supported_versions
    exts.extend(ext(0x000a, &[0x00, 0x04, 0x00, 0x1d, 0x00, 0x17])); // supported_groups
    let mut alpn = Vec::new();
    alpn.extend([0x02, b'h', b'2']);
    alpn.extend([0x08]);
    alpn.extend(b"http/1.1");
    let mut alpn_body = u16be(alpn.len()).to_vec();
    alpn_body.extend(alpn);
    exts.extend(ext(0x0010, &alpn_body)); // ALPN
    let mut sni_body = Vec::new();
    sni_body.push(0u8);
    sni_body.extend(u16be(sni.len()));
    sni_body.extend(sni.as_bytes());
    let mut sni_list = u16be(sni_body.len()).to_vec();
    sni_list.extend(sni_body);
    exts.extend(ext(0x0000, &sni_list));

    let mut body = vec![0x03, 0x03];
    body.extend((0..32u8).map(|i| i.wrapping_mul(7)));
    body.push(32);
    body.extend((0..32u8).map(|i| i.wrapping_add(100)));
    body.extend(u16be(4));
    body.extend([0x13, 0x01, 0x13, 0x02]);
    body.extend([1, 0]);
    body.extend(u16be(exts.len()));
    body.extend(exts);

    let mut hs = vec![0x01, 0, 0, 0];
    let l = body.len();
    hs[1] = (l >> 16) as u8;
    hs[2] = (l >> 8) as u8;
    hs[3] = l as u8;
    hs.extend(body);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend(u16be(hs.len()));
    rec.extend(hs);
    rec
}

fn fixture() -> Vec<u8> {
    let built = build_client_hello("www.digikala.ir");
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/clienthello.bin");
    if std::env::var("Q2_REGEN_FIXTURE").is_ok() {
        std::fs::write(path, &built).unwrap();
    }
    let on_disk = std::fs::read(path).unwrap();
    assert_eq!(on_disk, built, "fixture drifted from generator");
    on_disk
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn tls_sni() {
    assert_eq!(
        peek_host(&fixture()),
        PeekResult::Host("www.digikala.ir".into())
    );
}

#[test]
fn tls_truncated() {
    let f = fixture();
    assert_eq!(peek_host(&f[..20]), PeekResult::NeedMore);
    for n in 0..f.len() {
        assert_eq!(peek_host(&f[..n]), PeekResult::NeedMore, "len {n}");
    }
}

#[test]
fn tls_no_sni_is_not_found() {
    let mut f = build_client_hello("a.b");
    // Corrupt the SNI extension type (last ext) so no SNI exists.
    let pos = f.len() - 12; // 4-byte ext header + 8-byte body for "a.b"
    f[pos + 1] = 0x99;
    assert_eq!(peek_host(&f), PeekResult::NotFound);
}

#[test]
fn http_host() {
    let r = b"GET / HTTP/1.1\r\nHost: Example.IR:8080\r\n\r\n";
    assert_eq!(peek_host(r), PeekResult::Host("example.ir".into()));
    let r = b"POST /x HTTP/1.0\r\nUser-Agent: a\r\nhOsT:   www.Foo.com  \r\n\r\n";
    assert_eq!(peek_host(r), PeekResult::Host("www.foo.com".into()));
}

#[test]
fn http_partial_needs_more() {
    assert_eq!(
        peek_host(b"GET / HTTP/1.1\r\nUser-Agent: x\r\n"),
        PeekResult::NeedMore
    );
    assert_eq!(peek_host(b"GET / HT"), PeekResult::NeedMore);
    assert_eq!(peek_host(b"GE"), PeekResult::NeedMore);
    // Complete headers but no Host header.
    assert_eq!(peek_host(b"GET / HTTP/1.0\r\n\r\n"), PeekResult::NotFound);
}

#[test]
fn garbage() {
    let mut x = XorShift(0x9E3779B97F4A7C15);
    let buf: Vec<u8> = (0..1000).map(|_| (x.next() >> 24) as u8).collect();
    let mut buf = buf;
    buf[0] = 0xff; // definitely neither TLS nor HTTP
    assert_eq!(peek_host(&buf), PeekResult::NotFound);
}

#[test]
fn never_panics() {
    let mut x = XorShift(0x1234_5678_9ABC_DEF1);
    let f = fixture();
    for _ in 0..20_000 {
        let len = (x.next() % 300) as usize;
        let buf: Vec<u8> = (0..len).map(|_| x.next() as u8).collect();
        let _ = peek_host(&buf);
        // Mutated valid hello.
        let mut m = f.clone();
        for _ in 0..4 {
            let i = (x.next() as usize) % m.len();
            m[i] = x.next() as u8;
        }
        let cut = (x.next() as usize) % (m.len() + 1);
        let _ = peek_host(&m[..cut]);
        let mut h = b"GET / HTTP/1.1\r\nHost: a.b\r\n\r\n".to_vec();
        let i = (x.next() as usize) % h.len();
        h[i] = x.next() as u8;
        let _ = peek_host(&h);
    }
}

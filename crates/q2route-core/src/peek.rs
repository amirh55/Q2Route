//! Best-effort extraction of the destination host name from the first client
//! bytes of a flow: TLS ClientHello SNI or an HTTP/1.x `Host:` header.
//! Never panics on arbitrary input.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeekResult {
    /// Lowercased host name (no port).
    Host(String),
    /// Input is a plausible prefix; more bytes are needed to decide.
    NeedMore,
    /// Not TLS/HTTP, or no host present.
    NotFound,
}

const HTTP_METHODS: [&[u8]; 9] = [
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"CONNECT ", b"OPTIONS ", b"TRACE ",
    b"PATCH ",
];
/// Give up looking for the end of HTTP headers after this many bytes.
const MAX_HTTP_HEAD: usize = 16 * 1024;

/// Returns `NeedMore` until the whole first TLS record has arrived, so callers
/// must bound the wait with their own timeout and buffer cap.
pub fn peek_host(buf: &[u8]) -> PeekResult {
    match buf.first() {
        None => PeekResult::NeedMore,
        Some(0x16) => peek_tls(buf),
        Some(_) => peek_http(buf),
    }
}

/// Bounds-checked big-endian cursor.
struct Cur<'a>(&'a [u8]);

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<usize> {
        self.take(1).map(|b| b[0] as usize)
    }
    fn u16(&mut self) -> Option<usize> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
    }
    fn u24(&mut self) -> Option<usize> {
        self.take(3).map(|b| (b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
}

fn peek_tls(buf: &[u8]) -> PeekResult {
    if buf.len() < 5 {
        return PeekResult::NeedMore;
    }
    if buf[1] != 3 {
        return PeekResult::NotFound;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + rec_len {
        return PeekResult::NeedMore;
    }
    match parse_client_hello(&buf[5..5 + rec_len]) {
        Some(h) => PeekResult::Host(h),
        None => PeekResult::NotFound,
    }
}

fn parse_client_hello(rec: &[u8]) -> Option<String> {
    let mut c = Cur(rec);
    if c.u8()? != 1 {
        return None; // not ClientHello
    }
    let len = c.u24()?;
    let mut c = Cur(c.take(len)?);
    c.take(2 + 32)?; // version + random
    let sid = c.u8()?;
    c.take(sid)?;
    let cs = c.u16()?;
    c.take(cs)?;
    let comp = c.u8()?;
    c.take(comp)?;
    let ext_len = c.u16()?;
    let mut exts = Cur(c.take(ext_len)?);
    while !exts.0.is_empty() {
        let ty = exts.u16()?;
        let l = exts.u16()?;
        let body = exts.take(l)?;
        if ty == 0 {
            return parse_sni(body);
        }
    }
    None
}

fn parse_sni(body: &[u8]) -> Option<String> {
    let mut c = Cur(body);
    let list_len = c.u16()?;
    let mut list = Cur(c.take(list_len)?);
    while !list.0.is_empty() {
        let name_type = list.u8()?;
        let l = list.u16()?;
        let name = list.take(l)?;
        if name_type == 0 {
            let s = std::str::from_utf8(name).ok()?;
            return normalize(s);
        }
    }
    None
}

fn peek_http(buf: &[u8]) -> PeekResult {
    let mut maybe = false;
    let mut is_http = false;
    for m in HTTP_METHODS {
        if buf.starts_with(m) {
            is_http = true;
            break;
        }
        if m.starts_with(buf) {
            maybe = true;
        }
    }
    if !is_http {
        return if maybe { PeekResult::NeedMore } else { PeekResult::NotFound };
    }
    let (mut head, complete) = match find(buf, b"\r\n\r\n") {
        Some(i) => (&buf[..i], true),
        None => (buf, false),
    };
    if !complete {
        // The last line may be cut mid-way; only trust fully terminated lines.
        head = &head[..head.iter().rposition(|&b| b == b'\n').unwrap_or(0)];
    }
    // Skip the request line.
    for line in head.split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else { continue };
        if line[..colon].eq_ignore_ascii_case(b"host") {
            return match std::str::from_utf8(&line[colon + 1..]).ok().and_then(normalize) {
                Some(h) => PeekResult::Host(h),
                None => PeekResult::NotFound,
            };
        }
    }
    if complete || buf.len() >= MAX_HTTP_HEAD {
        PeekResult::NotFound
    } else {
        PeekResult::NeedMore
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Trim, strip `:port` (IPv6 literals in brackets handled), lowercase, drop trailing dot.
fn normalize(s: &str) -> Option<String> {
    let s = s.trim();
    let host = if let Some(rest) = s.strip_prefix('[') {
        &rest[..rest.find(']')?]
    } else {
        s.split(':').next().unwrap_or("")
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        None
    } else {
        Some(host)
    }
}

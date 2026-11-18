use q2route_core::leak::*;
use std::net::IpAddr;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

async fn serve(response: Vec<u8>) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<String>) {
    let (client, mut server) = duplex(256 * 1024);
    let h = tokio::spawn(async move {
        let mut req = Vec::new();
        let mut b = [0u8; 1024];
        while !req.ends_with(b"\r\n\r\n") {
            let n = server.read(&mut b).await.unwrap();
            if n == 0 {
                break;
            }
            req.extend_from_slice(&b[..n]);
        }
        let _ = server.write_all(&response).await;
        // dropping `server` closes the stream (EOF)
        String::from_utf8_lossy(&req).to_string()
    });
    (client, h)
}

#[tokio::test]
async fn http_get_content_length() {
    let (c, h) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA".to_vec()).await;
    let body = http_get(c, "example.com", "/x").await.unwrap();
    assert_eq!(body, "hello");
    let req = h.await.unwrap();
    assert!(req.starts_with("GET /x HTTP/1.1\r\n"));
    assert!(req.contains("Host: example.com\r\n"));
    assert!(req.contains("User-Agent: q2route-leak-check\r\n"));
    assert!(req.contains("Connection: close\r\n"));
}

#[tokio::test]
async fn http_get_chunked() {
    let (c, _h) = serve(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n"
            .to_vec(),
    )
    .await;
    assert_eq!(http_get(c, "h", "/").await.unwrap(), "abcdefg");
}

#[tokio::test]
async fn http_get_until_eof() {
    let (c, _h) = serve(b"HTTP/1.1 200 OK\r\n\r\n2400:cb00::1".to_vec()).await;
    assert_eq!(http_get(c, "h", "/").await.unwrap(), "2400:cb00::1");
}

#[tokio::test]
async fn http_non_200_is_error() {
    let (c, _h) =
        serve(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
    assert!(matches!(
        http_get(c, "h", "/").await,
        Err(LeakError::Http(_))
    ));
}

#[tokio::test]
async fn http_body_cap() {
    let mut r = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
    r.extend(std::iter::repeat_n(b'a', 65 * 1024));
    let (c, _h) = serve(r).await;
    assert!(http_get(c, "h", "/").await.is_err());
}

#[test]
fn ip_api_path_forms() {
    assert_eq!(
        ip_api_path(None),
        "/json/?fields=status,message,country,countryCode,isp,query"
    );
    assert_eq!(
        ip_api_path(Some("1.2.3.4".parse().unwrap())),
        "/json/1.2.3.4?fields=status,message,country,countryCode,isp,query"
    );
}

#[test]
fn parse_ip_api_ok() {
    let i = parse_ip_api(
        r#"{"status":"success","country":"Germany","countryCode":"DE","isp":"Hetzner","query":"141.98.7.5"}"#,
    )
    .unwrap();
    assert_eq!(i.ip, "141.98.7.5".parse::<IpAddr>().unwrap());
    assert_eq!(i.country, "Germany");
    assert_eq!(i.country_code, "DE");
    assert_eq!(i.isp, "Hetzner");
}

#[test]
fn parse_ip_api_fail() {
    let e = parse_ip_api(r#"{"status":"fail","message":"reserved range","query":"10.0.0.1"}"#)
        .unwrap_err();
    assert!(e.to_string().contains("reserved range"));
    assert!(matches!(parse_ip_api("nope"), Err(LeakError::Parse(_))));
}

#[test]
fn parse_resolver_txt_ip_and_ecs() {
    let (ip, ecs) = parse_resolver_txt(&[
        "2400:cb00::1".to_string(),
        "edns0-client-subnet 141.98.7.0/24".to_string(),
    ]);
    assert_eq!(ip, Some("2400:cb00::1".parse().unwrap()));
    assert_eq!(ecs, Some("141.98.7.0".parse().unwrap()));
}

#[test]
fn parse_resolver_txt_garbage() {
    let (ip, ecs) = parse_resolver_txt(&["hello".into(), "edns0-client-subnet nope".into()]);
    assert_eq!((ip, ecs), (None, None));
}

fn info(ip: &str, cc: &str, country: &str, isp: &str) -> IpInfo {
    IpInfo {
        ip: ip.parse().unwrap(),
        country: country.into(),
        country_code: cc.into(),
        isp: isp.into(),
    }
}
fn de() -> IpInfo {
    info("141.98.7.5", "DE", "Germany", "Hetzner")
}
fn ir() -> IpInfo {
    info("5.200.1.1", "IR", "Iran", "Irancell")
}
fn proxy() -> ProbeRoute {
    ProbeRoute::Proxy {
        group: "proxy".into(),
    }
}
fn direct() -> ProbeRoute {
    ProbeRoute::Direct {
        group: Some("direct".into()),
    }
}
fn got(i: IpInfo, route: ProbeRoute) -> Probe {
    Probe {
        outcome: ProbeOutcome::Got(i),
        route,
    }
}
fn failed(route: ProbeRoute) -> Probe {
    Probe {
        outcome: ProbeOutcome::Failed("timeout".into()),
        route,
    }
}
fn refused(route: ProbeRoute) -> Probe {
    Probe {
        outcome: ProbeOutcome::Refused("status HTTP/1.1 429 Too Many Requests".into()),
        route,
    }
}
fn no_v6() -> Probe {
    Probe {
        outcome: ProbeOutcome::NoIpv6,
        route: ProbeRoute::Unknown,
    }
}
fn base() -> LeakInputs {
    LeakInputs {
        running: true,
        ipv4: got(de(), proxy()),
        dns: got(de(), proxy()),
        dns_subnet: None,
        ipv6: no_v6(),
    }
}

#[test]
fn verdict_all_foreign_is_no_leak() {
    let v = verdict(&base());
    assert_eq!(v.level, Level::NoLeak);
    assert_eq!(
        v.headline,
        "No leak: proxied apps appear as 141.98.7.5 (Germany, Hetzner)"
    );
    assert_eq!(v.lines.len(), 3);
    assert_eq!(
        v.lines[0],
        "IPv4: 141.98.7.5 (Germany, Hetzner) \u{2014} via proxy"
    );
    assert_eq!(v.lines[1], "DNS: resolver 141.98.7.5 (Germany, Hetzner)");
}

#[test]
fn verdict_ipv4_ir_is_leak() {
    let mut i = base();
    i.ipv4 = got(ir(), proxy());
    let v = verdict(&i);
    assert_eq!(v.level, Level::Leak);
    assert_eq!(v.headline, "LEAK: IPv4 appear from Iran");
}

#[test]
fn verdict_dns_leak() {
    let mut i = base();
    i.dns = got(ir(), proxy());
    let v = verdict(&i);
    assert_eq!(v.level, Level::Leak);
    assert_eq!(v.headline, "LEAK: DNS appear from Iran");
}

#[test]
fn verdict_ipv6_ir_is_leak() {
    let mut i = base();
    i.ipv4 = got(ir(), proxy());
    i.ipv6 = got(info("2a00::1", "IR", "Iran", "X"), proxy());
    let v = verdict(&i);
    assert_eq!(v.level, Level::Leak);
    assert_eq!(v.headline, "LEAK: IPv4, IPv6 appear from Iran");
}

#[test]
fn verdict_stopped_is_cant_tell() {
    let mut i = base();
    i.running = false;
    i.ipv4 = got(ir(), direct());
    let v = verdict(&i);
    assert_eq!(v.level, Level::CantTell);
    assert_eq!(
        v.headline,
        "Can't tell: Q2Route is stopped (everything goes direct)"
    );
    assert!(v.lines.is_empty());
}

#[test]
fn verdict_direct_route_is_cant_tell() {
    let mut i = base();
    i.ipv4 = got(ir(), direct());
    let v = verdict(&i);
    assert_eq!(v.level, Level::CantTell);
    assert_eq!(
        v.headline,
        "Can't tell: this check was routed Direct by \"direct\""
    );
    // a Direct probe elsewhere is named when IPv4 is not Direct
    let mut j = base();
    j.dns = got(
        de(),
        ProbeRoute::Direct {
            group: Some("dns-direct".into()),
        },
    );
    assert_eq!(
        verdict(&j).headline,
        "Can't tell: this check was routed Direct by \"dns-direct\""
    );
}

#[test]
fn verdict_ir_via_non_direct_beats_direct_elsewhere() {
    let mut i = base();
    i.ipv4 = got(ir(), proxy());
    i.dns = got(de(), direct());
    assert_eq!(verdict(&i).level, Level::Leak);
}

#[test]
fn verdict_proxy_down_is_no_leak_with_note() {
    let mut i = base();
    i.ipv4 = failed(proxy());
    i.dns = failed(proxy());
    let v = verdict(&i);
    assert_eq!(v.level, Level::NoLeak);
    assert_eq!(
        v.headline,
        "No leak, but proxied traffic isn't getting through"
    );
    assert!(v.lines[0].starts_with("IPv4: failed"));
}

#[test]
fn verdict_nothing_produced_and_no_proxy_failure_is_cant_tell() {
    let i = LeakInputs {
        running: true,
        ipv4: no_v6(),
        dns: no_v6(),
        dns_subnet: None,
        ipv6: no_v6(),
    };
    assert_eq!(verdict(&i).level, Level::CantTell);
}

#[test]
fn verdict_no_ipv6_line() {
    let v = verdict(&base());
    assert_eq!(v.lines[2], "IPv6: none (nothing to leak)");
}

#[tokio::test]
async fn http_huge_chunk_size_is_error_not_panic() {
    let (c, _h) = serve(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nabc".to_vec(),
    )
    .await;
    assert!(matches!(
        http_get(c, "h", "/").await,
        Err(LeakError::Http(_))
    ));
}

#[tokio::test]
async fn http_truncated_chunked_is_error() {
    let (c, _h) =
        serve(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc".to_vec()).await;
    assert!(matches!(http_get(c, "h", "/").await, Err(LeakError::Io(_))));
}

#[tokio::test]
async fn http_eof_before_content_length_is_error() {
    let (c, _h) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc".to_vec()).await;
    assert!(matches!(http_get(c, "h", "/").await, Err(LeakError::Io(_))));
}

#[tokio::test]
async fn http_chunk_extension_and_mixed_case_headers() {
    let (c, _h) = serve(
        b"HTTP/1.1 200 OK\r\ntRaNsFeR-eNcOdInG: Chunked\r\n\r\n3;ext=1\r\nabc\r\n0\r\n\r\n"
            .to_vec(),
    )
    .await;
    assert_eq!(http_get(c, "h", "/").await.unwrap(), "abc");
    let (c, _h) = serve(b"HTTP/1.1 200 OK\r\ncontent-LENGTH: 2\r\n\r\nokXX".to_vec()).await;
    assert_eq!(http_get(c, "h", "/").await.unwrap(), "ok");
}

#[tokio::test]
async fn http_bad_content_length_is_error() {
    let (c, _h) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nxyz".to_vec()).await;
    assert!(matches!(
        http_get(c, "h", "/").await,
        Err(LeakError::Http(_))
    ));
}

#[test]
fn verdict_direct_failed_is_cant_tell() {
    let mut i = base();
    i.ipv4 = failed(direct());
    assert_eq!(verdict(&i).level, Level::CantTell);
}

#[test]
fn verdict_ipv4_failed_ipv6_ir_is_leak() {
    let mut i = base();
    i.ipv4 = failed(proxy());
    i.ipv6 = got(info("2a00::1", "IR", "Iran", "X"), proxy());
    assert_eq!(verdict(&i).level, Level::Leak);
}

#[test]
fn verdict_ipv4_none_never_names_dns_ip() {
    let mut i = base();
    i.ipv4 = no_v6();
    let v = verdict(&i);
    assert!(!v.headline.contains("141.98.7.5"));
}

#[test]
fn verdict_direct_hides_real_ip_and_other_probes() {
    let mut i = base();
    i.ipv4 = got(ir(), direct());
    i.dns = got(ir(), direct());
    i.ipv6 = got(info("2a00::1", "IR", "Iran", "X"), direct());
    let v = verdict(&i);
    assert_eq!(v.level, Level::CantTell);
    assert_eq!(v.lines.len(), 1);
    for l in &v.lines {
        assert!(!l.contains("5.200.1.1"), "{l}");
        assert!(!l.contains("2a00::1"), "{l}");
    }
    assert_eq!(
        v.lines[0],
        "IPv4: address not shown (routed Direct) \u{2014} via direct"
    );
}

#[test]
fn verdict_direct_without_group() {
    let mut i = base();
    i.ipv4 = got(ir(), ProbeRoute::Direct { group: None });
    let v = verdict(&i);
    assert_eq!(
        v.headline,
        "Can't tell: this check was routed Direct (always-direct app or no group)"
    );
    assert_eq!(v.lines, vec!["IPv4: address not shown (routed Direct)"]);
}

#[test]
fn verdict_unknown_route_failure_is_cant_tell() {
    let unconfirmed = "Can't tell: couldn't confirm how this check was routed";
    for p in [failed(ProbeRoute::Unknown), refused(ProbeRoute::Unknown)] {
        let mut i = base();
        i.ipv4 = p;
        let v = verdict(&i);
        assert_eq!(v.level, Level::CantTell);
        assert_eq!(v.headline, unconfirmed);
    }
    // the same for the DNS probe, even when IPv4 succeeded
    let mut i = base();
    i.dns = failed(ProbeRoute::Unknown);
    assert_eq!(verdict(&i).headline, unconfirmed);
}

#[test]
fn verdict_service_error_is_cant_tell() {
    for r in [
        proxy(),
        ProbeRoute::Block {
            group: "blk".into(),
        },
    ] {
        let mut i = base();
        i.ipv4 = refused(r);
        let v = verdict(&i);
        assert_eq!(v.level, Level::CantTell);
        assert_eq!(
            v.headline,
            "Can't tell: the IP service answered with an error (status HTTP/1.1 429 Too Many Requests)"
        );
        assert!(v.lines[0].starts_with("IPv4: service error: status HTTP/1.1 429"));
    }
    let mut i = base();
    i.dns = refused(proxy());
    let v = verdict(&i);
    assert_eq!(v.level, Level::CantTell);
    assert_eq!(
        v.lines[1],
        "DNS: service error: status HTTP/1.1 429 Too Many Requests"
    );
}

#[test]
fn verdict_block_failed_is_not_getting_through() {
    let mut i = base();
    i.ipv4 = failed(ProbeRoute::Block {
        group: "blk".into(),
    });
    let v = verdict(&i);
    assert_eq!(v.level, Level::NoLeak);
    assert_eq!(
        v.headline,
        "No leak, but proxied traffic isn't getting through"
    );
}

#[test]
fn verdict_proxy_down_with_unknown_dns_is_not_getting_through() {
    // v2ray server unreachable: IPv4 fails via the proxy, the DNS query fails too.
    let mut i = base();
    i.ipv4 = failed(proxy());
    i.dns = failed(ProbeRoute::Unknown);
    assert_eq!(
        verdict(&i).headline,
        "No leak, but proxied traffic isn't getting through"
    );
}

#[test]
fn verdict_dns_subnet_ir_is_leak() {
    let mut i = base();
    let net: IpAddr = "5.200.1.0".parse().unwrap();
    i.dns_subnet = Some((
        net,
        got(info("5.200.1.0", "IR", "Iran", "Irancell"), proxy()),
    ));
    let v = verdict(&i);
    assert_eq!(v.level, Level::Leak);
    assert_eq!(v.headline, "LEAK: DNS appear from Iran");
    assert_eq!(
        v.lines[1],
        "DNS: resolver 141.98.7.5 (Germany, Hetzner); client subnet 5.200.1.0 (Iran)"
    );
    // resolver and subnet both Iranian: DNS is named once
    i.dns = got(ir(), proxy());
    assert_eq!(verdict(&i).headline, "LEAK: DNS appear from Iran");
}

#[test]
fn verdict_dns_subnet_foreign_is_no_leak() {
    let mut i = base();
    let net: IpAddr = "141.98.7.0".parse().unwrap();
    i.dns_subnet = Some((
        net,
        got(info("141.98.7.0", "DE", "Germany", "Hetzner"), proxy()),
    ));
    let v = verdict(&i);
    assert_eq!(v.level, Level::NoLeak);
    assert!(v.lines[1].ends_with("; client subnet 141.98.7.0 (Germany)"));
    i.dns_subnet = Some((net, refused(proxy())));
    let v = verdict(&i);
    assert_eq!(v.level, Level::CantTell);
    assert!(v.lines[1].ends_with(
        "; client subnet 141.98.7.0: service error: status HTTP/1.1 429 Too Many Requests"
    ));
}

#[test]
fn outcome_from_error_kinds() {
    use ProbeOutcome as O;
    assert!(matches!(
        O::from_error(&LeakError::Http("x".into())),
        O::Refused(_)
    ));
    assert!(matches!(
        O::from_error(&LeakError::Parse("x".into())),
        O::Refused(_)
    ));
    assert!(matches!(
        O::from_error(&LeakError::Io("x".into())),
        O::Failed(_)
    ));
    assert!(matches!(O::from_error(&LeakError::Timeout), O::Failed(_)));
}

#[tokio::test]
async fn http_eof_without_response_is_io_error() {
    // e.g. the relay closes the connection because the proxy server is unreachable
    let (c, _h) = serve(Vec::new()).await;
    assert!(matches!(http_get(c, "h", "/").await, Err(LeakError::Io(_))));
}

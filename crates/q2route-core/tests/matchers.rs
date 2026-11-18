use q2route_core::matchers::*;
use std::net::IpAddr;
use std::path::Path;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn suffix_domain() {
    let p = DomainPattern::parse("*.ir").unwrap();
    assert!(p.matches("digikala.ir"));
    assert!(p.matches("WWW.Digikala.IR."));
    assert!(p.matches("ir"));
    assert!(p.matches("a.b.ir"));
    assert!(!p.matches("notir.com"));
    assert!(!p.matches("ir.com"));
    assert!(!p.matches("xir"));
}

#[test]
fn keyword_and_exact_domain() {
    let k = DomainPattern::parse("keyword:steam").unwrap();
    assert!(k.matches("steamcdn-a.akamaihd.net"));
    assert!(!k.matches("example.com"));
    let e = DomainPattern::parse("Example.com").unwrap();
    assert!(e.matches("EXAMPLE.com."));
    assert!(!e.matches("www.example.com"));
}

#[test]
fn bad_domains() {
    assert!(DomainPattern::parse("*.").is_err());
    assert!(DomainPattern::parse("").is_err());
    assert!(DomainPattern::parse("keyword:").is_err());
}

#[test]
fn ip_matcher() {
    let m = IpMatcher::parse("5.160.0.0/14").unwrap();
    assert!(m.matches(ip("5.161.2.3")));
    assert!(!m.matches(ip("5.164.0.1")));
    let single = IpMatcher::parse("1.2.3.4").unwrap();
    assert!(single.matches(ip("1.2.3.4")));
    assert!(!single.matches(ip("1.2.3.5")));
    let v6 = IpMatcher::parse("2001:db8::/32").unwrap();
    assert!(v6.matches(ip("2001:db8::1")));
    assert!(IpMatcher::parse("nope").is_err());
}

#[test]
fn port_range() {
    let r = PortRange::parse("27000-27050").unwrap();
    assert!(r.matches(27015));
    assert!(!r.matches(26999));
    assert!(PortRange::parse("443").unwrap().matches(443));
    assert!(PortRange::parse("50-40").is_err());
    assert!(PortRange::parse("abc").is_err());
}

#[test]
fn app_matchers() {
    let n = AppMatcher::parse("steam*.exe").unwrap();
    assert!(n.matches(Path::new(
        r"C:\Program Files (x86)\Steam\steamwebhelper.exe"
    )));
    assert!(n.matches(Path::new(r"C:\x\STEAM.EXE")));
    assert!(!n.matches(Path::new(r"C:\steam\game.exe")));
    let f = AppMatcher::parse(r"C:\Games\").unwrap();
    assert!(matches!(f, AppMatcher::Folder(_)));
    assert!(f.matches(Path::new(r"c:\games\x\y.exe")));
    assert!(!f.matches(Path::new(r"c:\gamesx\y.exe")));
    let p = AppMatcher::parse(r"C:\Tools\a.exe").unwrap();
    assert!(matches!(p, AppMatcher::Path(_)));
    assert!(p.matches(Path::new(r"c:\tools\A.EXE")));
    assert!(!p.matches(Path::new(r"c:\other\a.exe")));
    assert!(AppMatcher::parse("").is_err());
}

#[test]
fn always_direct_dst() {
    for s in [
        "192.168.1.5",
        "127.0.0.1",
        "::1",
        "10.1.1.1",
        "172.16.0.1",
        "172.31.255.255",
        "169.254.1.1",
        "fe80::1",
        "224.0.0.251",
        "ff02::fb",
        "255.255.255.255",
    ] {
        assert!(is_always_direct_dst(ip(s)), "{s}");
    }
    for s in ["8.8.8.8", "172.32.0.1", "2001:4860:4860::8888"] {
        assert!(!is_always_direct_dst(ip(s)), "{s}");
    }
}

#[test]
fn geoip_matcher() {
    use q2route_core::geoip::{GeoIp, IpSet};
    let geo = GeoIp::from_sets([(
        "IR".to_string(),
        IpSet::from_cidrs(&[("185.188.104.0".parse().unwrap(), 22)]),
    )]);
    let m = IpMatcher::parse_with("geoip:ir", &geo).unwrap();
    assert!(m.matches("185.188.107.12".parse().unwrap()));
    assert!(!m.matches("8.8.8.8".parse().unwrap()));
    // Without data: parses, matches nothing (falls through to the proxy).
    let none = IpMatcher::parse("geoip:ir").unwrap();
    assert!(!none.matches("185.188.107.12".parse().unwrap()));
    assert!(IpMatcher::parse("geoip:").is_err());
    assert_eq!(
        q2route_core::matchers::geoip_codes(&[
            "geoip:IR".to_string(),
            "1.2.3.4".into(),
            "geoip:ir".into()
        ]),
        ["ir"]
    );
}

#[test]
fn geosite_matcher() {
    use q2route_core::geosite::{DomainSet, GeoSite};
    let sites = GeoSite::from_sets([(
        "IR".to_string(),
        DomainSet::from_entries(&[], &["digikala.com"], &[]),
    )]);
    let m = DomainPattern::parse_with("geosite:ir", &sites).unwrap();
    assert!(m.matches("www.digikala.com"));
    assert!(!m.matches("example.com"));
    // Without data: parses, matches nothing.
    let none = DomainPattern::parse("geosite:ir").unwrap();
    assert!(!none.matches("www.digikala.com"));
    let up = DomainPattern::parse_with("GEOSITE:IR", &sites).unwrap();
    assert!(up.matches("www.digikala.com"));
    assert_eq!(geosite_codes(&["GEOSITE:IR".to_string()]), ["ir"]);
    assert!(DomainPattern::parse("GeoSite:").is_err());
    assert!(DomainPattern::parse("geosite:").is_err());
    assert!(DomainPattern::parse("geosite:ir@").is_err());
    assert_eq!(
        geosite_codes(&[
            "geosite:IR".to_string(),
            "*.ir".into(),
            "geosite:ir".into(),
            "geosite:ads@Ads".into()
        ]),
        ["ads@ads", "ir"]
    );
}

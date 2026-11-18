use q2route_core::geosite::GeoSite;

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

/// ty: 0 plain, 1 regex, 2 root domain, 3 full.
fn domain(ty: u64, value: &str, attrs: &[&str]) -> Vec<u8> {
    let mut d = Vec::new();
    if ty != 0 {
        varint(1 << 3, &mut d);
        varint(ty, &mut d);
    }
    bytes_field(2, value.as_bytes(), &mut d);
    for a in attrs {
        let mut at = Vec::new();
        bytes_field(1, a.as_bytes(), &mut at);
        varint(2 << 3, &mut at);
        varint(1, &mut at);
        bytes_field(3, &at, &mut d);
    }
    d
}

fn site(code: &str, domains: &[Vec<u8>]) -> Vec<u8> {
    let mut s = Vec::new();
    bytes_field(1, code.as_bytes(), &mut s);
    for d in domains {
        bytes_field(2, d, &mut s);
    }
    s
}

fn fixture() -> Vec<u8> {
    let entries = [
        site(
            "IR",
            &[
                domain(2, "digikala.com", &[]),
                domain(2, "ir", &[]),
                domain(3, "exact.example", &[]),
                domain(0, "snapp", &[]),
                domain(1, r"^ads\d+\.com$", &[]),
            ],
        ),
        site(
            "EMPTY",
            &[
                domain(0, "", &[]),
                domain(2, "", &[]),
                domain(2, ".", &[]),
                domain(3, "ok.example", &[]),
            ],
        ),
        site("DUP", &[domain(2, "one.com", &[])]),
        site("DUP", &[domain(2, "two.com", &[])]),
        site("STEAM", &[domain(2, "steampowered.com", &[])]),
        site(
            "ADS",
            &[domain(2, "a.com", &["ads"]), domain(2, "b.com", &[])],
        ),
    ];
    let mut f = Vec::new();
    for e in &entries {
        bytes_field(1, e, &mut f);
    }
    f
}

fn ir() -> std::sync::Arc<q2route_core::geosite::DomainSet> {
    GeoSite::parse(&fixture(), &["ir".into()])
        .unwrap()
        .get("ir")
        .unwrap()
}

#[test]
fn root_domain_matches_label_boundary() {
    let s = ir();
    assert!(s.contains("www.digikala.com"));
    assert!(s.contains("digikala.com"));
    assert!(s.contains("x.y.ir"));
    assert!(!s.contains("notdigikala.com"));
    assert!(!s.contains("digikala.com.evil.net"));
    assert!(!s.contains("iran.com"));
}

#[test]
fn full_and_keyword() {
    let s = ir();
    assert!(s.contains("exact.example"));
    assert!(!s.contains("a.exact.example"));
    assert!(s.contains("mysnapp.net"));
}

#[test]
fn codes_and_names_case_insensitive() {
    let s = ir();
    assert!(s.contains("WWW.Digikala.COM."));
}

#[test]
fn only_wanted_codes_decoded() {
    let g = GeoSite::parse(&fixture(), &["ir".into()]).unwrap();
    assert!(g.get("steam").is_none());
    assert_eq!(g.get("ir").unwrap().len(), 4);
    assert_eq!(g.skipped("ir"), 1);
}

#[test]
fn attribute_filter() {
    let g = GeoSite::parse(&fixture(), &["ads@ads".into()]).unwrap();
    let s = g.get("ads@ads").unwrap();
    assert!(s.contains("a.com"));
    assert!(!s.contains("b.com"));
    let g = GeoSite::parse(&fixture(), &["ads".into()]).unwrap();
    let s = g.get("ads").unwrap();
    assert!(s.contains("a.com") && s.contains("b.com"));
    let g = GeoSite::parse(&fixture(), &["ads".into(), "ads@ads".into()]).unwrap();
    assert!(g.get("ads").unwrap().contains("b.com"));
    assert!(!g.get("ads@ads").unwrap().contains("b.com"));
}

#[test]
fn malformed_geosite_is_error() {
    let mut data = fixture();
    data.truncate(data.len() - 3);
    assert!(GeoSite::parse(&data, &["ads".into()]).is_err());
}

#[test]
fn from_sets_lowercases_keys() {
    let g = GeoSite::from_sets([(
        "IR".to_string(),
        q2route_core::geosite::DomainSet::from_entries(&[], &["a.com"], &[]),
    )]);
    assert!(g.get("ir").unwrap().contains("x.a.com"));
}

#[test]
#[ignore]
fn real_file_smoke() {
    let Ok(data) = std::fs::read(r"C:\v2rayN\bin\geosite.dat") else {
        return;
    };
    let t = std::time::Instant::now();
    let g = GeoSite::parse(&data, &["ir".into()]).unwrap();
    let el = t.elapsed();
    println!("loaded in {el:?}, {} entries", g.get("ir").unwrap().len());
    assert!(g.get("ir").unwrap().contains("digikala.com"));
    assert!(el.as_secs_f64() < 1.0);
}

#[test]
fn empty_values_are_skipped() {
    let g = GeoSite::parse(&fixture(), &["empty".into()]).unwrap();
    let s = g.get("empty").unwrap();
    assert!(!s.contains("google.com"));
    assert!(!s.contains("") && !s.contains(".") && !s.contains(".."));
    assert!(s.contains("ok.example"));
    assert_eq!(s.len(), 1);
    assert_eq!(g.skipped("empty"), 3);
    let d = q2route_core::geosite::DomainSet::from_entries(&[""], &[""], &[""]);
    assert!(d.is_empty() && !d.contains("google.com"));
}

#[test]
fn duplicate_code_entries_merge() {
    let g = GeoSite::parse(&fixture(), &["dup".into()]).unwrap();
    let s = g.get("dup").unwrap();
    assert!(s.contains("one.com") && s.contains("two.com"));
}

#[test]
fn absent_code_is_none() {
    let g = GeoSite::parse(&fixture(), &["nope".into()]).unwrap();
    assert!(g.get("nope").is_none());
}

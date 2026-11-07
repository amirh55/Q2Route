use q2route_core::domain_map::*;
use std::net::IpAddr;
use std::time::{Duration, Instant};

fn ip(n: u32) -> IpAddr {
    IpAddr::from(n.to_be_bytes())
}

#[test]
fn insert_and_expire() {
    let m = DomainMap::new();
    let t = Instant::now();
    m.insert(ip(1), "a.ir", 10, t);
    assert_eq!(m.names(ip(1), t + Duration::from_secs(59)), vec!["a.ir"]);
    assert!(m.names(ip(1), t + Duration::from_secs(61)).is_empty());
}

#[test]
fn names_capped_most_recent_first() {
    let m = DomainMap::new();
    let t = Instant::now();
    for i in 0..10 {
        m.insert(ip(1), &format!("n{i}.com"), 300, t);
    }
    let n = m.names(ip(1), t);
    assert_eq!(n.len(), NAMES_PER_IP);
    assert_eq!(n[0], "n9.com");
    assert_eq!(n[NAMES_PER_IP - 1], "n2.com");
}

#[test]
fn ips_capped_evicts_oldest() {
    let m = DomainMap::new();
    let t = Instant::now();
    for i in 0..MAP_MAX_IPS as u32 {
        m.insert(ip(i), "a.com", 300, t);
    }
    assert_eq!(m.len(), MAP_MAX_IPS);
    m.insert(ip(MAP_MAX_IPS as u32), "b.com", 300, t);
    assert_eq!(m.len(), MAP_MAX_IPS);
    assert!(m.names(ip(0), t).is_empty());
    assert_eq!(m.names(ip(MAP_MAX_IPS as u32), t), vec!["b.com"]);
    // expired entries are dropped first
    let later = t + Duration::from_secs(400);
    m.insert(ip(MAP_MAX_IPS as u32 + 1), "c.com", 300, later);
    assert_eq!(m.len(), 1);
}

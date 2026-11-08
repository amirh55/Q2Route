//! Pure packet-rewrite tests for the flow table and the TCP NAT redirect.
//! Packets are crafted with `etherparse`; no administrator rights needed
//! (`calc_checksums` only loads WinDivert.dll, not the driver).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice, PacketBuilder, TcpHeaderSlice};
use q2route_service::flows::{FlowKey, FlowTable};
use q2route_service::nat::{
    redirect_outbound, restore_inbound, Family, NatTable, OriginalDst, Verdict, CLOSE_LINGER,
    IDLE_TIMEOUT,
};
use q2route_service::windivert::{Address, SocketData};

const RELAY: u16 = 34567;
const APP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const DST: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);

#[derive(Clone, Copy, Default)]
struct Flags {
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
}

const SYN: Flags = Flags {
    syn: true,
    ack: false,
    fin: false,
    rst: false,
};
const ACK: Flags = Flags {
    syn: false,
    ack: true,
    fin: false,
    rst: false,
};
const FIN: Flags = Flags {
    syn: false,
    ack: true,
    fin: true,
    rst: false,
};
const RST: Flags = Flags {
    syn: false,
    ack: false,
    fin: false,
    rst: true,
};

fn tcp4(src: SocketAddrV4, dst: SocketAddrV4, f: Flags, payload: &[u8]) -> Vec<u8> {
    let mut b = PacketBuilder::ipv4(src.ip().octets(), dst.ip().octets(), 64).tcp(
        src.port(),
        dst.port(),
        1000,
        65535,
    );
    if f.syn {
        b = b.syn();
    }
    if f.ack {
        b = b.ack(2000);
    }
    if f.fin {
        b = b.fin();
    }
    if f.rst {
        b = b.rst();
    }
    let mut out = Vec::with_capacity(b.size(payload.len()));
    b.write(&mut out, payload).unwrap();
    out
}

fn sa(ip: Ipv4Addr, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(ip, port)
}

fn outbound_addr() -> Address {
    let mut a = Address::default();
    a.set_outbound(true);
    a
}

/// Parses `pkt`, asserts both checksums are valid, returns (src, dst).
fn tuple_with_valid_checksums(pkt: &[u8]) -> (SocketAddrV4, SocketAddrV4) {
    let ip = Ipv4HeaderSlice::from_slice(pkt).unwrap();
    let iph = ip.to_header();
    assert_eq!(
        iph.header_checksum,
        iph.calc_header_checksum(),
        "ip checksum"
    );
    let rest = &pkt[ip.slice().len()..];
    let tcp = TcpHeaderSlice::from_slice(rest).unwrap();
    let payload = &rest[tcp.slice().len()..];
    let tcph = tcp.to_header();
    assert_eq!(
        tcph.checksum,
        tcph.calc_checksum_ipv4(&iph, payload).unwrap(),
        "tcp checksum"
    );
    (
        sa(ip.source_addr(), tcp.source_port()),
        sa(ip.destination_addr(), tcp.destination_port()),
    )
}

fn nat_with_entry() -> NatTable {
    let nat = NatTable::default();
    nat.insert(
        Family::V4,
        50000,
        OriginalDst {
            dst: sa(DST, 443).into(),
            pid: 4242,
        },
    );
    nat
}

#[test]
fn redirect_and_restore() {
    let nat = nat_with_entry();

    let mut pkt = tcp4(sa(APP, 50000), sa(DST, 443), SYN, b"");
    let mut addr = outbound_addr();
    assert_eq!(
        redirect_outbound(&mut pkt, &mut addr, RELAY, &nat),
        Verdict::Rewritten
    );
    assert_eq!(
        tuple_with_valid_checksums(&pkt),
        (sa(DST, 50000), sa(APP, RELAY))
    );
    assert!(!addr.outbound());

    let mut reply = tcp4(sa(APP, RELAY), sa(DST, 50000), ACK, b"hello");
    let mut addr = outbound_addr();
    assert_eq!(
        restore_inbound(&mut reply, &mut addr, RELAY, &nat),
        Verdict::Rewritten
    );
    assert_eq!(
        tuple_with_valid_checksums(&reply),
        (sa(DST, 443), sa(APP, 50000))
    );
    assert!(!addr.outbound());
    assert_eq!(&reply[reply.len() - 5..], b"hello");
}

#[test]
fn unknown_port_passes() {
    // The brief's name; the expected verdict for a relay reply with no NAT
    // entry is Drop (never let it escape un-restored).
    let nat = NatTable::default();
    let mut reply = tcp4(sa(APP, RELAY), sa(DST, 50000), ACK, b"");
    let orig = reply.clone();
    let mut addr = outbound_addr();
    assert_eq!(
        restore_inbound(&mut reply, &mut addr, RELAY, &nat),
        Verdict::Drop
    );
    assert_eq!(reply, orig);
}

#[test]
fn outbound_without_entry_passes_untouched() {
    let nat = NatTable::default();
    let mut pkt = tcp4(sa(APP, 50001), sa(DST, 443), SYN, b"");
    let orig = pkt.clone();
    let mut addr = outbound_addr();
    assert_eq!(
        redirect_outbound(&mut pkt, &mut addr, RELAY, &nat),
        Verdict::Pass
    );
    assert_eq!(pkt, orig);
    assert!(addr.outbound());
}

#[test]
fn outbound_to_other_destination_on_same_port_passes() {
    let nat = nat_with_entry();
    let mut pkt = tcp4(sa(APP, 50000), sa(DST, 80), SYN, b"");
    let orig = pkt.clone();
    let mut addr = outbound_addr();
    assert_eq!(
        redirect_outbound(&mut pkt, &mut addr, RELAY, &nat),
        Verdict::Pass
    );
    assert_eq!(pkt, orig);
}

#[test]
fn inbound_packets_are_not_touched() {
    let nat = nat_with_entry();
    let mut pkt = tcp4(sa(APP, 50000), sa(DST, 443), SYN, b"");
    let mut addr = Address::default(); // inbound
    assert_eq!(
        redirect_outbound(&mut pkt, &mut addr, RELAY, &nat),
        Verdict::Pass
    );
    let mut reply = tcp4(sa(APP, RELAY), sa(DST, 50000), ACK, b"");
    assert_eq!(
        restore_inbound(&mut reply, &mut addr, RELAY, &nat),
        Verdict::Pass
    );
}

#[test]
fn non_relay_source_passes_restore() {
    let nat = nat_with_entry();
    let mut pkt = tcp4(sa(APP, 50000), sa(DST, 443), ACK, b"");
    let mut addr = outbound_addr();
    assert_eq!(
        restore_inbound(&mut pkt, &mut addr, RELAY, &nat),
        Verdict::Pass
    );
}

#[test]
fn rst_removes_entry_after_rewriting() {
    let nat = nat_with_entry();
    let mut pkt = tcp4(sa(APP, 50000), sa(DST, 443), RST, b"");
    let mut addr = outbound_addr();
    assert_eq!(
        redirect_outbound(&mut pkt, &mut addr, RELAY, &nat),
        Verdict::Rewritten
    );
    assert_eq!(
        tuple_with_valid_checksums(&pkt),
        (sa(DST, 50000), sa(APP, RELAY))
    );
    assert!(nat.get(Family::V4, 50000).is_none());

    // RST from the relay side also removes.
    let nat = nat_with_entry();
    let mut reply = tcp4(sa(APP, RELAY), sa(DST, 50000), RST, b"");
    let mut addr = outbound_addr();
    assert_eq!(
        restore_inbound(&mut reply, &mut addr, RELAY, &nat),
        Verdict::Rewritten
    );
    assert!(nat.get(Family::V4, 50000).is_none());
}

#[test]
fn fin_both_ways_removes_entry_after_linger() {
    let nat = nat_with_entry();
    let mut addr = outbound_addr();
    let mut fin = tcp4(sa(APP, 50000), sa(DST, 443), FIN, b"");
    assert_eq!(
        redirect_outbound(&mut fin, &mut addr, RELAY, &nat),
        Verdict::Rewritten
    );
    let mut addr = outbound_addr();
    let mut fin_back = tcp4(sa(APP, RELAY), sa(DST, 50000), FIN, b"");
    assert_eq!(
        restore_inbound(&mut fin_back, &mut addr, RELAY, &nat),
        Verdict::Rewritten
    );
    let closed = Instant::now();

    // The final ACK of the close handshake must still be redirected.
    let mut last_ack = tcp4(sa(APP, 50000), sa(DST, 443), ACK, b"");
    let mut addr = outbound_addr();
    assert_eq!(
        redirect_outbound(&mut last_ack, &mut addr, RELAY, &nat),
        Verdict::Rewritten
    );

    nat.sweep(closed);
    assert!(nat.get(Family::V4, 50000).is_some());
    nat.sweep(closed + CLOSE_LINGER + Duration::from_secs(1));
    assert!(nat.get(Family::V4, 50000).is_none());
}

#[test]
fn sweep_expires_idle_entries() {
    let nat = nat_with_entry();
    let t0 = Instant::now();
    nat.sweep(t0 + IDLE_TIMEOUT - Duration::from_secs(5));
    assert!(nat.get(Family::V4, 50000).is_some());
    nat.sweep(t0 + IDLE_TIMEOUT + Duration::from_secs(1));
    assert!(nat.get(Family::V4, 50000).is_none());
}

#[test]
fn relay_attached_entry_is_never_idle_swept() {
    let nat = nat_with_entry();
    let t0 = Instant::now();
    assert!(
        nat.attach(Family::V4, 50000, Ipv4Addr::new(9, 9, 9, 9).into())
            .is_none(),
        "wrong ip"
    );
    let (o, token) = nat.attach(Family::V4, 50000, DST.into()).unwrap();
    assert_eq!(o.dst, SocketAddr::from(sa(DST, 443)));
    // A long-idle proxied connection keeps its entry while the relay holds it.
    nat.sweep(t0 + IDLE_TIMEOUT + Duration::from_secs(3600));
    assert!(nat.get(Family::V4, 50000).is_some());
    // The relay connection ends: the entry lingers, then goes.
    nat.release(Family::V4, 50000, token);
    nat.sweep(Instant::now());
    assert!(
        nat.get(Family::V4, 50000).is_some(),
        "lingers for the final packets"
    );
    nat.sweep(Instant::now() + CLOSE_LINGER + Duration::from_secs(1));
    assert!(nat.get(Family::V4, 50000).is_none());
}

#[test]
fn stale_release_does_not_touch_a_reused_port() {
    let nat = nat_with_entry();
    let (_, old) = nat.attach(Family::V4, 50000, DST.into()).unwrap();
    // The app reuses the port for a new connection (new SYN, new entry).
    nat.insert(
        Family::V4,
        50000,
        OriginalDst {
            dst: sa(DST, 443).into(),
            pid: 4242,
        },
    );
    let (_, new) = nat.attach(Family::V4, 50000, DST.into()).unwrap();
    assert_ne!(old, new);
    nat.release(Family::V4, 50000, old);
    nat.sweep(Instant::now() + CLOSE_LINGER + IDLE_TIMEOUT + Duration::from_secs(1));
    assert!(
        nat.get(Family::V4, 50000).is_some(),
        "new connection's entry kept"
    );
}

#[test]
fn malformed_packets_never_panic() {
    let nat = nat_with_entry();
    let good = tcp4(sa(APP, 50000), sa(DST, 443), SYN, b"data");
    let mut cases: Vec<Vec<u8>> = (0..good.len()).map(|n| good[..n].to_vec()).collect();
    cases.push(Vec::new());
    let mut bad_ihl = good.clone();
    bad_ihl[0] = 0x4f; // IHL 60 > packet
    cases.push(bad_ihl);
    let mut tiny_ihl = good.clone();
    tiny_ihl[0] = 0x41;
    cases.push(tiny_ihl);
    let mut v6 = good.clone();
    v6[0] = 0x65;
    cases.push(v6);
    let mut udp = good.clone();
    udp[9] = 17;
    cases.push(udp);
    let mut frag = good.clone();
    frag[6] = 0x00;
    frag[7] = 0x10; // fragment offset != 0
    cases.push(frag);
    let mut long_total = good.clone();
    long_total[2] = 0xff;
    cases.push(long_total);
    cases.push(vec![0xff; 64]);

    for case in cases {
        for relay_src in [false, true] {
            let mut p = case.clone();
            if relay_src && p.len() >= 22 {
                // Make it look like it comes from the relay when parseable.
                p[20..22].copy_from_slice(&RELAY.to_be_bytes());
            }
            let orig = p.clone();
            let mut addr = outbound_addr();
            // Every case is truncated or not IPv4/TCP (or a non-first
            // fragment): both functions must Pass and leave it untouched.
            assert_eq!(
                redirect_outbound(&mut p, &mut addr, RELAY, &nat),
                Verdict::Pass
            );
            assert_eq!(
                restore_inbound(&mut p, &mut addr, RELAY, &nat),
                Verdict::Pass
            );
            assert_eq!(p, orig);
            assert!(addr.outbound());
        }
    }
}

const APP6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
const DST6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1);

fn sa6(ip: Ipv6Addr, port: u16) -> SocketAddrV6 {
    SocketAddrV6::new(ip, port, 0, 0)
}

fn tcp6(src: SocketAddrV6, dst: SocketAddrV6, f: Flags, payload: &[u8]) -> Vec<u8> {
    let mut b = PacketBuilder::ipv6(src.ip().octets(), dst.ip().octets(), 57).tcp(
        src.port(),
        dst.port(),
        1000,
        65535,
    );
    if f.syn {
        b = b.syn();
    }
    if f.ack {
        b = b.ack(2000);
    }
    let mut out = Vec::with_capacity(b.size(payload.len()));
    b.write(&mut out, payload).unwrap();
    out
}

/// Parses an IPv6/TCP `pkt` (no extension headers), asserts the TCP
/// checksum and that the hop limit was kept, returns (src, dst).
fn tuple6_with_valid_checksum(pkt: &[u8]) -> (SocketAddrV6, SocketAddrV6) {
    let ip = Ipv6HeaderSlice::from_slice(pkt).unwrap();
    let iph = ip.to_header();
    assert_eq!(iph.hop_limit, 57, "hop limit kept");
    let rest = &pkt[40..];
    let tcp = TcpHeaderSlice::from_slice(rest).unwrap();
    let payload = &rest[tcp.slice().len()..];
    let tcph = tcp.to_header();
    assert_eq!(
        tcph.checksum,
        tcph.calc_checksum_ipv6(&iph, payload).unwrap(),
        "tcp checksum"
    );
    (
        sa6(ip.source_addr(), tcp.source_port()),
        sa6(ip.destination_addr(), tcp.destination_port()),
    )
}

fn nat_with_entry6() -> NatTable {
    let nat = NatTable::default();
    nat.insert(
        Family::V6,
        50000,
        OriginalDst {
            dst: sa6(DST6, 443).into(),
            pid: 4242,
        },
    );
    nat
}

#[test]
fn family_of() {
    assert_eq!(Family::of(&sa(DST, 1).into()), Family::V4);
    assert_eq!(Family::of(&sa6(DST6, 1).into()), Family::V6);
}

#[test]
fn ipv6_redirect_and_restore_roundtrip() {
    let nat = nat_with_entry6();

    let mut pkt = tcp6(sa6(APP6, 50000), sa6(DST6, 443), SYN, b"");
    let mut addr = outbound_addr();
    assert_eq!(
        redirect_outbound(&mut pkt, &mut addr, RELAY, &nat),
        Verdict::Rewritten
    );
    assert_eq!(
        tuple6_with_valid_checksum(&pkt),
        (sa6(DST6, 50000), sa6(APP6, RELAY))
    );
    assert!(!addr.outbound());

    let mut reply = tcp6(sa6(APP6, RELAY), sa6(DST6, 50000), ACK, b"hello");
    let mut addr = outbound_addr();
    assert_eq!(
        restore_inbound(&mut reply, &mut addr, RELAY, &nat),
        Verdict::Rewritten
    );
    assert_eq!(
        tuple6_with_valid_checksum(&reply),
        (sa6(DST6, 443), sa6(APP6, 50000))
    );
    assert!(!addr.outbound());
    assert_eq!(&reply[reply.len() - 5..], b"hello");

    // The relay attaches by the reflected peer `D:pa`.
    let (o, _) = nat.attach(Family::V6, 50000, DST6.into()).unwrap();
    assert_eq!(o.dst, SocketAddr::from(sa6(DST6, 443)));
}

#[test]
fn ipv6_relay_reply_without_entry_dropped() {
    // Only a V4 entry exists for the port.
    let nat = nat_with_entry();
    let mut reply = tcp6(sa6(APP6, RELAY), sa6(DST6, 50000), ACK, b"");
    let orig = reply.clone();
    let mut addr = outbound_addr();
    assert_eq!(
        restore_inbound(&mut reply, &mut addr, RELAY, &nat),
        Verdict::Drop
    );
    assert_eq!(reply, orig);
}

#[test]
fn ipv6_outbound_without_entry_passes_untouched() {
    // A V4 entry on the same port must not redirect an IPv6 flow.
    let nat = nat_with_entry();
    let mut pkt = tcp6(sa6(APP6, 50000), sa6(DST6, 443), SYN, b"");
    let orig = pkt.clone();
    let mut addr = outbound_addr();
    assert_eq!(
        redirect_outbound(&mut pkt, &mut addr, RELAY, &nat),
        Verdict::Pass
    );
    assert_eq!(pkt, orig);
    assert!(addr.outbound());
}

#[test]
fn same_port_v4_v6_do_not_collide() {
    let nat = NatTable::default();
    let d4: SocketAddr = sa(DST, 443).into();
    let d6: SocketAddr = sa6(DST6, 8443).into();
    nat.insert(Family::V4, 50000, OriginalDst { dst: d4, pid: 1 });
    nat.insert(Family::V6, 50000, OriginalDst { dst: d6, pid: 2 });
    assert_eq!(nat.get(Family::V4, 50000).unwrap().dst, d4);
    assert_eq!(nat.get(Family::V6, 50000).unwrap().dst, d6);

    // attach checks only the family's own entry.
    assert!(nat.attach(Family::V4, 50000, DST6.into()).is_none());
    assert!(nat.attach(Family::V6, 50000, DST.into()).is_none());
    let (o4, t4) = nat.attach(Family::V4, 50000, DST.into()).unwrap();
    let (o6, t6) = nat.attach(Family::V6, 50000, DST6.into()).unwrap();
    assert_eq!((o4.pid, o6.pid), (1, 2));

    // Releasing one family lingers only that entry.
    nat.release(Family::V4, 50000, t4);
    nat.sweep(Instant::now() + CLOSE_LINGER + Duration::from_secs(1));
    assert!(nat.get(Family::V4, 50000).is_none());
    assert!(nat.get(Family::V6, 50000).is_some(), "V6 still attached");

    // remove touches only its own family.
    nat.insert(Family::V4, 50000, OriginalDst { dst: d4, pid: 3 });
    nat.remove(Family::V6, 50000);
    assert!(nat.get(Family::V6, 50000).is_none());
    assert_eq!(nat.get(Family::V4, 50000).unwrap().pid, 3);
    nat.release(Family::V6, 50000, t6); // gone: no-op
    assert_eq!(nat.get(Family::V4, 50000).unwrap().pid, 3);
}

/// Inserts an 8-byte hop-by-hop options header (PadN) before the TCP header.
fn with_hop_by_hop(mut p: Vec<u8>) -> Vec<u8> {
    let next = p[6];
    p[6] = 0; // hop-by-hop
    let plen = u16::from_be_bytes([p[4], p[5]]) + 8;
    p[4..6].copy_from_slice(&plen.to_be_bytes());
    p.splice(40..40, [next, 0, 1, 4, 0, 0, 0, 0]);
    p
}

#[test]
fn ipv6_extension_header_on_redirected_flow_dropped() {
    let nat = nat_with_entry6();
    let mut pkt = with_hop_by_hop(tcp6(sa6(APP6, 50000), sa6(DST6, 443), ACK, b"x"));
    let orig = pkt.clone();
    let mut addr = outbound_addr();
    assert_eq!(
        redirect_outbound(&mut pkt, &mut addr, RELAY, &nat),
        Verdict::Drop
    );
    assert_eq!(pkt, orig);

    let mut reply = with_hop_by_hop(tcp6(sa6(APP6, RELAY), sa6(DST6, 50000), ACK, b"y"));
    let mut addr = outbound_addr();
    assert_eq!(
        restore_inbound(&mut reply, &mut addr, RELAY, &nat),
        Verdict::Drop
    );
    assert!(nat.get(Family::V6, 50000).is_some());

    // Not a redirected flow: passes untouched.
    let mut other = with_hop_by_hop(tcp6(sa6(APP6, 50001), sa6(DST6, 443), ACK, b""));
    let orig = other.clone();
    let mut addr = outbound_addr();
    assert_eq!(
        redirect_outbound(&mut other, &mut addr, RELAY, &nat),
        Verdict::Pass
    );
    assert_eq!(other, orig);
}

#[test]
fn malformed_ipv6_packets_never_panic() {
    let nat = nat_with_entry6();
    let good = tcp6(sa6(APP6, 50000), sa6(DST6, 443), SYN, b"data");
    let mut cases: Vec<Vec<u8>> = (0..good.len()).map(|n| good[..n].to_vec()).collect();
    let mut long_payload = good.clone();
    long_payload[4] = 0xff;
    cases.push(long_payload);
    let mut bad_off = good.clone();
    bad_off[40 + 12] = 0x40; // TCP data offset 16 bytes < 20
    cases.push(bad_off);
    let hbh = with_hop_by_hop(good.clone());
    cases.extend((0..hbh.len()).map(|n| {
        let mut p = hbh[..n].to_vec();
        if p.len() >= 40 {
            // Keep the payload length consistent with the truncation.
            let pl = u16::try_from(p.len() - 40).unwrap();
            p[4..6].copy_from_slice(&pl.to_be_bytes());
        }
        p
    }));
    for case in cases {
        for relay_src in [false, true] {
            let mut p = case.clone();
            if relay_src && p.len() >= 42 {
                p[40..42].copy_from_slice(&RELAY.to_be_bytes());
            }
            let orig = p.clone();
            let mut addr = outbound_addr();
            assert_ne!(
                redirect_outbound(&mut p, &mut addr, RELAY, &nat),
                Verdict::Rewritten
            );
            assert_ne!(
                restore_inbound(&mut p, &mut addr, RELAY, &nat),
                Verdict::Rewritten
            );
            assert_eq!(p, orig);
            assert!(addr.outbound());
        }
    }
}

fn sock(pid: u32, local: &str, remote: &str) -> SocketData {
    SocketData {
        pid,
        local: local.parse().unwrap(),
        remote: remote.parse().unwrap(),
        protocol: 6,
    }
}

#[test]
fn flow_table_pid() {
    let ft = FlowTable::default();
    let s = sock(777, "10.0.0.2:50000", "1.2.3.4:443");
    let key = FlowKey {
        local: s.local,
        remote: s.remote,
    };
    assert_eq!(ft.pid_for(&key), None);
    ft.on_connect(&s);
    assert_eq!(ft.pid_for(&key), Some(777));
    assert_eq!(ft.pid_for_local(s.local), Some(777));
    ft.on_close(&s);
    assert_eq!(ft.pid_for(&key), None);
    assert_eq!(ft.pid_for_local(s.local), None);
}

#[test]
fn flow_table_local_fallback_matches_unspecified_local_ip() {
    let ft = FlowTable::default();
    let s = sock(9, "0.0.0.0:50002", "1.2.3.4:443");
    ft.on_connect(&s);
    let seen: SocketAddr = "10.0.0.2:50002".parse().unwrap();
    assert_eq!(ft.pid_for_local(seen), Some(9));
    assert_eq!(ft.pid_for_local("10.0.0.2:50003".parse().unwrap()), None);
}

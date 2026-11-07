//! Builds the inbound IPv4/IPv6 UDP packets the UDP relay and the DNS proxy
//! inject toward apps.

use std::io;
use std::net::{SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU16, Ordering};

/// Largest UDP payload over IPv4 (65535 - 20 - 8).
const MAX_PAYLOAD: usize = 65507;

static IP_ID: AtomicU16 = AtomicU16::new(1);

/// Internet checksum (RFC 1071) over `chunks` (each treated as contiguous,
/// even-length except possibly the last).
fn checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for c in chunks {
        let (words, rest) = c.as_chunks::<2>();
        for w in words {
            sum += u32::from(u16::from_be_bytes(*w));
        }
        if let [b] = rest {
            sum += u32::from(*b) << 8;
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv4 + UDP packet from `src` to `dst` carrying `payload`, checksums filled,
/// TTL 64, DF clear, IP id from a process-wide counter. Err if payload > 65507.
pub fn build_inbound_udp(
    src: SocketAddrV4,
    dst: SocketAddrV4,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP payload too large",
        ));
    }
    let udp_len = (8 + payload.len()) as u16;
    let total = 20 + udp_len;
    let mut p = Vec::with_capacity(usize::from(total));
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&IP_ID.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    p.extend_from_slice(&[0, 0, 64, 17, 0, 0]);
    p.extend_from_slice(&src.ip().octets());
    p.extend_from_slice(&dst.ip().octets());
    let ip_sum = checksum(&[&p[..20]]);
    p[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    p.extend_from_slice(&src.port().to_be_bytes());
    p.extend_from_slice(&dst.port().to_be_bytes());
    p.extend_from_slice(&udp_len.to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src.ip().octets());
    pseudo[4..8].copy_from_slice(&dst.ip().octets());
    pseudo[9] = 17;
    pseudo[10..12].copy_from_slice(&udp_len.to_be_bytes());
    let mut udp_sum = checksum(&[&pseudo, &p[20..]]);
    if udp_sum == 0 {
        udp_sum = 0xffff; // 0 means "no checksum" in UDP
    }
    p[26..28].copy_from_slice(&udp_sum.to_be_bytes());
    Ok(p)
}

/// IPv6 + UDP packet from `src` to `dst` carrying `payload`, hop limit 64,
/// no extension headers, UDP checksum filled (mandatory over IPv6). Err if
/// the UDP length would not fit 16 bits (payload > 65527).
pub fn build_inbound_udp6(
    src: SocketAddrV6,
    dst: SocketAddrV6,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let udp_len = u16::try_from(8 + payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "UDP payload too large"))?;
    let mut p = Vec::with_capacity(40 + usize::from(udp_len));
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(&udp_len.to_be_bytes());
    p.extend_from_slice(&[17, 64]);
    p.extend_from_slice(&src.ip().octets());
    p.extend_from_slice(&dst.ip().octets());
    p.extend_from_slice(&src.port().to_be_bytes());
    p.extend_from_slice(&dst.port().to_be_bytes());
    p.extend_from_slice(&udp_len.to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    // Pseudo-header: src, dst, upper-layer length (32 bits), 3 zero bytes,
    // next header.
    let mut pseudo = [0u8; 40];
    pseudo[..32].copy_from_slice(&p[8..40]);
    pseudo[34..36].copy_from_slice(&udp_len.to_be_bytes());
    pseudo[39] = 17;
    let mut udp_sum = checksum(&[&pseudo, &p[40..]]);
    if udp_sum == 0 {
        udp_sum = 0xffff;
    }
    p[46..48].copy_from_slice(&udp_sum.to_be_bytes());
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{NetSlice, SlicedPacket, TransportSlice};

    #[test]
    fn inbound_packet_roundtrip_1400() {
        let src: SocketAddrV4 = "8.8.4.4:3478".parse().unwrap();
        let dst: SocketAddrV4 = "192.168.1.10:50000".parse().unwrap();
        let payload: Vec<u8> = (0..1400).map(|i| i as u8).collect();
        let pkt = build_inbound_udp(src, dst, &payload).unwrap();
        assert_eq!(pkt.len(), 20 + 8 + 1400);
        assert_eq!(pkt[8], 64, "TTL");
        assert_eq!(pkt[6] & 0x40, 0, "DF clear");
        let s = SlicedPacket::from_ip(&pkt).unwrap();
        let Some(NetSlice::Ipv4(ip)) = s.net else {
            panic!("not ipv4")
        };
        let h = ip.header();
        assert_eq!(h.source(), src.ip().octets());
        assert_eq!(h.destination(), dst.ip().octets());
        assert_eq!(
            h.header_checksum(),
            h.to_header().calc_header_checksum(),
            "ip checksum"
        );
        let Some(TransportSlice::Udp(u)) = s.transport else {
            panic!("not udp")
        };
        assert_eq!(u.source_port(), 3478);
        assert_eq!(u.destination_port(), 50000);
        assert_eq!(u.payload(), &payload[..]);
        let want = u
            .to_header()
            .calc_checksum_ipv4(&h.to_header(), u.payload())
            .unwrap();
        assert_eq!(u.checksum(), want, "udp checksum");
    }

    #[test]
    fn inbound_udp6_roundtrip() {
        let src: SocketAddrV6 = "[2001:db8::53]:53".parse().unwrap();
        let dst: SocketAddrV6 = "[2001:db8::5]:50000".parse().unwrap();
        for len in [0usize, 3, 512, 1400] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let pkt = build_inbound_udp6(src, dst, &payload).unwrap();
            assert_eq!(pkt.len(), 40 + 8 + len);
            assert_eq!(pkt[7], 64, "hop limit");
            let s = SlicedPacket::from_ip(&pkt).unwrap();
            let (Some(NetSlice::Ipv6(ip)), Some(TransportSlice::Udp(u))) = (s.net, s.transport)
            else {
                panic!("not ipv6/udp")
            };
            let h = ip.header().to_header();
            assert_eq!(h.source, src.ip().octets());
            assert_eq!(h.destination, dst.ip().octets());
            assert_eq!(usize::from(h.payload_length), 8 + len);
            assert_eq!(u.source_port(), 53);
            assert_eq!(u.destination_port(), 50000);
            assert_eq!(u.payload(), &payload[..]);
            assert_ne!(u.checksum(), 0, "checksum is mandatory over IPv6");
            let want = u.to_header().calc_checksum_ipv6(&h, u.payload()).unwrap();
            assert_eq!(u.checksum(), want, "udp checksum (len {len})");
        }
        let a: SocketAddrV6 = "[::1]:1".parse().unwrap();
        assert!(build_inbound_udp6(a, a, &vec![0; 65528]).is_err());
        assert!(build_inbound_udp6(a, a, &vec![0; 65527]).is_ok());
    }

    #[test]
    fn oversized_payload_errors() {
        let a: SocketAddrV4 = "1.2.3.4:1".parse().unwrap();
        assert!(build_inbound_udp(a, a, &vec![0; 65508]).is_err());
        assert!(build_inbound_udp(a, a, &vec![0; 65507]).is_ok());
    }

    #[test]
    fn odd_length_payload_checksum_verifies() {
        let a: SocketAddrV4 = "1.2.3.4:1".parse().unwrap();
        let b: SocketAddrV4 = "5.6.7.8:2".parse().unwrap();
        let pkt = build_inbound_udp(a, b, b"abc").unwrap();
        let s = SlicedPacket::from_ip(&pkt).unwrap();
        let (Some(NetSlice::Ipv4(ip)), Some(TransportSlice::Udp(u))) = (s.net, s.transport) else {
            panic!()
        };
        let want = u
            .to_header()
            .calc_checksum_ipv4(&ip.header().to_header(), u.payload())
            .unwrap();
        assert_eq!(u.checksum(), want);
    }
}

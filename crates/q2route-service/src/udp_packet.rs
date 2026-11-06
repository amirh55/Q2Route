//! Builds the inbound IPv4/UDP packets the UDP relay injects toward apps.

use std::io;
use std::net::SocketAddrV4;
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

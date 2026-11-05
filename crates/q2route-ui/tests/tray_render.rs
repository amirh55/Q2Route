//! Tray icon renderer: size, colours and scaling.

use q2route_ui::tray_icon_render::{render_icon, TrafficHistory, SIZE};

const UP: [u8; 3] = [0x4F, 0xC3, 0xF7];
const DOWN: [u8; 3] = [0x66, 0xBB, 0x6A];

fn count(px: &[u8], rgb: [u8; 3]) -> usize {
    px.as_chunks::<4>()
        .0
        .iter()
        .filter(|p| p[..3] == rgb && p[3] == 255)
        .count()
}

#[test]
fn render_size() {
    assert_eq!(SIZE, 32);
    assert_eq!(
        render_icon(&TrafficHistory::default(), true).len(),
        32 * 32 * 4
    );
}

#[test]
fn idle_has_no_bars() {
    let mut h = TrafficHistory::default();
    for _ in 0..8 {
        h.push(0, 0);
    }
    let px = render_icon(&h, true);
    assert_eq!(count(&px, DOWN), 0);
    assert_eq!(count(&px, UP), 0);
}

#[test]
fn busy_has_bars() {
    let mut h = TrafficHistory::default();
    h.push(0, 5_000_000);
    let px = render_icon(&h, true);
    assert!(count(&px, DOWN) > 0);
    assert_eq!(count(&px, UP), 0);
}

#[test]
fn stopped_is_grey() {
    let mut h = TrafficHistory::default();
    h.push(3_000_000, 5_000_000);
    let px = render_icon(&h, false);
    assert_eq!(count(&px, DOWN), 0);
    assert_eq!(count(&px, UP), 0);
    assert!(count(&px, [0x77, 0x77, 0x77]) > 0);
}

#[test]
fn small_traffic_scales_against_minimum() {
    // 1 KB/s against the 10 KB/s floor: a short bar, not a full-height one.
    let mut small = TrafficHistory::default();
    small.push(0, 1_000);
    let mut big = TrafficHistory::default();
    big.push(0, 10_000);
    let (s, b) = (
        count(&render_icon(&small, true), DOWN),
        count(&render_icon(&big, true), DOWN),
    );
    assert!(s > 0 && s * 4 < b, "small {s} big {b}");
}

#[test]
fn ring_keeps_last_eight() {
    let mut h = TrafficHistory::default();
    h.push(0, 5_000_000);
    for _ in 0..8 {
        h.push(0, 0);
    }
    assert_eq!(h.samples().len(), 8);
    assert_eq!(count(&render_icon(&h, true), DOWN), 0);
}

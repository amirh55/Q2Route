//! Pure tray-icon renderer: a dark rounded square with Proxifier-style
//! upload/download bars for the last 8 samples.

use std::collections::VecDeque;

pub const SIZE: usize = 32;
const SAMPLES: usize = 8;
/// Bars never scale below 10 KB/s, so idle noise stays small.
const MIN_SCALE: u64 = 10_000;

const BG: [u8; 3] = [0x1E, 0x1F, 0x24];
const UP: [u8; 3] = [0x4F, 0xC3, 0xF7];
const DOWN: [u8; 3] = [0x66, 0xBB, 0x6A];
const GREY: [u8; 3] = [0x77, 0x77, 0x77];
const PAUSE: [u8; 3] = [0xDD, 0xDD, 0xDD];
const RADIUS: usize = 6;
/// Bars sit on y = BASE and grow up to BAR_MAX pixels.
const BASE: usize = 28;
const BAR_MAX: usize = 24;
/// Each sample is a 3 px column (1 px up, 2 px down) starting at X0.
const X0: usize = 4;

/// Ring of the last 8 `(up_bps, down_bps)` samples, oldest first.
#[derive(Clone, Debug, Default)]
pub struct TrafficHistory {
    samples: VecDeque<(u64, u64)>,
}

impl TrafficHistory {
    pub fn push(&mut self, up: u64, down: u64) {
        if self.samples.len() == SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back((up, down));
    }

    pub fn samples(&self) -> &VecDeque<(u64, u64)> {
        &self.samples
    }
}

struct Canvas(Vec<u8>);

impl Canvas {
    fn put(&mut self, x: usize, y: usize, c: [u8; 3]) {
        let i = (y * SIZE + x) * 4;
        self.0[i..i + 4].copy_from_slice(&[c[0], c[1], c[2], 255]);
    }

    fn rect(&mut self, x: usize, y: usize, w: usize, h: usize, c: [u8; 3]) {
        for yy in y..y + h {
            for xx in x..x + w {
                self.put(xx, yy, c);
            }
        }
    }

    /// A vertical bar of `w` px rising `h` px from BASE.
    fn bar(&mut self, x: usize, w: usize, h: usize, c: [u8; 3]) {
        self.rect(x, BASE - h, w, h, c);
    }
}

/// Whether (x, y) lies inside the rounded background square.
fn inside(x: usize, y: usize) -> bool {
    let d = |v: usize| {
        if v < RADIUS {
            RADIUS - v
        } else if v >= SIZE - RADIUS {
            v + 1 + RADIUS - SIZE
        } else {
            0
        }
    };
    let (dx, dy) = (d(x) as f32 - 0.5, d(y) as f32 - 0.5);
    dx <= 0.0 || dy <= 0.0 || dx * dx + dy * dy <= (RADIUS * RADIUS) as f32
}

fn height(v: u64, scale: u64) -> usize {
    if v == 0 {
        return 0;
    }
    ((v as f64 / scale as f64 * BAR_MAX as f64).round() as usize).clamp(1, BAR_MAX)
}

/// Renders the 32x32 RGBA icon. When `running` is false the bars are grey and
/// a small pause mark (‖) is drawn in the top-right corner.
pub fn render_icon(h: &TrafficHistory, running: bool) -> Vec<u8> {
    let mut c = Canvas(vec![0; SIZE * SIZE * 4]);
    for y in 0..SIZE {
        for x in 0..SIZE {
            if inside(x, y) {
                c.put(x, y, BG);
            }
        }
    }
    let scale = h
        .samples
        .iter()
        .map(|&(u, d)| u.max(d))
        .max()
        .unwrap_or(0)
        .max(MIN_SCALE);
    let (up_c, down_c) = if running { (UP, DOWN) } else { (GREY, GREY) };
    // Newest sample is the right-most column.
    let first = SAMPLES - h.samples.len();
    for (i, &(up, down)) in h.samples.iter().enumerate() {
        let x = X0 + (first + i) * 3;
        c.bar(x, 1, height(up, scale), up_c);
        c.bar(x + 1, 2, height(down, scale), down_c);
    }
    if !running {
        c.rect(21, 3, 8, 10, BG);
        c.rect(23, 4, 2, 8, PAUSE);
        c.rect(26, 4, 2, 8, PAUSE);
    }
    c.0
}

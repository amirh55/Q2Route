//! In-memory ring of the latest log events, fed by a `tracing` layer and
//! served to the UI through `GetLog`.

use std::collections::VecDeque;
use std::fmt::{self, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use q2route_core::ipc::{LogEntry, LogLevel};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Longest stored message, in chars; longer ones are cut and get `…`.
pub const MAX_MSG_CHARS: usize = 1000;
const GLOBAL_CAP: usize = 2000;

struct Inner {
    cap: usize,
    next_seq: AtomicU64,
    entries: Mutex<VecDeque<LogEntry>>,
}

/// Cheap to clone; clones share the same ring.
#[derive(Clone)]
pub struct LogRing(Arc<Inner>);

/// The `tracing` layer that feeds a [`LogRing`].
pub struct RingLayer(LogRing);

impl LogRing {
    pub fn new(cap: usize) -> LogRing {
        LogRing(Arc::new(Inner {
            cap,
            next_seq: AtomicU64::new(1),
            entries: Mutex::new(VecDeque::with_capacity(cap.min(GLOBAL_CAP))),
        }))
    }

    /// Entries with `seq > after`, oldest first.
    pub fn since(&self, after: u64) -> Vec<LogEntry> {
        let g = self.0.entries.lock().unwrap_or_else(|e| e.into_inner());
        g.iter().filter(|e| e.seq > after).cloned().collect()
    }

    pub fn layer(&self) -> RingLayer {
        RingLayer(self.clone())
    }

    fn push(&self, level: LogLevel, target: &str, msg: String) {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        let mut g = self.0.entries.lock().unwrap_or_else(|e| e.into_inner());
        // Seq is taken under the lock so the deque stays ordered.
        let seq = self.0.next_seq.fetch_add(1, Ordering::Relaxed);
        if g.len() >= self.0.cap {
            g.pop_front();
        }
        if self.0.cap > 0 {
            g.push_back(LogEntry {
                seq,
                ms,
                level,
                target: target.to_string(),
                msg,
            });
        }
    }
}

/// The process-wide ring (2000 entries).
pub fn global() -> &'static LogRing {
    static G: OnceLock<LogRing> = OnceLock::new();
    G.get_or_init(|| LogRing::new(GLOBAL_CAP))
}

#[derive(Default)]
struct Fields {
    message: String,
    rest: String,
}

impl Visit for Fields {
    fn record_debug(&mut self, f: &Field, v: &dyn fmt::Debug) {
        if f.name() == "message" {
            let _ = write!(self.message, "{v:?}");
        } else {
            let _ = write!(self.rest, " {}={v:?}", f.name());
        }
    }
}

fn level_of(l: &Level) -> LogLevel {
    match *l {
        Level::ERROR => LogLevel::Error,
        Level::WARN => LogLevel::Warn,
        Level::INFO => LogLevel::Info,
        Level::DEBUG => LogLevel::Debug,
        Level::TRACE => LogLevel::Trace,
    }
}

fn cap_msg(mut s: String) -> String {
    if let Some((i, _)) = s.char_indices().nth(MAX_MSG_CHARS) {
        s.truncate(i);
        s.push('…');
    }
    s
}

impl<S: Subscriber> Layer<S> for RingLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut f = Fields::default();
        event.record(&mut f);
        f.message.push_str(&f.rest);
        let md = event.metadata();
        self.0
            .push(level_of(md.level()), md.target(), cap_msg(f.message));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    fn with_ring<R>(cap: usize, f: impl FnOnce() -> R) -> (LogRing, R) {
        let ring = LogRing::new(cap);
        let sub = tracing_subscriber::registry().with(ring.layer());
        let r = tracing::subscriber::with_default(sub, f);
        (ring, r)
    }

    #[test]
    fn captures_level_target_message_and_fields() {
        let (ring, ()) = with_ring(10, || {
            tracing::warn!(target: "q2route_service::relay", peer = 5, "boom");
        });
        let v = ring.since(0);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].level, LogLevel::Warn);
        assert_eq!(v[0].target, "q2route_service::relay");
        assert!(v[0].msg.contains("boom"), "{}", v[0].msg);
        assert!(v[0].msg.contains("peer=5"), "{}", v[0].msg);
    }

    #[test]
    fn seq_increases_and_since_filters() {
        let (ring, ()) = with_ring(10, || {
            tracing::info!("a");
            tracing::info!("b");
            tracing::info!("c");
        });
        let all = ring.since(0);
        assert_eq!(all.len(), 3);
        assert!(all[0].seq < all[1].seq && all[1].seq < all[2].seq);
        assert_eq!(ring.since(all[0].seq).len(), 2);
    }

    #[test]
    fn ring_drops_oldest() {
        let (ring, ()) = with_ring(5, || {
            for i in 0..12 {
                tracing::info!("m{i}");
            }
        });
        let v = ring.since(0);
        assert_eq!(v.len(), 5);
        assert_eq!(v[0].msg, "m7");
        assert_eq!(v[4].msg, "m11");
        assert!(v.windows(2).all(|w| w[0].seq < w[1].seq));
    }

    #[test]
    fn long_message_cut_on_char_boundary() {
        let long: String = "سلام".chars().cycle().take(1500).collect();
        let (ring, ()) = with_ring(5, || {
            tracing::info!("{long}");
        });
        let m = &ring.since(0)[0].msg;
        assert_eq!(m.chars().count(), MAX_MSG_CHARS + 1);
        assert!(m.ends_with('…'));
    }
}

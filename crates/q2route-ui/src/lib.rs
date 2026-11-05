//! Q2Route desktop UI library: IPC client, views and settings.

pub mod app;
pub mod client;
pub mod settings;
pub mod views;

/// Formats a byte rate: `512 B/s`, `120 KB/s`, `2.4 MB/s` (decimal units).
pub fn format_speed(bps: u64) -> String {
    match bps {
        0..=999 => format!("{bps} B/s"),
        1_000..=999_999 => format!("{} KB/s", bps / 1_000),
        _ => format!("{:.1} MB/s", bps as f64 / 1_000_000.0),
    }
}

#[cfg(test)]
mod tests {
    use super::format_speed;

    #[test]
    fn speeds() {
        assert_eq!(format_speed(0), "0 B/s");
        assert_eq!(format_speed(512), "512 B/s");
        assert_eq!(format_speed(120_000), "120 KB/s");
        assert_eq!(format_speed(2_400_000), "2.4 MB/s");
    }
}

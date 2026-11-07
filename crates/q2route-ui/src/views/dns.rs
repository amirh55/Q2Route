//! DNS: the proxy resolver address, the DoH/DoT block and a cache flush.

use std::net::SocketAddr;

use eframe::egui::{self, Color32};
use q2route_core::config::DnsSettings;
use q2route_core::ipc::{Request, Response, StateSnapshot};
use tokio::sync::oneshot;

use crate::client::Client;

/// True when `s` is a usable `ip:port` resolver address.
pub fn resolver_ok(s: &str) -> bool {
    s.trim().parse::<SocketAddr>().is_ok()
}

/// Editable copy of the DNS settings.
#[derive(Clone, Default)]
struct Form {
    proxy_resolver: String,
}

impl Form {
    fn from_settings(d: &DnsSettings) -> Form {
        Form {
            proxy_resolver: d.proxy_resolver.clone(),
        }
    }

    fn to_settings(&self, base: &DnsSettings) -> DnsSettings {
        DnsSettings {
            proxy_resolver: self.proxy_resolver.trim().to_string(),
            ..base.clone()
        }
    }
}

enum Pending {
    Idle,
    Waiting(oneshot::Receiver<Response>, &'static str),
    Done(Result<&'static str, String>),
}

pub struct DnsView {
    /// `None` until the first snapshot arrives.
    form: Option<Form>,
    pending: Pending,
}

impl Default for DnsView {
    fn default() -> Self {
        DnsView {
            form: None,
            pending: Pending::Idle,
        }
    }
}

impl DnsView {
    fn send(&mut self, client: &Client, r: Request, ok: &'static str) {
        self.pending = Pending::Waiting(client.send(r), ok);
    }

    fn poll(&mut self) {
        if let Pending::Waiting(rx, ok) = &mut self.pending {
            let ok = *ok;
            self.pending = match rx.try_recv() {
                Ok(Response::Error(e)) => Pending::Done(Err(e)),
                Ok(_) => Pending::Done(Ok(ok)),
                Err(oneshot::error::TryRecvError::Closed) => {
                    Pending::Done(Err("disconnected".into()))
                }
                Err(oneshot::error::TryRecvError::Empty) => return,
            };
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui, snap: Option<&StateSnapshot>, client: &Client) {
        let Some(s) = snap else { return };
        self.poll();
        let current = &s.config.settings.dns;
        let form = self
            .form
            .get_or_insert_with(|| Form::from_settings(current));
        ui.heading("DNS");
        ui.add_space(6.0);
        ui.label(
            "Names that match a Direct group (e.g. *.ir) are resolved by your normal DNS server. \
             Every other name is resolved through the proxy at the address above, so your \
             internet provider doesn't see it.",
        );
        ui.add_space(8.0);
        let mut save = false;
        ui.horizontal(|ui| {
            ui.label("Proxy resolver");
            ui.add(
                egui::TextEdit::singleline(&mut form.proxy_resolver)
                    .desired_width(180.0)
                    .hint_text("1.1.1.1:53"),
            );
            let ok = resolver_ok(&form.proxy_resolver);
            save = ui.add_enabled(ok, egui::Button::new("Save")).clicked();
            if !ok {
                ui.colored_label(ui.visuals().error_fg_color, "Use ip:port, e.g. 1.1.1.1:53");
            }
        });
        let mut block = current.block_doh;
        let block_clicked = ui
            .checkbox(&mut block, "Block DoH/DoT for proxied apps")
            .changed();
        let flush = ui.button("Flush DNS cache").clicked();
        let busy = matches!(self.pending, Pending::Waiting(..));
        if save && !busy {
            let d = form.to_settings(current);
            self.send(client, Request::SetDns(d), "Saved");
        } else if block_clicked {
            let d = DnsSettings {
                block_doh: block,
                ..current.clone()
            };
            self.send(client, Request::SetDns(d), "Saved");
        } else if flush {
            self.send(client, Request::FlushDns, "DNS cache flushed");
        }
        match &self.pending {
            Pending::Idle => {}
            Pending::Waiting(..) => {
                ui.spinner();
            }
            Pending::Done(Ok(t)) => {
                ui.colored_label(Color32::from_rgb(0x66, 0xbb, 0x6a), *t);
            }
            Pending::Done(Err(e)) => {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_ok_cases() {
        assert!(resolver_ok("1.1.1.1:53"));
        assert!(resolver_ok(" 9.9.9.9:53 "));
        assert!(resolver_ok("[2606:4700::1111]:53"));
        assert!(!resolver_ok("1.1.1.1"));
        assert!(!resolver_ok("dns.google:53"));
        assert!(!resolver_ok("1.1.1.1:99999"));
        assert!(!resolver_ok(""));
    }
}

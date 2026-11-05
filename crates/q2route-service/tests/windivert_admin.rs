//! WinDivert integration test. Requires an elevated shell (the WinDivert
//! driver can only be loaded by an administrator):
//!
//! `cargo test -p q2route-service --test windivert_admin -- --ignored`

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use q2route_service::winapi::listener_pid;
use q2route_service::windivert::{Handle, Layer, EVENT_SOCKET_CONNECT, FLAG_RECV_ONLY, FLAG_SNIFF};

#[test]
#[ignore = "requires administrator (loads the WinDivert driver)"]
fn socket_layer_reports_pid() {
    let handle = Handle::open(
        "tcp and event == CONNECT",
        Layer::Socket,
        0,
        FLAG_SNIFF | FLAG_RECV_ONLY,
    )
    .expect("WinDivertOpen (are you elevated?)");
    let handle = std::sync::Arc::new(handle);

    let target: SocketAddr = "1.1.1.1:80".parse().unwrap();
    let my_pid = std::process::id();

    let (tx, rx) = mpsc::channel();
    let reader = {
        let handle = handle.clone();
        thread::spawn(move || loop {
            match handle.recv(&mut []) {
                Ok((_, addr)) => {
                    if let Some(sock) = addr.socket() {
                        if tx.send((addr.event(), sock)).is_err() {
                            return;
                        }
                    }
                }
                Err(_) => return, // shutdown
            }
        })
    };

    // Give the reader a moment, then connect (the result does not matter:
    // the CONNECT event fires on the attempt).
    thread::sleep(Duration::from_millis(200));
    let connector = thread::spawn(move || {
        let _ = TcpStream::connect_timeout(&target, Duration::from_secs(3));
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut found = None;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok((event, sock)) => {
                if sock.pid == my_pid && sock.remote == target {
                    found = Some((event, sock));
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    handle.shutdown();
    reader.join().unwrap();
    connector.join().unwrap();

    let (event, sock) = found.expect("no CONNECT SocketData for our pid / 1.1.1.1:80");
    assert_eq!(event, EVENT_SOCKET_CONNECT);
    assert_eq!(sock.pid, my_pid);
    assert_eq!(sock.protocol, 6);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    assert_eq!(
        listener_pid(port, IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Some(my_pid)
    );
}

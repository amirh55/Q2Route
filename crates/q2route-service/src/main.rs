//! `q2route-service.exe install | uninstall | run | console`

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use q2route_core::ipc::PIPE_NAME;
use q2route_service::engine::{Engine, Result};
use q2route_service::ipc_server::{serve_pipe, Control};
use tokio_util::sync::CancellationToken;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

const SERVICE_NAME: &str = "Q2Route";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

fn data_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").unwrap_or_else(|| OsString::from(r"C:\ProgramData"));
    PathBuf::from(base).join("Q2Route")
}

fn config_path() -> PathBuf {
    data_dir().join("config.toml")
}

/// Logs to `%ProgramData%\Q2Route\logs` (daily files), plus stdout in
/// console mode. Keep the guard alive to flush on exit.
fn init_logging(console: bool) -> Option<WorkerGuard> {
    let filter = || EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let logs = data_dir().join("logs");
    let (file, guard) = match std::fs::create_dir_all(&logs) {
        Ok(()) => {
            match tracing_appender::rolling::Builder::new()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .filename_prefix("q2route")
                .filename_suffix("log")
                .max_log_files(14)
                .build(&logs)
            {
                Ok(appender) => {
                    let (w, g) = tracing_appender::non_blocking(appender);
                    (Some(fmt::layer().with_writer(w).with_ansi(false)), Some(g))
                }
                Err(e) => {
                    eprintln!("cannot open log file in {}: {e}", logs.display());
                    (None, None)
                }
            }
        }
        Err(e) => {
            eprintln!("cannot create {}: {e}", logs.display());
            (None, None)
        }
    };
    let stdout = console.then(fmt::layer);
    let _ = tracing_subscriber::registry()
        .with(filter())
        .with(file)
        .with(q2route_service::log_ring::global().layer())
        .with(stdout)
        .try_init();
    guard
}

/// Runs the engine and the pipe server until `stop` fires. Routing is
/// resumed iff it was running at the last shutdown.
async fn serve(stop: CancellationToken) -> Result<()> {
    let engine = Arc::new(Engine::new(config_path())?);
    if engine.last_running() {
        if let Err(e) = engine.start().await {
            tracing::error!("cannot start routing: {e}");
        }
    }
    let pipe_cancel = CancellationToken::new();
    let ctrl: Arc<dyn Control> = engine.clone();
    let mut pipe = tokio::spawn({
        let c = pipe_cancel.clone();
        async move { serve_pipe(ctrl, PIPE_NAME, c).await }
    });
    tokio::select! {
        _ = stop.cancelled() => {}
        r = &mut pipe => {
            tracing::error!("pipe server ended: {r:?}");
            stop.cancelled().await;
        }
    }
    pipe_cancel.cancel();
    // Service stop: everything goes direct, `last_running` is kept.
    engine.shutdown().await?;
    tracing::info!("service stopped");
    Ok(())
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
}

fn console() -> Result<()> {
    let _guard = init_logging(true);
    let rt = runtime()?;
    rt.block_on(async {
        let stop = CancellationToken::new();
        let s = stop.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("Ctrl+C: stopping");
            s.cancel();
        });
        serve(stop).await
    })
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("service failed: {e}");
    }
}

fn status(state: ServiceState, exit: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::from_secs(if state == ServiceState::StopPending {
            10
        } else {
            0
        }),
        process_id: None,
    }
}

fn run_service() -> Result<()> {
    let stop = CancellationToken::new();
    let s = stop.clone();
    let handle = service_control_handler::register(SERVICE_NAME, move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            s.cancel();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    handle.set_service_status(status(ServiceState::Running, 0))?;
    let result = runtime().map_err(Into::into).and_then(|rt| {
        let r = rt.block_on(async {
            let r = serve(stop.clone()).await;
            if r.is_err() {
                // Startup failure: there is nothing to stop.
                stop.cancel();
            }
            r
        });
        let _ = handle.set_service_status(status(ServiceState::StopPending, 0));
        rt.shutdown_timeout(Duration::from_secs(5));
        r
    });
    let exit = if result.is_ok() { 0 } else { 1 };
    handle.set_service_status(status(ServiceState::Stopped, exit))?;
    result
}

/// Windows Firewall rule letting reflected inbound connections reach the
/// relay listener (LocalSystem service, random port, so no prompt appears).
const FIREWALL_RULE: &str = "Q2Route relay";

fn firewall_add_args(exe: &std::path::Path) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "add".into(),
        "rule".into(),
        format!("name=\"{FIREWALL_RULE}\""),
        "dir=in".into(),
        "action=allow".into(),
        format!("program=\"{}\"", exe.display()),
        "enable=yes".into(),
        "profile=any".into(),
        "protocol=TCP".into(),
    ]
}

fn firewall_delete_args() -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "delete".into(),
        "rule".into(),
        format!("name=\"{FIREWALL_RULE}\""),
    ]
}

/// The command line as a user would type it (for warnings).
fn netsh_line(args: &[String]) -> String {
    format!("netsh {}", args.join(" "))
}

/// Runs netsh with `args` passed verbatim (netsh does its own `key="value"`
/// parsing, so the arguments must not be re-quoted).
fn netsh(args: &[String]) -> std::result::Result<(), String> {
    use std::os::windows::process::CommandExt;
    let mut cmd = std::process::Command::new("netsh");
    for a in args {
        cmd.raw_arg(a);
    }
    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} {}",
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Idempotent: deletes any old rule, then adds it. Never fails the install.
fn add_firewall_rule(exe: &std::path::Path) {
    let _ = netsh(&firewall_delete_args());
    let add = firewall_add_args(exe);
    match netsh(&add) {
        Ok(()) => println!("firewall rule '{FIREWALL_RULE}' added"),
        Err(e) => {
            tracing::error!("cannot add firewall rule: {e}");
            eprintln!(
                "warning: cannot add the Windows Firewall rule ({e}).\n\
                 Proxied traffic may be blocked. Run as administrator:\n  {}",
                netsh_line(&add)
            );
        }
    }
}

fn remove_firewall_rule() {
    let del = firewall_delete_args();
    match netsh(&del) {
        Ok(()) => println!("firewall rule '{FIREWALL_RULE}' removed"),
        Err(e) => {
            tracing::error!("cannot remove firewall rule: {e}");
            eprintln!(
                "warning: cannot remove the Windows Firewall rule ({e}). Run as administrator:\n  {}",
                netsh_line(&del)
            );
        }
    }
}

fn install() -> Result<()> {
    let exe = std::env::current_exe()?;
    let mgr = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_NAME.into(),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.clone(),
        launch_arguments: vec!["run".into()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let svc = mgr.create_service(&info, ServiceAccess::START | ServiceAccess::CHANGE_CONFIG)?;
    svc.set_description("Q2Route per-app traffic router")?;
    // Before the start, so the relay is reachable from the first flow.
    add_firewall_rule(&exe);
    svc.start::<&str>(&[])?;
    println!("service {SERVICE_NAME} installed and started");
    Ok(())
}

fn uninstall() -> Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = mgr.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    if svc.query_status()?.current_state != ServiceState::Stopped {
        let _ = svc.stop();
        let deadline = Instant::now() + Duration::from_secs(20);
        while svc.query_status()?.current_state != ServiceState::Stopped
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    svc.delete()?;
    println!("service {SERVICE_NAME} removed");
    remove_firewall_rule();
    Ok(())
}

const USAGE: &str = "usage: q2route-service <install | uninstall | run | console>";

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let r = match cmd.as_str() {
        "install" => install(),
        "uninstall" => uninstall(),
        "console" => console(),
        "run" => {
            let _guard = init_logging(false);
            service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(Into::into)
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(e) = r {
        eprintln!("error: {e}");
        tracing::error!("{cmd} failed: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_add_command() {
        let exe = std::path::Path::new(r"C:\Program Files\Q2Route\q2route-service.exe");
        assert_eq!(
            netsh_line(&firewall_add_args(exe)),
            r#"netsh advfirewall firewall add rule name="Q2Route relay" dir=in action=allow program="C:\Program Files\Q2Route\q2route-service.exe" enable=yes profile=any protocol=TCP"#
        );
    }

    #[test]
    fn firewall_delete_command() {
        assert_eq!(
            netsh_line(&firewall_delete_args()),
            r#"netsh advfirewall firewall delete rule name="Q2Route relay""#
        );
    }
}

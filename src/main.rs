use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use gate::{Allowlist, controller, proxy};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gate=info".parse().unwrap()),
        )
        .json()
        .init();

    let allowlist: Allowlist = Arc::new(RwLock::new(HashSet::new()));

    let upstream_host =
        std::env::var("UPSTREAM_HOST").unwrap_or_else(|_| "kourier.kourier-system.svc".into());
    let tls_listen = std::env::var("TLS_LISTEN").unwrap_or_else(|_| "0.0.0.0:8443".into());
    let http_listen = std::env::var("HTTP_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let health_listen = std::env::var("HEALTH_LISTEN").unwrap_or_else(|_| "0.0.0.0:9090".into());

    info!(
        upstream = upstream_host,
        tls_listen, http_listen, health_listen, "starting gate"
    );

    let tls_proxy = proxy::run_tls_proxy(
        tls_listen,
        upstream_host.clone(),
        443,
        allowlist.clone(),
    );

    let http_proxy = proxy::run_http_proxy(
        http_listen,
        upstream_host.clone(),
        80,
        allowlist.clone(),
    );

    let health = proxy::run_health_server(health_listen);

    let controller = controller::run(allowlist.clone());

    tokio::select! {
        r = tls_proxy => { if let Err(e) = r { tracing::error!(error = %e, "tls proxy exited"); } }
        r = http_proxy => { if let Err(e) = r { tracing::error!(error = %e, "http proxy exited"); } }
        r = health => { if let Err(e) = r { tracing::error!(error = %e, "health server exited"); } }
        r = controller => { if let Err(e) = r { tracing::error!(error = ?e, "controller exited"); } }
    }
}

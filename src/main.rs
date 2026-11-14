use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use gate::cert::{CertStore, DynamicCertResolver};
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
    let cert_store = Arc::new(std::sync::RwLock::new(CertStore::new()));
    let cert_resolver = Arc::new(DynamicCertResolver::new(
        cert_store.clone(),
        allowlist.clone(),
    ));

    let upstream_host =
        std::env::var("UPSTREAM_HOST").unwrap_or_else(|_| "kourier.kourier-system.svc".into());
    let upstream_port = env_u16("UPSTREAM_PORT", 443);
    let tls_listen = std::env::var("TLS_LISTEN").unwrap_or_else(|_| "0.0.0.0:8443".into());
    let http_listen = std::env::var("HTTP_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let health_listen = std::env::var("HEALTH_LISTEN").unwrap_or_else(|_| "0.0.0.0:9090".into());

    info!(
        upstream = upstream_host,
        upstream_port, tls_listen, http_listen, health_listen, "starting gate"
    );

    let limiter = proxy::ConnLimiter::new(
        env_usize("MAX_CONN", 256).clamp(1, 65_536),
        env_usize("MAX_CONN_PER_IP", 50).max(1),
    );

    let options = proxy::ProxyOptions {
        hsts: proxy::hsts_header(env_usize("HSTS_MAX_AGE", 86_400) as u64),
        request_timeout: std::time::Duration::from_secs(
            env_usize("REQUEST_TIMEOUT_SECS", 120).max(1) as u64,
        ),
        ..proxy::ProxyOptions::default()
    };
    let tls_proxy = proxy::run_tls_proxy_with_options(
        tls_listen,
        upstream_host.clone(),
        upstream_port,
        allowlist.clone(),
        cert_resolver,
        limiter.clone(),
        options,
    );

    let http_proxy = proxy::run_http_redirect(http_listen, allowlist.clone(), limiter);

    let sync = Arc::new(controller::SyncStatus::default());
    let health = proxy::run_health_server(
        health_listen,
        sync.clone(),
        std::time::Duration::from_secs(env_usize("SYNC_STALE_SECS", 300) as u64),
    );

    let controller = controller::run(allowlist.clone(), cert_store.clone(), sync);

    tokio::select! {
        r = tls_proxy => { if let Err(e) = r { tracing::error!(error = %e, "tls proxy exited"); } }
        r = http_proxy => { if let Err(e) = r { tracing::error!(error = %e, "http proxy exited"); } }
        r = health => { if let Err(e) = r { tracing::error!(error = %e, "health server exited"); } }
        r = controller => { if let Err(e) = r { tracing::error!(error = ?e, "controller exited"); } }
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u16(key: &str, default: u16) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

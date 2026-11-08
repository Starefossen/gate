use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tracing::{debug, info};

use crate::Allowlist;
use crate::sni;

const MAX_CLIENT_HELLO: usize = 4096;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PROXY_TIMEOUT: Duration = Duration::from_secs(300);

/// Caps concurrent connections globally and per client IP.
/// Shared by both listeners.
#[derive(Clone)]
pub struct ConnLimiter {
    global: Arc<Semaphore>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_ip: usize,
}

pub struct ConnPermit {
    _global: OwnedSemaphorePermit,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl ConnLimiter {
    pub fn new(max_total: usize, max_per_ip: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(max_total)),
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip,
        }
    }

    pub fn try_acquire(&self, ip: IpAddr) -> Option<ConnPermit> {
        let global = self.global.clone().try_acquire_owned().ok()?;
        let mut map = self.per_ip.lock().unwrap();
        let count = map.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            return None;
        }
        *count += 1;
        Some(ConnPermit {
            _global: global,
            per_ip: self.per_ip.clone(),
            ip,
        })
    }
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        let mut map = self.per_ip.lock().unwrap();
        if let Some(count) = map.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

pub async fn run_tls_proxy(
    listen_addr: String,
    upstream_host: String,
    upstream_port: u16,
    allowlist: Allowlist,
    limiter: ConnLimiter,
) -> io::Result<()> {
    let listener = TcpListener::bind(&listen_addr).await?;
    info!(addr = listen_addr, "tls proxy listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let Some(permit) = limiter.try_acquire(peer.ip()) else {
            debug!(peer = %peer, "connection limit reached, dropping");
            continue;
        };
        let upstream_host = upstream_host.clone();
        let allowlist = allowlist.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) =
                handle_tls_connection(stream, &upstream_host, upstream_port, &allowlist).await
            {
                debug!(peer = %peer, error = %e, "tls connection error");
            }
        });
    }
}

async fn handle_tls_connection(
    mut inbound: TcpStream,
    upstream_host: &str,
    upstream_port: u16,
    allowlist: &Allowlist,
) -> io::Result<()> {
    let mut buf = vec![0u8; MAX_CLIENT_HELLO];
    let n = timeout(HANDSHAKE_TIMEOUT, inbound.peek(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timeout"))??;

    let sni_name = match sni::extract_sni(&buf[..n]) {
        Some(name) => name,
        None => {
            debug!("no sni found in client hello");
            return Ok(());
        }
    };

    {
        let allowed = allowlist.read().await;
        if !allowed.contains(&sni_name) {
            debug!(sni = sni_name, "domain not in allowlist, rejecting");
            return Ok(());
        }
    }

    debug!(sni = sni_name, upstream_host, "forwarding tls connection");

    let mut upstream = TcpStream::connect((upstream_host, upstream_port)).await?;
    let _ = timeout(
        PROXY_TIMEOUT,
        copy_bidirectional(&mut inbound, &mut upstream),
    )
    .await;

    Ok(())
}

/// Port 80 never reaches Kourier: allowlisted hosts get a redirect to HTTPS,
/// everything else 403. Plaintext is never proxied, so pipelined requests
/// for other hosts cannot ride along on an allowed connection.
pub async fn run_http_redirect(
    listen_addr: String,
    allowlist: Allowlist,
    limiter: ConnLimiter,
) -> io::Result<()> {
    let listener = TcpListener::bind(&listen_addr).await?;
    info!(addr = listen_addr, "http redirect listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let Some(permit) = limiter.try_acquire(peer.ip()) else {
            debug!(peer = %peer, "connection limit reached, dropping");
            continue;
        };
        let allowlist = allowlist.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_http_connection(stream, &allowlist).await {
                debug!(peer = %peer, error = %e, "http connection error");
            }
        });
    }
}

async fn handle_http_connection(mut inbound: TcpStream, allowlist: &Allowlist) -> io::Result<()> {
    let mut buf = vec![0u8; 4096];
    let n = timeout(HANDSHAKE_TIMEOUT, inbound.read(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timeout"))??;

    let response = http_response(&buf[..n], &*allowlist.read().await);
    inbound.write_all(response.as_bytes()).await?;
    inbound.shutdown().await
}

fn http_response(req: &[u8], allowed: &HashSet<String>) -> String {
    let Some(host) = extract_http_host(req) else {
        return "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into();
    };
    if !allowed.contains(&host) {
        debug!(host, "domain not in allowlist, rejecting");
        return "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into();
    }
    format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{host}{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        extract_path(req)
    )
}

/// Origin-form request target, or "/" for anything else (absolute-form,
/// asterisk, garbage). The host comes from the allowlist, never the target.
fn extract_path(req: &[u8]) -> &str {
    let line = req
        .split(|&b| b == b'\r' || b == b'\n')
        .next()
        .unwrap_or(&[]);
    std::str::from_utf8(line)
        .ok()
        .and_then(|l| l.split(' ').nth(1))
        .filter(|p| {
            p.starts_with('/') && !p.starts_with("//") && p.bytes().all(|b| b.is_ascii_graphic())
        })
        .unwrap_or("/")
}

/// Extract the Host header value from raw HTTP request bytes.
/// Case-insensitive header name matching per HTTP/1.1 spec (RFC 9110 §5.1).
/// Strips port if present (e.g., "example.com:80" -> "example.com").
fn extract_http_host(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;

    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("host") {
            let host = value.trim();
            return Some(
                host.rfind(':')
                    .map(|i| &host[..i])
                    .unwrap_or(host)
                    .to_lowercase(),
            );
        }
    }

    None
}

pub async fn run_health_server(listen_addr: String) -> io::Result<()> {
    let listener = TcpListener::bind(&listen_addr).await?;
    info!(addr = listen_addr, "health server listening");

    loop {
        let (mut stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            let _ = stream.write_all(response).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::RwLock;

    // =========================================================
    // HTTP host extraction tests
    // =========================================================

    #[test]
    fn host_standard() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        assert_eq!(extract_http_host(req), Some("example.com".to_string()));
    }

    #[test]
    fn host_with_port_80() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com:80\r\nAccept: */*\r\n\r\n";
        assert_eq!(extract_http_host(req), Some("example.com".to_string()));
    }

    #[test]
    fn host_with_port_443() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        assert_eq!(extract_http_host(req), Some("example.com".to_string()));
    }

    #[test]
    fn host_with_port_8080() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(extract_http_host(req), Some("example.com".to_string()));
    }

    #[test]
    fn host_lowercase_header() {
        let req = b"GET / HTTP/1.1\r\nhost: Example.COM\r\n\r\n";
        assert_eq!(extract_http_host(req), Some("example.com".to_string()));
    }

    #[test]
    fn host_uppercase_header() {
        let req = b"GET / HTTP/1.1\r\nHOST: example.com\r\n\r\n";
        assert_eq!(extract_http_host(req), Some("example.com".to_string()));
    }

    #[test]
    fn host_mixed_case_header() {
        let req = b"GET / HTTP/1.1\r\nhOsT: example.com\r\n\r\n";
        assert_eq!(extract_http_host(req), Some("example.com".to_string()));
    }

    #[test]
    fn host_missing() {
        let req = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        assert_eq!(extract_http_host(req), None);
    }

    #[test]
    fn host_not_first_header() {
        let req = b"GET / HTTP/1.1\r\nAccept: */*\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_http_host(req), Some("example.com".to_string()));
    }

    #[test]
    fn host_post_request() {
        let req = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{}";
        assert_eq!(extract_http_host(req), Some("api.example.com".to_string()));
    }

    #[test]
    fn host_subdomain() {
        let req = b"GET / HTTP/1.1\r\nHost: hello.hello.fn.flaatten.org\r\n\r\n";
        assert_eq!(
            extract_http_host(req),
            Some("hello.hello.fn.flaatten.org".to_string())
        );
    }

    #[test]
    fn host_empty_request() {
        assert_eq!(extract_http_host(b""), None);
    }

    #[test]
    fn host_only_request_line() {
        let req = b"GET / HTTP/1.1\r\n";
        assert_eq!(extract_http_host(req), None);
    }

    #[test]
    fn host_whitespace_in_value() {
        let req = b"GET / HTTP/1.1\r\nHost:  example.com  \r\n\r\n";
        assert_eq!(extract_http_host(req), Some("example.com".to_string()));
    }

    #[test]
    fn host_no_body_separator() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept:";
        assert_eq!(extract_http_host(req), Some("example.com".to_string()));
    }

    #[test]
    fn host_garbage() {
        assert_eq!(extract_http_host(&[0xFF, 0xFE, 0x00, 0x80]), None);
    }

    // =========================================================
    // Integration tests: TLS proxy
    // =========================================================

    #[tokio::test]
    async fn tls_proxy_allowed_domain() {
        let (upstream_addr, mut upstream_rx) = start_echo_server().await;
        let allowlist = make_allowlist(vec!["allowed.example.com"]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_tls_connection(
                stream,
                &upstream_addr.ip().to_string(),
                upstream_addr.port(),
                &allowlist,
            )
            .await;
        });

        let hello = crate::sni::tests::build_client_hello("allowed.example.com", &[]);
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&hello).await.unwrap();
        client.shutdown().await.unwrap();

        let received = upstream_rx.recv().await.unwrap();
        assert_eq!(&received[..hello.len()], &hello[..]);
    }

    #[tokio::test]
    async fn tls_proxy_rejected_domain() {
        let allowlist = make_allowlist(vec!["allowed.example.com"]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_tls_connection(stream, "127.0.0.1", 1, &allowlist).await;
        });

        let hello = crate::sni::tests::build_client_hello("evil.example.com", &[]);
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&hello).await.unwrap();

        let mut buf = vec![0u8; 1024];
        match client.read(&mut buf).await {
            Ok(0) => {}
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("expected connection close, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn tls_proxy_non_tls_data() {
        let allowlist = make_allowlist(vec!["example.com"]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_tls_connection(stream, "127.0.0.1", 1, &allowlist).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();

        let mut buf = vec![0u8; 1024];
        match client.read(&mut buf).await {
            Ok(0) => {}
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("expected connection close, got {:?}", other),
        }
    }

    // =========================================================
    // Integration tests: HTTP proxy
    // =========================================================

    #[test]
    fn redirect_allowed_host_keeps_path() {
        let allowed = make_set(&["allowed.example.com"]);
        let r = http_response(
            b"GET /a/b?c=1 HTTP/1.1\r\nHost: allowed.example.com:80\r\n\r\n",
            &allowed,
        );
        assert!(r.starts_with("HTTP/1.1 301 "));
        assert!(r.contains("Location: https://allowed.example.com/a/b?c=1\r\n"));
    }

    #[test]
    fn redirect_odd_targets_fall_back_to_root() {
        let allowed = make_set(&["a.example.com"]);
        for target in ["http://evil.com/x", "//evil.com/x", "*", ""] {
            let req = format!("GET {target} HTTP/1.1\r\nHost: a.example.com\r\n\r\n");
            let r = http_response(req.as_bytes(), &allowed);
            assert!(
                r.contains("Location: https://a.example.com/\r\n"),
                "{target}: {r}"
            );
        }
    }

    #[test]
    fn redirect_forbidden_host() {
        let r = http_response(
            b"GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n",
            &make_set(&["a.example.com"]),
        );
        assert!(r.starts_with("HTTP/1.1 403 "));
    }

    #[tokio::test]
    async fn http_pipelined_request_is_not_proxied() {
        let allowlist = make_allowlist(vec!["allowed.example.com"]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_http_connection(stream, &allowlist).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: allowed.example.com\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal.example.com\r\n\r\n")
            .await
            .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).await.unwrap();
        assert_eq!(resp.matches("HTTP/1.1").count(), 1);
        assert!(resp.contains("Location: https://allowed.example.com/\r\n"));
    }

    #[test]
    fn limiter_per_ip_and_global() {
        let l = ConnLimiter::new(3, 2);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let p1 = l.try_acquire(a).unwrap();
        let _p2 = l.try_acquire(a).unwrap();
        assert!(l.try_acquire(a).is_none());
        let _p3 = l.try_acquire(b).unwrap();
        assert!(l.try_acquire(b).is_none(), "global cap");
        drop(p1);
        assert!(l.try_acquire(a).is_some());
    }

    #[test]
    fn limiter_rejection_does_not_leak() {
        let l = ConnLimiter::new(10, 1);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let p = l.try_acquire(a).unwrap();
        for _ in 0..20 {
            assert!(l.try_acquire(a).is_none());
        }
        drop(p);
        assert!(l.per_ip.lock().unwrap().is_empty());
        assert_eq!(l.global.available_permits(), 10);
    }

    #[tokio::test]
    async fn http_proxy_forbidden_domain() {
        let allowlist = make_allowlist(vec!["allowed.example.com"]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_http_connection(stream, &allowlist).await;
        });

        let request = b"GET / HTTP/1.1\r\nHost: evil.example.com\r\n\r\n";
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(request).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        let response = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
    }

    #[tokio::test]
    async fn http_proxy_missing_host() {
        let allowlist = make_allowlist(vec!["example.com"]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_http_connection(stream, &allowlist).await;
        });

        let request = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(request).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        let response = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
    }

    // =========================================================
    // Integration tests: Health server
    // =========================================================

    #[tokio::test]
    async fn health_server_returns_ok() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            let _ = stream.write_all(response).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        let response = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("ok"));
    }

    // =========================================================
    // Test helpers
    // =========================================================

    fn make_set(domains: &[&str]) -> HashSet<String> {
        domains.iter().map(|s| s.to_string()).collect()
    }

    fn make_allowlist(domains: Vec<&str>) -> Allowlist {
        let set: HashSet<String> = domains.into_iter().map(|s| s.to_string()).collect();
        Arc::new(RwLock::new(set))
    }

    async fn start_echo_server() -> (std::net::SocketAddr, tokio::sync::mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = Vec::new();
            let _ = stream.read_to_end(&mut data).await;
            let _ = tx.send(data).await;
        });

        (addr, rx)
    }
}

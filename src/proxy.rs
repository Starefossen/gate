use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info};

use crate::Allowlist;
use crate::sni;

const MAX_CLIENT_HELLO: usize = 4096;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PROXY_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn run_tls_proxy(
    listen_addr: String,
    upstream_host: String,
    upstream_port: u16,
    allowlist: Allowlist,
) -> io::Result<()> {
    let listener = TcpListener::bind(&listen_addr).await?;
    info!(addr = listen_addr, "tls proxy listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let upstream_host = upstream_host.clone();
        let allowlist = allowlist.clone();

        tokio::spawn(async move {
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
    let _ = timeout(PROXY_TIMEOUT, copy_bidirectional(&mut inbound, &mut upstream)).await;

    Ok(())
}

pub async fn run_http_proxy(
    listen_addr: String,
    upstream_host: String,
    upstream_port: u16,
    allowlist: Allowlist,
) -> io::Result<()> {
    let listener = TcpListener::bind(&listen_addr).await?;
    info!(addr = listen_addr, "http proxy listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let upstream_host = upstream_host.clone();
        let allowlist = allowlist.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_http_connection(stream, &upstream_host, upstream_port, &allowlist).await
            {
                debug!(peer = %peer, error = %e, "http connection error");
            }
        });
    }
}

async fn handle_http_connection(
    mut inbound: TcpStream,
    upstream_host: &str,
    upstream_port: u16,
    allowlist: &Allowlist,
) -> io::Result<()> {
    let mut buf = vec![0u8; 4096];
    let n = timeout(HANDSHAKE_TIMEOUT, inbound.peek(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timeout"))??;

    let host = match extract_http_host(&buf[..n]) {
        Some(h) => h,
        None => {
            let response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            inbound.write_all(response).await?;
            return Ok(());
        }
    };

    {
        let allowed = allowlist.read().await;
        if !allowed.contains(&host) {
            debug!(host, "domain not in allowlist, rejecting");
            let response = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            inbound.write_all(response).await?;
            return Ok(());
        }
    }

    debug!(host, upstream_host, "forwarding http connection");

    let mut upstream = TcpStream::connect((upstream_host, upstream_port)).await?;
    let _ = timeout(PROXY_TIMEOUT, copy_bidirectional(&mut inbound, &mut upstream)).await;

    Ok(())
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
    use std::collections::HashSet;
    use std::sync::Arc;
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

    #[tokio::test]
    async fn http_proxy_allowed_domain() {
        let (upstream_addr, mut upstream_rx) = start_echo_server().await;
        let allowlist = make_allowlist(vec!["allowed.example.com"]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_http_connection(
                stream,
                &upstream_addr.ip().to_string(),
                upstream_addr.port(),
                &allowlist,
            )
            .await;
        });

        let request = b"GET / HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n";
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let received = upstream_rx.recv().await.unwrap();
        assert_eq!(&received[..request.len()], &request[..]);
    }

    #[tokio::test]
    async fn http_proxy_forbidden_domain() {
        let allowlist = make_allowlist(vec!["allowed.example.com"]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_http_connection(stream, "127.0.0.1", 1, &allowlist).await;
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
            let _ = handle_http_connection(stream, "127.0.0.1", 1, &allowlist).await;
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

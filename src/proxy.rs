use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode, header};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::Allowlist;
use crate::cert::{self, DynamicCertResolver};
use crate::upstream::{self, ClientType};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Caps concurrent connections globally and per client IP.
/// Shared by all listeners.
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

pub fn default_upstream_tls_config() -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let native_certs = rustls_native_certs::load_native_certs();
    for cert in native_certs.certs {
        let _ = root_store.add(cert);
    }
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

pub async fn run_tls_proxy(
    listen_addr: String,
    upstream_host: String,
    upstream_port: u16,
    allowlist: Allowlist,
    cert_resolver: Arc<DynamicCertResolver>,
    limiter: ConnLimiter,
) -> io::Result<()> {
    run_tls_proxy_with_config(
        listen_addr,
        upstream_host,
        upstream_port,
        allowlist,
        cert_resolver,
        limiter,
        default_upstream_tls_config(),
    )
    .await
}

pub async fn run_tls_proxy_with_config(
    listen_addr: String,
    upstream_host: String,
    upstream_port: u16,
    allowlist: Allowlist,
    cert_resolver: Arc<DynamicCertResolver>,
    limiter: ConnLimiter,
    upstream_tls_config: Arc<rustls::ClientConfig>,
) -> io::Result<()> {
    let listener = TcpListener::bind(&listen_addr).await?;
    info!(addr = listen_addr, "tls proxy listening");

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let upstream_target = format!("{upstream_host}:{upstream_port}");
    let upstream_client = upstream::create_upstream_client(upstream_target, upstream_tls_config);

    loop {
        let (stream, peer) = listener.accept().await?;
        let Some(permit) = limiter.try_acquire(peer.ip()) else {
            warn!(peer = %peer, "connection limit reached, dropping");
            continue;
        };
        let tls_acceptor = tls_acceptor.clone();
        let allowlist = allowlist.clone();
        let upstream_client = upstream_client.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) =
                handle_tls_connection(stream, peer, tls_acceptor, allowlist, upstream_client).await
            {
                debug!(peer = %peer, error = %e, "tls connection closed");
            }
        });
    }
}

async fn handle_tls_connection(
    stream: TcpStream,
    peer: SocketAddr,
    tls_acceptor: TlsAcceptor,
    allowlist: Allowlist,
    upstream_client: ClientType<Incoming>,
) -> io::Result<()> {
    let tls_stream = match timeout(HANDSHAKE_TIMEOUT, tls_acceptor.accept(stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(peer = %peer, error = %e, "tls handshake rejected or failed");
            return Ok(());
        }
        Err(_) => {
            debug!(peer = %peer, "tls handshake timed out");
            return Ok(());
        }
    };

    let sni = match tls_stream.get_ref().1.server_name() {
        Some(s) => cert::normalize_name(s),
        None => {
            debug!(peer = %peer, "no sni in tls connection, closing");
            return Ok(());
        }
    };
    let negotiated_sni = Arc::new(sni);

    let io = TokioIo::new(tls_stream);
    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());

    let service = hyper::service::service_fn({
        let negotiated_sni = negotiated_sni.clone();
        let allowlist = allowlist.clone();
        let upstream_client = upstream_client.clone();
        move |req: Request<Incoming>| {
            let negotiated_sni = negotiated_sni.clone();
            let allowlist = allowlist.clone();
            let upstream_client = upstream_client.clone();
            async move {
                handle_http_request(req, peer, &negotiated_sni, &allowlist, &upstream_client).await
            }
        }
    });

    let _ = builder.serve_connection_with_upgrades(io, service).await;
    Ok(())
}

async fn handle_http_request(
    mut req: Request<Incoming>,
    peer: SocketAddr,
    negotiated_sni: &str,
    allowlist: &Allowlist,
    upstream_client: &ClientType<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let effective_host = match extract_effective_host(&req) {
        Some(h) => h,
        None => {
            debug!(peer = %peer, "missing Host header or authority, rejecting with 421");
            return Ok(misdirected_response());
        }
    };

    if effective_host != negotiated_sni {
        debug!(
            peer = %peer,
            effective_host = %effective_host,
            negotiated_sni = %negotiated_sni,
            "domain-fronting detected: Host != SNI, returning 421"
        );
        return Ok(misdirected_response());
    }

    {
        let allowed = allowlist.read().await;
        if !allowed.contains(&effective_host) {
            debug!(
                peer = %peer,
                effective_host = %effective_host,
                "host not in allowlist, returning 421"
            );
            return Ok(misdirected_response());
        }
    }

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let outgoing_uri =
        match format!("https://{effective_host}{path_and_query}").parse::<hyper::Uri>() {
            Ok(u) => u,
            Err(_) => return Ok(bad_request_response()),
        };

    let is_upgrade = req.headers().get(header::UPGRADE).is_some()
        || req
            .headers()
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false);

    let client_upgrade = if is_upgrade {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let (mut parts, body) = req.into_parts();
    parts.uri = outgoing_uri;

    parts.headers.insert(
        header::HOST,
        header::HeaderValue::from_str(&effective_host).unwrap(),
    );

    parts.headers.insert(
        header::HeaderName::from_static("x-forwarded-proto"),
        header::HeaderValue::from_static("https"),
    );

    let client_ip = peer.ip().to_string();
    if let Some(existing) = parts.headers.get("x-forwarded-for") {
        if let Ok(existing_str) = existing.to_str() {
            let new_xff = format!("{existing_str}, {client_ip}");
            if let Ok(val) = header::HeaderValue::from_str(&new_xff) {
                parts.headers.insert("x-forwarded-for", val);
            }
        }
    } else if let Ok(val) = header::HeaderValue::from_str(&client_ip) {
        parts.headers.insert("x-forwarded-for", val);
    }

    let outgoing_req = Request::from_parts(parts, body);

    let mut upstream_res = match upstream_client.request(outgoing_req).await {
        Ok(res) => res,
        Err(e) => {
            debug!(peer = %peer, error = %e, "upstream request error");
            return Ok(bad_gateway_response());
        }
    };

    if upstream_res.status() == StatusCode::SWITCHING_PROTOCOLS
        && let Some(client_fut) = client_upgrade
    {
        let upstream_fut = hyper::upgrade::on(&mut upstream_res);
        tokio::spawn(async move {
            match tokio::try_join!(client_fut, upstream_fut) {
                Ok((client_io, upstream_io)) => {
                    let mut client_io = TokioIo::new(client_io);
                    let mut upstream_io = TokioIo::new(upstream_io);
                    let _ = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await;
                }
                Err(e) => {
                    debug!(error = %e, "upgrade streaming error");
                }
            }
        });
    }

    let (res_parts, res_body) = upstream_res.into_parts();
    Ok(Response::from_parts(res_parts, res_body.boxed()))
}

fn misdirected_response() -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = Full::new(Bytes::from("421 Misdirected Request\n"))
        .map_err(|e| match e {})
        .boxed();
    Response::builder()
        .status(StatusCode::MISDIRECTED_REQUEST)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, "24")
        .header(header::CONNECTION, "close")
        .body(body)
        .unwrap()
}

fn bad_request_response() -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = Full::new(Bytes::from("400 Bad Request\n"))
        .map_err(|e| match e {})
        .boxed();
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, "16")
        .header(header::CONNECTION, "close")
        .body(body)
        .unwrap()
}

fn bad_gateway_response() -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = Full::new(Bytes::from("502 Bad Gateway\n"))
        .map_err(|e| match e {})
        .boxed();
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, "16")
        .header(header::CONNECTION, "close")
        .body(body)
        .unwrap()
}

/// Extract the effective host from an HTTP request.
/// Checks req.uri().host() first (absolute-form URI and HTTP/2 :authority),
/// then falls back to the Host header.
/// Strips port and normalizes to lowercase without trailing dots.
pub fn extract_effective_host<B>(req: &Request<B>) -> Option<String> {
    if let Some(host) = req.uri().host()
        && !host.is_empty()
    {
        return Some(normalize_host(host));
    }

    if let Some(host_val) = req.headers().get(header::HOST)
        && let Ok(host_str) = host_val.to_str()
    {
        let normalized = normalize_host(host_str);
        if !normalized.is_empty() {
            return Some(normalized);
        }
    }

    None
}

/// Normalizes a host string by stripping any port, IPv6 brackets,
/// trailing dot, and converting to lowercase.
pub fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host_no_port = if host.starts_with('[') {
        if let Some(bracket_end) = host.find(']') {
            &host[..=bracket_end]
        } else {
            host
        }
    } else if let Some((h, _port)) = host.rsplit_once(':') {
        if h.contains(':') { host } else { h }
    } else {
        host
    };

    host_no_port.trim_end_matches('.').to_ascii_lowercase()
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
            warn!(peer = %peer, "connection limit reached, dropping");
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
    use http_body_util::Empty;

    // =========================================================
    // Unit tests: Host/SNI normalization & extraction (Req 6)
    // =========================================================

    #[test]
    fn host_normalization_port_stripping() {
        assert_eq!(normalize_host("example.com"), "example.com");
        assert_eq!(normalize_host("example.com:80"), "example.com");
        assert_eq!(normalize_host("example.com:443"), "example.com");
        assert_eq!(normalize_host("example.com:8443"), "example.com");
        assert_eq!(normalize_host("[::1]:8443"), "[::1]");
        assert_eq!(normalize_host("[::1]"), "[::1]");
    }

    #[test]
    fn host_normalization_case_and_trailing_dot() {
        assert_eq!(normalize_host("Example.COM"), "example.com");
        assert_eq!(normalize_host("example.com."), "example.com");
        assert_eq!(normalize_host("EXAMPLE.COM.:8443"), "example.com");
        assert_eq!(
            normalize_host("  hello.fn.flaatten.org.  "),
            "hello.fn.flaatten.org"
        );
    }

    #[test]
    fn extract_effective_host_standard() {
        let req = Request::builder()
            .uri("/path")
            .header("Host", "hello.hello.fn.flaatten.org")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert_eq!(
            extract_effective_host(&req),
            Some("hello.hello.fn.flaatten.org".to_string())
        );
    }

    #[test]
    fn extract_effective_host_with_port() {
        let req = Request::builder()
            .uri("/path")
            .header("Host", "hello.hello.fn.flaatten.org:8443")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert_eq!(
            extract_effective_host(&req),
            Some("hello.hello.fn.flaatten.org".to_string())
        );
    }

    #[test]
    fn extract_effective_host_mixed_case_and_trailing_dot() {
        let req = Request::builder()
            .uri("/path")
            .header("Host", "Hello.Hello.Fn.Flaatten.Org.:443")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert_eq!(
            extract_effective_host(&req),
            Some("hello.hello.fn.flaatten.org".to_string())
        );
    }

    #[test]
    fn extract_effective_host_absolute_form() {
        let req = Request::builder()
            .uri("https://hello.hello.fn.flaatten.org:8443/api/v1")
            .header("Host", "ignored-if-uri-present.com")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert_eq!(
            extract_effective_host(&req),
            Some("hello.hello.fn.flaatten.org".to_string())
        );
    }

    #[test]
    fn extract_effective_host_missing() {
        let req = Request::builder()
            .uri("/path")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert_eq!(extract_effective_host(&req), None);
    }

    // =========================================================
    // HTTP redirect host extraction tests (Port 80)
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
    // Port 80 redirect tests
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
    // Integration tests: TLS Termination & Domain-Fronting (Req 6)
    // =========================================================

    #[tokio::test]
    async fn test_tls_termination_and_domain_fronting_defense() {
        // 1. Generate self-signed Root CA and Server certificates
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Certificate for "allowed.example.com"
        let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut server_params = rcgen::CertificateParams::default();
        server_params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("allowed.example.com").unwrap(),
        )];
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        // 2. Start a stub upstream HTTPS server (simulating Kourier)
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let mut upstream_server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(
                    server_cert.der().to_vec(),
                )],
                rustls::pki_types::PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
            )
            .unwrap();
        upstream_server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let upstream_acceptor = TlsAcceptor::from(Arc::new(upstream_server_config));

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = upstream_listener.accept().await else {
                    break;
                };
                let acceptor = upstream_acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls_stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let io = TokioIo::new(tls_stream);
                    let service = hyper::service::service_fn(|req: Request<Incoming>| async move {
                        let xff = req
                            .headers()
                            .get("x-forwarded-for")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let proto = req
                            .headers()
                            .get("x-forwarded-proto")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();

                        assert_eq!(proto, "https");
                        assert!(!xff.is_empty());

                        let body = Full::new(Bytes::from("stub upstream ok\n"))
                            .map_err(|e| match e {})
                            .boxed();
                        Ok::<_, hyper::Error>(Response::builder().status(200).body(body).unwrap())
                    });
                    let builder =
                        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                    let _ = builder.serve_connection(io, service).await;
                });
            }
        });

        // 3. Configure Gate CertStore and Resolver
        let mut cert_store = cert::CertStore::new();
        cert_store.set_allowlist(HashSet::from(["allowed.example.com".to_string()]));
        cert_store
            .add_cert(
                "default/allowed",
                server_cert.pem().as_bytes(),
                server_key.serialize_pem().as_bytes(),
            )
            .unwrap();

        let cert_store = Arc::new(std::sync::RwLock::new(cert_store));
        let allowlist = make_allowlist(vec!["allowed.example.com"]);
        let cert_resolver = Arc::new(DynamicCertResolver::new(cert_store, allowlist.clone()));

        // Gate's upstream client trusts our test CA
        let mut client_root_store = rustls::RootCertStore::empty();
        client_root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();
        let upstream_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store)
                .with_no_client_auth(),
        );

        // 4. Start Gate TLS Proxy
        let gate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate_addr = gate_listener.local_addr().unwrap();
        drop(gate_listener);

        let limiter = ConnLimiter::new(100, 50);
        let gate_task = tokio::spawn(run_tls_proxy_with_config(
            gate_addr.to_string(),
            upstream_addr.ip().to_string(),
            upstream_addr.port(),
            allowlist,
            cert_resolver,
            limiter,
            upstream_tls_config,
        ));

        // Yield to allow gate listener to bind
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Configure test client TLS connector trusting our CA
        let mut test_client_roots = rustls::RootCertStore::empty();
        test_client_roots
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();
        let test_client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(test_client_roots)
                .with_no_client_auth(),
        );
        let client_connector = tokio_rustls::TlsConnector::from(test_client_config);

        // =================================================================
        // Case A: Fronted request (SNI = allowed.example.com, Host = fronted.example.com)
        // Must get 421 Misdirected Request!
        // =================================================================
        {
            let tcp = TcpStream::connect(gate_addr).await.unwrap();
            let server_name =
                rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
            let mut tls = client_connector.connect(server_name, tcp).await.unwrap();

            let request =
                b"GET /secret HTTP/1.1\r\nHost: fronted.example.com\r\nConnection: close\r\n\r\n";
            tls.write_all(request).await.unwrap();

            let mut response = String::new();
            tls.read_to_string(&mut response).await.unwrap();
            assert!(
                response.starts_with("HTTP/1.1 421 Misdirected Request"),
                "expected 421 Misdirected Request for domain-fronted attempt, got: {response}"
            );
        }

        // =================================================================
        // Case B: Legitimate request (SNI = allowed.example.com, Host = allowed.example.com)
        // Must be proxied to upstream and return 200 OK!
        // =================================================================
        {
            let tcp = TcpStream::connect(gate_addr).await.unwrap();
            let server_name =
                rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
            let mut tls = client_connector.connect(server_name, tcp).await.unwrap();

            let request =
                b"GET /test HTTP/1.1\r\nHost: allowed.example.com:8443\r\nConnection: close\r\n\r\n";
            tls.write_all(request).await.unwrap();

            let mut response = String::new();
            tls.read_to_string(&mut response).await.unwrap();
            assert!(
                response.starts_with("HTTP/1.1 200 OK"),
                "expected 200 OK for legitimate request, got: {response}"
            );
            assert!(response.contains("stub upstream ok"));
        }

        // =================================================================
        // Case C: Unknown/Non-allowed SNI
        // TLS handshake must be rejected (cannot establish connection)
        // =================================================================
        {
            let tcp = TcpStream::connect(gate_addr).await.unwrap();
            let server_name =
                rustls::pki_types::ServerName::try_from("unknown.example.com".to_string()).unwrap();
            let res = client_connector.connect(server_name, tcp).await;
            assert!(res.is_err(), "expected handshake failure for unallowed SNI");
        }

        gate_task.abort();
    }

    // =========================================================
    // Test helpers
    // =========================================================

    fn make_set(domains: &[&str]) -> HashSet<String> {
        domains.iter().map(|s| s.to_string()).collect()
    }

    fn make_allowlist(domains: Vec<&str>) -> Allowlist {
        let set: HashSet<String> = domains.into_iter().map(|s| s.to_string()).collect();
        Arc::new(tokio::sync::RwLock::new(set))
    }
}

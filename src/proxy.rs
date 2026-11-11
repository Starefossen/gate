use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode, header};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
use tracing::{debug, info, warn};

use crate::Allowlist;
use crate::cert::{self, DynamicCertResolver};
use crate::upstream::{self, ClientType};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct ProxyOptions {
    pub upstream_tls_config: Arc<rustls::ClientConfig>,
    pub handshake_timeout: Duration,
    pub header_read_timeout: Duration,
    pub h2_keep_alive_interval: Duration,
    pub h2_keep_alive_timeout: Duration,
    pub tunnel_idle_timeout: Duration,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        Self {
            upstream_tls_config: default_upstream_tls_config(),
            handshake_timeout: Duration::from_secs(10),
            header_read_timeout: Duration::from_secs(15),
            h2_keep_alive_interval: Duration::from_secs(30),
            h2_keep_alive_timeout: Duration::from_secs(10),
            tunnel_idle_timeout: Duration::from_secs(10 * 60),
        }
    }
}

struct ActivityStream<T> {
    inner: T,
    tx: tokio::sync::mpsc::Sender<()>,
}

impl<T> ActivityStream<T> {
    fn new(inner: T, tx: tokio::sync::mpsc::Sender<()>) -> Self {
        Self { inner, tx }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ActivityStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res
            && buf.filled().len() > before
        {
            let _ = self.tx.try_send(());
        }
        res
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ActivityStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

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
    run_tls_proxy_with_options(
        listen_addr,
        upstream_host,
        upstream_port,
        allowlist,
        cert_resolver,
        limiter,
        ProxyOptions::default(),
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
    let options = ProxyOptions {
        upstream_tls_config,
        ..ProxyOptions::default()
    };
    run_tls_proxy_with_options(
        listen_addr,
        upstream_host,
        upstream_port,
        allowlist,
        cert_resolver,
        limiter,
        options,
    )
    .await
}

pub async fn run_tls_proxy_with_options(
    listen_addr: String,
    upstream_host: String,
    upstream_port: u16,
    allowlist: Allowlist,
    cert_resolver: Arc<DynamicCertResolver>,
    limiter: ConnLimiter,
    options: ProxyOptions,
) -> io::Result<()> {
    let listener = TcpListener::bind(&listen_addr).await?;
    info!(addr = listen_addr, "tls proxy listening");

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let upstream_target = format!("{upstream_host}:{upstream_port}");
    let upstream_client =
        upstream::create_upstream_client(upstream_target, options.upstream_tls_config.clone());

    loop {
        let (stream, peer) = listener.accept().await?;
        let Some(permit) = limiter.try_acquire(peer.ip()) else {
            warn!(peer = %peer, "connection limit reached, dropping");
            continue;
        };
        let tls_acceptor = tls_acceptor.clone();
        let allowlist = allowlist.clone();
        let upstream_client = upstream_client.clone();
        let options = options.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_tls_connection(
                stream,
                peer,
                tls_acceptor,
                allowlist,
                upstream_client,
                options,
                permit,
            )
            .await
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
    options: ProxyOptions,
    permit: ConnPermit,
) -> io::Result<()> {
    let permit = Arc::new(permit);
    let tls_stream = match timeout(options.handshake_timeout, tls_acceptor.accept(stream)).await {
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
    let is_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");

    let service = hyper::service::service_fn({
        let negotiated_sni = negotiated_sni.clone();
        let allowlist = allowlist.clone();
        let upstream_client = upstream_client.clone();
        let permit = permit.clone();
        let options = options.clone();
        move |req: Request<Incoming>| {
            let negotiated_sni = negotiated_sni.clone();
            let allowlist = allowlist.clone();
            let upstream_client = upstream_client.clone();
            let permit = permit.clone();
            let options = options.clone();
            async move {
                handle_http_request(
                    req,
                    peer,
                    &negotiated_sni,
                    &allowlist,
                    &upstream_client,
                    permit,
                    &options,
                )
                .await
            }
        }
    });

    // ALPN already chose the protocol. hyper-util's auto builder would sniff
    // the first bytes with no timeout, letting an idle client hold its permit.
    // hyper's h2 server has no deadline for the client preface either, so read
    // it here under header_read_timeout and replay it to hyper.
    if is_h2 {
        let mut tls_stream = tls_stream;
        let mut preface = [0u8; H2_PREFACE.len()];
        match timeout(
            options.header_read_timeout,
            tls_stream.read_exact(&mut preface),
        )
        .await
        {
            Ok(Ok(_)) if preface == *H2_PREFACE => {}
            _ => {
                debug!(peer = %peer, "no valid h2 preface before timeout, closing");
                return Ok(());
            }
        }
        let (rd, wr) = tokio::io::split(tls_stream);
        let io = TokioIo::new(tokio::io::join(std::io::Cursor::new(preface).chain(rd), wr));
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .keep_alive_interval(options.h2_keep_alive_interval)
            .keep_alive_timeout(options.h2_keep_alive_timeout)
            .serve_connection(io, service)
            .await;
    } else {
        let io = TokioIo::new(tls_stream);
        let _ = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(options.header_read_timeout)
            .serve_connection(io, service)
            .with_upgrades()
            .await;
    }
    let _permit = permit;
    Ok(())
}

async fn handle_http_request(
    mut req: Request<Incoming>,
    peer: SocketAddr,
    negotiated_sni: &str,
    allowlist: &Allowlist,
    upstream_client: &ClientType<Incoming>,
    permit: Arc<ConnPermit>,
    options: &ProxyOptions,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    if req.method() == hyper::Method::CONNECT {
        debug!(peer = %peer, "rejecting CONNECT method with 405");
        return Ok(method_not_allowed_response());
    }

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

    let is_websocket_upgrade = req.version() == hyper::Version::HTTP_11 && {
        let has_upgrade_ws = req
            .headers()
            .get(header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);
        let has_conn_upgrade = req
            .headers()
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                v.split(',')
                    .any(|s| s.trim().eq_ignore_ascii_case("upgrade"))
            })
            .unwrap_or(false);
        has_upgrade_ws && has_conn_upgrade
    };

    let client_upgrade = if is_websocket_upgrade {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let mut headers_to_remove = Vec::new();
    if let Some(conn_val) = req.headers().get(header::CONNECTION)
        && let Ok(conn_str) = conn_val.to_str()
    {
        for name in conn_str.split(',') {
            let name = name.trim();
            if !name.is_empty() && (!is_websocket_upgrade || !name.eq_ignore_ascii_case("upgrade"))
            {
                headers_to_remove.push(name.to_ascii_lowercase());
            }
        }
    }

    let (mut parts, body) = req.into_parts();
    parts.version = hyper::Version::HTTP_11;
    parts.uri = outgoing_uri;

    for h in &headers_to_remove {
        parts.headers.remove(h.as_str());
    }

    parts.headers.remove("x-forwarded-host");
    parts.headers.remove("forwarded");
    parts.headers.remove("x-real-ip");
    parts.headers.remove("keep-alive");
    parts.headers.remove(header::TE);
    parts.headers.remove(header::TRAILER);
    parts.headers.remove(header::TRANSFER_ENCODING);

    if is_websocket_upgrade {
        parts.headers.insert(
            header::UPGRADE,
            header::HeaderValue::from_static("websocket"),
        );
        parts.headers.insert(
            header::CONNECTION,
            header::HeaderValue::from_static("Upgrade"),
        );
    } else {
        parts.headers.remove(header::UPGRADE);
        parts.headers.remove(header::CONNECTION);
    }

    let proxy_headers: Vec<header::HeaderName> = parts
        .headers
        .keys()
        .filter(|name| name.as_str().starts_with("proxy-"))
        .cloned()
        .collect();
    for h in proxy_headers {
        parts.headers.remove(&h);
    }

    parts.headers.insert(
        header::HOST,
        header::HeaderValue::from_str(&effective_host).unwrap(),
    );

    parts.headers.insert(
        header::HeaderName::from_static("x-forwarded-proto"),
        header::HeaderValue::from_static("https"),
    );

    let client_ip = peer.ip().to_string();
    parts.headers.insert(
        header::HeaderName::from_static("x-forwarded-for"),
        header::HeaderValue::from_str(&client_ip).unwrap(),
    );

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
        let tunnel_permit = permit.clone();
        let upstream_fut = hyper::upgrade::on(&mut upstream_res);
        let idle_timeout = options.tunnel_idle_timeout;
        tokio::spawn(async move {
            let _permit = tunnel_permit;
            match tokio::try_join!(client_fut, upstream_fut) {
                Ok((client_io, upstream_io)) => {
                    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
                    let mut client_io = ActivityStream::new(TokioIo::new(client_io), tx.clone());
                    let mut upstream_io = ActivityStream::new(TokioIo::new(upstream_io), tx);
                    let mut sleep = Box::pin(tokio::time::sleep(idle_timeout));
                    let copy_fut = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io);
                    tokio::pin!(copy_fut);

                    loop {
                        tokio::select! {
                            _ = &mut sleep => {
                                debug!("tunnel idle timeout reached");
                                break;
                            }
                            Some(()) = rx.recv() => {
                                sleep.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                            }
                            res = &mut copy_fut => {
                                if let Err(e) = res {
                                    debug!(error = %e, "upgrade streaming error");
                                }
                                break;
                            }
                        }
                    }
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

fn method_not_allowed_response() -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = Full::new(Bytes::from("405 Method Not Allowed\n"))
        .map_err(|e| match e {})
        .boxed();
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(
            header::ALLOW,
            "GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS",
        )
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, "23")
        .header(header::CONNECTION, "close")
        .body(body)
        .unwrap()
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

        // Server certificate covering BOTH allowed.example.com AND fronted.example.com
        let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut server_params = rcgen::CertificateParams::default();
        server_params.subject_alt_names = vec![
            rcgen::SanType::DnsName(rcgen::Ia5String::try_from("allowed.example.com").unwrap()),
            rcgen::SanType::DnsName(rcgen::Ia5String::try_from("fronted.example.com").unwrap()),
        ];
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
        upstream_server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
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
                        assert_eq!(xff, "127.0.0.1");

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

        // 3. Configure Gate CertStore and Resolver with BOTH domains allowlisted!
        let mut cert_store = cert::CertStore::new();
        cert_store.set_allowlist(HashSet::from([
            "allowed.example.com".to_string(),
            "fronted.example.com".to_string(),
        ]));
        cert_store
            .add_cert(
                "default/allowed",
                server_cert.pem().as_bytes(),
                server_key.serialize_pem().as_bytes(),
            )
            .unwrap();

        let cert_store = Arc::new(std::sync::RwLock::new(cert_store));
        let allowlist = make_allowlist(vec!["allowed.example.com", "fronted.example.com"]);
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
        let mut test_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(test_client_roots)
            .with_no_client_auth();
        let mut h1_client_config = test_client_config.clone();
        h1_client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let h1_connector = tokio_rustls::TlsConnector::from(Arc::new(h1_client_config));
        test_client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let client_connector = tokio_rustls::TlsConnector::from(Arc::new(test_client_config));

        // =================================================================
        // Case A1: Fronted request via HTTP/1.1 Host header
        // SNI = allowed.example.com, Host = fronted.example.com (both allowlisted!)
        // Must get 421 Misdirected Request because Host != SNI!
        // =================================================================
        {
            let tcp = TcpStream::connect(gate_addr).await.unwrap();
            let server_name =
                rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
            let mut tls = h1_connector.connect(server_name, tcp).await.unwrap();

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
        // Case A2: Fronted request via HTTP/1.1 absolute-form URI
        // SNI = allowed.example.com, URI host = fronted.example.com
        // Must get 421 Misdirected Request because absolute URI host != SNI!
        // =================================================================
        {
            let tcp = TcpStream::connect(gate_addr).await.unwrap();
            let server_name =
                rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
            let mut tls = h1_connector.connect(server_name, tcp).await.unwrap();

            let request =
                b"GET https://fronted.example.com/secret HTTP/1.1\r\nHost: allowed.example.com\r\nConnection: close\r\n\r\n";
            tls.write_all(request).await.unwrap();

            let mut response = String::new();
            tls.read_to_string(&mut response).await.unwrap();
            assert!(
                response.starts_with("HTTP/1.1 421 Misdirected Request"),
                "expected 421 for absolute-form domain-fronted attempt, got: {response}"
            );
        }

        // =================================================================
        // Case A3: Fronted request via HTTP/2 :authority pseudo-header
        // SNI = allowed.example.com, :authority = fronted.example.com
        // Must get 421 Misdirected Request because :authority != SNI!
        // =================================================================
        {
            let tcp = TcpStream::connect(gate_addr).await.unwrap();
            let server_name =
                rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
            let tls = client_connector.connect(server_name, tcp).await.unwrap();

            let (mut client, h2_conn) = h2::client::handshake(tls).await.unwrap();
            tokio::spawn(async move {
                let _ = h2_conn.await;
            });

            let req = hyper::Request::builder()
                .method("GET")
                .uri("https://fronted.example.com/secret")
                .body(())
                .unwrap();
            let (res_fut, _) = client.send_request(req, true).unwrap();
            let res = res_fut.await.unwrap();
            assert_eq!(
                res.status(),
                hyper::StatusCode::MISDIRECTED_REQUEST,
                "expected 421 Misdirected Request for h2 :authority fronting"
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
            let mut tls = h1_connector.connect(server_name, tcp).await.unwrap();

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

    #[tokio::test]
    async fn test_idle_connection_gets_closed() {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut server_params = rcgen::CertificateParams::default();
        server_params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("allowed.example.com").unwrap(),
        )];
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

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

        let mut client_root_store = rustls::RootCertStore::empty();
        client_root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();
        let upstream_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store.clone())
                .with_no_client_auth(),
        );

        let gate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate_addr = gate_listener.local_addr().unwrap();
        drop(gate_listener);

        let limiter = ConnLimiter::new(10, 10);
        let options = ProxyOptions {
            upstream_tls_config,
            header_read_timeout: Duration::from_millis(150),
            ..ProxyOptions::default()
        };

        let gate_task = tokio::spawn(run_tls_proxy_with_options(
            gate_addr.to_string(),
            "127.0.0.1".into(),
            9999,
            allowlist,
            cert_resolver,
            limiter.clone(),
            options,
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let test_client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store)
                .with_no_client_auth(),
        );
        let client_connector = tokio_rustls::TlsConnector::from(test_client_config);

        let tcp = TcpStream::connect(gate_addr).await.unwrap();
        let server_name =
            rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
        let mut tls = client_connector.connect(server_name, tcp).await.unwrap();

        // Check that permit was acquired
        let peer_ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            *limiter.per_ip.lock().unwrap().get(&peer_ip).unwrap_or(&0),
            1
        );

        // Sit idle without sending any HTTP data. Read from connection expecting EOF on timeout.
        let mut buf = [0u8; 128];
        let n = tls.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "expected EOF from closed idle connection");

        // Wait brief moment for task cleanup and verify permit was dropped
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            *limiter.per_ip.lock().unwrap().get(&peer_ip).unwrap_or(&0),
            0
        );

        gate_task.abort();
    }

    #[tokio::test]
    async fn test_idle_h2_connection_gets_closed() {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut server_params = rcgen::CertificateParams::default();
        server_params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("allowed.example.com").unwrap(),
        )];
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

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

        let mut client_root_store = rustls::RootCertStore::empty();
        client_root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();
        let upstream_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store.clone())
                .with_no_client_auth(),
        );

        let gate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate_addr = gate_listener.local_addr().unwrap();
        drop(gate_listener);

        let limiter = ConnLimiter::new(10, 10);
        let options = ProxyOptions {
            upstream_tls_config,
            header_read_timeout: Duration::from_millis(150),
            ..ProxyOptions::default()
        };

        let gate_task = tokio::spawn(run_tls_proxy_with_options(
            gate_addr.to_string(),
            "127.0.0.1".into(),
            9999,
            allowlist,
            cert_resolver,
            limiter.clone(),
            options,
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut test_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(client_root_store)
            .with_no_client_auth();
        test_client_config.alpn_protocols = vec![b"h2".to_vec()];
        let test_client_config = Arc::new(test_client_config);
        let client_connector = tokio_rustls::TlsConnector::from(test_client_config);

        let tcp = TcpStream::connect(gate_addr).await.unwrap();
        let server_name =
            rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
        let mut tls = client_connector.connect(server_name, tcp).await.unwrap();

        // Check that permit was acquired
        let peer_ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            *limiter.per_ip.lock().unwrap().get(&peer_ip).unwrap_or(&0),
            1
        );

        // Sit idle without sending any HTTP data. Read from connection expecting EOF on timeout.
        let mut buf = [0u8; 128];
        let n = tls.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "expected EOF from closed idle connection");

        // Wait brief moment for task cleanup and verify permit was dropped
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            *limiter.per_ip.lock().unwrap().get(&peer_ip).unwrap_or(&0),
            0
        );

        gate_task.abort();
    }

    #[tokio::test]
    async fn test_connect_method_rejected_with_405() {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut server_params = rcgen::CertificateParams::default();
        server_params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("allowed.example.com").unwrap(),
        )];
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

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

        let mut client_root_store = rustls::RootCertStore::empty();
        client_root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();
        let upstream_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store.clone())
                .with_no_client_auth(),
        );

        let gate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate_addr = gate_listener.local_addr().unwrap();
        drop(gate_listener);

        let limiter = ConnLimiter::new(10, 10);
        let gate_task = tokio::spawn(run_tls_proxy_with_config(
            gate_addr.to_string(),
            "127.0.0.1".into(),
            9999,
            allowlist,
            cert_resolver,
            limiter,
            upstream_tls_config,
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let test_client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store)
                .with_no_client_auth(),
        );
        let client_connector = tokio_rustls::TlsConnector::from(test_client_config);

        let tcp = TcpStream::connect(gate_addr).await.unwrap();
        let server_name =
            rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
        let mut tls = client_connector.connect(server_name, tcp).await.unwrap();

        let req = b"CONNECT allowed.example.com:443 HTTP/1.1\r\nHost: allowed.example.com\r\nConnection: close\r\n\r\n";
        tls.write_all(req).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tls.read(&mut buf).await.unwrap();
        let res = String::from_utf8_lossy(&buf[..n]);
        assert!(
            res.starts_with("HTTP/1.1 405 Method Not Allowed"),
            "got: {res}"
        );

        gate_task.abort();
    }

    #[tokio::test]
    async fn test_edge_headers_and_hop_by_hop_sanitization() {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut server_params = rcgen::CertificateParams::default();
        server_params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("allowed.example.com").unwrap(),
        )];
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

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
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let tls_stream = upstream_acceptor.accept(stream).await.unwrap();
            let io = TokioIo::new(tls_stream);
            let service = hyper::service::service_fn(|req: Request<Incoming>| async move {
                // Verify edge headers:
                let xff = req
                    .headers()
                    .get("x-forwarded-for")
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert_eq!(xff, "127.0.0.1", "XFF must not contain spoofed IP");
                assert_eq!(req.headers().get("x-forwarded-proto").unwrap(), "https");
                assert!(req.headers().get("x-forwarded-host").is_none());
                assert!(req.headers().get("forwarded").is_none());
                assert!(req.headers().get("x-real-ip").is_none());

                // Verify hop-by-hop stripped:
                assert!(req.headers().get("x-custom-hop").is_none());
                assert!(req.headers().get("keep-alive").is_none());
                assert!(req.headers().get("proxy-auth").is_none());
                assert!(req.headers().get(header::UPGRADE).is_none());

                let body = Full::new(Bytes::from("sanitized ok\n"))
                    .map_err(|e| match e {})
                    .boxed();
                Ok::<_, hyper::Error>(Response::builder().status(200).body(body).unwrap())
            });
            let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            let _ = builder.serve_connection(io, service).await;
        });

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

        let mut client_root_store = rustls::RootCertStore::empty();
        client_root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();
        let upstream_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store.clone())
                .with_no_client_auth(),
        );

        let gate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate_addr = gate_listener.local_addr().unwrap();
        drop(gate_listener);

        let limiter = ConnLimiter::new(10, 10);
        let gate_task = tokio::spawn(run_tls_proxy_with_config(
            gate_addr.to_string(),
            upstream_addr.ip().to_string(),
            upstream_addr.port(),
            allowlist,
            cert_resolver,
            limiter,
            upstream_tls_config,
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let test_client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store)
                .with_no_client_auth(),
        );
        let client_connector = tokio_rustls::TlsConnector::from(test_client_config);

        let tcp = TcpStream::connect(gate_addr).await.unwrap();
        let server_name =
            rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
        let mut tls = client_connector.connect(server_name, tcp).await.unwrap();

        let req = concat!(
            "GET /test HTTP/1.1\r\n",
            "Host: allowed.example.com\r\n",
            "X-Forwarded-For: 198.51.100.1\r\n",
            "X-Forwarded-Host: spoofed.com\r\n",
            "Forwarded: for=198.51.100.1\r\n",
            "X-Real-IP: 198.51.100.1\r\n",
            "Connection: close, X-Custom-Hop\r\n",
            "X-Custom-Hop: hop-value\r\n",
            "Keep-Alive: timeout=5\r\n",
            "Proxy-Auth: secret\r\n",
            "Upgrade: bogus\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tls.read(&mut buf).await.unwrap();
        let res = String::from_utf8_lossy(&buf[..n]);
        assert!(res.starts_with("HTTP/1.1 200 OK"), "got: {res}");
        assert!(res.contains("sanitized ok"));

        gate_task.abort();
    }

    #[tokio::test]
    async fn test_h1_request_with_upstream_delay_succeeds() {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut server_params = rcgen::CertificateParams::default();
        server_params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("allowed.example.com").unwrap(),
        )];
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

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
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let tls_stream = upstream_acceptor.accept(stream).await.unwrap();
            let io = TokioIo::new(tls_stream);
            let service = hyper::service::service_fn(|_req: Request<Incoming>| async move {
                // Delay longer than gate's header_read_timeout (100ms)
                tokio::time::sleep(Duration::from_millis(250)).await;
                let body = Full::new(Bytes::from("delayed upstream ok\n"))
                    .map_err(|e| match e {})
                    .boxed();
                Ok::<_, hyper::Error>(Response::builder().status(200).body(body).unwrap())
            });
            let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            let _ = builder.serve_connection(io, service).await;
        });

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

        let mut client_root_store = rustls::RootCertStore::empty();
        client_root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();
        let upstream_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store.clone())
                .with_no_client_auth(),
        );

        let gate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate_addr = gate_listener.local_addr().unwrap();
        drop(gate_listener);

        let limiter = ConnLimiter::new(10, 10);
        let options = ProxyOptions {
            upstream_tls_config,
            header_read_timeout: Duration::from_millis(100),
            ..ProxyOptions::default()
        };

        let gate_task = tokio::spawn(run_tls_proxy_with_options(
            gate_addr.to_string(),
            upstream_addr.ip().to_string(),
            upstream_addr.port(),
            allowlist,
            cert_resolver,
            limiter,
            options,
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let test_client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store)
                .with_no_client_auth(),
        );
        let client_connector = tokio_rustls::TlsConnector::from(test_client_config);

        let tcp = TcpStream::connect(gate_addr).await.unwrap();
        let server_name =
            rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
        let mut tls = client_connector.connect(server_name, tcp).await.unwrap();

        let request =
            b"GET /delayed HTTP/1.1\r\nHost: allowed.example.com\r\nConnection: close\r\n\r\n";
        tls.write_all(request).await.unwrap();

        let mut response = String::new();
        tls.read_to_string(&mut response).await.unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "expected 200 OK for delayed response, got: {response}"
        );
        assert!(response.contains("delayed upstream ok"));

        gate_task.abort();
    }

    #[tokio::test]
    async fn test_h2_client_forwarding() {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut server_params = rcgen::CertificateParams::default();
        server_params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("allowed.example.com").unwrap(),
        )];
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

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
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let tls_stream = upstream_acceptor.accept(stream).await.unwrap();
            let io = TokioIo::new(tls_stream);
            let service = hyper::service::service_fn(|req: Request<Incoming>| async move {
                // Downstream h2 request MUST be forwarded as HTTP/1.1 to upstream
                assert_eq!(req.version(), hyper::Version::HTTP_11);

                // Downstream :authority MUST become Host header upstream
                let host = req
                    .headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                assert_eq!(host, "allowed.example.com");

                let body = Full::new(Bytes::from("h2 to h1 upstream ok\n"))
                    .map_err(|e| match e {})
                    .boxed();
                Ok::<_, hyper::Error>(Response::builder().status(200).body(body).unwrap())
            });
            let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            let _ = builder.serve_connection(io, service).await;
        });

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

        let mut client_root_store = rustls::RootCertStore::empty();
        client_root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();
        let upstream_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store.clone())
                .with_no_client_auth(),
        );

        let gate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate_addr = gate_listener.local_addr().unwrap();
        drop(gate_listener);

        let limiter = ConnLimiter::new(10, 10);
        let gate_task = tokio::spawn(run_tls_proxy_with_config(
            gate_addr.to_string(),
            upstream_addr.ip().to_string(),
            upstream_addr.port(),
            allowlist,
            cert_resolver,
            limiter,
            upstream_tls_config,
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut test_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(client_root_store)
            .with_no_client_auth();
        test_client_config.alpn_protocols = vec![b"h2".to_vec()];
        let client_connector = tokio_rustls::TlsConnector::from(Arc::new(test_client_config));

        let tcp = TcpStream::connect(gate_addr).await.unwrap();
        let server_name =
            rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
        let tls = client_connector.connect(server_name, tcp).await.unwrap();

        // Verify ALPN h2 negotiated
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let (mut client, h2_conn) = h2::client::handshake(tls).await.unwrap();
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        // Request without explicit Host header, only :authority
        let req = hyper::Request::builder()
            .method("GET")
            .uri("https://allowed.example.com/test-h2")
            .body(())
            .unwrap();
        let (res_fut, _) = client.send_request(req, true).unwrap();
        let mut res = res_fut.await.unwrap();
        assert_eq!(res.status(), hyper::StatusCode::OK);

        let mut body = Vec::new();
        while let Some(chunk) = res.body_mut().data().await {
            body.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(body, b"h2 to h1 upstream ok\n");

        gate_task.abort();
    }

    async fn start_websocket_upstream(
        server_cert_der: Vec<u8>,
        server_key_der: Vec<u8>,
    ) -> SocketAddr {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let mut upstream_server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(server_cert_der)],
                rustls::pki_types::PrivateKeyDer::Pkcs8(server_key_der.into()),
            )
            .unwrap();
        upstream_server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let upstream_acceptor = TlsAcceptor::from(Arc::new(upstream_server_config));

        tokio::spawn(async move {
            while let Ok((stream, _)) = upstream_listener.accept().await {
                let acceptor = upstream_acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls_stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let io = TokioIo::new(tls_stream);
                    let service =
                        hyper::service::service_fn(|mut req: Request<Incoming>| async move {
                            let is_ws = req
                                .headers()
                                .get(header::UPGRADE)
                                .and_then(|v| v.to_str().ok())
                                .map(|v| v.eq_ignore_ascii_case("websocket"))
                                .unwrap_or(false);
                            if is_ws {
                                let upgrade_fut = hyper::upgrade::on(&mut req);
                                tokio::spawn(async move {
                                    if let Ok(upgraded) = upgrade_fut.await {
                                        let upgraded = TokioIo::new(upgraded);
                                        let (mut rd, mut wr) = tokio::io::split(upgraded);
                                        let _ = tokio::io::copy(&mut rd, &mut wr).await;
                                    }
                                });
                                let body =
                                    http_body_util::Empty::new().map_err(|e| match e {}).boxed();
                                let res = Response::builder()
                                    .status(StatusCode::SWITCHING_PROTOCOLS)
                                    .header(header::UPGRADE, "websocket")
                                    .header(header::CONNECTION, "Upgrade")
                                    .header(
                                        header::SEC_WEBSOCKET_ACCEPT,
                                        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
                                    )
                                    .body(body)
                                    .unwrap();
                                Ok::<_, hyper::Error>(res)
                            } else {
                                let body = Full::new(Bytes::from("not websocket\n"))
                                    .map_err(|e| match e {})
                                    .boxed();
                                Ok::<_, hyper::Error>(
                                    Response::builder().status(200).body(body).unwrap(),
                                )
                            }
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await;
                });
            }
        });

        upstream_addr
    }

    #[tokio::test]
    async fn test_websocket_echo() {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut server_params = rcgen::CertificateParams::default();
        server_params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("allowed.example.com").unwrap(),
        )];
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        let upstream_addr =
            start_websocket_upstream(server_cert.der().to_vec(), server_key.serialize_der()).await;

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

        let mut client_root_store = rustls::RootCertStore::empty();
        client_root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();
        let upstream_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store.clone())
                .with_no_client_auth(),
        );

        let gate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate_addr = gate_listener.local_addr().unwrap();
        drop(gate_listener);

        let limiter = ConnLimiter::new(10, 10);
        let gate_task = tokio::spawn(run_tls_proxy_with_config(
            gate_addr.to_string(),
            upstream_addr.ip().to_string(),
            upstream_addr.port(),
            allowlist,
            cert_resolver,
            limiter,
            upstream_tls_config,
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let test_client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store)
                .with_no_client_auth(),
        );
        let client_connector = tokio_rustls::TlsConnector::from(test_client_config);

        let tcp = TcpStream::connect(gate_addr).await.unwrap();
        let server_name =
            rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
        let mut tls = client_connector.connect(server_name, tcp).await.unwrap();

        let req = concat!(
            "GET /ws HTTP/1.1\r\n",
            "Host: allowed.example.com\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).await.unwrap();

        let mut res_buf = [0u8; 1024];
        let mut n = 0;
        while !res_buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
            let r = tls.read(&mut res_buf[n..]).await.unwrap();
            assert!(r > 0, "unexpected EOF while reading 101 response");
            n += r;
        }
        let res_header = String::from_utf8_lossy(&res_buf[..n]);
        assert!(res_header.starts_with("HTTP/1.1 101 Switching Protocols"));

        tls.write_all(b"hello websocket\n").await.unwrap();
        let mut echo_buf = [0u8; 32];
        let n = tls.read(&mut echo_buf).await.unwrap();
        assert_eq!(&echo_buf[..n], b"hello websocket\n");

        gate_task.abort();
    }

    #[tokio::test]
    async fn test_websocket_tunnel_holds_permit_until_close() {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut server_params = rcgen::CertificateParams::default();
        server_params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("allowed.example.com").unwrap(),
        )];
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        let upstream_addr =
            start_websocket_upstream(server_cert.der().to_vec(), server_key.serialize_der()).await;

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

        let mut client_root_store = rustls::RootCertStore::empty();
        client_root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();
        let upstream_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store.clone())
                .with_no_client_auth(),
        );

        let gate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate_addr = gate_listener.local_addr().unwrap();
        drop(gate_listener);

        let limiter = ConnLimiter::new(10, 10);
        let gate_task = tokio::spawn(run_tls_proxy_with_config(
            gate_addr.to_string(),
            upstream_addr.ip().to_string(),
            upstream_addr.port(),
            allowlist,
            cert_resolver,
            limiter.clone(),
            upstream_tls_config,
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let test_client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store)
                .with_no_client_auth(),
        );
        let client_connector = tokio_rustls::TlsConnector::from(test_client_config);

        let tcp = TcpStream::connect(gate_addr).await.unwrap();
        let server_name =
            rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
        let mut tls = client_connector.connect(server_name, tcp).await.unwrap();

        let req = concat!(
            "GET /ws HTTP/1.1\r\n",
            "Host: allowed.example.com\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).await.unwrap();

        let mut res_buf = [0u8; 1024];
        let mut n = 0;
        while !res_buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
            let r = tls.read(&mut res_buf[n..]).await.unwrap();
            assert!(r > 0, "unexpected EOF while reading 101 response");
            n += r;
        }
        let res_header = String::from_utf8_lossy(&res_buf[..n]);
        assert!(res_header.starts_with("HTTP/1.1 101 Switching Protocols"));

        let peer_ip: IpAddr = "127.0.0.1".parse().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            *limiter.per_ip.lock().unwrap().get(&peer_ip).unwrap_or(&0),
            1,
            "permit must be kept alive while tunnel is open"
        );

        drop(tls);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            *limiter.per_ip.lock().unwrap().get(&peer_ip).unwrap_or(&0),
            0,
            "permit must return to 0 after tunnel is closed"
        );

        gate_task.abort();
    }

    #[tokio::test]
    async fn test_h2_request_with_upgrade_headers_holds_permit_while_open() {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut server_params = rcgen::CertificateParams::default();
        server_params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("allowed.example.com").unwrap(),
        )];
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        let upstream_addr =
            start_websocket_upstream(server_cert.der().to_vec(), server_key.serialize_der()).await;

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

        let mut client_root_store = rustls::RootCertStore::empty();
        client_root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();
        let upstream_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store.clone())
                .with_no_client_auth(),
        );

        let gate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate_addr = gate_listener.local_addr().unwrap();
        drop(gate_listener);

        let limiter = ConnLimiter::new(10, 10);
        let gate_task = tokio::spawn(run_tls_proxy_with_config(
            gate_addr.to_string(),
            upstream_addr.ip().to_string(),
            upstream_addr.port(),
            allowlist,
            cert_resolver,
            limiter.clone(),
            upstream_tls_config,
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut test_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(client_root_store)
            .with_no_client_auth();
        test_client_config.alpn_protocols = vec![b"h2".to_vec()];
        let client_connector = tokio_rustls::TlsConnector::from(Arc::new(test_client_config));

        let tcp = TcpStream::connect(gate_addr).await.unwrap();
        let server_name =
            rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
        let mut tls = client_connector.connect(server_name, tcp).await.unwrap();

        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let peer_ip: IpAddr = "127.0.0.1".parse().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            *limiter.per_ip.lock().unwrap().get(&peer_ip).unwrap_or(&0),
            1,
            "permit must be acquired on connection accept"
        );

        // Send HTTP/2 connection preface
        tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        // Send client empty SETTINGS frame
        tls.write_all(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])
            .await
            .unwrap();

        // Construct HEADERS frame on stream 1 carrying Upgrade and Connection headers
        let mut hpack = vec![
            0x82, // :method: GET
            0x84, // :path: /
            0x87, // :scheme: https
            0x00, 10, // :authority (literal without indexing, new name)
        ];
        hpack.extend_from_slice(b":authority");
        hpack.push(19);
        hpack.extend_from_slice(b"allowed.example.com");

        hpack.extend_from_slice(&[0x00, 7]);
        hpack.extend_from_slice(b"upgrade");
        hpack.push(9);
        hpack.extend_from_slice(b"websocket");

        hpack.extend_from_slice(&[0x00, 10]);
        hpack.extend_from_slice(b"connection");
        hpack.push(7);
        hpack.extend_from_slice(b"upgrade");

        let frame_len = hpack.len() as u32;
        let mut frame = vec![
            ((frame_len >> 16) & 0xFF) as u8,
            ((frame_len >> 8) & 0xFF) as u8,
            (frame_len & 0xFF) as u8,
            0x01, // HEADERS
            0x05, // END_STREAM | END_HEADERS
            0x00,
            0x00,
            0x00,
            0x01, // stream 1
        ];
        frame.extend_from_slice(&hpack);

        tls.write_all(&frame).await.unwrap();

        // Read server response / frame (e.g., SETTINGS frame or stream reset)
        let mut buf = [0u8; 256];
        let _ = timeout(Duration::from_millis(100), tls.read(&mut buf)).await;

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            *limiter.per_ip.lock().unwrap().get(&peer_ip).unwrap_or(&0),
            1,
            "permit must stay 1 while h2 connection is open even after request with Upgrade headers"
        );

        drop(tls);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            *limiter.per_ip.lock().unwrap().get(&peer_ip).unwrap_or(&0),
            0,
            "permit must return to 0 after h2 connection is closed"
        );

        gate_task.abort();
    }

    #[tokio::test]
    async fn test_websocket_tunnel_idle_timeout() {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut server_params = rcgen::CertificateParams::default();
        server_params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("allowed.example.com").unwrap(),
        )];
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        let upstream_addr =
            start_websocket_upstream(server_cert.der().to_vec(), server_key.serialize_der()).await;

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

        let mut client_root_store = rustls::RootCertStore::empty();
        client_root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();
        let upstream_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store.clone())
                .with_no_client_auth(),
        );

        let gate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate_addr = gate_listener.local_addr().unwrap();
        drop(gate_listener);

        let limiter = ConnLimiter::new(10, 10);
        let options = ProxyOptions {
            upstream_tls_config,
            tunnel_idle_timeout: Duration::from_millis(100),
            ..ProxyOptions::default()
        };

        let gate_task = tokio::spawn(run_tls_proxy_with_options(
            gate_addr.to_string(),
            upstream_addr.ip().to_string(),
            upstream_addr.port(),
            allowlist,
            cert_resolver,
            limiter.clone(),
            options,
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;

        let test_client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(client_root_store)
                .with_no_client_auth(),
        );
        let client_connector = tokio_rustls::TlsConnector::from(test_client_config);

        let tcp = TcpStream::connect(gate_addr).await.unwrap();
        let server_name =
            rustls::pki_types::ServerName::try_from("allowed.example.com".to_string()).unwrap();
        let mut tls = client_connector.connect(server_name, tcp).await.unwrap();

        let req = concat!(
            "GET /ws HTTP/1.1\r\n",
            "Host: allowed.example.com\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).await.unwrap();

        let mut res_buf = [0u8; 1024];
        let mut n = 0;
        while !res_buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
            let r = tls.read(&mut res_buf[n..]).await.unwrap();
            assert!(r > 0, "unexpected EOF while reading 101 response");
            n += r;
        }
        let res_header = String::from_utf8_lossy(&res_buf[..n]);
        assert!(res_header.starts_with("HTTP/1.1 101 Switching Protocols"));

        let peer_ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            *limiter.per_ip.lock().unwrap().get(&peer_ip).unwrap_or(&0),
            1
        );

        // Sit idle without sending any data. Read from connection expecting EOF on timeout.
        let mut buf = [0u8; 128];
        let n = tls.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "expected EOF when idle tunnel closes");

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            *limiter.per_ip.lock().unwrap().get(&peer_ip).unwrap_or(&0),
            0,
            "permit must be released after idle tunnel closes"
        );

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

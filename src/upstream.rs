use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tower_service::Service;

#[derive(Clone)]
pub struct UpstreamConnector {
    upstream_target: String,
    tls_connector: TlsConnector,
}

impl UpstreamConnector {
    pub fn new(upstream_target: String, tls_connector: TlsConnector) -> Self {
        Self {
            upstream_target,
            tls_connector,
        }
    }
}

pub struct UpstreamStream {
    inner: TokioIo<TlsStream<TcpStream>>,
}

impl hyper::rt::Read for UpstreamStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for UpstreamStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Connection for UpstreamStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl Service<Uri> for UpstreamConnector {
    type Response = UpstreamStream;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let upstream_target = self.upstream_target.clone();
        let connector = self.tls_connector.clone();

        Box::pin(async move {
            let host = dst.host().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing host in uri")
            })?;
            let server_name = ServerName::try_from(host.to_string())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

            let tcp = TcpStream::connect(&upstream_target).await?;
            let tls = connector.connect(server_name, tcp).await?;
            Ok(UpstreamStream {
                inner: TokioIo::new(tls),
            })
        })
    }
}

pub type ClientType<B> = hyper_util::client::legacy::Client<UpstreamConnector, B>;

pub fn create_upstream_client<B>(
    upstream_target: String,
    tls_config: Arc<rustls::ClientConfig>,
) -> ClientType<B>
where
    B: hyper::body::Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let connector = UpstreamConnector::new(upstream_target, TlsConnector::from(tls_config));
    hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(32)
        .build(connector)
}

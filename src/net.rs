//! Listening sockets.
//!
//! The unspecified IPv6 address (`[::]`, the default) is bound as a
//! dual-stack socket with `IPV6_V6ONLY` cleared explicitly, so it accepts IPv4
//! and IPv6 whatever `net.ipv6.bindv6only` says. If the kernel has no IPv6 at
//! all, it falls back to `0.0.0.0`. Any other address is bound as given.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};

/// Bind `addr` for listening (see the module docs for `[::]`).
pub fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    if addr.ip() != IpAddr::from(std::net::Ipv6Addr::UNSPECIFIED) {
        return bind_plain(addr);
    }
    match bind_dual_stack(addr) {
        Ok(listener) => Ok(listener),
        // No IPv6 in this kernel/netns: listen on IPv4 only rather than fail.
        Err(err) if ipv6_unavailable(&err) => {
            let v4 = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), addr.port());
            tracing::warn!(requested = %addr, fallback = %v4, error = %err, "IPv6 unavailable; listening on IPv4 only");
            bind_plain(v4)
        }
        Err(err) => Err(err),
    }
}

fn bind_dual_stack(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(false)?;
    // Same as tokio's TcpListener::bind: allow a quick restart while old
    // connections sit in TIME_WAIT.
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

fn bind_plain(addr: SocketAddr) -> io::Result<TcpListener> {
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener)
}

/// Socket creation fails with EAFNOSUPPORT when IPv6 is disabled
/// (`ipv6.disable=1`); binding `[::]` fails with EADDRNOTAVAIL on some setups.
fn ipv6_unavailable(err: &io::Error) -> bool {
    const EAFNOSUPPORT: i32 = 97; // Linux
    err.raw_os_error() == Some(EAFNOSUPPORT) || err.kind() == io::ErrorKind::AddrNotAvailable
}

/// An IPv4 client on a dual-stack socket shows up as `::ffff:a.b.c.d`; log
/// and report it as plain IPv4.
pub fn canonical_peer(peer: SocketAddr) -> SocketAddr {
    SocketAddr::new(peer.ip().to_canonical(), peer.port())
}

/// A connection holds its admission permit until the socket is dropped.
/// Deadlines apply to both reads and writes, including a peer that stops
/// consuming responses. Only peer input resets the idle deadline.
pub(crate) struct LimitedIo<I> {
    inner: I,
    _permit: OwnedSemaphorePermit,
    idle: Pin<Box<Sleep>>,
    lifetime: Pin<Box<Sleep>>,
    idle_timeout: Duration,
    preface_remaining: usize,
}

impl<I> LimitedIo<I> {
    pub(crate) fn new(
        inner: I,
        permit: OwnedSemaphorePermit,
        idle_timeout: Duration,
        max_age: Duration,
        preface: Option<(usize, Duration)>,
    ) -> Self {
        let (preface_remaining, first_timeout) = preface.unwrap_or((0, idle_timeout));
        Self {
            inner,
            _permit: permit,
            idle: Box::pin(tokio::time::sleep(first_timeout)),
            lifetime: Box::pin(tokio::time::sleep(max_age)),
            idle_timeout,
            preface_remaining,
        }
    }

    fn check_deadlines(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.lifetime.as_mut().poll(cx).is_ready() || self.idle.as_mut().poll(cx).is_ready() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection deadline exceeded",
            ));
        }
        Ok(())
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for LimitedIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check_deadlines(cx)?;
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let read = buf.filled().len() - before;
        if read > 0 {
            self.preface_remaining = self.preface_remaining.saturating_sub(read);
            // Partial HTTP/2 prefaces cannot extend their fixed deadline.
            if self.preface_remaining == 0 {
                let deadline = Instant::now() + self.idle_timeout;
                self.idle.as_mut().reset(deadline);
            }
        }
        result
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for LimitedIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check_deadlines(cx)?;
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_deadlines(cx)?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_deadlines(cx)?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.check_deadlines(cx)?;
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Separate admission budget for health/metrics, so the plain HTTP listener
/// cannot bypass the gRPC connection cap and consume all process descriptors.
pub(crate) struct HealthListener {
    inner: TcpListener,
    permits: Arc<Semaphore>,
}

impl HealthListener {
    pub(crate) fn new(inner: TcpListener) -> Self {
        Self {
            inner,
            permits: Arc::new(Semaphore::new(16)),
        }
    }
}

impl axum::serve::Listener for HealthListener {
    type Io = LimitedIo<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (tcp, peer) = axum::serve::Listener::accept(&mut self.inner).await;
            if let Ok(permit) = self.permits.clone().try_acquire_owned() {
                return (
                    LimitedIo::new(
                        tcp,
                        permit,
                        Duration::from_secs(10),
                        Duration::from_secs(60),
                        None,
                    ),
                    peer,
                );
            }
            drop(tcp);
            tokio::task::yield_now().await;
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn limited_pair(
        preface: bool,
    ) -> (
        LimitedIo<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
        Arc<Semaphore>,
    ) {
        let (server, peer) = tokio::io::duplex(128);
        let permits = Arc::new(Semaphore::new(1));
        let io = LimitedIo::new(
            server,
            permits.clone().try_acquire_owned().unwrap(),
            Duration::from_secs(30),
            Duration::from_secs(60),
            preface.then_some((24, Duration::from_secs(10))),
        );
        (io, peer, permits)
    }

    #[tokio::test(start_paused = true)]
    async fn partial_preface_has_a_fixed_deadline_and_releases_capacity() {
        let (mut io, mut peer, permits) = limited_pair(true);
        assert!(permits.try_acquire().is_err());
        for _ in 0..3 {
            peer.write_all(b"P").await.unwrap();
            assert_eq!(io.read_u8().await.unwrap(), b'P');
            tokio::time::advance(Duration::from_secs(3)).await;
        }
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            io.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        drop(io);
        assert!(permits.try_acquire().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_deadline_resets_on_peer_input_but_not_server_writes() {
        let (mut io, mut peer, _) = limited_pair(true);
        peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        let mut preface = [0; 24];
        io.read_exact(&mut preface).await.unwrap();
        tokio::time::advance(Duration::from_secs(20)).await;
        peer.write_all(b"x").await.unwrap();
        io.read_u8().await.unwrap();
        tokio::time::advance(Duration::from_secs(20)).await;
        io.write_all(b"response").await.unwrap();
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(
            io.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            io.write_all(b"more").await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test(start_paused = true)]
    async fn active_connections_still_expire() {
        let (mut io, mut peer, _) = limited_pair(false);
        for _ in 0..3 {
            peer.write_all(b"x").await.unwrap();
            io.read_u8().await.unwrap();
            tokio::time::advance(Duration::from_secs(20)).await;
        }
        assert_eq!(
            io.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn health_listener_rejects_overload_and_recovers() {
        use axum::serve::Listener;
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let mut listener = HealthListener::new(tcp);
        listener.permits = Arc::new(Semaphore::new(1));
        let _first = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (held, _) = listener.accept().await;
        let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                _ = listener.accept() => panic!("health connection cap bypassed"),
                result = second.read_u8() => assert!(result.is_err()),
            }
        })
        .await
        .unwrap();
        drop(held);
        let _third = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _accepted = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn dual_stack_accepts_ipv4_and_ipv6() {
        let listener = bind("[::]:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.is_ipv6(), "fell back to IPv4: {addr}");
        let port = addr.port();

        let v4 = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(canonical_peer(peer).ip(), v4.local_addr().unwrap().ip());
        assert!(canonical_peer(peer).is_ipv4(), "{peer}");

        // ::1 may be missing in minimal sandboxes; IPv4 above is the
        // regression this guards against.
        if let Ok(v6) = tokio::net::TcpStream::connect(("::1", port)).await {
            let (_, peer) = listener.accept().await.unwrap();
            assert_eq!(canonical_peer(peer).ip(), v6.local_addr().unwrap().ip());
        }
    }

    #[tokio::test]
    async fn specific_addresses_bind_as_given() {
        let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        assert_eq!(listener.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn canonical_peer_unmaps_ipv4() {
        let mapped: SocketAddr = "[::ffff:10.0.0.7]:5000".parse().unwrap();
        assert_eq!(canonical_peer(mapped), "10.0.0.7:5000".parse().unwrap());
        let v6: SocketAddr = "[fd00::7]:5000".parse().unwrap();
        assert_eq!(canonical_peer(v6), v6);
    }
}

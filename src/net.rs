//! Listening sockets.
//!
//! The unspecified IPv6 address (`[::]`, the default) is bound as a
//! dual-stack socket with `IPV6_V6ONLY` cleared explicitly, so it accepts IPv4
//! and IPv6 whatever `net.ipv6.bindv6only` says. If the kernel has no IPv6 at
//! all, it falls back to `0.0.0.0`. Any other address is bound as given.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

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

#[cfg(test)]
mod tests {
    use super::*;

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

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::os::fd::RawFd;

/// Owns a stable, kernel-ready socket address for asynchronous io_uring calls.
pub struct RawSocketAddress {
    storage: libc::sockaddr_storage,
    length: libc::socklen_t,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedTarget {
    pub address: SocketAddr,
    pub host: String,
}

impl ResolvedTarget {
    pub fn from_ip(address: SocketAddr) -> Self {
        Self {
            host: address.ip().to_string(),
            address,
        }
    }

    pub fn resolve(host: &str, port: u16) -> io::Result<Self> {
        Ok(Self {
            address: resolve_target(host, port)?,
            host: host.to_owned(),
        })
    }

    pub fn resolve_ipv6(&self) -> io::Result<Self> {
        if self.host.parse::<IpAddr>().is_ok() {
            return Ok(self.clone());
        }
        Ok(Self {
            address: resolve_target_ipv6(&self.host, self.address.port())?,
            host: self.host.clone(),
        })
    }
}

impl RawSocketAddress {
    pub fn new(address: SocketAddr) -> Self {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let length = match address {
            SocketAddr::V4(address) => {
                let raw = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: address.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(address.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };
                unsafe {
                    std::ptr::write(
                        (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>(),
                        raw,
                    );
                }
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
            }
            SocketAddr::V6(address) => {
                let raw = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: address.port().to_be(),
                    sin6_flowinfo: address.flowinfo(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: address.ip().octets(),
                    },
                    sin6_scope_id: address.scope_id(),
                };
                unsafe {
                    std::ptr::write(
                        (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>(),
                        raw,
                    );
                }
                mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
            }
        };
        Self { storage, length }
    }

    pub fn as_ptr(&self) -> *const libc::sockaddr {
        (&self.storage as *const libc::sockaddr_storage).cast()
    }

    pub fn len(&self) -> libc::socklen_t {
        self.length
    }
}

pub fn socket_domain(address: SocketAddr) -> libc::c_int {
    match address {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    }
}

pub fn socket_address(storage: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let address = unsafe {
                &*((storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>())
            };
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(address.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let address = unsafe {
                &*((storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>())
            };
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(address.sin6_addr.s6_addr),
                u16::from_be(address.sin6_port),
                address.sin6_flowinfo,
                address.sin6_scope_id,
            )))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported socket address family",
        )),
    }
}

pub fn peer_ip(descriptor: RawFd) -> io::Result<IpAddr> {
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut length = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let result = unsafe {
        libc::getpeername(
            descriptor,
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket_address(&storage)?.ip())
}

/// Preserve the former IPv4 preference for dual-stack names while accepting
/// IPv6-only names and literal IPv6 destinations.
pub fn resolve_target(host: &str, port: u16) -> io::Result<SocketAddr> {
    let mut ipv6 = None;
    for address in (host, port).to_socket_addrs()? {
        match address {
            SocketAddr::V4(_) => return Ok(address),
            SocketAddr::V6(_) if ipv6.is_none() => ipv6 = Some(address),
            SocketAddr::V6(_) => {}
        }
    }
    ipv6.ok_or_else(|| io::Error::other("target name has no address"))
}

pub fn resolve_target_ipv6(host: &str, port: u16) -> io::Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .find(SocketAddr::is_ipv6)
        .ok_or_else(|| io::Error::other("target name has no IPv6 address"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_ipv4_and_ipv6_socket_addresses() {
        for address in [
            "127.0.0.1:19090".parse().unwrap(),
            "[2001:db8::7]:19091".parse().unwrap(),
        ] {
            let raw = RawSocketAddress::new(address);
            let storage = unsafe { &*(raw.as_ptr().cast::<libc::sockaddr_storage>()) };
            assert_eq!(socket_address(storage).unwrap(), address);
        }
    }

    #[test]
    fn ipv6_strategy_keeps_literal_addresses() {
        for address in [
            "192.0.2.1:443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ] {
            let target = ResolvedTarget::from_ip(address);
            assert_eq!(target.resolve_ipv6().unwrap(), target);
        }
    }
}

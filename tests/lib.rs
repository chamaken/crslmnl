use std::os::unix::io::{RawFd, AsRawFd};
use std::mem::size_of;
use std::iter::repeat;
// use std::io::Cursor;

extern crate crslmnl as mnl;
use mnl::linux as linux;
extern crate libc;
use libc::{socket};

#[test]
fn netlink_netfilter() {
    assert!(mnl::linux::netlink::Family::NETFILTER.c_int() == 12)
}

#[test]
fn socket_open() {
    assert!(mnl::Socket::open(mnl::linux::netlink::Family::NETFILTER).is_ok());
}

#[cfg(feature = "mnl-gt-1_0_4")]
#[test]
fn socket_open2() {
    assert!(mnl::Socket::open2(mnl::linux::netlink::Family::NETFILTER, 0).is_ok());
}

#[cfg(feature = "mnl-gt-1_0_4")]
#[test]
fn socket_fdopen() {
    struct RawSocket {
        fd: RawFd,
    }
    impl AsRawFd for RawSocket {
        fn as_raw_fd(&self) -> RawFd {
            self.fd
        }
    }

    // socket(AF_NETLINK, SOCK_RAW | NETLINK_NETFILTER);
    let sock = RawSocket { fd: unsafe { socket(16, 3, 12) }};
    assert!(mnl::Socket::fdopen(&sock).is_ok());
}

macro_rules! default_socket {
    () => {
        mnl::Socket::open(mnl::linux::netlink::Family::NETFILTER).unwrap()
    }
}

#[test]
fn socket_bind() {
    let nls = default_socket!();
    assert!(nls.bind(0, mnl::SOCKET_AUTOPID).is_ok());
}

#[test]
fn socket_get_fd() {
    let nls = default_socket!();
    assert!(nls.as_raw_fd() >= 0);
}

#[test]
fn socket_get_portid() {
    let nls = default_socket!();
    nls.bind(0, mnl::SOCKET_AUTOPID).unwrap();
    assert!(nls.portid() > 0);
}

// XXX: no...
//   sendto, recvfrom
//   setsockopt, getsockopt

#[test]
fn nlmsg_size() {
    assert!(mnl::Nlmsg::size(123) == 16 + 123);
}

#[test]
fn nlmsg_put_header() {
    let mut buf = vec![123 as u8; mnl::SOCKET_BUFFER_SIZE()];
    let nlh = mnl::Nlmsg::new(&mut buf);
    assert!(nlh.nlmsg_len == 16);
}

#[test]
fn nlmsg_put_extra_header() {
    let mut buf = vec![123 as u8; mnl::SOCKET_BUFFER_SIZE()];
    let nlh = mnl::Nlmsg::new(&mut buf);
    {
        let exthdr: &mut linux::netfilter::nfnetlink::Nfgenmsg
            = nlh.put_extra_header(size_of::<linux::netfilter::nfnetlink::Nfgenmsg>());
        assert!(exthdr.nfgen_family == 0);
        assert!(exthdr.version == 0);
        assert!(exthdr.res_id == 0);
    }
    assert!(nlh.nlmsg_len as usize == 16 + size_of::<linux::netfilter::nfnetlink::Nfgenmsg>());
}

#[test]
fn nlmsg_ok() {
    let mut buf = vec![0; mnl::NLMSG_HDRLEN() as usize];
    let nlh = mnl::Nlmsg::new(&mut buf);
    assert!(!nlh.ok(15));
    assert!(nlh.ok(16));
    assert!(nlh.ok(17));
}

#[test]
fn nlmsg_next_header() {
    let hdrlen = mnl::NLMSG_HDRLEN() as usize;
    let mut buf: Vec<u8> = repeat(0u8).take(512).collect();
    {
    let nlh = mnl::Nlmsg::new(&mut buf);
    let (next_nlh, rest) = nlh.next(512);
    assert!(rest == 512 - hdrlen as isize);
    assert!(next_nlh.nlmsg_len == 0);
    next_nlh.nlmsg_len = 0x11111111;
    }
    assert_eq!(buf[hdrlen..(hdrlen + 4)], [0x11, 0x11, 0x11, 0x11]);
}

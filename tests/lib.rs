use std::os::unix::io::AsRawFd;
use std::mem::size_of;
use std::iter::repeat;
// use std::io::Cursor;
use std::iter::Iterator;

extern crate crslmnl as mnl;
use mnl::linux as linux;
extern crate libc;


fn buf_offset_as<T>(buf: &[u8], offset: isize) -> &T {
    assert!(buf.len() >= offset as usize + size_of::<T>());
    unsafe {
        (buf.as_ptr().offset(offset) as *const T).as_ref().unwrap()
    }
}

fn set_buf<T>(buf: &mut [u8], offset: isize, v: T) {
    assert!(buf.len() >= offset as usize + size_of::<T>());
    unsafe {
        *(buf.as_mut_ptr().offset(offset) as *mut T) = v;
    }
}

#[allow(dead_code)]
fn set_nlmsg_len(buf: &mut[u8], len: u32) {
    set_buf(buf, 0, len);
}

#[allow(dead_code)]
fn set_nlmsg_type(buf: &mut[u8], mtype: u16) {
    set_buf(buf, 4, mtype);
}

#[allow(dead_code)]
fn set_nlmsg_flags(buf: &mut[u8], flags: u16) {
    set_buf(buf, 6, flags);
}

#[allow(dead_code)]
fn set_nlmsg_seq(buf: &mut[u8], seq: u32) {
    set_buf(buf, 8, seq);
}

#[allow(dead_code)]
fn set_nlmsg_pid(buf: &mut[u8], pid: u32) {
    set_buf(buf, 12, pid);
}

#[test]
fn netlink_netfilter() {
    assert!(linux::netlink::Family::NETFILTER.c_int() == 12)
}

#[test]
fn socket_open() {
    assert!(mnl::Socket::open(linux::netlink::Family::NETFILTER).is_ok());
}

#[cfg(feature = "mnl-gt-1_0_4")]
#[test]
fn socket_open2() {
    assert!(mnl::Socket::open2(linux::netlink::Family::NETFILTER, 0).is_ok());
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
        mnl::Socket::open(linux::netlink::Family::NETFILTER).unwrap()
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
    let nlh = mnl::Nlmsg::new(&mut buf).unwrap();
    assert!(*nlh.nlmsg_len == 16);
}

#[test]
fn nlmsg_put_extra_header_raw() {
    let mut buf = vec![123 as u8; mnl::SOCKET_BUFFER_SIZE()];
    let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
    {
        let exthdr: &mut linux::netfilter::nfnetlink::Nfgenmsg
            = nlh.put_extra_header_raw(size_of::<linux::netfilter::nfnetlink::Nfgenmsg>());
        assert!(exthdr.nfgen_family == 0);
        assert!(exthdr.version == 0);
        assert!(exthdr.res_id == 0);
    }
    assert!(*nlh.nlmsg_len as usize == 16 + size_of::<linux::netfilter::nfnetlink::Nfgenmsg>());
}

#[test]
fn nlmsg_put_extra_header() {
    let mut buf = vec![123 as u8; mnl::SOCKET_BUFFER_SIZE()];
    let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
    {
        let exthdr: &mut linux::netfilter::nfnetlink::Nfgenmsg
            = nlh.put_extra_header(size_of::<linux::netfilter::nfnetlink::Nfgenmsg>()).unwrap();
        assert!(exthdr.nfgen_family == 0);
        assert!(exthdr.version == 0);
        assert!(exthdr.res_id == 0);
    }
    assert!(*nlh.nlmsg_len as usize == 16 + size_of::<linux::netfilter::nfnetlink::Nfgenmsg>());
}


#[test]
fn nlmsg_ok() {
    let mut buf = vec![0; mnl::NLMSG_HDRLEN() as usize];
    let nlh = mnl::Nlmsg::from_bytes(&mut buf).unwrap();
    *nlh.nlmsg_len = 16;
    assert!(nlh.ok());
    *nlh.nlmsg_len = 17;
    assert!(!nlh.ok());
}

#[test]
fn nlmsg_next_header() {
    let hdrlen = mnl::NLMSG_HDRLEN() as usize;
    let mut buf: Vec<u8> = repeat(0u8).take(512).collect();
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        let mut nnlh = nlh.next().unwrap();
        assert!(nnlh.buflen() == 512 - hdrlen);
        assert!(*nnlh.nlmsg_len == 0);
        *nnlh.nlmsg_len = 0x11111111;
        assert!(nnlh.next().is_none());
    }
    assert_eq!(buf[hdrlen..(hdrlen + 4)], [0x11, 0x11, 0x11, 0x11]);
}

#[test]
fn nlmsg_seq_ok() {
    let mut buf =vec![0u8; 512];
    {
        let nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.seq_ok(0));
    }
    set_nlmsg_seq(&mut buf, 1234567890);
    {
        let nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.seq_ok(1234567890));
    }
}

#[test]
fn nlmsg_porid_ok() {
    let mut buf =vec![0u8; 512];
    {
        let nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.portid_ok(0));
    }
    set_nlmsg_seq(&mut buf, 1234567890);
    {
        let nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.portid_ok(1234567890));
    }
}

#[test]
fn nlmsg_payload() {
    let mut buf =vec![0u8; 512];
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        let v: &mut u64 = nlh.payload_mut();
        *v = std::u64::MAX;
        assert!(*nlh.payload::<u64>() == std::u64::MAX);
        assert!(*nlh.payload_mut::<u64>() == std::u64::MAX);
    }
    assert!(*buf_offset_as::<u64>(&buf, 16) == std::u64::MAX);
}

#[test]
fn nlmsg_payload_offset() {
    let mut buf =vec![0u8; 512];
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        let v: &mut u64 = nlh.payload_offset_mut(128);
        *v = std::u64::MAX;
        assert!(*nlh.payload_offset::<u64>(128) == std::u64::MAX);
        assert!(*nlh.payload_offset_mut::<u64>(128) == std::u64::MAX);
    }
    assert!(*buf_offset_as::<u64>(&buf, 16 + 128) == std::u64::MAX);
}

#[test]
fn nlmsg_payload_tail() {
    // let nlhp: &mut mnl::Nlmsg = Default::default();
    let mut buf =vec![0u8; 512];
    set_nlmsg_len(&mut buf, 64);
    {
        let mut nlh = mnl::Nlmsg::from_bytes(&mut buf).unwrap();
        let v: &mut u64 = nlh.payload_tail_mut();
        *v = std::u64::MAX;
        assert!(*nlh.payload_tail::<u64>() == std::u64::MAX);
        assert!(*nlh.payload_tail_mut::<u64>() == std::u64::MAX);
    }
    assert!(*buf_offset_as::<u64>(&buf, 64) == std::u64::MAX);
}

#[test]
fn nlmsg_put_raw() {
    let mut buf = vec![0u8; 512];
    let attr_len = linux::netlink::NLA_HDRLEN() + (size_of::<u64>() as u16);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        nlh.put_raw(123, &std::u64::MAX);
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len as u32));

        let attr = nlh.payload::<linux::netlink::Nlattr>();
        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 123);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 123);
    assert!(*buf_offset_as::<u64>(&buf, 20) == std::u64::MAX);
}

#[test]
fn nlmsg_put_u8_raw() {
    let mut buf = vec![0u8; 512];
    let attr_len = linux::netlink::NLA_HDRLEN() + (size_of::<u8>() as u16);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        nlh.put_u8_raw(12, 34);
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len as u32));

        let attr = nlh.payload::<linux::netlink::Nlattr>();
        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 12);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 12);
    assert!(*buf_offset_as::<u8>(&buf, 20) == 34);

    {
        let mut nlh = mnl::Nlmsg::from_bytes(&mut buf).unwrap();
        let attr = nlh.payload_tail::<linux::netlink::Nlattr>();
        nlh.put_u8_raw(56, 78);
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN((attr_len) as u32) * 2);

        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 56);
    }
    assert!(*buf_offset_as::<u16>(&buf, 24) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 26) == 56);
    assert!(*buf_offset_as::<u8>(&buf, 28) == 78);
}

#[test]
fn nlmsg_put_u16_raw() {
    let mut buf = vec![0u8; 512];
    let attr_len = linux::netlink::NLA_HDRLEN() + (size_of::<u16>() as u16);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        nlh.put_u16_raw(1234, 5678);
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len as u32));

        let attr = nlh.payload::<linux::netlink::Nlattr>();
        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 1234);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 1234);
    assert!(*buf_offset_as::<u16>(&buf, 20) == 5678);

    {
        let mut nlh = mnl::Nlmsg::from_bytes(&mut buf).unwrap();
        let attr = nlh.payload_tail::<linux::netlink::Nlattr>();
        nlh.put_u16_raw(9012, 3456);
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN((attr_len) as u32) * 2);

        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 9012);
    }
    assert!(*buf_offset_as::<u16>(&buf, 24) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 26) == 9012);
    assert!(*buf_offset_as::<u16>(&buf, 28) == 3456);
}

#[test]
fn nlmsg_put_u32_raw() {
    let mut buf = vec![0u8; 512];
    let attr_len = linux::netlink::NLA_HDRLEN() + (size_of::<u32>() as u16);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        nlh.put_u32_raw(1234, 56789012);
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len as u32));

        let attr = nlh.payload::<linux::netlink::Nlattr>();
        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 1234);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 1234);
    assert!(*buf_offset_as::<u32>(&buf, 20) == 56789012);

    {
        let mut nlh = mnl::Nlmsg::from_bytes(&mut buf).unwrap();
        let attr = nlh.payload_tail::<linux::netlink::Nlattr>();
        nlh.put_u32_raw(3456, 78901234);
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN((attr_len) as u32) * 2);

        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 3456);
    }
    assert!(*buf_offset_as::<u16>(&buf, 24) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 26) == 3456);
    assert!(*buf_offset_as::<u32>(&buf, 28) == 78901234);
}

#[test]
fn nlmsg_put_u64_raw() {
    let mut buf = vec![0u8; 512];
    let attr_len = linux::netlink::NLA_HDRLEN() + (size_of::<u64>() as u16);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        nlh.put_u64_raw(1234, 0x567890abcdef0123);
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len as u32));

        let attr = nlh.payload::<linux::netlink::Nlattr>();
        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 1234);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 1234);
    assert!(*buf_offset_as::<u64>(&buf, 20) == 0x567890abcdef0123);

    {
        let mut nlh = mnl::Nlmsg::from_bytes(&mut buf).unwrap();
        let attr = nlh.payload_tail::<linux::netlink::Nlattr>();
        nlh.put_u64_raw(4567, 0x890abcdef0123456);
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN((attr_len) as u32) * 2);

        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 4567);
    }
    assert!(*buf_offset_as::<u16>(&buf, 28) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 30) == 4567);
    assert!(*buf_offset_as::<u64>(&buf, 32) == 0x890abcdef0123456);
}

#[test]
fn nlmsg_put_str_raw() {
    let mut buf = vec![0u8; 512];
    let s1 = "Hello, world!";
    let b1 = s1.as_bytes(); // .len() == 13
    let attr_len1 = linux::netlink::NLA_HDRLEN() + (b1.len() as u16);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        nlh.put_str_raw(1234, s1);
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len1 as u32));

        let attr = nlh.payload::<linux::netlink::Nlattr>();
        assert!(attr.nla_len == attr_len1);
        assert!(attr.nla_type == 1234);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == attr_len1);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 1234);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 13]>(&buf, 20)).unwrap() == s1);

    let s2 = "My name is";
    let b2 = s2.as_bytes(); // .len() == 10
    let attr_len2 = linux::netlink::NLA_HDRLEN() + (b2.len() as u16);
    let bi: isize;
    {
        let mut nlh = mnl::Nlmsg::from_bytes(&mut buf).unwrap();
        let attr = nlh.payload_tail::<linux::netlink::Nlattr>();
        bi = *nlh.nlmsg_len as isize;
        nlh.put_str_raw(5678, s2);
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN()
                + mnl::ALIGN(attr_len1 as u32) + mnl::ALIGN(attr_len2 as u32));

        assert!(attr.nla_len == attr_len2);
        assert!(attr.nla_type == 5678);
    }
    assert!(*buf_offset_as::<u16>(&buf, bi) == attr_len2);
    assert!(*buf_offset_as::<u16>(&buf, bi + 2) == 5678);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 10]>(&buf, bi + 4)).unwrap() == s2);
}

#[test]
fn nlmsg_put_strz_raw() {
    let mut buf = vec![0u8; 512];
    let s1 = "Hello, world!";
    let b1 = s1.as_bytes(); // .len() == 13
    let attr_len1 = linux::netlink::NLA_HDRLEN() + (b1.len() as u16) + 1;
    let mut nlmsg_len = mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len1 as u32);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        nlh.put_strz_raw(1234, s1);
        assert!(*nlh.nlmsg_len == nlmsg_len);

        let attr = nlh.payload::<linux::netlink::Nlattr>();
        assert!(attr.nla_len == attr_len1);
        assert!(attr.nla_type == 1234);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == attr_len1);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 1234);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 13]>(&buf, 20)).unwrap() == s1);
    assert!(*buf_offset_as::<u8>(&buf, nlmsg_len as isize) == 0);

    let s2 = "My name is";
    let b2 = s2.as_bytes(); // .len() == 10
    let attr_len2 = linux::netlink::NLA_HDRLEN() + (b2.len() as u16) + 1;
    nlmsg_len = mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len1 as u32) + mnl::ALIGN(attr_len2 as u32);
    let attr_tail = (mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len1 as u32) + attr_len2 as u32 - 1) as isize;
    let bi: isize;
    {
        set_buf(&mut buf, attr_tail, 0xffu8);
        let mut nlh = mnl::Nlmsg::from_bytes(&mut buf).unwrap();
        let attr = nlh.payload_tail::<linux::netlink::Nlattr>();
        bi = *nlh.nlmsg_len as isize;
        nlh.put_strz_raw(5678, s2);
        assert!(*nlh.nlmsg_len == nlmsg_len);

        assert!(attr.nla_len == attr_len2);
        assert!(attr.nla_type == 5678);
    }
    assert!(*buf_offset_as::<u16>(&buf, bi) == attr_len2);
    assert!(*buf_offset_as::<u16>(&buf, bi + 2) == 5678);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 10]>(&buf, bi + 4)).unwrap() == s2);
    assert!(*buf_offset_as::<u8>(&buf, attr_tail) == 0);
}

#[test]
fn nlmsg_put_check() {
    let mut buf = vec![0u8; 512];
    let attr_len = linux::netlink::NLA_HDRLEN() + (size_of::<u64>() as u16);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put(123, &std::u64::MAX).is_ok());
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len as u32));

        let attr = nlh.payload::<linux::netlink::Nlattr>();
        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 123);
        // nlmsg: 16, attr: 4, data: 8 == 28
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 123);
    assert!(*buf_offset_as::<u64>(&buf, 20) == std::u64::MAX);

    {
        let mut buf = vec![0u8; 39];
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put(123, &std::u64::MAX).is_ok());
        assert!(nlh.put(234, &std::u64::MAX).is_err());
    }
    {
        let mut buf = vec![0u8; 40];
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put(123, &std::u64::MAX).is_ok());
        assert!(nlh.put(234, &std::u64::MAX).is_ok());
    }
}

#[test]
fn nlmsg_put_u8_check() {
    let mut buf = vec![0u8; 512];
    let attr_len = linux::netlink::NLA_HDRLEN() + (size_of::<u8>() as u16);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_u8(12, 34).is_ok());
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len as u32));

        let attr = nlh.payload::<linux::netlink::Nlattr>();
        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 12);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 12);
    assert!(*buf_offset_as::<u8>(&buf, 20) == 34);

    {
        let mut buf = vec![0u8; 31];
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_u8(12, 34).is_ok());
        assert!(nlh.put_u8(56, 78).is_err());
    }

    buf = vec![0u8; 32];
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_u8(12, 34).is_ok());
        let attr = nlh.payload_tail::<linux::netlink::Nlattr>();
        assert!(nlh.put_u8(56, 78).is_ok());

        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 56);
    }
    assert!(*buf_offset_as::<u16>(&buf, 24) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 26) == 56);
    assert!(*buf_offset_as::<u8>(&buf, 28) == 78);
}

#[test]
fn nlmsg_put_u16_check() {
    let mut buf = vec![0u8; 512];
    let attr_len = linux::netlink::NLA_HDRLEN() + (size_of::<u16>() as u16);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_u16(1234, 5678).is_ok());
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len as u32));

        let attr = nlh.payload::<linux::netlink::Nlattr>();
        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 1234);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 1234);
    assert!(*buf_offset_as::<u16>(&buf, 20) == 5678);

    {
        let mut buf = vec![0u8; 31];
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_u16(1234, 5678).is_ok());
        assert!(nlh.put_u16(9012, 3456).is_err());
    }

    let mut buf = vec![0u8; 32];
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_u16(1234, 5678).is_ok());
        let attr = nlh.payload_tail::<linux::netlink::Nlattr>();
        assert!(nlh.put_u16(9012, 3456).is_ok());

        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 9012);
    }
    assert!(*buf_offset_as::<u16>(&buf, 24) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 26) == 9012);
    assert!(*buf_offset_as::<u16>(&buf, 28) == 3456);
}

#[test]
fn nlmsg_put_u32_check() {
    let mut buf = vec![0u8; 512];
    let attr_len = linux::netlink::NLA_HDRLEN() + (size_of::<u32>() as u16);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_u32(1234, 56789012).is_ok());
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len as u32));

        let attr = nlh.payload::<linux::netlink::Nlattr>();
        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 1234);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 1234);
    assert!(*buf_offset_as::<u32>(&buf, 20) == 56789012);

    {
        let mut buf = vec![0u8; 31];
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_u32(1234, 56789012).is_ok());
        assert!(nlh.put_u32(3456, 78901234).is_err());
    }

    buf = vec![0u8; 32];
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_u32(1234, 56789012).is_ok());
        let attr = nlh.payload_tail::<linux::netlink::Nlattr>();
        assert!(nlh.put_u32(3456, 78901234).is_ok());

        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 3456);
    }
    assert!(*buf_offset_as::<u16>(&buf, 24) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 26) == 3456);
    assert!(*buf_offset_as::<u32>(&buf, 28) == 78901234);
}

#[test]
fn nlmsg_put_u64_check() {
    let mut buf = vec![0u8; 512];
    let attr_len = linux::netlink::NLA_HDRLEN() + (size_of::<u64>() as u16);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_u64(1234, 0x567890abcdef0123).is_ok());
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len as u32));

        let attr = nlh.payload::<linux::netlink::Nlattr>();
        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 1234);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 1234);
    assert!(*buf_offset_as::<u64>(&buf, 20) == 0x567890abcdef0123);

    {
        let mut buf = vec![0u8; 39];
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_u64(1234, 0x567890abcdef0123).is_ok());
        assert!(nlh.put_u64(4567, 0x890abcdef0123456).is_err());
    }

    buf = vec![0u8; 40];
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_u64(1234, 0x567890abcdef0123).is_ok());
        let attr = nlh.payload_tail::<linux::netlink::Nlattr>();
        assert!(nlh.put_u64(4567, 0x890abcdef0123456).is_ok());

        assert!(attr.nla_len == attr_len);
        assert!(attr.nla_type == 4567);
    }
    assert!(*buf_offset_as::<u16>(&buf, 28) == attr_len);
    assert!(*buf_offset_as::<u16>(&buf, 30) == 4567);
    assert!(*buf_offset_as::<u64>(&buf, 32) == 0x890abcdef0123456);
}

#[test]
fn nlmsg_put_str_check() {
    let mut buf = vec![0u8; 512];
    let s1 = "Hello, world!";
    let b1 = s1.as_bytes(); // .len() == 13
    let attr_len1 = linux::netlink::NLA_HDRLEN() + (b1.len() as u16);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_str(1234, s1).is_ok());
        assert!(*nlh.nlmsg_len == mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len1 as u32));

        let attr = nlh.payload::<linux::netlink::Nlattr>();
        assert!(attr.nla_len == attr_len1);
        assert!(attr.nla_type == 1234);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == attr_len1);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 1234);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 13]>(&buf, 20)).unwrap() == s1);

    let s2 = "My name is";

    {
        let mut buf = vec![0u8; 51];
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_str(1234, s1).is_ok());
        assert!(nlh.put_str(5678, s2).is_err());
    }

    buf = vec![0u8; 52];
    let bi: isize;
    let b2 = s2.as_bytes(); // .len() == 10
    let attr_len2 = linux::netlink::NLA_HDRLEN() + (b2.len() as u16);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_str(1234, s1).is_ok());
        let attr = nlh.payload_tail::<linux::netlink::Nlattr>();
        bi = *nlh.nlmsg_len as isize;
        assert!(nlh.put_str(5678, s2).is_ok());

        assert!(attr.nla_len == attr_len2);
        assert!(attr.nla_type == 5678);
    }
    assert!(*buf_offset_as::<u16>(&buf, bi) == attr_len2);
    assert!(*buf_offset_as::<u16>(&buf, bi + 2) == 5678);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 10]>(&buf, bi + 4)).unwrap() == s2);
}

#[test]
fn nlmsg_put_strz_check() {
    let mut buf = vec![0u8; 512];
    let s1 = "Hello, world!";
    let b1 = s1.as_bytes(); // .len() == 13
    let attr_len1 = linux::netlink::NLA_HDRLEN() + (b1.len() as u16) + 1;
    let mut nlmsg_len = mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len1 as u32);
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_strz(1234, s1).is_ok());
        assert!(*nlh.nlmsg_len == nlmsg_len);

        let attr = nlh.payload::<linux::netlink::Nlattr>();
        assert!(attr.nla_len == attr_len1);
        assert!(attr.nla_type == 1234);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == attr_len1);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 1234);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 13]>(&buf, 20)).unwrap() == s1);
    assert!(*buf_offset_as::<u8>(&buf, nlmsg_len as isize) == 0);

    let s2 = "My name is";
    {
        let mut buf = vec![0u8; 51];
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();

        assert!(nlh.put_strz(1234, s1).is_ok());
        assert!(nlh.put_strz(5678, s2).is_err());
    }

    let b2 = s2.as_bytes(); // .len() == 10
    let attr_len2 = linux::netlink::NLA_HDRLEN() + (b2.len() as u16) + 1;
    nlmsg_len = mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len1 as u32) + mnl::ALIGN(attr_len2 as u32);
    let attr_tail = (mnl::NLMSG_HDRLEN() + mnl::ALIGN(attr_len1 as u32) + attr_len2 as u32 - 1) as isize;
    let bi: isize;
    buf = vec![0u8; 52];
    {
        set_buf(&mut buf, attr_tail, 0xffu8);
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.put_strz(1234, s1).is_ok());
        let attr = nlh.payload_tail::<linux::netlink::Nlattr>();
        bi = *nlh.nlmsg_len as isize;
        assert!(nlh.put_strz(5678, s2).is_ok());
        assert!(*nlh.nlmsg_len == nlmsg_len);

        assert!(attr.nla_len == attr_len2);
        assert!(attr.nla_type == 5678);
    }
    assert!(*buf_offset_as::<u16>(&buf, bi) == attr_len2);
    assert!(*buf_offset_as::<u16>(&buf, bi + 2) == 5678);
    assert!(std::str::from_utf8(buf_offset_as::<[u8; 10]>(&buf, bi + 4)).unwrap() == s2);
    assert!(*buf_offset_as::<u8>(&buf, attr_tail) == 0);
}

#[test]
fn nlmsg_nest_start() {
    let mut buf = vec![0u8; 512];
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        let attr = nlh.nest_start_raw(0x123);

        assert!(*nlh.nlmsg_len == linux::netlink::NLMSG_LENGTH(linux::netlink::NLA_HDRLEN() as u32));
        assert!(attr.nla_len == 0); // will update after _end
        assert!(attr.nla_type & linux::netlink::NLA_F_NESTED != 0);
        assert!(attr.nla_type & linux::netlink::NLA_TYPE_MASK == 0x123);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == 0);
}

#[test]
fn nlmsg_nest_start_check() {
    let mut buf: std::vec::Vec<u8>;
    {
        buf = vec![0u8; 19];
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        assert!(nlh.nest_start(0x123).is_err());
    }
    {
        buf = vec![0u8; 20];
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        if let Ok(attr) = nlh.nest_start(0x123) {
            assert!(*nlh.nlmsg_len == linux::netlink::NLMSG_LENGTH(linux::netlink::NLA_HDRLEN() as u32));
            assert!(attr.nla_len == 0); // will update after _end
            assert!(attr.nla_type & linux::netlink::NLA_F_NESTED != 0);
            assert!(attr.nla_type & linux::netlink::NLA_TYPE_MASK == 0x123);
        } else {
            assert!(false);
        }
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == 0);
}

#[test]
fn nlmsg_nest_end() {
    let mut buf = vec![0u8; 512];
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        let attr = nlh.nest_start(0x123).unwrap();
        nlh.put_u8(0x4567, 0x89).unwrap();
        nlh.put_u64(0xabcd, 0xef01234567890abc).unwrap();
        nlh.nest_end(attr);

        assert!(*nlh.nlmsg_len == 16 + 4 + 8 + 12);
        assert!(attr.nla_len == 4 + 8 + 12);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == 4 + 8 + 12);
    assert!(*buf_offset_as::<u16>(&buf, 18) == linux::netlink::NLA_F_NESTED | 0x123);
    assert!(*buf_offset_as::<u16>(&buf, 20) == 5);
    assert!(*buf_offset_as::<u16>(&buf, 22) == 0x4567);
    assert!(*buf_offset_as::<u8>(&buf, 24) == 0x89);
    assert!(*buf_offset_as::<u16>(&buf, 28) == 12);
    assert!(*buf_offset_as::<u16>(&buf, 30) == 0xabcd);
    assert!(*buf_offset_as::<u64>(&buf, 32) == 0xef01234567890abc);
}

#[test]
fn nlmsg_nest_cancel() {
    let mut buf = vec![0u8; 512];
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();

        let mut attr = nlh.nest_start(0x123).unwrap();
        nlh.nest_cancel(attr);
        assert!(*nlh.nlmsg_len == 16);

        nlh.put_u8(0x2345, 0x67).unwrap();
        attr = nlh.nest_start(0x234).unwrap();
        nlh.nest_cancel(attr);
        assert!(*nlh.nlmsg_len == 24);
    }
    assert!(*buf_offset_as::<u16>(&buf, 16) == 5);
    assert!(*buf_offset_as::<u16>(&buf, 18) == 0x2345);
    assert!(*buf_offset_as::<u8>(&buf, 20) == 0x67);
}

fn nlmsg_parse_cb1(attr: &mnl::Attr, data: &mut u8) -> mnl::CbRet {
    if attr.nla_type as u8 != *data {
        return mnl::CbRet::ERROR;
    }
    if attr.u8() != 0x10 + *data {
        return mnl::CbRet::ERROR;
    }
    *data += 1;
    mnl::CbRet::OK
}

#[test]
fn nlmsg_parse() {
    let mut buf = vec![0u8; 512];
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        nlh.put_u8(1, 0x11).unwrap();
        nlh.put_u8(2, 0x12).unwrap();
        nlh.put_u8(3, 0x13).unwrap();
        nlh.put_u8(4, 0x14).unwrap();
        assert!(nlh.parse(0, nlmsg_parse_cb1, &mut 1).unwrap() == mnl::CbRet::OK);
    }
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        nlh.put_u8(0, 0x0).unwrap();
        assert!(nlh.parse(0, nlmsg_parse_cb1, &mut 1).is_err());
    }
}

#[test]
fn nlmsg_parse_2() {
    let mut buf = vec![0u8; 512];
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        nlh.put_u8(1, 0x11).unwrap();
        nlh.put_u8(2, 0x12).unwrap();
        nlh.put_u8(3, 0x13).unwrap();
        nlh.put_u8(4, 0x14).unwrap();
        let mut data = 1;
        assert!(nlh.cl_parse(0, Box::new(|attr| {
            if attr.nla_type as u8 != data {
                return mnl::CbRet::ERROR;
            }
            if attr.u8() != 0x10 + data {
                return mnl::CbRet::ERROR;
            }
            data += 1;
            mnl::CbRet::OK
        })).unwrap() == mnl::CbRet::OK);
    }
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        nlh.put_u8(0, 0x0).unwrap();
        let mut data = 1;
        assert!(nlh.cl_parse(0, Box::new(|attr| {
            if attr.nla_type as u8 != data {
                return mnl::CbRet::ERROR;
            }
            if attr.u8() != 0x10 + data {
                return mnl::CbRet::ERROR;
            }
            data += 1;
            mnl::CbRet::OK
        })).is_err());
    }
}


#[test]
fn nlmsg_attrs() {
    let mut buf = vec![0u8; 512];
    let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
    nlh.put_u8(0, 0x10).unwrap();
    nlh.put_u8(1, 0x11).unwrap();
    nlh.put_u8(2, 0x12).unwrap();
    nlh.put_u8(3, 0x13).unwrap();

    for (i, attr) in nlh.attrs(0).enumerate() {
        assert!(attr.nla_type == i as u16);
        assert!(attr.u8() == 0x10 + i as u8);
    }
}

#[test]
fn nlmsg_batch_start() {
    let mut buf = vec![0u8; 512];
    let _ = mnl::NlmsgBatch::start(&mut buf, 512 / 2).unwrap();
}

#[test]
fn nlmsg_batch_next() {
    let mut buf = vec![0u8; 512];
    let b = mnl::NlmsgBatch::start(&mut buf, 512 / 2).unwrap();
    assert!(b.proceed_next() == true);

    {
        let mut nlh = b.current_nlmsg().unwrap();
        *nlh.nlmsg_len = 256;
    }
    assert!(b.proceed_next() == true);

    // The original will success
    // since assumes buf size limit is the half of the buf.
    // But this limits equals to the size of buffer
    // {
    //     let mut nlh = b.current_nlmsg().unwrap();
    //     *nlh.nlmsg_len = 1;
    // }
    // assert!(b.proceed_next() == false);
}

#[test]
fn nlmsg_batch_size() {
    let mut buf = vec![0u8; 512];
    let b = mnl::NlmsgBatch::start(&mut buf, 512 / 2).unwrap();
    assert!(b.proceed_next() == true);
    assert!(b.size() == 0);

    {
        let mut nlh = b.current_nlmsg().unwrap();
        *nlh.nlmsg_len = 128;
    }
    assert!(b.proceed_next() == true);
    assert!(b.size() == 128);

    {
        let mut nlh = b.current_nlmsg().unwrap();
        *nlh.nlmsg_len = 128;
    }
    assert!(b.proceed_next() == true);
    assert!(b.size() == 256);

    // {
    //     let mut nlh = b.current_nlmsg().unwrap();
    //     *nlh.nlmsg_len = 1;
    // }
    // assert!(b.proceed_next() == false);
    // assert!(b.size() == 256);
}

#[test]
fn nlmsg_batch_reset() {
    let mut buf = vec![0u8; 512];
    let b = mnl::NlmsgBatch::start(&mut buf, 512 / 2).unwrap();
    {
        let mut nlh = b.current_nlmsg().unwrap();
        *nlh.nlmsg_len = 256;
    }
    assert!(b.proceed_next() == true);
    assert!(b.size() == 256);
    b.reset();
    assert!(b.size() == 0);

    {
        let mut nlh = b.current_nlmsg().unwrap();
        *nlh.nlmsg_len = 256;
    }
    assert!(b.proceed_next() == true);

    // {
    //     let mut nlh = b.current_nlmsg().unwrap();
    //     *nlh.nlmsg_len = 256;
    // }
    // assert!(b.proceed_next() == false);
    // b.reset();
    // assert!(b.size() == 256);
}

#[test]
fn nlmsg_batch_head() {
    let mut buf = vec![0u8; 512];
    let bufptr = buf.as_ptr();
    let b = mnl::NlmsgBatch::start(&mut *buf, 512 / 2).unwrap();
    assert!(b.head::<u8>() as *const u8 == bufptr);

    {
        let mut nlh = b.current_nlmsg().unwrap();
        *nlh.nlmsg_len = 256;
    }
    assert!(b.proceed_next() == true);
    assert!(b.head::<u8>() as *const u8 == bufptr);
}

#[test]
fn nlmsg_batch_current() {
    let mut buf = vec![0u8; 512];
    let bufptr = buf.as_ptr();
    let b = mnl::NlmsgBatch::start(&mut *buf, 512 / 2).unwrap();
    assert!(b.current::<u8>() as *const u8 == bufptr);

    {
        let mut nlh = b.current_nlmsg().unwrap();
        *nlh.nlmsg_len = 256;
    }
    assert!(b.proceed_next() == true);
    assert!(b.current::<u8>() as *const u8
            == unsafe { bufptr.offset(256) });
}

#[test]
fn nlmsg_batch_is_empty() {
    let mut buf = vec![0u8; 512];
    let b = mnl::NlmsgBatch::start(&mut *buf, 512 / 2).unwrap();
    assert!(b.is_empty() == true);

    {
        let mut nlh = b.current_nlmsg().unwrap();
        *nlh.nlmsg_len = 256;
    }
    assert!(b.proceed_next() == true);
    assert!(b.is_empty() == false);
    b.reset();
    assert!(b.is_empty() == true);
}

// fn nlmsg_cb_ok<'a>() -> Box<FnMut(mnl::Nlmsg<'a>) -> mnl::CbRet> {
fn nlmsg_cb_ok() -> Box<FnMut(mnl::Nlmsg) -> mnl::CbRet> {
    Box::new(|_| mnl::CbRet::OK)
}

// fn nlmsg_cb_stop<'a>() -> Box<FnMut(mnl::Nlmsg<'a>) -> mnl::CbRet> {
fn nlmsg_cb_stop() -> Box<FnMut(mnl::Nlmsg) -> mnl::CbRet> {
    Box::new(|_| mnl::CbRet::STOP)
}

// fn nlmsg_cb_error<'a>() -> Box<FnMut(mnl::Nlmsg<'a>) -> mnl::CbRet> {
fn nlmsg_cb_error() -> Box<FnMut(mnl::Nlmsg) -> mnl::CbRet> {
    Box::new(|_| mnl::CbRet::ERROR)
}

#[test]
fn nlmsg_cb_run4() {
    let mut buf = vec![0u8; 512];
    let b = mnl::NlmsgBatch::start(&mut *buf, 512 / 2).unwrap();
    {
        let mut nlh = b.current_nlmsg().unwrap();
        nlh.put_header().unwrap();
        *nlh.nlmsg_type = linux::netlink::NLMSG_NOOP;	// 0x1
    }

    let _ = b.proceed_next();
    {
        let mut nlh = b.current_nlmsg().unwrap();
        nlh.put_header().unwrap();
        *nlh.nlmsg_type = linux::netlink::NLMSG_ERROR;	// 0x2
    }

    let _ = b.proceed_next();
    {
        let mut nlh = b.current_nlmsg().unwrap();
        nlh.put_header().unwrap();
        *nlh.nlmsg_type = linux::netlink::NLMSG_DONE;	// 0x3
    }

    let _ = b.proceed_next();
    {
        let mut nlh = b.current_nlmsg().unwrap();
        nlh.put_header().unwrap();
        *nlh.nlmsg_type = linux::netlink::NLMSG_OVERRUN;// 0x4
    }

    let mut ctlcbs
        = [None,
           Some(nlmsg_cb_ok()),		// NLMSG_NOOP
           Some(nlmsg_cb_ok()), 	// NLMSG_ERROR
           Some(nlmsg_cb_ok()), 	// NLMSG_DONE
           Some(nlmsg_cb_ok()), ];	// NLMSG_OVERRUN
    // bufsize = 16 * 4
    assert!(mnl::cl_run2(b.head::<[u8; 48]>(), 0, 0, None, &mut ctlcbs[..]).unwrap() == mnl::CbRet::OK);

    ctlcbs
        = [None,
           Some(nlmsg_cb_ok()),		// NLMSG_NOOP
           Some(nlmsg_cb_error()), 	// NLMSG_ERROR
           Some(nlmsg_cb_ok()), 	// NLMSG_DONE
           Some(nlmsg_cb_ok()), ];	// NLMSG_OVERRUN
    assert!(mnl::cl_run2(b.head::<[u8; 48]>(), 0, 0, None, &mut ctlcbs[..]).is_err());

    ctlcbs
        = [None,
           Some(nlmsg_cb_ok()),		// NLMSG_NOOP
           Some(nlmsg_cb_ok()), 	// NLMSG_ERROR
           Some(nlmsg_cb_stop()), 	// NLMSG_DONE
           Some(nlmsg_cb_ok()), ];	// NLMSG_OVERRUN
    assert!(mnl::cl_run2(b.head::<[u8; 48]>(), 0, 0, None, &mut ctlcbs[..]).unwrap() == mnl::CbRet::STOP);
}

#[test]
fn nlmsg_batch_iterator() {
    let mut buf = [0u8; 64];
    {
        let b = mnl::NlmsgBatch::new(&mut buf[..]).unwrap();
        for (i, mut nlh) in b.enumerate() {
            nlh.put_header().unwrap(); // *nlh.nlmsg_len = 16;
            *nlh.nlmsg_type = i as u16;
        }
        b.cap();
        assert!(b.size() == 64);
    }
    {
        for (i, nlh) in mnl::Nlmsg::from_bytes(&mut buf[..]).unwrap().into_iter().enumerate() {
            assert!(*nlh.nlmsg_type == i as u16);
            for (j, my) in nlh.into_iter().enumerate() {
                assert!(*my.nlmsg_type == (i + j) as u16);
            }
        }
    }

    {
        let b = mnl::NlmsgBatch::new(&mut buf[..]).unwrap();
        for (i, mut nlh) in b.enumerate() {
            nlh.put_header().unwrap(); // *nlh.nlmsg_len = 16;
            *nlh.nlmsg_type = i as u16;
        }
        b.put_back();
        b.cap();
        assert!(b.size() == 48);
    }
    {
        for (i, nlh) in mnl::Nlmsg::from_bytes(&mut buf[..]).unwrap().into_iter().enumerate() {
            assert!(*nlh.nlmsg_type == i as u16);
        }
    }
}

#[test]
fn nlmsg_put_extra_header_check() {
    let mut buf = [0u8; 32];
    let mut nlh = mnl::Nlmsg::new(&mut buf[..]).unwrap();
    {
        assert!(nlh.put_extra_header::<linux::netlink::Nlmsghdr>(16).is_ok());
    }
    {
        assert!(nlh.put_extra_header::<linux::netlink::Nlmsghdr>(16).is_err());
    }
}

#[test]
fn nlmsg_put_sized_header_check() {
    let mut buf = [0u8; 32];
    let mut nlh = mnl::Nlmsg::new(&mut buf[..]).unwrap();
    {
        assert!(nlh.put_sized_header::<linux::netlink::Nlmsghdr>().is_ok());
    }
    {
        assert!(nlh.put_sized_header::<linux::netlink::Nlmsghdr>().is_err());
    }
}

fn attr_cb1(attr: &mnl::Attr, data: &mut u16) -> mnl::CbRet {
    if attr.nla_type < *data {
        return mnl::CbRet::OK;
    }
    mnl::CbRet::ERROR
}

#[test]
fn attr_parse_attrs() {
    let mut buf = [0u8; 512];
    let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
    for i in 0..4 {
        nlh.put_u8(i as u16, i).unwrap();
    }

    assert!(mnl::parse_attrs(nlh.payload_bytes(), attr_cb1, &mut 4u16).unwrap() == mnl::CbRet::OK);
    assert!(mnl::parse_attrs(nlh.payload_bytes(), attr_cb1, &mut 3u16).is_err());
}

#[test]
fn attr_cl_parse_payload() {
    let mut buf = [0u8; 512];
    let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
    for i in 0..4 {
        nlh.put_u8(i as u16, i).unwrap();
    }

    let mut data = 4;
    assert!(mnl::cl_parse_attrs(nlh.payload_bytes(),
                                Box::new(move |attr| {
                                    if attr.nla_type < data {
                                        return mnl::CbRet::OK;
                                    }
                                    mnl::CbRet::ERROR
                                })).unwrap() == mnl::CbRet::OK);

    data = 3;
    assert!(mnl::cl_parse_attrs(nlh.payload_bytes(),
                                Box::new(move |attr| {
                                    if attr.nla_type < data {
                                        return mnl::CbRet::OK;
                                    }
                                    mnl::CbRet::ERROR
                                })).is_err());
}

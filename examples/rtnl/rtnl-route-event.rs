use std::io::Write;
use std::mem::size_of;
use std::ffi::CStr;

extern crate libc;
extern crate crslmnl as mnl;
use libc::{ c_int, c_char, c_void, socklen_t };

use mnl::linux::netlink as netlink;
use mnl::linux::rtnetlink;

extern {
    // const char *inet_ntop(int af, const void *src,
    //                       char *dst, socklen_t size);
    fn inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: socklen_t) -> *const c_char;
}
pub const INET_ADDRSTRLEN: usize = 16;
pub const INET6_ADDRSTRLEN: usize = 46;

trait AddrFamily {
    fn family(&self) -> c_int;
}
impl AddrFamily for libc::in_addr {
    fn family(&self) -> c_int { libc::AF_INET }
}
impl AddrFamily for libc::in6_addr {
    fn family(&self) -> c_int { libc::AF_INET6 }
}

fn _inet_ntoa<T: AddrFamily>(addr: &T) -> String {
    let mut buf = [0u8; INET6_ADDRSTRLEN];
    unsafe {
        let rs = inet_ntop(addr.family(), addr as *const _ as *const c_void,
                           buf.as_mut_ptr() as *mut c_char, INET6_ADDRSTRLEN as socklen_t);
        CStr::from_ptr(rs).to_string_lossy().into_owned()
    }
}

macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

fn data_attr_cb2<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    // skip unsupported attribute in user-space
    if let Err(_) = attr.type_valid(rtnetlink::RTAX_MAX as u16) {
        return mnl::CbRet::OK;
    }

    if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
        println_stderr!("mnl_attr_validate: {}", errno);
        return mnl::CbRet::ERROR;
    }

    tb[attr.atype() as usize] = Some(attr);
    mnl::CbRet::OK
}

fn attributes_show_ip<T: AddrFamily>(tb: &[Option<&mnl::Attr>]) {
    tb[rtnetlink::RTA_TABLE as usize]
        .map(|attr| print!("table={} ", attr.u32()));
    tb[rtnetlink::RTA_DST as usize]
        .map(|attr| print!("dst={} ", _inet_ntoa::<T>(attr.payload())));
    tb[rtnetlink::RTA_SRC as usize]
        .map(|attr| print!("src={} ", _inet_ntoa::<T>(attr.payload())));
    tb[rtnetlink::RTA_OIF as usize]
        .map(|attr| print!("oif={} ", attr.u32()));
    tb[rtnetlink::RTA_FLOW as usize]
        .map(|attr| print!("flow={} ", attr.u32()));
    tb[rtnetlink::RTA_PREFSRC as usize]
        .map(|attr| print!("prefsrc={} ", _inet_ntoa::<T>(attr.payload())));
    tb[rtnetlink::RTA_GATEWAY as usize]
        .map(|attr| print!("gw={} ", _inet_ntoa::<T>(attr.payload())));
    tb[rtnetlink::RTA_PRIORITY as usize]
        .map(|attr| print!("prio={} ", attr.u32()));
    tb[rtnetlink::RTA_METRICS as usize]
        .map(|attr| {
            let mut tbx: [Option<&mnl::Attr>; rtnetlink::RTAX_MAX as usize + 1]
                = [None; rtnetlink::RTAX_MAX as usize + 1];
            let _ = attr.parse_nested(data_attr_cb2, &mut tbx);
            for i in 0..rtnetlink::RTAX_MAX as usize {
                tbx[i].map(|attr| print!("metrics[{}]={} ", i, attr.u32()));
            }
        });
}

fn data_ipv4_attr_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    // skip unsupported attribute in user-space
    if let Err(_) = attr.type_valid(rtnetlink::RTA_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if (n == rtnetlink::RTA_TABLE ||
              n == rtnetlink::RTA_DST ||
              n == rtnetlink::RTA_SRC ||
	      n == rtnetlink::RTA_DST ||
	      n == rtnetlink::RTA_SRC ||
	      n == rtnetlink::RTA_OIF ||
	      n == rtnetlink::RTA_FLOW ||
	      n == rtnetlink::RTA_PREFSRC ||
	      n == rtnetlink::RTA_GATEWAY ||
	      n == rtnetlink::RTA_PRIORITY) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if n == rtnetlink::RTA_METRICS => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::NESTED) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        _ => {},
    }
    tb[atype as usize] = Some(attr);
    mnl::CbRet::OK
}

fn data_ipv6_attr_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    // skip unsupported attribute in user-space
    if let Err(_) = attr.type_valid(rtnetlink::RTA_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
	n if (n == rtnetlink::RTA_TABLE ||
	      n == rtnetlink::RTA_OIF ||
	      n == rtnetlink::RTA_FLOW ||
	      n == rtnetlink::RTA_PRIORITY) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
	n if (n == rtnetlink::RTA_DST ||
	      n == rtnetlink::RTA_SRC ||
	      n == rtnetlink::RTA_PREFSRC ||
	      n == rtnetlink::RTA_GATEWAY) => {
                if let Err(errno) = attr.validate2(mnl::AttrDataType::BINARY, size_of::<libc::in6_addr>()) {
                    println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                    return mnl::CbRet::ERROR;
                }
            },
        n if n == rtnetlink::RTA_METRICS => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::NESTED) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        _ => {},
    }
    tb[atype as usize] = Some(attr);
    mnl::CbRet::OK
}

fn data_cb(nlh: mnl::Nlmsg, _: &mut Option<u8>) -> mnl::CbRet {
    let rm = nlh.payload::<rtnetlink::Rtmsg>();

    match *nlh.nlmsg_type {
        n if n == rtnetlink::RTM_NEWROUTE => print!("[NEW] "),
        n if n == rtnetlink::RTM_DELROUTE => print!("[DEL] "),
        _ => {},
    }

    // protocol family = AF_INET | AF_INET6 //
    print!("family={} ", rm.rtm_family);

    // destination CIDR, eg. 24 or 32 for IPv4
    print!("dst_len={} ", rm.rtm_dst_len);

    // source CIDR
    print!("src_len={} ", rm.rtm_src_len);

    // type of service (TOS), eg. 0
    print!("tos={} ", rm.rtm_tos);

    // table id:
    //	RT_TABLE_UNSPEC		= 0
    //
    //	... user defined values ...
    //
    //		RT_TABLE_COMPAT		= 252
    //		RT_TABLE_DEFAULT	= 253
    //		RT_TABLE_MAIN		= 254
    //		RT_TABLE_LOCAL		= 255
    //		RT_TABLE_MAX		= 0xFFFFFFFF
    //
    //	Synonimous attribute: RTA_TABLE.
    print!("table={} ", rm.rtm_table);

    // type:
    // 	RTN_UNSPEC	= 0
    // 	RTN_UNICAST	= 1
    // 	RTN_LOCAL	= 2
    // 	RTN_BROADCAST	= 3
    //	RTN_ANYCAST	= 4
    //	RTN_MULTICAST	= 5
    //	RTN_BLACKHOLE	= 6
    //	RTN_UNREACHABLE	= 7
    //	RTN_PROHIBIT	= 8
    //	RTN_THROW	= 9
    //	RTN_NAT		= 10
    //	RTN_XRESOLVE	= 11
    //	__RTN_MAX	= 12
    print!("type={} ", rm.rtm_type);

    // scope:
    // 	RT_SCOPE_UNIVERSE	= 0   : everywhere in the universe
    //
    //	... user defined values ...
    //
    //	 	RT_SCOPE_SITE		= 200
    //	 	RT_SCOPE_LINK		= 253 : destination attached to link
    //	 	RT_SCOPE_HOST		= 254 : local address
    //	 	RT_SCOPE_NOWHERE	= 255 : not existing destination
    print!("scope={} ", rm.rtm_scope);

    // protocol:
    // 	RTPROT_UNSPEC	= 0
    // 	RTPROT_REDIRECT = 1
    // 	RTPROT_KERNEL	= 2 : route installed by kernel
    // 	RTPROT_BOOT	= 3 : route installed during boot
    // 	RTPROT_STATIC	= 4 : route installed by administrator
    //
    // Values >= RTPROT_STATIC are not interpreted by kernel, they are
    // just user-defined.
    print!("proto={} ", rm.rtm_protocol);

    // flags:
    // 	RTM_F_NOTIFY	= 0x100: notify user of route change
    // 	RTM_F_CLONED	= 0x200: this route is cloned
    // 	RTM_F_EQUALIZE	= 0x400: Multipath equalizer: NI
    // 	RTM_F_PREFIX	= 0x800: Prefix addresses
    print!("flags={:x} ", rm.rtm_flags);

    let mut tb: [Option<&mnl::Attr>; rtnetlink::RTA_MAX as usize + 1]
        = [None; rtnetlink::RTA_MAX as usize + 1];
    match rm.rtm_family as c_int {
        libc::AF_INET => {
            let _ = nlh.parse(size_of::<rtnetlink::Rtmsg>(), data_ipv4_attr_cb, &mut tb);
            attributes_show_ip::<libc::in_addr>(&tb);
        },
        libc::AF_INET6 => {
            let _ = nlh.parse(size_of::<rtnetlink::Rtmsg>(), data_ipv6_attr_cb, &mut tb);
            attributes_show_ip::<libc::in6_addr>(&tb);
        },
        _ => unreachable!()
    }

    println!("");
    mnl::CbRet::OK
}

fn main() {
    let nl = mnl::Socket::open(netlink::Family::ROUTE)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(rtnetlink::RTMGRP_IPV4_ROUTE | rtnetlink::RTMGRP_IPV6_ROUTE,
            mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));

    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
        if mnl::cb_run(&buf[0..nrecv], 0, 0, Some(data_cb), &mut None)
            .unwrap_or_else(|errno| panic!("mnl_cb_run: {}", errno))
            == mnl::CbRet::STOP {
            break;
        }
    }
    let _ = nl.close();
}

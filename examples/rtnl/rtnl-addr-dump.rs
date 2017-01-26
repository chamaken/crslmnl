use std::env;
use std::io::Write;
use std::mem::size_of;
use std::vec::Vec;
use std::net::{Ipv4Addr, Ipv6Addr};

extern crate libc;
extern crate time;
extern crate crslmnl as mnl;
use libc::{ AF_INET, AF_INET6 };

use mnl::linux::netlink as netlink;
use mnl::linux::rtnetlink;
use mnl::linux::if_addr;
use mnl::linux::if_link;

macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

fn data_attr_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    // skip unsupported attribute in user-space
    if let Err(_) = attr.type_valid(if_addr::IFA_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if n == if_addr::IFA_ADDRESS => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::BINARY) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        _ => {},
    }
    tb[atype as usize] = Some(attr);
    mnl::CbRet::OK
}

fn data_cb(nlh: &mnl::Nlmsg, _: &mut Option<u8>) -> mnl::CbRet {
    let mut tb: [Option<&mnl::Attr>; if_link::IFLA_MAX as usize + 1]
        = [None; if_link::IFLA_MAX as usize + 1];
    let ifa = nlh.payload::<if_addr::Ifaddrmsg>();

    print!("index={} family={} ", ifa.ifa_index, ifa.ifa_family);
    let _ = nlh.parse(size_of::<if_addr::Ifaddrmsg>(), data_attr_cb, &mut tb);
    print!("addr=");
    tb[if_addr::IFA_ADDRESS as usize]
        .map(|attr| {
            if ifa.ifa_family == AF_INET as u8 {
                let in_addr = attr.payload::<Ipv4Addr>();
                print!("{} ", in_addr);
            } else if ifa.ifa_family == AF_INET6 as u8 {
                let in6_addr = attr.payload::<Ipv6Addr>();
                print!("{} ", in6_addr);
            }
        });
    print!("scope=");
    match ifa.ifa_scope {
        0	=> print!("global "),
        200	=> print!("site "),
        253	=> print!("link "),
        254	=> print!("host "),
        255	=> print!("nowhere "),
        _	=> print!("{} ", ifa.ifa_scope),
    }

    println!("");
    return mnl::CbRet::OK;
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        panic!("Usage: {} <inet|inet6>", args[0]);
    }

    let nl = mnl::Socket::open(netlink::Family::ROUTE)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    let seq = time::now().to_timespec().sec as u32;
    {
        let nlh = mnl::Nlmsg::put_header(&mut buf);
        nlh.nlmsg_type = rtnetlink::RTM_GETADDR;
        nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP;
        nlh.nlmsg_seq = seq;
        let rt = nlh.put_sized_header::<rtnetlink::Rtgenmsg>();
        if args[1] == "inet" {
        rt.rtgen_family = AF_INET as u8;
        } else if args[1] == "inet6" {
            rt.rtgen_family = AF_INET6 as u8;
        }
        nl.send_nlmsg(nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        if mnl::cb_run(&buf[0..nrecv], seq, portid, Some(data_cb), &mut None)
            .unwrap_or_else(|errno| panic!("mnl_cb_run: {}", errno))
            == mnl::CbRet::STOP {
            break;
        }
    }
    let _ = nl.close();
}

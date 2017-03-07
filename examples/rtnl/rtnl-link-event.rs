use std::io::Write;
use std::mem::size_of;

extern crate crslmnl as mnl;

use mnl::linux::netlink as netlink;
use mnl::linux::rtnetlink;
use mnl::linux::if_link;
use mnl::linux::ifh;

macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

fn data_attr_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    // skip unsupported attribute in user-space
    if let Err(_) = attr.type_valid(if_link::IFLA_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if n == if_link::IFLA_MTU => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if n == if_link::IFLA_IFNAME => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::STRING) {
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
    let mut tb: [Option<&mnl::Attr>; if_link::IFLA_MAX as usize + 1]
        = [None; if_link::IFLA_MAX as usize + 1];
    let ifm = nlh.payload::<rtnetlink::Ifinfomsg>();

    print!("index={} type={} flags=0x{:x} family={} ",
           ifm.ifi_index, ifm.ifi_type, ifm.ifi_flags, ifm.ifi_family);

    if ifm.ifi_flags & ifh::IFF_RUNNING != 0 {
        print!("[RUNNING] ");
    } else {
        print!("[NOT RUNNING] ");
    }

    let _ = nlh.parse(size_of::<rtnetlink::Ifinfomsg>(), data_attr_cb, &mut tb);
    tb[if_link::IFLA_MTU as usize]
        .map(|attr| print!("mtu={} ", attr.u32()));
    tb[if_link::IFLA_IFNAME as usize]
        .map(|attr| print!("name={} ", attr.str()));
    println!("");
    mnl::CbRet::OK
}

fn main() {
    let nl = mnl::Socket::open(netlink::Family::ROUTE)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(rtnetlink::RTMGRP_LINK, mnl::SOCKET_AUTOPID)
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

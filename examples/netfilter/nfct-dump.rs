use std::io::Write;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::exit;
use std::vec::Vec;

extern crate libc;
extern crate time;
extern crate crslmnl as mnl;

use mnl::linux::netlink as netlink;
use mnl::linux::netfilter::nfnetlink as nfnl;
use mnl::linux::netfilter::nfnetlink_conntrack as nfct;

macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

fn parse_counters_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(nfct::CTA_COUNTERS_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if (n == nfct::AttrCounters::PACKETS as u16 ||
              n == nfct::AttrCounters::BYTES as u16) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U64) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        _ => {},
    }
    tb[atype as usize] = Some(attr);
    mnl::CbRet::OK
}

fn print_counters(nest: &mnl::Attr) {
    let mut tb: [Option<&mnl::Attr>; nfct::CTA_COUNTERS_MAX as usize + 1]
        = [None; nfct::CTA_COUNTERS_MAX as usize + 1];

    let _ = nest.parse_nested(parse_counters_cb, &mut tb);
    if let Some(v) = tb[nfct::AttrCounters::PACKETS as usize] {
        print!("packets={} ", v.u64());
    }
    if let Some(v) = tb[nfct::AttrCounters::BYTES as usize] {
        print!("bytes={} ", v.u64());
    }
}

fn parse_ip_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(nfct::CTA_IP_MAX) {
        return mnl::CbRet::OK
    }

    let atype = attr.atype();
    match atype {
        n if (n == nfct::AttrIp::V4_SRC as u16 ||
              n == nfct::AttrIp::V4_DST as u16) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if (n == nfct::AttrIp::V6_SRC as u16 ||
              n == nfct::AttrIp::V6_DST as u16) => {
            if let Err(errno) = attr.validate2(mnl::AttrDataType::BINARY, size_of::<Ipv6Addr>()) {
                println_stderr!("mnl_attr_validate2 - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        _ => {},
    }
    tb[atype as usize] = Some(attr);
    mnl::CbRet::OK
}

fn print_ip(nest: &mnl::Attr) {
    let mut tb: [Option<&mnl::Attr>; nfct::CTA_IP_MAX as usize + 1]
        = [None; nfct::CTA_IP_MAX as usize + 1];

    let _ = nest.parse_nested(parse_ip_cb, &mut tb);
    if let Some(attr) = tb[nfct::AttrIp::V4_SRC as usize] {
        let in_addr = attr.payload::<Ipv4Addr>();
        print!("src={} ", in_addr);
    }
    if let Some(attr) = tb[nfct::AttrIp::V4_DST as usize] {
        let in_addr = attr.payload::<Ipv4Addr>();
        print!("dst={} ", in_addr);
    }
    if let Some(attr) = tb[nfct::AttrIp::V6_SRC as usize] {
        let in6_addr = attr.payload::<Ipv6Addr>();
        print!("src={} ", in6_addr);
    }
    if let Some(attr) = tb[nfct::AttrIp::V6_DST as usize] {
        let in6_addr = attr.payload::<Ipv6Addr>();
        print!("dst={} ", in6_addr);
    }
}

fn parse_proto_cb<'a>(attr: &'a mnl::Attr, tb: &mut[Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(nfct::CTA_PROTO_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if (n == nfct::AttrL4proto::NUM as u16 ||
              n == nfct::AttrL4proto::ICMP_TYPE as u16 ||
              n == nfct::AttrL4proto::ICMP_CODE as u16) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U8) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if (n == nfct::AttrL4proto::SRC_PORT as u16 ||
              n == nfct::AttrL4proto::DST_PORT as u16 ||
              n == nfct::AttrL4proto::ICMP_ID as u16) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U16) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        _ => {},
    }
    tb[atype as usize] = Some(attr);
    mnl::CbRet::OK
}

fn print_proto(nest: &mnl::Attr) {
    let mut tb: [Option<&mnl::Attr>; nfct::CTA_PROTO_MAX as usize + 1]
        = [None; nfct::CTA_PROTO_MAX as usize + 1];

    let _ = nest.parse_nested(parse_proto_cb, &mut tb);
    if let Some(attr) = tb[nfct::AttrL4proto::NUM as usize] {
        print!("proto={} ", attr.u8());
    }
    if let Some(attr) = tb[nfct::AttrL4proto::SRC_PORT as usize] {
        print!("sport={} ", u16::from_be(attr.u16()));
    }
    if let Some(attr) = tb[nfct::AttrL4proto::DST_PORT as usize] {
        print!("dport={} ", u16::from_be(attr.u16()));
    }
    if let Some(attr) = tb[nfct::AttrL4proto::ICMP_ID as usize] {
        print!("id={} ", u16::from_be(attr.u16()));
    }
    if let Some(attr) = tb[nfct::AttrL4proto::ICMP_TYPE as usize] {
        print!("type={} ", u8::from_be(attr.u8()));
    }
    if let Some(attr) = tb[nfct::AttrL4proto::ICMP_CODE as usize] {
        print!("code={} ", u8::from_be(attr.u8()));
    }
}

fn parse_tuple_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(nfct::CTA_TUPLE_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if n == nfct::AttrTuple::IP as u16 => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::NESTED) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if n == nfct::AttrTuple::PROTO as u16 => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::NESTED) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR
            }
        },
        _ => {},
    }
    tb[atype as usize] = Some(attr);
    mnl::CbRet::OK
}

fn print_tuple(nest: &mnl::Attr) {
    let mut tb: [Option<&mnl::Attr>; nfct::CTA_TUPLE_MAX as usize + 1]
        = [None; nfct::CTA_TUPLE_MAX as usize + 1];

    let _ = nest.parse_nested(parse_tuple_cb, &mut tb);
    if let Some(attr) = tb[nfct::AttrTuple::IP as usize] {
        print_ip(attr);
    }
    if let Some(attr) = tb[nfct::AttrTuple::PROTO as usize] {
        print_proto(attr);
    }
}

fn data_attr_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(nfct::CTA_MAX as u16) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if (n == nfct::AttrType::TUPLE_ORIG as u16 ||
              n == nfct::AttrType::COUNTERS_ORIG as u16 ||
              n == nfct::AttrType::COUNTERS_REPLY as u16) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::NESTED) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if (n == nfct::AttrType::TIMEOUT as u16 ||
              n == nfct::AttrType::MARK as u16 ||
              n == nfct::AttrType::SECMARK as u16) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        _ => {},
    }
    tb[atype as usize] = Some(attr);
    mnl::CbRet::OK
}

fn data_cb(nlh: &mnl::Nlmsg, _: &mut u8) -> mnl::CbRet {
    let mut tb: [Option<&mnl::Attr>; nfct::CTA_MAX as usize + 1]
        = [None; nfct::CTA_MAX as usize + 1];
    // let nfg = nlh.payload::<nfnl::Nfgenmsg>();

    let _ = nlh.parse(size_of::<nfnl::Nfgenmsg>(), data_attr_cb, &mut tb);
    if let Some(attr) = tb[nfct::AttrType::TUPLE_ORIG as usize] {
        print_tuple(attr);
    }
    if let Some(attr) = tb[nfct::AttrType::MARK as usize] {
        print!("mark={} ", u32::from_be(attr.u32()));
    }
    if let Some(attr) = tb[nfct::AttrType::SECMARK as usize] {
        print!("secmark={} ", u32::from_be(attr.u32()));
    }
    if let Some(attr) = tb[nfct::AttrType::COUNTERS_ORIG as usize] {
        print!("original ");
        print_counters(attr);
    }
    if let Some(attr) = tb[nfct::AttrType::COUNTERS_REPLY as usize] {
        print!("reply ");
        print_counters(attr);
    }

    println!("");
    mnl::CbRet::OK
}

fn main() {
    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];

    let nl: &mut mnl::Socket;
    match mnl::Socket::open(netlink::Family::NETFILTER) {
        Ok(sock) => nl = sock,
        Err(errno) => {
            println_stderr!("mnl_socket_open: {}", errno);
            exit(libc::EXIT_FAILURE);
        }
    }

    if let Err(errno) = nl.bind(0, mnl::SOCKET_AUTOPID) {
        println_stderr!("mnl_socket_bind: {}", errno);
        exit(libc::EXIT_FAILURE);
    }

    let seq = time::now().to_timespec().sec as u32;
    {
        let mut nlh = mnl::Nlmsg::put_header(&mut buf);
        // nlh.nlmsg_type = (nfnl::SUBSYS_CTNETLINK << 8) | nfct::MsgTypes::GET as u16;
        nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP;
        nlh.nlmsg_seq = seq;

        let nfh = nlh.put_sized_header::<nfnl::Nfgenmsg>();
        nfh.nfgen_family = libc::AF_INET as u8;
        nfh.version = nfnl::NFNETLINK_V0;
        nfh.res_id = 0;

        if let Err(errno) = nl.send_nlmsg(nlh) {
            println_stderr!("mnl_socket_sendto: {}", errno);
            exit(libc::EXIT_FAILURE);
        }
    }
    let portid = nl.portid();

    let mut nrecv: usize;
    loop {
        match nl.recvfrom(&mut buf) {
            Err(errno) => {
                println_stderr!("mnl_socket_recvfrom: {}", errno);
                exit(libc::EXIT_FAILURE);
            },
            Ok(n) => nrecv = n,
        }

        match mnl::cb_run(&buf[0..nrecv], seq, portid, data_cb, &mut 0) {
            Err(errno) => {
                println_stderr!("mnl_cb_run: {}", errno);
                exit(libc::EXIT_FAILURE);
            },
            Ok(ret) => {
                if ret == mnl::CbRet::STOP {
                    break;
                }
            },
        }
    }
    let _ = nl.close();
}

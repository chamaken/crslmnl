use std::io::Write;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};

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
    tb[nfct::AttrCounters::PACKETS as usize]
        .map(|attr| print!("packets={} ", attr.u64()));
    tb[nfct::AttrCounters::BYTES as usize]
        .map(|attr| print!("bytes={} ", attr.u64()));
}

fn parse_ip_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(nfct::CTA_IP_MAX) {
        return mnl::CbRet::OK
    }

    let atype = attr.atype();
    match atype {
        n if (n == nfct::CtattrIp::V4_SRC as u16 ||
              n == nfct::CtattrIp::V4_DST as u16) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if (n == nfct::CtattrIp::V6_SRC as u16 ||
              n == nfct::CtattrIp::V6_DST as u16) => {
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
    tb[nfct::CtattrIp::V4_SRC as usize]
        .map(|attr| {
            let in_addr = attr.payload::<Ipv4Addr>();
            print!("src={} ", in_addr);
        });
    tb[nfct::CtattrIp::V4_DST as usize]
        .map(|attr| {
            let in_addr = attr.payload::<Ipv4Addr>();
            print!("dst={} ", in_addr);
        });
    tb[nfct::CtattrIp::V6_SRC as usize]
        .map(|attr| {
            let in6_addr = attr.payload::<Ipv6Addr>();
            print!("src={} ", in6_addr);
        });
    tb[nfct::CtattrIp::V6_DST as usize]
        .map(|attr| {
            let in6_addr = attr.payload::<Ipv6Addr>();
            print!("dst={} ", in6_addr);
        });
}

fn parse_proto_cb<'a>(attr: &'a mnl::Attr, tb: &mut[Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(nfct::CTA_PROTO_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if (n == nfct::CtattrL4proto::NUM as u16 ||
              n == nfct::CtattrL4proto::ICMP_TYPE as u16 ||
              n == nfct::CtattrL4proto::ICMP_CODE as u16) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U8) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if (n == nfct::CtattrL4proto::SRC_PORT as u16 ||
              n == nfct::CtattrL4proto::DST_PORT as u16 ||
              n == nfct::CtattrL4proto::ICMP_ID as u16) => {
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
    tb[nfct::CtattrL4proto::NUM as usize]
        .map(|attr| print!("proto={} ", attr.u8()));
    tb[nfct::CtattrL4proto::SRC_PORT as usize]
        .map(|attr| print!("sport={} ", u16::from_be(attr.u16())));
    tb[nfct::CtattrL4proto::DST_PORT as usize]
        .map(|attr| print!("dport={} ", u16::from_be(attr.u16())));
    tb[nfct::CtattrL4proto::ICMP_ID as usize]
        .map(|attr| print!("id={} ", u16::from_be(attr.u16())));
    tb[nfct::CtattrL4proto::ICMP_TYPE as usize]
        .map(|attr| print!("type={} ", u8::from_be(attr.u8())));
    tb[nfct::CtattrL4proto::ICMP_CODE as usize]
        .map(|attr| print!("code={} ", u8::from_be(attr.u8())));
}

fn parse_tuple_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(nfct::CTA_TUPLE_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if n == nfct::CtattrTuple::IP as u16 => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::NESTED) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if n == nfct::CtattrTuple::PROTO as u16 => {
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
    tb[nfct::CtattrTuple::IP as usize]
        .map(|attr| print_ip(attr));
    tb[nfct::CtattrTuple::PROTO as usize]
        .map(|attr| print_proto(attr));
}

fn data_attr_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(nfct::CTA_MAX as u16) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if (n == nfct::CtattrType::TUPLE_ORIG as u16 ||
              n == nfct::CtattrType::COUNTERS_ORIG as u16 ||
              n == nfct::CtattrType::COUNTERS_REPLY as u16) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::NESTED) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if (n == nfct::CtattrType::TIMEOUT as u16 ||
              n == nfct::CtattrType::MARK as u16 ||
              n == nfct::CtattrType::SECMARK as u16) => {
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

fn data_cb(nlh: &mnl::Nlmsg, _: &mut Option<u8>) -> mnl::CbRet {
    let mut tb: [Option<&mnl::Attr>; nfct::CTA_MAX as usize + 1]
        = [None; nfct::CTA_MAX as usize + 1];
    // let nfg = nlh.payload::<nfnl::Nfgenmsg>();

    let _ = nlh.parse(size_of::<nfnl::Nfgenmsg>(), data_attr_cb, &mut tb);
    tb[nfct::CtattrType::TUPLE_ORIG as usize]
        .map(|attr| print_tuple(attr));
    tb[nfct::CtattrType::MARK as usize]
        .map(|attr| print!("mark={} ", u32::from_be(attr.u32())));
    tb[nfct::CtattrType::SECMARK as usize]
        .map(|attr| print!("secmark={} ", u32::from_be(attr.u32())));
    tb[nfct::CtattrType::COUNTERS_ORIG as usize]
        .map(|attr| {
            print!("original ");
            print_counters(attr);
        });
    tb[nfct::CtattrType::COUNTERS_REPLY as usize]
        .map(|attr| {
            print!("reply ");
            print_counters(attr);
        });
    println!("");

    mnl::CbRet::OK
}

fn main() {
    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];

    let nl = mnl::Socket::open(netlink::Family::NETFILTER)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));

    let seq = time::now().to_timespec().sec as u32;
    {
        let mut nlh = mnl::Nlmsg::put_header(&mut buf);
        nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_CTNETLINK << 8) | nfct::CtnlMsgTypes::GET as u16;
        nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP;
        nlh.nlmsg_seq = seq;

        let nfh = nlh.put_sized_header::<nfnl::Nfgenmsg>();
        nfh.nfgen_family = libc::AF_INET as u8;
        nfh.version = nfnl::NFNETLINK_V0;
        nfh.res_id = 0;

        nl.send_nlmsg(nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }
    let portid = nl.portid();

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

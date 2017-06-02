use std::env;
use std::io::Write;
use std::mem::size_of;
use std::vec::Vec;

extern crate libc;
extern crate pnet;
extern crate crslmnl as mnl;

use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ethernet::EthernetPacket;

use mnl::linux::netlink as netlink;
use mnl::linux::netfilter::nfnetlink as nfnl;
use mnl::linux::netfilter::nfnetlink_log as nful;


macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

fn parse_attr_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    // skip unsupported attribute in user-space
    if let Err(_) = attr.type_valid(nful::NFULA_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if (n == nful::AttrType::MARK as u16 ||
              n == nful::AttrType::IFINDEX_INDEV as u16 ||
              n == nful::AttrType::IFINDEX_OUTDEV as u16 ||
              n == nful::AttrType::IFINDEX_PHYSINDEV as u16 ||
              n == nful::AttrType::IFINDEX_PHYSOUTDEV as u16) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if n == nful::AttrType::TIMESTAMP as u16 => {
            if let Err(errno) = attr.validate2(mnl::AttrDataType::UNSPEC,
                                               size_of::<nful::MsgPacketTimestamp>()) {
                println_stderr!("mnl_attr_validate2: {}", errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if n == nful::AttrType::HWADDR as u16 => {
            if let Err(errno) = attr.validate2(mnl::AttrDataType::STRING,
                                               size_of::<nful::MsgPacketHw>()) {
                println_stderr!("mnl_attr_validate2: {}", errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if n == nful::AttrType::PREFIX as u16 => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::NUL_STRING) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        }
        n if n == nful::AttrType::PAYLOAD as u16 => {},
        _ => {},
    }
    tb[atype as usize] = Some(attr);
    mnl::CbRet::OK
}

fn log_cb(nlh: mnl::Nlmsg, _: &mut Option<u8>) -> mnl::CbRet {
    let mut ph: &nful::MsgPacketHdr = &nful::MsgPacketHdr { hw_protocol: 0, hook: 0, _pad: 0 };
    let mut prefix = "";
    let mut mark: u32 = 0;
    let mut tb: [Option<&mnl::Attr>; nful::NFULA_MAX as usize + 1]
        = [None; nful::NFULA_MAX as usize + 1];

    let nfg = nlh.payload::<nfnl::Nfgenmsg>();
    let pf = nfg.nfgen_family;
    nlh.parse(size_of::<nfnl::Nfgenmsg>(), parse_attr_cb, &mut tb)
        .unwrap_or_else(|errno| panic!("mnl_attr_parse: {}", errno));

    tb[nful::AttrType::PACKET_HDR as usize]
        .map(|attr| ph = attr.payload());
    tb[nful::AttrType::PREFIX as usize]
        .map(|attr| prefix = attr.str());
    tb[nful::AttrType::MARK as usize]
        .map(|attr| mark = attr.u32());

    println!("log received (prefix={}, hw=0x{:x}, hook={}, mark={})",
             prefix, ph.hw_protocol, ph.hook, mark);

    tb[nful::AttrType::PAYLOAD as usize]
        .map(|attr| {
            let pbuf: &[u8] = unsafe {
                std::slice::from_raw_parts(attr.payload::<u8>() as *const u8,
                                           attr.nla_len as usize)
            };
            match pf as i32 {
                libc::PF_BRIDGE => {
                    let pkt = EthernetPacket::new(pbuf).unwrap();
                    println!("payload src: {}, dst: {}, ether type: {}",
                             pkt.get_source(), pkt.get_destination(),
                             pkt.get_ethertype());
                },
                libc::PF_INET => {
                    let pkt = Ipv4Packet::new(pbuf).unwrap();
                    println!("payload src: {}, dst: {}, protocol: {}",
                             pkt.get_source(), pkt.get_destination(),
                             pkt.get_next_level_protocol());
                },
                libc::PF_INET6 => {
                    let pkt = Ipv6Packet::new(pbuf).unwrap();
                    println!("payload src: {}, dst: {}, next header: {}",
                    	     pkt.get_source(), pkt.get_destination(),
                             pkt.get_next_header());
                },
                _ => panic!("unknown protocol family: {}", pf),
            }
        });

    mnl::CbRet::OK
}

fn nflog_build_cfg_pf_request<'a>(buf: &'a mut [u8], command: u8) -> mnl::Nlmsg {
    let mut nlh = mnl::Nlmsg::new(buf).unwrap();
    *nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_ULOG << 8) | nful::MsgTypes::CONFIG as u16;
    *nlh.nlmsg_flags = netlink::NLM_F_REQUEST;

    let nfg = nlh.put_sized_header::<nfnl::Nfgenmsg>().unwrap();
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = nfnl::NFNETLINK_V0;

    let cmd = nful::MsgConfigCmd{command: command};
    nlh.put(nful::AttrConfig::CMD as u16, &cmd).unwrap();
    nlh
}

fn nflog_build_cfg_request<'a>(buf: &'a mut [u8], command: u8, qnum: u16) -> mnl::Nlmsg {
    let mut nlh = mnl::Nlmsg::new(buf).unwrap();
    *nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_ULOG << 8) | nful::MsgTypes::CONFIG as u16;
    *nlh.nlmsg_flags = netlink::NLM_F_REQUEST;

    let nfg = nlh.put_sized_header::<nfnl::Nfgenmsg>().unwrap();
    nfg.nfgen_family = libc::AF_INET as u8;
    nfg.version = nfnl::NFNETLINK_V0;
    nfg.res_id = qnum.to_be();

    let cmd = nful::MsgConfigCmd{command: command};
    nlh.put(nful::AttrConfig::CMD as u16, &cmd).unwrap();
    nlh
}

fn nflog_build_cfg_params<'a>(buf: &'a mut [u8], mode: u8, range: u32, qnum: u16) -> mnl::Nlmsg {
    let mut nlh = mnl::Nlmsg::new(buf).unwrap();
    *nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_ULOG << 8) | nful::MsgTypes::CONFIG as u16;
    *nlh.nlmsg_flags = netlink::NLM_F_REQUEST;

    let nfg = nlh.put_sized_header::<nfnl::Nfgenmsg>().unwrap();
    nfg.nfgen_family = 0; // libc::AF_UNSPEC as u8;
    nfg.version = nfnl::NFNETLINK_V0;
    nfg.res_id = qnum.to_be();

    let params = nful::MsgConfigMode{
        copy_range: range.to_be(),
        copy_mode: mode,
        _pad: 0,
    };
    nlh.put(nful::AttrConfig::MODE as u16, &params).unwrap();
    nlh
}


fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        panic!("Usage: {} [queue_num]", args[0]);
    }
    let qnum: u16 = args[1].trim().parse().expect("queue number required");

    let nl = mnl::Socket::open(netlink::Family::NETFILTER)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    {
        let nlh = nflog_build_cfg_pf_request(&mut buf, nful::MsgConfigCmds::PF_UNBIND as u8);
        nl.send_nlmsg(&nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    {
        let nlh = nflog_build_cfg_pf_request(&mut buf, nful::MsgConfigCmds::PF_BIND as u8);
        nl.send_nlmsg(&nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    {
        let nlh = nflog_build_cfg_request(&mut buf, nful::MsgConfigCmds::BIND as u8, qnum);
        nl.send_nlmsg(&nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    {
        let nlh = nflog_build_cfg_params(&mut buf, nful::COPY_PACKET as u8, 0xffff, qnum);
        nl.send_nlmsg(&nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        if mnl::cb_run(&buf[0..nrecv], 0, portid, Some(log_cb), &mut None)
            .unwrap_or_else(|errno| panic!("mnl_cb_run: {}", errno))
            == mnl::CbRet::STOP {
                break;
        }
    }
    let _ = nl.close();
}

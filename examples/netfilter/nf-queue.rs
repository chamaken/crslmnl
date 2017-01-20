use std::env;
use std::io::Write;
use std::mem::size_of;
use std::vec::Vec;

extern crate libc;
extern crate time;
extern crate crslmnl as mnl;

use mnl::linux::netlink as netlink;
use mnl::linux::netfilter as nf;
use mnl::linux::netfilter::nfnetlink as nfnl;
use mnl::linux::netfilter::nfnetlink_queue as nfq;

macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

fn parse_attr_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    // skip unsupported attribute in user-space
    if let Err(_) = attr.type_valid(nfq::NFQA_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if (n == nfq::AttrType::MARK as u16 ||
              n == nfq::AttrType::IFINDEX_INDEV as u16 ||
              n == nfq::AttrType::IFINDEX_OUTDEV as u16 ||
              n == nfq::AttrType::IFINDEX_PHYINDEV as u16 ||
              n == nfq::AttrType::IFINDEX_PHYOUTDEV as u16) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if n == nfq::AttrType::TIMESTAMP as u16 => {
            if let Err(errno) = attr.validate2(mnl::AttrDataType::UNSPEC,
                                               size_of::<nfq::MsgPacketTimestamp>()) {
                println_stderr!("mnl_attr_validate2 - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if n == nfq::AttrType::HWADDR as u16 => {
            if let Err(errno) = attr.validate2(mnl::AttrDataType::UNSPEC,
                                               size_of::<nfq::MsgPacketHw>()) {
                println_stderr!("mnl_attr_validate2 - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if n == nfq::AttrType::PAYLOAD as u16 => {},
        _ => {},
    }
    tb[atype as usize] = Some(attr);
    mnl::CbRet::OK
}

fn queue_cb(nlh: &mnl::Nlmsg, packet_id: &mut u32) -> mnl::CbRet {
    let mut tb: [Option<&mnl::Attr>; nfq::NFQA_MAX as usize]
        = [None; nfq::NFQA_MAX as usize];
    let mut id: u32 = 0;

    let _ = nlh.parse(size_of::<nfnl::Nfgenmsg>(), parse_attr_cb, &mut tb);
    tb[nfq::AttrType::PACKET_HDR as usize]
        .map(|attr| {
            let ph: &nfq::MsgPacketHdr = attr.payload::<nfq::MsgPacketHdr>();
            id = u32::from_be(ph.packet_id);
            println!("packet received (id={} hw=0x{:04x} hook={})",
                     id, u16::from_be(ph.hw_protocol), ph.hook);
        });

    *packet_id = id;
    mnl::CbRet::OK
}

fn nfq_build_cfg_pf_request<'a>(buf: &'a mut[u8], command: u8) -> &mut mnl::Nlmsg {
    let nlh = mnl::Nlmsg::put_header(buf);
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_QUEUE << 8) | nfq::MsgTypes::CONFIG as u16;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST;

    let nfg = nlh.put_sized_header::<nfnl::Nfgenmsg>();
    nfg.nfgen_family = 0; // libc::AF_UNSPEC as u8;
    nfg.version = nfnl::NFNETLINK_V0;

    let cmd = nfq::MsgConfigCmd {
        command: command,
        pf: libc::AF_INET.to_be() as u16,
        ..Default::default()
    };
    nlh.put(nfq::AttrConfig::CMD as u16, cmd);

    nlh
}

fn nfq_build_cfg_request<'a>(buf: &'a mut[u8], command: u8, queue_num: u16) -> &mut mnl::Nlmsg {
    let nlh = mnl::Nlmsg::put_header(buf);
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_QUEUE << 8) | nfq::MsgTypes::CONFIG as u16;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST;

    let nfg = nlh.put_sized_header::<nfnl::Nfgenmsg>();
    nfg.nfgen_family = 0; // libc::AF_UNSPEC as u8;
    nfg.version = nfnl::NFNETLINK_V0;
    nfg.res_id = queue_num.to_be();

    let cmd = nfq::MsgConfigCmd {
        command: command,
        pf: libc::AF_INET.to_be() as u16,
        ..Default::default()
    };
    nlh.put(nfq::AttrConfig::CMD as u16, cmd);

    nlh
}

fn nfq_build_cfg_params<'a>(buf: &'a mut [u8], mode: u8, range: u32, queue_num: u16) -> &mut mnl::Nlmsg {
    let nlh = mnl::Nlmsg::put_header(buf);
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_QUEUE << 8) | nfq::MsgTypes::CONFIG as u16;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST;

    let nfg = nlh.put_sized_header::<nfnl::Nfgenmsg>();
    nfg.nfgen_family = 0; // libc::AF_UNSPEC as u8;
    nfg.version = nfnl::NFNETLINK_V0;
    nfg.res_id = queue_num.to_be();

    let params = nfq::MsgConfigParams { copy_range: range.to_be(), copy_mode: mode };
    nlh.put(nfq::AttrConfig::PARAMS as u16, params);

    nlh
}

fn nfq_build_verdict<'a>(buf: &'a mut [u8], id: u32, queue_num: u16, verd: u32) -> &mut mnl::Nlmsg {
    let nlh = mnl::Nlmsg::put_header(buf);
    nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_QUEUE << 8) | nfq::MsgTypes::VERDICT as u16;
    nlh.nlmsg_flags = netlink::NLM_F_REQUEST;
    let nfg = nlh.put_sized_header::<nfnl::Nfgenmsg>();
    nfg.nfgen_family = 0; // libc::AF_UNSPEC as u8;
    nfg.version = nfnl::NFNETLINK_V0;
    nfg.res_id = queue_num.to_be();

    let vh = nfq::MsgVerdictHdr { verdict: verd.to_be(), id: id.to_be() };
    let _ = nlh.put(nfq::AttrType::VERDICT_HDR as u16, vh);

    nlh
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        panic!("Usage: {} [queue_num]", args[0]);
    }
    let queue_num: u16 = args[1].trim().parse().expect("queue number required");

    let nl = mnl::Socket::open(netlink::Family::NETFILTER)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    {
        let nlh = nfq_build_cfg_pf_request(&mut buf, nfq::MsgConfigCmds::PF_UNBIND as u8);
        nl.send_nlmsg(nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    {
        let nlh = nfq_build_cfg_pf_request(&mut buf, nfq::MsgConfigCmds::PF_BIND as u8);
        nl.send_nlmsg(nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    {
        let nlh = nfq_build_cfg_request(&mut buf, nfq::MsgConfigCmds::BIND as u8, queue_num);
        nl.send_nlmsg(nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    {
        let nlh = nfq_build_cfg_params(&mut buf, nfq::ConfigMode::COPY_PACKET as u8, 0xFFFF, queue_num);
        nl.send_nlmsg(nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    let mut id: u32 = 0;
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        mnl::cb_run(&buf[0..nrecv], 0, portid, queue_cb, &mut id)
            .unwrap_or_else(|errno| panic!("mnl_cb_run: {}", errno));

        let nlh = nfq_build_verdict(&mut buf, id, queue_num, nf::NF_ACCEPT);
        nl.send_nlmsg(nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    // let _ = nl.close();
}

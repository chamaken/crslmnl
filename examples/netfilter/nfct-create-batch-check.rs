use std::io;
use std::net;
use std::os::unix::io::AsRawFd;
use std::mem::zeroed;

extern crate libc;
extern crate time;
extern crate crslmnl as mnl;

use mnl::linux::netlink as netlink;
use mnl::linux::netfilter::nfnetlink as nfnl;
use mnl::linux::netfilter::nfnetlink_conntrack as nfct;
use mnl::linux::netfilter::nf_conntrack_common as nfct_common;
use mnl::linux::netfilter::nf_conntrack_tcp as nfct_tcp;

mod epoll;

fn put_msg(nlh: &mut mnl::Nlmsg, i: u16, seq: u32) -> io::Result<()>{
    nlh.put_header().unwrap();
    *nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_CTNETLINK << 8) | nfct::IPCTNL_MSG_CT_NEW;
    *nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_CREATE
        | netlink::NLM_F_EXCL | netlink::NLM_F_ACK;
    *nlh.nlmsg_seq = seq;

    let nfh = try!(nlh.put_sized_header::<nfnl::Nfgenmsg>());
    nfh.nfgen_family = libc::AF_INET as u8;
    nfh.version = nfnl::NFNETLINK_V0;
    nfh.res_id = 0;

    let mut nest1 = try!(nlh.nest_start(nfct::CTA_TUPLE_ORIG));
    let mut nest2 = try!(nlh.nest_start(nfct::CTA_TUPLE_IP));
    try!(nlh.put_u32(nfct::CTA_IP_V4_SRC, u32::from(net::Ipv4Addr::new(1, 1, 1, 1))));
    try!(nlh.put_u32(nfct::CTA_IP_V4_DST, u32::from(net::Ipv4Addr::new(2, 2, 2, 2))));
    nlh.nest_end(nest2);

    nest2 = try!(nlh.nest_start(nfct::CTA_TUPLE_PROTO));
    try!(nlh.put_u8(nfct::CTA_PROTO_NUM, libc::IPPROTO_TCP as u8));
    try!(nlh.put_u16(nfct::CTA_PROTO_SRC_PORT, u16::to_be(i)));
    try!(nlh.put_u16(nfct::CTA_PROTO_DST_PORT, u16::to_be(1025)));
    nlh.nest_end(nest2);
    nlh.nest_end(nest1);

    nest1 = try!(nlh.nest_start(nfct::CTA_TUPLE_REPLY));
    nest2 = try!(nlh.nest_start(nfct::CTA_TUPLE_IP));
    try!(nlh.put_u32(nfct::CTA_IP_V4_SRC, u32::from(net::Ipv4Addr::new(2, 2, 2, 2))));
    try!(nlh.put_u32(nfct::CTA_IP_V4_DST, u32::from(net::Ipv4Addr::new(1, 1, 1, 1))));
    nlh.nest_end(nest2);

    nest2 = try!(nlh.nest_start(nfct::CTA_TUPLE_PROTO));
    try!(nlh.put_u8(nfct::CTA_PROTO_NUM, libc::IPPROTO_TCP as u8));
    try!(nlh.put_u16(nfct::CTA_PROTO_SRC_PORT, u16::to_be(1025)));
    try!(nlh.put_u16(nfct::CTA_PROTO_DST_PORT, u16::to_be(i)));
    nlh.nest_end(nest2);
    nlh.nest_end(nest1);

    nest1 = try!(nlh.nest_start(nfct::CTA_PROTOINFO));
    nest2 = try!(nlh.nest_start(nfct::CTA_PROTOINFO_TCP));
    try!(nlh.put_u8(nfct::CTA_PROTOINFO_TCP_STATE, nfct_tcp::TCP_CONNTRACK_SYN_SENT));
    nlh.nest_end(nest2);
    nlh.nest_end(nest1);

    try!(nlh.put_u32(nfct::CTA_STATUS, u32::to_be(nfct_common::IPS_CONFIRMED)));
    try!(nlh.put_u32(nfct::CTA_TIMEOUT, u32::to_be(1000)));

    Ok(())
}

fn error_cb(nlh: mnl::Nlmsg, _: &mut u8) -> mnl::CbRet {
    let err = nlh.payload::<netlink::Nlmsgerr>();
    if err.error != 0 {
        println!("message with seq {} has failed: {}",
                 nlh.nlmsg_seq, io::Error::from_raw_os_error(-err.error));
    }
    mnl::CbRet::OK
}

fn send_batch(nl: &mut mnl::Socket, b: &mut mnl::NlmsgBatch, portid: u32) {
    nl.send_batch(b)
        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));

    let rawfd = nl.as_raw_fd();
    let epoll = epoll::Epoll::create1(0)
        .unwrap_or_else(|errno| panic!("epoll_create1: {}", errno));
    let event = epoll::Event::with_fd(libc::EPOLLIN as u32, rawfd);
    epoll.ctl(libc::EPOLL_CTL_ADD, rawfd, event)
        .unwrap_or_else(|errno| panic!("epoll_ctl: {}", errno));

    let mut events: [epoll::Event; 1] = unsafe { zeroed() };
    let mut rcv_buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    let ctl_cbs = [None,
                   None,		// NLMSG_NOOP
                   Some(error_cb as mnl::Cb<u8>),];	// NLMSG_ERROR
    loop {
        let nevents = epoll.wait(&mut events[..], 0)
            .unwrap_or_else(|errno| panic!("epoll_wait: {}", errno));
        if nevents == 0 { return; }

        let nrecv = nl.recvfrom(&mut rcv_buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        let rc = mnl::cb_run2(&rcv_buf[0..nrecv], 0, portid,
                              None, &mut 0, &ctl_cbs[..])
            .unwrap_or_else(|errno| panic!("mnl_cb_run2: {}", errno));
        if rc == mnl::CbRet::STOP {
            return;
        }
    }
}

fn main() {
    let nl = mnl::Socket::open(netlink::Family::NETFILTER)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut snd_buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    let mut b = mnl::NlmsgBatch::new(&mut snd_buf)
        .unwrap_or_else(|errno| panic!("mnl_nlmsg_batch_start: {}", errno));

    let seq = time::now().to_timespec().sec as u32;
    let mut sport = 1024u32;
    'sports: loop {
        for mut nlh in &mut b {
            if let Err(_) = put_msg(&mut nlh, sport as u16, seq + sport - 1024) {
                break;
            }
            sport += 1;
            if sport >= 65535 { break 'sports; }
        }
        send_batch(nl, b, portid);
        b.reset();
    }

    if !b.is_empty() {
        b.cap();
        send_batch(nl, b, portid);
    }

    let _ = nl.close();
}

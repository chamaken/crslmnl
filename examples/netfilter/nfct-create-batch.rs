use std::io;
use std::net;
use std::time::Duration;
use std::os::unix::io::AsRawFd;

extern crate libc;
extern crate time;
extern crate mio;
extern crate crslmnl as mnl;

use mio::{ Ready, Poll, PollOpt, Token };

use mnl::linux::netlink as netlink;
use mnl::linux::netfilter::nfnetlink as nfnl;
use mnl::linux::netfilter::nfnetlink_conntrack as nfct;
use mnl::linux::netfilter::nf_conntrack_common as nfct_common;
use mnl::linux::netfilter::nf_conntrack_tcp as nfct_tcp;

mod timerfd;

fn put_msg(nlh: &mut mnl::Nlmsg, i: u16, seq: u32) {
    nlh.put_header().unwrap();
    *nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_CTNETLINK << 8) | nfct::IPCTNL_MSG_CT_NEW;
    *nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_CREATE
        | netlink::NLM_F_EXCL | netlink::NLM_F_ACK;
    *nlh.nlmsg_seq = seq;

    let nfh = nlh.put_sized_header::<nfnl::Nfgenmsg>().unwrap();
    nfh.nfgen_family = libc::AF_INET as u8;
    nfh.version = nfnl::NFNETLINK_V0;
    nfh.res_id = 0;

    let mut nest1 = nlh.nest_start(nfct::CTA_TUPLE_ORIG).unwrap();
    let mut nest2 = nlh.nest_start(nfct::CTA_TUPLE_IP).unwrap();
    nlh.put_u32(nfct::CTA_IP_V4_SRC, u32::from(net::Ipv4Addr::new(1, 1, 1, 1))).unwrap();
    nlh.put_u32(nfct::CTA_IP_V4_DST, u32::from(net::Ipv4Addr::new(2, 2, 2, 2))).unwrap();
    nlh.nest_end(nest2);

    nest2 = nlh.nest_start(nfct::CTA_TUPLE_PROTO).unwrap();
    nlh.put_u8(nfct::CTA_PROTO_NUM, libc::IPPROTO_TCP as u8).unwrap();
    nlh.put_u16(nfct::CTA_PROTO_SRC_PORT, u16::to_be(i)).unwrap();
    nlh.put_u16(nfct::CTA_PROTO_DST_PORT, u16::to_be(1025)).unwrap();
    nlh.nest_end(nest2);
    nlh.nest_end(nest1);

    nest1 = nlh.nest_start(nfct::CTA_TUPLE_REPLY).unwrap();
    nest2 = nlh.nest_start(nfct::CTA_TUPLE_IP).unwrap();
    nlh.put_u32(nfct::CTA_IP_V4_SRC, u32::from(net::Ipv4Addr::new(2, 2, 2, 2))).unwrap();
    nlh.put_u32(nfct::CTA_IP_V4_DST, u32::from(net::Ipv4Addr::new(1, 1, 1, 1))).unwrap();
    nlh.nest_end(nest2);

    nest2 = nlh.nest_start(nfct::CTA_TUPLE_PROTO).unwrap();
    nlh.put_u8(nfct::CTA_PROTO_NUM, libc::IPPROTO_TCP as u8).unwrap();
    nlh.put_u16(nfct::CTA_PROTO_SRC_PORT, u16::to_be(1025)).unwrap();
    nlh.put_u16(nfct::CTA_PROTO_DST_PORT, u16::to_be(i)).unwrap();
    nlh.nest_end(nest2);
    nlh.nest_end(nest1);

    nest1 = nlh.nest_start(nfct::CTA_PROTOINFO).unwrap();
    nest2 = nlh.nest_start(nfct::CTA_PROTOINFO_TCP).unwrap();
    nlh.put_u8(nfct::CTA_PROTOINFO_TCP_STATE, nfct_tcp::TCP_CONNTRACK_SYN_SENT).unwrap();
    nlh.nest_end(nest2);
    nlh.nest_end(nest1);

    nlh.put_u32(nfct::CTA_STATUS, u32::to_be(nfct_common::IPS_CONFIRMED)).unwrap();
    nlh.put_u32(nfct::CTA_TIMEOUT, u32::to_be(1000)).unwrap();
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

    let poll = Poll::new().unwrap();
    let timer = timerfd::Timerfd::create(libc::CLOCK_MONOTONIC, 0).unwrap();
    poll.register(&timer, Token(0),
                  Ready::readable(), PollOpt::edge()).unwrap();

    let rawfd = nl.as_raw_fd();
    let listener = mio::unix::EventedFd(&rawfd);
    poll.register(&listener, Token(rawfd as usize),
                  Ready::readable(), PollOpt::level()).unwrap();

    let mut events = mio::Events::with_capacity(256);
    let mut rcv_buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    let ctl_cbs = [None,
                   None,		// NLMSG_NOOP
                   Some(error_cb as mnl::Cb<u8>),];	// NLMSG_ERROR
    loop {
        timer.settime(
            0,
            &timerfd::Itimerspec {
                it_interval: Duration::new(0, 0),
                it_value: Duration::new(0, 1),
            }).unwrap();
        poll.poll(&mut events, None).unwrap();

        // handle only the first event - for event in events.iter() {
        match events.get(0) {
            Some(event) => {
                if event.token() == Token(0) {
                    return;
                }
            },
            None => continue, // this happened.
        }

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

    // The buffer that we use to batch messages is MNL_SOCKET_BUFFER_SIZE
    // multiplied by 2 bytes long, but we limit the batch to half of it
    // since the last message that does not fit the batch goes over the
    // upper boundary, if you break this rule, expect memory corruptions.
    let mut snd_buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE() * 2];
    let b = mnl::NlmsgBatch::start(&mut snd_buf, mnl::SOCKET_BUFFER_SIZE())
        .unwrap_or_else(|errno| panic!("mnl_nlmsg_batch_start: {}", errno));

    let seq = time::now().to_timespec().sec as u32;
    for i in 1024u16..65535 {
        put_msg(&mut b.current_nlmsg().unwrap(), i, seq + i as u32 - 1024);
	// is there room for more messages in this batch?
	// if so, continue.
        if b.proceed_next() {
            continue;
        }
        send_batch(nl, b, portid);
	// this moves the last message that did not fit into the
	// batch to the head of it.
        b.reset();
    }

    // check if there is any message in the batch not sent yet.
    if !b.is_empty() {
        send_batch(nl, b, portid);
    }

    let _ = nl.close();
}

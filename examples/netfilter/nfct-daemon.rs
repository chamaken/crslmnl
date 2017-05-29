use std::env;
use std::io;
use std::io::Write;
use std::time::Duration;
use std::os::unix::io::AsRawFd;
use std::mem::{ size_of, transmute };
use std::net::{ IpAddr, Ipv4Addr, Ipv6Addr };
use std::collections::HashMap;
use std::os::unix::io::FromRawFd;

extern crate libc;
extern crate mio;
extern crate crslmnl as mnl;

use libc::{ c_int, c_void, socklen_t };
use mnl::linux::netlink;
use mnl::linux::netfilter::nfnetlink as nfnl;
use mnl::linux::netfilter::nfnetlink_conntrack as nfct;

mod timerfd;


macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

#[derive(Debug)]
struct Nstats {
    pkts: u64,
    bytes: u64,
}

fn parse_counters_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(nfct::CTA_COUNTERS_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if (n == nfct::CTA_COUNTERS_PACKETS ||
              n == nfct::CTA_COUNTERS_BYTES) => {
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

fn parse_counters(nest: &mnl::Attr, ns: &mut Nstats) {
    let mut tb: [Option<&mnl::Attr>; nfct::CTA_COUNTERS_MAX as usize + 1]
        = [None; nfct::CTA_COUNTERS_MAX as usize + 1];

    let _ = nest.parse_nested(parse_counters_cb, &mut tb);
    tb[nfct::CTA_COUNTERS_PACKETS as usize]
        .map(|attr| ns.pkts += u64::from_be(attr.u64()));
    tb[nfct::CTA_COUNTERS_BYTES as usize]
        .map(|attr| ns.bytes += u64::from_be(attr.u64()));
}

fn parse_ip_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(nfct::CTA_IP_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if (n == nfct::CTA_IP_V4_SRC ||
              n == nfct::CTA_IP_V4_DST) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if (n == nfct::CTA_IP_V6_SRC ||
              n == nfct::CTA_IP_V6_DST) => {
            if let Err(errno) = attr.validate2(mnl::AttrDataType::BINARY,
                                               size_of::<libc::in6_addr>()) {
                println_stderr!("mnl_attr_validate2 - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        _ => {},
    }
    tb[atype as usize] = Some(attr);
    mnl::CbRet::OK
}

fn parse_ip(nest: &mnl::Attr, addr: &mut IpAddr) {
    let mut tb: [Option<&mnl::Attr>; nfct::CTA_IP_MAX as usize + 1]
        = [None; nfct::CTA_IP_MAX as usize + 1];

    let _ = nest.parse_nested(parse_ip_cb, &mut tb);
    tb[nfct::CTA_IP_V4_SRC as usize]
        .map(|attr| {
            let r = unsafe { transmute::<libc::in_addr, [u8; 4]>(*attr.payload::<libc::in_addr>()) };
            *addr = IpAddr::V4(Ipv4Addr::new(r[0], r[1], r[2], r[3]));
        });
    tb[nfct::CTA_IP_V6_SRC as usize]
        .map(|attr| {
            let r = unsafe { transmute::<libc::in6_addr, [u16; 8]>(*attr.payload::<libc::in6_addr>()) };
            *addr = IpAddr::V6(Ipv6Addr::new(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]));
        });
}

fn parse_tuple_cb<'a>(attr: &'a mnl::Attr, tb: &mut[Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(nfct::CTA_TUPLE_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if n == nfct::CTA_TUPLE_IP => {
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

fn parse_tuple(nest: &mnl::Attr, addr: &mut IpAddr) {
    let mut tb: [Option<&mnl::Attr>; nfct::CTA_TUPLE_MAX as usize + 1]
        = [None; nfct::CTA_TUPLE_MAX as usize + 1];

    let _ = nest.parse_nested(parse_tuple_cb, &mut tb);
    tb[nfct::CTA_TUPLE_IP as usize]
        .map(|attr| parse_ip(attr, addr));
}

fn data_attr_cb<'a>(attr: &'a mnl::Attr, tb: &mut[Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(nfct::CTA_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if (n == nfct::CTA_TUPLE_ORIG ||
              n == nfct::CTA_COUNTERS_ORIG ||
              n == nfct::CTA_COUNTERS_REPLY) => {
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

fn data_cb(nlh: mnl::Nlmsg, hmap: &mut HashMap<IpAddr, Box<Nstats>>) -> mnl::CbRet {
    let mut tb: [Option<&mnl::Attr>; nfct::CTA_MAX as usize + 1]
        = [None; nfct::CTA_MAX as usize + 1];
    // let nfg = nlh.payload::<nfnl::Nfgenmsg>();

    let _ = nlh.parse(size_of::<nfnl::Nfgenmsg>(), data_attr_cb, &mut tb);
    let mut addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)); // XXX: no default?
    let mut ns = Box::new(Nstats { pkts: 0, bytes: 0 });

    tb[nfct::CTA_TUPLE_ORIG as usize]
        .map(|attr| parse_tuple(attr, &mut addr));
    tb[nfct::CTA_COUNTERS_ORIG as usize]
        .map(|attr| parse_counters(attr, &mut *ns));
    tb[nfct::CTA_COUNTERS_ORIG as usize]
        .map(|attr| parse_counters(attr, &mut *ns));

    if let Some(cur) = hmap.get_mut(&addr) {
        cur.pkts += ns.pkts;
        cur.bytes += ns.pkts;
        return mnl::CbRet::OK;
    }

    hmap.insert(addr, ns);
    mnl::CbRet::OK
}

fn handle(nl: &mut mnl::Socket, hmap: &mut HashMap<IpAddr, Box<Nstats>>) -> io::Result<mnl::CbRet> {
    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    match nl.recvfrom(&mut buf) {
        Ok(nrecv) =>
            return mnl::cb_run(&buf[0..nrecv], 0, 0, Some(data_cb), hmap),
        Err(errno) => {
            if let Some(raw_os_err) = errno.raw_os_error() {
                if raw_os_err == libc::ENOBUFS {
                    println!("The daemon has hit ENOBUFS, you can \
			     increase the size of your receiver \
			     buffer to mitigate this or enable \
			     reliable delivery.");
                } else {
                    println!("mnl_socket_recvfrom: {}", errno);
                }
            }
            return Err(errno);
        },
    }
}

////////

pub const SO_RECVBUFFORCE: c_int = 33;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        panic!("\nUsage: {} <poll-secs>", args[0]);
    }
    let secs = args[1].parse::<u32>().unwrap();
    println!("Polling every {} seconds from kernel...", secs);

    // Set high priority for this process, less chances to overrun
    // the netlink receiver buffer since the scheduler gives this process
    // more chances to run.
    unsafe { libc::nice(-20); };

    let nl = mnl::Socket::open(netlink::Family::NETFILTER)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(nfct::NF_NETLINK_CONNTRACK_DESTROY, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    unsafe {
	// Set netlink receiver buffer to 16 MBytes, to avoid packet drops
        let buffersize: c_int = 1 << 22;
        libc::setsockopt(nl.as_raw_fd(), libc::SOL_SOCKET, SO_RECVBUFFORCE,
                         &buffersize as *const _ as *const c_void, size_of::<socklen_t>() as u32);
    }
    // The two tweaks below enable reliable event delivery, packets may
    // be dropped if the netlink receiver buffer overruns. This happens ...
    //
    // a) if the kernel spams this user-space process until the receiver
    //    is filled.
    //
    // or:
    //
    // b) if the user-space process does not pull messages from the
    //    receiver buffer so often.
    let _ = nl.setsockopt::<i32>(netlink::NETLINK_BROADCAST_ERROR, 1);
    let _ = nl.setsockopt::<i32>(netlink::NETLINK_NO_ENOBUFS, 1);

    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
    // Counters are atomically zeroed in each dump
    *nlh.nlmsg_type = (nfnl::NFNL_SUBSYS_CTNETLINK << 8) | nfct::IPCTNL_MSG_CT_GET_CTRZERO;
    *nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_DUMP;

    let nfh = nlh.put_sized_header::<nfnl::Nfgenmsg>();
    nfh.nfgen_family = libc::AF_INET as u8;
    nfh.version = nfnl::NFNETLINK_V0;
    nfh.res_id = 0;

    // Filter by mark: We only want to dump entries whose mark is zero
    nlh.put_u32(nfct::CTA_MARK, 0u32.to_be());
    nlh.put_u32(nfct::CTA_MARK_MASK, 0xffffffffu32.to_be());

    let mut hmap = HashMap::<IpAddr, Box<Nstats>>::new();

    // mio initializations
    let token = mio::Token(nl.as_raw_fd() as usize);
    let listener = unsafe { mio::net::UdpSocket::from_raw_fd(nl.as_raw_fd()) };
    let timer = timerfd::Timerfd::create(libc::CLOCK_MONOTONIC, 0).unwrap();
    timer.settime(
        0,
        &timerfd::Itimerspec {
            it_interval: Duration::new(secs as u64, 0),
            it_value: Duration::new(0, 1),
        }).unwrap();

    // Create an poll instance
    let poll = mio::Poll::new().unwrap();
    // Start listening for incoming connections
    poll.register(&listener, token, mio::Ready::readable(),
                  mio::PollOpt::edge()).unwrap();
    poll.register(&timer, mio::Token(0), mio::Ready::readable(),
                  mio::PollOpt::edge()).unwrap();
    // Create storage for events
    let mut events = mio::Events::with_capacity(256);
    loop {
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match usize::from(event.token()) {
                0 => { // timer
                    timer.read().unwrap(); // just consume
                    nl.send_nlmsg(&nlh)
                        .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
                    for (addr, nstats) in hmap.iter() {
                        print!("src={:?} ", addr);
                        println!("counters {} {}", nstats.pkts, nstats.bytes);
                    }
                },
                _ => {
                    let _ = handle(nl, &mut hmap).unwrap();
                },
            }
        }
    }
}

use std::env;
use std::mem::size_of;

extern crate time;
extern crate crslmnl as mnl;

use mnl::linux::netlink as netlink;
use mnl::linux::rtnetlink;
use mnl::linux::if_link;
use mnl::linux::ifh;

enum StdoutRawFd { Dummy, }

impl std::os::unix::io::AsRawFd for StdoutRawFd {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        1
    }
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        panic!("Usage: {} [ifname] [up|down]", args[0]);
    }

    let mut change: u32 = 0;
    let mut flags: u32 = 0;
    // if args[2].eq_ignore_ascii_case("up")
    match args[2].to_lowercase().as_ref() {
        "up" => {
            change |= ifh::IFF_UP;
            flags |= ifh::IFF_UP;
        },
        "down" => {
            change |= ifh::IFF_UP;
            flags &= !ifh::IFF_UP;
        },
        _ => panic!("{} is not `up' nor `down'", args[2]),
    }

    let nl = mnl::Socket::open(netlink::Family::ROUTE)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let seq = time::now().to_timespec().sec as u32;
    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    {
        let nlh = mnl::Nlmsg::put_header(&mut buf);
        nlh.nlmsg_type = rtnetlink::RTM_NEWLINK;
        nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_ACK;
        nlh.nlmsg_seq = seq;
        let ifm = nlh.put_sized_header::<rtnetlink::Ifinfomsg>();
        ifm.ifi_family = 0; // no libc::AF_UNSPEC;
        ifm.ifi_change = change;
        ifm.ifi_flags = flags;

        nlh.put_str(if_link::IFLA_IFNAME, &args[1]);

        let my_stdout = StdoutRawFd::Dummy;
        nlh.fprintf(&my_stdout, size_of::<rtnetlink::Ifinfomsg>());

        nl.send_nlmsg(nlh)
            .unwrap_or_else(|errno| panic!("mnl_socket_sendto: {}", errno));
    }

    {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        mnl::cb_run::<u8>(&buf[0..nrecv], seq, portid, None, &mut 0)
            .unwrap_or_else(|errno| panic!("mnl_cb_run: {}", errno));
    }

    let _ = nl.close();
}

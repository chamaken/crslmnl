use std::env;

extern crate libc;
extern crate crslmnl as mnl;

use mnl::linux::netlink as netlink;


fn data_cb(nlh: mnl::Nlmsg, group: &mut libc::c_int) -> mnl::CbRet {
    println!("received event type={} from genetlink group {}",
             nlh.nlmsg_type, *group);
    return mnl::CbRet::OK;
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        panic!("{} [group]", args[0]);
    }
    let mut group: libc::c_int = args[1].trim().parse().expect("group number required");

    let nl = mnl::Socket::open(netlink::Family::GENERIC)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    nl.setsockopt(netlink::NETLINK_ADD_MEMBERSHIP, group)
        .unwrap_or_else(|errno| panic!("mnl_socket_setsockopt: {}", errno));

    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        if mnl::cb_run(&buf[0..nrecv], 0, 0, Some(data_cb), &mut group)
            .unwrap_or_else(|errno| panic!("mnl_cb_run: {}", errno))
            == mnl::CbRet::STOP {
            break;
        }
    }
    let _ = nl.close();
}

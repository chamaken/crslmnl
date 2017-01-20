extern crate libc;
extern crate crslmnl as mnl;

use mnl::linux::netlink as netlink;


fn main() {
    let nl = mnl::Socket::open(netlink::Family::KOBJECT_UEVENT)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));

    // There is one single group in kobject over netlink
    nl.bind(1 << 0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));

    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    loop {
        let nrecv = nl.recvfrom(&mut buf)
            .unwrap_or_else(|errno| panic!("mnl_socket_recvfrom: {}", errno));
        if nrecv == 0 {
            break;
        }
	// kobject uses a string based protocol, with no initial
	// netlink header.
        for i in 0..nrecv {
            print!("{}", buf[i] as char);
        }
        println!("");
    }

    let _ = nl.close();
}

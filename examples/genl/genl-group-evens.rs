use std::env;
use std::io::Write;
use std::process::exit;

extern crate libc;
extern crate crslmnl as mnl;

use mnl::linux::netlink as netlink;


macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

fn data_cb(nlh: &mnl::Nlmsg, group: &mut libc::c_int) -> mnl::CbRet {
    println!("received event type={} from genetlink group {}",
             nlh.nlmsg_type, *group);
    return mnl::CbRet::OK;
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("{} [group]", args[0]);
        exit(libc::EXIT_FAILURE);
    }
    let mut group: libc::c_int = args[1].trim().parse().expect("group number required");

    let nl: &mut mnl::Socket;
    match mnl::Socket::open(netlink::Family::GENERIC) {
        Ok(sock) => nl = sock,
        Err(errno) => {
            println_stderr!("mnl_socket_open: {}", errno);
            exit(libc::EXIT_FAILURE);
        },
    }

    if let Err(errno) = nl.bind(0, mnl::SOCKET_AUTOPID) {
        println_stderr!("mnl_socket_bind: {}", errno);
        exit(libc::EXIT_FAILURE);
    }

    if let Err(errno) = nl.setsockopt(netlink::NETLINK_ADD_MEMBERSHIP, group) {
        println_stderr!("mnl_socket_setsockopt: {}", errno);
        exit(libc::EXIT_FAILURE);
    }

    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    let mut nrecv: usize;
    loop {
        match nl.recvfrom(&mut buf) {
            Err(errno) => {
                println_stderr!("mnl_socket_recvfrom: {}", errno);
                exit(libc::EXIT_FAILURE);
            },
            Ok(n) => nrecv = n,
        }

        match mnl::cb_run(&buf[0..nrecv], 0, 0, data_cb, &mut group) {
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

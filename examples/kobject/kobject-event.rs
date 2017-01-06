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

fn main() {

    let nl: &mut mnl::Socket;
    match mnl::Socket::open(netlink::Family::KOBJECT_UEVENT) {
        Ok(sock) => nl = sock,
        Err(errno) => {
            println_stderr!("mnl_socket_open: {}", errno);
            exit(libc::EXIT_FAILURE);
        },
    }

    // There is one single group in kobject over netlink
    if let Err(errno) = nl.bind(1 << 0, mnl::SOCKET_AUTOPID) {
        println_stderr!("mnl_socket_bind: {}", errno);
        exit(libc::EXIT_FAILURE);
    }

    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    loop {
        match nl.recvfrom(&mut buf) {
            Err(errno) => {
                println_stderr!("mnl_socket_recvfrom: {}", errno);
                exit(libc::EXIT_FAILURE);
            },
            Ok(nrecv) => {
                if nrecv == 0 {
                    break;
                }
		// kobject uses a string based protocol, with no initial
		// netlink header.
                for i in 0..nrecv {
                    print!("{}", buf[i] as char);
                }
                println!("");
            },
        }
    }

    let _ = nl.close();
}

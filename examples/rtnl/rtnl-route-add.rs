use std::env;
use std::mem::{ size_of, transmute };
use std::ffi::CString;
use std::io;
use std::net::{ IpAddr, Ipv4Addr, Ipv6Addr };

extern crate libc;
extern crate time;
extern crate crslmnl as mnl;
use libc::{ c_int, c_void, sockaddr_storage, if_nametoindex, AF_INET, AF_INET6, in6_addr };

use mnl::linux::netlink;
use mnl::linux::rtnetlink;

extern {
    // int inet_pton(int af, const char *src, void *dst);
    fn inet_pton(af: c_int, src: *const c_void, dst: *mut c_void) -> c_int;
}

// really?
fn _inet_pton(af: c_int, src: &str) -> io::Result<IpAddr> {
    let mut s = vec![0u8; size_of::<sockaddr_storage>()];
    unsafe {
        {
            let t = s.as_mut_ptr() as *mut c_void;
            if inet_pton(af, src as *const _ as *const c_void, t) != 1 {
                return Err(io::Error::last_os_error());
            };
        }
        match af {
            AF_INET => {
                let t = s.as_ptr() as *const u8;
                return Ok(IpAddr::V4(Ipv4Addr::new(
                    *t.offset(0), *t.offset(1), *t.offset(2), *t.offset(3))));
            },
            AF_INET6 => {
                let t = s.as_ptr() as *const u16;
                return Ok(IpAddr::V6(Ipv6Addr::new(
                    *t.offset(0), *t.offset(1), *t.offset(2), *t.offset(3),
                    *t.offset(4), *t.offset(5), *t.offset(6), *t.offset(7))));
            },
            _ => unreachable!(),
        }
    }
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() <= 3 {
	panic!("
Usage: {} iface destination cidr [gateway]
Example: {} eth0 10.0.1.12 32 10.0.1.11
         {} eth0 ffff::10.0.1.12 128 fdff::1\n",
               args[0], args[0], args[0]);
    }

    let iface = unsafe {
        let ptr = CString::new(args[1].clone()).unwrap(); // clone?
        if_nametoindex(ptr.as_ptr())
    };
    if iface == 0 {
        panic!("if_nametoindex: {}", io::Error::last_os_error());
    }

    let family;
    let dst;
    match _inet_pton(AF_INET, &args[2]) {
        Ok(d) => {
            family = AF_INET;
            dst = d;
        },
        Err(_) => {
            match _inet_pton(AF_INET6, &args[2]) {
                Ok(d) => {
                    family = AF_INET6;
                    dst = d;
                },
                Err(errno) => panic!("inet_pton: {}", errno),
            };
        },
    }

    let prefix = args[3].parse::<u32>().unwrap();

    let gw = if args.len() == 5 {
        Some(_inet_pton(family, &args[4])
             .unwrap_or_else(|errno| panic!("inet_pton: {}", errno)))
    } else {
        None
    };

    let nl = mnl::Socket::open(netlink::Family::ROUTE)
        .unwrap_or_else(|errno| panic!("mnl_socket_open: {}", errno));
    nl.bind(0, mnl::SOCKET_AUTOPID)
        .unwrap_or_else(|errno| panic!("mnl_socket_bind: {}", errno));
    let portid = nl.portid();

    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    let seq = time::now().to_timespec().sec as u32;
    {
        let mut nlh = mnl::Nlmsg::new(&mut buf).unwrap();
        *nlh.nlmsg_type = rtnetlink::RTM_NEWROUTE;
        *nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_CREATE | netlink::NLM_F_ACK;
        *nlh.nlmsg_seq = seq;

        let rtm = nlh.put_sized_header::<rtnetlink::Rtmsg>();
        rtm.rtm_family = family as u8;
        rtm.rtm_dst_len = prefix as u8;
        rtm.rtm_src_len = 0;
        rtm.rtm_tos = 0;
        rtm.rtm_protocol = rtnetlink::RTPROT_STATIC;
        rtm.rtm_table = rtnetlink::RT_TABLE_MAIN as u8;
        rtm.rtm_type = rtnetlink::RTN_UNICAST;
        // is there any gateway?
        rtm.rtm_scope = if args.len() == 4 {
            rtnetlink::RT_SCOPE_LINK
        } else {
            rtnetlink::RT_SCOPE_UNIVERSE
        };
        rtm.rtm_flags = 0;

        match dst {
            IpAddr::V4(addr) =>
                nlh.put_u32(rtnetlink::RTA_DST,
                            unsafe { transmute::<[u8; 4], u32>(addr.octets()) }),
            IpAddr::V6(addr) =>
                nlh.put(rtnetlink::RTA_DST,
                        &unsafe { transmute::<[u16; 8], in6_addr>(addr.segments()) }),
        }
        nlh.put_u32(rtnetlink::RTA_OIF, iface);
        if let Some(nh) = gw {
            match nh {
                IpAddr::V4(addr) =>
                    nlh.put_u32(rtnetlink::RTA_GATEWAY,
                                unsafe { transmute::<[u8; 4], u32>(addr.octets()) }),
                IpAddr::V6(addr) =>
                    nlh.put(rtnetlink::RTA_GATEWAY,
                            &unsafe { transmute::<[u16; 8], in6_addr>(addr.segments()) }),
            }
        }
        nl.send_nlmsg(&nlh)
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

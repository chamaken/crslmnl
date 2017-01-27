use std::net::{ IpAddr, Ipv4Addr, Ipv6Addr };
use std::io;

extern crate libc;
use libc::{ c_int, c_void, AF_INET, AF_INET6 };


extern {
    // int inet_pton(int af, const char *src, void *dst);
    fn inet_pton(af: c_int, src: *const c_void, dst: *mut c_void) -> c_int;
}

fn _inet_pton(af: c_int, src: &str) -> io::Result<IpAddr> {
    let mut s = vec![0u8; ::std::mem::size_of::<libc::sockaddr_storage>()];
    unsafe {
        {
            let t = s.as_mut_ptr() as *mut c_void;
            if inet_pton(af, src as *const _ as *const c_void, t) != 1 {
                return Err(io::Error::last_os_error());
            };
        }
        match af {
            libc::AF_INET => {
                let t = s.as_ptr() as *const u8;
                return Ok(IpAddr::V4(Ipv4Addr::new(
                    *t.offset(0), *t.offset(1), *t.offset(2), *t.offset(3))));
            },
            libc::AF_INET6 => {
                let t = s.as_ptr() as *const u16;
                return Ok(IpAddr::V6(Ipv6Addr::new(
                    *t.offset(0), *t.offset(1), *t.offset(2), *t.offset(3),
                    *t.offset(4), *t.offset(5), *t.offset(6), *t.offset(7))));
            },
            _ => unreachable!(),
        }
    }
}

fn loopback(family: c_int) -> Result<IpAddr, &'static str> {
    match family {
        AF_INET => return Ok(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        AF_INET6 => return Ok(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
        _ => {},
    }
    Err("invalid address family")
}

fn main() {
    let lo = loopback(AF_INET).unwrap();
    println!("lo4: {:?}", lo);

    let lo6 = _inet_pton(AF_INET6, "::1").unwrap();
    println!("lo6: {:?}", lo6);
}

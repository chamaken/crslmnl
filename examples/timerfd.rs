#![allow(dead_code)]

extern crate libc;

use std::io;
use std::time::Duration;
use std::os::unix::io::{ RawFd, AsRawFd };
use libc::{ c_int, c_void, timespec, time_t };

/*
 * libc timer implementation
 */
#[allow(non_camel_case_types)]
#[repr(C)]
struct itimerspec {
    it_interval: timespec,
    it_value: timespec,
}

#[allow(non_camel_case_types)]
pub struct Itimerspec {
    pub it_interval: Duration,
    pub it_value: Duration,
}

extern "C" {
    fn timerfd_create(clockid: c_int, flags: c_int) -> RawFd;
    fn timerfd_settime(fd: RawFd, flags: c_int,
                       new_value: *const itimerspec, old_value: *mut itimerspec) -> libc::c_int;
    fn timerfd_gettime(fd: RawFd, curr_value: *mut itimerspec) -> libc::c_int;
}


pub struct Timerfd(RawFd);

impl Timerfd {
    pub fn create(clockid: c_int, flags: c_int) -> io::Result<Self> {
        let timerfd = unsafe { timerfd_create(clockid, flags) };
        if timerfd == -1 {
            return Err(io::Error::last_os_error())
        }
        Ok(Timerfd(timerfd))
    }

    pub fn settime(&self, flags: c_int, new_value: &Itimerspec) -> io::Result<Itimerspec> {
        let new_raw = itimerspec{
            it_interval: timespec {
                tv_sec: new_value.it_interval.as_secs() as time_t,
                tv_nsec: new_value.it_interval.subsec_nanos() as i64,
            },
            it_value: timespec {
                tv_sec: new_value.it_value.as_secs() as time_t,
                tv_nsec: new_value.it_value.subsec_nanos() as i64,
            },
        };
        let mut old_raw = itimerspec { it_interval: timespec { tv_sec: 0, tv_nsec: 0 },
                                       it_value: timespec { tv_sec: 0, tv_nsec: 0 } };
        
        if unsafe { timerfd_settime(self.0, flags, &new_raw, &mut old_raw) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Itimerspec{
            it_interval: Duration::new(old_raw.it_interval.tv_sec as u64,
                                       old_raw.it_interval.tv_nsec as u32),
            it_value: Duration::new(old_raw.it_value.tv_sec as u64,
                                    old_raw.it_value.tv_nsec as u32),
        })
    }

    pub fn gettime(&self) -> io::Result<Itimerspec> {
        let mut raw = itimerspec { it_interval: timespec { tv_sec: 0, tv_nsec: 0 },
                                   it_value: timespec { tv_sec: 0, tv_nsec: 0 } };
        if unsafe { timerfd_gettime(self.0, &mut raw) } == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(Itimerspec{
            it_interval: Duration::new(raw.it_interval.tv_sec as u64,
                                       raw.it_interval.tv_nsec as u32),
            it_value: Duration::new(raw.it_value.tv_sec as u64,
                                    raw.it_value.tv_nsec as u32),
        })
    }

    pub fn read(&self) -> io::Result<u64> {
        let mut buf = 0u64;
        let nr = unsafe {
            libc::read(self.0, &mut buf as *mut _ as *mut c_void, ::std::mem::size_of::<u64>())
        };
        if nr == ::std::mem::size_of::<u64>() as isize {
            return Ok(buf);
        }
        Err(io::Error::last_os_error())
    }
}

impl Drop for Timerfd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

impl AsRawFd for Timerfd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}


/*
 * mio Evented implementation
 */
extern crate mio;

use mio::{ Ready, Poll, PollOpt, Token };
use mio::unix::EventedFd;
use mio::event::Evented;

impl Evented for Timerfd {
    fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()> {
        EventedFd(&self.0).register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()> {
        EventedFd(&self.0).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.0).deregister(poll)
    }
}

fn main() {}

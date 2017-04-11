#![allow(dead_code)]

extern crate libc;

use std::io;
use std::os::unix::io::{ RawFd, AsRawFd };
use libc::c_int;

macro_rules! cvt_cint {
    ($f:expr) => ( {
        let ret = unsafe { $f };
        if ret == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    } )
}

#[repr(C)]
#[repr(packed)]
pub struct Event {
    pub events: u32,
    data: u64,
}

impl Event {
    pub fn ptr<T>(&mut self) -> &T {
        unsafe {
            ::std::mem::transmute::<u64, &mut T>(self.data)
        }
    }

    pub fn fd(&self) -> RawFd {
        unsafe { *(&self.data as *const _ as *const RawFd) }
    }        

    pub fn u32(&self) -> u32 {
        unsafe { *(&self.data as *const _ as *const u32) }
    }

    pub fn u64(&self) -> u64 {
        self.data
    }

    pub fn with_ptr<T>(events: u32, ptr: &mut T) -> Event {
        unsafe {
            Event {
                events: events,
                data: ::std::mem::transmute::<&mut T, u64>(ptr),
            }
        }
    }

    pub fn with_fd(events: u32, fd: RawFd) -> Event {
        let mut e = Event { events: events, data: 0 };
        unsafe { *(&mut e.data as *mut _ as *mut RawFd) = fd; }
        e
    }

    pub fn with_u32(events: u32, val: u32) -> Event {
        let mut e = Event { events: events, data: 0 };
        unsafe { *(&mut e.data as *mut _ as *mut u32) = val; }
        e
    }

    pub fn with_u64(events: u32, val: u64) -> Event {
        Event { events: events, data: val, }
    }
}

pub struct Epoll(RawFd);

impl Epoll {
    pub fn create1(flags: c_int) -> io::Result<Self> {
        let epfd = unsafe { libc::epoll_create1(flags) };
        if epfd == -1 {
            return Err(io::Error::last_os_error())
        }
        Ok(Epoll(epfd))
    }

    pub fn ctl(&self, op: c_int, fd: RawFd, event: Event) -> io::Result<(i32)> {
        let mut e = libc::epoll_event {
            events: event.events,
            u64: event.data,
        };
        cvt_cint!(libc::epoll_ctl(self.0, op, fd, &mut e))
    }

    pub fn wait(&self, events: &mut [Event], timeout: isize) -> io::Result<i32> {
        cvt_cint!(libc::epoll_wait(self.0, events.as_mut_ptr() as *mut libc::epoll_event,
                                  events.len() as i32, timeout as c_int))
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

impl AsRawFd for Epoll {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

fn main() {}

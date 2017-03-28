#![allow(dead_code)]
// #![crate_type = "lib"]

// mio interface for timerfd

use std::io;
use std::os::unix::io::AsRawFd;

extern crate mio;
extern crate timerfd;

use mio::{ Ready, Poll, PollOpt, Token };
use mio::unix::EventedFd;
use mio::event::Evented;
use timerfd::{TimerFd, TimerState, SetTimeFlags};

pub struct Timer {
    io: timerfd::TimerFd,
}

impl Timer {
    pub fn new() -> io::Result<Timer> {
        match TimerFd::new() {
            Ok(fd) => Ok(Timer { io: fd }),
            Err(errno) => Err(errno),
        }
    }

    pub fn set_state(&mut self, state: TimerState, sflags: SetTimeFlags) -> TimerState {
        self.io.set_state(state, sflags)
    }

    pub fn read(&mut self) -> u64 {
        self.io.read()
    }
}

impl Evented for Timer {
    fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()> {
        EventedFd(&self.io.as_raw_fd()).register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()> {
        EventedFd(&self.io.as_raw_fd()).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.io.as_raw_fd()).deregister(poll)
    }
}

fn main() { }

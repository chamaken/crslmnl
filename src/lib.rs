#![allow(dead_code)]
// no effect? #![link(name = "mnl")]

use std::io;
use std::mem::{ size_of, size_of_val, zeroed, forget };
use std::os::unix::io::{ RawFd, AsRawFd };
use std::ffi::{ CString, CStr };
use std::fmt;

extern crate libc;
use libc::{ c_int, c_uint, c_char, c_void, size_t, ssize_t, socklen_t, pid_t, FILE, uintptr_t };

pub mod linux;
use linux::netlink;


macro_rules! cvt_isize {
    ($f:expr) => ( {
        let ret = unsafe { $f };
        if ret == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    } )
}

macro_rules! cvt_null {
    ($f:expr) => ( {
        let ret = unsafe { $f };
        if ret.is_null() {
            Err(io::Error::last_os_error())
        } else {
            unsafe { Ok(&mut(*ret)) }
        }
    } )
}

macro_rules! cvt_cbret {
    ($f:expr) => ( {
        match unsafe { $f } {
            n if n < 0 => Err(io::Error::last_os_error()),
            n if n > 0 => Ok(CbRet::OK),
            _ => Ok(CbRet::STOP),
        }
    } )
}

pub const ALIGNTO: u32	= 4;
#[allow(non_snake_case)]
pub fn ALIGN(len: u32) -> u32 {
    (len + ALIGNTO - 1) & !(ALIGNTO - 1)
}
#[allow(non_snake_case)]
pub fn NLMSG_HDRLEN() -> u32 {
    ALIGN(size_of::<netlink::Nlmsghdr>() as u32)
}

// Netlink socket API

pub const SOCKET_AUTOPID: u32 = 0;
#[allow(non_snake_case)]
pub fn SOCKET_BUFFER_SIZE() -> usize {// pub const fn ?
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size < 8192 {
        page_size as usize
    } else {
        8192
    }
}

pub enum Socket{}

#[link(name = "mnl")]
extern {
    fn mnl_socket_open(bus: c_int) -> *mut Socket;

    #[cfg(feature = "ge-1_0_4")]
    fn mnl_socket_open2(bus: c_int, flags: c_int) -> *mut Socket;
    #[cfg(feature = "ge-1_0_4")]
    fn mnl_socket_fdopen(fd: c_int) -> *mut Socket;

    fn mnl_socket_bind(nl: *mut Socket, group: c_uint, pid: pid_t) -> c_int;
    fn mnl_socket_close(nl: *mut Socket) -> c_int;
    fn mnl_socket_get_fd(nl: *const Socket) -> c_int;
    fn mnl_socket_get_portid(nl: *const Socket) -> c_uint;
    fn mnl_socket_sendto(nl: *const Socket, buf: *const c_void, siz: size_t) -> ssize_t;
    fn mnl_socket_recvfrom(nl: *const Socket, buf: *mut c_void, siz: size_t) -> ssize_t;
    fn mnl_socket_setsockopt(nl: *const Socket, t: c_int, buf: *const c_void, len: socklen_t) -> c_int;
    fn mnl_socket_getsockopt(nl: *const Socket, t: c_int, buf: *mut c_void, len: *mut socklen_t) -> c_int;
}

#[link(name = "mnl")]
extern {
    fn mnl_nlmsg_size(len: size_t) -> size_t;
    fn mnl_nlmsg_get_payload_len(nlh: *const netlink::Nlmsghdr) -> size_t;
    fn mnl_nlmsg_put_header(buf: *mut c_void) -> *mut netlink::Nlmsghdr;
    fn mnl_nlmsg_put_extra_header(nlh: *mut netlink::Nlmsghdr, size: size_t) -> *mut c_void;
    fn mnl_nlmsg_ok(nlh: *const netlink::Nlmsghdr, len: c_int) -> bool;
    fn mnl_nlmsg_next(nlh: *const netlink::Nlmsghdr, len: *mut c_int)-> *mut netlink::Nlmsghdr;
    fn mnl_nlmsg_seq_ok(nlh: *const netlink::Nlmsghdr, seq: c_uint) -> bool;
    fn mnl_nlmsg_portid_ok(nlh: *const netlink::Nlmsghdr, portid: c_uint) -> bool;
    fn mnl_nlmsg_get_payload(nlh: *const netlink::Nlmsghdr)-> *mut c_void;
    fn mnl_nlmsg_get_payload_offset(nlh: *const netlink::Nlmsghdr, offset: size_t)-> *mut c_void;
    fn mnl_nlmsg_get_payload_tail(nlh: *const netlink::Nlmsghdr) -> *mut c_void;
    fn mnl_nlmsg_fprintf(fd: *mut FILE, data: *const c_void, datalen: size_t, extra_header_size: size_t);
}

pub enum NlmsgBatch {}

#[link(name = "mnl")]
extern {
    fn mnl_nlmsg_batch_start(buf: *mut c_void, bufsiz: size_t) -> *mut NlmsgBatch;
    // fn mnl_nlmsg_batch_next(b: *mut NlmsgBatch) -> bool;
    fn mnl_nlmsg_batch_next(b: *const NlmsgBatch) -> bool;
    fn mnl_nlmsg_batch_stop(b: *mut NlmsgBatch);
    // fn mnl_nlmsg_batch_size(b: *mut NlmsgBatch) -> size_t;
    fn mnl_nlmsg_batch_size(b: *const NlmsgBatch) -> size_t;
    fn mnl_nlmsg_batch_reset(b: *mut NlmsgBatch);
    fn mnl_nlmsg_batch_head(b: *mut NlmsgBatch) -> *mut c_void;
    fn mnl_nlmsg_batch_current(b: *mut NlmsgBatch) -> *mut c_void;
    // fn mnl_nlmsg_batch_is_empty(b: *mut NlmsgBatch) -> bool;
    fn mnl_nlmsg_batch_is_empty(b: *const NlmsgBatch) -> bool;
}

extern { // arbitrary function
    fn mnl_nlmsg_batch_rest(b: *const NlmsgBatch) -> size_t;
}


// Netlink attributes API
#[link(name = "mnl")]
extern {
    fn mnl_attr_get_type(attr: *const netlink::Nlattr) -> u16;
    fn mnl_attr_get_len(attr: *const netlink::Nlattr) -> u16;
    fn mnl_attr_get_payload_len(attr: *const netlink::Nlattr) -> u16;
    fn mnl_attr_get_payload(attr: *const netlink::Nlattr) -> *mut c_void;
    fn mnl_attr_get_u8(attr: *const netlink::Nlattr) -> u8;
    fn mnl_attr_get_u16(attr: *const netlink::Nlattr) -> u16;
    fn mnl_attr_get_u32(attr: *const netlink::Nlattr) -> u32;
    fn mnl_attr_get_u64(attr: *const netlink::Nlattr) -> u64;
    fn mnl_attr_get_str(attr: *const netlink::Nlattr) -> *mut c_char;

    fn mnl_attr_put(nlh: *mut netlink::Nlmsghdr, atype: u16, len: size_t, data: *const c_void);
    fn mnl_attr_put_u8(nlh: *mut netlink::Nlmsghdr, atype: u16, data: u8);
    fn mnl_attr_put_u16(nlh: *mut netlink::Nlmsghdr, atype: u16, data: u16);
    fn mnl_attr_put_u32(nlh: *mut netlink::Nlmsghdr, atype: u16, data: u32);
    fn mnl_attr_put_u64(nlh: *mut netlink::Nlmsghdr, atype: u16, data: u64);
    fn mnl_attr_put_str(nlh: *mut netlink::Nlmsghdr, atype: u16, data: *const c_char);
    fn mnl_attr_put_strz(nlh: *mut netlink::Nlmsghdr, atype: u16, data: *const c_char);

    fn mnl_attr_put_check(nlh: *mut netlink::Nlmsghdr, buflen: size_t, atype: u16, len: size_t, data: *const c_void) -> bool;
    fn mnl_attr_put_u8_check(nlh: *mut netlink::Nlmsghdr, buflen: size_t, atype: u16, data: u8) -> bool;

    fn mnl_attr_put_u16_check(nlh: *mut netlink::Nlmsghdr, buflen: size_t, atype: u16, data: u16) -> bool;
    fn mnl_attr_put_u32_check(nlh: *mut netlink::Nlmsghdr, buflen: size_t, atype: u16, data: u32) -> bool;
    fn mnl_attr_put_u64_check(nlh: *mut netlink::Nlmsghdr, buflen: size_t, atype: u16, data: u64) -> bool;
    fn mnl_attr_put_str_check(nlh: *mut netlink::Nlmsghdr, buflen: size_t, atype: u16, data: *const c_char) -> bool;
    fn mnl_attr_put_strz_check(nlh: *mut netlink::Nlmsghdr, buflen: size_t, atype: u16, data: *const c_char) -> bool;

    fn mnl_attr_nest_start(nlh: *mut netlink::Nlmsghdr, atype: u16) -> *mut netlink::Nlattr;
    fn mnl_attr_nest_start_check(nlh: *mut netlink::Nlmsghdr, buflen: size_t, atype: u16) -> *mut netlink::Nlattr;
    fn mnl_attr_nest_end(nlh: *mut netlink::Nlmsghdr, start: *mut netlink::Nlattr);
    fn mnl_attr_nest_cancel(nlh: *mut netlink::Nlmsghdr, start: *mut netlink::Nlattr);

    fn mnl_attr_type_valid(attr: *const netlink::Nlattr, maxtype: u16) -> c_int;
}

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum AttrDataType {
    UNSPEC,
    U8,
    U16,
    U32,
    U64,
    STRING,
    FLAG,
    MSECS,
    NESTED,
    NESTED_COMPAT,
    NUL_STRING,
    BINARY,
}

#[link(name = "mnl")]
extern {
    fn mnl_attr_validate(attr: *const netlink::Nlattr, atype: u16) -> c_int;
    fn mnl_attr_validate2(attr: *const netlink::Nlattr, atype: u16, exp_len: size_t) -> c_int;

    fn mnl_attr_ok(attr: *const netlink::Nlattr, len: c_int) -> bool;
    fn mnl_attr_next(attr: *const netlink::Nlattr) -> *mut netlink::Nlattr;
}

// XXX: not implemented yet.
// #define mnl_attr_for_each_payload(payload, payload_size)

type AttrCbT = extern "C" fn(attr: *const Attr, data: *mut c_void) -> c_int;
pub type AttrCb<'a, T: ?Sized> = fn(attr: &'a Attr, data: &mut T) -> CbRet;
struct AttrCbData <'a, 'b, T: 'a + 'b + ?Sized> {
    cb: AttrCb<'a, T>,
    data: &'b mut T,
}

#[link(name = "mnl")]
extern {
    fn mnl_attr_parse(nlh: *const netlink::Nlmsghdr, offset: c_uint, cb: AttrCbT, data: *mut c_void) -> c_int;
    fn mnl_attr_parse_nested(attr: *const netlink::Nlattr, cb: AttrCbT, data: *mut c_void) -> c_int;
    fn mnl_attr_parse_payload(payload: *const c_void, payload_len: size_t, cb: AttrCbT, data: *mut c_void) -> c_int;
}

#[repr(i32)]
#[derive(PartialEq)]
pub enum CbRet {
    ERROR	= -1,
    STOP	= 0,
    OK		= 1,
}

type CbT = extern "C" fn(nlh: *const netlink::Nlmsghdr, data: *mut c_void) -> c_int;
pub type Cb<'a, T: ?Sized> = fn(nlh: Nlmsg, data: &'a mut T) -> CbRet;
struct CbData <'a, 'b: 'a, T: 'b + ?Sized> {
    cb: Option<Cb<'b, T>>,
    ctl_cbs: &'a [Option<Cb<'b, T>>],
    data: &'a mut T,
}


#[link(name = "mnl")]
extern {
    fn mnl_cb_run(buf: *const c_void, numbytes: size_t, seq: c_uint,
                  portid: c_uint, cb_data: CbT, data: *mut c_void) -> c_int;
    fn mnl_cb_run2(buf: *const c_void, numbytes: size_t, seq: c_uint,
                   portid: c_uint, cb_data: CbT, data: *mut c_void,
                   cb_ctl_array: *const CbT, cb_ctl_array_len: c_uint) -> c_int;
}

impl <'a> Socket {
    /// open a netlink socket
    ///
    /// # Arguments
    /// * `bus` the netlink socket bus ID (see NETLINK_* constants)
    ///
    /// # Return value
    /// On error, it returns errno. Otherwise, it returns a Ok() of the
    /// mnl_socket structure.
    pub fn open(bus: netlink::Family) -> io::Result<&'a mut Socket> {
        cvt_null!(mnl_socket_open(bus.c_int()))
    }

    #[cfg(feature = "ge-1_0_4")]
    /// open a netlink socket with appropriate flags
    ///
    /// This is similar to mnl_socket_open(), but allows to set flags like
    /// SOCK_CLOEXEC at socket creation time (useful for multi-threaded programs
    /// performing exec calls).
    ///
    /// # Arguments
    /// * `bus` the netlink socket bus ID (see NETLINK_* constants)
    /// * `param` flags the netlink socket flags (see SOCK_* constants in socket(2))
    ///
    /// # Return value
    /// On error, it returns errno. Otherwise, it returns a Ok() of the
    /// mnl_socket structure.
    pub fn open2(bus: netlink::Family, flags: c_int) -> io::Result<&'a mut Socket> {
        cvt_null!(mnl_socket_open2(bus.c_int(), flags))
    }

    #[cfg(feature = "ge-1_0_4")]
    /// associates a mnl_socket object with pre-existing socket.
    ///
    /// # Arguments
    /// * `fd` pre-existing socket descriptor.
    ///
    /// # Return value
    /// On error, it returns errno. Otherwise, it returns a Ok() of the
    /// mnl_socket structure. It also sets the portID if the socket fd is
    /// already bound and it is AF_NETLINK.
    ///
    /// # Note
    /// get_portid() returns 0 if this function is used with non-netlink socket.
    /// It would be better to use IntoRawFd instead of &AsRawFd, but Sized trait...
    pub fn fdopen(fd: &AsRawFd) -> io::Result<&'a mut Socket> {
        cvt_null!(mnl_socket_fdopen(fd.as_raw_fd()))
    }

    /// bind netlink socket
    ///
    /// # Arguments
    /// * `groups` the group of message you're interested in
    /// * `pid` the port ID you want to use (use zero for automatic selection)
    ///
    /// # Return value
    /// On error, this function returns errno. On success, Ok is returned. You
    /// can use MNL_SOCKET_AUTOPID which is 0 for automatic port ID selection.
    pub fn bind(&mut self, group: u32, pid: u32) -> io::Result<()> {
        try!(cvt_isize!(mnl_socket_bind(self, group as c_uint, pid as pid_t)));
        Ok(())
    }

    /// close a given netlink socket
    ///
    /// # Return value
    /// On error, this function returns errno.  On success, it returns Ok.
    ///
    /// # Note
    /// not implemented as drop trait, which means it's needed to call
    /// close() explicitly
    pub fn close(&mut self) -> io::Result<()> {
        try!(cvt_isize!(mnl_socket_close(self)));
        Ok(())
    }

    // mnl_socket_get_fd() is used as a AsRawFd trait

    /// obtain Netlink PortID from netlink socket
    ///
    /// # Return value
    /// This function returns the Netlink PortID of a given netlink socket.
    /// It's a common mistake to assume that this PortID equals the process ID
    /// which is not always true. This is the case if you open more than one
    /// socket that is binded to the same Netlink subsystem from the same
    /// process.
    pub fn portid(&self) -> u32 {
        unsafe { mnl_socket_get_portid(self) as u32 }
    }

    /// send a netlink message of a certain size
    ///
    /// # Arguments
    /// * `buf` buffer containing the netlink message to be sent
    ///
    /// # Return value
    /// On error, it returns errno. Otherwise, it returns Ok of the number of
    /// bytes sent.
    pub fn sendto(&self, buf: &[u8]) -> io::Result<usize> {
        let n = try!(cvt_isize!(
            mnl_socket_sendto(self, buf.as_ptr() as *const c_void, buf.len() as size_t)));
        Ok(n as usize)
    }

    /// send a netlink message
    ///
    /// # Arguments
    /// * `nlh` the netlink message to be sent
    ///
    /// # Return value
    /// On error, it returns errno. Otherwise, it returns Ok of the number of
    /// bytes sent.
    pub fn send_nlmsg(&self, nlh: &Nlmsg) -> io::Result<usize> {
        let n = try!(cvt_isize!(
            mnl_socket_sendto(self, nlh.buf.as_ptr() as *const _ as *const c_void,
                              *nlh.nlmsg_len as size_t)));
        Ok(n as usize)
    }

    /// send a netlink batch
    ///
    /// # Arguments
    /// * `b` the bunch of netlink message to be sent
    ///
    /// # Return value
    /// On error, it returns errno. Otherwise, it returns Ok of the number of
    /// bytes sent.
    pub fn send_batch(&self, b: &mut NlmsgBatch) -> io::Result<usize> {
        let n = try!(cvt_isize!(
            mnl_socket_sendto(self, b.head::<c_void>(), b.size() as size_t)));
        Ok(n as usize)
    }

    /// receive a netlink message
    ///
    /// # Arguments
    /// * `buf` buffer that you want to use to store the netlink message
    ///
    /// # Return value
    /// On error, function returns errno.
    pub fn recvfrom(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = try!(cvt_isize!(
            mnl_socket_recvfrom(self, buf.as_mut_ptr() as *mut c_void, buf.len() as size_t)));
        Ok(n as usize)
    }

    /// set Netlink socket option
    ///
    /// # Arguments
    /// * `T` type of Netlink socket options
    /// * `val` the value about this option
    ///
    /// This function allows you to set some Netlink socket option. As of writing
    /// this (see linux/netlink.h), the existing options are:
    ///
    ///	- #define NETLINK_ADD_MEMBERSHIP  1
    ///	- #define NETLINK_DROP_MEMBERSHIP 2
    ///	- #define NETLINK_PKTINFO         3
    ///	- #define NETLINK_BROADCAST_ERROR 4
    ///	- #define NETLINK_NO_ENOBUFS      5
    ///
    /// In the early days, Netlink only supported 32 groups expressed in a
    /// 32-bits mask. However, since 2.6.14, Netlink may have up to 2^32 multicast
    /// groups but you have to use setsockopt() with NETLINK_ADD_MEMBERSHIP to
    /// join a given multicast group. This function internally calls setsockopt()
    /// to join a given netlink multicast group. You can still use mnl_bind()
    /// and the 32-bit mask to join a set of Netlink multicast groups.
    ///
    /// On error, this function returns errno.
    pub fn setsockopt<T>(&self, optname: c_int, val: T) -> io::Result<()> {
        let optval = &val as *const T as *const c_void;
        try!(cvt_isize!(
            mnl_socket_setsockopt(self, optname, optval,
                                  size_of::<T>() as socklen_t)));
        Ok(())
    }

    /// get a Netlink socket option
    ///
    /// # Arguments
    /// * `T` type of Netlink socket options
    /// * `optname` name of Netlink socket options
    ///
    /// # Return value
    /// On error, this function returns errno.
    pub fn getsockopt<T: Copy>(&self, optname: c_int) -> io::Result<T> {
        let mut slot: T = unsafe { zeroed() };
        let mut len = size_of::<T>() as socklen_t;
        try!(cvt_isize!(
            mnl_socket_getsockopt(self, optname,
                                  &mut slot as *mut _ as *mut _,
                                  &mut len)));
        assert_eq!(len as usize, size_of::<T>());
        Ok(slot)
    }
}

// TODO: impl FromRawFd, IntoRawFd
impl AsRawFd for Socket {
    /// obtain file descriptor from netlink socket
    ///
    /// # Return value
    /// This function returns the file descriptor of a given netlink socket.
    fn as_raw_fd(&self) -> RawFd {
        unsafe { mnl_socket_get_fd(self) }
    }
}

pub struct Nlmsg <'a> {
    buf: &'a mut [u8],
    remaining: isize,
    pub nlmsg_len: &'a mut u32,
    pub nlmsg_type: &'a mut u16,
    pub nlmsg_flags: &'a mut u16,
    pub nlmsg_seq: &'a mut u32,
    pub nlmsg_pid: &'a mut u32,
}

impl <'a> Nlmsg <'a> {
    pub fn buflen(&self) -> usize {
        self.buf.len()
    }

    fn as_raw_ref(&self) -> &netlink::Nlmsghdr {
        unsafe { (self.buf.as_ptr() as *const netlink::Nlmsghdr).as_ref().unwrap() }
    }

    fn as_raw_mut(&mut self) -> &mut netlink::Nlmsghdr {
        unsafe { (self.buf.as_mut_ptr() as *mut netlink::Nlmsghdr).as_mut().unwrap() }
    }


    /// calculate the size of Netlink message (without alignment)
    ///
    /// # Arguments
    /// * `len` length of the Netlink payload
    ///
    /// # Return value
    /// This function returns the size of a netlink message (header plus payload)
    /// without alignment.
    pub fn size(len: usize) -> usize {
        unsafe { mnl_nlmsg_size(len as size_t) }
    }

    /// get the length of the Netlink payload
    ///
    /// # Return value
    /// This function returns the Length of the netlink payload, ie. the length
    /// of the full message minus the size of the Netlink header.
    pub fn payload_len(&self) -> usize {
        unsafe { mnl_nlmsg_get_payload_len(self.as_raw_ref()) }
    }

    pub fn from_bytes(buf: &'a mut [u8]) -> Self {
        // XXX: check buf len > sizeof(Nlmsg)
        let buflen = buf.len() as isize;
        let p = buf.as_mut_ptr();
        let nlh = Nlmsg {
            buf:	 buf,
            remaining:	 buflen,
            nlmsg_len:   unsafe { (p as *mut u32).offset(0).as_mut().unwrap() },
            nlmsg_type:  unsafe { (p as *mut u16).offset(2).as_mut().unwrap() },
            nlmsg_flags: unsafe { (p as *mut u16).offset(3).as_mut().unwrap() },
            nlmsg_seq:   unsafe { (p as *mut u32).offset(2).as_mut().unwrap() },
            nlmsg_pid:   unsafe { (p as *mut u32).offset(3).as_mut().unwrap() },
        };
        nlh
    }

    /// create, reserve and prepare room for Netlink header
    ///
    /// # Arguments
    /// * `buf` memory already allocated to store the Netlink header
    ///
    /// # Return value
    /// This function sets to zero the room that is required to put the Netlink
    /// header in the memory buffer passed as parameter. This function also
    /// initializes the nlmsg_len field to the size of the Netlink header. This
    /// function returns a Netlink header structure.
    pub fn new(buf: &'a mut [u8]) -> Self {
        let mut nlh = Self::from_bytes(buf);
        nlh.put_header();
        nlh
    }

    fn from_raw(nlh: *const netlink::Nlmsghdr) -> Self {
        let buf: &'a mut[u8] = unsafe {
            std::slice::from_raw_parts_mut((nlh as *mut u8),
                                           (*nlh).nlmsg_len as usize)
        };
        Self::from_bytes(buf)
    }

    fn from_raw_parts(p: *mut u8, size: usize) -> Self {
        let buf: &'a mut[u8] = unsafe {
            std::slice::from_raw_parts_mut(p, size)
        };
        Self::from_bytes(buf)
    }

    /// reserve and prepare room for Netlink header
    ///
    /// This function sets to zero the room that is required to put the Netlink
    /// header in the memory buffer passed as parameter. This function also
    /// initializes the nlmsg_len field to the size of the Netlink header.
    pub fn put_header(&mut self) {
        unsafe { &mut(*mnl_nlmsg_put_header(self.as_raw_mut() as *mut _ as *mut c_void)); }
    }

    /// reserve and prepare room for an extra header
    ///
    /// # Arguments
    /// * `size` size of the extra header that we want to put
    ///
    /// This function sets to zero the room that is required to put the extra
    /// header after the initial Netlink header. This function also increases
    /// the nlmsg_len field. You have to invoke mnl_nlmsg_put_header() before
    /// you call this function. This function returns a pointer to the extra
    /// header.
    pub fn put_extra_header<T>(&mut self, size: usize) -> &'a mut T {
        unsafe { &mut(*(mnl_nlmsg_put_extra_header(self.as_raw_mut(), size as usize) as *mut T)) }
    }

    pub fn put_sized_header<T: Sized>(&mut self) -> &'a mut T {
        unsafe { &mut(*(mnl_nlmsg_put_extra_header(self.as_raw_mut(), size_of::<T>()) as *mut T)) }
    }

    pub fn ok(&self, len: isize) -> bool {
        unsafe { mnl_nlmsg_ok(self.as_raw_ref(), len as c_int) }
    }

    pub fn raw_next<'b: 'a>(&'b mut self, len: isize) -> (Self, isize) {
        let mut rest = len as c_int;
        let _ = unsafe { &mut(*mnl_nlmsg_next(self.as_raw_mut(), &mut rest)) };
        let u = self.buf.len() - rest as usize;
        (Self::from_bytes(&mut self.buf[u..]), rest as isize)
    }

    /// perform sequence tracking
    ///
    /// # Arguments
    /// * `seq` last sequence number used to send a message
    ///
    /// # Return values
    /// This functions returns true if the sequence tracking is fulfilled, otherwise
    /// false is returned. We skip the tracking for netlink messages whose sequence
    /// number is zero since it is usually reserved for event-based kernel
    /// notifications. On the other hand, if seq is set but the message sequence
    /// number is not set (i.e. this is an event message coming from kernel-space),
    /// then we also skip the tracking. This approach is good if we use the same
    /// socket to send commands to kernel-space (that we want to track) and to
    /// listen to events (that we do not track).
    pub fn seq_ok(&self, seq: usize) -> bool {
        unsafe { mnl_nlmsg_seq_ok(self.as_raw_ref(), seq as c_uint) }
    }

    /// perform portID origin check
    ///
    /// # Arguments
    /// * `portid` netlink portid that we want to check
    ///
    /// This functions returns true if the origin is fulfilled, otherwise
    /// false is returned. We skip the tracking for netlink message whose portID
    /// is zero since it is reserved for event-based kernel notifications. On the
    /// other hand, if portid is set but the message PortID is not (i.e. this
    /// is an event message coming from kernel-space), then we also skip the
    /// tracking. This approach is good if we use the same socket to send commands
    /// to kernel-space (that we want to track) and to listen to events (that we
    /// do not track).
    pub fn portid_ok(&self, portid: u32) -> bool {
        unsafe { mnl_nlmsg_portid_ok(self.as_raw_ref(), portid as c_uint) }
    }

    /// get a pointer to the payload of the netlink message
    ///
    /// # Return value
    /// This function returns a pointer to the payload of the netlink message.
    pub fn payload<T>(&self) -> &'a T {
        unsafe { &(*(mnl_nlmsg_get_payload(self.as_raw_ref()) as *const T)) }
    }

    pub fn payload_mut<T>(&mut self) -> &'a mut T {
        unsafe { &mut(*(mnl_nlmsg_get_payload(self.as_raw_mut()) as *mut T)) }
    }

    /// get a pointer to the payload of the message
    ///
    /// # Arguments
    /// * `offset` offset to the payload of the attributes TLV set
    ///
    /// # Return value
    /// This function returns a pointer to the payload of the netlink message plus
    /// a given offset.
    pub fn payload_offset<T>(&self, offset: usize) -> &'a T {
        unsafe { &(*(mnl_nlmsg_get_payload_offset(self.as_raw_ref(), offset as size_t) as *const T)) }
    }

    pub fn payload_offset_mut<T>(&mut self, offset: usize) -> &'a mut T {
        unsafe { &mut(*(mnl_nlmsg_get_payload_offset(self.as_raw_mut(), offset as size_t) as *mut T)) }
    }

    /// get the ending of the netlink message
    ///
    /// # Return value
    /// This function returns a pointer to the netlink message tail. This is useful
    /// to build a message since we continue adding attributes at the end of the
    /// message.
    pub fn payload_tail<T>(&self) -> &'a T {
        unsafe { &(*(mnl_nlmsg_get_payload_tail(self.as_raw_ref()) as *const T)) }
    }

    pub fn payload_tail_mut<T>(&mut self) -> &'a mut T {
        unsafe { &mut(*(mnl_nlmsg_get_payload_tail(self.as_raw_mut()) as *mut T)) }
    }

    /// print netlink message to file
    ///
    /// # Arguments
    /// * `fd` pointer to file type
    /// * `extra_header_size` size of the extra header (if any)
    ///
    /// This function prints the netlink header to a file handle.
    /// It may be useful for debugging purposes. One example of the output
    /// is the following:
    ///
    /// ```no run
    ///     ----------------        ------------------
    ///     |  0000000040  |        | message length |
    ///     | 00016 | R-A- |        |  type | flags  |
    ///     |  1289148991  |        | sequence number|
    ///     |  0000000000  |        |     port ID    |
    ///     ----------------        ------------------
    ///     | 00 00 00 00  |        |  extra header  |
    ///     | 00 00 00 00  |        |  extra header  |
    ///     | 01 00 00 00  |        |  extra header  |
    ///     | 01 00 00 00  |        |  extra header  |
    ///     |00008|--|00003|        |len |flags| type|
    ///     | 65 74 68 30  |        |      data      |       e t h 0
    ///     ----------------        ------------------
    ///
    /// This example above shows the netlink message that is send to kernel-space
    /// to set up the link interface eth0. The netlink and attribute header data
    /// are displayed in base 10 whereas the extra header and the attribute payload
    /// are expressed in base 16. The possible flags in the netlink header are:
    ///
    /// - `R`, that indicates that NLM_F_REQUEST is set.
    /// - `M`, that indicates that NLM_F_MULTI is set.
    /// - `A`, that indicates that NLM_F_ACK is set.
    /// - `E`, that indicates that NLM_F_ECHO is set.
    ///
    /// The lack of one flag is displayed with '-'. On the other hand, the possible
    /// attribute flags available are:
    ///
    /// - `N`, that indicates that NLA_F_NESTED is set.
    /// - `B`, that indicates that NLA_F_NET_BYTEORDER is set.
    pub fn fprintf(&self, fd: &AsRawFd, extra_header_size: usize) {
        let mode = CString::new("a").unwrap();
        unsafe {
            let f = libc::fdopen(fd.as_raw_fd(), mode.as_ptr());
            mnl_nlmsg_fprintf(f, self.as_raw_ref() as *const _ as *const c_void,
                              self.buf.len() as size_t, extra_header_size as size_t)
        }
    }

    // belows are mnl_attr_...

    /// add an attribute to netlink message
    ///
    /// # Arguments
    /// * `type` netlink attribute type that you want to add
    /// * `data` pointer to the data that will be stored by the new attribute
    ///
    /// This function updates the length field of the Netlink message (nlmsg_len)
    /// by adding the size (header + payload) of the new attribute.
    pub fn put<T: ?Sized>(&mut self, atype: u16, data: &T) {
        // ???: data must be a #[repr(C)]
        unsafe { mnl_attr_put(self.as_raw_mut(), atype, size_of_val(data), data as *const T as *const c_void) }
    }

    /// add 8-bit unsigned integer attribute to netlink message
    ///
    /// # Arguments
    /// * `atype` netlink attribute type
    /// * `data` 8-bit unsigned integer data that is stored by the new attribute
    ///
    /// This function updates the length field of the Netlink message (nlmsg_len)
    /// by adding the size (header + payload) of the new attribute.
    pub fn put_u8(&mut self, atype: u16, data: u8) {
        unsafe { mnl_attr_put_u8(self.as_raw_mut(), atype, data) }
    }

    /// add 16-bit unsigned integer attribute to netlink message
    ///
    /// # Arguments
    /// * `atype` netlink attribute type
    /// * `data` 16-bit unsigned integer data that is stored by the new attribute
    ///
    /// This function updates the length field of the Netlink message (nlmsg_len)
    /// by adding the size (header + payload) of the new attribute.
    pub fn put_u16(&mut self, atype: u16, data: u16) {
        unsafe { mnl_attr_put_u16(self.as_raw_mut(), atype, data) }
    }

    /// add 32-bit unsigned integer attribute to netlink message
    ///
    /// # Arguments
    /// * `type` netlink attribute type
    /// * `data` 32-bit unsigned integer data that is stored by the new attribute
    ///
    /// This function updates the length field of the Netlink message (nlmsg_len)
    /// by adding the size (header + payload) of the new attribute.
    pub fn put_u32(&mut self, atype: u16, data: u32) {
        unsafe { mnl_attr_put_u32(self.as_raw_mut(), atype, data) }
    }

    /// add 64-bit unsigned integer attribute to netlink message
    /// # Arguments
    /// * `atype netlink attribute type
    /// * `data` 64-bit unsigned integer data that is stored by the new attribute
    ///
    /// This function updates the length field of the Netlink message (nlmsg_len)
    /// by adding the size (header + payload) of the new attribute.
    pub fn put_u64(&mut self, atype: u16, data: u64) {
        unsafe { mnl_attr_put_u64(self.as_raw_mut(), atype, data) }
    }

    /// add string attribute to netlink message
    ///
    /// # Arguments
    /// * `type` netlink attribute type
    /// * `data` pointer to string data that is stored by the new attribute
    ///
    /// This function updates the length field of the Netlink message (nlmsg_len)
    /// by adding the size (header + payload) of the new attribute.
    pub fn put_str(&mut self, atype: u16, data: &str) {
        let cs = CString::new(data).unwrap();
        unsafe {
            mnl_attr_put_str(self.as_raw_mut(), atype, cs.as_ptr())
        }
    }

    /// add string attribute to netlink message
    ///
    /// # Arguments
    /// * `atype` netlink attribute type
    /// * `data` pointer to string data that is stored by the new attribute
    ///
    /// This function is similar to mnl_attr_put_str, but it includes the
    /// NUL/zero ('\0') terminator at the end of the string.
    ///
    /// This function updates the length field of the Netlink message (nlmsg_len)
    /// by adding the size (header + payload) of the new attribute.
    pub fn put_strz(&mut self, atype: u16, data: &str) {
        let cs = CString::new(data).unwrap();
        unsafe {
            mnl_attr_put_strz(self.as_raw_mut(), atype, cs.as_ptr())
        }
    }

    /// mnl_attr_put_check - add an attribute to netlink message
    ///
    /// # Arguments
    /// * `buflen` size of buffer which stores the message
    /// * `atype` netlink attribute type that you want to add
    /// * `data` pointer to the data that will be stored by the new attribute
    ///
    /// This function first checks that the data can be added to the message
    /// (fits into the buffer) and then updates the length field of the Netlink
    /// message (nlmsg_len) by adding the size (header + payload) of the new
    /// attribute. The function returns true if the attribute could be added
    /// to the message, otherwise false is returned.
    pub fn put_check<T: Sized>(&mut self, atype: u16, data: &T) -> bool {
        unsafe { mnl_attr_put_check(self.as_raw_mut(), self.buf.len() as size_t, atype,
                                    size_of_val(data), data as *const T as *const c_void) }
    }

    /// mnl_attr_put_u8_check - add 8-bit unsigned int attribute to netlink message
    /// \param nlh pointer to the netlink message
    /// \param buflen size of buffer which stores the message
    /// \param type netlink attribute type
    /// \param data 8-bit unsigned integer data that is stored by the new attribute
    ///
    /// This function first checks that the data can be added to the message
    /// (fits into the buffer) and then updates the length field of the Netlink
    /// message (nlmsg_len) by adding the size (header + payload) of the new
    /// attribute. The function returns true if the attribute could be added
    /// to the message, otherwise false is returned.
    pub fn put_u8_check(&mut self, atype: u16, data: u8) -> bool {
        unsafe { mnl_attr_put_u8_check(self.as_raw_mut(), self.buf.len() as size_t, atype, data) }
    }

    /// add 16-bit unsigned int attribute to netlink message
    ///
    /// # Arguments
    /// * `atype` netlink attribute type
    /// * `data` 16-bit unsigned integer data that is stored by the new attribute
    ///
    /// This function first checks that the data can be added to the message
    /// (fits into the buffer) and then updates the length field of the Netlink
    /// message (nlmsg_len) by adding the size (header + payload) of the new
    /// attribute. The function returns true if the attribute could be added
    /// to the message, otherwise false is returned.
    /// This function updates the length field of the Netlink message (nlmsg_len)
    /// by adding the size (header + payload) of the new attribute.
    pub fn put_u16_check(&mut self, atype: u16, data: u16) -> bool {
        unsafe { mnl_attr_put_u16_check(self.as_raw_mut(), self.buf.len() as size_t, atype, data) }
    }

    /// add 32-bit unsigned int attribute to netlink message
    ///
    /// # Arguments
    /// * `atype` netlink attribute type
    /// * `data` 32-bit unsigned integer data that is stored by the new attribute
    ///
    /// This function first checks that the data can be added to the message
    /// (fits into the buffer) and then updates the length field of the Netlink
    /// message (nlmsg_len) by adding the size (header + payload) of the new
    /// attribute. The function returns true if the attribute could be added
    /// to the message, otherwise false is returned.
    /// This function updates the length field of the Netlink message (nlmsg_len)
    /// by adding the size (header + payload) of the new attribute.
    pub fn put_u32_check(&mut self, atype: u16, data: u32) -> bool {
        unsafe { mnl_attr_put_u32_check(self.as_raw_mut(), self.buf.len() as size_t, atype, data) }
    }

    /// add 64-bit unsigned int attribute to netlink message
    ///
    /// # Arguments
    /// * `atype` netlink attribute type
    /// *  `data` 64-bit unsigned integer data that is stored by the new attribute
    ///
    /// This function first checks that the data can be added to the message
    /// (fits into the buffer) and then updates the length field of the Netlink
    /// message (nlmsg_len) by adding the size (header + payload) of the new
    /// attribute. The function returns true if the attribute could be added
    /// to the message, otherwise false is returned.
    /// This function updates the length field of the Netlink message (nlmsg_len)
    /// by adding the size (header + payload) of the new attribute.
    pub fn put_u64_check(&mut self, atype: u16, data: u64) -> bool {
        unsafe { mnl_attr_put_u64_check(self.as_raw_mut(), self.buf.len() as size_t, atype, data) }
    }

    /// add string attribute to netlink message
    ///
    /// # Arguments
    /// * `atype` netlink attribute type
    /// * `data` pointer to string data that is stored by the new attribute
    ///
    /// This function first checks that the data can be added to the message
    /// (fits into the buffer) and then updates the length field of the Netlink
    /// message (nlmsg_len) by adding the size (header + payload) of the new
    /// attribute. The function returns true if the attribute could be added
    /// to the message, otherwise false is returned.
    /// This function updates the length field of the Netlink message (nlmsg_len)
    /// by adding the size (header + payload) of the new attribute.
    pub fn put_str_check(&mut self, atype: u16, data: &str) -> bool {
        let cs = CString::new(data).unwrap();
        unsafe {
            mnl_attr_put_str_check(self.as_raw_mut(), self.buf.len() as size_t, atype, cs.as_ptr())
        }
    }

    /// add string attribute to netlink message
    ///
    /// # Arguments
    /// * `atype` netlink attribute type
    /// * `data` pointer to string data that is stored by the new attribute
    ///
    /// This function is similar to mnl_attr_put_str, but it includes the
    /// NUL/zero ('\0') terminator at the end of the string.
    ///
    /// This function first checks that the data can be added to the message
    /// (fits into the buffer) and then updates the length field of the Netlink
    /// message (nlmsg_len) by adding the size (header + payload) of the new
    /// attribute. The function returns true if the attribute could be added
    /// to the message, otherwise false is returned.
    pub fn put_strz_check(&mut self, atype: u16, data: &str) -> bool {
        let cs = CString::new(data).unwrap();
        unsafe {
            mnl_attr_put_strz_check(self.as_raw_mut(), self.buf.len() as size_t, atype, cs.as_ptr())
        }
    }

    /// start an attribute nest
    ///
    /// # Arguments
    /// * `atype` netlink attribute type
    ///
    /// This function adds the attribute header that identifies the beginning of
    /// an attribute nest.
    ///
    /// #Return value
    /// This function always returns a valid pointer to the
    /// beginning of the nest.
    pub fn nest_start(&mut self, atype: u16) -> &'a mut Attr {
        unsafe { &mut *mnl_attr_nest_start(self.as_raw_mut(), atype) }
    }

    /// start an attribute nest
    ///
    /// # Arguments
    /// * `atype` netlink attribute type
    ///
    /// This function adds the attribute header that identifies the beginning of
    /// an attribute nest. If the nested attribute cannot be added then NULL,
    /// otherwise valid pointer to the beginning of the nest is returned.
    pub fn nest_start_check(&mut self, atype: u16) -> Option<&'a mut Attr> {
        let p = unsafe { mnl_attr_nest_start_check(self.as_raw_mut(), self.buf.len() as size_t, atype) };
        if p.is_null() { return None; }
        unsafe { Some(&mut *p) }
    }

    /// end an attribute nest
    ///
    /// # Arguments
    /// * `start` pointer to the attribute nest returned by mnl_attr_nest_start()
    ///
    /// This function updates the attribute header that identifies the nest.
    pub fn nest_end(&mut self, start: &mut Attr) {
        unsafe { mnl_attr_nest_end(self.as_raw_mut(), start) }
    }

    /// cancel an attribute nest
    ///
    /// # Arguments
    /// * `start` pointer to the attribute nest returned by mnl_attr_nest_start()
    ///
    /// This function updates the attribute header that identifies the nest.
    pub fn nest_cancel(&mut self, start: &mut Attr) {
        unsafe { mnl_attr_nest_cancel(self.as_raw_mut(), start) }
    }

    /// mnl_attr_parse - parse attributes
    ///
    /// # Arguments
    /// * `offset` offset to start parsing from (if payload is after any header)
    /// * `cb` callback function that is called for each attribute
    /// * `data` pointer to data that is passed to the callback function
    ///
    /// This function allows to iterate over the sequence of attributes that compose
    /// the Netlink message. You can then put the attribute in an array as it
    /// usually happens at this stage or you can use any other data structure (such
    /// as lists or trees).
    ///
    /// This function propagates the return value of the callback, which can be
    /// MNL_CB_ERROR, MNL_CB_OK or MNL_CB_STOP.
    pub fn parse<T: ?Sized + 'a>(&self, offset: usize, cb: AttrCb<'a, T>, data: &mut T) -> io::Result<(CbRet)> {
        let mut cbdata = AttrCbData {cb: cb, data: data};
        let pdata = &mut cbdata as *mut _ as *mut c_void;
        cvt_cbret!(mnl_attr_parse(self.as_raw_ref(), offset as c_uint, attr_parse_cb::<T>, pdata))
    }

    pub fn cl_parse<'b, 'c>(&self, offset: usize, cb: Box<FnMut(&'b Attr) -> CbRet + 'c>) -> io::Result<(CbRet)> {
        cvt_cbret!(mnl_attr_parse(self.as_raw_ref(), offset as c_uint, attr_parse_cb2,
                                  Box::into_raw(Box::new(cb)) as *mut c_void))
    }

    pub fn attrs(&'a self, offset: usize) -> Box<Iterator<Item=&Attr> + 'a> {
        Box::new(AttrIterator { attr: self.payload_offset::<Attr>(offset),
                                tail: self.payload_tail::<Attr>() as *const _ as uintptr_t })
    }
}

impl <'a> Iterator for Nlmsg<'a> {
    type Item = Self;

    fn next(&mut self) -> Option<Self> {
        if ! unsafe { mnl_nlmsg_ok(self.as_raw_ref(), self.remaining as c_int) } {
            return None;
        }
        let nlh = unsafe { &mut(*mnl_nlmsg_next(self.as_raw_mut(), &mut (self.remaining as c_int))) };
        Some(Self::from_raw(nlh))
    }
}

struct AttrIterator<'a> {
    attr: &'a Attr,
    tail: uintptr_t,
}

impl <'a> Iterator for AttrIterator<'a> {
    type Item = &'a Attr;

    fn next(&mut self) -> Option<&'a Attr> {
        if !self.attr.ok(self.tail - self.attr as *const _ as uintptr_t) {
            return None;
        }

        let curr = self.attr;
        self.attr = curr.next();
        Some(curr)
    }
}

impl Drop for NlmsgBatch {
    fn drop(&mut self) {
        unsafe { mnl_nlmsg_batch_stop(self) };
    }
}

impl NlmsgBatch {
    /// initialize a batch
    ///
    /// # Arguments
    /// * `buf` pointer to the buffer that will store this batch
    /// * `limit` maximum size of the batch (should be MNL_SOCKET_BUFFER_SIZE).
    ///
    /// The buffer that you pass must be double of MNL_SOCKET_BUFFER_SIZE. The
    /// limit must be half of the buffer size, otherwise expect funny memory
    /// corruptions 8-).
    ///
    /// You can allocate the buffer that you use to store the batch in the stack or
    /// the heap, no restrictions in this regard. This function returns NULL on
    /// error.
    pub fn start<'a>(buf: &'a mut [u8], bufsiz: usize) -> io::Result<&'a mut NlmsgBatch> {
        // cvt_null!(&mut(*mnl_nlmsg_batch_start(buf.as_ptr() as *mut c_void, buf.len() as size_t)))
        cvt_null!(mnl_nlmsg_batch_start(buf.as_ptr() as *mut c_void, bufsiz as size_t))
    }

    /// get room for the next message in the batch
    ///
    /// # Return values
    /// This function returns false if the last message did not fit into the
    /// batch. Otherwise, it prepares the batch to provide room for the new
    /// Netlink message in the batch and returns true.
    ///
    /// You have to put at least one message in the batch before calling this
    /// function, otherwise your application is likely to crash.
    pub fn next(&self) -> bool {
        unsafe { mnl_nlmsg_batch_next(self) }
    }

    // stop() is used at drop trait

    /// get current size of the batch
    ///
    /// # Return values
    /// This function returns the current size of the batch.
    pub fn size(&self) -> usize {
        unsafe { mnl_nlmsg_batch_size(self) as usize }
    }

    /// reset the batch
    ///
    /// This function allows to reset a batch, so you can reuse it to create a
    /// new one. This function moves the last message which does not fit the
    /// batch to the head of the buffer, if any.
    pub fn reset(&mut self) {
        unsafe { mnl_nlmsg_batch_reset(self) }
    }

    /// get head of this batch
    ///
    /// # Return values
    /// This function returns a pointer to the head of the batch, which is the
    /// beginning of the buffer that is used.
    pub fn head<'a, T>(&'a mut self) -> &'a mut T {
        unsafe { &mut(*(mnl_nlmsg_batch_head(self) as *mut T)) }
    }

    /// returns current position in the batch
    ///
    /// # Return values
    /// This function returns a pointer to the current position in the buffer
    /// that is used to store the batch.
    pub fn current<'a, T>(&'a mut self) -> &'a mut T {
        unsafe { &mut(*(mnl_nlmsg_batch_current(self) as *mut T)) }
    }

    pub fn current_nlmsg(&mut self) -> Nlmsg {
        let p = unsafe { mnl_nlmsg_batch_current(self) as *mut u8 };
        Nlmsg::from_raw_parts(p, self.rest())
    }

    /// check if there is any message in the batch
    ///
    /// # Return values
    /// This function returns true if the batch is empty.
    pub fn is_empty(&self) -> bool {
        unsafe { mnl_nlmsg_batch_is_empty(self) }
    }

    pub fn rest(&self) -> usize {
        unsafe { mnl_nlmsg_batch_rest(self) as usize }
    }
}

pub type Attr = netlink::Nlattr;

impl fmt::Debug for Attr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Attr[{:?}]", self as *const _)
    }
}

impl <'a> Attr {
    /// get type of netlink attribute
    ///
    /// # Return values
    /// This function returns the attribute type.
    pub fn atype(&self) -> u16 {
        unsafe { mnl_attr_get_type(self) }
    }

    ///  get length of netlink attribute
    ///
    /// # Return values
    /// This function returns the attribute length that is the attribute header
    /// plus the attribute payload.
    pub fn len(&self) -> u16 {
        unsafe { mnl_attr_get_len(self) }
    }

    /// get the attribute payload-value length
    ///
    /// # Return values
    /// This function returns the attribute payload-value length.
    pub fn payload_len(&self) -> u16 {
        unsafe { mnl_attr_get_payload_len(self) }
    }

    /// get pointer to the attribute payload
    ///
    /// # Return values
    /// This function return a pointer to the attribute payload.
    pub fn payload<T>(&self) -> &'a T {
        unsafe { &(*(mnl_attr_get_payload(self) as *const T)) }
    }

    pub fn payload_mut<T>(&mut self) -> &'a mut T {
        unsafe { &mut(*(mnl_attr_get_payload(self) as *mut T)) }
    }

    /// returns 8-bit unsigned integer attribute payload
    ///
    /// # Return values
    /// This function returns the 8-bit value of the attribute payload.
    pub fn u8(&self) -> u8 {
        unsafe { mnl_attr_get_u8(self) }
    }

    /// returns 16-bit unsigned integer attribute payload
    ///
    /// # Return values
    /// This function returns the 16-bit value of the attribute payload.
    pub fn u16(&self) -> u16 {
        unsafe { mnl_attr_get_u16(self) }
    }

    /// returns 32-bit unsigned integer attribute payload
    ///
    /// # Return values
    /// This function returns the 32-bit value of the attribute payload.
    pub fn u32(&self) -> u32 {
        unsafe { mnl_attr_get_u32(self) }
    }

    /// returns 64-bit unsigned integer attribute.
    ///
    /// # Return values
    /// This function returns the 64-bit value of the attribute payload. This
    /// function is align-safe, since accessing 64-bit Netlink attributes is a
    /// common source of alignment issues.
    pub fn u64(&self) -> u64 {
        unsafe { mnl_attr_get_u64(self) }
    }

    pub fn string(&self) -> String {
        unsafe {
            CStr::from_ptr(mnl_attr_get_str(self)).to_string_lossy().into_owned()
        }
    }

    /// returns pointer to string attribute.
    ///
    /// # Return values
    /// This function returns the payload of string attribute value.
    pub fn str(&self) -> &'a str {
        unsafe {
            CStr::from_ptr(mnl_attr_get_str(self)).to_str().unwrap()
        }
    }

    /// check if the attribute type is valid
    ///
    /// # Arguments
    /// * `maxtype` maximum attribute type
    ///
    /// # Return values
    /// This function allows to check if the attribute type is higher than the
    /// maximum supported type. If the attribute type is invalid, this function
    /// returns -1 and errno is explicitly set. On success, this function returns 1.
    ///
    /// Strict attribute checking in user-space is not a good idea since you may
    /// run an old application with a newer kernel that supports new attributes.
    /// This leads to backward compatibility breakages in user-space. Better check
    /// if you support an attribute, if not, skip it.
    pub fn type_valid(&self, maxtype: u16) -> io::Result<()> {
        try!(cvt_isize!(mnl_attr_type_valid(self, maxtype)));
        Ok(())
    }

    /// validate netlink attribute (simplified version)
    ///
    /// # Arguments
    /// * `atype` data type (see enum mnl_attr_data_type)
    ///
    /// # Return values
    /// The validation is based on the data type. Specifically, it checks that
    /// integers (u8, u16, u32 and u64) have enough room for them. This function
    /// returns -1 in case of error, and errno is explicitly set.
    pub fn validate(&self, atype: AttrDataType) -> io::Result<()> {
        try!(cvt_isize!(mnl_attr_validate(self, atype as u16)));
        Ok(())
    }

    /// validate netlink attribute (extended version)
    ///
    /// # Arguments
    /// * `atype` attribute type (see enum mnl_attr_data_type)
    /// * `exp_len` expected attribute data size
    ///
    /// # Return values
    /// This function allows to perform a more accurate validation for attributes
    /// whose size is variable. If the size of the attribute is not what we expect,
    /// this functions returns -1 and errno is explicitly set.
    pub fn validate2(&self, atype: AttrDataType, exp_len: usize) -> io::Result<()> {
        try!(cvt_isize!(mnl_attr_validate2(self, atype as u16, exp_len as size_t)));
        Ok(())
    }

    /// check if there is room for an attribute in a buffer
    ///
    /// # Arguments
    /// * `len` remaining bytes in a buffer that contains the attribute
    ///
    /// # Return values
    /// This function is used to check that a buffer, which is supposed to contain
    /// an attribute, has enough room for the attribute that it stores, i.e. this
    /// function can be used to verify that an attribute is neither malformed nor
    /// truncated.
    ///
    /// This function does not set errno in case of error since it is intended
    /// for iterations. Thus, it returns true on success and false on error.
    ///
    /// The len parameter may be negative in the case of malformed messages during
    /// attribute iteration, that is why we use a signed integer.
    pub fn ok(&self, len: usize) -> bool {
        unsafe { mnl_attr_ok(self, len as c_int) }
    }

    /// get the next attribute in the payload of a netlink message
    ///
    /// # Return values
    /// This function returns a pointer to the next attribute after the one passed
    /// as parameter. You have to use mnl_attr_ok() to ensure that the next
    /// attribute is valid.
    pub fn next(&self) -> &'a mut Attr {
        unsafe { &mut *mnl_attr_next(self) }
    }

    /// parse attributes inside a nest
    ///
    /// # Arguments
    /// * `nested` pointer to netlink attribute that contains a nest
    /// * `cb` callback function that is called for each attribute in the nest
    /// * `data` pointer to data passed to the callback function
    ///
    /// This function allows to iterate over the sequence of attributes that compose
    /// the Netlink message. You can then put the attribute in an array as it
    /// usually happens at this stage or you can use any other data structure (such
    /// as lists or trees).
    ///
    /// # Return values
    /// This function propagates the return value of the callback, which can be
    /// MNL_CB_ERROR, MNL_CB_OK or MNL_CB_STOP.
    pub fn parse_nested<T: ?Sized + 'a>(&self, cb: AttrCb<'a, T>, data: &mut T)
                                        -> io::Result<(CbRet)> {
        let mut cbdata = AttrCbData {cb: cb, data: data};
        let pdata = &mut cbdata as *mut _ as *mut c_void;
        cvt_cbret!(mnl_attr_parse_nested(self, attr_parse_cb::<T>, pdata))
    }

    pub fn cl_parse_nested<'b>(&self, cb: Box<FnMut(&'a Attr) -> CbRet + 'b>) -> io::Result<(CbRet)> {
        cvt_cbret!(mnl_attr_parse_nested(self, attr_parse_cb2, Box::into_raw(Box::new(cb)) as *mut c_void))
    }

    pub fn nesteds(&'a self) -> Box<Iterator<Item=&Attr> + 'a> {
        Box::new(AttrIterator { attr: self.payload::<Attr>(),
                                tail: self.payload::<Attr>() as *const _ as uintptr_t
                                      + self.payload_len() as uintptr_t })
    }

}

extern fn attr_parse_cb<T: ?Sized>(attr: *const netlink::Nlattr, data: *mut c_void) -> c_int {
    unsafe {
        let cbdata = &mut *(data as *mut AttrCbData<T>);
        (cbdata.cb)(attr.as_ref().unwrap(), cbdata.data) as c_int
    }
}

extern fn attr_parse_cb2(attr: *const netlink::Nlattr, data: *mut c_void) -> c_int {
    unsafe {
        let mut cb = Box::from_raw(data as *mut Box<FnMut(&Attr) -> CbRet>);
        let rc = (cb)(attr.as_ref().unwrap()) as c_int;
        forget(cb);
        rc
    }
}

/// parse attributes in payload of Netlink message
///
/// # Arguments
/// * `payload` pointer to payload of the Netlink message
/// * `payload_len` payload length that contains the attributes
/// * `cb` callback function that is called for each attribute
/// * `data` pointer to data that is passed to the callback function
///
/// This function takes a pointer to the area that contains the attributes,
/// commonly known as the payload of the Netlink message. Thus, you have to
/// pass a pointer to the Netlink message payload, instead of the entire
/// message.
///
/// This function allows you to iterate over the sequence of attributes that are
/// located at some payload offset. You can then put the attributes in one array
/// as usual, or you can use any other data structure (such as lists or trees).
///
/// # Return values
/// This function propagates the return value of the callback, which can be
/// MNL_CB_ERROR, MNL_CB_OK or MNL_CB_STOP.
pub fn parse_payload<'a, T: 'a + ?Sized>(payload: &[u8], payload_len: usize, cb: AttrCb<'a, T>, data: &mut T) -> io::Result<(CbRet)> {
    let mut cbdata = AttrCbData{ cb: cb, data: data };
    let pdata = &mut cbdata as *mut _ as *mut c_void;
    cvt_cbret!(mnl_attr_parse_payload(payload.as_ptr() as *const c_void,
                                      payload_len as size_t, attr_parse_cb::<T>, pdata))
}

extern fn nlmsg_parse_cb<T: ?Sized>(nlh: *const netlink::Nlmsghdr, data: *mut c_void) -> c_int {
    unsafe {
        let arg = &mut *(data as *mut CbData<T>);
        if let Some(cb) = arg.cb {
            return cb(Nlmsg::from_raw(nlh), arg.data) as c_int;
        }
        CbRet::OK as c_int // MNL_CB_OK
    }
}

extern fn nlmsg_parse_cb2(nlh: *const netlink::Nlmsghdr, data: *mut c_void) -> c_int {
    unsafe {
        let mut op = Box::from_raw(data as *mut (Option<Box<FnMut(Nlmsg) -> CbRet>>,
                                                 &[Option<Box<FnMut(Nlmsg) -> CbRet>>]));
        let mut rc = CbRet::OK as c_int;
        if let Some(ref mut cb) = op.0.as_mut() {
            rc = cb(Nlmsg::from_raw(nlh)) as c_int;
        }
        forget(op);
        rc
    }
}

extern fn nlmsg_ctl_cb<T: ?Sized>(nlh: *const netlink::Nlmsghdr, data: *mut c_void) -> c_int {
    unsafe {
        let arg = &mut *(data as *mut CbData<T>);
        if let Some(ctl_cb) = arg.ctl_cbs[(*nlh).nlmsg_type as usize] {
            return ctl_cb(Nlmsg::from_raw(nlh), arg.data) as c_int;
        }
        CbRet::OK as c_int // MNL_CB_OK
    }
}

extern fn nlmsg_ctl_cb2(nlh: *const netlink::Nlmsghdr, data: *mut c_void) -> c_int {
    unsafe {
        let mut cbs = Box::from_raw(data as *mut (Option<Box<FnMut(Nlmsg) -> CbRet>>,
                                                  &mut [Option<Box<FnMut(Nlmsg) -> CbRet>>]));
        let rc = match cbs.1[(*nlh).nlmsg_type as usize] {
            Some(ref mut cb) => cb(Nlmsg::from_raw(nlh)) as c_int,
            None => CbRet::OK as c_int,
        };
        forget(cbs);
        rc
    }
}

pub fn cb_run<'a, T>(buf: &[u8], seq: u32, portid: u32,
                     cb_data: Option<Cb<'a, T>>, data: &mut T)
                     -> io::Result<(CbRet)> {
    let nil = [None::<Cb<'a, T>>];
    let mut arg = CbData{ cb: cb_data, ctl_cbs: &nil, data: data };
    let argp = &mut arg as *mut _ as *mut c_void;
    cvt_cbret!(mnl_cb_run(buf.as_ptr() as *const c_void, buf.len() as size_t,
                          seq, portid, nlmsg_parse_cb::<T>, argp))
}

pub fn cl_run(buf: &[u8], seq: u32, portid: u32,
              cb_data: Option<Box<FnMut(Nlmsg) -> CbRet>>)
              -> io::Result<(CbRet)> {
    cvt_cbret!(mnl_cb_run(buf.as_ptr() as *const c_void, buf.len() as size_t,
                          seq, portid, nlmsg_parse_cb2,
                          Box::into_raw(Box::new((cb_data, &[None::<Box<FnMut(Nlmsg) -> CbRet>>]))) as *mut c_void))
}

/// callback runqueue for netlink messages
/// # Arguments
/// * `buf` buffer that contains the netlink messages
/// * `seq` sequence number that we expect to receive
/// * `portid` Netlink PortID that we expect to receive
/// * `cb_data` callback handler for data messages
/// * `data` pointer to data that will be passed to the data callback handler
/// * `cb_ctl` callback handler from control messages
/// * `ctltypes` list of ctl type which is handled by cb_ctl
///
/// Your callback may return three possible values:
/// 	- `MNL_CB_ERROR (<=-1)`: an error has occurred. Stop callback runqueue.
/// 	- `MNL_CB_STOP (=0)`: stop callback runqueue.
/// 	- `MNL_CB_OK (>=1)`: no problem has occurred.
///
/// # Return values
/// This function propagates the callback return value. On error, it returns
/// -1 and errno is explicitly set. If the portID is not the expected, errno
/// is set to ESRCH. If the sequence number is not the expected, errno is set
/// to EPROTO. If the dump was interrupted, errno is set to EINTR and you should
/// request a new fresh dump again.
pub fn cb_run2<'a, T: 'a>(buf: &[u8], seq: u32, portid: u32,
                          cb_data: Option<Cb<'a, T>>, data: &mut T,
                          ctl_cbs: &'a [Option<Cb<'a, T>>])
                          -> io::Result<(CbRet)> {
    let ctlen = ctl_cbs.len();
    let raw_ctl_cbs = vec![nlmsg_ctl_cb::<T> as CbT; ctlen];
    let mut arg = CbData{ cb: cb_data, ctl_cbs: ctl_cbs, data: data };
    let argp = &mut arg as *mut _ as *mut c_void;
    cvt_cbret!(mnl_cb_run2(buf.as_ptr() as *const c_void, buf.len() as size_t,
                           seq, portid, nlmsg_parse_cb::<T>, argp,
                           raw_ctl_cbs.as_ptr() as *const CbT, ctlen as c_uint))
}

pub fn cl_run2(buf: &[u8], seq: u32, portid: u32,
               cb_data: Option<Box<FnMut(Nlmsg) -> CbRet>>,
               cb_ctl_array: &mut [Option<Box<FnMut(Nlmsg) -> CbRet>>])
               -> io::Result<(CbRet)> {
    let ctlen = cb_ctl_array.len();
    let raw_ctl_cbs = vec![nlmsg_ctl_cb2 as CbT; ctlen];
    let data = Box::into_raw(Box::new((cb_data, cb_ctl_array))) as *mut c_void;
    cvt_cbret!(mnl_cb_run2(buf.as_ptr() as *const c_void, buf.len() as size_t,
                           seq, portid, nlmsg_parse_cb2, data,
                           raw_ctl_cbs.as_ptr() as *const CbT, ctlen as c_uint))
}

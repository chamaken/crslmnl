#![allow(dead_code)]
// no effect? #![link(name = "mnl")]

use std::io;
use std::mem::{ size_of, zeroed };
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
    ALIGN(size_of::<Nlmsg>() as u32)
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
    fn mnl_socket_open2(bus: c_int, flags: c_int) -> *mut Socket;
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
    fn mnl_nlmsg_put_extra_header(nlh: *mut Nlmsg, size: size_t) -> *mut c_void;
    fn mnl_nlmsg_ok(nlh: *const netlink::Nlmsghdr, len: c_int) -> bool;
    fn mnl_nlmsg_next(nlh: *const netlink::Nlmsghdr, len: *mut c_int)-> *mut netlink::Nlmsghdr;
    fn mnl_nlmsg_seq_ok(nlh: *const netlink::Nlmsghdr, seq: c_uint) -> bool;
    fn mnl_nlmsg_portid_ok(nlh: *const netlink::Nlmsghdr, portid: c_uint) -> bool;
    fn mnl_nlmsg_get_payload(nlh: *const netlink::Nlmsghdr)-> *mut c_void;
    fn mnl_nlmsg_get_payload_offset(nlh: *const netlink::Nlmsghdr, offset: size_t)-> *mut c_void;
    fn mnl_nlmsg_get_payload_tail(nlh: *const netlink::Nlmsghdr) -> *mut c_void;
    fn mnl_nlmsg_fprintf(fd: *mut FILE, data: *const c_void, datalen: size_t, extra_header_size: size_t);
}

enum NlmsgBatch {}

#[link(name = "mnl")]
extern {
    fn mnl_nlmsg_batch_start(buf: *mut c_void, bufsiz: size_t) -> *mut NlmsgBatch;
    fn mnl_nlmsg_batch_next(b: *mut NlmsgBatch) -> bool;
    fn mnl_nlmsg_batch_stop(b: *mut NlmsgBatch);
    // fn mnl_nlmsg_batch_size(b: *mut NlmsgBatch) -> size_t;
    fn mnl_nlmsg_batch_size(b: *const NlmsgBatch) -> size_t;
    fn mnl_nlmsg_natch_reset(b: *mut NlmsgBatch);
    fn mnl_nlmsg_batch_head(b: *mut NlmsgBatch) -> *mut c_void;
    fn mnl_nlmsg_batch_current(b: *mut NlmsgBatch) -> *mut c_void;
    // fn mnl_nlmsg_batch_is_empty(b: *mut NlmsgBatch) -> bool;
    fn mnl_nlmsg_batch_is_empty(b: *const NlmsgBatch) -> bool;
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
// #define mnl_attr_for_each(attr, nlh, offset)
// #define mnl_attr_for_each_nested(attr, nest)
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

type CbT = extern "C" fn(nlh: *const Nlmsg, data: *mut c_void) -> c_int;
pub type Cb<'a, T: ?Sized> = fn(nlh: &'a Nlmsg, data: &'a mut T) -> CbRet;
struct CbData <'a, 'b, T: 'a + 'b + ?Sized> {
    cb: Cb<'a, T>,
    data: &'b mut T,
}

#[link(name = "mnl")]
extern {
    fn mnl_cb_run(buf: *const c_void, numbytes: size_t, seq: c_uint,
                  portid: c_uint, cb_data: CbT, data: *mut c_void) -> c_int;
    fn mnl_cb_run2(buf: *const c_void, numbytes: size_t, seq: c_uint,
                   portid: c_uint, cb_data: CbT, data: *mut c_void,
                   cb_ctl_array: *const CbT, cb_ctl_array_len: c_uint) -> c_int;
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe { mnl_socket_close(self) };
    }
}

impl <'a> Socket {
    pub fn open(bus: netlink::Family) -> io::Result<&'a mut Socket> {
        cvt_null!(mnl_socket_open(bus.c_int()))
    }

    pub fn open2(bus: netlink::Family, flags: c_int) -> io::Result<&'a mut Socket> {
        cvt_null!(mnl_socket_open2(bus.c_int(), flags))
    }

    // would be better IntoRawFd instead of &AsRawFd, but Sized trait...
    pub fn fdopen(fd: &AsRawFd) -> io::Result<&'a mut Socket> {
        cvt_null!(mnl_socket_fdopen(fd.as_raw_fd()))
    }

    pub fn bind(&mut self, group: u32, pid: u32) -> io::Result<()> {
        try!(cvt_isize!(mnl_socket_bind(self, group as c_uint, pid as pid_t)));
        Ok(())
    }

    // mnl_socket_close() is used as a Drop trait too, with no error...?
    pub fn close(&mut self) -> io::Result<()> {
        try!(cvt_isize!(mnl_socket_close(self)));
        Ok(())
    }

    // mnl_socket_get_fd() is used as a AsRawFd trait

    pub fn portid(&self) -> u32 {
        unsafe { mnl_socket_get_portid(self) as u32 }
    }

    pub fn sendto(&self, buf: &[u8]) -> io::Result<usize> {
        let n = try!(cvt_isize!(
            mnl_socket_sendto(self, buf.as_ptr() as *const c_void, buf.len() as size_t)));
        Ok(n as usize)
    }

    pub fn send_nlmsg(&self, nlh: &netlink::Nlmsghdr) -> io::Result<usize> {
        let n = try!(cvt_isize!(
            mnl_socket_sendto(self, nlh as *const _ as *const c_void, nlh.nlmsg_len as size_t)));
        Ok(n as usize)
    }

    pub fn recvfrom(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = try!(cvt_isize!(
            mnl_socket_recvfrom(self, buf.as_mut_ptr() as *mut c_void, buf.len() as size_t)));
        Ok(n as usize)
    }

    pub fn setsockopt<T>(&self, optname: c_int, val: T) -> io::Result<()> {
        let optval = &val as *const T as *const c_void;
        try!(cvt_isize!(
            mnl_socket_setsockopt(self, optname, optval,
                                  size_of::<T>() as socklen_t)));
        Ok(())
    }

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

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        unsafe { mnl_socket_get_fd(self) }
    }
}

pub type Nlmsg = netlink::Nlmsghdr; // pub type Nlmsg<'a> = netlink::Nlmsghdr<'a>;
impl <'a> Nlmsg { // impl <'a> Nlmsg <'a> {
    pub fn size(len: usize) -> usize {
        unsafe { mnl_nlmsg_size(len as size_t) }
    }

    pub fn payload_len(&self) -> usize {
        unsafe { mnl_nlmsg_get_payload_len(self) }
    }

    pub fn put_header(buf: &mut [u8]) -> &mut Nlmsg {
        // XXX: check buf len > sizeof(Nlmsg)
        unsafe { &mut(*mnl_nlmsg_put_header(buf.as_ptr() as *mut c_void)) }
    }

    pub fn put_extra_header<T>(&mut self, size: usize) -> &'a mut T {
        unsafe { &mut(*(mnl_nlmsg_put_extra_header(self, size as usize) as *mut T)) }
    }

    pub fn put_sized_header<T: Sized>(&mut self) -> &'a mut T {
        unsafe { &mut(*(mnl_nlmsg_put_extra_header(self, size_of::<T>()) as *mut T)) }
    }

    pub fn ok(&self, len: usize) -> bool {
        unsafe { mnl_nlmsg_ok(self, len as c_int) }
    }

    pub fn next(&mut self, len: isize) -> (&'a mut Nlmsg, isize) {
        let mut rest = len as c_int;
        let nlh = unsafe { &mut(*mnl_nlmsg_next(self, &mut rest)) };
        (nlh, rest as isize)
    }

    pub fn seq_ok(&self, seq: usize) -> bool {
        unsafe { mnl_nlmsg_seq_ok(self, seq as c_uint) }
    }

    pub fn portid_ok(&self, portid: u32) -> bool {
        unsafe { mnl_nlmsg_portid_ok(self, portid as c_uint) }
    }

    pub fn payload<T>(&self) -> &'a mut T {
        unsafe { &mut(*(mnl_nlmsg_get_payload(self) as *mut T)) }
    }

    pub fn payload_offset<T>(&self, offset: usize) -> &'a mut T {
        unsafe { &mut(*(mnl_nlmsg_get_payload_offset(self, offset as size_t) as *mut T)) }
    }

    pub fn payload_tail<T>(&self) -> &'a mut T {
        unsafe { &mut(*(mnl_nlmsg_get_payload_tail(self) as *mut T)) }
    }

    pub fn fprintf<T>(fd: &AsRawFd, data: *const T, datalen: usize, extra_header_size: usize) {
        let mode = CString::new("a").unwrap();
        unsafe {
            let f = libc::fdopen(fd.as_raw_fd(), mode.as_ptr());
            mnl_nlmsg_fprintf(f, data as *const c_void,
                              datalen as size_t, extra_header_size as size_t)
        }
    }

    // belows are mnl_attr_...
    pub fn put<T: Sized>(&mut self, atype: u16, data: T) {
        // ???: data must be a #[repr(C)]
        unsafe { mnl_attr_put(self, atype, size_of::<T>(), &data as *const T as *const c_void) }
    }

    pub fn put_u8(&mut self, atype: u16, data: u8) {
        unsafe { mnl_attr_put_u8(self, atype, data) }
    }

    pub fn put_u16(&mut self, atype: u16, data: u16) {
        unsafe { mnl_attr_put_u16(self, atype, data) }
    }

    pub fn put_u32(&mut self, atype: u16, data: u32) {
        unsafe { mnl_attr_put_u32(self, atype, data) }
    }

    pub fn put_u64(&mut self, atype: u16, data: u64) {
        unsafe { mnl_attr_put_u64(self, atype, data) }
    }

    pub fn put_str(&mut self, atype: u16, data: &str) {
        let cs = CString::new(data).unwrap();
        unsafe {
            mnl_attr_put_str(self, atype, cs.as_ptr())
        }
    }

    pub fn put_strz(&mut self, atype: u16, data: &str) {
        let cs = CString::new(data).unwrap();
        unsafe {
            mnl_attr_put_strz(self, atype, cs.as_ptr())
        }
    }

    pub fn put_check<T>(&mut self, buflen: usize, atype: u16, data: T) -> bool {
        unsafe { mnl_attr_put_check(self, buflen as size_t, atype,
                                    size_of::<T>(), &data as *const T as *const c_void) }
    }

    pub fn put_u8_check(&mut self, buflen: usize, atype: u16, data: u8) -> bool {
        unsafe { mnl_attr_put_u8_check(self, buflen as size_t, atype, data) }
    }

    pub fn put_u16_check(&mut self, buflen: usize, atype: u16, data: u16) -> bool {
        unsafe { mnl_attr_put_u16_check(self, buflen as size_t, atype, data) }
    }

    pub fn put_u32_check(&mut self, buflen: usize, atype: u16, data: u32) -> bool {
        unsafe { mnl_attr_put_u32_check(self, buflen as size_t, atype, data) }
    }

    pub fn put_u64_check(&mut self, buflen: usize, atype: u16, data: u64) -> bool {
        unsafe { mnl_attr_put_u64_check(self, buflen as size_t, atype, data) }
    }

    pub fn put_str_check(&mut self, buflen: usize, atype: u16, data: &str) -> bool {
        let cs = CString::new(data).unwrap();
        unsafe {
            mnl_attr_put_str_check(self, buflen as size_t, atype, cs.as_ptr())
        }
    }

    pub fn put_strz_check(&mut self, buflen: usize, atype: u16, data: &str) -> bool {
        let cs = CString::new(data).unwrap();
        unsafe {
            mnl_attr_put_strz_check(self, buflen as size_t, atype, cs.as_ptr())
        }
    }

    pub fn nest_start(&mut self, atype: u16) -> &mut Attr {
        unsafe { &mut *mnl_attr_nest_start(self, atype) }
    }

    pub fn nest_start_check(&mut self, buflen: usize, atype: u16) -> &mut Attr {
        unsafe { &mut *mnl_attr_nest_start_check(self, buflen as size_t, atype) }
    }

    pub fn nest_end(&mut self, start: &mut Attr) {
        unsafe { mnl_attr_nest_end(self, start) }
    }

    pub fn nest_cancel(&mut self, start: &mut Attr) {
        unsafe { mnl_attr_nest_cancel(self, start) }
    }

    pub fn parse<'b, 'c, T: 'b + ?Sized>(&self, offset: usize, cb: AttrCb<'b, T>, data: &'c mut T) -> io::Result<(CbRet)> {
        let mut cbdata = AttrCbData {cb: cb, data: data};
        let pdata = &mut cbdata as *mut _ as *mut c_void;
        cvt_cbret!(mnl_attr_parse(self, offset as c_uint, attr_parse_cb::<T>, pdata))
    }

    pub fn attrs(&'a self, offset: usize) -> Box<Iterator<Item=&Attr> + 'a> {
        Box::new(AttrIterator { attr: self.payload_offset::<Attr>(offset),
                                tail: self.payload_tail::<Attr>() as *const _ as uintptr_t })
    }
}

struct AttrIterator<'a> {
    attr: &'a Attr,
    tail: uintptr_t,
}

impl <'a> AttrIterator <'a> {
    fn ok(&self) -> bool {
        self.attr.ok(
            self.tail - self.attr as *const _ as uintptr_t
        )
    }
}

impl <'a> Iterator for AttrIterator <'a> {
    type Item = &'a Attr;

    fn next(&mut self) -> Option<&'a Attr> {
        if !self.ok() {
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
    pub fn start<'a>(buf: &'a [u8]) -> &'a mut NlmsgBatch {
        unsafe { &mut(*mnl_nlmsg_batch_start(buf.as_ptr() as *mut c_void, buf.len() as size_t)) }
    }

    pub fn next(&mut self) -> bool {
        unsafe { mnl_nlmsg_batch_next(self) }
    }

    // stop() is used at drop trait

    pub fn size(&self) -> usize {
        unsafe { mnl_nlmsg_batch_size(self) as usize }
    }

    pub fn head<'a, T>(&'a mut self) -> &'a mut T {
        unsafe { &mut(*(mnl_nlmsg_batch_head(self) as *mut T)) }
    }

    pub fn current<'a, T>(&'a mut self) -> &'a mut T {
        unsafe { &mut(*(mnl_nlmsg_batch_current(self) as *mut T)) }
    }

    pub fn is_empty(&self) -> bool {
        unsafe { mnl_nlmsg_batch_is_empty(self) }
    }
}

pub type Attr = netlink::Nlattr;

impl fmt::Debug for Attr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Attr[{:?}]", self as *const _)
    }
}

impl <'a> Attr {
    pub fn atype(&self) -> u16 {
        unsafe { mnl_attr_get_type(self) }
    }

    pub fn len(&self) -> u16 {
        unsafe { mnl_attr_get_len(self) }
    }

    pub fn payload_len(&self) -> u16 {
        unsafe { mnl_attr_get_payload_len(self) }
    }

    pub fn payload<T>(&self) -> &'a mut T {
        unsafe { &mut(*(mnl_attr_get_payload(self) as *mut T)) }
    }

    pub fn u8(&self) -> u8 {
        unsafe { mnl_attr_get_u8(self) }
    }

    pub fn u16(&self) -> u16 {
        unsafe { mnl_attr_get_u16(self) }
    }

    pub fn u32(&self) -> u32 {
        unsafe { mnl_attr_get_u32(self) }
    }

    pub fn u64(&self) -> u64 {
        unsafe { mnl_attr_get_u64(self) }
    }

    pub fn string(&self) -> String {
        unsafe {
            CStr::from_ptr(mnl_attr_get_str(self)).to_string_lossy().into_owned()
        }
    }

    pub fn str(&self) -> &'a str {
        unsafe {
            CStr::from_ptr(mnl_attr_get_str(self)).to_str().unwrap()
        }
    }

    pub fn type_valid(&self, maxtype: u16) -> io::Result<()> {
        try!(cvt_isize!(mnl_attr_type_valid(self, maxtype)));
        Ok(())
    }

    pub fn validate(&self, atype: AttrDataType) -> io::Result<()> {
        try!(cvt_isize!(mnl_attr_validate(self, atype as u16)));
        Ok(())
    }

    pub fn validate2(&self, atype: AttrDataType, exp_len: usize) -> io::Result<()> {
        try!(cvt_isize!(mnl_attr_validate2(self, atype as u16, exp_len as size_t)));
        Ok(())
    }

    pub fn ok(&self, len: usize) -> bool {
        unsafe { mnl_attr_ok(self, len as c_int) }
    }

    pub fn next(&self) -> &'a mut Attr {
        unsafe { &mut *mnl_attr_next(self) }
    }

    pub fn parse_nested<'b, 'c, T: 'b + ?Sized>(&self, cb: AttrCb<'b, T>, data: &'c mut T)
                                       -> io::Result<(CbRet)> {
        let mut cbdata = AttrCbData {cb: cb, data: data};
        let pdata = &mut cbdata as *mut _ as *mut c_void;
        cvt_cbret!(mnl_attr_parse_nested(self, attr_parse_cb::<T>, pdata))
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

pub fn parse_payload<'a, 'b, T: 'a + 'b + ?Sized>(payload: &[u8], payload_len: usize, cb: AttrCb<'a, T>, data: &'b mut T) -> io::Result<(CbRet)> {
    let mut cbdata = AttrCbData{ cb: cb, data: data };
    let pdata = &mut cbdata as *mut _ as *mut c_void;
    cvt_cbret!(mnl_attr_parse_payload(payload.as_ptr() as *const c_void,
                                      payload_len as size_t, attr_parse_cb::<T>, pdata))
}

extern fn nlmsg_parse_cb<T: ?Sized>(nlh: *const Nlmsg, data: *mut c_void) -> c_int {
    unsafe {
        let arg = &mut *(data as *mut CbData<T>);
        (arg.cb)(&*nlh, arg.data) as c_int
    }
}

pub fn cb_run<'a, 'b, T: 'a + 'b + ?Sized>(buf: &[u8], seq: u32, portid: u32, cb_data: Cb<'a, T>, data: &'b mut T)
                             -> io::Result<(CbRet)> {
    let mut arg = CbData{ cb: cb_data, data: data };
    let argp = &mut arg as *mut _ as *mut c_void;
    cvt_cbret!(mnl_cb_run(buf.as_ptr() as *const c_void, buf.len() as size_t,
                          seq, portid, nlmsg_parse_cb::<T>, argp))
}

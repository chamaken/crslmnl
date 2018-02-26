use libc::{ c_int, c_uint, sockaddr_nl };
// use std::marker::PhantomData;
use std::mem::size_of;

pub const NETLINK_ROUTE: c_int		= 0;	// Routing/device hook
pub const NETLINK_UNUSED: c_int		= 1;	// Unused number
pub const NETLINK_USERSOCK: c_int	= 2;	// Reserved for user mode socket protocols
pub const NETLINK_FIREWALL: c_int	= 3;	// Unused number, formerly ip_queue
pub const NETLINK_SOCK_DIAG: c_int	= 4;	// socket monitoring
pub const NETLINK_NFLOG: c_int		= 5;	// netfilter/iptables ULOG
pub const NETLINK_XFRM: c_int		= 6;	// ipsec
pub const NETLINK_SELINUX: c_int	= 7;	// SELinux event notifications
pub const NETLINK_ISCSI: c_int		= 8;	// Open-iSCSI
pub const NETLINK_AUDIT: c_int		= 9;	// auditing
pub const NETLINK_FIB_LOOKUP: c_int	= 10;
pub const NETLINK_CONNECTOR: c_int	= 11;
pub const NETLINK_NETFILTER: c_int	= 12;	// netfilter subsystem
pub const NETLINK_IP6_FW: c_int		= 13;
pub const NETLINK_DNRTMSG: c_int	= 14;	// DECnet routing messages
pub const NETLINK_KOBJECT_UEVENT: c_int	= 15;	// Kernel messages to userspace
pub const NETLINK_GENERIC: c_int	= 16;
// leave room for NETLINK_DM (DM Events)
pub const NETLINK_SCSITRANSPORT: c_int	= 18;	// SCSI Transports
pub const NETLINK_ECRYPTFS: c_int	= 19;
pub const NETLINK_RDMA: c_int		= 20;
pub const NETLINK_CRYPTO: c_int		= 21;	// Crypto layer
pub const NETLINK_SMC: c_int		= 22;	// SMC monitoring

pub const NETLINK_INET_DIAG: c_int	= NETLINK_SOCK_DIAG;

pub const MAX_LINKS: c_int		= 32;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum Family {
    ROUTE,             // Routing/device hook
    UNUSED,            // Unused number
    USERSOCK,          // Reserved for user mode socket protocols
    FIREWALL,          // Unused number, formerly ip_queue
    SOCK_DIAG,         // socket monitoring
    NFLOG,             // netfilter/iptables ULOG
    XFRM,              // ipsec
    SELINUX,           // SELinux event notifications
    ISCSI,             // Open-iSCSI
    AUDIT,             // auditing
    FIB_LOOKUP,
    CONNECTOR,
    NETFILTER,         // netfilter subsystem
    IP6_FW,
    DNRTMSG,           // DECnet routing messages
    KOBJECT_UEVENT,    // Kernel messages to userspace
    GENERIC,

    SCSITRANSPORT,     // SCSI Transports
    ECRYPTFS,
    RDMA,
    CRYPTO,            // Crypto layer

    INET_DIAG,         // NETLINK_SOCK_DIAG
}

impl Family {
    pub fn c_int(self) -> c_int {
	match self {
	    Family::ROUTE		=> NETLINK_ROUTE,
	    Family::UNUSED		=> NETLINK_UNUSED,
	    Family::USERSOCK		=> NETLINK_USERSOCK,
	    Family::FIREWALL		=> NETLINK_FIREWALL,
	    Family::SOCK_DIAG		=> NETLINK_SOCK_DIAG,
	    Family::NFLOG		=> NETLINK_NFLOG,
	    Family::XFRM		=> NETLINK_XFRM,
	    Family::SELINUX		=> NETLINK_SELINUX,
	    Family::ISCSI		=> NETLINK_ISCSI,
	    Family::AUDIT		=> NETLINK_AUDIT,
	    Family::FIB_LOOKUP		=> NETLINK_FIB_LOOKUP,
	    Family::CONNECTOR		=> NETLINK_CONNECTOR,
	    Family::NETFILTER		=> NETLINK_NETFILTER,
	    Family::IP6_FW		=> NETLINK_IP6_FW,
	    Family::DNRTMSG		=> NETLINK_DNRTMSG,
	    Family::KOBJECT_UEVENT	=> NETLINK_KOBJECT_UEVENT,
	    Family::GENERIC		=> NETLINK_GENERIC,
	    Family::SCSITRANSPORT	=> NETLINK_SCSITRANSPORT,
	    Family::ECRYPTFS		=> NETLINK_ECRYPTFS,
	    Family::RDMA		=> NETLINK_RDMA,
	    Family::CRYPTO		=> NETLINK_CRYPTO,
	    Family::INET_DIAG		=> NETLINK_INET_DIAG,
	}
    }
}

// XXX: not ported yet
// #[repr(C)]
pub struct SockaddrNl { inner: sockaddr_nl }


#[repr(C)]
pub struct Nlmsghdr { // pub struct Nlmsghdr <'a> {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
    // pub phantom: PhantomData<&'a [u8]>
}

// Flags values
pub const NLM_F_REQUEST: u16		= 0x01;	// It is request message.
pub const NLM_F_MULTI: u16		= 0x02;	// Multipart message, terminated by NLMSG_DONE
pub const NLM_F_ACK: u16		= 0x04;	// Reply with ack, with zero or error code
pub const NLM_F_ECHO: u16		= 0x08;	// Echo this request
pub const NLM_F_DUMP_INTR: u16		= 0x10;	// Dump was inconsistent due to sequence change
pub const NLM_F_DUMP_FILTERED: u16	= 0x20;	// Dump was filtered as requested

// Modifiers to GET request
pub const NLM_F_ROOT: u16	= 0x100;	// specify tree	root
pub const NLM_F_MATCH: u16	= 0x200;	// return all matching
pub const NLM_F_ATOMIC: u16	= 0x400;	// atomic GET
pub const NLM_F_DUMP: u16	= (NLM_F_ROOT|NLM_F_MATCH);

// Modifiers to NEW request
pub const NLM_F_REPLACE: u16	= 0x100;	// Override existing
pub const NLM_F_EXCL: u16	= 0x200;	// Do not touch, if it exists
pub const NLM_F_CREATE: u16	= 0x400;	// Create, if it does not exist
pub const NLM_F_APPEND: u16	= 0x800;	// Add to end of list

// Modifiers to DELETE request
pub const NLM_F_NONREC:u16	= 0x100;	// Do not delete recursively

// Flags for ACK message
pub const NLM_F_CAPPED: u16	= 0x100;	// request was capped
pub const NLM_F_ACK_TLVS: u16	= 0x200;	// extended ACK TVLs were included


// 4.4BSD ADD		NLM_F_CREATE|NLM_F_EXCL
// 4.4BSD CHANGE	NLM_F_REPLACE
//
// True CHANGE		NLM_F_CREATE|NLM_F_REPLACE
// Append		NLM_F_CREATE
// Check		NLM_F_EXCL

pub const NLMSG_ALIGNTO: u32	= 4;
#[allow(non_snake_case)]
pub fn NLMSG_ALIGN(len: u32) -> u32 {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

#[allow(non_snake_case)]
pub fn NLMSG_HDRLEN() -> u32 {
    NLMSG_ALIGN(size_of::<Nlmsghdr>() as u32)
}
// macro_rules! NLMSG_HDRLEN {
//    () => { ALIGN(size_of::<Nlmsghdr>() as u32) }
// }

#[allow(non_snake_case)]
pub fn NLMSG_LENGTH(len: u32) -> u32 {
    len + NLMSG_HDRLEN()
}

#[allow(non_snake_case)]
pub fn NLMSG_SPACE(len: u32) -> u32 {
    NLMSG_ALIGN(NLMSG_LENGTH(len))
}

#[allow(non_snake_case)]
pub fn NLMSG_DATA<T>(nlh: &mut Nlmsghdr) -> &mut T {
    unsafe {
        ((nlh as *mut _ as *mut u8)
         .offset(NLMSG_LENGTH(0) as isize) as *mut T)
            .as_mut()
    }.unwrap()
}

#[allow(non_snake_case)]
pub fn NLMSG_NEXT<'a>(nlh: &'a mut Nlmsghdr, len: &mut u32) -> &'a mut Nlmsghdr {
    *len -= NLMSG_ALIGN(nlh.nlmsg_len);
    unsafe {
        ((nlh as *mut _ as *mut u8)
         .offset(NLMSG_ALIGN(nlh.nlmsg_len) as isize) as *mut Nlmsghdr)
            .as_mut()
    }.unwrap()
}

#[allow(non_snake_case)]
pub fn NLMSG_OK(nlh: &Nlmsghdr, len: u32) -> bool {
    len >= size_of::<Nlmsghdr>() as u32 &&
	nlh.nlmsg_len >= size_of::<Nlmsghdr>() as u32 &&
	nlh.nlmsg_len <= len
}

#[allow(non_snake_case)]
pub fn NLMSG_PAYLOAD(nlh: &Nlmsghdr, len: u32) -> u32 {
    nlh.nlmsg_len - NLMSG_SPACE((len))
}

pub const NLMSG_NOOP: u16	= 0x1;	// Nothing.
pub const NLMSG_ERROR: u16	= 0x2;	// Error
pub const NLMSG_DONE: u16	= 0x3;	// End of a dump
pub const NLMSG_OVERRUN: u16	= 0x4;	// Data lost

pub const NLMSG_MIN_TYPE: u16	= 0x10;	// < 0x10: reserved control messages

#[repr(C)]
pub struct Nlmsgerr {		// pub struct Nlmsgerr <'a> {
    pub error: c_int,
    pub msg: Nlmsghdr,		// pub msg: Nlmsghdr<'a>,
    //followed by the message contents unless NETLINK_CAP_ACK was set
    //or the ACK indicates success (error == 0)
    // message length is aligned with NLMSG_ALIGN()

    // followed by TLVs defined in enum nlmsgerr_attrs
    // if NETLINK_EXT_ACK was set
}

// enum nlmsgerr_attrs - nlmsgerr attributes
// @NLMSGERR_ATTR_UNUSED: unused
// @NLMSGERR_ATTR_MSG: error message string (string)
// @NLMSGERR_ATTR_OFFS: offset of the invalid attribute in the original
//      message, counting from the beginning of the header (u32)
// @NLMSGERR_ATTR_COOKIE: arbitrary subsystem specific cookie to
//     be used - in the success case - to identify a created
//     object or operation or similar (binary)
// @__NLMSGERR_ATTR_MAX: number of attributes
// @NLMSGERR_ATTR_MAX: highest attribute number
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum NlmsgerrAttrs {
    UNUSED	= 0,
    MSG		= 1,
    OFFS	= 2,
    COOKIE	= 3,
    MAX		= 4,
}
pub const NLMSGERR_ATTR_UNUSED: u16	= NlmsgerrAttrs::UNUSED as u16;
pub const NLMSGERR_ATTR_MSG: u16	= NlmsgerrAttrs::MSG as u16;
pub const NLMSGERR_ATTR_OFFS: u16	= NlmsgerrAttrs::OFFS as u16;
pub const NLMSGERR_ATTR_COOKIE: u16	= NlmsgerrAttrs::COOKIE as u16;
pub const __NLMSGERR_ATTR_MAX: u16	= NlmsgerrAttrs::MAX as u16;
pub const MSGERR_ATTR_MAX: u16		= __NLMSGERR_ATTR_MAX - 1;

pub const NETLINK_ADD_MEMBERSHIP: c_int		= 1;
pub const NETLINK_DROP_MEMBERSHIP: c_int	= 2;
pub const NETLINK_PKTINFO: c_int		= 3;
pub const NETLINK_BROADCAST_ERROR: c_int	= 4;
pub const NETLINK_NO_ENOBUFS: c_int		= 5;
// pub const NETLINK_RX_RING: c_int		= 6;
// pub const NETLINK_TX_RING: c_int		= 7;
pub const NETLINK_LISTEN_ALL_NSID: c_int	= 8;
pub const NETLINK_LIST_MEMBERSHIPS: c_int	= 9;
pub const NETLINK_CAP_ACK: c_int		= 10;
pub const NETLINK_EXT_ACK: c_int		= 11;

#[repr(C)]
pub struct NlPktinfo {
    group: u32,
}

pub const NET_MAJOR: c_uint	= 36;	// Major 36 is reserved for networking

// struct sock_common.skc_state;
pub const NETLINK_UNCONNECTED: u8	= 0;
pub const NETLINK_CONNECTED: u8		= 1;


//  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
// +---------------------+- - -+- - - - - - - - - -+- - -+
// |        Header       | Pad |     Payload       | Pad |
// |   (struct nlattr)   | ing |                   | ing |
// +---------------------+- - -+- - - - - - - - - -+- - -+
//  <-------------- nlattr->nla_len -------------->
#[repr(C)]
pub struct Nlattr {
    pub nla_len: u16,
    pub nla_type: u16,
}


// nla_type (16 bits)
// +---+---+-------------------------------+
// | N | O | Attribute Type                |
// +---+---+-------------------------------+
// N := Carries nested attributes
// O := Payload stored in network byte order
//
// Note: The N and O flag are mutually exclusive.
pub const NLA_F_NESTED: u16		= (1 << 15);
pub const NLA_F_NET_BYTEORDER: u16	= (1 << 14);
pub const NLA_TYPE_MASK: u16		= !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

pub const NLA_ALIGNTO: u16		= 4;

#[allow(non_snake_case)]
pub fn NLA_ALIGN(len: u16) -> u16 {
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}

#[allow(non_snake_case)]
pub fn NLA_HDRLEN() -> u16 {
    NLA_ALIGN(size_of::<Nlattr>() as u16)
}
// macro_rules! ATTR_HDRLEN {
//     () => { ALIGN(size_of::<Nlattr>() as u16) }
// }

// Generic 32 bitflags attribute content sent to the kernel.
//
// The value is a bitmap that defines the values being set
// The selector is a bitmask that defines which value is legit
//
// Examples:
//  value = 0x0, and selector = 0x1
//  implies we are selecting bit 1 and we want to set its value to 0.
//
//  value = 0x2, and selector = 0x2
//  implies we are selecting bit 2 and we want to set its value to 1.
#[repr(C)]
pub struct NlaBitfield32 { // struct nla_bitfield32
    pub value: u32,
    pub selector: u32,
}

use std::mem::size_of;

use linux::netlink;
use linux::rtnetlink;

#[repr(C)]
pub struct Ifaddrmsg {
    pub ifa_family: u8,
    pub ifa_prefixlen: u8,
    pub ifa_flags: u8,
    pub ifa_scope: u8,
    pub ifa_index: u32,
}

// Important comment:
// IFA_ADDRESS is prefix address, rather than local interface address.
// It makes no difference for normally configured broadcast interfaces,
// but for point-to-point IFA_ADDRESS is DESTINATION address,
// local address is supplied in IFA_LOCAL attribute.
//
// IFA_FLAGS is a u32 attribute that extends the u8 field ifa_flags.
// If present, the value from struct ifaddrmsg will be ignored.
#[repr(u16)]
pub enum IFA {
    UNSPEC	= 0,
    ADDRESS	= 1,
    LOCAL	= 2,
    LABEL	= 3,
    BROADCAST	= 4,
    ANYCAST	= 5,
    CACHEINFO	= 6,
    MULTICAST	= 7,
    FLAGS	= 8,
    _MAX	= 9,
}
pub const IFA_UNSPEC: u16	= IFA::UNSPEC as u16;
pub const IFA_ADDRESS: u16	= IFA::ADDRESS as u16;
pub const IFA_LOCAL: u16	= IFA::LOCAL as u16;
pub const IFA_LABEL: u16	= IFA::LABEL as u16;
pub const IFA_BROADCAST: u16	= IFA::BROADCAST as u16;
pub const IFA_ANYCAST: u16	= IFA::ANYCAST as u16;
pub const IFA_CACHEINFO: u16	= IFA::CACHEINFO as u16;
pub const IFA_MULTICAST: u16	= IFA::MULTICAST as u16;
pub const IFA_FLAGS: u16	= IFA::FLAGS as u16;
pub const __IFA_MAX: u16	= IFA::_MAX as u16;
pub const IFA_MAX: u16		= __IFA_MAX - 1;

//ifa_flags
pub const IFA_F_SECONDARY: u32		= 0x01;
pub const IFA_F_TEMPORARY: u32		= IFA_F_SECONDARY;
pub const IFA_F_NODAD: u32		= 0x02;
pub const IFA_F_OPTIMISTIC: u32		= 0x04;
pub const IFA_F_DADFAILED: u32		= 0x08;
pub const IFA_F_HOMEADDRESS: u32	= 0x10;
pub const IFA_F_DEPRECATED: u32		= 0x20;
pub const IFA_F_TENTATIVE: u32		= 0x40;
pub const IFA_F_PERMANENT: u32		= 0x80;
pub const IFA_F_MANAGETEMPADDR: u32	= 0x100;
pub const IFA_F_NOPREFIXROUTE: u32	= 0x200;
pub const IFA_F_MCAUTOJOIN: u32		= 0x400;
pub const IFA_F_STABLE_PRIVACY: u32	= 0x800;

#[repr(C)]
pub struct IfaCacheinfo {
    pub ifa_prefered: u32,
    pub ifa_valid: u32,
    pub cstamp: u32,
    pub tstamp: u32,
}

#[allow(non_snake_case)]
pub fn IFA_RTA(r: &mut Ifaddrmsg) -> &mut rtnetlink::Rtattr {
    unsafe {
        ((r as *mut _ as *mut u8)
         .offset(netlink::NLMSG_ALIGN(size_of::<Ifaddrmsg>() as u32) as isize) as *mut rtnetlink::Rtattr)
            .as_mut()
    }.unwrap()
}
#[allow(non_snake_case)]
pub fn IFA_PAYLOAD(n: &netlink::Nlmsghdr) -> u32 {
    netlink::NLMSG_PAYLOAD(n, size_of::<Ifaddrmsg>() as u32)
}

use std::mem::size_of;
use libc::{c_int, sa_family_t};

use linux::netlink;

// #![allow(dead_code,
//          non_camel_case_types,
//          non_upper_case_globals,
//          non_snake_case)]

// rtnetlink families. Values up to 127 are reserved for real address
// families, values above 128 may be used arbitrarily.
pub const RTNL_FAMILY_IPMR: u8	= 128;
pub const RTNL_FAMILY_IP6MR: u8	= 129;
pub const RTNL_FAMILY_MAX: u8	= 129;

// Routing/neighbour discovery messages.
// XXX: #[repr(C)]?
#[repr(u16)]
pub enum RTM {
    // BASE		= 16,
    NEWLINK		= 16,
    DELLINK		= 17,
    GETLINK		= 18,
    SETLINK		= 19,
    NEWADDR		= 20,
    DELADDR		= 21,
    GETADDR		= 22,
    NEWROUTE		= 24,
    DELROUTE		= 25,
    GETROUTE		= 26,
    NEWNEIGH		= 28,
    DELNEIGH		= 29,
    GETNEIGH		= 30,
    NEWRULE		= 32,
    DELRULE		= 33,
    GETRULE		= 34,
    NEWQDISC		= 36,
    DELQDISC		= 37,
    GETQDISC		= 38,
    NEWTCLASS		= 40,
    DELTCLASS		= 41,
    GETTCLASS		= 42,
    NEWTFILTER		= 44,
    DELTFILTER		= 45,
    GETTFILTER		= 46,
    NEWACTION		= 48,
    DELACTION		= 49,
    GETACTION		= 50,
    NEWPREFIX		= 52,
    GETMULTICAST	= 58,
    GETANYCAST		= 62,
    NEWNEIGHTBL		= 64,
    GETNEIGHTBL		= 66,
    SETNEIGHTBL		= 67,
    NEWNDUSEROPT	= 68,
    NEWADDRLABEL	= 72,
    DELADDRLABEL	= 73,
    GETADDRLABEL	= 74,
    GETDCB		= 78,
    SETDCB		= 79,
    NEWNETCONF		= 80,
    GETNETCONF		= 82,
    NEWMDB		= 84,
    DELMDB		= 85,
    GETMDB		= 86,
    NEWNSID		= 88,
    DELNSID		= 89,
    GETNSID		= 90,
    NEWSTATS		= 92,
    GETSTATS		= 94,
    _MAX		= 95,
}
pub const RTM_BASE: u16			= RTM::NEWLINK as u16;	// XXX
pub const RTM_NEWLINK: u16		= RTM::NEWLINK as u16;
pub const RTM_DELLINK: u16		= RTM::DELLINK as u16;
pub const RTM_GETLINK: u16		= RTM::GETLINK as u16;
pub const RTM_SETLINK: u16		= RTM::SETLINK as u16;
pub const RTM_NEWADDR: u16		= RTM::NEWADDR as u16;
pub const RTM_DELADDR: u16		= RTM::DELADDR as u16;
pub const RTM_GETADDR: u16		= RTM::GETADDR as u16;
pub const RTM_NEWROUTE: u16		= RTM::NEWROUTE as u16;
pub const RTM_DELROUTE: u16		= RTM::DELROUTE as u16;
pub const RTM_GETROUTE: u16		= RTM::GETROUTE as u16;
pub const RTM_NEWNEIGH: u16		= RTM::NEWNEIGH as u16;
pub const RTM_DELNEIGH: u16		= RTM::DELNEIGH as u16;
pub const RTM_GETNEIGH: u16		= RTM::GETNEIGH as u16;
pub const RTM_NEWRULE: u16		= RTM::NEWRULE as u16;
pub const RTM_DELRULE: u16		= RTM::DELRULE as u16;
pub const RTM_GETRULE: u16		= RTM::GETRULE as u16;
pub const RTM_NEWQDISC: u16		= RTM::NEWQDISC as u16;
pub const RTM_DELQDISC: u16		= RTM::DELQDISC as u16;
pub const RTM_GETQDISC: u16		= RTM::GETQDISC as u16;
pub const RTM_NEWTCLASS: u16		= RTM::NEWTCLASS as u16;
pub const RTM_DELTCLASS: u16		= RTM::DELTCLASS as u16;
pub const RTM_GETTCLASS: u16		= RTM::GETTCLASS as u16;
pub const RTM_NEWTFILTER: u16		= RTM::NEWTFILTER as u16;
pub const RTM_DELTFILTER: u16		= RTM::DELTFILTER as u16;
pub const RTM_GETTFILTER: u16		= RTM::GETTFILTER as u16;
pub const RTM_NEWACTION: u16		= RTM::NEWACTION as u16;
pub const RTM_DELACTION: u16		= RTM::DELACTION as u16;
pub const RTM_GETACTION: u16		= RTM::GETACTION as u16;
pub const RTM_NEWPREFIX: u16		= RTM::NEWPREFIX as u16;
pub const RTM_GETMULTICAST: u16	= RTM::GETMULTICAST as u16;
pub const RTM_GETANYCAST: u16		= RTM::GETANYCAST as u16;
pub const RTM_NEWNEIGHTBL: u16	= RTM::NEWNEIGHTBL as u16;
pub const RTM_GETNEIGHTBL: u16	= RTM::GETNEIGHTBL as u16;
pub const RTM_SETNEIGHTBL: u16	= RTM::SETNEIGHTBL as u16;
pub const RTM_NEWNDUSEROPT: u16	= RTM::NEWNDUSEROPT as u16;
pub const RTM_NEWADDRLABEL: u16	= RTM::NEWADDRLABEL as u16;
pub const RTM_DELADDRLABEL: u16	= RTM::DELADDRLABEL as u16;
pub const RTM_GETADDRLABEL: u16	= RTM::GETADDRLABEL as u16;
pub const RTM_GETDCB: u16		= RTM::GETDCB as u16;
pub const RTM_SETDCB: u16		= RTM::SETDCB as u16;
pub const RTM_NEWNETCONF: u16		= RTM::NEWNETCONF as u16;
pub const RTM_GETNETCONF: u16		= RTM::GETNETCONF as u16;
pub const RTM_NEWMDB: u16		= RTM::NEWMDB as u16;
pub const RTM_DELMDB: u16		= RTM::DELMDB as u16;
pub const RTM_GETMDB: u16		= RTM::GETMDB as u16;
pub const RTM_NEWNSID: u16		= RTM::NEWNSID as u16;
pub const RTM_DELNSID: u16		= RTM::DELNSID as u16;
pub const RTM_GETNSID: u16		= RTM::GETNSID as u16;
pub const RTM_NEWSTATS: u16		= RTM::NEWSTATS as u16;
pub const RTM_GETSTATS: u16		= RTM::GETSTATS as u16;
pub const RTM_MAX: u16			= ((RTM::_MAX as u16 + 3) & !3) - 1;

pub const RTM_NR_MSGTYPES: u16		= RTM_MAX + 1 - RTM_BASE;
pub const RTM_NR_FAMILIES: u16		= RTM_NR_MSGTYPES >> 2;
#[allow(non_snake_case)]
pub fn RTM_FAM(cmd: u16) -> u16 {
    (cmd - RTM_BASE) >> 2
}

// Generic structure for encapsulation of optional route information.
// It is reminiscent of sockaddr, but with sa_family replaced
// with attribute type.
#[repr(C)]
pub struct Rtattr {
    pub rta_len: u16,	// ::std::os::raw::c_ushort,
    pub rta_type: u16,	// ::std::os::raw::c_ushort,
}

// Macros to handle rtattributes
pub const RTA_ALIGNTO: u16	= 4;
#[allow(non_snake_case)]
pub fn RTA_ALIGN(len: u16) -> u16 {
    (len + RTA_ALIGNTO -1) & !(RTA_ALIGNTO - 1)
}
#[allow(non_snake_case)]
pub fn RTA_OK(rta: &Rtattr, len: u16) -> bool {
    len >= size_of::<Rtattr>() as u16 &&
        rta.rta_len >= size_of::<Rtattr> as u16 &&
        rta.rta_len <= len
}
#[allow(non_snake_case)]
pub fn RTA_NEXT<'a>(rta: &'a mut Rtattr, attrlen: &mut u16) -> &'a mut Rtattr {
    *attrlen -= RTA_ALIGN(rta.rta_len);
    unsafe {
        ((rta as *mut _ as *mut u8)
         .offset(rta.rta_len as isize) as *mut Rtattr).as_mut()
    }.unwrap()
}
#[allow(non_snake_case)]
pub fn RTA_LENGTH(len: u16) -> u16 {
    RTA_ALIGN(size_of::<Rtattr>() as u16 + len)
}
#[allow(non_snake_case)]
pub fn RTA_SPACE(len: u16) -> u16 {
    RTA_ALIGN(RTA_LENGTH(len))
}
#[allow(non_snake_case)]
pub fn RTA_DATA<T>(rta: &mut Rtattr) -> &mut T {
    unsafe {
        ((rta as *mut _ as *mut u8)
         .offset(RTA_LENGTH(0) as isize) as *mut T).as_mut()
    }.unwrap()
}
#[allow(non_snake_case)]
pub fn RTA_PAYLOAD(rta: &Rtattr) -> u16 {
    rta.rta_len - RTA_LENGTH(0)
}

// Definitions used in routing table administration.
#[repr(C)]
pub struct Rtmsg {
    pub rtm_family: u8, 	// 				::std::os::raw::c_uchar,
    pub rtm_dst_len: u8,	// 				::std::os::raw::c_uchar,
    pub rtm_src_len: u8,	// 				::std::os::raw::c_uchar,
    pub rtm_tos: u8,		// 				::std::os::raw::c_uchar,
    pub rtm_table: u8, 		// Routing table id		::std::os::raw::c_uchar,
    pub rtm_protocol: u8, 	// Routing protocol; see below	::std::os::raw::c_uchar,
    pub rtm_scope: u8, 		// See below			::std::os::raw::c_uchar,
    pub rtm_type: u8,		// See below			::std::os::raw::c_uchar,
    pub rtm_flags: u32,		// 				::std::os::raw::c_uint,
}

// rtm_type
#[repr(u8)]
pub enum RTN {
    UNSPEC	= 0,
    UNICAST	= 1,	// Gateway or direct route
    LOCAL	= 2,    // Accept locally
    BROADCAST	= 3,    // Accept locally as broadcast,
    			// send as broadcast
    ANYCAST	= 4,    // Accept locally as broadcast,
                        // but send as unicast
    MULTICAST	= 5,    // Multicast route
    BLACKHOLE	= 6,    // Drop
    UNREACHABLE	= 7,    // Destination is unreachable
    PROHIBIT	= 8,    // Administratively prohibited
    THROW	= 9,    // Not in this table
    NAT		= 10,   // Translate this address
    XRESOLVE	= 11,   // Use external resolver
    _MAX	= 12,
}
pub const RTN_UNSPEC: u8	= RTN::UNSPEC as u8;
pub const RTN_UNICAST: u8	= RTN::UNICAST as u8;
pub const RTN_LOCAL: u8		= RTN::LOCAL as u8;
pub const RTN_BROADCAST: u8	= RTN::BROADCAST as u8;
pub const RTN_ANYCAST: u8	= RTN::ANYCAST as u8;
pub const RTN_MULTICAST: u8	= RTN::MULTICAST as u8;
pub const RTN_BLACKHOLE: u8	= RTN::BLACKHOLE as u8;
pub const RTN_UNREACHABLE: u8	= RTN::UNREACHABLE as u8;
pub const RTN_PROHIBIT: u8	= RTN::PROHIBIT as u8;
pub const RTN_THROW: u8		= RTN::THROW as u8;
pub const RTN_NAT: u8		= RTN::NAT as u8;
pub const RTN_XRESOLVE: u8	= RTN::XRESOLVE as u8;
pub const RTN_MAX: u8		= RTN::_MAX as u8 - 1;

// rtm_protocol
pub const RTPROT_UNSPEC: u8	= 0;
pub const RTPROT_REDIRECT: u8	= 1;	// Route installed by ICMP redirects;
				  	// not used by current IPv4
pub const RTPROT_KERNEL: u8	= 2;	// Route installed by kernel
pub const RTPROT_BOOT: u8	= 3;	// Route installed during boot
pub const RTPROT_STATIC: u8	= 4;	// Route installed by administrator
// Values of protocol >= RTPROT_STATIC are not interpreted by kernel;
// they are just passed from user and back as is.
// It will be used by hypothetical multiple routing daemons.
// Note that protocol values should be standardized in order to
// avoid conflicts.
pub const RTPROT_GATED: u8	= 8;	// Apparently, GateD
pub const RTPROT_RA: u8		= 9;	// RDISC/ND router advertisements
pub const RTPROT_MRT: u8	= 10;	// Merit MRT
pub const RTPROT_ZEBRA: u8	= 11;	// Zebra
pub const RTPROT_BIRD: u8	= 12;	// BIRD
pub const RTPROT_DNROUTED: u8	= 13;	// DECnet routing daemon
pub const RTPROT_XORP: u8	= 14;	// XORP
pub const RTPROT_NTK: u8	= 15;	// Netsukuku
pub const RTPROT_DHCP: u8	= 16;   // DHCP client
pub const RTPROT_MROUTED: u8	= 17;   // Multicast daemon
pub const RTPROT_BABEL: u8	= 42;   // Babel daemon

// rtm_scope
//
// Really it is not scope, but sort of distance to the destination.
// NOWHERE are reserved for not existing destinations, HOST is our
// local addresses, LINK are destinations, located on directly attached
// link and UNIVERSE is everywhere in the Universe.
//
// Intermediate values are also possible f.e. interior routes
// could be assigned a value between UNIVERSE and LINK.
#[repr(u8)]
pub enum RtScope {
    UNIVERSE	= 0,
    // User defined values
    SITE	= 200,
    LINK	= 253,
    HOST	= 254,
    NOWHERE	= 255,
}
pub const RT_SCOPE_UNIVERSE: u8	= RtScope::UNIVERSE as u8;
pub const RT_SCOPE_SITE: u8	= RtScope::SITE as u8;
pub const RT_SCOPE_LINK: u8	= RtScope::LINK as u8;
pub const RT_SCOPE_HOST: u8	= RtScope::HOST as u8;
pub const RT_SCOPE_NOWHERE: u8	= RtScope::NOWHERE as u8;

// rtm_flags
pub const RTM_F_NOTIFY: u32		= 0x100;	// Notify user of route change
pub const RTM_F_CLONED: u32		= 0x200;	// This route is cloned
pub const RTM_F_EQUALIZE: u32		= 0x400;	// Multipath equalizer: NI
pub const RTM_F_PREFIX: u32		= 0x800;	// Prefix addresses
pub const RTM_F_LOOKUP_TABLE: u32	= 0x1000;	// set rtm_table to FIB lookup result

#[repr(u32)]
pub enum RtClass {
    UNSPEC	= 0,
    // User defined values
    COMPAT	= 252,
    DEFAULT	= 253,
    MAIN	= 254,
    LOCAL	= 255,
    MAX		= 0xFFFFFFFF,
}
pub const RT_TABLE_UNSPEC: u32	= RtClass::UNSPEC as u32;
pub const RT_TABLE_COMPAT: u32	= RtClass::COMPAT as u32;
pub const RT_TABLE_DEFAULT: u32	= RtClass::DEFAULT as u32;
pub const RT_TABLE_MAIN: u32	= RtClass::MAIN as u32;
pub const RT_TABLE_LOCAL: u32	= RtClass::LOCAL as u32;
pub const RT_TABLE_MAX: u32	= RtClass::MAX as u32;

// Routing message attributes
#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum RtattrType {
    UNSPEC	= 0,
    DST		= 1,
    SRC		= 2,
    IIF		= 3,
    OIF		= 4,
    GATEWAY	= 5,
    PRIORITY	= 6,
    PREFSRC	= 7,
    METRICS	= 8,
    MULTIPATH	= 9,
    PROTOINFO	= 10,	// no longer used
    FLOW	= 11,
    CACHEINFO	= 12,
    SESSION	= 13,	// no longer used
    MP_ALGO	= 14,	// no longer used
    TABLE	= 15,
    MARK	= 16,
    MFC_STATS	= 17,
    VIA		= 18,
    NEWDST	= 19,
    PREF	= 20,
    ENCAP_TYPE	= 21,
    ENCAP	= 22,
    EXPIRES	= 23,
    PAD		= 24,
    UID		= 25,
    _MAX	= 26,
}
pub const RTA_UNSPEC: u16	= RtattrType::UNSPEC as u16;
pub const RTA_DST: u16		= RtattrType::DST as u16;
pub const RTA_SRC: u16		= RtattrType::SRC as u16;
pub const RTA_IIF: u16		= RtattrType::IIF as u16;
pub const RTA_OIF: u16		= RtattrType::OIF as u16;
pub const RTA_GATEWAY: u16	= RtattrType::GATEWAY as u16;
pub const RTA_PRIORITY: u16	= RtattrType::PRIORITY as u16;
pub const RTA_PREFSRC: u16	= RtattrType::PREFSRC as u16;
pub const RTA_METRICS: u16	= RtattrType::METRICS as u16;
pub const RTA_MULTIPATH: u16	= RtattrType::MULTIPATH as u16;
pub const RTA_PROTOINFO: u16	= RtattrType::PROTOINFO as u16;
pub const RTA_FLOW: u16		= RtattrType::FLOW as u16;
pub const RTA_CACHEINFO: u16	= RtattrType::CACHEINFO as u16;
pub const RTA_SESSION: u16	= RtattrType::SESSION as u16;
pub const RTA_MP_ALGO: u16	= RtattrType::MP_ALGO as u16;
pub const RTA_TABLE: u16	= RtattrType::TABLE as u16;
pub const RTA_MARK: u16		= RtattrType::MARK as u16;
pub const RTA_MFC_STATS: u16	= RtattrType::MFC_STATS as u16;
pub const RTA_VIA: u16		= RtattrType::VIA as u16;
pub const RTA_NEWDST: u16	= RtattrType::NEWDST as u16;
pub const RTA_PREF: u16		= RtattrType::PREF as u16;
pub const RTA_ENCAP_TYPE: u16	= RtattrType::ENCAP_TYPE as u16;
pub const RTA_ENCAP: u16	= RtattrType::ENCAP as u16;
pub const RTA_EXPIRES: u16	= RtattrType::EXPIRES as u16;
pub const RTA_PAD: u16		= RtattrType::PAD as u16;
pub const RTA_UID: u16		= RtattrType::UID as u16;
pub const RTA_MAX: u16		= 26 - 1; // RtattrType::_MAX as u16 - 1;

#[allow(non_snake_case)]
pub fn RTM_RTA(r: &mut Rtmsg) -> &mut Rtattr {
    unsafe { ((r as *mut _ as *mut u8)
              .offset(netlink::NLMSG_ALIGN(size_of::<Rtmsg>() as u32) as isize) as *mut Rtattr)
               .as_mut()
    }.unwrap()
}

// RTM_MULTIPATH --- array of struct rtnexthop.
//
// "struct rtnexthop" describes all necessary nexthop information,
// i.e. parameters of path to a destination via this nexthop.
//
// At the moment it is impossible to set different prefsrc, mtu, window
// and rtt for different paths from multipath.
#[repr(C)]
pub struct Rtnexthop {
    pub rtnh_len: u16,		// ::std::os::raw::c_ushort,
    pub rtnh_flags: u8,		// ::std::os::raw::c_uchar,
    pub rtnh_hops: u8,		// ::std::os::raw::c_uchar,
    pub rtnh_ifindex: u32,	// ::std::os::raw::c_int,
}

// rtnh_flags
pub const RTNH_F_DEAD: u8	= 1;	// Nexthop is dead (used by multipath)
pub const RTNH_F_PERVASIVE: u8	= 2;	// Do recursive gateway lookup
pub const RTNH_F_ONLINK: u8	= 4;	// Gateway is forced on link
pub const RTNH_F_OFFLOAD: u8	= 8;	// offloaded route
pub const RTNH_F_LINKDOWN: u8	= 16;	// carrier-down on nexthop

pub const RTNH_COMPARE_MASK: u8	= (RTNH_F_DEAD | RTNH_F_LINKDOWN | RTNH_F_OFFLOAD);

// Macros to handle hexthops
pub const RTNH_ALIGNTO: u16	= 4;
#[allow(non_snake_case)]
pub fn RTNH_ALIGN(len: u16) -> u16 {
    (len + RTNH_ALIGNTO - 1) & !(RTNH_ALIGNTO - 1)
}
#[allow(non_snake_case)]
pub fn RTNH_OK(rtnh: &Rtnexthop, len: u16) -> bool {
    rtnh.rtnh_len >= size_of::<Rtnexthop>() as u16 &&
        rtnh.rtnh_len <= len
}
#[allow(non_snake_case)]
pub fn RTNH_NEXT(rtnh: &mut Rtnexthop) -> &mut Rtnexthop {
    unsafe {
        ((rtnh as *mut _ as *mut u8)
         .offset(RTNH_ALIGN(rtnh.rtnh_len) as isize) as *mut Rtnexthop)
            .as_mut()
    }.unwrap()
}
#[allow(non_snake_case)]
pub fn RTNH_LENGTH(len: u16) -> u16 {
    RTNH_ALIGN(size_of::<Rtnexthop>() as u16 + len)
}
#[allow(non_snake_case)]
pub fn RTNH_SPACE(len: u16) -> u16 {
    RTNH_ALIGN(RTNH_LENGTH(len))
}
#[allow(non_snake_case)]
pub fn RTNH_DATA(rtnh: &mut Rtnexthop) -> &mut Rtattr {
    unsafe {
        ((rtnh as *mut _ as *mut u8)
         .offset(RTNH_LENGTH(0) as isize) as *mut Rtattr)
            .as_mut()
    }.unwrap()
}

// RTA_VIA
#[repr(C)]
pub struct Rtvia {
    pub rtvia_family: sa_family_t,
    pub rtvia_addr: [u8; 0],
}

// RTM_CACHEINFO
#[repr(C)]
pub struct RtaCacheinfo {
    pub rta_clntref: u32,
    pub rta_lastuse: u32,
    pub rta_expires: i32,
    pub rta_error: u32,
    pub rta_used: u32,
    pub rta_id: u32,
    pub rta_ts: u32,
    pub rta_tsage: u32,
}
pub const RTNETLINK_HAVE_PEERINFO: u32	= 1;	// XXX: ???

// RTM_METRICS --- array of struct rtattr with types of RTAX_*
#[repr(C)]
pub enum RTAX {
    UNSPEC	= 0,
    LOCK	= 1,
    MTU		= 2,
    WINDOW	= 3,
    RTT		= 4,
    RTTVAR	= 5,
    SSTHRESH	= 6,
    CWND	= 7,
    ADVMSS	= 8,
    REORDERING	= 9,
    HOPLIMIT	= 10,
    INITCWND	= 11,
    FEATURES	= 12,
    RTO_MIN	= 13,
    INITRWND	= 14,
    QUICKACK	= 15,
    CC_ALGO	= 16,
    _MAX	= 17,
}
pub const RTAX_UNSPEC: c_int		= RTAX::UNSPEC as c_int;
pub const RTAX_LOCK: c_int		= RTAX::LOCK as c_int;
pub const RTAX_MTU: c_int		= RTAX::MTU as c_int;
pub const RTAX_WINDOW: c_int		= RTAX::WINDOW as c_int;
pub const RTAX_RTT: c_int		= RTAX::RTT as c_int;
pub const RTAX_RTTVAR: c_int		= RTAX::RTTVAR as c_int;
pub const RTAX_SSTHRESH: c_int		= RTAX::SSTHRESH as c_int;
pub const RTAX_CWND: c_int		= RTAX::CWND as c_int;
pub const RTAX_ADVMSS: c_int		= RTAX::ADVMSS as c_int;
pub const RTAX_REORDERING: c_int	= RTAX::REORDERING as c_int;
pub const RTAX_HOPLIMIT: c_int		= RTAX::HOPLIMIT as c_int;
pub const RTAX_INITCWND: c_int		= RTAX::INITCWND as c_int;
pub const RTAX_FEATURES: c_int		= RTAX::FEATURES as c_int;
pub const RTAX_RTO_MIN: c_int		= RTAX::RTO_MIN as c_int;
pub const RTAX_INITRWND: c_int		= RTAX::INITRWND as c_int;
pub const RTAX_QUICKACK: c_int		= RTAX::QUICKACK as c_int;
pub const RTAX_CC_ALGO: c_int		= RTAX::CC_ALGO as c_int;
pub const RTAX_MAX: c_int		= 17 - 1; // RTAX::_MAX as c_int - 1;

pub const RTAX_FEATURE_ECN: u32		= (1 << 0);
pub const RTAX_FEATURE_SACK: u32	= (1 << 1);
pub const RTAX_FEATURE_TIMESTAMP: u32	= (1 << 2);
pub const RTAX_FEATURE_ALLFRAG: u32	= (1 << 3);
pub const RTAX_FEATURE_MASK: u32	= (RTAX_FEATURE_ECN | RTAX_FEATURE_SACK |
                                           RTAX_FEATURE_TIMESTAMP | RTAX_FEATURE_ALLFRAG);
#[derive(Default)]
#[repr(C)]
pub struct RtaSession {
    pub proto: u8,
    pub pad1: u8,
    pub pad2: u16,
    pub _u: [u8; 4],
}

impl RtaSession {
    pub fn ports(&mut self) -> &mut RtaSessionPorts {
        unsafe { (&mut self._u as *mut _ as *mut RtaSessionPorts).as_mut() }.unwrap()
    }
    pub fn icmpt(&mut self) -> &mut RtaSessionIcmpt {
        unsafe { (&mut self._u as *mut _ as *mut RtaSessionIcmpt).as_mut() }.unwrap()
    }
    pub fn spi(&mut self) -> &mut u32 {
        unsafe { (&mut self._u as *mut _ as *mut u32).as_mut() }.unwrap()
    }
}
#[repr(C)]
pub struct RtaSessionPorts {
    pub sport: u16,
    pub dport: u16,
}
#[repr(C)]
pub struct RtaSessionIcmpt {
    pub itype: u8,
    pub code: u8,
    pub ident: u16,
}

#[repr(C)]
pub struct RtaMfcStats {
    pub mfcs_packets: u64,
    pub mfcs_bytes: u64,
    pub mfcs_wrong_if: u64,
}

// General form of address family dependent message.
#[repr(C)]
pub struct Rtgenmsg {
    pub rtgen_family: u8, // ::std::os::raw::c_uchar,
}

// Link layer specific messages.

// struct ifinfomsg
// passes link level specific information, not dependent
// on network protocol.
#[repr(C)]
pub struct Ifinfomsg {
    pub ifi_family: u8,		// ::std::os::raw::c_uchar,
    pub __ifi_pad: u8,		// ::std::os::raw::c_uchar,
    pub ifi_type: u16,		// ::std::os::raw::c_ushort,	ARPHRD_*
    pub ifi_index: i32,		// ::std::os::raw::c_int,       Link index
    pub ifi_flags: u32,		// ::std::os::raw::c_uint,      IFF_* flags
    pub ifi_change: u32,	// ::std::os::raw::c_uint,      IFF_* change mask
}

// prefix information
#[repr(C)]
pub struct prefixmsg {
    pub prefix_family: u8,	// ::std::os::raw::c_uchar,
    pub prefix_pad1: u8,	// ::std::os::raw::c_uchar,
    pub prefix_pad2: u16,	// ::std::os::raw::c_ushort,
    pub prefix_ifindex: i32,	// ::std::os::raw::c_int,
    pub prefix_type: u8,	// ::std::os::raw::c_uchar,
    pub prefix_len: u8,		// ::std::os::raw::c_uchar,
    pub prefix_flags: u8,	// ::std::os::raw::c_uchar,
    pub prefix_pad3: u8,	// ::std::os::raw::c_uchar,
}

#[repr(u16)]
pub enum PREFIX {
    UNSPEC	= 0,
    ADDRESS	= 1,
    CACHEINFO	= 2,
    _MAX	= 3,
}
pub const PREFIX_UNSPEC: u16	= PREFIX::UNSPEC as u16;
pub const PREFIX_ADDRESS: u16	= PREFIX::ADDRESS as u16;
pub const PREFIX_CACHEINFO: u16	= PREFIX::CACHEINFO as u16;
pub const PREFIX_MAX: u16	= PREFIX::_MAX as u16 - 1;

#[repr(C)]
pub struct PrefixCacheinfo {
    pub preferred_time: u32,
    pub valid_time: u32,
}

// Traffic control messages.
#[allow(non_snake_case)]
#[repr(C)]
pub struct Tcmsg {
    pub tcm_family: u8,		// ::std::os::raw::c_uchar,
    pub tcm__pad1: u8,		// ::std::os::raw::c_uchar,
    pub tcm__pad2: u16,		// ::std::os::raw::c_ushort,
    pub tcm_ifindex: i32,	// ::std::os::raw::c_int,
    pub tcm_handle: u32,
    pub tcm_parent: u32,
    pub tcm_info: u32,
}

#[repr(u16)]
pub enum TCA {
    UNSPEC	= 0,
    KIND	= 1,
    OPTIONS	= 2,
    STATS	= 3,
    XSTATS	= 4,
    RATE	= 5,
    FCNT	= 6,
    STATS2	= 7,
    STAB	= 8,
    PAD		= 9,
    MAX		= 10,
}
pub const TCA_UNSPEC: u16	= TCA::UNSPEC as u16;
pub const TCA_KIND: u16		= TCA::KIND as u16;
pub const TCA_OPTIONS: u16	= TCA::OPTIONS as u16;
pub const TCA_STATS: u16	= TCA::STATS as u16;
pub const TCA_XSTATS: u16	= TCA::XSTATS as u16;
pub const TCA_RATE: u16		= TCA::RATE as u16;
pub const TCA_FCNT: u16		= TCA::FCNT as u16;
pub const TCA_STATS2: u16	= TCA::STATS2 as u16;
pub const TCA_STAB: u16		= TCA::STAB as u16;
pub const TCA_PAD: u16		= TCA::PAD as u16;
pub const TCA_MAX: u16		= TCA::MAX as u16 - 1;

#[allow(non_snake_case)]
pub fn TCA_RTA(r: &mut Tcmsg)  -> &Rtattr {
    unsafe {
        ((r as *mut _ as *mut u8)
         .offset(netlink::NLMSG_ALIGN(size_of::<Tcmsg>() as u32) as isize) as *mut Rtattr)
            .as_ref()
    }.unwrap()
}
#[allow(non_snake_case)]
pub fn TCA_PAYLOAD(n: &netlink::Nlmsghdr) -> u32 {
    netlink::NLMSG_PAYLOAD(n, size_of::<Tcmsg>() as u32)
}

// Neighbor Discovery userland options
#[repr(C)]
pub struct nduseroptmsg {
    pub nduseropt_family: u8,		// ::std::os::raw::c_uchar,
    pub nduseropt_pad1: u8,		// ::std::os::raw::c_uchar,
    pub nduseropt_opts_len: u16,	// ::std::os::raw::c_ushort,	Total length of options
    pub nduseropt_ifindex: i32,		// ::std::os::raw::c_int,
    pub nduseropt_icmp_type: u8,
    pub nduseropt_icmp_code: u8,
    pub nduseropt_pad2: u16,		// ::std::os::raw::c_ushort,
    pub nduseropt_pad3: u32,		// ::std::os::raw::c_uint,
    // Followed by one or more ND options
}

#[repr(u16)]
pub enum NDUSEROPT {
    UNSPEC	= 0,
    SRCADDR	= 1,
    _MAX	= 2,
}
pub const NDUSEROPT_UNSPEC: u16		= NDUSEROPT::UNSPEC as u16;
pub const NDUSEROPT_SRCADDR: u16	= NDUSEROPT::SRCADDR as u16;
pub const NDUSEROPT_MAX: u16		= NDUSEROPT::_MAX as u16 - 1;

// RTnetlink multicast groups - backwards compatibility for userspace
pub const RTMGRP_LINK: u32		= 1;
pub const RTMGRP_NOTIFY: u32		= 2;
pub const RTMGRP_NEIGH: u32		= 4;
pub const RTMGRP_TC: u32		= 8;
pub const RTMGRP_IPV4_IFADDR: u32	= 0x10;
pub const RTMGRP_IPV4_MROUTE: u32	= 0x20;
pub const RTMGRP_IPV4_ROUTE: u32	= 0x40;
pub const RTMGRP_IPV4_RULE: u32		= 0x80;
pub const RTMGRP_IPV6_IFADDR: u32	= 0x100;
pub const RTMGRP_IPV6_MROUTE: u32	= 0x200;
pub const RTMGRP_IPV6_ROUTE: u32	= 0x400;
pub const RTMGRP_IPV6_IFINFO: u32	= 0x800;
#[allow(non_upper_case_globals)]
pub const RTMGRP_DECnet_IFADDR: u32	= 0x1000;
#[allow(non_upper_case_globals)]
pub const RTMGRP_DECnet_ROUTE: u32	= 0x4000;
pub const RTMGRP_IPV6_PREFIX: u32	= 0x20000;

// RTnetlink multicast groups
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum RtnetlinkGroups {
    NONE		= 0,
    LINK		= 1,
    NOTIFY		= 2,
    NEIGH		= 3,
    TC			= 4,
    IPV4_IFADDR		= 5,
    IPV4_MROUTE		= 6,
    IPV4_ROUTE		= 7,
    IPV4_RULE		= 8,
    IPV6_IFADDR		= 9,
    IPV6_MROUTE		= 10,
    IPV6_ROUTE		= 11,
    IPV6_IFINFO		= 12,
    DECnet_IFADDR	= 13,
    NOP2		= 14,
    DECnet_ROUTE	= 15,
    DECnet_RULE		= 16,
    NOP4		= 17,
    IPV6_PREFIX		= 18,
    IPV6_RULE		= 19,
    ND_USEROPT		= 20,
    PHONET_IFADDR	= 21,
    PHONET_ROUTE	= 22,
    DCB			= 23,
    IPV4_NETCONF	= 24,
    IPV6_NETCONF	= 25,
    MDB			= 26,
    MPLS_ROUTE		= 27,
    NSID		= 28,
    _MAX		= 29,
}
pub const RTNLGRP_NONE: u32		= RtnetlinkGroups::NONE as u32;
pub const RTNLGRP_LINK: u32		= RtnetlinkGroups::LINK as u32;
pub const RTNLGRP_NOTIFY: u32		= RtnetlinkGroups::NOTIFY as u32;
pub const RTNLGRP_NEIGH: u32		= RtnetlinkGroups::NEIGH as u32;
pub const RTNLGRP_TC: u32		= RtnetlinkGroups::TC as u32;
pub const RTNLGRP_IPV4_IFADDR: u32	= RtnetlinkGroups::IPV4_IFADDR as u32;
pub const RTNLGRP_IPV4_MROUTE: u32	= RtnetlinkGroups::IPV4_MROUTE as u32;
pub const RTNLGRP_IPV4_ROUTE: u32	= RtnetlinkGroups::IPV4_ROUTE as u32;
pub const RTNLGRP_IPV4_RULE: u32	= RtnetlinkGroups::IPV4_RULE as u32;
pub const RTNLGRP_IPV6_IFADDR: u32	= RtnetlinkGroups::IPV6_IFADDR as u32;
pub const RTNLGRP_IPV6_MROUTE: u32	= RtnetlinkGroups::IPV6_MROUTE as u32;
pub const RTNLGRP_IPV6_ROUTE: u32	= RtnetlinkGroups::IPV6_ROUTE as u32;
pub const RTNLGRP_IPV6_IFINFO: u32	= RtnetlinkGroups::IPV6_IFINFO as u32;
#[allow(non_upper_case_globals)]
pub const RTNLGRP_DECnet_IFADDR: u32	= RtnetlinkGroups::DECnet_IFADDR as u32;
pub const RTNLGRP_NOP2: u32		= RtnetlinkGroups::NOP2 as u32;
#[allow(non_upper_case_globals)]
pub const RTNLGRP_DECnet_ROUTE: u32	= RtnetlinkGroups::DECnet_ROUTE as u32;
#[allow(non_upper_case_globals)]
pub const RTNLGRP_DECnet_RULE: u32	= RtnetlinkGroups::DECnet_RULE as u32;
pub const RTNLGRP_NOP4: u32		= RtnetlinkGroups::NOP4 as u32;
pub const RTNLGRP_IPV6_PREFIX: u32	= RtnetlinkGroups::IPV6_PREFIX as u32;
pub const RTNLGRP_IPV6_RULE: u32	= RtnetlinkGroups::IPV6_RULE as u32;
pub const RTNLGRP_ND_USEROPT: u32	= RtnetlinkGroups::ND_USEROPT as u32;
pub const RTNLGRP_PHONET_IFADDR: u32	= RtnetlinkGroups::PHONET_IFADDR as u32;
pub const RTNLGRP_PHONET_ROUTE: u32	= RtnetlinkGroups::PHONET_ROUTE as u32;
pub const RTNLGRP_DCB: u32		= RtnetlinkGroups::DCB as u32;
pub const RTNLGRP_IPV4_NETCONF: u32	= RtnetlinkGroups::IPV4_NETCONF as u32;
pub const RTNLGRP_IPV6_NETCONF: u32	= RtnetlinkGroups::IPV6_NETCONF as u32;
pub const RTNLGRP_MDB: u32		= RtnetlinkGroups::MDB as u32;
pub const RTNLGRP_MPLS_ROUTE: u32	= RtnetlinkGroups::MPLS_ROUTE as u32;
pub const RTNLGRP_NSID: u32		= RtnetlinkGroups::NSID as u32;
pub const RTNLGRP_MAX: u32		= RtnetlinkGroups::_MAX as u32 - 1;

// TC action piece
#[allow(non_snake_case)]
#[repr(C)]
pub struct Tcamsg {
    pub tca_family: u8,	// ::std::os::raw::c_uchar,
    pub tca__pad1: u8,	// ::std::os::raw::c_uchar,
    pub tca__pad2: u16,	// ::std::os::raw::c_ushort,
}

#[allow(non_snake_case)]
pub fn TA_RTA(r: &mut Tcamsg) -> &mut Rtattr {
    unsafe {
        ((r as *mut _ as *mut u8)
         .offset(netlink::NLMSG_ALIGN(size_of::<Tcamsg>() as u32) as isize) as *mut Rtattr)
            .as_mut()
    }.unwrap()
}
#[allow(non_snake_case)]
pub fn TA_PAYLOAD(n: &netlink::Nlmsghdr) -> u32 {
    netlink::NLMSG_PAYLOAD(n, size_of::<Tcamsg>() as u32)
}
pub const TCA_ACT_TAB: u16	= 1;	// attr type must be >=1
pub const TCAA_MAX: u16		= 1;

// New extended info filters for IFLA_EXT_MASK
pub const RTEXT_FILTER_VF: u32			= (1 << 0);
pub const RTEXT_FILTER_BRVLAN: u32		= (1 << 1);
pub const RTEXT_FILTER_BRVLAN_COMPRESSED: u32	= (1 << 2);
pub const RTEXT_FILTER_SKIP_STATS: u32		= (1 << 3);

// End of information exported to user level

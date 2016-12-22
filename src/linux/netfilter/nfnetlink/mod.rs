use linux::netlink;

#[repr(C)]
pub struct Nfattr {
    pub nfa_len: u16,
    pub nfa_type: u16,
}

#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum Groups {
    NONE			= 0,
    CONNTRACK_NEW		= 1,
    CONNTRACK_UPDATE		= 2,
    CONNTRACK_DESTROY		= 3,
    CONNTRACK_EXP_NEW		= 4,
    CONNTRACK_EXP_UPDATE	= 5,
    CONNTRACK_EXP_DESTROY	= 6,
    NFTABLES			= 7,
    ACCT_QUOTA			= 8,
    NFTRACE			= 9,
    _MAX			= 10,
}

pub const GRP_NONE: u32 			= Groups::NONE as u32;
pub const GRP_CONNTRACK_NEW: u32		= Groups::CONNTRACK_NEW as u32;
pub const GRP_CONNTRACK_UPDATE: u32		= Groups::CONNTRACK_UPDATE as u32;
pub const GRP_CONNTRACK_DESTROY: u32	= Groups::CONNTRACK_DESTROY as u32;
pub const GRP_CONNTRACK_EXP_NEW: u32	= Groups::CONNTRACK_EXP_NEW as u32;
pub const GRP_CONNTRACK_EXP_UPDATE: u32	= Groups::CONNTRACK_EXP_UPDATE as u32;
pub const GRP_CONNTRACK_EXP_DESTROY: u32  	= Groups::CONNTRACK_EXP_DESTROY as u32;
pub const GRP_NFTABLES: u32			= Groups::NFTABLES as u32;
pub const GRP_ACCT_QUOTA: u32		= Groups::ACCT_QUOTA as u32;
pub const GRP_NFTRACE: u32			= Groups::NFTRACE as u32;
pub const GRP_MAX: u32			= Groups::_MAX as u32 - 1;

// General form of address family dependent message.
#[repr(C)]
pub struct Nfgenmsg {
    pub nfgen_family: u8,	// AF_xxx
    pub version: u8,            // nfnetlink version
    pub res_id: u16,            // resource id
}

pub const NFNETLINK_V0: u8 = 0;

// netfilter netlink message types are split in two pieces:
// 8 bit subsystem, 8bit operation.

#[allow(non_snake_case)]
pub fn SUBSYS_ID(x: u16) -> u16 {
    (x & 0xff00) >> 8
}
#[allow(non_snake_case)]
pub fn MSG_TYPE(x: u16) -> u8 {
    (x as u8)
}

// No enum here, otherwise __stringify() trick of MODULE_ALIAS_NFNL_SUBSYS()
// won't work anymore
pub const SUBSYS_NONE: u16			= 0;
pub const SUBSYS_CTNETLINK: u16		= 1;
pub const SUBSYS_CTNETLINK_EXP: u16	= 2;
pub const SUBSYS_QUEUE: u16		= 3;
pub const SUBSYS_ULOG: u16			= 4;
pub const SUBSYS_OSF: u16			= 5;
pub const SUBSYS_IPSET: u16		= 6;
pub const SUBSYS_ACCT: u16			= 7;
pub const SUBSYS_CTNETLINK_TIMEOUT: u16	= 8;
pub const SUBSYS_CTHELPER: u16		= 9;
pub const SUBSYS_NFTABLES: u16		= 10;
pub const SUBSYS_NFT_COMPAT: u16		= 11;
pub const SUBSYS_COUNT: u16		= 12;

// Reserved control nfnetlink messages
pub const MSG_BATCH_BEGIN: u16		= netlink::NLMSG_MIN_TYPE;
pub const MSG_BATCH_END: u16		= netlink::NLMSG_MIN_TYPE + 1;

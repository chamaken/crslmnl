// This file describes the netlink messages (i.e. 'protocol packets'),
// and not any kind of function definitions.  It is shared between kernel and
// userspace.  Don't put kernel specific stuff in here

#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum MsgTypes {
    PACKET = 0,		// packet from kernel to userspace
    CONFIG = 1,		// connect to a particular queue
    MAX = 2,
}

#[repr(C)]
pub struct MsgPacketHdr {
    pub hw_protocol: u16,	// hw protocol (network order)
    pub hook: u8,		// netfilter hook
    pub _pad: u8,
}

#[repr(C)]
pub struct MsgPacketHw {
    pub hw_addrlen: u16,
    pub _pad: u16,
    pub hw_addr: [u8; 8usize],
}

#[repr(C)]
pub struct MsgPacketTimestamp {
    pub sec: u64,
    pub usec: u64,
}

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum AttrType {
    UNSPEC		= 0,
    PACKET_HDR		= 1,
    MARK		= 2,	// __u32 nfmark
    TIMESTAMP		= 3,	// nfulnl_msg_packet_timestamp
    IFINDEX_INDEV	= 4,	// __u32 ifindex
    IFINDEX_OUTDEV	= 5,	// __u32 ifindex
    IFINDEX_PHYSINDEV	= 6,	// __u32 ifindex
    IFINDEX_PHYSOUTDEV	= 7,	// __u32 ifindex
    HWADDR		= 8,	// nfulnl_msg_packet_hw
    PAYLOAD		= 9,	// opaque data payload
    PREFIX		= 10,	// string prefix
    UID			= 11,	// user id of socket
    SEQ			= 12,	// instance-local sequence number
    SEQ_GLOBAL		= 13,	// global sequence number
    GID			= 14,	// group id of socket
    HWTYPE		= 15,	// hardware type
    HWHEADER		= 16,	// hardware header
    HWLEN		= 17,	// hardware header length
    CT			= 18,	// nf_conntrack_netlink.h
    CT_INFO		= 19,	// enum ip_conntrack_info
    _MAX		= 20,
}
// pub const ATTR_TYPE_MAX: u16 = AttrType::_MAX as u16 - 1;
pub const NFULA_MAX: u16 = 20 - 1;

#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum MsgConfigCmds {
    NONE	= 0,
    BIND	= 1,
    UNBIND	= 2,
    PF_BIND	= 3,
    PF_UNBIND	= 4,
}

#[repr(C, packed)]
pub struct MsgConfigCmd {
    pub command: u8,	// nfulnl_msg_config_cmds
}

#[repr(C, packed)]
pub struct MsgConfigMode {
    pub copy_range: u32,
    pub copy_mode: u8,
    pub _pad: u8,
}

#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum AttrConfig {
    UNSPEC	= 0,
    CMD		= 1,	// nfulnl_msg_config_cmd
    MODE	= 2,	// nfulnl_msg_config_mode
    NLBUFSIZ	= 3,	// __u32 buffer size
    TIMEOUT	= 4,	// __u32 in 1/100 s
    QTHRESH	= 5,	// __u32
    FLAGS	= 6,	// __u16
    _MAX	= 7,
}
pub const ATTR_CONFIG_MAX: u32 = AttrConfig::_MAX as u32 - 1;

pub const COPY_NONE: u8		= 0x00;
pub const COPY_META: u8		= 0x01;
pub const COPY_PACKET: u8	= 0x02;
// 0xff is reserved, don't use it for new copy modes.

pub const CFG_F_SEQ: u16	= 0x0001;
pub const CFG_F_SEQ_GLOBAL: u16	= 0x0002;
pub const CFG_F_CONNTRACK: u16	= 0x0004;

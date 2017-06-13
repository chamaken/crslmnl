#[allow(non_camel_case_types)]
#[repr(usize)]
pub enum MsgTypes {
    PACKET		= 0,	// packet from kernel to userspace
    VERDICT		= 1,	// verdict from userspace to kernel
    CONFIG		= 2,    // connect to a particular queue
    VERDICT_BATCH	= 3,    // batchv from userspace to kernel
    MAX			= 4,
}
pub const NFQNL_MSG_PACKET: usize		= MsgTypes::PACKET as usize;
pub const NFQNL_MSG_VERDICT: usize		= MsgTypes::VERDICT as usize;
pub const NFQNL_MSG_CONFIG: usize		= MsgTypes::CONFIG as usize;
pub const NFQNL_MSG_VERDICT_BATCH: usize	= MsgTypes::VERDICT_BATCH as usize;
pub const NFQNL_MSG_MAX: usize			= MsgTypes::MAX as usize;

#[repr(C, packed)]
pub struct MsgPacketHdr {
    pub packet_id: u32,		// unique ID of packet in queue
    pub hw_protocol: u16,       // hw protocol (network order)
    pub hook: u8,               // netfilter hook
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

#[repr(u16)]
pub enum VlanAttr {
    UNSPEC	= 0,
    PROTO	= 1,	// __be16 skb vlan_proto
    TCI		= 2,    // __be16 skb htons(vlan_tci)
    _MAX	= 3,
}
pub const NFQA_VLAN_UNSPEC: u16	= VlanAttr::UNSPEC as u16;
pub const NFQA_VLAN_PROTO: u16	= VlanAttr::PROTO as u16;
pub const NFQA_VLAN_TCI: u16	= VlanAttr::TCI as u16;
pub const __NFQA_VLAN_MAX: u16	= VlanAttr::_MAX as u16;
pub const NFQA_VLAN_MAX: u16 = __NFQA_VLAN_MAX - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum AttrType {
    UNSPEC		= 0,
    PACKET_HDR		= 1,
    VERDICT_HDR		= 2,	// nfqnl_msg_verdict_hrd
    MARK		= 3,    // __u32 nfmark
    TIMESTAMP		= 4,    // nfqnl_msg_packet_timestamp
    IFINDEX_INDEV	= 5,    // __u32 ifindex
    IFINDEX_OUTDEV	= 6,    // __u32 ifindex
    IFINDEX_PHYINDEV	= 7,    // __u32 ifindex
    IFINDEX_PHYOUTDEV	= 8,    // __u32 ifindex
    HWADDR		= 9,    // nfqnl_msg_packet_hw
    PAYLOAD		= 10,   // opaque data payload
    CT			= 11,   // nf_conntrack_netlink.h
    CT_INFO		= 12,   // enum ip_conntrack_info
    CAP_LEN		= 13,   // __u32 length of captured packet
    SKB_INFO		= 14,   // __u32 skb meta information
    EXP			= 15,   // nf_conntrack_netlink.h
    UID			= 16,   // __u32 sk uid
    GID			= 17,   // __u32 sk gid
    SECCTX		= 18,   // security context string
    VLAN		= 19,   // nested attribute: packet vlan info
    L2HDR		= 20,   // full L2 header
    _MAX		= 21,
}
pub const NFQA_UNSPEC: u16		= AttrType::UNSPEC as u16;
pub const NFQA_PACKET_HDR: u16		= AttrType::PACKET_HDR as u16;
pub const NFQA_VERDICT_HDR: u16		= AttrType::VERDICT_HDR as u16;
pub const NFQA_MARK: u16		= AttrType::MARK as u16;
pub const NFQA_TIMESTAMP: u16		= AttrType::TIMESTAMP as u16;
pub const NFQA_IFINDEX_INDEV: u16	= AttrType::IFINDEX_INDEV as u16;
pub const NFQA_IFINDEX_OUTDEV: u16	= AttrType::IFINDEX_OUTDEV as u16;
pub const NFQA_IFINDEX_PHYSINDEV: u16	= AttrType::IFINDEX_PHYINDEV as u16;
pub const NFQA_IFINDEX_PHYSOUTDEV: u16	= AttrType::IFINDEX_PHYOUTDEV as u16;
pub const NFQA_HWADDR: u16		= AttrType::HWADDR as u16;
pub const NFQA_PAYLOAD: u16		= AttrType::PAYLOAD as u16;
pub const NFQA_CT: u16			= AttrType::CT as u16;
pub const NFQA_CT_INFO: u16		= AttrType::CT_INFO as u16;
pub const NFQA_CAP_LEN: u16		= AttrType::CAP_LEN as u16;
pub const NFQA_SKB_INFO: u16		= AttrType::SKB_INFO as u16;
pub const NFQA_EXP: u16			= AttrType::EXP as u16;
pub const NFQA_UID: u16			= AttrType::UID as u16;
pub const NFQA_GID: u16			= AttrType::GID as u16;
pub const NFQA_SECCTX: u16		= AttrType::SECCTX as u16;
pub const NFQA_VLAN: u16		= AttrType::VLAN as u16;
pub const NFQA_L2HDR: u16		= AttrType::L2HDR as u16;
pub const __NFQA_MAX: u16		= AttrType::_MAX as u16;
pub const NFQA_MAX: u16			= __NFQA_MAX - 1;

#[repr(C)]
pub struct MsgVerdictHdr {
    pub verdict: u32,
    pub id: u32,
}

#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum MsgConfigCmds {
    NONE	= 0,
    BIND	= 1,
    UNBIND	= 2,
    PF_BIND	= 3,
    PF_UNBIND	= 4,
}

#[derive(Default)]
#[repr(C)]
pub struct MsgConfigCmd {
    pub command: u8,	// nfqnl_msg_config_cmds
    pub _pad: u8,
    pub pf: u16,	// AF_xxx for PF_[UN]BIND
}

#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum ConfigMode {
    COPY_NONE	= 0,
    COPY_META	= 1,
    COPY_PACKET	= 2,
}

#[repr(C, packed)]
pub struct MsgConfigParams {
    pub copy_range: u32,
    pub copy_mode: u8,		// enum nfqnl_config_mode
}

#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum AttrConfig {
    UNSPEC		= 0,
    CMD			= 1,	// nfqnl_msg_config_cmd
    PARAMS		= 2,    // nfqnl_msg_config_params
    QUEUE_MAXLEN	= 3,    // __u32
    MASK		= 4,    // identify which flags to change
    FLAGS		= 5,    // value of these flags (__u32)
    _MAX		= 6,
}
pub const NFQA_CFG_UNSPEC: u32		= AttrConfig::UNSPEC as u32;
pub const NFQA_CFG_CMD: u32		= AttrConfig::CMD as u32;
pub const NFQA_CFG_PARAMS: u32		= AttrConfig::PARAMS as u32;
pub const NFQA_CFG_QUEUE_MAXLEN: u32	= AttrConfig::QUEUE_MAXLEN as u32;
pub const NFQA_CFG_MASK: u32		= AttrConfig::MASK as u32;
pub const NFQA_CFG_FLAGS: u32		= AttrConfig::FLAGS as u32;
pub const __NFQA_CFG_MAX: u32		= AttrConfig::_MAX as u32;
pub const NFQA_CFG_MAX: u32 		= __NFQA_CFG_MAX - 1;

// Flags for NFQA_CFG_FLAGS
pub const NFQA_CFG_F_FAIL_OPEN: u32	= (1 << 0);
pub const NFQA_CFG_F_CONNTRACK: u32	= (1 << 1);
pub const NFQA_CFG_F_GSO: u32	= (1 << 2);
pub const NFQA_CFG_F_UID_GID: u32	= (1 << 3);
pub const NFQA_CFG_F_SECCTX: u32	= (1 << 4);
pub const NFQA_CFG_F_MAX: u32	= (1 << 5);

// flags for NFQA_SKB_INFO
// packet appears to have wrong checksums, but they are ok
pub const NFQA_SKB_CSUMNOTREADY: u32 = (1 << 0);
// packet is GSO (i.e., exceeds device mtu)
pub const NFQA_SKB_GSO: u32 = (1 << 1);
// csum not validated (incoming device doesn't support hw checksum, etc.)
pub const NFQA_SKB_CSUM_NOTVERIFIED: u32 =  (1 << 2);

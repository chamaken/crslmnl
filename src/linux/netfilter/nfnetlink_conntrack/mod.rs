#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum CtnlMsgTypes {
    NEW			= 0,
    GET			= 1,
    DELETE		= 2,
    GET_CTRZERO		= 3,
    GET_STATS_CPU	= 4,
    GET_STATS		= 5,
    GET_DYING		= 6,
    GET_UNCONFIRMED	= 7,
    MAX			= 8,
}
pub const IPCTNL_MSG_CT_NEW: u16		= CtnlMsgTypes::NEW as u16;
pub const IPCTNL_MSG_CT_GET: u16		= CtnlMsgTypes::GET as u16;
pub const IPCTNL_MSG_CT_DELETE: u16		= CtnlMsgTypes::DELETE as u16;
pub const IPCTNL_MSG_CT_GET_CTRZERO: u16	= CtnlMsgTypes::GET_CTRZERO as u16;
pub const IPCTNL_MSG_CT_GET_STATS_CPU: u16	= CtnlMsgTypes::GET_STATS_CPU as u16;
pub const IPCTNL_MSG_CT_GET_STATS: u16		= CtnlMsgTypes::GET_STATS as u16;
pub const IPCTNL_MSG_CT_GET_DYING: u16		= CtnlMsgTypes::GET_DYING as u16;
pub const IPCTNL_MSG_CT_GET_UNCONFIRMED: u16	= CtnlMsgTypes::GET_UNCONFIRMED as u16;
pub const IPCTNL_MSG_MAX: u16			= CtnlMsgTypes::MAX as u16;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum CtnlExpMsgTypes {
    NEW			= 0,
    GET			= 1,
    DELETE		= 2,
    GET_STATS_CPU	= 3,
    MAX			= 4,
}
pub const IPCTNL_MSG_EXP_NEW: u16		= CtnlExpMsgTypes::NEW as u16;
pub const IPCTNL_MSG_EXP_GET: u16		= CtnlExpMsgTypes::GET as u16;
pub const IPCTNL_MSG_EXP_DELETE: u16		= CtnlExpMsgTypes::DELETE as u16;
pub const IPCTNL_MSG_EXP_GET_STATS_CPU: u16	= CtnlExpMsgTypes::GET_STATS_CPU as u16;
pub const IPCTNL_MSG_EXP_MAX: u16		= CtnlExpMsgTypes::MAX as u16;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum CtattrType {
    UNSPEC		= 0,
    TUPLE_ORIG		= 1,
    TUPLE_REPLY		= 2,
    STATUS		= 3,
    PROTOINFO		= 4,
    HELP		= 5,
    NAT_SRC		= 6,
    TIMEOUT		= 7,
    MARK		= 8,
    COUNTERS_ORIG	= 9,
    COUNTERS_REPLY	= 10,
    USE			= 11,
    ID			= 12,
    NAT_DST		= 13,
    TUPLE_MASTER	= 14,
    SEQ_ADJ_ORIG	= 15,
    SEQ_ADJ_REPLY	= 16,
    SECMARK		= 17,	// obsolete
    ZONE		= 18,
    SECCTX		= 19,
    TIMESTAMP		= 20,
    MARK_MASK		= 21,
    LABELS		= 22,
    LABELS_MASK		= 23,
    _MAX		= 24,
}
pub const CTA_UNSPEC: u16		= CtattrType::UNSPEC as u16;
pub const CTA_TUPLE_ORIG: u16		= CtattrType::TUPLE_ORIG as u16;
pub const CTA_TUPLE_REPLY: u16		= CtattrType::TUPLE_REPLY as u16;
pub const CTA_STATUS: u16		= CtattrType::STATUS as u16;
pub const CTA_PROTOINFO: u16		= CtattrType::PROTOINFO as u16;
pub const CTA_HELP: u16			= CtattrType::HELP as u16;
pub const CTA_NAT_SRC: u16		= CtattrType::NAT_SRC as u16;
pub const CTA_NAT: u16			= CTA_NAT_SRC;				// backwards compatibility
pub const CTA_TIMEOUT: u16		= CtattrType::TIMEOUT as u16;
pub const CTA_MARK: u16			= CtattrType::MARK as u16;
pub const CTA_COUNTERS_ORIG: u16	= CtattrType::COUNTERS_ORIG as u16;
pub const CTA_COUNTERS_REPLY: u16	= CtattrType::COUNTERS_REPLY as u16;
pub const CTA_USE: u16			= CtattrType::USE as u16;
pub const CTA_ID: u16			= CtattrType::ID as u16;
pub const CTA_NAT_DST: u16		= CtattrType::NAT_DST as u16;
pub const CTA_TUPLE_MASTER: u16		= CtattrType::TUPLE_MASTER as u16;
pub const CTA_SEQ_ADJ_ORIG: u16		= CtattrType::SEQ_ADJ_ORIG as u16;
pub const CTA_NAT_SEQ_ADJ_ORIG:u16	= CTA_SEQ_ADJ_ORIG;
pub const CTA_SEQ_ADJ_REPLY: u16	= CtattrType::SEQ_ADJ_REPLY as u16;
pub const CTA_NAT_SEQ_ADJ_REPLY: u16	= CTA_SEQ_ADJ_REPLY;
pub const CTA_SECMARK: u16		= CtattrType::SECMARK as u16;
pub const CTA_ZONE: u16			= CtattrType::ZONE as u16;
pub const CTA_SECCTX: u16		= CtattrType::SECCTX as u16;
pub const CTA_TIMESTAMP: u16		= CtattrType::TIMESTAMP as u16;
pub const CTA_MARK_MASK: u16		= CtattrType::MARK_MASK as u16;
pub const CTA_LABELS: u16		= CtattrType::LABELS as u16;
pub const CTA_LABELS_MASK: u16		= CtattrType::LABELS_MASK as u16;
pub const __CTA_MAX: u16 		= 24u16; // CtattrType::_MAX as u16;
pub const CTA_MAX: u16 			= __CTA_MAX - 1;


#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum CtattrTuple {
    UNSPEC	= 0,
    IP		= 1,
    PROTO	= 2,
    ZONE	= 3,
    _MAX = 4,
}
pub const CTA_TUPLE_UNSPEC: u16	= CtattrTuple::UNSPEC as u16;
pub const CTA_TUPLE_IP: u16	= CtattrTuple::IP as u16;
pub const CTA_TUPLE_PROTO: u16	= CtattrTuple::PROTO as u16;
pub const CTA_TUPLE_ZONE: u16	= CtattrTuple::ZONE as u16;
pub const __CTA_TUPLE_MAX: u16	= 4; // CtattrTuple::_MAX as u16;
pub const CTA_TUPLE_MAX: u16	 = __CTA_TUPLE_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum CtattrIp {
    UNSPEC	= 0,
    V4_SRC	= 1,
    V4_DST	= 2,
    V6_SRC	= 3,
    V6_DST	= 4,
    _MAX	= 5,
}
pub const CTA_IP_UNSPEC: u16	= CtattrIp::UNSPEC as u16;
pub const CTA_IP_V4_SRC: u16	= CtattrIp::V4_SRC as u16;
pub const CTA_IP_V4_DST: u16	= CtattrIp::V4_DST as u16;
pub const CTA_IP_V6_SRC: u16	= CtattrIp::V6_SRC as u16;
pub const CTA_IP_V6_DST: u16	= CtattrIp::V6_DST as u16;
pub const __CTA_IP_MAX: u16	= 5u16; // CtattrIp::_MAX as u16;
pub const CTA_IP_MAX: u16	= __CTA_IP_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum CtattrL4proto {
    UNSPEC	= 0,
    NUM		= 1,
    SRC_PORT	= 2,
    DST_PORT	= 3,
    ICMP_ID	= 4,
    ICMP_TYPE	= 5,
    ICMP_CODE	= 6,
    ICMPV6_ID	= 7,
    ICMPV6_TYPE	= 8,
    ICMPV6_CODE	= 9,
    _MAX = 10,
}
pub const CTA_PROTO_UNSPEC: u16		= CtattrL4proto::UNSPEC as u16;
pub const CTA_PROTO_NUM: u16		= CtattrL4proto::NUM as u16;
pub const CTA_PROTO_SRC_PORT: u16	= CtattrL4proto::SRC_PORT as u16;
pub const CTA_PROTO_DST_PORT: u16	= CtattrL4proto::DST_PORT as u16;
pub const CTA_PROTO_ICMP_ID: u16	= CtattrL4proto::ICMP_ID as u16;
pub const CTA_PROTO_ICMP_TYPE: u16	= CtattrL4proto::ICMP_TYPE as u16;
pub const CTA_PROTO_ICMP_CODE: u16	= CtattrL4proto::ICMP_CODE as u16;
pub const CTA_PROTO_ICMPV6_ID: u16	= CtattrL4proto::ICMPV6_ID as u16;
pub const CTA_PROTO_ICMPV6_TYPE: u16	= CtattrL4proto::ICMPV6_TYPE as u16;
pub const CTA_PROTO_ICMPV6_CODE: u16	= CtattrL4proto::ICMPV6_CODE as u16;
pub const __CTA_PROTO_MAX: u16		= 10u16; // CtattrL4proto::_MAX as u16;
pub const CTA_PROTO_MAX: u16		= __CTA_PROTO_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum CtattrProtoinfo {
    UNSPEC	= 0,
    TCP		= 1,
    DCCP	= 2,
    SCTP	= 3,
    _MAX	= 4,
}
pub const CTA_PROTOINFO_UNSPEC: u16	= CtattrProtoinfo::UNSPEC as u16;
pub const CTA_PROTOINFO_TCP: u16	= CtattrProtoinfo::TCP as u16;
pub const CTA_PROTOINFO_DCCP: u16	= CtattrProtoinfo::DCCP as u16;
pub const CTA_PROTOINFO_SCTP: u16	= CtattrProtoinfo::SCTP as u16;
pub const __CTA_PROTOINFO_MAX: u16	= CtattrProtoinfo::_MAX as u16;
pub const CTA_PROTOINFO_MAX: u16	= __CTA_PROTOINFO_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum CtattrProtoinfoTcp {
    UNSPEC		= 0,
    STATE		= 1,
    WSCALE_ORIGINAL	= 2,
    WSCALE_REPLY	= 3,
    FLAGS_ORIGINAL	= 4,
    FLAGS_REPLY		= 5,
    _MAX		= 6,
}
pub const CTA_PROTOINFO_TCP_UNSPEC: u16			= CtattrProtoinfoTcp::UNSPEC as u16;
pub const CTA_PROTOINFO_TCP_STATE: u16			= CtattrProtoinfoTcp::STATE as u16;
pub const CTA_PROTOINFO_TCP_WSCALE_ORIGINAL: u16	= CtattrProtoinfoTcp::WSCALE_ORIGINAL as u16;
pub const CTA_PROTOINFO_TCP_WSCALE_REPLY: u16		= CtattrProtoinfoTcp::WSCALE_REPLY as u16;
pub const CTA_PROTOINFO_TCP_FLAGS_ORIGINAL: u16		= CtattrProtoinfoTcp::FLAGS_ORIGINAL as u16;
pub const CTA_PROTOINFO_TCP_FLAGS_REPLY: u16		= CtattrProtoinfoTcp::FLAGS_REPLY as u16;
pub const __CTA_PROTOINFO_TCP_MAX: u16			= CtattrProtoinfoTcp::_MAX as u16;
pub const CTA_PROTOINFO_TCP_MAX: u16			= __CTA_PROTOINFO_TCP_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum CtattrProtoinfoDccp {
    UNSPEC		= 0,
    STATE		= 1,
    ROLE		= 2,
    HANDSHAKE_SEQ	= 3,
    PAD			= 4,
    _MAX		= 5,
}
pub const CTA_PROTOINFO_DCCP_MAX: u16 = (CtattrProtoinfoDccp::_MAX as u16) - 1;
pub const CTA_PROTOINFO_DCCP_UNSPEC: u16	= CtattrProtoinfoDccp::UNSPEC as u16;
pub const CTA_PROTOINFO_DCCP_STATE: u16		= CtattrProtoinfoDccp::STATE as u16;
pub const CTA_PROTOINFO_DCCP_ROLE: u16		= CtattrProtoinfoDccp::ROLE as u16;
pub const CTA_PROTOINFO_DCCP_HANDSHAKE_SEQ: u16	= CtattrProtoinfoDccp::HANDSHAKE_SEQ as u16;
pub const CTA_PROTOINFO_DCCP_PAD: u16		= CtattrProtoinfoDccp::PAD as u16;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrProtoinfoSctp {
    UNSPEC = 0,
    STATE = 1,
    VTAG_ORIGINAL = 2,
    VTAG_REPLY = 3,
    _MAX = 4,
}
pub const CTA_PROTOINFO_SCTP_MAX: u16 = (AttrProtoinfoSctp::_MAX as u16) - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrCounters {
    UNSPEC	= 0,
    PACKETS	= 1,	// 64bit counters
    BYTES	= 2,    // 64bit counters
    PACKETS32	= 3,    // old 32bit counters, unused
    BYTES32	= 4,    // old 32bit counters, unused
    PAD		= 5,
    _MAX	= 6,
}
// unimplemented constant expression: enum variants
// pub const CTA_COUNTERS_MAX: u16 = (AttrCounters::_MAX as u16) - 1;
pub const CTA_COUNTERS_MAX: u16 = 6 - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrTstamp {
    UNSPEC	= 0,
    START	= 1,
    STOP	= 2,
    PAD		= 3,
    _MAX	= 4,
}
pub const CTA_TIMESTAMP_MAX: u16 = (AttrTstamp::_MAX as u16) - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrNat {
    UNSPEC	= 0,
    V4_MINIP	= 1,
    V4_MAXIP	= 2,
    PROTO	= 3,
    V6_MINIP	= 4,
    V6_MAXIP	= 5,
    _MAX	= 6,
}
pub const CTA_NAT_MAX: u16 = (AttrNat::_MAX as u16) - 1;
// XXX: look for avoiding: discriminant value '' already exists
pub const CTATTR_NAT_MINIP: AttrNat = AttrNat::V4_MINIP;
pub const CTATTR_NAT_MAXIP: AttrNat = AttrNat::V4_MAXIP;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrProtonat {
    UNSPEC	= 0,
    PORT_MIN	= 1,
    PORT_MAX	= 2,
    _MAX	= 3,
}
pub const CTA_PROTONAT_MAX: u16 = (AttrProtonat::_MAX as u16) - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrSeqadj {
    UNSPEC		= 0,
    CORRECTION_POS	= 1,
    OFFSET_BEFORE	= 2,
    OFFSET_AFTER	= 3,
    _MAX		= 4,
}
pub const CTA_SEQADJ_MAX: u16 = (AttrSeqadj::_MAX as u16) - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrNatseq {
    UNSPEC = 0,
    CORRECTION_POS = 1,
    OFFSET_BEFORE = 2,
    OFFSET_AFTER = 3,
    _MAX = 4,
}
pub const CTA_NAT_SEQ_MAX: u16 = (AttrNatseq::_MAX as u16) - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrExpect {
    UNSPEC	= 0,
    MASTER	= 1,
    TUPLE	= 2,
    MASK	= 3,
    TIMEOUT	= 4,
    ID		= 5,
    HELP_NAME	= 6,
    ZONE	= 7,
    FLAGS	= 8,
    CLASS	= 9,
    NAT		= 10,
    FN		= 11,
    _MAX	= 12,
}
pub const CTA_EXPECT_MAX: u16 = (AttrExpect::_MAX as u16) - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum AttrExpectNat {
    UNSPEC	= 0,
    DIR		= 1,
    TUPLE	= 2,
    _MAX	= 3,
}
pub const CTA_EXPECT_NAT_MAX: u16 = (AttrExpectNat::_MAX as u16) - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrHelp {
    UNSPEC	= 0,
    NAME	= 1,
    INFO	= 2,
    _MAX	= 3,
}
pub const CTA_HELP_MAX: u16 = (AttrHelp::_MAX as u16) - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrSecctx {
    UNSPEC	= 0,
    NAME	= 1,
    _MAX	= 2,
}
pub const CTA_SECCTX_MAX: u16 = (AttrSecctx::_MAX as u16) - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrStatsCpu {
    UNSPEC		= 0,
    SEARCHED		= 1,	// no longer used
    FOUND		= 2,
    NEW			= 3,	// no longer used
    INVALID		= 4,
    IGNORE		= 5,
    DELETE		= 6,	// no longer used
    DELETE_LIST		= 7,	// no longer used
    INSERT		= 8,
    INSERT_FAILED 	= 9,
    DROP		= 10,
    EARLY_DROP		= 11,
    ERROR		= 12,
    SEARCH_RESTART	= 13,
    _MAX		= 14,
}
pub const CTA_STATS_MAX: u16 = (AttrStatsCpu::_MAX as u16) - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrStatsGlobal {
    UNSPEC	= 0,
    ENTRIES	= 1,
    _MAX	= 2,
}
pub const CTA_STATS_GLOBAL: u16 = (AttrStatsGlobal::_MAX as u16) - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrExpectStats {
    UNSPEC	= 0,
    NEW		= 1,
    CREATE	= 2,
    DELETE	= 3,
    _MAX	= 4,
}
pub const CTA_STATS_EXP_MAX: u16 = (AttrExpectStats::_MAX as u16) - 1;

// XXX: copy only NF_NETLINK_ from nfnetlink_compat.h
// Old nfnetlink macros for userspace */
// nfnetlink groups: Up to 32 maximum
pub const NF_NETLINK_CONNTRACK_NEW: u32		= 0x00000001;
pub const NF_NETLINK_CONNTRACK_UPDATE: u32	= 0x00000002;
pub const NF_NETLINK_CONNTRACK_DESTROY: u32	= 0x00000004;
pub const NF_NETLINK_CONNTRACK_EXP_NEW: u32	= 0x00000008;
pub const NF_NETLINK_CONNTRACK_EXP_UPDATE: u32	= 0x00000010;
pub const NF_NETLINK_CONNTRACK_EXP_DESTROY: u32	= 0x00000020;

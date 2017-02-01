#[allow(non_camel_case_types)]
#[repr(u16)]
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
#[repr(u16)]
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
#[repr(u16)]
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
pub const CTA_NAT: u16			= CTA_NAT_SRC;			// backwards compatibility
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
// pub const CTA_MAX: u16		= CtattrType::_MAX as u16 - 1;
pub const CTA_MAX: u16 			= 24 - 1;


#[allow(non_camel_case_types)]
#[repr(u16)]
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
// pub const CTA_TUPLE_MAX: u16	= CtattrTuple::_MAX as u16 - 1;
pub const CTA_TUPLE_MAX: u16	 = 4 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
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
// pub const CTA_IP_MAX: u16	= CtattrIp::_MAX as u16 - 1;
pub const CTA_IP_MAX: u16	= 5 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
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
// pub const CTA_PROTO_MAX: u16		= CtattrL4proto::_MAX as u16 - 1;
pub const CTA_PROTO_MAX: u16		= 10 - 1;

#[allow(non_camel_case_types)]
#[repr(u32)]
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
#[repr(u16)]
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
#[repr(u16)]
pub enum CtattrProtoinfoDccp {
    UNSPEC		= 0,
    STATE		= 1,
    ROLE		= 2,
    HANDSHAKE_SEQ	= 3,
    PAD			= 4,
    _MAX		= 5,
}
pub const CTA_PROTOINFO_DCCP_UNSPEC: u16	= CtattrProtoinfoDccp::UNSPEC as u16;
pub const CTA_PROTOINFO_DCCP_STATE: u16		= CtattrProtoinfoDccp::STATE as u16;
pub const CTA_PROTOINFO_DCCP_ROLE: u16		= CtattrProtoinfoDccp::ROLE as u16;
pub const CTA_PROTOINFO_DCCP_HANDSHAKE_SEQ: u16	= CtattrProtoinfoDccp::HANDSHAKE_SEQ as u16;
pub const CTA_PROTOINFO_DCCP_PAD: u16		= CtattrProtoinfoDccp::PAD as u16;
pub const CTA_PROTOINFO_DCCP_MAX: u16		= CtattrProtoinfoDccp::_MAX as u16 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtattrProtoinfoSctp {
    UNSPEC		= 0,
    STATE		= 1,
    VTAG_ORIGINAL	= 2,
    VTAG_REPLY		= 3,
    _MAX		= 4,
}
pub const CTA_PROTOINFO_SCTP_UNSPEC: u16	= CtattrProtoinfoSctp::UNSPEC as u16;
pub const CTA_PROTOINFO_SCTP_STATE: u16		= CtattrProtoinfoSctp::STATE as u16;
pub const CTA_PROTOINFO_SCTP_VTAG_ORIGINAL: u16	= CtattrProtoinfoSctp::VTAG_ORIGINAL as u16;
pub const CTA_PROTOINFO_SCTP_VTAG_REPLY: u16	= CtattrProtoinfoSctp::VTAG_REPLY as u16;
pub const CTA_PROTOINFO_SCTP_MAX: u16		= (CtattrProtoinfoSctp::_MAX as u16) - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtattrCounters {
    UNSPEC	= 0,
    PACKETS	= 1,	// 64bit counters
    BYTES	= 2,    // 64bit counters
    PACKETS32	= 3,    // old 32bit counters, unused
    BYTES32	= 4,    // old 32bit counters, unused
    PAD		= 5,
    _MAX	= 6,
}
pub const CTA_COUNTERS_UNSPEC: u16	= CtattrCounters::UNSPEC as u16;
pub const CTA_COUNTERS_PACKETS: u16	= CtattrCounters::PACKETS as u16;
pub const CTA_COUNTERS_BYTES: u16	= CtattrCounters::BYTES as u16;
pub const CTA_COUNTERS32_PACKETS: u16	= CtattrCounters::PACKETS32 as u16;
pub const CTA_COUNTERS32_BYTES: u16	= CtattrCounters::BYTES32 as u16;
pub const CTA_COUNTERS_PAD: u16		= CtattrCounters::PAD as u16;
// pub const CTA_COUNTERS_MAX: u16	= (CtattrCounters::_MAX as u16) - 1;
pub const CTA_COUNTERS_MAX: u16		= 6 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtattrTstamp {
    UNSPEC	= 0,
    START	= 1,
    STOP	= 2,
    PAD		= 3,
    _MAX	= 4,
}
pub const CTA_TIMESTAMP_UNSPEC: u16	= CtattrTstamp::UNSPEC as u16;
pub const CTA_TIMESTAMP_START: u16	= CtattrTstamp::START as u16;
pub const CTA_TIMESTAMP_STOP: u16	= CtattrTstamp::STOP as u16;
pub const CTA_TIMESTAMP_PAD: u16	= CtattrTstamp::PAD as u16;
pub const CTA_TIMESTAMP_MAX: u16	= CtattrTstamp::_MAX as u16 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtattrNat {
    UNSPEC	= 0,
    V4_MINIP	= 1,
    V4_MAXIP	= 2,
    PROTO	= 3,
    V6_MINIP	= 4,
    V6_MAXIP	= 5,
    _MAX	= 6,
}
pub const CTA_NAT_UNSPEC: u16	= CtattrNat::UNSPEC as u16;
pub const CTA_NAT_V4_MINIP: u16	= CtattrNat::V4_MINIP as u16;
pub const CTATTR_NAT_MINIP: u16	= CTA_NAT_V4_MINIP;
pub const CTA_NAT_V4_MAXIP: u16	= CtattrNat::V4_MAXIP as u16;
pub const CTATTR_NAT_MAXIP: u16	= CTA_NAT_V4_MAXIP;
pub const CTA_NAT_PROTO: u16	= CtattrNat::PROTO as u16;
pub const CTA_NAT_V6_MINIP: u16	= CtattrNat::V6_MINIP as u16;
pub const CTA_NAT_V6_MAXIP: u16	= CtattrNat::V6_MAXIP as u16;
pub const CTA_NAT_MAX: u16	= CtattrNat::_MAX as u16 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtattrProtonat {
    UNSPEC	= 0,
    PORT_MIN	= 1,
    PORT_MAX	= 2,
    _MAX	= 3,
}
pub const CTA_PROTONAT_UNSPEC: u16	= CtattrProtonat::UNSPEC as u16;
pub const CTA_PROTONAT_PORT_MIN: u16	= CtattrProtonat::PORT_MIN as u16;
pub const CTA_PROTONAT_PORT_MAX: u16	= CtattrProtonat::PORT_MAX as u16;
pub const CTA_PROTONAT_MAX: u16		= CtattrProtonat::_MAX as u16 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtattrSeqadj {
    UNSPEC		= 0,
    CORRECTION_POS	= 1,
    OFFSET_BEFORE	= 2,
    OFFSET_AFTER	= 3,
    _MAX		= 4,
}
pub const CTA_SEQADJ_UNSPEC: u16		= CtattrSeqadj::UNSPEC as u16;
pub const CTA_SEQADJ_CORRECTION_POS: u16	= CtattrSeqadj::CORRECTION_POS as u16;
pub const CTA_SEQADJ_OFFSET_BEFORE: u16		= CtattrSeqadj::OFFSET_BEFORE as u16;
pub const CTA_SEQADJ_OFFSET_AFTER: u16		= CtattrSeqadj::OFFSET_AFTER as u16;
pub const CTA_SEQADJ_MAX: u16			= CtattrSeqadj::_MAX as u16 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtattrNatseq {
    UNSPEC		= 0,
    CORRECTION_POS	= 1,
    OFFSET_BEFORE	= 2,
    OFFSET_AFTER	= 3,
    _MAX		= 4,
}
pub const CTA_NAT_SEQ_UNSPEC: u16		= CtattrNatseq::UNSPEC as u16;
pub const CTA_NAT_SEQ_CORRECTION_POS: u16	= CtattrNatseq::CORRECTION_POS as u16;
pub const CTA_NAT_SEQ_OFFSET_BEFORE: u16	= CtattrNatseq::OFFSET_BEFORE as u16;
pub const CTA_NAT_SEQ_OFFSET_AFTER: u16		= CtattrNatseq::OFFSET_AFTER as u16;
pub const CTA_NAT_SEQ_MAX: u16			= CtattrNatseq::_MAX as u16 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtattrExpect {
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
pub const CTA_EXPECT_UNSPEC: u16	= CtattrExpect::UNSPEC as u16;
pub const CTA_EXPECT_MASTER: u16	= CtattrExpect::MASTER as u16;
pub const CTA_EXPECT_TUPLE: u16		= CtattrExpect::TUPLE as u16;
pub const CTA_EXPECT_MASK: u16		= CtattrExpect::MASK as u16;
pub const CTA_EXPECT_TIMEOUT: u16	= CtattrExpect::TIMEOUT as u16;
pub const CTA_EXPECT_ID: u16		= CtattrExpect::ID as u16;
pub const CTA_EXPECT_HELP_NAME: u16	= CtattrExpect::HELP_NAME as u16;
pub const CTA_EXPECT_ZONE: u16		= CtattrExpect::ZONE as u16;
pub const CTA_EXPECT_FLAGS: u16		= CtattrExpect::FLAGS as u16;
pub const CTA_EXPECT_CLASS: u16		= CtattrExpect::CLASS as u16;
pub const CTA_EXPECT_NAT: u16		= CtattrExpect::NAT as u16;
pub const CTA_EXPECT_FN: u16		= CtattrExpect::FN as u16;
pub const CTA_EXPECT_MAX: u16		= CtattrExpect::_MAX as u16 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtattrExpectNat {
    UNSPEC	= 0,
    DIR		= 1,
    TUPLE	= 2,
    _MAX	= 3,
}
pub const CTA_EXPECT_NAT_UNSPEC: u16	= CtattrExpectNat::UNSPEC as u16;
pub const CTA_EXPECT_NAT_DIR: u16	= CtattrExpectNat::DIR as u16;
pub const CTA_EXPECT_NAT_TUPLE: u16	= CtattrExpectNat::TUPLE as u16;
pub const CTA_EXPECT_NAT_MAX: u16	= CtattrExpectNat::_MAX as u16 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtattrHelp {
    UNSPEC	= 0,
    NAME	= 1,
    INFO	= 2,
    _MAX	= 3,
}
pub const CTA_HELP_UNSPEC: u16	= CtattrHelp::UNSPEC as u16;
pub const CTA_HELP_NAME: u16	= CtattrHelp::NAME as u16;
pub const CTA_HELP_INFO: u16	= CtattrHelp::INFO as u16;
pub const CTA_HELP_MAX: u16	= CtattrHelp::_MAX as u16 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtattrSecctx {
    UNSPEC	= 0,
    NAME	= 1,
    _MAX	= 2,
}
pub const CTA_SECCTX_UNSPEC: u16	= CtattrSecctx::UNSPEC as u16;
pub const CTA_SECCTX_NAME: u16		= CtattrSecctx::NAME as u16;
pub const CTA_SECCTX_MAX: u16		= CtattrSecctx::_MAX as u16 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtattrStatsCpu {
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
pub const CTA_STATS_UNSPEC: u16		= CtattrStatsCpu::UNSPEC as u16;
pub const CTA_STATS_SEARCHED: u16	= CtattrStatsCpu::SEARCHED as u16;
pub const CTA_STATS_FOUND: u16		= CtattrStatsCpu::FOUND as u16;
pub const CTA_STATS_NEW: u16		= CtattrStatsCpu::NEW as u16;
pub const CTA_STATS_INVALID: u16	= CtattrStatsCpu::INVALID as u16;
pub const CTA_STATS_IGNORE: u16		= CtattrStatsCpu::IGNORE as u16;
pub const CTA_STATS_DELETE: u16		= CtattrStatsCpu::DELETE as u16;
pub const CTA_STATS_DELETE_LIST: u16	= CtattrStatsCpu::DELETE_LIST as u16;
pub const CTA_STATS_INSERT: u16		= CtattrStatsCpu::INSERT as u16;
pub const CTA_STATS_INSERT_FAILED: u16	= CtattrStatsCpu::INSERT_FAILED as u16;
pub const CTA_STATS_DROP: u16		= CtattrStatsCpu::DROP as u16;
pub const CTA_STATS_EARLY_DROP: u16	= CtattrStatsCpu::EARLY_DROP as u16;
pub const CTA_STATS_ERROR: u16		= CtattrStatsCpu::ERROR as u16;
pub const CTA_STATS_SEARCH_RESTART: u16	= CtattrStatsCpu::SEARCH_RESTART as u16;
pub const CTA_STATS_MAX: u16		= CtattrStatsCpu::_MAX as u16 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtattrStatsGlobal {
    UNSPEC	= 0,
    ENTRIES	= 1,
    _MAX	= 2,
}
pub const CTA_STATS_GLOBAL_UNSPEC: u16	= CtattrStatsGlobal::UNSPEC as u16;
pub const CTA_STATS_GLOBAL_ENTRIES: u16	= CtattrStatsGlobal::ENTRIES as u16;
pub const CTA_STATS_GLOBAL: u16		= CtattrStatsGlobal::_MAX as u16 - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtattrExpectStats {
    UNSPEC	= 0,
    NEW		= 1,
    CREATE	= 2,
    DELETE	= 3,
    _MAX	= 4,
}
pub const CTA_STATS_EXP_UNSPEC: u16	= CtattrExpectStats::UNSPEC as u16;
pub const CTA_STATS_EXP_NEW: u16	= CtattrExpectStats::NEW as u16;
pub const CTA_STATS_EXP_CREATE: u16	= CtattrExpectStats::CREATE as u16;
pub const CTA_STATS_EXP_DELETE: u16	= CtattrExpectStats::DELETE as u16;
pub const CTA_STATS_EXP_MAX: u16	= CtattrExpectStats::_MAX as u16 - 1;

// XXX: copy only NF_NETLINK_ from nfnetlink_compat.h
// Old nfnetlink macros for userspace */
// nfnetlink groups: Up to 32 maximum
pub const NF_NETLINK_CONNTRACK_NEW: u32		= 0x00000001;
pub const NF_NETLINK_CONNTRACK_UPDATE: u32	= 0x00000002;
pub const NF_NETLINK_CONNTRACK_DESTROY: u32	= 0x00000004;
pub const NF_NETLINK_CONNTRACK_EXP_NEW: u32	= 0x00000008;
pub const NF_NETLINK_CONNTRACK_EXP_UPDATE: u32	= 0x00000010;
pub const NF_NETLINK_CONNTRACK_EXP_DESTROY: u32	= 0x00000020;

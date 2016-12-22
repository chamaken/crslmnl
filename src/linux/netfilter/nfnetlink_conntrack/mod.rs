#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum MsgTypes {
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

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum CntlExpMsgTypes {
    NEW			= 0,
    GET			= 1,
    DELETE		= 2,
    GET_STATS_CPU	= 3,
    MAX			= 4,
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrType {
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
// unimplemented constant expression: enum variants
// pub const CTA_MAX: u16 = (AttrType::_MAX as u16) - 1;
pub const CTA_MAX: u16 = 24 - 1;
// XXX: look for avoiding: discriminant value '' already exists
pub const CTA_NAT: AttrType 			= AttrType::NAT_SRC;
pub const CTA_NAT_SEQ_ADJ_ORIG:AttrType		= AttrType::SEQ_ADJ_ORIG;
pub const CTA_NAT_SEQ_ADJ_REPLY:AttrType	= AttrType::SEQ_ADJ_REPLY;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrTuple {
    UNSPEC	= 0,
    IP		= 1,
    PROTO	= 2,
    ZONE	= 3,
    _MAX = 4,
}
// unimplemented constant expression: enum variants
// pub const CTA_TUPLE_MAX: u16 = (AttrTuple::_MAX as u16) - 1;
pub const CTA_TUPLE_MAX: u16 = 4 - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrIp {
    UNSPEC	= 0,
    V4_SRC	= 1,
    V4_DST	= 2,
    V6_SRC	= 3,
    V6_DST	= 4,
    _MAX	= 5,
}
// unimplemented constant expression: enum variants
// pub const CTA_IP_MAX: u16 = (AttrIp::_MAX as u16) - 1;
pub const CTA_IP_MAX: u16 = 5 - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrL4proto {
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
// unimplemented constant expression: enum variants
// pub const CTA_PROTO_MAX: u16 = (AttrL4proto::_MAX as u16) - 1;
pub const CTA_PROTO_MAX: u16 = 10 - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum AttrProtoinfo {
    UNSPEC	= 0,
    TCP		= 1,
    DCCP	= 2,
    SCTP	= 3,
    _MAX	= 4,
}
pub const CTA_PROTOINFO_MAX: u16 = (AttrProtoinfo::_MAX as u16) - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum AttrProtoinfoTcp {
    UNSPEC		= 0,
    STATE		= 1,
    WSCALE_ORIGINAL	= 2,
    WSCALE_REPLY	= 3,
    FLAGS_ORIGINAL	= 4,
    FLAGS_REPLY		= 5,
    _MAX		= 6,
}
pub const CTA_PROTOINFO_TCP_MAX: u16 = (AttrProtoinfoTcp::_MAX as u16) - 1;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(u16)]
#[derive(Debug)]
pub enum AttrProtoinfoDccp {
    UNSPEC		= 0,
    STATE		= 1,
    ROLE		= 2,
    HANDSHAKE_SEQ	= 3,
    PAD			= 4,
    _MAX		= 5,
}
pub const CTA_PROTOINFO_DCCP_MAX: u16 = (AttrProtoinfoDccp::_MAX as u16) - 1;

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

// XXX: not follow the original
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum IpConntrackInfo {
    // Part of an established connection (either direction).
    ESTABLISHED		= 0,

    // Like NEW, but related to an existing connection, or ICMP error
    // (in either direction).
    RELATED		= 1,

    // Started a new connection to track (only
    // IP_CT_DIR_ORIGINAL); may be a retransmission.
    NEW			= 2,

    // >= this indicates reply direction
    IS_REPLY		= 3,

    // >= this indicates reply direction
    RELATED_REPLY	= 4,

    // Number of distinct IP_CT types.
    NUMBER		= 5,

    // NEW_REOLY	= NUMBER
    UNTRACKED		= 7,
}
pub const IP_CT_ESTABLISHED: u8		= IpConntrackInfo::ESTABLISHED as u8;
pub const IP_CT_RELATED: u8		= IpConntrackInfo::RELATED as u8;
pub const IP_CT_NEW: u8			= IpConntrackInfo::NEW as u8;
pub const IP_CT_IS_REPLY: u8		= IpConntrackInfo::IS_REPLY as u8;
pub const IP_CT_ESTABLISHED_REPLY: u8	= IP_CT_ESTABLISHED as u8 + IP_CT_IS_REPLY as u8;
pub const IP_CT_RELATED_REPLY: u8	= IP_CT_RELATED as u8 + IP_CT_IS_REPLY as u8;
pub const IP_CT_NUMBER: u8		= IpConntrackInfo::NUMBER as u8;
pub const IP_CT_NEW_REPLY: u8		= IP_CT_NUMBER as u8;
pub const IP_CT_UNTRACKED: u8		= IpConntrackInfo::UNTRACKED as u8;

pub const NFCT_STATE_INVALID_BIT: u32	= 1 << 0;
#[allow(non_snake_case)]
pub fn NF_CT_STATE_BIT(ctinfo: u8) -> u32 {
    1 << ((ctinfo) % IP_CT_IS_REPLY + 1)
}
pub const NF_CT_STATE_UNTRACKED_BIT: u32	= 1 << (IP_CT_UNTRACKED as u32 + 1);

pub const IPS_EXPECTED_BIT: u8		= 0;
pub const IPS_SEEN_REPLY_BIT: u8	= 1;
pub const IPS_ASSURED_BIT: u8		= 2;
pub const IPS_CONFIRMED_BIT: u8		= 3;
pub const IPS_SRC_NAT_BIT: u8		= 4;
pub const IPS_DST_NAT_BIT: u8		= 5;
pub const IPS_SEQ_ADJUST_BIT: u8	= 6;
pub const IPS_SRC_NAT_DONE_BIT: u8	= 7;
pub const IPS_DST_NAT_DONE_BIT: u8	= 8;
pub const IPS_DYING_BIT: u8		= 9;
pub const IPS_FIXED_TIMEOUT_BIT: u8	= 10;
pub const IPS_TEMPLATE_BIT: u8		= 11;
pub const IPS_UNTRACKED_BIT: u8		= 12;
pub const IPS_HELPER_BIT: u8		= 13;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum IpConntrackStatus { // unsigned int
    // It's an expected connection: bit 0 set.  This bit never changed
    EXPECTED		= 1 << IPS_EXPECTED_BIT,
    // We've seen packets both ways: bit 1 set.  Can be set, not unset.
    SEEN_REPLY		= 1 << IPS_SEEN_REPLY_BIT,
    // Conntrack should never be early-expired.
    ASSURED		= 1 << IPS_ASSURED_BIT,
    // Connection is confirmed: originating packet has left box
    CONFIRMED		= 1 << IPS_CONFIRMED_BIT,
    // Connection needs src nat in orig dir.  This bit never changed.
    SRC_NAT		= 1 << IPS_SRC_NAT_BIT,
    // Connection needs dst nat in orig dir.  This bit never changed.
    DST_NAT		= 1 << IPS_DST_NAT_BIT,
    // Both together.
    NAT_MASK		= (1 << IPS_SRC_NAT_BIT) | (1 << IPS_DST_NAT_BIT),
    // Connection needs TCP sequence adjusted.
    SEQ_ADJUST		= 1 << IPS_SEQ_ADJUST_BIT,
    // NAT initialization bits.
    SRC_NAT_DONE	= 1 << IPS_SRC_NAT_DONE_BIT,
    DST_NAT_DONE	= 1 << IPS_DST_NAT_DONE_BIT,
    // Both together
    NAT_DONE_MASK	= (1 << IPS_SRC_NAT_DONE_BIT) | (1 << IPS_DST_NAT_DONE_BIT),
    // Connection is dying (removed from lists), can not be unset.
    DYING		= 1 << IPS_DYING_BIT,
    // Connection has fixed timeout.
    FIXED_TIMEOUT	= 1 << IPS_FIXED_TIMEOUT_BIT,
    // Conntrack is a template
    TEMPLATE		= 1 << IPS_TEMPLATE_BIT,
    // Conntrack is a fake untracked entry. Obsolete and not used anymore
    UNTRACKED		= 1 << IPS_UNTRACKED_BIT,
    // Conntrack got a helper explicitly attached via CT target.
    HELPER		= 1 << IPS_HELPER_BIT,

    // Be careful here, modifying these bits can make things messy,
    // so don't let users modify them directly.
    UNCHANGEABLE_MASK	= (IPS_NAT_DONE_MASK | IPS_NAT_MASK |
			   IPS_EXPECTED | IPS_CONFIRMED | IPS_DYING |
			   IPS_SEQ_ADJUST | IPS_TEMPLATE),

    MAX_BIT = 14,
}
pub const IPS_EXPECTED: u32		= IpConntrackStatus::EXPECTED as u32;
pub const IPS_SEEN_REPLY: u32		= IpConntrackStatus::SEEN_REPLY as u32;
pub const IPS_ASSURED: u32		= IpConntrackStatus::ASSURED as u32;
pub const IPS_CONFIRMED: u32		= IpConntrackStatus::CONFIRMED as u32;
pub const IPS_SRC_NAT: u32		= IpConntrackStatus::SRC_NAT as u32;
pub const IPS_DST_NAT: u32		= IpConntrackStatus::DST_NAT as u32;
pub const IPS_NAT_MASK: u32		= IpConntrackStatus::DST_NAT as u32 | IpConntrackStatus::SRC_NAT as u32;
pub const IPS_SEQ_ADJUST: u32		= IpConntrackStatus::SEQ_ADJUST as u32;
pub const IPS_SRC_NAT_DONE: u32		= IpConntrackStatus::SRC_NAT_DONE as u32;
pub const IPS_DST_NAT_DONE: u32		= IpConntrackStatus::DST_NAT_DONE as u32;
pub const IPS_NAT_DONE_MASK: u32	= IpConntrackStatus::DST_NAT_DONE as u32 | IpConntrackStatus::SRC_NAT_DONE as u32;
pub const IPS_DYING: u32		= IpConntrackStatus::DYING as u32;
pub const IPS_FIXED_TIMEOUT: u32	= IpConntrackStatus::FIXED_TIMEOUT as u32;
pub const IPS_TEMPLATE: u32		= IpConntrackStatus::TEMPLATE as u32;
pub const IPS_UNTRACKED: u32		= IpConntrackStatus::UNTRACKED as u32;
pub const IPS_HELPER: u32		= IpConntrackStatus::HELPER as u32;
pub const IPS_UNCHANGEABLE_MASK: u32	= IpConntrackStatus::UNCHANGEABLE_MASK as u32;

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum IpConntrackEvents { // shift bit
    NEW		= 0,	// new conntrack
    RELATED	= 1,    // related conntrack
    DESTROY	= 2,    // destroyed conntrack
    REPLY	= 3,    // connection has seen two-way traffic
    ASSURED	= 4,    // connection status has changed to assured
    PROTOINFO	= 5,    // protocol information has changed
    HELPER	= 6,    // new helper has been set
    MARK	= 7,    // new mark has been set
    SEQADJ	= 8,    // sequence adjustment has changed
    // NATSEQADJ	= SEQADJ
    SECMARK	= 9,    // new security mark has been set
    LABEL	= 10,   // new connlabel has been set
    _MAX	= 11,
}
pub const IPCT_NEW: u8		= IpConntrackEvents::NEW as u8;
pub const IPCT_RELATED: u8	= IpConntrackEvents::RELATED as u8;
pub const IPCT_DESTROY: u8	= IpConntrackEvents::DESTROY as u8;
pub const IPCT_REPLY: u8	= IpConntrackEvents::REPLY as u8;
pub const IPCT_ASSURED: u8	= IpConntrackEvents::ASSURED as u8;
pub const IPCT_PROTOINFO: u8	= IpConntrackEvents::PROTOINFO as u8;
pub const IPCT_HELPER: u8	= IpConntrackEvents::HELPER as u8;
pub const IPCT_MARK: u8		= IpConntrackEvents::MARK as u8;
pub const IPCT_SEQADJ: u8	= IpConntrackEvents::SEQADJ as u8;
pub const IPCT_NATSEQADJ: u8	= IpConntrackEvents::SEQADJ as u8;
pub const IPCT_SECMARK: u8	= IpConntrackEvents::SECMARK as u8;
pub const IPCT_LABEL: u8	= IpConntrackEvents::LABEL as u8;

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum IpConntrackExpectEvents {
    NEW		= 0,	// new expectation
    DESTROY	= 1,	// destroyed expectation
}
pub const IPEXP_NEW: u8		= IpConntrackExpectEvents::NEW as u8;
pub const IPEXP_DESTROY: u8	= IpConntrackExpectEvents::DESTROY as u8;

// expectation flags - unsigned int
pub const NF_CT_EXPECT_PERMANENT: u32	= 0x1;
pub const NF_CT_EXPECT_INACTIVE: u32	= 0x2;
pub const NF_CT_EXPECT_USERSPACE: u32	= 0x4;

pub mod nfnetlink;
pub mod nfnetlink_log;
pub mod nfnetlink_conntrack;
pub mod nfnetlink_queue;
pub mod nf_conntrack_common;
pub mod nf_conntrack_tcp;

// Responses from hook functions.
#[derive(Debug, Copy, Clone)]
#[repr(u32)] // ???
pub enum Verdict {
    DROP	= 0,
    ACCEPT	= 1,
    STOLEN	= 2,
    QUEUE	= 3,
    REPEAT	= 4,
    STOP	= 5,	// Deprecated, for userspace nf_queue compatibility.
}
pub const NF_DROP: u32		= Verdict::DROP as u32;
pub const NF_ACCEPT: u32	= Verdict::ACCEPT as u32;
pub const NF_STOLEN: u32	= Verdict::STOLEN as u32;
pub const NF_QUEUE: u32		= Verdict::QUEUE as u32;
pub const NF_REPEAT: u32	= Verdict::REPEAT as u32;
pub const NF_STOP: u32		= Verdict::STOP as u32;
pub const NF_MAX_VERDICT: u32	= Verdict::STOP as u32;

// we overload the higher bits for encoding auxiliary data such as the queue
// number or errno values. Not nice, but better than additional function
// arguments. */
pub const NF_VERDICT_MASK: u32	=  0x000000ff;

// extra verdict flags have mask 0x0000ff00 */
pub const NF_VERDICT_FLAG_QUEUE_BYPASS: u32 = 0x00008000;

// queue number (NF_QUEUE) or errno (NF_DROP) */
pub const NF_VERDICT_QMASK: u32	= 0xffff0000;
pub const NF_VERDICT_QBITS: u8	= 16;

#[allow(non_snake_case)]
pub fn NF_QUEUE_NR(x: u32) -> u32 {
    (((x) << 16) & NF_VERDICT_QMASK) | NF_QUEUE
}

#[allow(non_snake_case)]
pub fn NF_DROP_ERR(x: i32) -> u32 {
    ((-x) << 16) as u32 | NF_DROP
}

// only for userspace compatibility */
// #ifndef __KERNEL__
// Generic cache responses from hook functions.
//   <= 0x2000 is used for protocol-flags.
pub const NFC_UNKNOWN: u16	= 0x4000;
pub const NFC_ALTERED: u16	= 0x8000;

// NF_VERDICT_BITS should be 8 now, but userspace might break if this changes */
pub const NF_VERDICT_BITS: u8	=  16;
// #endif

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum InetHooks {
    // bitop? or u32
    PRE_ROUTING		= 0,
    LOCAL_IN		= 1,
    FORWARD		= 2,
    LOCAL_OUT		= 3,
    POST_ROUTING	= 4,
    NUMHOOKS		= 5,
}
pub const NF_INET_PRE_ROUTING: u8	= InetHooks::PRE_ROUTING as u8;
pub const NF_INET_LOCAL_IN: u8		= InetHooks::LOCAL_IN as u8;
pub const NF_INET_FORWARD: u8		= InetHooks::FORWARD as u8;
pub const NF_INET_LOCAL_OUT: u8		= InetHooks::LOCAL_OUT as u8;
pub const NF_INET_POST_ROUTING: u8	= InetHooks::POST_ROUTING as u8;
pub const NF_INET_NUMHOOKS: u8		= InetHooks::NUMHOOKS as u8;

#[repr(u32)]
pub enum DevHooks {
    INGRESS	= 0,
    NUMHOOKS	= 1,
}
pub const NF_NETDEV_INGRESS: u32	= DevHooks::INGRESS as u32;
pub const NF_NETDEV_NUMHOOKS: u32	= DevHooks::NUMHOOKS as u32;

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum Proto {
    UNSPEC	=  0,
    INET  	=  1,
    IPV4   	=  2,
    ARP    	=  3,
    NETDEV 	=  5,
    BRIDGE 	=  7,
    IPV6   	= 10,
    DECNET 	= 12,
    NUMPROTO	= 13,
}
pub const NFPROTO_UNSPEC: u8 	= Proto::UNSPEC as u8;
pub const NFPROTO_INET: u8   	= Proto::INET as u8;
pub const NFPROTO_IPV4: u8   	= Proto::IPV4 as u8;
pub const NFPROTO_ARP: u8    	= Proto::ARP as u8;
pub const NFPROTO_NETDEV: u8 	= Proto::NETDEV as u8;
pub const NFPROTO_BRIDGE: u8 	= Proto::BRIDGE as u8;
pub const NFPROTO_IPV6: u8 	= Proto::IPV6 as u8;
pub const NFPROTO_DECNET: u8	= Proto::DECNET as u8;
pub const NFPROTO_NUMPROTO: u8	= Proto::NUMPROTO as u8;

// XXX: not implemented yet
// union nf_inet_addr {
// 	__u32		all[4];
// 	__be32		ip;
// 	__be32		ip6[4];
// 	struct in_addr	in;
// 	struct in6_addr	in6;
// };

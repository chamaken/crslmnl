pub mod nfnetlink;
pub mod nfnetlink_log;
pub mod nfnetlink_conntrack;
pub mod nfnetlink_queue;

// Responses from hook functions.
pub const NF_DROP: u32		= 0;
pub const NF_ACCEPT: u32	= 1;
pub const NF_STOLEN: u32	= 2;
pub const NF_QUEUE: u32		= 3;
pub const NF_REPEAT: u32	= 4;
pub const NF_STOP: u32		= 5;	// Deprecated, for userspace nf_queue compatibility.
pub const NF_MAX_VERDICT: u32	= NF_STOP;

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
#[derive(Copy, Clone)]
#[repr(u8)]
#[derive(Debug)]
pub enum InetHooks {
    // bitop? or u32
    PRE_ROUTING		= 0,
    LOCAL_IN		= 1,
    FORWARD		= 2,
    LOCAL_OUT		= 3,
    POST_ROUTING	= 4,
    NUMHOOKS		= 5
}

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
enum DevHooks {
	INGRESS,
	NUMHOOKS
}

// enum {
pub const NFPROTO_UNSPEC: u8 	=  0;
pub const NFPROTO_INET: u8   	=  1;
pub const NFPROTO_IPV4: u8   	=  2;
pub const NFPROTO_ARP: u8    	=  3;
pub const NFPROTO_NETDEV: u8 	=  5;
pub const NFPROTO_BRIDGE: u8 	=  7;
pub const NFPROTO_IPV6: u8 	= 10;
pub const NFPROTO_DECNET: u8	= 12;
pub const NFPROTO_NUMPROTO: u8	= 13;

// union nf_inet_addr {
// 	__u32		all[4];
// 	__be32		ip;
// 	__be32		ip6[4];
// 	struct in_addr	in;
// 	struct in6_addr	in6;
// };

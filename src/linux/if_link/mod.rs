extern crate libc;
use libc::c_int;

// This struct should be in sync with struct rtnl_link_stats64
#[repr(C)]
pub struct LinkStats {
    pub rx_packets: u32,		// total packets received
    pub tx_packets: u32,                // total packets transmitted
    pub rx_bytes: u32,                  // total bytes received
    pub tx_bytes: u32,                  // total bytes transmitted
    pub rx_errors: u32,                 // bad packets received
    pub tx_errors: u32,                 // packet transmit problems
    pub rx_dropped: u32,                // no space in linux buffers
    pub tx_dropped: u32,                // no space available in linux
    pub multicast: u32,                 // multicast packets received
    pub collisions: u32,

    // detailed rx_errors:
    pub rx_length_errors: u32,
    pub rx_over_errors: u32,		// receiver ring buff overflow
    pub rx_crc_errors: u32,             // recved pkt with crc error
    pub rx_frame_errors: u32,           // recv'd frame alignment error
    pub rx_fifo_errors: u32,            // recv'r fifo overrun
    pub rx_missed_errors: u32,          // receiver missed packet

    // detailed tx_errors
    pub tx_aborted_errors: u32,
    pub tx_carrier_errors: u32,
    pub tx_fifo_errors: u32,
    pub tx_heartbeat_errors: u32,
    pub tx_window_errors: u32,

    // for cslip etc
    pub rx_compressed: u32,
    pub tx_compressed: u32,
    pub rx_nohandler: u32,		// dropped, no handler found
}

// The main device statistics structure
#[repr(C)]
pub struct LinkStats64 {
    pub rx_packets: u64,		// total packets received
    pub tx_packets: u64,                // total packets transmitted
    pub rx_bytes: u64,                  // total bytes received
    pub tx_bytes: u64,                  // total bytes transmitted
    pub rx_errors: u64,                 // bad packets received
    pub tx_errors: u64,                 // packet transmit problems
    pub rx_dropped: u64,                // no space in linux buffers
    pub tx_dropped: u64,                // no space available in linux
    pub multicast: u64,                 // multicast packets received
    pub collisions: u64,

    // detailed rx_errors:
    pub rx_length_errors: u64,
    pub rx_over_errors: u64,		// receiver ring buff overflow
    pub rx_crc_errors: u64,             // recved pkt with crc error
    pub rx_frame_errors: u64,           // recv'd frame alignment error
    pub rx_fifo_errors: u64,            // recv'r fifo overrun
    pub rx_missed_errors: u64,          // receiver missed packet

    // detailed tx_errors
    pub tx_aborted_errors: u64,
    pub tx_carrier_errors: u64,
    pub tx_fifo_errors: u64,
    pub tx_heartbeat_errors: u64,
    pub tx_window_errors: u64,

    // for cslip etc
    pub rx_compressed: u64,
    pub tx_compressed: u64,
    pub rx_nohandler: u64,		// dropped, no handler found
}

#[repr(C)]
pub struct LinkIfmap {
    pub mem_start: u64,
    pub mem_end: u64,
    pub base_addr: u64,
    pub irq: u16,
    pub dma: u8,
    pub port: u8,
}

// IFLA_AF_SPEC
//   Contains nested attributes for address family specific attributes.
//   Each address family may create a attribute with the address family
//   number as type and create its own attribute structure in it.
//
//   Example:
//   [IFLA_AF_SPEC] = {
//       [AF_INET] = {
//           [IFLA_INET_CONF] = ...,
//       },
//       [AF_INET6] = {
//           [IFLA_INET6_FLAGS] = ...,
//           [IFLA_INET6_CONF] = ...,
//       }
//   }
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum AttrType {
    UNSPEC		= 0,
    ADDRESS		= 1,
    BROADCAST		= 2,
    IFNAME		= 3,
    MTU			= 4,
    LINK		= 5,
    QDISC		= 6,
    STATS		= 7,
    COST		= 8,
    PRIORITY		= 9,
    MASTER		= 10,
    WIRELESS		= 11,
    PROTINFO		= 12,
    TXQLEN		= 13,
    MAP			= 14,
    WEIGHT		= 15,
    OPERSTATE		= 16,
    LINKMODE		= 17,
    LINKINFO		= 18,
    NET_NS_PID		= 19,
    IFALIAS		= 20,
    NUM_VF		= 21,
    VFINFO_LIST		= 22,
    STATS64		= 23,
    VF_PORTS		= 24,
    PORT_SELF		= 25,
    AF_SPEC		= 26,
    GROUP		= 27,
    NET_NS_FD		= 28,
    EXT_MASK		= 29,
    PROMISCUITY 	= 30,
    NUM_TX_QUEUES 	= 31,
    NUM_RX_QUEUES 	= 32,
    CARRIER		= 33,
    PHYS_PORT_ID	= 34,
    CARRIER_CHANGES	= 35,
    PHYS_SWITCH_ID	= 36,
    LINK_NETNSID	= 37,
    PHYS_PORT_NAME	= 38,
    PROTO_DOWN		= 39,
    GSO_MAX_SEGS	= 40,
    GSO_MAX_SIZE	= 41,
    PAD			= 42,
    XDP			= 43,
    _MAX		= 44,
}
pub const IFLA_UNSPEC: u16		= AttrType::UNSPEC as u16;
pub const IFLA_ADDRESS: u16		= AttrType::ADDRESS as u16;
pub const IFLA_BROADCAST: u16		= AttrType::BROADCAST as u16;
pub const IFLA_IFNAME: u16		= AttrType::IFNAME as u16;
pub const IFLA_MTU: u16			= AttrType::MTU as u16;
pub const IFLA_LINK: u16		= AttrType::LINK as u16;
pub const IFLA_QDISC: u16		= AttrType::QDISC as u16;
pub const IFLA_STATS: u16		= AttrType::STATS as u16;
pub const IFLA_COST: u16		= AttrType::COST as u16;
pub const IFLA_PRIORITY: u16		= AttrType::PRIORITY as u16;
pub const IFLA_MASTER: u16		= AttrType::MASTER as u16;
pub const IFLA_WIRELESS: u16		= AttrType::WIRELESS as u16;
pub const IFLA_PROTINFO: u16		= AttrType::PROTINFO as u16;
pub const IFLA_TXQLEN: u16		= AttrType::TXQLEN as u16;
pub const IFLA_MAP: u16			= AttrType::MAP as u16;
pub const IFLA_WEIGHT: u16		= AttrType::WEIGHT as u16;
pub const IFLA_OPERSTATE: u16		= AttrType::OPERSTATE as u16;
pub const IFLA_LINKMODE: u16		= AttrType::LINKMODE as u16;
pub const IFLA_LINKINFO: u16		= AttrType::LINKINFO as u16;
pub const IFLA_NET_NS_PID: u16		= AttrType::NET_NS_PID as u16;
pub const IFLA_IFALIAS: u16		= AttrType::IFALIAS as u16;
pub const IFLA_NUM_VF: u16		= AttrType::NUM_VF as u16;
pub const IFLA_VFINFO_LIST: u16		= AttrType::VFINFO_LIST as u16;
pub const IFLA_STATS64: u16		= AttrType::STATS64 as u16;
pub const IFLA_VF_PORTS: u16		= AttrType::VF_PORTS as u16;
pub const IFLA_PORT_SELF: u16		= AttrType::PORT_SELF as u16;
pub const IFLA_AF_SPEC: u16		= AttrType::AF_SPEC as u16;
pub const IFLA_GROUP: u16		= AttrType::GROUP as u16;
pub const IFLA_NET_NS_FD: u16		= AttrType::NET_NS_FD as u16;
pub const IFLA_EXT_MASK: u16		= AttrType::EXT_MASK as u16;
pub const IFLA_PROMISCUITY: u16		= AttrType::PROMISCUITY as u16;
pub const IFLA_NUM_TX_QUEUES: u16	= AttrType::NUM_TX_QUEUES as u16;
pub const IFLA_NUM_RX_QUEUES: u16	= AttrType::NUM_RX_QUEUES as u16;
pub const IFLA_CARRIER: u16		= AttrType::CARRIER as u16;
pub const IFLA_PHYS_PORT_ID: u16	= AttrType::PHYS_PORT_ID as u16;
pub const IFLA_CARRIER_CHANGES: u16	= AttrType::CARRIER_CHANGES as u16;
pub const IFLA_PHYS_SWITCH_ID: u16	= AttrType::PHYS_SWITCH_ID as u16;
pub const IFLA_LINK_NETNSID: u16	= AttrType::LINK_NETNSID as u16;
pub const IFLA_PHYS_PORT_NAME: u16	= AttrType::PHYS_PORT_NAME as u16;
pub const IFLA_PROTO_DOWN: u16		= AttrType::PROTO_DOWN as u16;
pub const IFLA_GSO_MAX_SEGS: u16	= AttrType::GSO_MAX_SEGS as u16;
pub const IFLA_GSO_MAX_SIZE: u16	= AttrType::GSO_MAX_SIZE as u16;
pub const IFLA_PAD: u16			= AttrType::PAD as u16;
pub const IFLA_XDP: u16			= AttrType::XDP as u16;
pub const __IFLA_MAX: u16		= AttrType::_MAX as u16;
pub const IFLA_MAX: u16			= __IFLA_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum AttrTypeInet {
    UNSPEC	= 0,
    CONF	= 1,
    _MAX	= 2,
}
pub const IFLA_INET_UNSPEC: u16	= AttrTypeInet::UNSPEC as u16;
pub const IFLA_INET_CONF: u16	= AttrTypeInet::CONF as u16;
pub const __IFLA_INET_MAX: u16	= AttrTypeInet::_MAX as u16;
pub const IFLA_INET_MAX: u16	= __IFLA_INET_MAX - 1;


// ifi_flags.
//
//   IFF_* flags.
//
//   The only change is:
//   IFF_LOOPBACK, IFF_BROADCAST and IFF_POINTOPOINT are
//   more not changeable by user. They describe link media
//   characteristics and set by device driver.
//
//   Comments:
//   - Combination IFF_BROADCAST|IFF_POINTOPOINT is invalid
//   - If neither of these three flags are set;
//     the interface is NBMA.
//
//   - IFF_MULTICAST does not mean anything special:
//   multicasts can be used on all not-NBMA links.
//   IFF_MULTICAST means that this media uses special encapsulation
//   for multicast frames. Apparently, all IFF_POINTOPOINT and
//   IFF_BROADCAST devices are able to use multicasts too.
//

// IFLA_LINK.
//   For usual devices it is equal ifi_index.
//   If it is a "virtual interface" (f.e. tunnel), ifi_link
//   can point to real physical interface (f.e. for bandwidth calculations),
//   or maybe 0, what means, that real media is unknown (usual
//   for IPIP tunnels, when route to endpoint is allowed to change)

// Subtype attributes for IFLA_PROTINFO
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum AttrTypeInet6 {
    UNSPEC		= 0,
    FLAGS		= 1,	// link flags
    CONF		= 2,    // sysctl parameters
    STATS		= 3,    // statistics
    MCAST		= 4,    // MC things. What of them?
    CACHEINFO		= 5,    // time values and max reasm size
    ICMP6STATS		= 6,    // statistics (icmpv6)
    TOKEN		= 7,    // device token
    ADDR_GEN_MODE	= 8,    // implicit address generator mode
    _MAX		= 9,
}
pub const IFLA_INET6_UNSPEC: u16	= AttrTypeInet6::UNSPEC as u16;
pub const IFLA_INET6_FLAGS: u16		= AttrTypeInet6::FLAGS as u16;
pub const IFLA_INET6_CONF: u16		= AttrTypeInet6::CONF as u16;
pub const IFLA_INET6_STATS: u16		= AttrTypeInet6::STATS as u16;
pub const IFLA_INET6_MCAST: u16		= AttrTypeInet6::MCAST as u16;
pub const IFLA_INET6_CACHEINFO: u16	= AttrTypeInet6::CACHEINFO as u16;
pub const IFLA_INET6_ICMP6STATS: u16	= AttrTypeInet6::ICMP6STATS as u16;
pub const IFLA_INET6_TOKEN: u16		= AttrTypeInet6::TOKEN as u16;
pub const IFLA_INET6_ADDR_GEN_MODE: u16	= AttrTypeInet6::ADDR_GEN_MODE as u16;
pub const __IFLA_INET6_MAX: u16		= AttrTypeInet6::_MAX as u16;
pub const IFLA_INET6_MAX: u16		= __IFLA_INET6_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum In6AddrGenMode {
    EUI64		= 0,
    NONE		= 1,
    STABLE_PRIVACY	= 2,
    RANDOM		= 3,
}
pub const IN6_ADDR_GEN_MODE_EUI64: u16		= In6AddrGenMode::EUI64 as u16;
pub const IN6_ADDR_GEN_MODE_NONE: u16	 	= In6AddrGenMode::NONE as u16;
pub const IN6_ADDR_GEN_MODE_STABLE_PRIVACY: u16	= In6AddrGenMode::STABLE_PRIVACY as u16;
pub const IN6_ADDR_GEN_MODE_RANDOM: u16		= In6AddrGenMode::RANDOM as u16;

// Bridge section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum AttrTypeBr {
    UNSPEC 			= 0,
    FORWARD_DELAY		= 1,
    HELLO_TIME			= 2,
    MAX_AGE			= 3,
    AGEING_TIME			= 4,
    STP_STATE			= 5,
    PRIORITY			= 6,
    VLAN_FILTERING		= 7,
    VLAN_PROTOCOL		= 8,
    GROUP_FWD_MASK		= 9,
    ROOT_ID			= 10,
    BRIDGE_ID			= 11,
    ROOT_PORT			= 12,
    ROOT_PATH_COST		= 13,
    TOPOLOGY_CHANGE		= 14,
    TOPOLOGY_CHANGE_DETECTED	= 15,
    HELLO_TIMER			= 16,
    TCN_TIMER			= 17,
    TOPOLOGY_CHANGE_TIMER	= 18,
    GC_TIMER			= 19,
    GROUP_ADDR			= 20,
    FDB_FLUSH			= 21,
    MCAST_ROUTER		= 22,
    MCAST_SNOOPING		= 23,
    MCAST_QUERY_USE_IFADDR	= 24,
    MCAST_QUERIER		= 25,
    MCAST_HASH_ELASTICITY	= 26,
    MCAST_HASH_MAX		= 27,
    MCAST_LAST_MEMBER_CNT	= 28,
    MCAST_STARTUP_QUERY_CNT	= 29,
    MCAST_LAST_MEMBER_INTVL	= 30,
    MCAST_MEMBERSHIP_INTVL	= 31,
    MCAST_QUERIER_INTVL		= 32,
    MCAST_QUERY_INTVL		= 33,
    MCAST_QUERY_RESPONSE_INTVL	= 34,
    MCAST_STARTUP_QUERY_INTVL	= 35,
    NF_CALL_IPTABLES		= 36,
    NF_CALL_IP6TABLES 		= 37,
    NF_CALL_ARPTABLES		= 38,
    VLAN_DEFAULT_PVID		= 39,
    PAD				= 40,
    VLAN_STATS_ENABLED		= 41,
    MCAST_STATS_ENABLED		= 42,
    MCAST_IGMP_VERSION		= 43,
    MCAST_MLD_VERSION		= 44,
    _MAX			= 45,
}
pub const IFLA_BR_UNSPEC: u16				= AttrTypeBr::UNSPEC as u16;
pub const IFLA_BR_FORWARD_DELAY: u16			= AttrTypeBr::FORWARD_DELAY as u16;
pub const IFLA_BR_HELLO_TIME: u16			= AttrTypeBr::HELLO_TIME as u16;
pub const IFLA_BR_MAX_AGE: u16				= AttrTypeBr::MAX_AGE as u16;
pub const IFLA_BR_AGEING_TIME: u16			= AttrTypeBr::AGEING_TIME as u16;
pub const IFLA_BR_STP_STATE: u16			= AttrTypeBr::STP_STATE as u16;
pub const IFLA_BR_PRIORITY: u16				= AttrTypeBr::PRIORITY as u16;
pub const IFLA_BR_VLAN_FILTERING: u16			= AttrTypeBr::VLAN_FILTERING as u16;
pub const IFLA_BR_VLAN_PROTOCOL: u16			= AttrTypeBr::VLAN_PROTOCOL as u16;
pub const IFLA_BR_GROUP_FWD_MASK: u16			= AttrTypeBr::GROUP_FWD_MASK as u16;
pub const IFLA_BR_ROOT_ID: u16				= AttrTypeBr::ROOT_ID as u16;
pub const IFLA_BR_BRIDGE_ID: u16			= AttrTypeBr::BRIDGE_ID as u16;
pub const IFLA_BR_ROOT_PORT: u16			= AttrTypeBr::ROOT_PORT as u16;
pub const IFLA_BR_ROOT_PATH_COST: u16			= AttrTypeBr::ROOT_PATH_COST as u16;
pub const IFLA_BR_TOPOLOGY_CHANGE: u16			= AttrTypeBr::TOPOLOGY_CHANGE as u16;
pub const IFLA_BR_TOPOLOGY_CHANGE_DETECTED: u16		= AttrTypeBr::TOPOLOGY_CHANGE_DETECTED as u16;
pub const IFLA_BR_HELLO_TIMER: u16			= AttrTypeBr::HELLO_TIMER as u16;
pub const IFLA_BR_TCN_TIMER: u16			= AttrTypeBr::TCN_TIMER as u16;
pub const IFLA_BR_TOPOLOGY_CHANGE_TIMER: u16		= AttrTypeBr::TOPOLOGY_CHANGE_TIMER as u16;
pub const IFLA_BR_GC_TIMER: u16				= AttrTypeBr::GC_TIMER as u16;
pub const IFLA_BR_GROUP_ADDR: u16			= AttrTypeBr::GROUP_ADDR as u16;
pub const IFLA_BR_FDB_FLUSH: u16			= AttrTypeBr::FDB_FLUSH as u16;
pub const IFLA_BR_MCAST_ROUTER: u16			= AttrTypeBr::MCAST_ROUTER as u16;
pub const IFLA_BR_MCAST_SNOOPING: u16			= AttrTypeBr::MCAST_SNOOPING as u16;
pub const IFLA_BR_MCAST_QUERY_USE_IFADDR: u16		= AttrTypeBr::MCAST_QUERY_USE_IFADDR as u16;
pub const IFLA_BR_MCAST_QUERIER: u16			= AttrTypeBr::MCAST_QUERIER as u16;
pub const IFLA_BR_MCAST_HASH_ELASTICITY: u16		= AttrTypeBr::MCAST_HASH_ELASTICITY as u16;
pub const IFLA_BR_MCAST_HASH_MAX: u16			= AttrTypeBr::MCAST_HASH_MAX as u16;
pub const IFLA_BR_MCAST_LAST_MEMBER_CNT: u16		= AttrTypeBr::MCAST_LAST_MEMBER_CNT as u16;
pub const IFLA_BR_MCAST_STARTUP_QUERY_CNT: u16		= AttrTypeBr::MCAST_STARTUP_QUERY_CNT as u16;
pub const IFLA_BR_MCAST_LAST_MEMBER_INTVL: u16		= AttrTypeBr::MCAST_LAST_MEMBER_INTVL as u16;
pub const IFLA_BR_MCAST_MEMBERSHIP_INTVL: u16		= AttrTypeBr::MCAST_MEMBERSHIP_INTVL as u16;
pub const IFLA_BR_MCAST_QUERIER_INTVL: u16		= AttrTypeBr::MCAST_QUERIER_INTVL as u16;
pub const IFLA_BR_MCAST_QUERY_INTVL: u16		= AttrTypeBr::MCAST_QUERY_INTVL as u16;
pub const IFLA_BR_MCAST_QUERY_RESPONSE_INTVL: u16	= AttrTypeBr::MCAST_QUERY_RESPONSE_INTVL as u16;
pub const IFLA_BR_MCAST_STARTUP_QUERY_INTVL: u16	= AttrTypeBr::MCAST_STARTUP_QUERY_INTVL as u16;
pub const IFLA_BR_NF_CALL_IPTABLES: u16			= AttrTypeBr::NF_CALL_IPTABLES as u16;
pub const IFLA_BR_NF_CALL_IP6TABLES: u16		= AttrTypeBr::NF_CALL_IP6TABLES as u16;
pub const IFLA_BR_NF_CALL_ARPTABLES: u16		= AttrTypeBr::NF_CALL_ARPTABLES as u16;
pub const IFLA_BR_VLAN_DEFAULT_PVID: u16		= AttrTypeBr::VLAN_DEFAULT_PVID as u16;
pub const IFLA_BR_PAD: u16				= AttrTypeBr::PAD as u16;
pub const IFLA_BR_VLAN_STATS_ENABLED: u16		= AttrTypeBr::VLAN_STATS_ENABLED as u16;
pub const IFLA_BR_MCAST_STATS_ENABLED: u16		= AttrTypeBr::MCAST_STATS_ENABLED as u16;
pub const IFLA_BR_MCAST_IGMP_VERSION: u16		= AttrTypeBr::MCAST_IGMP_VERSION as u16;
pub const IFLA_BR_MCAST_MLD_VERSION: u16		= AttrTypeBr::MCAST_MLD_VERSION as u16;
pub const __IFLA_BR_MAX: u16				= AttrTypeBr::_MAX as u16;
pub const IFLA_BR_MAX: u16				= __IFLA_BR_MAX - 1;

#[repr(C)]
pub struct IflaBridgeId {
    pub prio: [u8; 2usize],
    pub addr: [u8; 6usize],
}

// XXX: unused?
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum BridgeMode {
    UNSPEC	= 0,
    HAIRPIN	= 1,
}
pub const BRIDGE_MODE_UNSPECL: u32 = BridgeMode::UNSPEC as u32;
pub const BRIDGE_MODE_HAIRPIN: u32 = BridgeMode::HAIRPIN as u32;

#[repr(u16)]
#[allow(non_camel_case_types)]
enum AttrBrport {
    UNSPEC		= 0,
    STATE		= 1,	// Spanning tree state
    PRIORITY		= 2,	// "             priority
    COST		= 3,	// "             cost
    MODE		= 4,	// mode (hairpin)
    GUARD		= 5,	// bpdu guard
    PROTECT		= 6,	// root port protection
    FAST_LEAVE		= 7,	// multicast fast leave
    LEARNING		= 8,	// mac learning
    UNICAST_FLOOD	= 9,	// flood unicast traffic
    PROXYARP		= 10,	// proxy ARP
    LEARNING_SYNC	= 11,	// mac learning sync from device
    PROXYARP_WIFI	= 12,	// proxy ARP for Wi-Fi
    ROOT_ID		= 13,	// designated root
    BRIDGE_ID		= 14,	// designated bridge
    DESIGNATED_PORT	= 15,
    DESIGNATED_COST	= 16,
    ID			= 17,
    NO			= 18,
    TOPOLOGY_CHANGE_ACK	= 19,
    CONFIG_PENDING	= 20,
    MESSAGE_AGE_TIMER	= 21,
    FORWARD_DELAY_TIMER	= 22,
    HOLD_TIMER		= 23,
    FLUSH		= 24,
    MULTICAST_ROUTER	= 25,
    PAD			= 26,
    MCAST_FLOOD		= 27,
    MCAST_TO_UCAST	= 28,
    VLAN_TUNNEL		= 29,
    BCAST_FLOOD		= 30,
    _MAX		= 31,
}
pub const IFLA_BRPORT_UNSPEC: u16		= AttrBrport::UNSPEC as u16;
pub const IFLA_BRPORT_STATE: u16		= AttrBrport::STATE as u16;
pub const IFLA_BRPORT_PRIORITY: u16		= AttrBrport::PRIORITY as u16;
pub const IFLA_BRPORT_COST: u16			= AttrBrport::COST as u16;
pub const IFLA_BRPORT_MODE: u16			= AttrBrport::MODE as u16;
pub const IFLA_BRPORT_GUARD: u16		= AttrBrport::GUARD as u16;
pub const IFLA_BRPORT_PROTECT: u16		= AttrBrport::PROTECT as u16;
pub const IFLA_BRPORT_FAST_LEAVE: u16		= AttrBrport::FAST_LEAVE as u16;
pub const IFLA_BRPORT_LEARNING: u16		= AttrBrport::LEARNING as u16;
pub const IFLA_BRPORT_UNICAST_FLOOD: u16	= AttrBrport::UNICAST_FLOOD as u16;
pub const IFLA_BRPORT_PROXYARP: u16		= AttrBrport::PROXYARP as u16;
pub const IFLA_BRPORT_LEARNING_SYNC: u16	= AttrBrport::LEARNING_SYNC as u16;
pub const IFLA_BRPORT_PROXYARP_WIFI: u16	= AttrBrport::PROXYARP_WIFI as u16;
pub const IFLA_BRPORT_ROOT_ID: u16		= AttrBrport::ROOT_ID as u16;
pub const IFLA_BRPORT_BRIDGE_ID: u16		= AttrBrport::BRIDGE_ID as u16;
pub const IFLA_BRPORT_DESIGNATED_PORT: u16	= AttrBrport::DESIGNATED_PORT as u16;
pub const IFLA_BRPORT_DESIGNATED_COST: u16	= AttrBrport::DESIGNATED_COST as u16;
pub const IFLA_BRPORT_ID: u16			= AttrBrport::ID as u16;
pub const IFLA_BRPORT_NO: u16			= AttrBrport::NO as u16;
pub const IFLA_BRPORT_TOPOLOGY_CHANGE_ACK: u16	= AttrBrport::TOPOLOGY_CHANGE_ACK as u16;
pub const IFLA_BRPORT_CONFIG_PENDING: u16	= AttrBrport::CONFIG_PENDING as u16;
pub const IFLA_BRPORT_MESSAGE_AGE_TIMER: u16	= AttrBrport::MESSAGE_AGE_TIMER as u16;
pub const IFLA_BRPORT_FORWARD_DELAY_TIMER: u16	= AttrBrport::FORWARD_DELAY_TIMER as u16;
pub const IFLA_BRPORT_HOLD_TIMER: u16		= AttrBrport::HOLD_TIMER as u16;
pub const IFLA_BRPORT_FLUSH: u16		= AttrBrport::FLUSH as u16;
pub const IFLA_BRPORT_MULTICAST_ROUTER: u16	= AttrBrport::MULTICAST_ROUTER as u16;
pub const IFLA_BRPORT_PAD: u16			= AttrBrport::PAD as u16;
pub const IFLA_BRPORT_MCAST_FLOOD: u16		= AttrBrport::MCAST_FLOOD as u16;
pub const IFLA_BRPORT_MCAST_TO_UCAST: u16	= AttrBrport::MCAST_TO_UCAST as u16;
pub const IFLA_BRPORT_VLAN_TUNNEL: u16		= AttrBrport::VLAN_TUNNEL as u16;
pub const IFLA_BRPORT_BCAST_FLOOD: u16		= AttrBrport::BCAST_FLOOD as u16;
pub const __IFLA_BRPORT_MAX: u16		= AttrBrport::_MAX as u16;
pub const IFLA_BRPORT_MAX: u16			= __IFLA_BRPORT_MAX - 1;

#[repr(C)]
pub struct IflaCacheinfo {
    pub max_reasm_len: u32,
    pub tstamp: u32,
    pub reachable_time: u32,
    pub retrans_time: u32,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum AttrTypeInfo {
    UNSPEC	= 0,
    KIND	= 1,
    DATA	= 2,
    XSTATS	= 3,
    SLAVE_KIND	= 4,
    SLAVE_DATA	= 5,
    _MAX	= 6,
}
pub const IFLA_INFO_UNSPEC: u16		= AttrTypeInfo::UNSPEC as u16;
pub const IFLA_INFO_KIND: u16		= AttrTypeInfo::KIND as u16;
pub const IFLA_INFO_DATA: u16		= AttrTypeInfo::DATA as u16;
pub const IFLA_INFO_XSTATS: u16		= AttrTypeInfo::XSTATS as u16;
pub const IFLA_INFO_SLAVE_KIND: u16	= AttrTypeInfo::SLAVE_KIND as u16;
pub const IFLA_INFO_SLAVE_DATA: u16	= AttrTypeInfo::SLAVE_DATA as u16;
pub const __IFLA_INFO_MAX: u16		= AttrTypeInfo::_MAX as u16;
pub const IFLA_INFO_MAX: u16		= __IFLA_INFO_MAX - 1;
// VLAN section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum AttrTypeVlan {
    UNSPEC	= 0,
    ID		= 1,
    FLAGS	= 2,
    EGRESS_QOS	= 3,
    INGRESS_QOS	= 4,
    PROTOCOL	= 5,
    _MAX	= 6,
}
pub const IFLA_VLAN_UNSPEC: u16		= AttrTypeVlan::UNSPEC as u16;
pub const IFLA_VLAN_ID: u16		= AttrTypeVlan::ID as u16;
pub const IFLA_VLAN_FLAGS: u16		= AttrTypeVlan::FLAGS as u16;
pub const IFLA_VLAN_EGRESS_QOS: u16	= AttrTypeVlan::EGRESS_QOS as u16;
pub const IFLA_VLAN_INGRESS_QOS: u16	= AttrTypeVlan::INGRESS_QOS as u16;
pub const IFLA_VLAN_PROTOCOL: u16	= AttrTypeVlan::PROTOCOL as u16;
pub const __IFLA_VLAN_MAX: u16		= AttrTypeVlan::_MAX as u16;
pub const IFLA_VLAN_MAX: u16		= __IFLA_VLAN_MAX - 1;

#[repr(C)]
pub struct IflaVlanFlags {
    pub flags: u32,
    pub mask: u32,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum AttrTypeVlanQos {
    QOS_UNSPEC	= 0,
    QOS_MAPPING	= 1,
    _MAX	= 2,
}
pub const IFLA_VLAN_QOS_UNSPEC: u16	= AttrTypeVlanQos::QOS_UNSPEC as u16;
pub const IFLA_VLAN_QOS_MAPPING: u16	= AttrTypeVlanQos::QOS_MAPPING as u16;
pub const __IFLA_VLAN_QOS_MAX: u16	= AttrTypeVlanQos::_MAX as u16;
pub const IFLA_VLAN_QOS_MAX: u16	= __IFLA_VLAN_QOS_MAX - 1;

#[repr(C)]
pub struct IflaVlanQosMapping {
    pub from: u32,
    pub to: u32,
}

// MACVLAN section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum AttrTypeMacvlan {
    UNSPEC		= 0,
    MODE		= 1,
    FLAGS		= 2,
    MACADDR_MODE	= 3,
    MACADDR		= 4,
    MACADDR_DATA	= 5,
    MACADDR_COUNT	= 6,
    _MAX		= 7,
}
pub const IFLA_MACVLAN_UNSPEC: u16		= AttrTypeMacvlan::UNSPEC as u16;
pub const IFLA_MACVLAN_MODE: u16		= AttrTypeMacvlan::MODE as u16;
pub const IFLA_MACVLAN_FLAGS: u16		= AttrTypeMacvlan::FLAGS as u16;
pub const IFLA_MACVLAN_MACADDR_MODE: u16	= AttrTypeMacvlan::MACADDR_MODE as u16;
pub const IFLA_MACVLAN_MACADDR: u16		= AttrTypeMacvlan::MACADDR as u16;
pub const IFLA_MACVLAN_MACADDR_DATA: u16	= AttrTypeMacvlan::MACADDR_DATA as u16;
pub const IFLA_MACVLAN_MACADDR_COUNT: u16	= AttrTypeMacvlan::MACADDR_COUNT as u16;
pub const __IFLA_MACVLAN_MAX: u16		= AttrTypeMacvlan::_MAX as u16;
pub const IFLA_MACVLAN_MAX: u16			= __IFLA_MACVLAN_MAX - 1;

#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum MacvlanMode {
    PRIVATE	= 1,	// don't talk to other macvlans
    VEPA	= 2,    // talk to other ports through ext bridge
    BRIDGE	= 4,    // talk to bridge ports directly
    PASSTHRU	= 8,    // take over the underlying device
    SOURCE	= 16,   // use source MAC address list to assign
}
pub const MACVLAN_MODE_PRIVATE: u32	= MacvlanMode::PRIVATE as u32;
pub const MACVLAN_MODE_VEPA: u32	= MacvlanMode::VEPA as u32;
pub const MACVLAN_MODE_BRIDGE: u32	= MacvlanMode::BRIDGE as u32;
pub const MACVLAN_MODE_PASSTHRU: u32	= MacvlanMode::PASSTHRU as u32;
pub const MACVLAN_MODE_SOURCE: u32	= MacvlanMode::SOURCE as u32;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum MacvlanMacaddrMode {
    ADD		= 0,
    DEL		= 1,
    FLUSH	= 2,
    SET		= 3,
}
pub const MACVLAN_MACADDR_ADD: u32	= MacvlanMacaddrMode::ADD as u32;
pub const MACVLAN_MACADDR_DEL: u32	= MacvlanMacaddrMode::DEL as u32;
pub const MACVLAN_MACADDR_FLUSH: u32	= MacvlanMacaddrMode::FLUSH as u32;
pub const MACVLAN_MACADDR_SET: u32	= MacvlanMacaddrMode::SET as u32;

// VRF section

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum Vrf {
    UNSPEC	= 0,
    TABLE	= 1,
    _MAX	= 2,
}
pub const IFLA_VRF_UNSPEC: u16	= Vrf::UNSPEC as u16;
pub const IFLA_VRF_TABLE: u16	= Vrf::TABLE as u16;
pub const __IFLA_VRF_MAX: u16	= Vrf::_MAX as u16;
pub const IFLA_VRF_MAX: u16	= __IFLA_VRF_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum VrfPort {
    UNSPEC	= 0,
    TABLE	= 1,
    _MAX	= 2,
}
pub const IFLA_VRF_PORT_UNSPEC: u16	= VrfPort::UNSPEC as u16;
pub const IFLA_VRF_PORT_TABLE: u16	= VrfPort::TABLE as u16;
pub const __IFLA_VRF_PORT_MAX: u16	= VrfPort::_MAX as u16;
pub const IFLA_VRF_PORT_MAX: u16	= __IFLA_VRF_PORT_MAX - 1;

// MACSEC section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum Macsec {
    UNSPEC		= 0,
    SCI			= 1,
    PORT		= 2,
    ICV_LEN		= 3,
    CIPHER_SUITE	= 4,
    WINDOW		= 5,
    ENCODING_SA		= 6,
    ENCRYPT		= 7,
    PROTECT		= 8,
    INC_SCI		= 9,
    ES			= 10,
    SCB			= 11,
    REPLAY_PROTECT	= 12,
    VALIDATION		= 13,
    PAD			= 14,
    _MAX		= 15,
}
pub const IFLA_MACSEC_UNSPEC: u16		= Macsec::UNSPEC as u16;
pub const IFLA_MACSEC_SCI: u16			= Macsec::SCI as u16;
pub const IFLA_MACSEC_PORT: u16			= Macsec::PORT as u16;
pub const IFLA_MACSEC_ICV_LEN: u16		= Macsec::ICV_LEN as u16;
pub const IFLA_MACSEC_CIPHER_SUITE: u16		= Macsec::CIPHER_SUITE as u16;
pub const IFLA_MACSEC_WINDOW: u16		= Macsec::WINDOW as u16;
pub const IFLA_MACSEC_ENCODING_SA: u16		= Macsec::ENCODING_SA as u16;
pub const IFLA_MACSEC_ENCRYPT: u16		= Macsec::ENCRYPT as u16;
pub const IFLA_MACSEC_PROTECT: u16		= Macsec::PROTECT as u16;
pub const IFLA_MACSEC_INC_SCI: u16		= Macsec::INC_SCI as u16;
pub const IFLA_MACSEC_ES: u16			= Macsec::ES as u16;
pub const IFLA_MACSEC_SCB: u16			= Macsec::SCB as u16;
pub const IFLA_MACSEC_REPLAY_PROTECT: u16	= Macsec::REPLAY_PROTECT as u16;
pub const IFLA_MACSEC_VALIDATION: u16		= Macsec::VALIDATION as u16;
pub const IFLA_MACSEC_PAD: u16			= Macsec::PAD as u16;
pub const __IFLA_MACSEC_MAX: u16		= Macsec::_MAX as u16;
pub const IFLA_MACSEC_MAX: u16			= __IFLA_MACSEC_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum MacsecValidationType {
    DISABLED	= 0,
    CHECK	= 1,
    STRICT	= 2,
    _END	= 3,
}
pub const MACSEC_VALIDATE_DISABLED: u8	= MacsecValidationType::DISABLED as u8;
pub const MACSEC_VALIDATE_CHECK: u8	= MacsecValidationType::CHECK as u8;
pub const MACSEC_VALIDATE_STRICT: u8	= MacsecValidationType::STRICT as u8;
pub const __MACSEC_VALIDATE_END: u8	= MacsecValidationType::_END as u8;
pub const MACSEC_VALIDATE_MAX: u8	= __MACSEC_VALIDATE_END - 1;

// IPVLAN section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum Ipvlan {
    UNSPEC	= 0,
    MODE	= 1,
    _MAX	= 2,
}
pub const IFLA_IPVLAN_UNSPEC: u16	= Ipvlan::UNSPEC as u16;
pub const IFLA_IPVLAN_MODE: u16		= Ipvlan::MODE as u16;
pub const __IFLA_IPVLAN_MAX: u16	= Ipvlan::_MAX as u16;
pub const IFLA_IPVLAN_MAX: u16		= __IFLA_IPVLAN_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum IpvlanMode {
    L2		= 0,
    L3		= 1,
    L3S		= 2,
    MAX		= 3,
}
pub const IPVLAN_MODE_L2: u16	= IpvlanMode::L2 as u16;
pub const IPVLAN_MODE_L3: u16	= IpvlanMode::L3 as u16;
pub const IPVLAN_MODE_L3S: u16	= IpvlanMode::L3S as u16;
pub const IPVLAN_MODE_MAX: u16	= IpvlanMode::MAX as u16; // XXX: differ from another?

// VXLAN section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum Vxlan {
    UNSPEC		= 0,
    ID			= 1,
    GROUP		= 2,	// group or remote address
    LINK		= 3,
    LOCAL		= 4,
    TTL			= 5,
    TOS			= 6,
    LEARNING		= 7,
    AGEING		= 8,
    LIMIT		= 9,
    PORT_RANGE		= 10,	// source port
    PROXY		= 11,
    RSC			= 12,
    L2MISS		= 13,
    L3MISS		= 14,
    PORT		= 15,	// destination port
    GROUP6		= 16,
    LOCAL6		= 17,
    UDP_CSUM		= 18,
    UDP_ZERO_CSUM6_TX	= 19,
    UDP_ZERO_CSUM6_RX	= 20,
    REMCSUM_TX		= 21,
    REMCSUM_RX		= 22,
    GBP			= 23,
    REMCSUM_NOPARTIAL	= 24,
    COLLECT_METADATA 	= 25,
    LABEL		= 26,
    GPE			= 27,
    _MAX 		= 28,
}
pub const IFLA_VXLAN_UNSPEC: u16		= Vxlan::UNSPEC as u16;
pub const IFLA_VXLAN_ID: u16			= Vxlan::ID as u16;
pub const IFLA_VXLAN_GROUP: u16			= Vxlan::GROUP as u16;
pub const IFLA_VXLAN_LINK: u16			= Vxlan::LINK as u16;
pub const IFLA_VXLAN_LOCAL: u16			= Vxlan::LOCAL as u16;
pub const IFLA_VXLAN_TTL: u16			= Vxlan::TTL as u16;
pub const IFLA_VXLAN_TOS: u16			= Vxlan::TOS as u16;
pub const IFLA_VXLAN_LEARNING: u16		= Vxlan::LEARNING as u16;
pub const IFLA_VXLAN_AGEING: u16		= Vxlan::AGEING as u16;
pub const IFLA_VXLAN_LIMIT: u16			= Vxlan::LIMIT as u16;
pub const IFLA_VXLAN_PORT_RANGE: u16		= Vxlan::PORT_RANGE as u16;
pub const IFLA_VXLAN_PROXY: u16			= Vxlan::PROXY as u16;
pub const IFLA_VXLAN_RSC: u16			= Vxlan::RSC as u16;
pub const IFLA_VXLAN_L2MISS: u16		= Vxlan::L2MISS as u16;
pub const IFLA_VXLAN_L3MISS: u16		= Vxlan::L3MISS as u16;
pub const IFLA_VXLAN_PORT: u16			= Vxlan::PORT as u16;
pub const IFLA_VXLAN_GROUP6: u16		= Vxlan::GROUP6 as u16;
pub const IFLA_VXLAN_LOCAL6: u16		= Vxlan::LOCAL6 as u16;
pub const IFLA_VXLAN_UDP_CSUM: u16		= Vxlan::UDP_CSUM as u16;
pub const IFLA_VXLAN_UDP_ZERO_CSUM6_TX: u16	= Vxlan::UDP_ZERO_CSUM6_TX as u16;
pub const IFLA_VXLAN_UDP_ZERO_CSUM6_RX: u16	= Vxlan::UDP_ZERO_CSUM6_RX as u16;
pub const IFLA_VXLAN_REMCSUM_TX: u16		= Vxlan::REMCSUM_TX as u16;
pub const IFLA_VXLAN_REMCSUM_RX: u16		= Vxlan::REMCSUM_RX as u16;
pub const IFLA_VXLAN_GBP: u16			= Vxlan::GBP as u16;
pub const IFLA_VXLAN_REMCSUM_NOPARTIAL: u16	= Vxlan::REMCSUM_NOPARTIAL as u16;
pub const IFLA_VXLAN_COLLECT_METADATA: u16	= Vxlan::COLLECT_METADATA as u16;
pub const IFLA_VXLAN_LABEL: u16			= Vxlan::LABEL as u16;
pub const IFLA_VXLAN_GPE: u16			= Vxlan::GPE as u16;
pub const __IFLA_VXLAN_MAX: u16			= Vxlan::_MAX as u16;
pub const IFLA_VXLAN_MAX: u16			= __IFLA_VXLAN_MAX - 1;

#[repr(C)]
pub struct IflaVxlanPortRange {
    pub low: u16,
    pub high: u16,
}

// GENEVE section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum Geneve {
    UNSPEC		= 0,
    ID			= 1,
    REMOTE		= 2,
    TTL			= 3,
    TOS			= 4,
    PORT		= 5,
    COLLECT_METADATA	= 6,
    REMOTE6		= 7,
    UDP_CSUM		= 8,
    UDP_ZERO_CSUM6_TX	= 9,
    UDP_ZERO_CSUM6_RX	= 10,
    LABEL		= 11,
    _MAX		= 12,
}
pub const IFLA_GENEVE_UNSPEC: u16		= Geneve::UNSPEC as u16;
pub const IFLA_GENEVE_ID: u16			= Geneve::ID as u16;
pub const IFLA_GENEVE_REMOTE: u16		= Geneve::REMOTE as u16;
pub const IFLA_GENEVE_TTL: u16			= Geneve::TTL as u16;
pub const IFLA_GENEVE_TOS: u16			= Geneve::TOS as u16;
pub const IFLA_GENEVE_PORT: u16			= Geneve::PORT as u16;
pub const IFLA_GENEVE_COLLECT_METADATA: u16	= Geneve::COLLECT_METADATA as u16;
pub const IFLA_GENEVE_REMOTE6: u16		= Geneve::REMOTE6 as u16;
pub const IFLA_GENEVE_UDP_CSUM: u16		= Geneve::UDP_CSUM as u16;
pub const IFLA_GENEVE_UDP_ZERO_CSUM6_TX: u16	= Geneve::UDP_ZERO_CSUM6_TX as u16;
pub const IFLA_GENEVE_UDP_ZERO_CSUM6_RX: u16	= Geneve::UDP_ZERO_CSUM6_RX as u16;
pub const IFLA_GENEVE_LABEL: u16		= Geneve::LABEL as u16;
pub const __IFLA_GENEVE_MAX: u16		= Geneve::_MAX as u16;
pub const IFLA_GENEVE_MAX: u16			= __IFLA_GENEVE_MAX - 1;

// PPP section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum Ppp {
    UNSPEC	= 0,
    DEV_FD	= 1,
    _MAX	= 2,
}
pub const IFLA_PPP_UNSPEC: u16	= Ppp::UNSPEC as u16;
pub const IFLA_PPP_DEV_FD: u16	= Ppp::DEV_FD as u16;
pub const __IFLA_PPP_MAX: u16	= Ppp::_MAX as u16;
pub const IFLA_PPP_MAX: u16	= __IFLA_PPP_MAX - 1;

// GTP section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum IflaGtpRole {
    GGSN	= 0,
    SGSN	= 1,
}
pub const GTP_ROLE_GGSN: u32	= IflaGtpRole::GGSN as u32;
pub const GTP_ROLE_SGSN: u32	= IflaGtpRole::SGSN as u32;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum Gtp {
    UNSPEC		= 0,
    FD0			= 1,
    FD1			= 2,
    PDP_HASHSIZE	= 3,
    ROLE		= 4,
    _MAX		= 5,
}
pub const IFLA_GTP_UNSPEC: u16		= Gtp::UNSPEC as u16;
pub const IFLA_GTP_FD0: u16		= Gtp::FD0 as u16;
pub const IFLA_GTP_FD1: u16		= Gtp::FD1 as u16;
pub const IFLA_GTP_PDP_HASHSIZE: u16	= Gtp::PDP_HASHSIZE as u16;
pub const IFLA_GTP_ROLE: u16		= Gtp::ROLE as u16;
pub const __IFLA_GTP_MAX: u16		= Gtp::_MAX as u16;
pub const IFLA_GTP_MAX: u16		= __IFLA_GTP_MAX - 1;

// Bonding section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum Bond {
    UNSPEC		= 0,
    MODE		= 1,
    ACTIVE_SLAVE	= 2,
    MIIMON		= 3,
    UPDELAY		= 4,
    DOWNDELAY		= 5,
    USE_CARRIER		= 6,
    ARP_INTERVAL	= 7,
    ARP_IP_TARGET	= 8,
    ARP_VALIDATE	= 9,
    ARP_ALL_TARGETS	= 10,
    PRIMARY		= 11,
    PRIMARY_RESELECT	= 12,
    FAIL_OVER_MAC	= 13,
    XMIT_HASH_POLICY	= 14,
    RESEND_IGMP		= 15,
    NUM_PEER_NOTIF	= 16,
    ALL_SLAVES_ACTIVE	= 17,
    MIN_LINKS		= 18,
    LP_INTERVAL		= 19,
    PACKETS_PER_SLAVE	= 20,
    AD_LACP_RATE	= 21,
    AD_SELECT		= 22,
    AD_INFO		= 23,
    AD_ACTOR_SYS_PRIO	= 24,
    AD_USER_PORT_KEY	= 25,
    AD_ACTOR_SYSTEM	= 26,
    TLB_DYNAMIC_LB	= 27,
    _MAX		= 28,
}
pub const IFLA_BOND_UNSPEC: u16			= Bond::UNSPEC as u16;
pub const IFLA_BOND_MODE: u16			= Bond::MODE as u16;
pub const IFLA_BOND_ACTIVE_SLAVE: u16		= Bond::ACTIVE_SLAVE as u16;
pub const IFLA_BOND_MIIMON: u16			= Bond::MIIMON as u16;
pub const IFLA_BOND_UPDELAY: u16		= Bond::UPDELAY as u16;
pub const IFLA_BOND_DOWNDELAY: u16		= Bond::DOWNDELAY as u16;
pub const IFLA_BOND_USE_CARRIER: u16		= Bond::USE_CARRIER as u16;
pub const IFLA_BOND_ARP_INTERVAL: u16		= Bond::ARP_INTERVAL as u16;
pub const IFLA_BOND_ARP_IP_TARGET: u16		= Bond::ARP_IP_TARGET as u16;
pub const IFLA_BOND_ARP_VALIDATE: u16		= Bond::ARP_VALIDATE as u16;
pub const IFLA_BOND_ARP_ALL_TARGETS: u16	= Bond::ARP_ALL_TARGETS as u16;
pub const IFLA_BOND_PRIMARY: u16		= Bond::PRIMARY as u16;
pub const IFLA_BOND_PRIMARY_RESELECT: u16	= Bond::PRIMARY_RESELECT as u16;
pub const IFLA_BOND_FAIL_OVER_MAC: u16		= Bond::FAIL_OVER_MAC as u16;
pub const IFLA_BOND_XMIT_HASH_POLICY: u16	= Bond::XMIT_HASH_POLICY as u16;
pub const IFLA_BOND_RESEND_IGMP: u16		= Bond::RESEND_IGMP as u16;
pub const IFLA_BOND_NUM_PEER_NOTIF: u16		= Bond::NUM_PEER_NOTIF as u16;
pub const IFLA_BOND_ALL_SLAVES_ACTIVE: u16	= Bond::ALL_SLAVES_ACTIVE as u16;
pub const IFLA_BOND_MIN_LINKS: u16		= Bond::MIN_LINKS as u16;
pub const IFLA_BOND_LP_INTERVAL: u16		= Bond::LP_INTERVAL as u16;
pub const IFLA_BOND_PACKETS_PER_SLAVE: u16	= Bond::PACKETS_PER_SLAVE as u16;
pub const IFLA_BOND_AD_LACP_RATE: u16		= Bond::AD_LACP_RATE as u16;
pub const IFLA_BOND_AD_SELECT: u16		= Bond::AD_SELECT as u16;
pub const IFLA_BOND_AD_INFO: u16		= Bond::AD_INFO as u16;
pub const IFLA_BOND_AD_ACTOR_SYS_PRIO: u16	= Bond::AD_ACTOR_SYS_PRIO as u16;
pub const IFLA_BOND_AD_USER_PORT_KEY: u16	= Bond::AD_USER_PORT_KEY as u16;
pub const IFLA_BOND_AD_ACTOR_SYSTEM: u16	= Bond::AD_ACTOR_SYSTEM as u16;
pub const IFLA_BOND_TLB_DYNAMIC_LB: u16		= Bond::TLB_DYNAMIC_LB as u16;
pub const __IFLA_BOND_MAX: u16			= Bond::_MAX as u16;
pub const IFLA_BOND_MAX: u16			= __IFLA_BOND_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum BondAdInfo {
    UNSPEC	= 0,
    AGGREGATOR	= 1,
    NUM_PORTS	= 2,
    ACTOR_KEY	= 3,
    PARTNER_KEY	= 4,
    PARTNER_MAC	= 5,
    _MAX	= 6,
}
pub const IFLA_BOND_AD_INFO_UNSPEC: u16		= BondAdInfo::UNSPEC as u16;
pub const IFLA_BOND_AD_INFO_AGGREGATOR: u16	= BondAdInfo::AGGREGATOR as u16;
pub const IFLA_BOND_AD_INFO_NUM_PORTS: u16	= BondAdInfo::NUM_PORTS as u16;
pub const IFLA_BOND_AD_INFO_ACTOR_KEY: u16	= BondAdInfo::ACTOR_KEY as u16;
pub const IFLA_BOND_AD_INFO_PARTNER_KEY: u16	= BondAdInfo::PARTNER_KEY as u16;
pub const IFLA_BOND_AD_INFO_PARTNER_MAC: u16	= BondAdInfo::PARTNER_MAC as u16;
pub const __IFLA_BOND_AD_INFO_MAX: u16		= BondAdInfo::_MAX as u16;
pub const IFLA_BOND_AD_INFO_MAX: u16		= __IFLA_BOND_AD_INFO_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum BondSlave {
    UNSPEC			= 0,
    STATE			= 1,
    MII_STATUS			= 2,
    LINK_FAILURE_COUNT		= 3,
    PERM_HWADDR			= 4,
    QUEUE_ID			= 5,
    AD_AGGREGATOR_ID		= 6,
    AD_ACTOR_OPER_PORT_STATE	= 7,
    AD_PARTNER_OPER_PORT_STATE	= 8,
    _MAX			= 9,
}
pub const IFLA_BOND_SLAVE_UNSPEC: u16				= BondSlave::UNSPEC as u16;
pub const IFLA_BOND_SLAVE_STATE: u16				= BondSlave::STATE as u16;
pub const IFLA_BOND_SLAVE_MII_STATUS: u16			= BondSlave::MII_STATUS as u16;
pub const IFLA_BOND_SLAVE_LINK_FAILURE_COUNT: u16		= BondSlave::LINK_FAILURE_COUNT as u16;
pub const IFLA_BOND_SLAVE_PERM_HWADDR: u16			= BondSlave::PERM_HWADDR as u16;
pub const IFLA_BOND_SLAVE_QUEUE_ID: u16				= BondSlave::QUEUE_ID as u16;
pub const IFLA_BOND_SLAVE_AD_AGGREGATOR_ID: u16			= BondSlave::AD_AGGREGATOR_ID as u16;
pub const IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE: u16		= BondSlave::AD_ACTOR_OPER_PORT_STATE as u16;
pub const IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE: u16	= BondSlave::AD_PARTNER_OPER_PORT_STATE as u16;
pub const __IFLA_BOND_SLAVE_MAX: u16				= BondSlave::_MAX as u16;
pub const IFLA_BOND_SLAVE_MAX: u16				= __IFLA_BOND_SLAVE_MAX - 1;

// SR-IOV virtual function management section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum SrIov { // XXX: naming
    UNSPEC	= 0,
    INFO	= 1,
    _MAX	= 2,
}
pub const IFLA_VF_INFO_UNSPEC: u16	= SrIov::UNSPEC as u16;
pub const IFLA_VF_INFO: u16		= SrIov::INFO as u16;
pub const __IFLA_VF_INFO_MAX: u16	= SrIov::_MAX as u16;
pub const IFLA_VF_INFO_MAX: u16		= __IFLA_VF_INFO_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum VrInfo {
    UNSPEC		= 0,
    MAC			= 1,	// Hardware queue specific attributes
    VLAN		= 2,	// VLAN ID and QoS
    TX_RATE		= 3,	// Max TX Bandwidth Allocation
    SPOOFCHK		= 4,	// Spoof Checking on/off switch
    LINK_STATE		= 5,	// link state enable/disable/auto switch
    RATE		= 6,	// Min and Max TX Bandwidth Allocation
    RSS_QUERY_EN	= 7,	// RSS Redirection Table and Hash Key query
	        		// on/off switch
    STATS		= 8,	// network device statistics
    TRUST		= 9,	// Trust VF
    IB_NODE_GUID	= 10,	// VF Infiniband node GUID
    IB_PORT_GUID	= 11,	// VF Infiniband port GUID
    VLAN_LIST		= 12,	// nested list of vlans, option for QinQ
    _MAX		= 13,
}
pub const IFLA_VF_UNSPEC: u16		= VrInfo::UNSPEC as u16;
pub const IFLA_VF_MAC: u16		= VrInfo::MAC as u16;
pub const IFLA_VF_VLAN: u16		= VrInfo::VLAN as u16;
pub const IFLA_VF_TX_RATE: u16		= VrInfo::TX_RATE as u16;
pub const IFLA_VF_SPOOFCHK: u16		= VrInfo::SPOOFCHK as u16;
pub const IFLA_VF_LINK_STATE: u16	= VrInfo::LINK_STATE as u16;
pub const IFLA_VF_RATE: u16		= VrInfo::RATE as u16;
pub const IFLA_VF_RSS_QUERY_EN: u16	= VrInfo::RSS_QUERY_EN as u16;
pub const IFLA_VF_STATS: u16		= VrInfo::STATS as u16;
pub const IFLA_VF_TRUST: u16		= VrInfo::TRUST as u16;
pub const IFLA_VF_IB_NODE_GUID: u16	= VrInfo::IB_NODE_GUID as u16;
pub const IFLA_VF_IB_PORT_GUID: u16	= VrInfo::IB_PORT_GUID as u16;
pub const IFLA_VF_VLAN_LIST: u16	= VrInfo::VLAN_LIST as u16;
pub const __IFLA_VF_MAX: u16		= VrInfo::_MAX as u16;
pub const IFLA_VF_MAX: u16		= __IFLA_VF_MAX - 1;

#[repr(C)]
pub struct IflaVfMac {
    pub vf: u32,
    pub mac: [u8; 32usize],	// MAX_ADDR_LEN
}

#[repr(C)]
pub struct IflaVfVlan {
    pub vf: u32,
    pub vlan: u32,	// 0 - 4095, 0 disables VLAN filter
    pub qos: u32,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum VfVlan { // XXX: naming
    UNSPEC	= 0,
    INFO	= 1,	// VLAN ID, QoS and VLAN protocol
    _MAX	= 2,
}

pub const IFLA_VF_VLAN_INFO_UNSPEC: u16	= VfVlan::UNSPEC as u16;
pub const IFLA_VF_VLAN_INFO: u16	= VfVlan::INFO as u16;
pub const __IFLA_VF_VLAN_INFO_MAX: u16	= VfVlan::_MAX as u16;
pub const IFLA_VF_VLAN_INFO_MAX: u16	= __IFLA_VF_VLAN_INFO_MAX - 1;
pub const MAX_VLAN_LIST_LEN: usize	= 1usize;

#[repr(C)]
pub struct IflaVfVlanInfo {
    pub vf: u32,
    pub vlan: u32,		// 0 - 4095, 0 disables VLAN filter
    pub qos: u32,
    pub vlan_proto: u16,	// VLAN protocol either 802.1Q or 802.1ad
}

#[repr(C)]
pub struct IflaVfTxRate {
    pub vf: u32,
    pub rate: u32,	// Max TX bandwidth in Mbps, 0 disables throttling
}

#[repr(C)]
pub struct IflaVfRate {
    pub vf: u32,
    pub min_tx_rate: u32,	// Min Bandwidth in Mbps
    pub max_tx_rate: u32,	// Max Bandwidth in Mbps
}

#[repr(C)]
pub struct IflaVfSpoofchk {
    pub vf: u32,
    pub setting: u32,
}

#[repr(C)]
pub struct IflaVfGuid {
    pub vf: u32,
    pub guid: u64,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u32)] // ifla_vf_info.linkstate
pub enum VfLinkState {
    AUTO	= 0,	// link state of the uplink
    ENABLE	= 1,	// link always up
    DISABLE	= 2,	// link always down
    _MAX	= 3,
}
// XXX: no MAX def?

#[repr(C)]
pub struct IflaVfLinkState {
    pub vf: u32,
    pub link_state: u32,
}

#[repr(C)]
pub struct IflaVfRssQueryEn {
    pub vf: u32,
    pub setting: u32,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum VfStats {
    RX_PACKETS	= 0,
    TX_PACKETS	= 1,
    RX_BYTES	= 2,
    TX_BYTES	= 3,
    BROADCAST	= 4,
    MULTICAST	= 5,
    PAD		= 6,
    _MAX	= 7,
}
pub const IFLA_VF_STATS_RX_PACKETS: u16	= VfStats::RX_PACKETS as u16;
pub const IFLA_VF_STATS_TX_PACKETS: u16	= VfStats::TX_PACKETS as u16;
pub const IFLA_VF_STATS_RX_BYTES: u16	= VfStats::RX_BYTES as u16;
pub const IFLA_VF_STATS_TX_BYTES: u16	= VfStats::TX_BYTES as u16;
pub const IFLA_VF_STATS_BROADCAST: u16	= VfStats::BROADCAST as u16;
pub const IFLA_VF_STATS_MULTICAST: u16	= VfStats::MULTICAST as u16;
pub const IFLA_VF_STATS_PAD: u16	= VfStats::PAD as u16;
pub const __IFLA_VF_STATS_MAX: u16	= VfStats::_MAX as u16;
pub const IFLA_VF_STATS_MAX: u16	= __IFLA_VF_STATS_MAX - 1;

#[repr(C)]
pub struct ifla_vf_trust {
    pub vf: u32,
    pub setting: u32,
}

// VF ports management section
//
//	Nested layout of set/get msg is:
//
//		[IFLA_NUM_VF]
//		[IFLA_VF_PORTS]
//			[IFLA_VF_PORT]
//				[IFLA_PORT_*], ...
//			[IFLA_VF_PORT]
//				[IFLA_PORT_*], ...
//			...
//		[IFLA_PORT_SELF]
//			[IFLA_PORT_*], ...

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum VfPort { // XXX: naming
    UNSPEC	= 0,
    PORT	= 1,
    _MAX	= 2,
}
pub const IFLA_VF_PORT_UNSPEC: u16	= VfPort::UNSPEC as u16;
pub const IFLA_VF_PORT: u16		= VfPort::PORT as u16;	// nest
pub const __IFLA_VF_PORT_MAX: u16	= VfPort::_MAX as u16;
pub const IFLA_VF_PORT_MAX: u16		= __IFLA_VF_PORT_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum VfPortInfo { // XXX: naming
    UNSPEC		= 0,
    VF			= 1,	// __u32
    PROFILE		= 2,	// string
    VSI_TYPE		= 3,	// 802.1Qbg (pre-)standard VDP
    INSTANCE_UUID	= 4,	// binary UUID
    HOST_UUID		= 5,	// binary UUID
    REQUEST		= 6,	// __u8
    RESPONSE		= 7,	// __u16, output only
    _MAX		= 8,
}
pub const IFLA_PORT_UNSPEC: u16		= VfPortInfo::UNSPEC as u16;
pub const IFLA_PORT_VF: u16		= VfPortInfo::VF as u16;
pub const IFLA_PORT_PROFILE: u16	= VfPortInfo::PROFILE as u16;
pub const IFLA_PORT_VSI_TYPE: u16	= VfPortInfo::VSI_TYPE as u16;
pub const IFLA_PORT_INSTANCE_UUID: u16	= VfPortInfo::INSTANCE_UUID as u16;
pub const IFLA_PORT_HOST_UUID: u16	= VfPortInfo::HOST_UUID as u16;
pub const IFLA_PORT_REQUEST: u16	= VfPortInfo::REQUEST as u16;
pub const IFLA_PORT_RESPONSE: u16	= VfPortInfo::RESPONSE as u16;
pub const __IFLA_PORT_MAX: u16		= VfPortInfo::_MAX as u16;
pub const IFLA_PORT_MAX: u16		= __IFLA_PORT_MAX - 1;

pub const PORT_PROFILE_MAX: usize	= 40;
pub const PORT_UUID_MAX: usize		= 16;
pub const PORT_SELF_VF: c_int		= -1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum Enum_Unnamed30 { // enoc only?
    PORT_REQUEST_PREASSOCIATE = 0,
    PORT_REQUEST_PREASSOCIATE_RR = 1,
    PORT_REQUEST_ASSOCIATE = 2,
    PORT_REQUEST_DISASSOCIATE = 3,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum Enum_Unnamed31 { // not used, just defined?
    PORT_VDP_RESPONSE_SUCCESS = 0,
    PORT_VDP_RESPONSE_INVALID_FORMAT = 1,
    PORT_VDP_RESPONSE_INSUFFICIENT_RESOURCES = 2,
    PORT_VDP_RESPONSE_UNUSED_VTID = 3,
    PORT_VDP_RESPONSE_VTID_VIOLATION = 4,
    PORT_VDP_RESPONSE_VTID_VERSION_VIOALTION = 5,
    PORT_VDP_RESPONSE_OUT_OF_SYNC = 6,
    // 0x08-0xFF reserved for future VDP use
    PORT_PROFILE_RESPONSE_SUCCESS = 256,
    PORT_PROFILE_RESPONSE_INPROGRESS = 257,
    PORT_PROFILE_RESPONSE_INVALID = 258,
    PORT_PROFILE_RESPONSE_BADSTATE = 259,
    PORT_PROFILE_RESPONSE_INSUFFICIENT_RESOURCES = 260,
    PORT_PROFILE_RESPONSE_ERROR = 261,
}

#[repr(C)]
pub struct ifla_port_vsi {
    pub vsi_mgr_id: u8,
    pub vsi_type_id: [u8; 3usize],
    pub vsi_type_version: u8,
    pub pad: [u8; 3usize],
}

// IPoIB section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum Ipoib {
    UNSPEC	= 0,
    PKEY	= 1,
    MODE	= 2,
    UMCAST	= 3,
    _MAX	= 4,
}

pub const IFLA_IPOIB_UNSPEC: u16	= Ipoib::UNSPEC as u16;
pub const IFLA_IPOIB_PKEY: u16		= Ipoib::PKEY as u16;
pub const IFLA_IPOIB_MODE: u16		= Ipoib::MODE as u16;
pub const IFLA_IPOIB_UMCAST: u16	= Ipoib::UMCAST as u16;
pub const __IFLA_IPOIB_MAX: u16		= Ipoib::_MAX as u16;
pub const IFLA_IPOIB_MAX: u16		= __IFLA_IPOIB_MAX - 1;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum IpoibMode {
    DATAGRAM	= 0, // using unreliable datagram QPs
    CONNECTED	= 1, // using connected QPs
}

// HSR section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum Hsr {
    UNSPEC		= 0,
    SLAVE1		= 1,
    SLAVE2		= 2,
    MULTICAST_SPEC	= 3,	// Last byte of supervision addr
    SUPERVISION_ADDR	= 4,	// Supervision frame multicast addr
    SEQ_NR		= 5,
    VERSION		= 6,	// HSR version
    _MAX		= 7,
}
pub const IFLA_HSR_UNSPEC: u16			= Hsr::UNSPEC as u16;
pub const IFLA_HSR_SLAVE1: u16			= Hsr::SLAVE1 as u16;
pub const IFLA_HSR_SLAVE2: u16			= Hsr::SLAVE2 as u16;
pub const IFLA_HSR_MULTICAST_SPEC: u16		= Hsr::MULTICAST_SPEC as u16;
pub const IFLA_HSR_SUPERVISION_ADDR: u16	= Hsr::SUPERVISION_ADDR as u16;
pub const IFLA_HSR_SEQ_NR: u16			= Hsr::SEQ_NR as u16;
pub const IFLA_HSR_VERSION: u16			= Hsr::VERSION as u16;
pub const __IFLA_HSR_MAX: u16			= Hsr::_MAX as u16;
pub const IFLA_HSR_MAX: u16			= __IFLA_HSR_MAX - 1;

// STATS section
#[repr(C)]
pub struct IfStatsMsg {
    pub family: u8,
    _pad1: u8,
    _pad2: u16,
    pub ifindex: u32,
    pub filter_mask: u32,
}

// A stats attribute can be netdev specific or a global stat.
// For netdev stats, lets use the prefix IFLA_STATS_LINK_
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)] // maybe
pub enum Stats {
    UNSPEC		= 0,	// also used as 64bit pad attribute
    LINK_64		= 1,
    LINK_XSTATS		= 2,
    LINK_XSTATS_SLAVE	= 3,
    LINK_OFFLOAD_XSTATS	= 4,
    AF_SPEC		= 5,
    _MAX		= 6,
}
pub const IFLA_STATS_UNSPEC: u16		= Stats::UNSPEC as u16;
pub const IFLA_STATS_LINK_64: u16		= Stats::LINK_64 as u16;
pub const IFLA_STATS_LINK_XSTATS: u16		= Stats::LINK_XSTATS as u16;
pub const IFLA_STATS_LINK_XSTATS_SLAVE: u16	= Stats::LINK_XSTATS_SLAVE as u16;
pub const IFLA_STATS_LINK_OFFLOAD_XSTATS: u16	= Stats::LINK_OFFLOAD_XSTATS as u16;
pub const IFLA_STATS_AF_SPEC: u16		= Stats::AF_SPEC as u16;
pub const __IFLA_STATS_MAX: u16			= Stats::_MAX as u16;
pub const IFLA_STATS_MAX: u16			= __IFLA_STATS_MAX - 1;

#[allow(non_snake_case)]
pub fn IFLA_STATS_FILTER_BIT(ATTR: u16) -> u16 {
    1 << (ATTR - 1)
}

// These are embedded into IFLA_STATS_LINK_XSTATS:
// [IFLA_STATS_LINK_XSTATS]
// -> [LINK_XSTATS_TYPE_xxx]
//    -> [rtnl link type specific attributes]
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum LinkXstatsType {
    UNSPEC	= 0,
    BRIDGE	= 1,
    _MAX	= 2,
}
pub const LINK_XSTATS_TYPE_UNSPEC: u16	 = LinkXstatsType::UNSPEC as u16;
pub const LINK_XSTATS_TYPE_BRIDGE: u16	 = LinkXstatsType::BRIDGE as u16;
pub const __LINK_XSTATS_TYPE_MAX: u16	 = LinkXstatsType::_MAX as u16;
pub const LINK_XSTATS_TYPE_MAX: u16	 = __LINK_XSTATS_TYPE_MAX - 1;

// These are stats embedded into IFLA_STATS_LINK_OFFLOAD_XSTATS
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum OffloadXstats {
    UNSPEC	= 0,
    CPU_HIT	= 1,	// struct rtnl_link_stats64
    _MAX	= 2,
}
pub const IFLA_OFFLOAD_XSTATS_UNSPEC: u16	= OffloadXstats::UNSPEC as u16;
pub const IFLA_OFFLOAD_XSTATS_CPU_HIT: u16	= OffloadXstats::CPU_HIT as u16;
pub const __IFLA_OFFLOAD_XSTATS_MAX: u16	= OffloadXstats::_MAX as u16;
pub const IFLA_OFFLOAD_XSTATS_MAX: u16		= __IFLA_OFFLOAD_XSTATS_MAX - 1;

// XDP section
pub const XDP_FLAGS_UPDATE_IF_NOEXIST: u32	= 1 << 0;
pub const XDP_FLAGS_SKB_MODE: u32		= 2 << 0;
pub const XDP_FLAGS_MASK: u32			= (XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE);

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum Xdp {
    UNSPEC	= 0,
    FD		= 1,
    ATTACHED	= 2,
    FLAGS	= 3,
    _MAX	= 4,
}
pub const IFLA_XDP_UNSPEC: u16		= Xdp::UNSPEC as u16;
pub const IFLA_XDP_FD: u16		= Xdp::FD as u16;
pub const IFLA_XDP_ATTACHED: u16	= Xdp::ATTACHED as u16;
pub const IFLA_XDP_FLAGS: u16		= Xdp::FLAGS as u16;
pub const __IFLA_XDP_MAX: u16		= Xdp::_MAX as u16;
pub const IFLA_XDP_MAX: u16		= __IFLA_XDP_MAX - 1;

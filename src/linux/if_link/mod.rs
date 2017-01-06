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
pub const IFLA_MAX: u16	= AttrType::_MAX as u16 - 1;

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


#[repr(u16)]
pub enum AttrTypeInet {
    UNSPEC	= 0,
    CONF	= 1,
    _MAX	= 2,
}
pub const IFLA_INET_MAX: u16 = AttrTypeInet::_MAX as u16 - 1;

pub const IFLA_INET_UNSPEC: u16	= AttrTypeInet::UNSPEC as u16;
pub const IFLA_INET_CONF: u16	= AttrTypeInet::CONF as u16;


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
pub const IFLA_INET6_MAX: u16 = AttrTypeInet6::_MAX as u16 - 1;
pub const IFLA_INET6_UNSPEC: u16	= AttrTypeInet6::UNSPEC as u16;
pub const IFLA_INET6_FLAGS: u16		= AttrTypeInet6::FLAGS as u16;
pub const IFLA_INET6_CONF: u16		= AttrTypeInet6::CONF as u16;
pub const IFLA_INET6_STATS: u16		= AttrTypeInet6::STATS as u16;
pub const IFLA_INET6_MCAST: u16		= AttrTypeInet6::MCAST as u16;
pub const IFLA_INET6_CACHEINFO: u16	= AttrTypeInet6::CACHEINFO as u16;
pub const IFLA_INET6_ICMP6STATS: u16	= AttrTypeInet6::ICMP6STATS as u16;
pub const IFLA_INET6_TOKEN: u16		= AttrTypeInet6::TOKEN as u16;
pub const IFLA_INET6_ADDR_GEN_MODE: u16	= AttrTypeInet6::ADDR_GEN_MODE as u16;

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
pub const IFLA_BR_MAX: u16				= AttrTypeBr::_MAX - 1;
pub const IFLA_BR_UNSPEC: u16				= AttrTypeBr::UNSPEC as u16;
pub const IFLA_BR_FORWARD_DELAY: u16			= AttrTypeBr::FORWARD_DELAY as u16;
pub const IFLA_BR_HELLO_TIME: u16			= AttrTypeBr::HELLO_TIME as u16;
pub const IFLA_BR_MAX_AGE : u16				= AttrTypeBr::MAX_AGE as u16;
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

#[repr(C)]
pub struct IflaBridgeId {
    pub prio: [u8; 2usize],
    pub addr: [u8; 6usize],
}

// XXX: unused?
#[repr(u32)]
pub enum BridgeMode {
    UNSPEC	= 0,
    HAIRPIN	= 1,
}
pub const BRIDGE_MODE_UNSPECL: u32 = BridgeMode::UNSPEC;
pub const BRIDGE_MODE_HAIRPIN: u32 = BridgeMode::HAIRPIN;

#[repr(u16)]

enum AttrBrport {
	IFLA_BRPORT_UNSPEC		= 0,
	IFLA_BRPORT_STATE		= 1,	// Spanning tree state
	IFLA_BRPORT_PRIORITY		= 2,	// "             priority
	IFLA_BRPORT_COST		= 3,	// "             cost
	IFLA_BRPORT_MODE		= 4,	// mode (hairpin)
	IFLA_BRPORT_GUARD		= 5,	// bpdu guard
	IFLA_BRPORT_PROTECT		= 6,	// root port protection
	IFLA_BRPORT_FAST_LEAVE		= 7,	// multicast fast leave
	IFLA_BRPORT_LEARNING		= 8,	// mac learning
	IFLA_BRPORT_UNICAST_FLOOD	= 9,	// flood unicast traffic
	IFLA_BRPORT_PROXYARP		= 10,	// proxy ARP
	IFLA_BRPORT_LEARNING_SYNC	= 11,	// mac learning sync from device
	IFLA_BRPORT_PROXYARP_WIFI	= 12,	// proxy ARP for Wi-Fi
	IFLA_BRPORT_ROOT_ID		= 13,	// designated root
	IFLA_BRPORT_BRIDGE_ID		= 14,	// designated bridge
	IFLA_BRPORT_DESIGNATED_PORT	= 15,
	IFLA_BRPORT_DESIGNATED_COST	= 16,
	IFLA_BRPORT_ID			= 17,
	IFLA_BRPORT_NO			= 18,
	IFLA_BRPORT_TOPOLOGY_CHANGE_ACK	= 19,
	IFLA_BRPORT_CONFIG_PENDING	= 20,
	IFLA_BRPORT_MESSAGE_AGE_TIMER	= 21,
	IFLA_BRPORT_FORWARD_DELAY_TIMER	= 22,
	IFLA_BRPORT_HOLD_TIMER		= 23,
	IFLA_BRPORT_FLUSH		= 24,
	IFLA_BRPORT_MULTICAST_ROUTER	= 25,
	IFLA_BRPORT_PAD			= 26,
	IFLA_BRPORT_MCAST_FLOOD		= 27,
	_MAX			       	= 28
};
pub const IFLA_BRPORT_MAX: u16			= AttrBrport::_MAX - 1 as u16;
pub const IFLA_BRPORT_UNSPEC: u16		= AttrBrport::IFLA_BRPORT_UNSPEC as u16;
pub const IFLA_BRPORT_STATE: u16		= AttrBrport::IFLA_BRPORT_STATE as u16;
pub const IFLA_BRPORT_PRIORITY: u16		= AttrBrport::IFLA_BRPORT_PRIORITY as u16;
pub const IFLA_BRPORT_COST: u16			= AttrBrport::IFLA_BRPORT_COST as u16;
pub const IFLA_BRPORT_MODE: u16			= AttrBrport::IFLA_BRPORT_MODE as u16;
pub const IFLA_BRPORT_GUARD: u16		= AttrBrport::IFLA_BRPORT_GUARD as u16;
pub const IFLA_BRPORT_PROTECT: u16		= AttrBrport::IFLA_BRPORT_PROTECT as u16;
pub const IFLA_BRPORT_FAST_LEAVE: u16		= AttrBrport::IFLA_BRPORT_FAST_LEAVE as u16;
pub const IFLA_BRPORT_LEARNING: u16		= AttrBrport::IFLA_BRPORT_LEARNING as u16;
pub const IFLA_BRPORT_UNICAST_FLOOD: u16	= AttrBrport::IFLA_BRPORT_UNICAST_FLOOD as u16;
pub const IFLA_BRPORT_PROXYARP: u16		= AttrBrport::IFLA_BRPORT_PROXYARP as u16;
pub const IFLA_BRPORT_LEARNING_SYNC: u16	= AttrBrport::IFLA_BRPORT_LEARNING_SYNC as u16;
pub const IFLA_BRPORT_PROXYARP_WIFI: u16	= AttrBrport::IFLA_BRPORT_PROXYARP_WIFI as u16;
pub const IFLA_BRPORT_ROOT_ID: u16		= AttrBrport::IFLA_BRPORT_ROOT_ID as u16;
pub const IFLA_BRPORT_BRIDGE_ID: u16		= AttrBrport::IFLA_BRPORT_BRIDGE_ID as u16;
pub const IFLA_BRPORT_DESIGNATED_PORT: u16	= AttrBrport::IFLA_BRPORT_DESIGNATED_PORT as u16;
pub const IFLA_BRPORT_DESIGNATED_COST: u16	= AttrBrport::IFLA_BRPORT_DESIGNATED_COST as u16;
pub const IFLA_BRPORT_ID: u16			= AttrBrport::IFLA_BRPORT_ID as u16;
pub const IFLA_BRPORT_NO: u16			= AttrBrport::IFLA_BRPORT_NO as u16;
pub const IFLA_BRPORT_TOPOLOGY_CHANGE_ACK: u16	= AttrBrport::IFLA_BRPORT_TOPOLOGY_CHANGE_ACK as u16;
pub const IFLA_BRPORT_CONFIG_PENDING: u16	= AttrBrport::IFLA_BRPORT_CONFIG_PENDING as u16;
pub const IFLA_BRPORT_MESSAGE_AGE_TIMER: u16	= AttrBrport::IFLA_BRPORT_MESSAGE_AGE_TIMER as u16;
pub const IFLA_BRPORT_FORWARD_DELAY_TIMER: u16	= AttrBrport::IFLA_BRPORT_FORWARD_DELAY_TIMER as u16;
pub const IFLA_BRPORT_HOLD_TIMER: u16		= AttrBrport::IFLA_BRPORT_HOLD_TIMER as u16;
pub const IFLA_BRPORT_FLUSH: u16		= AttrBrport::IFLA_BRPORT_FLUSH as u16;
pub const IFLA_BRPORT_MULTICAST_ROUTER: u16	= AttrBrport::IFLA_BRPORT_MULTICAST_ROUTER as u16;
pub const IFLA_BRPORT_PAD: u16			= AttrBrport::IFLA_BRPORT_PAD as u16;
pub const IFLA_BRPORT_MCAST_FLOOD: u16		= AttrBrport::IFLA_BRPORT_MCAST_FLOOD as u16;

#[repr(C)]
pub struct IflaCacheinfo {
    pub max_reasm_len: u32,
    pub tstamp: u32,
    pub reachable_time: u32,
    pub retrans_time: u32,
}

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
pub const IFLA_INFO_MAX: u16		= AttrTypeInfo::_MAX as u16;
pub const IFLA_INFO_UNSPEC: u16		= AttrTypeInfo::UNSPEC as u16;
pub const IFLA_INFO_KIND: u16		= AttrTypeInfo::KIND as u16;
pub const IFLA_INFO_DATA: u16		= AttrTypeInfo::DATA as u16;
pub const IFLA_INFO_XSTATS: u16		= AttrTypeInfo::XSTATS as u16;
pub const IFLA_INFO_SLAVE_KIND: u16	= AttrTypeInfo::SLAVE_KIND as u16;
pub const IFLA_INFO_SLAVE_DATA: u16	= AttrTypeInfo::SLAVE_DATA as u16;

// VLAN section
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
pub const IFLA_INFO_MAX: u16		= AttrTypeVlan::_MAX as u16;
pub const IFLA_VLAN_UNSPEC: u16		= AttrTypeVlan::UNSPEC as u16;
pub const IFLA_VLAN_ID: u16		= AttrTypeVlan::ID as u16;
pub const IFLA_VLAN_FLAGS: u16		= AttrTypeVlan::FLAGS as u16;
pub const IFLA_VLAN_EGRESS_QOS: u16	= AttrTypeVlan::EGRESS_QOS as u16;
pub const IFLA_VLAN_INGRESS_QOS: u16	= AttrTypeVlan::INGRESS_QOS as u16;
pub const IFLA_VLAN_PROTOCOL: u16	= AttrTypeVlan::PROTOCOL as u16;

#[repr(C)]
pub struct IflaVlanFlags {
    pub flags: u32,
    pub mask: u32,
}

#[repr(u16)]
pub enum AttrTypeVlanQos {
    QOS_UNSPEC	= 0,
    QOS_MAPPING	= 1,
    _MAX	= 2,
}
pub const IFLA_VLAN_QOS_MAX: u16	= AttrTypeVlanQos::_MAX as u16;
pub const IFLA_VLAN_QOS_UNSPEC: u16	= AttrTypeVlanQos::QOS_UNSPEC as u16;
pub const IFLA_VLAN_QOS_MAPPING: u16	= AttrTypeVlanQos::QOS_MAPPING as u16;

#[repr(C)]
pub struct IflaVlanQosMapping {
    pub from: u32,
    pub to: u32,
}

// MACVLAN section
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
pub const IFLA_MACVLAN_MAX: u16			= AttrTypeMacvlan::_MAX as u16;
pub const IFLA_MACVLAN_UNSPEC: u16		= AttrTypeMacvlan::UNSPEC as u16;
pub const IFLA_MACVLAN_MODE: u16		= AttrTypeMacvlan::MODE as u16;
pub const IFLA_MACVLAN_FLAGS: u16		= AttrTypeMacvlan::FLAGS as u16;
pub const IFLA_MACVLAN_MACADDR_MODE: u16	= AttrTypeMacvlan::MACADDR_MODE as u16;
pub const IFLA_MACVLAN_MACADDR: u16		= AttrTypeMacvlan::MACADDR as u16;
pub const IFLA_MACVLAN_MACADDR_DATA: u16	= AttrTypeMacvlan::MACADDR_DATA as u16;
pub const IFLA_MACVLAN_MACADDR_COUNT: u16	= AttrTypeMacvlan::MACADDR_COUNT as u16;


#[repr(u32)]
pub enum MacvlanMode { // u8?
    PRIVATE	= 1,
    VEPA	= 2,
    BRIDGE	= 4,
    PASSTHRU	= 8,
    SOURCE	= 16,
}
pub const MACVLAN_MODE_PRIVATE: u32	= MacvlanMode::PRIVATE as u32;
pub const MACVLAN_MODE_VEPA: u32	= MacvlanMode::VEPA as u32;
pub const MACVLAN_MODE_BRIDGE: u32	= MacvlanMode::BRIDGE as u32;
pub const MACVLAN_MODE_PASSTHRU : u32	= MacvlanMode::PASSTHRU as u32;
pub const MACVLAN_MODE_SOURCE: u32	= MacvlanMode::SOURCE as u32;

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum macvlan_macaddr_mode {
    MACVLAN_MACADDR_ADD = 0,
    MACVLAN_MACADDR_DEL = 1,
    MACVLAN_MACADDR_FLUSH = 2,
    MACVLAN_MACADDR_SET = 3,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed12 {
    IFLA_VRF_UNSPEC = 0,
    IFLA_VRF_TABLE = 1,
    __IFLA_VRF_MAX = 2,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed13 {
    IFLA_VRF_PORT_UNSPEC = 0,
    IFLA_VRF_PORT_TABLE = 1,
    __IFLA_VRF_PORT_MAX = 2,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed14 {
    IFLA_MACSEC_UNSPEC = 0,
    IFLA_MACSEC_SCI = 1,
    IFLA_MACSEC_PORT = 2,
    IFLA_MACSEC_ICV_LEN = 3,
    IFLA_MACSEC_CIPHER_SUITE = 4,
    IFLA_MACSEC_WINDOW = 5,
    IFLA_MACSEC_ENCODING_SA = 6,
    IFLA_MACSEC_ENCRYPT = 7,
    IFLA_MACSEC_PROTECT = 8,
    IFLA_MACSEC_INC_SCI = 9,
    IFLA_MACSEC_ES = 10,
    IFLA_MACSEC_SCB = 11,
    IFLA_MACSEC_REPLAY_PROTECT = 12,
    IFLA_MACSEC_VALIDATION = 13,
    IFLA_MACSEC_PAD = 14,
    __IFLA_MACSEC_MAX = 15,
}
pub const MACSEC_VALIDATE_MAX: macsec_validation_type =
    macsec_validation_type::MACSEC_VALIDATE_STRICT;
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum macsec_validation_type {
    MACSEC_VALIDATE_DISABLED = 0,
    MACSEC_VALIDATE_CHECK = 1,
    MACSEC_VALIDATE_STRICT = 2,
    __MACSEC_VALIDATE_END = 3,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed15 {
    IFLA_IPVLAN_UNSPEC = 0,
    IFLA_IPVLAN_MODE = 1,
    __IFLA_IPVLAN_MAX = 2,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum ipvlan_mode {
    IPVLAN_MODE_L2 = 0,
    IPVLAN_MODE_L3 = 1,
    IPVLAN_MODE_L3S = 2,
    IPVLAN_MODE_MAX = 3,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed16 {
    IFLA_VXLAN_UNSPEC = 0,
    IFLA_VXLAN_ID = 1,
    IFLA_VXLAN_GROUP = 2,
    IFLA_VXLAN_LINK = 3,
    IFLA_VXLAN_LOCAL = 4,
    IFLA_VXLAN_TTL = 5,
    IFLA_VXLAN_TOS = 6,
    IFLA_VXLAN_LEARNING = 7,
    IFLA_VXLAN_AGEING = 8,
    IFLA_VXLAN_LIMIT = 9,
    IFLA_VXLAN_PORT_RANGE = 10,
    IFLA_VXLAN_PROXY = 11,
    IFLA_VXLAN_RSC = 12,
    IFLA_VXLAN_L2MISS = 13,
    IFLA_VXLAN_L3MISS = 14,
    IFLA_VXLAN_PORT = 15,
    IFLA_VXLAN_GROUP6 = 16,
    IFLA_VXLAN_LOCAL6 = 17,
    IFLA_VXLAN_UDP_CSUM = 18,
    IFLA_VXLAN_UDP_ZERO_CSUM6_TX = 19,
    IFLA_VXLAN_UDP_ZERO_CSUM6_RX = 20,
    IFLA_VXLAN_REMCSUM_TX = 21,
    IFLA_VXLAN_REMCSUM_RX = 22,
    IFLA_VXLAN_GBP = 23,
    IFLA_VXLAN_REMCSUM_NOPARTIAL = 24,
    IFLA_VXLAN_COLLECT_METADATA = 25,
    IFLA_VXLAN_LABEL = 26,
    IFLA_VXLAN_GPE = 27,
    __IFLA_VXLAN_MAX = 28,
}
#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct ifla_vxlan_port_range {
    pub low: __be16,
    pub high: __be16,
}
impl ::std::default::Default for ifla_vxlan_port_range {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed17 {
    IFLA_GENEVE_UNSPEC = 0,
    IFLA_GENEVE_ID = 1,
    IFLA_GENEVE_REMOTE = 2,
    IFLA_GENEVE_TTL = 3,
    IFLA_GENEVE_TOS = 4,
    IFLA_GENEVE_PORT = 5,
    IFLA_GENEVE_COLLECT_METADATA = 6,
    IFLA_GENEVE_REMOTE6 = 7,
    IFLA_GENEVE_UDP_CSUM = 8,
    IFLA_GENEVE_UDP_ZERO_CSUM6_TX = 9,
    IFLA_GENEVE_UDP_ZERO_CSUM6_RX = 10,
    IFLA_GENEVE_LABEL = 11,
    __IFLA_GENEVE_MAX = 12,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed18 {
    IFLA_PPP_UNSPEC = 0,
    IFLA_PPP_DEV_FD = 1,
    __IFLA_PPP_MAX = 2,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed19 {
    IFLA_GTP_UNSPEC = 0,
    IFLA_GTP_FD0 = 1,
    IFLA_GTP_FD1 = 2,
    IFLA_GTP_PDP_HASHSIZE = 3,
    __IFLA_GTP_MAX = 4,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed20 {
    IFLA_BOND_UNSPEC = 0,
    IFLA_BOND_MODE = 1,
    IFLA_BOND_ACTIVE_SLAVE = 2,
    IFLA_BOND_MIIMON = 3,
    IFLA_BOND_UPDELAY = 4,
    IFLA_BOND_DOWNDELAY = 5,
    IFLA_BOND_USE_CARRIER = 6,
    IFLA_BOND_ARP_INTERVAL = 7,
    IFLA_BOND_ARP_IP_TARGET = 8,
    IFLA_BOND_ARP_VALIDATE = 9,
    IFLA_BOND_ARP_ALL_TARGETS = 10,
    IFLA_BOND_PRIMARY = 11,
    IFLA_BOND_PRIMARY_RESELECT = 12,
    IFLA_BOND_FAIL_OVER_MAC = 13,
    IFLA_BOND_XMIT_HASH_POLICY = 14,
    IFLA_BOND_RESEND_IGMP = 15,
    IFLA_BOND_NUM_PEER_NOTIF = 16,
    IFLA_BOND_ALL_SLAVES_ACTIVE = 17,
    IFLA_BOND_MIN_LINKS = 18,
    IFLA_BOND_LP_INTERVAL = 19,
    IFLA_BOND_PACKETS_PER_SLAVE = 20,
    IFLA_BOND_AD_LACP_RATE = 21,
    IFLA_BOND_AD_SELECT = 22,
    IFLA_BOND_AD_INFO = 23,
    IFLA_BOND_AD_ACTOR_SYS_PRIO = 24,
    IFLA_BOND_AD_USER_PORT_KEY = 25,
    IFLA_BOND_AD_ACTOR_SYSTEM = 26,
    IFLA_BOND_TLB_DYNAMIC_LB = 27,
    __IFLA_BOND_MAX = 28,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed21 {
    IFLA_BOND_AD_INFO_UNSPEC = 0,
    IFLA_BOND_AD_INFO_AGGREGATOR = 1,
    IFLA_BOND_AD_INFO_NUM_PORTS = 2,
    IFLA_BOND_AD_INFO_ACTOR_KEY = 3,
    IFLA_BOND_AD_INFO_PARTNER_KEY = 4,
    IFLA_BOND_AD_INFO_PARTNER_MAC = 5,
    __IFLA_BOND_AD_INFO_MAX = 6,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed22 {
    IFLA_BOND_SLAVE_UNSPEC = 0,
    IFLA_BOND_SLAVE_STATE = 1,
    IFLA_BOND_SLAVE_MII_STATUS = 2,
    IFLA_BOND_SLAVE_LINK_FAILURE_COUNT = 3,
    IFLA_BOND_SLAVE_PERM_HWADDR = 4,
    IFLA_BOND_SLAVE_QUEUE_ID = 5,
    IFLA_BOND_SLAVE_AD_AGGREGATOR_ID = 6,
    IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE = 7,
    IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE = 8,
    __IFLA_BOND_SLAVE_MAX = 9,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed23 {
    IFLA_VF_INFO_UNSPEC = 0,
    IFLA_VF_INFO = 1,
    __IFLA_VF_INFO_MAX = 2,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed24 {
    IFLA_VF_UNSPEC = 0,
    IFLA_VF_MAC = 1,
    IFLA_VF_VLAN = 2,
    IFLA_VF_TX_RATE = 3,
    IFLA_VF_SPOOFCHK = 4,
    IFLA_VF_LINK_STATE = 5,
    IFLA_VF_RATE = 6,
    IFLA_VF_RSS_QUERY_EN = 7,
    IFLA_VF_STATS = 8,
    IFLA_VF_TRUST = 9,
    IFLA_VF_IB_NODE_GUID = 10,
    IFLA_VF_IB_PORT_GUID = 11,
    IFLA_VF_VLAN_LIST = 12,
    __IFLA_VF_MAX = 13,
}
#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct ifla_vf_mac {
    pub vf: u32,
    pub mac: [u8; 32usize],
}
impl ::std::default::Default for ifla_vf_mac {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct ifla_vf_vlan {
    pub vf: u32,
    pub vlan: u32,
    pub qos: u32,
}
impl ::std::default::Default for ifla_vf_vlan {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed25 {
    IFLA_VF_VLAN_INFO_UNSPEC = 0,
    IFLA_VF_VLAN_INFO = 1,
    __IFLA_VF_VLAN_INFO_MAX = 2,
}
#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct ifla_vf_vlan_info {
    pub vf: u32,
    pub vlan: u32,
    pub qos: u32,
    pub vlan_proto: __be16,
}
impl ::std::default::Default for ifla_vf_vlan_info {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct ifla_vf_tx_rate {
    pub vf: u32,
    pub rate: u32,
}
impl ::std::default::Default for ifla_vf_tx_rate {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct ifla_vf_rate {
    pub vf: u32,
    pub min_tx_rate: u32,
    pub max_tx_rate: u32,
}
impl ::std::default::Default for ifla_vf_rate {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct ifla_vf_spoofchk {
    pub vf: u32,
    pub setting: u32,
}
impl ::std::default::Default for ifla_vf_spoofchk {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct ifla_vf_guid {
    pub vf: u32,
    pub guid: u64,
}
impl ::std::default::Default for ifla_vf_guid {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed26 {
    IFLA_VF_LINK_STATE_AUTO = 0,
    IFLA_VF_LINK_STATE_ENABLE = 1,
    IFLA_VF_LINK_STATE_DISABLE = 2,
    __IFLA_VF_LINK_STATE_MAX = 3,
}
#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct ifla_vf_link_state {
    pub vf: u32,
    pub link_state: u32,
}
impl ::std::default::Default for ifla_vf_link_state {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct ifla_vf_rss_query_en {
    pub vf: u32,
    pub setting: u32,
}
impl ::std::default::Default for ifla_vf_rss_query_en {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed27 {
    IFLA_VF_STATS_RX_PACKETS = 0,
    IFLA_VF_STATS_TX_PACKETS = 1,
    IFLA_VF_STATS_RX_BYTES = 2,
    IFLA_VF_STATS_TX_BYTES = 3,
    IFLA_VF_STATS_BROADCAST = 4,
    IFLA_VF_STATS_MULTICAST = 5,
    IFLA_VF_STATS_PAD = 6,
    __IFLA_VF_STATS_MAX = 7,
}
#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct ifla_vf_trust {
    pub vf: u32,
    pub setting: u32,
}
impl ::std::default::Default for ifla_vf_trust {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed28 {
    IFLA_VF_PORT_UNSPEC = 0,
    IFLA_VF_PORT = 1,
    __IFLA_VF_PORT_MAX = 2,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed29 {
    IFLA_PORT_UNSPEC = 0,
    IFLA_PORT_VF = 1,
    IFLA_PORT_PROFILE = 2,
    IFLA_PORT_VSI_TYPE = 3,
    IFLA_PORT_INSTANCE_UUID = 4,
    IFLA_PORT_HOST_UUID = 5,
    IFLA_PORT_REQUEST = 6,
    IFLA_PORT_RESPONSE = 7,
    __IFLA_PORT_MAX = 8,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed30 {
    PORT_REQUEST_PREASSOCIATE = 0,
    PORT_REQUEST_PREASSOCIATE_RR = 1,
    PORT_REQUEST_ASSOCIATE = 2,
    PORT_REQUEST_DISASSOCIATE = 3,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed31 {
    PORT_VDP_RESPONSE_SUCCESS = 0,
    PORT_VDP_RESPONSE_INVALID_FORMAT = 1,
    PORT_VDP_RESPONSE_INSUFFICIENT_RESOURCES = 2,
    PORT_VDP_RESPONSE_UNUSED_VTID = 3,
    PORT_VDP_RESPONSE_VTID_VIOLATION = 4,
    PORT_VDP_RESPONSE_VTID_VERSION_VIOALTION = 5,
    PORT_VDP_RESPONSE_OUT_OF_SYNC = 6,
    PORT_PROFILE_RESPONSE_SUCCESS = 256,
    PORT_PROFILE_RESPONSE_INPROGRESS = 257,
    PORT_PROFILE_RESPONSE_INVALID = 258,
    PORT_PROFILE_RESPONSE_BADSTATE = 259,
    PORT_PROFILE_RESPONSE_INSUFFICIENT_RESOURCES = 260,
    PORT_PROFILE_RESPONSE_ERROR = 261,
}
#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct ifla_port_vsi {
    pub vsi_mgr_id: u8,
    pub vsi_type_id: [u8; 3usize],
    pub vsi_type_version: u8,
    pub pad: [u8; 3usize],
}
impl ::std::default::Default for ifla_port_vsi {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed32 {
    IFLA_IPOIB_UNSPEC = 0,
    IFLA_IPOIB_PKEY = 1,
    IFLA_IPOIB_MODE = 2,
    IFLA_IPOIB_UMCAST = 3,
    __IFLA_IPOIB_MAX = 4,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed33 { IPOIB_MODE_DATAGRAM = 0, IPOIB_MODE_CONNECTED = 1, }
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed34 {
    IFLA_HSR_UNSPEC = 0,
    IFLA_HSR_SLAVE1 = 1,
    IFLA_HSR_SLAVE2 = 2,
    IFLA_HSR_MULTICAST_SPEC = 3,
    IFLA_HSR_SUPERVISION_ADDR = 4,
    IFLA_HSR_SEQ_NR = 5,
    IFLA_HSR_VERSION = 6,
    __IFLA_HSR_MAX = 7,
}
#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct if_stats_msg {
    pub family: u8,
    pub pad1: u8,
    pub pad2: u16,
    pub ifindex: u32,
    pub filter_mask: u32,
}
impl ::std::default::Default for if_stats_msg {
    fn default() -> Self { unsafe { ::std::mem::zeroed() } }
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed35 {
    IFLA_STATS_UNSPEC = 0,
    IFLA_STATS_LINK_64 = 1,
    IFLA_STATS_LINK_XSTATS = 2,
    IFLA_STATS_LINK_XSTATS_SLAVE = 3,
    IFLA_STATS_LINK_OFFLOAD_XSTATS = 4,
    __IFLA_STATS_MAX = 5,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed36 {
    LINK_XSTATS_TYPE_UNSPEC = 0,
    LINK_XSTATS_TYPE_BRIDGE = 1,
    __LINK_XSTATS_TYPE_MAX = 2,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed37 {
    IFLA_OFFLOAD_XSTATS_UNSPEC = 0,
    IFLA_OFFLOAD_XSTATS_CPU_HIT = 1,
    __IFLA_OFFLOAD_XSTATS_MAX = 2,
}
#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed38 {
    IFLA_XDP_UNSPEC = 0,
    IFLA_XDP_FD = 1,
    IFLA_XDP_ATTACHED = 2,
    IFLA_XDP_FLAGS = 3,
    __IFLA_XDP_MAX = 4,
}

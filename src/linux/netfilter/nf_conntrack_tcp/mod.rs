// This is exposed to userspace (ctnetlink) - ip_ct_tcp.state
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum TcpConntrack {
    NONE	= 0,
    SYN_SENT	= 1,
    SYN_RECV	= 2,
    ESTABLISHED	= 3,
    FIN_WAIT	= 4,
    CLOSE_WAIT	= 5,
    LAST_ACK	= 6,
    TIME_WAIT	= 7,
    CLOSE	= 8,
    LISTEN	= 9,	// obsolete
    MAX		= 10,
    IGNORE	= 11,
    RETRANS	= 12,
    UNACK	= 13,
    TIMEOUT_MAX	= 14,
}
pub const TCP_CONNTRACK_NONE: u8	= TcpConntrack::NONE as u8;
pub const TCP_CONNTRACK_SYN_SENT: u8	= TcpConntrack::SYN_SENT as u8;
pub const TCP_CONNTRACK_SYN_RECV: u8	= TcpConntrack::SYN_RECV as u8;
pub const TCP_CONNTRACK_ESTABLISHED: u8	= TcpConntrack::ESTABLISHED as u8;
pub const TCP_CONNTRACK_FIN_WAIT: u8	= TcpConntrack::FIN_WAIT as u8;
pub const TCP_CONNTRACK_CLOSE_WAIT: u8	= TcpConntrack::CLOSE_WAIT as u8;
pub const TCP_CONNTRACK_LAST_ACK: u8	= TcpConntrack::LAST_ACK as u8;
pub const TCP_CONNTRACK_TIME_WAIT: u8	= TcpConntrack::TIME_WAIT as u8;
pub const TCP_CONNTRACK_CLOSE: u8	= TcpConntrack::CLOSE as u8;
pub const TCP_CONNTRACK_LISTEN: u8	= TcpConntrack::LISTEN as u8;
pub const TCP_CONNTRACK_SYN_SENT2: u8	= TCP_CONNTRACK_LISTEN;
pub const TCP_CONNTRACK_MAX: u8		= TcpConntrack::MAX as u8;
pub const TCP_CONNTRACK_IGNORE: u8	= TcpConntrack::IGNORE as u8;
pub const TCP_CONNTRACK_RETRANS: u8	= TcpConntrack::RETRANS as u8;
pub const TCP_CONNTRACK_UNACK: u8	= TcpConntrack::UNACK as u8;
pub const TCP_CONNTRACK_TIMEOUT_MAX: u8	= TcpConntrack::TIMEOUT_MAX as u8;


// Window scaling is advertised by the sender
pub const IP_CT_TCP_FLAG_WINDOW_SCALE: u8		= 0x01;
// SACK is permitted by the sender
pub const IP_CT_TCP_FLAG_SACK_PERM: u8			= 0x02;
// This sender sent FIN first
pub const IP_CT_TCP_FLAG_CLOSE_INIT: u8			= 0x04;
// Be liberal in window checking
pub const IP_CT_TCP_FLAG_BE_LIBERAL: u8			= 0x08;
// Has unacknowledged data
pub const IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED: u8	= 0x10;
// The field td_maxack has been set
pub const IP_CT_TCP_FLAG_MAXACK_SET: u8			= 0x20;
// Marks possibility for expected RFC5961 challenge ACK
pub const IP_CT_EXP_CHALLENGE_ACK: u8 			= 0x40;

#[repr(C)]
pub struct NfCtTcpFlags {
    pub flags: u8,
    pub mask: u8,
}

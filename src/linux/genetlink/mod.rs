use std::mem::size_of;
use linux::netlink;

pub const GENL_NAMSIZ: u8	= 16;

pub const GENL_MIN_ID: u16	= netlink::NLMSG_MIN_TYPE;
pub const GENL_MAX_ID: u16	= 1023;

pub struct Genlmsghdr {
    pub cmd: u8,
    pub version: u8,
    pub reserved: u16,
}

#[allow(non_snake_case)]
pub fn GENL_HDRLEN() -> u32 {
    netlink::NLMSG_ALIGN(size_of::<Genlmsghdr>() as u32)
}

pub const GENL_ADMIN_PERM: u8		= 0x01;
pub const GENL_CMD_CAP_DO: u8		= 0x02;
pub const GENL_CMD_CAP_DUMP: u8		= 0x04;
pub const GENL_CMD_CAP_HASPOL: u8	= 0x08;
pub const GENL_UNS_ADMIN_PERM: u8	= 0x10;

// List of reserved static generic netlink identifiers:
pub const GENL_ID_CTRL: u16		= netlink::NLMSG_MIN_TYPE;
pub const GENL_ID_VFS_DQUOT: u16	= netlink::NLMSG_MIN_TYPE + 1;
pub const GENL_ID_PMCRAID: u16		= netlink::NLMSG_MIN_TYPE + 2;
// must be last reserved + 1
pub const GENL_START_ALLOC: u16		= netlink::NLMSG_MIN_TYPE + 3;

// Controller
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum CtrlCmd {
    UNSPEC		= 0,
    NEWFAMILY		= 1,
    DELFAMILY		= 2,
    GETFAMILY		= 3,
    NEWOPS		= 4,
    DELOPS		= 5,
    GETOPS		= 6,
    NEWMCAST_GRP	= 7,
    DELMCAST_GRP	= 8,
    GETMCAST_GRP	= 9, // unused
    _MAX		= 10,
}
pub const CTRL_CMD_UNSPEC: u8		= CtrlCmd::UNSPEC as u8;
pub const CTRL_CMD_NEWFAMILY: u8	= CtrlCmd::NEWFAMILY as u8;
pub const CTRL_CMD_DELFAMILY: u8	= CtrlCmd::DELFAMILY as u8;
pub const CTRL_CMD_GETFAMILY: u8	= CtrlCmd::GETFAMILY as u8;
pub const CTRL_CMD_NEWOPS: u8		= CtrlCmd::NEWOPS as u8;
pub const CTRL_CMD_DELOPS: u8		= CtrlCmd::DELOPS as u8;
pub const CTRL_CMD_GETOPS: u8		= CtrlCmd::GETOPS as u8;
pub const CTRL_CMD_NEWMCAST_GRP: u8	= CtrlCmd::NEWMCAST_GRP as u8;
pub const CTRL_CMD_DELMCAST_GRP: u8	= CtrlCmd::DELMCAST_GRP as u8;
pub const CTRL_CMD_GETMCAST_GRP: u8	= CtrlCmd::GETMCAST_GRP as u8;
pub const __CTRL_CMD_MAX: u8		= CtrlCmd::_MAX as u8;
pub const CTRL_CMD_MAX: u8		= __CTRL_CMD_MAX - 1;

#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CtrlAttr {
    UNSPEC		= 0,
    FAMILY_ID		= 1,
    FAMILY_NAME		= 2,
    VERSION		= 3,
    HDRSIZE		= 4,
    MAXATTR 		= 5,
    OPS			= 6,
    MCAST_GROUPS	= 7,
    _MAX		= 8,
}
pub const CTRL_ATTR_UNSPEC: u16		= CtrlAttr::UNSPEC as u16;
pub const CTRL_ATTR_FAMILY_ID: u16	= CtrlAttr::FAMILY_ID as u16;
pub const CTRL_ATTR_FAMILY_NAME: u16	= CtrlAttr::FAMILY_NAME as u16;
pub const CTRL_ATTR_VERSION: u16	= CtrlAttr::VERSION as u16;
pub const CTRL_ATTR_HDRSIZE: u16	= CtrlAttr::HDRSIZE as u16;
pub const CTRL_ATTR_MAXATTR: u16	= CtrlAttr::MAXATTR as u16;
pub const CTRL_ATTR_OPS: u16		= CtrlAttr::OPS as u16;
pub const CTRL_ATTR_MCAST_GROUPS: u16	= CtrlAttr::MCAST_GROUPS as u16;
pub const __CTRL_ATTR_MAX: u16		= CtrlAttr::_MAX as u16;
pub const CTRL_ATTR_MAX: u16		= __CTRL_ATTR_MAX - 1;

#[repr(u16)]
pub enum CtrlAttrOp {
    UNSPEC	= 0,
    ID		= 1,
    FLAGS	= 2,
    _MAX	= 3,
}
pub const CTRL_ATTR_OP_UNSPEC: u16	= CtrlAttrOp::UNSPEC as u16;
pub const CTRL_ATTR_OP_ID: u16		= CtrlAttrOp::ID as u16;
pub const CTRL_ATTR_OP_FLAGS: u16	= CtrlAttrOp::FLAGS as u16;
pub const __CTRL_ATTR_OP_MAX: u16	= CtrlAttrOp::_MAX as u16;
pub const CTRL_ATTR_OP_MAX: u16		= __CTRL_ATTR_OP_MAX - 1;

#[repr(u16)]
pub enum CtrlAttrMcastGrp {
    UNSPEC	= 0,
    NAME	= 1,
    ID		= 2,
    _MAX	= 3,
}
pub const CTRL_ATTR_MCAST_GRP_UNSPEC: u16	= CtrlAttrMcastGrp::UNSPEC as u16;
pub const CTRL_ATTR_MCAST_GRP_NAME: u16		= CtrlAttrMcastGrp::NAME as u16;
pub const CTRL_ATTR_MCAST_GRP_ID: u16		= CtrlAttrMcastGrp::ID as u16;
pub const __CTRL_ATTR_MCAST_GRP_MAX: u16	= CtrlAttrMcastGrp::_MAX as u16;
pub const CTRL_ATTR_MCAST_GRP_MAX: u16		= __CTRL_ATTR_MCAST_GRP_MAX - 1;

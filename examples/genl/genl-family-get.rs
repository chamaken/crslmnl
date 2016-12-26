use std::env;
use std::io::Write;
use std::mem::size_of;
use std::process::exit;

extern crate libc;
extern crate time;
extern crate crslmnl as mnl;

use mnl::linux::netlink as netlink;
use mnl::linux::genetlink as genl;


macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

fn parse_mc_grps_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    // skip unsupported attribute in user-space
    if let Err(_) = attr.type_valid(genl::CTRL_ATTR_MCAST_GRP_MAX as u16) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if n == genl::CtrlAttrMcastGrp::ID as u16 => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if n == genl::CtrlAttrMcastGrp::NAME as u16 => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::STRING) {
                println_stderr!("mnl_attr_validate- {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        _ => {},
    }
    tb[atype as usize] = Some(attr);
    mnl::CbRet::OK
}

fn parse_genl_mc_grps(nested: &mnl::Attr) {
    for pos in nested.nesteds() {
        let mut tb: [Option<&mnl::Attr>; genl::CTRL_ATTR_MCAST_GRP_MAX as usize + 1]
            = [None; genl::CTRL_ATTR_MCAST_GRP_MAX as usize + 1];

        let _ = pos.parse_nested(parse_mc_grps_cb, &mut tb);
        if let Some(attr) = tb[genl::CtrlAttrMcastGrp::ID as usize] {
            print!("id-0x{:x} ", attr.u32());
        }
        if let Some(attr) = tb[genl::CtrlAttrMcastGrp::NAME as usize] {
            print!("name: {} ", attr.str());
        }
        println!("");
    }
}

fn parse_family_ops_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(genl::CTRL_ATTR_OP_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if (n == genl::CtrlAttrOp::ID as u16 ||
              n == genl::CtrlAttrOp::FLAGS as u16) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if n == genl::CTRL_ATTR_OP_MAX => {},
        _ => {
            return mnl::CbRet::OK;
        },
    }

    tb[atype as usize] = Some(attr);
    return mnl::CbRet::OK;
}

fn parse_genl_family_ops(nested: &mnl::Attr) {
    for pos in nested.nesteds() {
        let mut tb: [Option<&mnl::Attr>; genl::CTRL_ATTR_OP_MAX as usize + 1]
            = [None; genl::CTRL_ATTR_OP_MAX as usize + 1];

        let _ = pos.parse_nested(parse_family_ops_cb, &mut tb);
        if let Some(attr) = tb[genl::CtrlAttrOp::ID as usize] {
            print!("id-0x{:x} ", attr.u32());
        }
        if let Some(attr) = tb[genl::CtrlAttrOp::FLAGS as usize] {
            print!("flags 0x{:08x}", attr.u32());
        }
        println!("");
    }
}

fn data_attr_cb<'a>(attr: &'a mnl::Attr, tb: &mut [Option<&'a mnl::Attr>]) -> mnl::CbRet {
    if let Err(_) = attr.type_valid(genl::CTRL_ATTR_MAX) {
        return mnl::CbRet::OK;
    }

    let atype = attr.atype();
    match atype {
        n if n == genl::CtrlAttr::FAMILY_NAME as u16 => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::STRING) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if n == genl::CtrlAttr::FAMILY_ID as u16 => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U16) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if (n == genl::CtrlAttr::VERSION as u16 ||
              n == genl::CtrlAttr::HDRSIZE as u16 ||
              n == genl::CtrlAttr::MAXATTR as u16) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::U32) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        n if (n == genl::CtrlAttr::OPS as u16 ||
              n == genl::CtrlAttr::MCAST_GROUPS as u16) => {
            if let Err(errno) = attr.validate(mnl::AttrDataType::NESTED) {
                println_stderr!("mnl_attr_validate - {}: {}", atype, errno);
                return mnl::CbRet::ERROR;
            }
        },
        _ => {},
    }

    tb[atype as usize] = Some(attr);
    return mnl::CbRet::OK;
}

fn data_cb(nlh: &mnl::Nlmsg, _: &mut u8) -> mnl::CbRet {
    let mut tb: [Option<&mnl::Attr>; genl::CTRL_ATTR_MAX as usize + 1]
        = [None; genl::CTRL_ATTR_MAX as usize + 1];

    let _ = nlh.parse(size_of::<genl::Genlmsghdr>(), data_attr_cb, &mut tb);
    if let Some(attr) = tb[genl::CtrlAttr::FAMILY_NAME as usize] {
        print!("name={}\t", attr.str());
    }
    if let Some(attr) = tb[genl::CtrlAttr::FAMILY_ID as usize] {
        print!("id={}\t", attr.u16());
    }
    if let Some(attr) = tb[genl::CtrlAttr::VERSION as usize] {
        print!("version={}\t", attr.u32());
    }
    if let Some(attr) = tb[genl::CtrlAttr::HDRSIZE as usize] {
        print!("hdrsize={}\t", attr.u32());
    }
    if let Some(attr) = tb[genl::CtrlAttr::MAXATTR as usize] {
        print!("maxattr={}\t", attr.u32());
    }
    println!("");
    if let Some(attr) = tb[genl::CtrlAttr::OPS as usize] {
        println!("ops:");
        parse_genl_family_ops(attr);
    }
    if let Some(attr) = tb[genl::CtrlAttr::MCAST_GROUPS as usize] {
        println!("grps:");
        parse_genl_mc_grps(attr);
    }
    println!("");
    return mnl::CbRet::OK;
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() > 2 {
        println!("{} [family name]", args[0]);
        exit(libc::EXIT_FAILURE);
    }

    let nl: &mut mnl::Socket;
    match mnl::Socket::open(netlink::Family::GENERIC) {
        Ok(sock) => { nl = sock },
        Err(errno) => {
            println_stderr!("mnl_socket_open: {}", errno);
            exit(libc::EXIT_FAILURE);
        },
    }

    if let Err(errno) = nl.bind(0, mnl::SOCKET_AUTOPID) {
        println_stderr!("mnl_socket_bind: {}", errno);
        exit(libc::EXIT_FAILURE);
    }
    let portid = nl.portid();

    let mut buf = vec![0u8; mnl::SOCKET_BUFFER_SIZE()];
    let seq = time::now().to_timespec().sec as u32;
    {
        let nlh = mnl::Nlmsg::put_header(&mut buf);
        nlh.nlmsg_type = genl::GENL_ID_CTRL;
        nlh.nlmsg_flags = netlink::NLM_F_REQUEST | netlink::NLM_F_ACK;
        nlh.nlmsg_seq = seq;

        let genl = nlh.put_sized_header::<genl::Genlmsghdr>();
        genl.cmd = genl::CtrlCmd::GETFAMILY as u8;
        genl.version = 1;

        nlh.put_u16(genl::CtrlAttr::FAMILY_ID as u16, genl::GENL_ID_CTRL);
        if args.len() >= 2 {
            nlh.put_strz(genl::CtrlAttr::FAMILY_NAME as u16, &args[1]);
        } else {
            nlh.nlmsg_flags |= netlink::NLM_F_DUMP;
        }

        if let Err(errno) = nl.send_nlmsg(nlh) {
            println_stderr!("mnl_socket_sendto: {}", errno);
            exit(libc::EXIT_FAILURE);
        }
    }

    let mut nrecv: usize;
    loop {
        match nl.recvfrom(&mut buf) {
            Err(errno) => {
                println_stderr!("mnl_socket_recvfrom: {}", errno);
                exit(libc::EXIT_FAILURE);
            },
            Ok(n) => nrecv = n,
        }

        match mnl::cb_run(&buf[0..nrecv], seq, portid, data_cb, &mut 0) {
            Err(errno) => {
                println_stderr!("mnl_cb_run: {}", errno);
                exit(libc::EXIT_FAILURE);
            },
            Ok(ret) => {
                if ret == mnl::CbRet::STOP {
                    break;
                }
            },
        }
    }
    let _ = nl.close();
}

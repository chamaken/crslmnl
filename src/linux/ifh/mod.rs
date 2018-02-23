// XXX: IFF_ only

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum NetDeviceFlags {
    UP				= 1<<0,  // sysfs
    BROADCAST			= 1<<1,  // volatile
    DEBUG			= 1<<2,  // sysfs
    LOOPBACK			= 1<<3,  // volatile
    POINTOPOINT			= 1<<4,  // volatile
    NOTRAILERS			= 1<<5,  // sysfs
    RUNNING			= 1<<6,  // volatile
    NOARP			= 1<<7,  // sysfs
    PROMISC			= 1<<8,  // sysfs
    ALLMULTI			= 1<<9,  // sysfs
    MASTER			= 1<<10, // volatile
    SLAVE			= 1<<11, // volatile
    MULTICAST			= 1<<12, // sysfs
    PORTSEL			= 1<<13, // sysfs
    AUTOMEDIA			= 1<<14, // sysfs
    DYNAMIC			= 1<<15, // sysfs
    LOWER_UP			= 1<<16, // volatile
    DORMANT			= 1<<17, // volatile
    ECHO			= 1<<18, // volatile
}


pub const IFF_UP: u32				= NetDeviceFlags::UP as u32;
pub const IFF_BROADCAST: u32			= NetDeviceFlags::BROADCAST as u32;
pub const IFF_DEBUG: u32			= NetDeviceFlags::DEBUG as u32;
pub const IFF_LOOPBACK: u32			= NetDeviceFlags::LOOPBACK as u32;
pub const IFF_POINTOPOINT: u32			= NetDeviceFlags::POINTOPOINT as u32;
pub const IFF_NOTRAILERS: u32			= NetDeviceFlags::NOTRAILERS as u32;
pub const IFF_RUNNING: u32			= NetDeviceFlags::RUNNING as u32;
pub const IFF_NOARP: u32			= NetDeviceFlags::NOARP as u32;
pub const IFF_PROMISC: u32			= NetDeviceFlags::PROMISC as u32;
pub const IFF_ALLMULTI: u32			= NetDeviceFlags::ALLMULTI as u32;
pub const IFF_MASTER: u32			= NetDeviceFlags::MASTER as u32;
pub const IFF_SLAVE: u32			= NetDeviceFlags::SLAVE as u32;
pub const IFF_MULTICAST: u32			= NetDeviceFlags::MULTICAST as u32;
pub const IFF_PORTSEL: u32			= NetDeviceFlags::PORTSEL as u32;
pub const IFF_AUTOMEDIA: u32			= NetDeviceFlags::AUTOMEDIA as u32;
pub const IFF_DYNAMIC: u32			= NetDeviceFlags::DYNAMIC as u32;
pub const IFF_LOWER_UP: u32			= NetDeviceFlags::LOWER_UP as u32;
pub const IFF_DORMANT: u32			= NetDeviceFlags::DORMANT as u32;
pub const IFF_ECHO: u32				= NetDeviceFlags::ECHO as u32;
pub const IFF_VOLATILE: u32	= (IFF_LOOPBACK|IFF_POINTOPOINT|IFF_BROADCAST|IFF_ECHO|
		                   IFF_MASTER|IFF_SLAVE|IFF_RUNNING|IFF_LOWER_UP|IFF_DORMANT);

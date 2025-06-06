use anyhow::Result;
use nix::ioctl_write_ptr_bad;
use std::{
    fs::{File, OpenOptions},
    os::fd::AsRawFd,
};
use tokio::io::unix::AsyncFd;

use libc::{__c_anonymous_ifr_ifru, ifreq, IFF_NO_PI, IFF_TUN, IFNAMSIZ, TUNSETIFF};

ioctl_write_ptr_bad!(tun_set_iff, TUNSETIFF, ifreq);

pub fn create(name: &str) -> Result<AsyncFd<File>> {
    // https://docs.kernel.org/networking/tuntap.html
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;

    let fd = f.as_raw_fd();

    let mut ifreq = libc::ifreq {
        ifr_name: [0; IFNAMSIZ],
        ifr_ifru: __c_anonymous_ifr_ifru {
            ifru_flags: (IFF_TUN | IFF_NO_PI) as _,
        },
    };
    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as i8;
    }
    unsafe {
        tun_set_iff(fd, &ifreq)?;
    }

    Ok(AsyncFd::new(f)?)
}

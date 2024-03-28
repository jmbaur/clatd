use std::{fs::File, os::fd::AsRawFd};

use crate::bindings::{ifreq, ifreq__bindgen_ty_1, ifreq__bindgen_ty_2, IFF_NO_PI, IFF_TUN};

const DEV_NET_TUN: &'static str = "/dev/net/tun";

nix::ioctl_write_int!(tunsetiff, b'T', 202);

pub struct Tun {
    /// The name of the tun device, as assigned by the kernel.
    pub name: String,
    /// The file corresponding to the open file descriptor of the tun device.
    file: File,
}

impl Tun {
    pub fn open(name: &str) -> anyhow::Result<Self> {
        // The name must be less than or equal to 14 characters since we must append the format
        // string specifier "%d" to it in order for the linux kernel to assign an index to our
        // interface name, so we trim the name the caller passes.
        let name = match name.char_indices().nth(14) {
            None => name,
            Some((i, _)) => &name[..i],
        };

        let dev_net_tun = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(DEV_NET_TUN)?;

        let mut name_format = [0i8; crate::bindings::IFNAMSIZ as usize];

        debug_assert!(name.len() <= 14, "tun name is too long");
        for (i, char) in name.chars().enumerate() {
            name_format[i] = char as i8;
        }
        name_format[name.len()] = '%' as i8;
        name_format[name.len() + 1] = 'd' as i8;

        let ifr = ifreq {
            ifr_ifrn: ifreq__bindgen_ty_1 {
                ifrn_name: name_format,
            },
            ifr_ifru: ifreq__bindgen_ty_2 {
                ifru_flags: IFF_TUN as i16 | IFF_NO_PI as i16,
            },
        };

        _ = unsafe { tunsetiff(dev_net_tun.as_raw_fd(), &ifr as *const ifreq as _) }?;

        let name = String::from_utf8(unsafe { ifr.ifr_ifrn.ifrn_name }.map(|c| c as u8).to_vec())?;
        Ok(Self {
            name,
            file: dev_net_tun,
        })
    }
}

impl std::io::Read for Tun {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl std::io::Write for Tun {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

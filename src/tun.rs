use std::{fs::File, os::fd::AsRawFd};

use crate::bindings::{ifreq, ifreq__bindgen_ty_1, ifreq__bindgen_ty_2, IFF_NO_PI, IFF_TUN};

const DEV_NET_TUN: &'static str = "/dev/net/tun";

nix::ioctl_write_int!(tunsetiff, b'T', 202);

pub struct Tun<'a> {
    name: &'a str,
    /// The file corresponding to the open file descriptor of the tun device.
    file: Option<File>,
}

impl<'a> Tun<'a> {
    pub fn new(name: &'a str) -> Self {
        // The name must be less than or equal to 14 characters since we must append the format
        // string specifier "%d" to it in order for the linux kernel to assign an index to our
        // interface name, so we trim the name the caller passes.
        let name = match name.char_indices().nth(14){
            None => name,
            Some((i, _)) => &name[..i],
        };

        Self { name, file: None }
    }

    pub fn open(self: &mut Self) -> anyhow::Result<()> {
        let dev_net_tun = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(DEV_NET_TUN)?;

        self.file = Some(dev_net_tun);

        let mut name = [0i8; 16];
        for (i, char) in self.name.chars().enumerate() {
            name[i] = char as i8;
        }
        name[self.name.len()] = '%' as i8;
        name[self.name.len() + 1] = 'd' as i8;

        let ifr = ifreq {
            ifr_ifrn: ifreq__bindgen_ty_1 { ifrn_name: name },
            ifr_ifru: ifreq__bindgen_ty_2 {
                ifru_flags: IFF_TUN as i16 | IFF_NO_PI as i16,
            },
        };

        _ = unsafe {
            tunsetiff(
                self.file.as_ref().unwrap().as_raw_fd(),
                &ifr as *const ifreq as _,
            )
        }?;

        Ok(())
    }
}

impl std::io::Read for Tun<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.as_ref().unwrap().read(buf)
    }
}

impl std::io::Write for Tun<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.as_ref().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.as_ref().unwrap().flush()
    }
}

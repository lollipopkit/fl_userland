//! Host interface discovery and ioctl compatibility.

use super::*;

// ------------------------------------------------------- the ioctl interface

/// `struct ifreq`: sixteen bytes of name and a twenty-four-byte union.
///
/// Measured on an arm64 kernel rather than taken from a header, because there
/// is no Linux header on the host to take it from: `sizeof(struct ifreq)` is
/// **40** and `IFNAMSIZ` is 16.
pub const IFREQ_LEN: usize = 40;
/// `struct ifconf`: a length and a pointer, with the pointer eight-aligned.
pub const IFCONF_LEN: usize = 16;
pub const IFNAMSIZ: usize = 16;

/// The `SIOCGIF*` a guest asks a socket for. Linux's numbers.
pub const SIOCGIFNAME: u32 = 0x8910;
pub const SIOCGIFCONF: u32 = 0x8912;
pub const SIOCGIFFLAGS: u32 = 0x8913;
pub const SIOCGIFADDR: u32 = 0x8915;
pub const SIOCGIFNETMASK: u32 = 0x891b;
pub const SIOCGIFMTU: u32 = 0x8921;
pub const SIOCGIFHWADDR: u32 = 0x8927;
pub const SIOCGIFINDEX: u32 = 0x8933;
pub const SIOCGIFTXQLEN: u32 = 0x8942;

/// `ARPHRD_ETHER` in a `sockaddr`'s family slot, which is where
/// `SIOCGIFHWADDR` puts the hardware type.
fn hwaddr_family(i: &Iface) -> u16 {
    if i.loopback {
        ARPHRD_LOOPBACK
    } else {
        ARPHRD_ETHER
    }
}

/// The name in an `ifreq`, without its NUL.
pub fn ifreq_name(req: &[u8]) -> Vec<u8> {
    let n = req.len().min(IFNAMSIZ);
    let end = req[..n].iter().position(|b| *b == 0).unwrap_or(n);
    req[..end].to_vec()
}

/// Answer one `ifreq`-shaped `SIOCGIF*` in place. `false` for a command this
/// does not carry, so a caller can fall through to the host's.
///
/// The name selects the interface for every one of them except `SIOCGIFNAME`,
/// which selects by the index in the union and writes the name — the one that
/// goes the other way, and the one a loop over indices uses.
pub fn ifreq_ioctl(cmd: u32, req: &mut [u8], ifaces: &[Iface]) -> Result<(), c_int> {
    use guest_errno::c_int_::{EINVAL, ENODEV};
    if req.len() < IFREQ_LEN {
        return Err(EINVAL);
    }
    let found = if cmd == SIOCGIFNAME {
        let index = u32::from_le_bytes(req[16..20].try_into().unwrap());
        ifaces.iter().find(|i| i.index == index)
    } else {
        let name = ifreq_name(req);
        ifaces.iter().find(|i| i.name.as_bytes() == name.as_slice())
    };
    let Some(i) = found else {
        return Err(ENODEV);
    };
    // The union, cleared: a caller reads the whole thing and Linux does not
    // leave the request's own bytes in the part it did not fill.
    req[IFNAMSIZ..IFREQ_LEN].fill(0);
    match cmd {
        SIOCGIFNAME => {
            req[..IFNAMSIZ].fill(0);
            let n = i.name.len().min(IFNAMSIZ - 1);
            req[..n].copy_from_slice(&i.name.as_bytes()[..n]);
        }
        SIOCGIFFLAGS => req[16..18].copy_from_slice(&(i.flags as u16).to_le_bytes()),
        SIOCGIFINDEX => req[16..20].copy_from_slice(&i.index.to_le_bytes()),
        SIOCGIFMTU => req[16..20].copy_from_slice(&i.mtu.to_le_bytes()),
        // 1000, as `IFLA_TXQLEN` reports. Nothing here has a queue; busybox
        // `ip` asks for this directly and prints a failure per interface
        // without it.
        SIOCGIFTXQLEN => req[16..20].copy_from_slice(&1000u32.to_le_bytes()),
        SIOCGIFHWADDR => {
            req[16..18].copy_from_slice(&hwaddr_family(i).to_le_bytes());
            let n = i.mac.len().min(14);
            req[18..18 + n].copy_from_slice(&i.mac[..n]);
        }
        SIOCGIFADDR | SIOCGIFNETMASK => {
            // The first IPv4 address, which is what this interface answers
            // with: the ioctl interface has no way to name a second, which is
            // the reason netlink replaced it.
            let Some((_, prefix, bytes)) =
                i.addrs.iter().find(|(f, _, _)| *f as i32 == libc::AF_INET)
            else {
                return Err(ENODEV);
            };
            req[16..18].copy_from_slice(&2u16.to_le_bytes()); // AF_INET, Linux's
            if cmd == SIOCGIFADDR {
                req[20..24].copy_from_slice(&bytes[..4]);
            } else {
                let mut mask = [0u8; 4];
                for bit in 0..*prefix as usize {
                    mask[bit / 8] |= 0x80 >> (bit % 8);
                }
                req[20..24].copy_from_slice(&mask);
            }
        }
        _ => return Err(EINVAL),
    }
    Ok(())
}

/// The `ifreq` array `SIOCGIFCONF` fills: one per IPv4 address.
///
/// Linux reports one entry per *address*, not per interface, so an interface
/// with two appears twice — which is why `ifconfig` can show `eth0` and
/// `eth0:1`. An interface with no IPv4 address is left out entirely.
pub fn ifconf_entries(ifaces: &[Iface]) -> Vec<u8> {
    let mut out = Vec::new();
    for i in ifaces {
        for (family, _, bytes) in &i.addrs {
            if *family as i32 != libc::AF_INET {
                continue;
            }
            let mut req = [0u8; IFREQ_LEN];
            let n = i.name.len().min(IFNAMSIZ - 1);
            req[..n].copy_from_slice(&i.name.as_bytes()[..n]);
            req[16..18].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
            req[20..24].copy_from_slice(&bytes[..4]);
            out.extend_from_slice(&req);
        }
    }
    out
}

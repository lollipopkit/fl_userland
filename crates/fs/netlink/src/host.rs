//! Host interface discovery and ioctl compatibility.

use super::*;

/// The host's interfaces, as a guest is told about them.
///
/// `getifaddrs` rather than a list of our own: a passthrough network means the
/// guest's interfaces are the host's, and inventing `lo` and `eth0` — which is
/// what `/proc/net/dev` did before this — tells a program binding to a named
/// interface that one exists which does not.
///
/// The index is the host's `if_nametoindex`, so it is stable for the life of
/// the process and matches the one `IFLA_IFNAME` names.
pub fn host_ifaces() -> Vec<Iface> {
    let Some(list) = IfAddrs::get() else {
        return Vec::new();
    };
    let mut by_name: Vec<Iface> = Vec::new();
    for e in list.iter() {
        // SAFETY: the name came from the same list, and is NUL-terminated.
        let index = unsafe { libc::if_nametoindex(e.name.as_ptr()) };
        if index == 0 {
            continue;
        }
        let name = e.name.to_string_lossy().into_owned();
        let shown = guest_name(&name);
        let at = match by_name.iter().position(|i| i.name == shown) {
            Some(at) => at,
            None => {
                by_name.push(Iface {
                    index,
                    name: shown.to_string(),
                    mac: Vec::new(),
                    // 1500 unless the host says otherwise, which it does
                    // through AF_LINK below.
                    mtu: 1500,
                    flags: linux_flags(e.flags),
                    loopback: e.flags & 0x8 != 0,
                    addrs: Vec::new(),
                });
                by_name.len() - 1
            }
        };
        let Some(addr) = e.addr else {
            continue;
        };
        match addr[1] as i32 {
            libc::AF_INET => {
                if let Some(bytes) = field::<4>(addr, 4) {
                    let prefix = e.netmask.map_or(32, |m| prefix_len(&field_padded::<4>(m, 4)));
                    by_name[at].addrs.push((libc::AF_INET as u8, prefix, bytes.to_vec()));
                }
            }
            libc::AF_INET6 => {
                if let Some(bytes) = field::<16>(addr, 8) {
                    let prefix = e.netmask.map_or(128, |m| prefix_len(&field_padded::<16>(m, 8)));
                    by_name[at].addrs.push((libc::AF_INET6 as u8, prefix, bytes.to_vec()));
                }
            }
            // Darwin carries the hardware address and the MTU on an AF_LINK
            // entry rather than on the address ones, which is why the list is
            // folded by name rather than taken entry by entry.
            libc::AF_LINK => {
                // `sockaddr_dl`, at the offsets `net/if_dl.h` states: sdl_len,
                // sdl_family, sdl_index (2), sdl_type, sdl_nlen, sdl_alen,
                // sdl_slen, then the name and the address.
                if addr.len() >= 8 {
                    let at_mac = 8 + addr[5] as usize;
                    if let Some(mac) = addr.get(at_mac..at_mac + addr[6] as usize)
                        && !mac.is_empty()
                    {
                        by_name[at].mac = mac.to_vec();
                    }
                }
                if let Some(mtu) = host_mtu(&name) {
                    by_name[at].mtu = mtu;
                }
            }
            _ => {}
        }
    }
    by_name
}

/// `N` bytes at `at` of a sockaddr, or `None` for one too short to hold them.
/// The name a guest knows an interface by. Darwin's loopback is `lo0` and
/// every Linux program that names one says `lo` -- `ip addr show lo`
/// answered "can't find device" until 2026-10-18. Index 1 on both. The
/// others keep the host's names: there is no Linux name for `en0` that a
/// program would be looking for instead.
fn guest_name(host: &str) -> &str {
    if host == "lo0" { "lo" } else { host }
}

pub(crate) fn field<const N: usize>(sa: &[u8], at: usize) -> Option<[u8; N]> {
    sa.get(at..at + N)?.try_into().ok()
}

/// The same for a **netmask**, which Darwin trims: its `sa_len` stops after
/// the last non-zero byte, so lo0's /8 is a five-byte sockaddr. What is cut
/// off is zero.
pub(crate) fn field_padded<const N: usize>(sa: &[u8], at: usize) -> [u8; N] {
    let mut out = [0; N];
    if let Some(have) = sa.get(at..) {
        let n = have.len().min(N);
        out[..n].copy_from_slice(&have[..n]);
    }
    out
}

/// What `getifaddrs` answered, given back with `freeifaddrs` when dropped.
///
/// Every pointer the list holds is read here and nowhere else: the entries
/// come out as a name and byte slices exactly as long as each sockaddr says it
/// is, so decoding them is safe code with its bounds checked. The decoding
/// used to cast each sockaddr to the struct its family named and read the
/// field, which on a trimmed netmask is a read past its end: lo0's IPv4 mask
/// is five bytes and `sin_addr` is at four to eight. The bytes there were zero
/// when this was checked, so no wrong prefix was observed.
struct IfAddrs(std::ptr::NonNull<libc::ifaddrs>);

/// One entry of [`IfAddrs`].
struct IfAddr<'a> {
    name: &'a std::ffi::CStr,
    flags: u32,
    addr: Option<&'a [u8]>,
    netmask: Option<&'a [u8]>,
}

impl IfAddrs {
    fn get() -> Option<IfAddrs> {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: `getifaddrs` fills the pointer or fails; `Drop` releases it.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return None;
        }
        std::ptr::NonNull::new(head).map(IfAddrs)
    }

    fn iter(&self) -> impl Iterator<Item = IfAddr<'_>> {
        let mut p: *const libc::ifaddrs = self.0.as_ptr();
        std::iter::from_fn(move || {
            loop {
                // SAFETY: a node of the list, which lives until `self` drops.
                let e = unsafe { p.as_ref() }?;
                p = e.ifa_next;
                if e.ifa_name.is_null() {
                    continue;
                }
                // SAFETY: a non-null name is NUL-terminated, and the
                // sockaddrs are each `sa_len` bytes long; all live with
                // `self`.
                return Some(unsafe {
                    IfAddr {
                        name: std::ffi::CStr::from_ptr(e.ifa_name),
                        flags: e.ifa_flags,
                        addr: sockaddr_bytes(e.ifa_addr),
                        netmask: sockaddr_bytes(e.ifa_netmask),
                    }
                });
            }
        })
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        // SAFETY: the head `getifaddrs` filled in, released once.
        unsafe { libc::freeifaddrs(self.0.as_ptr()) };
    }
}

/// A sockaddr as the bytes its own `sa_len` covers; `None` for null, or for
/// one too short to name a family.
///
/// # Safety
/// `sa` is null or points to `sa_len` readable bytes that outlive `'a`.
unsafe fn sockaddr_bytes<'a>(sa: *const libc::sockaddr) -> Option<&'a [u8]> {
    let len = unsafe { sa.as_ref() }?.sa_len as usize;
    (len >= 2).then(|| unsafe { std::slice::from_raw_parts(sa.cast::<u8>(), len) })
}

/// The host's MTU for a named interface, through `SIOCGIFMTU`.
fn host_mtu(name: &str) -> Option<u32> {
    use std::os::fd::AsRawFd;
    // A datagram socket, used only for the ioctl; it closes as it drops.
    let s = rustix::net::socket(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::DGRAM,
        None,
    )
    .ok()?;
    // SAFETY: `ifreq` is plain data, for which all zeroes is a valid value.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    let bytes = name.as_bytes();
    if bytes.len() >= req.ifr_name.len() {
        return None;
    }
    for (i, b) in bytes.iter().enumerate() {
        req.ifr_name[i] = *b as _;
    }
    // SAFETY: `req` is a whole `ifreq` and SIOCGIFMTU fills its union.
    let ok = unsafe { libc::ioctl(s.as_raw_fd(), libc::SIOCGIFMTU, &mut req) } == 0;
    // SAFETY: the ioctl filled the `ifru_mtu` arm of the union, and without
    // it the arm reads the zeroes it started as.
    ok.then_some(unsafe { req.ifr_ifru.ifru_mtu } as u32)
}

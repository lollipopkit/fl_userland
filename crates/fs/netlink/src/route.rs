//! The host's routing table, and the two ways a guest asks for it.
//!
//! `ip route` answered `RTNETLINK answers: Not supported` and `route -n` could
//! not open `/proc/net/route`, which did not exist. Both are here now, from one
//! source: the host's own table.
//!
//! # Where it comes from
//!
//! There is no `/proc/net/route` on Darwin and no netlink either. The table is
//! a `sysctl(CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_DUMP, 0)`, which answers a
//! run of variable-length `struct rt_msghdr`, each followed by the sockaddrs
//! its `rtm_addrs` bitmask names.
//!
//! Three things about that format are easy to get wrong and silent when got
//! wrong, so each has a test:
//!
//! - **A sockaddr's length is its own first byte**, not `sizeof` anything, and a
//!   zero length advances by four rather than by zero. A walk that trusts
//!   `sizeof(struct sockaddr)` reads the second address out of the middle of the
//!   first.
//! - **They are present in bitmask order** and only the named ones are there, so
//!   the gateway is not at a fixed offset: a route with a netmask and no gateway
//!   puts the netmask where a fixed reading expects the gateway.
//! - **The mask arrives as a `sockaddr` whose `sa_len` is truncated** — Darwin
//!   stores `255.255.255.0` as four bytes and `0.0.0.0` as *zero*, so a default
//!   route's mask is an empty sockaddr and not sixteen bytes of zero.
//!
//! # What a guest is told
//!
//! Only what it can act on: `AF_INET` and `AF_INET6` routes that are up, with a
//! destination, a prefix length, an optional gateway and an interface. Not the
//! host's cloned ARP entries (`RTF_WASCLONED`), which are neighbour cache and
//! not routes -- Linux keeps those in `/proc/net/arp`, and listing them as
//! routes makes `ip route` print a line per machine on the LAN.

use std::ffi::c_int;

/// One route, in the terms both readers below need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// `AF_INET` or `AF_INET6`, as **Linux** numbers them.
    pub family: u8,
    /// Network-order destination bytes: 4 or 16 of them.
    pub dst: Vec<u8>,
    /// How many leading bits of `dst` are the network. 0 is a default route.
    pub prefix_len: u8,
    /// The next hop, empty for an on-link route.
    pub gateway: Vec<u8>,
    /// The interface it leaves by.
    pub if_index: u32,
    pub if_name: String,
    /// Linux's `RTF_*`, translated.
    pub flags: u16,
    pub metric: u32,
}

/// Linux's `RTF_*`, which `/proc/net/route` prints and which are not Darwin's.
pub const RTF_UP: u16 = 0x0001;
pub const RTF_GATEWAY: u16 = 0x0002;
pub const RTF_HOST: u16 = 0x0004;

/// `rtm_flags` as Linux's `RTF_*`.
///
/// Only the three `/proc/net/route` prints and `route -n` decodes. Darwin's
/// `RTF_UP`, `RTF_GATEWAY` and `RTF_HOST` happen to be 1, 2 and 4 as well, and
/// that is a coincidence worth writing down rather than relying on: everything
/// above them diverges, and passing the word through would tell a guest a route
/// is `RTF_REJECT` when the host said `RTF_LLINFO`.
pub(crate) fn linux_route_flags(host: c_int) -> u16 {
    let mut out = 0;
    for (h, l) in [
        (libc::RTF_UP, RTF_UP),
        (libc::RTF_GATEWAY, RTF_GATEWAY),
        (libc::RTF_HOST, RTF_HOST),
    ] {
        if host & h != 0 {
            out |= l;
        }
    }
    out
}

/// How far to step past a sockaddr in a routing message.
///
/// `SA_SIZE`: round `sa_len` up to four, and treat zero as four. The zero case
/// is not hypothetical -- a default route's netmask is a sockaddr of length 0,
/// and a walk that adds it steps nowhere and loops for ever.
pub(crate) fn sa_step(sa_len: u8) -> usize {
    if sa_len == 0 {
        4
    } else {
        (sa_len as usize + 3) & !3
    }
}

/// The bits set in a mask sockaddr's address bytes.
///
/// Darwin truncates: `255.255.255.0` arrives as a 4-byte sockaddr holding three
/// mask bytes after the two-byte header, and `0.0.0.0` as a sockaddr of length
/// zero. Missing bytes are zero, which is what makes the truncation lossless.
pub(crate) fn mask_prefix_len(sa: &[u8], family_len: usize) -> u8 {
    // Byte 0 is sa_len, byte 1 sa_family, then (for AF_INET) two bytes of port
    // before the address -- but a mask sockaddr is truncated *into* that, so
    // the address starts at the same offset the family's sockaddr puts it and
    // whatever is missing is zero.
    let start = if family_len == 4 { 4 } else { 8 };
    let mut bits = 0u8;
    for i in 0..family_len {
        let b = sa.get(start + i).copied().unwrap_or(0);
        bits += b.count_ones() as u8;
    }
    bits
}

/// The address bytes out of a `sockaddr_in` or `sockaddr_in6`.
///
/// `None` for a family this does not carry -- `AF_LINK`, which is what a
/// gateway is for an on-link route, and which has no address a guest can use.
pub(crate) fn sa_addr(sa: &[u8]) -> Option<(u8, Vec<u8>)> {
    let family = *sa.get(1)? as c_int;
    if family == libc::AF_INET {
        let b = sa.get(4..8)?;
        Some((crate::linux_family(libc::AF_INET as u8), b.to_vec()))
    } else if family == libc::AF_INET6 {
        let b = sa.get(8..24)?;
        Some((crate::linux_family(libc::AF_INET6 as u8), b.to_vec()))
    } else {
        None
    }
}

/// Walk one routing message's sockaddrs, in bitmask order.
///
/// Answers the sockaddr for each bit set in `addrs`, in the order the bits are
/// numbered -- which is the order they appear. A message whose lengths run past
/// the buffer ends the walk rather than reading on.
pub(crate) fn sockaddrs(mut body: &[u8], addrs: c_int) -> Vec<(c_int, Vec<u8>)> {
    let mut out = Vec::new();
    for bit in 0..8 {
        let flag = 1 << bit;
        if addrs & flag == 0 {
            continue;
        }
        if body.is_empty() {
            break;
        }
        let step = sa_step(body[0]);
        if step > body.len() {
            break;
        }
        out.push((flag, body[..step].to_vec()));
        body = &body[step..];
    }
    out
}

#[cfg(test)]
#[path = "route_tests.rs"]
mod tests;

// ------------------------------------------------------------- the host's own

/// The host's routing table.
///
/// `sysctl` twice: once for the size, once for the bytes. The table can change
/// between the two, so the second call is allowed to want more and the whole
/// thing is retried -- a short buffer answers `ENOMEM` and returning a
/// half-parsed table would show a guest a subset with no indication it was one.
///
/// An empty answer is an empty table, not an error: the two are the same to
/// every caller here, and a guest that cannot route is told nothing rather than
/// told a lie.
pub fn host_routes() -> Vec<Route> {
    let names = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        0, // AF_UNSPEC: every family
        libc::NET_RT_DUMP,
        0,
    ];
    sysctl_table(&names)
        .map(|buf| parse_dump(&buf, &crate::host_ifaces()))
        .unwrap_or_default()
}

/// One `sysctl` table, read whole: once for the size, once for the bytes,
/// and again from the start if it grew between the two -- a short buffer
/// answers `ENOMEM`, and a half-read table would show a guest a subset with no
/// indication it was one. `None` for any other failure, or a table that kept
/// growing.
///
/// The neighbour table read once and gave up on `ENOMEM` until 2026-10-18;
/// both tables go through this now.
fn sysctl_table(names: &[libc::c_int]) -> Option<Vec<u8>> {
    let call = |buf: &mut [u8], len: &mut libc::size_t| {
        let out = if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr().cast() };
        // SAFETY: `names` is a MIB of `names.len()` integers, and `out` is
        // null (asking for the size) or `buf`, whose length `len` holds.
        unsafe {
            libc::sysctl(names.as_ptr().cast_mut(), names.len() as u32, out, len, std::ptr::null_mut(), 0)
        }
    };
    for _ in 0..4 {
        let mut len: libc::size_t = 0;
        if call(&mut [], &mut len) != 0 || len == 0 {
            return None;
        }
        // Room for the table to have grown between the two calls, which is
        // what makes the retry terminate in practice rather than in principle.
        let mut buf = vec![0u8; len + 4096];
        let mut got = buf.len();
        if call(&mut buf, &mut got) == 0 {
            buf.truncate(got);
            return Some(buf);
        }
        // Anything but "it grew again" is an empty table.
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
            return None;
        }
    }
    None
}

/// The messages of a routing-socket dump: each one's header and its whole
/// bytes, stopping at the first that is shorter than a header or runs past the
/// buffer.
fn messages(mut buf: &[u8]) -> impl Iterator<Item = (libc::rt_msghdr, &[u8])> {
    const HDR: usize = std::mem::size_of::<libc::rt_msghdr>();
    std::iter::from_fn(move || {
        let msglen = u16::from_ne_bytes([*buf.first()?, *buf.get(1)?]) as usize;
        if msglen < HDR || msglen > buf.len() {
            return None;
        }
        let (msg, rest) = buf.split_at(msglen);
        buf = rest;
        // SAFETY: `msg` is at least `HDR` bytes, and `rt_msghdr` is integers
        // only, so any bytes are a value of it.
        let hdr: libc::rt_msghdr = unsafe { std::ptr::read_unaligned(msg.as_ptr().cast()) };
        Some((hdr, msg))
    })
}

/// A `NET_RT_DUMP` answer as routes a guest can read.
///
/// Separate from the `sysctl` above so a test can hand it bytes: the host's
/// table is not something a test can arrange, and the awkward cases -- a
/// default route, a truncated mask, a link-level gateway -- are exactly the
/// ones a machine may or may not have today.
pub fn parse_dump(buf: &[u8], ifaces: &[crate::Iface]) -> Vec<Route> {
    const HDR: usize = std::mem::size_of::<libc::rt_msghdr>();
    let mut out = Vec::new();
    for (hdr, msg) in messages(buf) {
        if hdr.rtm_version != libc::RTM_VERSION as u8 || hdr.rtm_type != libc::RTM_GET as u8 {
            continue;
        }
        if hdr.rtm_flags & libc::RTF_UP == 0 {
            continue;
        }
        // A cloned entry is the neighbour cache -- one per machine seen on the
        // LAN -- and Linux keeps those in /proc/net/arp rather than in the
        // route table. Listing them makes `ip route` print a screen of hosts.
        if hdr.rtm_flags & libc::RTF_WASCLONED != 0 {
            continue;
        }

        let mut dst = None;
        let mut gateway = Vec::new();
        let mut mask: Option<Vec<u8>> = None;
        for (which, sa) in sockaddrs(&msg[HDR..], hdr.rtm_addrs) {
            match which {
                libc::RTA_DST => dst = sa_addr(&sa),
                // **Only when RTF_GATEWAY says so.** Darwin puts something in
                // RTA_GATEWAY for every route: an `AF_LINK` sockaddr naming
                // the interface for an on-link one, and for the loopback the
                // interface's own address. Taken at face value, `127.0.0.0/8`
                // reads as "via 127.0.0.1" and `ip route` prints a next hop
                // for a route that has none. Linux's table has 0.0.0.0 there
                // and the flag is what distinguishes the two.
                libc::RTA_GATEWAY if hdr.rtm_flags & libc::RTF_GATEWAY != 0 => {
                    gateway = sa_addr(&sa).map(|(_, b)| b).unwrap_or_default()
                }
                libc::RTA_NETMASK => mask = Some(sa),
                _ => {}
            }
        }
        let Some((family, dst)) = dst else { continue };

        // A host route has no netmask sockaddr at all; its prefix is every bit.
        let prefix_len = if hdr.rtm_flags & libc::RTF_HOST != 0 {
            (dst.len() * 8) as u8
        } else {
            mask.map(|m| mask_prefix_len(&m, dst.len())).unwrap_or(0)
        };

        let index = hdr.rtm_index as u32;
        let name = ifaces
            .iter()
            .find(|i| i.index == index)
            .map(|i| i.name.clone())
            .unwrap_or_default();
        // An interface this kernel does not report is one a guest cannot name,
        // so a route out of it is not one it can act on.
        if name.is_empty() {
            continue;
        }

        out.push(Route {
            family,
            dst,
            prefix_len,
            gateway,
            if_index: index,
            if_name: name,
            flags: linux_route_flags(hdr.rtm_flags),
            metric: 0,
        });
    }
    // The one place the order is chosen rather than inherited: among routes of
    // the same prefix length, the ones with a next hop first.
    //
    // This machine has **four** default routes -- two VPN tunnels, a bridge and
    // the real interface -- and only one of them has a gateway. Darwin picks
    // between them by a preference this dump does not carry, and a guest
    // reading `/proc/net/route` for "the default gateway" takes the first line
    // whose destination is zero. In host order that was `utun10` with no
    // gateway, so the answer was 0.0.0.0. A stable sort, so everything else
    // stays in the order the host gave.
    out.sort_by_key(|r| (r.prefix_len, r.gateway.is_empty()));
    out
}

// ------------------------------------------------------------------ the query

/// The route an address would take: longest prefix wins.
///
/// A pure function over the table, so the tie-breaking is something a unit test
/// can state rather than something a machine's routing happens to demonstrate.
/// Among routes of equal specificity the first is taken, which is
/// [`parse_dump`]'s order — a next hop before one without.
pub fn lookup<'a>(table: &'a [Route], family: u8, dst: &[u8]) -> Option<&'a Route> {
    // `max_by_key` answers the **last** maximum, which is the opposite of the
    // rule above: this machine has four default routes and `parse_dump` puts
    // the one with a gateway first, so the last of them was chosen and
    // `ip route get 8.8.8.8` answered `dev utun8 scope link` -- a VPN tunnel
    // whose only other route is 100.64.0.0/10. `min_by_key` on the negated
    // length answers the first.
    table
        .iter()
        .filter(|r| r.family == family && r.dst.len() == dst.len() && covers(r, dst))
        .min_by_key(|r| std::cmp::Reverse(r.prefix_len))
}

/// Whether a route's network contains an address.
///
/// The partial byte is the one to get right: a `/12` matches on the top four
/// bits of the second byte and on nothing below them, so a comparison that
/// rounds the prefix to whole bytes routes 172.32.0.0 down 172.16.0.0/12.
pub fn covers(r: &Route, dst: &[u8]) -> bool {
    let bits = r.prefix_len as usize;
    let whole = bits / 8;
    if r.dst.get(..whole) != dst.get(..whole) {
        return false;
    }
    let rest = bits % 8;
    if rest == 0 {
        return true;
    }
    let mask = 0xffu16 << (8 - rest);
    let (a, b) = (
        r.dst.get(whole).copied().unwrap_or(0),
        dst.get(whole).copied().unwrap_or(0),
    );
    a & mask as u8 == b & mask as u8
}

/// The address an interface would send from, of the family asked for.
///
/// `ip route get` prints it as `src`, and a program choosing a bind address
/// reads it. A link-local IPv6 is not one: it is scoped to the link and a
/// socket bound to it can reach nothing else, so a global one is preferred and
/// the link-local is the fallback rather than the answer.
pub fn preferred_src(ifaces: &[crate::Iface], if_index: u32, family: u8) -> Option<Vec<u8>> {
    let iface = ifaces.iter().find(|i| i.index == if_index)?;
    let mine: Vec<&(u8, u8, Vec<u8>)> = iface
        .addrs
        .iter()
        .filter(|(f, _, _)| crate::linux_family(*f) == family)
        .collect();
    mine.iter()
        .find(|(f, _, b)| crate::scope_of(*f, b) == crate::RT_SCOPE_UNIVERSE)
        .or_else(|| mine.first())
        .map(|(_, _, b)| b.clone())
}

// --------------------------------------------------------------- the neighbours

/// One entry of the neighbour cache: an address and the hardware address it
/// resolved to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbour {
    /// Network-order IPv4 bytes.
    pub addr: Vec<u8>,
    /// Six bytes for Ethernet, empty for an entry that has not resolved yet.
    pub mac: Vec<u8>,
    pub if_name: String,
}

/// `ATF_COM`: the entry has a hardware address. `/proc/net/arp`'s flags column
/// is this or zero, and `arp -a` prints `<incomplete>` for the second.
pub const ATF_COM: u32 = 0x02;

/// The MAC out of a `sockaddr_dl`.
///
/// The address is **not at a fixed offset**: `sdl_data` holds the interface
/// name first and the hardware address after it, so the start is
/// `sdl_nlen` bytes in and the length is `sdl_alen`. Reading twelve bytes from
/// `sdl_data` gives the *name* for any interface whose name is not empty.
pub fn sdl_mac(sa: &[u8]) -> Vec<u8> {
    if sa.get(1).copied().unwrap_or(0) as c_int != libc::AF_LINK {
        return Vec::new();
    }
    let nlen = sa.get(5).copied().unwrap_or(0) as usize;
    let alen = sa.get(6).copied().unwrap_or(0) as usize;
    let start = 8 + nlen;
    sa.get(start..start + alen)
        .map(|b| b.to_vec())
        .unwrap_or_default()
}

/// The host's ARP cache, as `/proc/net/arp` reports it.
///
/// The same `sysctl` the routing table comes from: on Darwin a resolved
/// neighbour *is* a route — a host route whose gateway is an `AF_LINK`
/// sockaddr carrying the MAC — which is why [`parse_dump`] has to exclude them
/// and this one keeps exactly what it excludes. Linux draws the line in the
/// same place and puts them in a different file.
pub fn host_neighbours() -> Vec<Neighbour> {
    let names = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        libc::NET_RT_FLAGS,
        libc::RTF_LLINFO,
    ];
    sysctl_table(&names)
        .map(|buf| parse_neighbours(&buf, &crate::host_ifaces()))
        .unwrap_or_default()
}

/// A `NET_RT_FLAGS`/`RTF_LLINFO` answer as neighbours. Separate from the
/// `sysctl` so a test can hand it bytes.
pub fn parse_neighbours(buf: &[u8], ifaces: &[crate::Iface]) -> Vec<Neighbour> {
    const HDR: usize = std::mem::size_of::<libc::rt_msghdr>();
    let mut out = Vec::new();
    for (hdr, msg) in messages(buf) {
        if hdr.rtm_version != libc::RTM_VERSION as u8 {
            continue;
        }
        let mut addr = Vec::new();
        let mut mac = Vec::new();
        for (which, sa) in sockaddrs(&msg[HDR..], hdr.rtm_addrs) {
            match which {
                libc::RTA_DST => {
                    if let Some((_, b)) = sa_addr(&sa) {
                        addr = b;
                    }
                }
                libc::RTA_GATEWAY => mac = sdl_mac(&sa),
                _ => {}
            }
        }
        if addr.len() != 4 {
            continue;
        }
        let name = ifaces
            .iter()
            .find(|i| i.index == hdr.rtm_index as u32)
            .map(|i| i.name.clone())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        out.push(Neighbour {
            addr,
            mac,
            if_name: name,
        });
    }
    out
}

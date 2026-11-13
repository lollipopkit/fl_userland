//! `AF_NETLINK`, `NETLINK_ROUTE`: enough of it to answer "what interfaces are
//! there".
//!
//! `socket(AF_NETLINK, ...)` answered `EAFNOSUPPORT` until 2026-09-08, and that
//! is not a degraded answer for anything that asks:
//!
//! - `ip addr` prints `socket(AF_NETLINK,3,0): Address family not supported`
//!   and stops.
//! - **Go's `net.Interfaces()` fails outright** —
//!   `route ip+net: netlinkrib: address family not supported by protocol` —
//!   because that is how the Go runtime enumerates interfaces on Linux. So does
//!   `net.InterfaceAddrs()`. Measured in a guest with a cross-compiled binary.
//! - `ss` uses it before falling back to `/proc/net`.
//!
//! # What is here and what is not
//!
//! Two requests: `RTM_GETLINK` and `RTM_GETADDR`, both as a dump. That is what
//! an enumerator sends and all it sends. Everything else answers `NLMSG_ERROR`
//! with `EOPNOTSUPP`, which is what a netlink caller expects for a message a
//! kernel does not implement — **not** a closed socket, because a caller reads
//! the error and reports it, and a truncated dump would be read as "no
//! interfaces".
//!
//! Routes, neighbours, links being brought up and the notification groups are
//! not here. A guest cannot change the host's network, so a request that would
//! is refused rather than pretended.
//!
//! # It is a wire format
//!
//! Every structure is little-endian, four-byte aligned, and length-prefixed by
//! a field that includes the header — get any of that wrong and a parser reads
//! the next message's header as an attribute. `CLAUDE.md` records four defects
//! of exactly that shape in this repository, so the encoder is here, alone,
//! with the offsets asserted against the numbers `linux/netlink.h` states.

use std::ffi::c_int;

// -------------------------------------------------------------- the constants

/// `NETLINK_ROUTE`. The only protocol this answers.
pub const NETLINK_ROUTE: c_int = 0;

pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;

pub mod route;

mod protocol;
pub(crate) use protocol::ifaddrmsg;
pub use protocol::{Message, Request, done, error, ifinfomsg, parse};

mod host;
pub use host::host_ifaces;
mod ioctl;
pub use ioctl::{
    IFCONF_LEN, IFNAMSIZ, IFREQ_LEN, SIOCGIFADDR, SIOCGIFCONF, SIOCGIFFLAGS, SIOCGIFHWADDR,
    SIOCGIFINDEX, SIOCGIFMTU, SIOCGIFNAME, SIOCGIFNETMASK, SIOCGIFTXQLEN, ifconf_entries,
    ifreq_ioctl, ifreq_name,
};

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_GETNEIGH: u16 = 30;

pub const NLM_F_REQUEST: u16 = 0x001;
pub const NLM_F_MULTI: u16 = 0x002;
pub const NLM_F_ACK: u16 = 0x004;
pub const NLM_F_DUMP: u16 = 0x300;

/// `struct nlmsghdr`: four bytes of length, two of type, two of flags, then a
/// sequence number and a port id.
pub const NLMSG_HDRLEN: usize = 16;
/// `struct ifinfomsg`.
pub const IFINFOMSG_LEN: usize = 16;
/// `struct ifaddrmsg`.
pub const IFADDRMSG_LEN: usize = 8;
/// `struct rtattr`: two bytes of length, two of type.
pub const RTA_HDRLEN: usize = 4;

pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_MTU: u16 = 4;
/// The transmit queue length. Sent because busybox `ip` falls back to
/// `ioctl(SIOCGIFTXQLEN)` without it and prints a failure per interface;
/// nothing here has a queue, and 1000 is what Linux defaults to.
pub const IFLA_TXQLEN: u16 = 13;
/// `IF_OPER_*`, which `ip` prints as `state`: see [`operstate`].
pub const IFLA_OPERSTATE: u16 = 16;

pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_LABEL: u16 = 3;

/// `ARPHRD_ETHER` and `ARPHRD_LOOPBACK`, which is what `ifi_type` carries.
pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_LOOPBACK: u16 = 772;

/// Everything is aligned to four bytes, including the payload of an attribute.
pub const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

// ---------------------------------------------------------------- the answers

/// One interface, as much of the host's as a guest is told.
pub struct Iface {
    pub index: u32,
    pub name: String,
    /// The hardware address, empty for a loopback or a tunnel.
    pub mac: Vec<u8>,
    pub mtu: u32,
    /// Linux's `IFF_*`, translated from the host's — the numbers differ.
    pub flags: u32,
    pub loopback: bool,
    /// Every address on it: family, prefix length, and the bytes.
    pub addrs: Vec<(u8, u8, Vec<u8>)>,
}

// Linux's IFF_*, which are not Darwin's beyond the first few.
const IFF_UP: u32 = 0x1;
const IFF_BROADCAST: u32 = 0x2;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_POINTOPOINT: u32 = 0x10;
const IFF_RUNNING: u32 = 0x40;
const IFF_NOARP: u32 = 0x80;
const IFF_PROMISC: u32 = 0x100;
const IFF_MULTICAST: u32 = 0x1000;
/// The carrier is up. Linux sets it with `IFF_RUNNING` for an interface that
/// is operationally up, and `ip` shows `LOWER_UP` from it; Darwin has no such
/// bit. Above the 16 bits `SIOCGIFFLAGS` carries, so only netlink reports it.
const IFF_LOWER_UP: u32 = 0x10000;

/// The host's flag word as Linux's.
///
/// **Translated, not passed through.** Darwin's `IFF_RUNNING` is 0x40 and so is
/// Linux's, but `IFF_MULTICAST` is 0x8000 on Darwin and 0x1000 on Linux, and
/// `IFF_PROMISC` is 0x100 on both while `IFF_ALLMULTI` is not. A word handed
/// over unmapped tells a guest an interface is something else — the same shape
/// as `guest_to_host_signal`'s pass-through default, which this repository
/// records delivering `SIGUSR1` as `SIGBUS`.
pub fn linux_flags(host: u32) -> u32 {
    let mut out = 0;
    for (h, l) in [
        (0x1u32, IFF_UP),
        (0x2, IFF_BROADCAST),
        (0x8, IFF_LOOPBACK),
        (0x10, IFF_POINTOPOINT),
        (0x40, IFF_RUNNING),
        (0x80, IFF_NOARP),
        (0x100, IFF_PROMISC),
        (0x8000, IFF_MULTICAST),
    ] {
        if host & h != 0 {
            out |= l;
        }
    }
    if out & IFF_RUNNING != 0 {
        out |= IFF_LOWER_UP;
    }
    out
}

/// `rtnetlink.h`'s address scopes.
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RT_SCOPE_HOST: u8 = 254;

/// `IFA_F_PERMANENT`: an address that was configured rather than leased.
///
/// Everything here is, because the host configured it and a guest cannot change
/// it. Without the bit `ip addr` labels every address `dynamic`, which says it
/// has a lifetime and will expire.
pub const IFA_F_PERMANENT: u8 = 0x80;

/// The scope an address has, which is not a property of the interface.
///
/// A link-local address — `fe80::/10`, or `169.254/16` — is **`RT_SCOPE_LINK`**
/// even on an interface whose other addresses are global, and a reader picking
/// a source address filters on exactly this. Reporting one as universe offers
/// it for traffic that cannot use it. A loopback address is `RT_SCOPE_HOST`.
pub fn scope_of(family: u8, addr: &[u8]) -> u8 {
    match (family as i32, addr) {
        (libc::AF_INET, [127, ..]) => RT_SCOPE_HOST,
        (libc::AF_INET, [169, 254, ..]) => RT_SCOPE_LINK,
        (libc::AF_INET6, a) if a.len() == 16 => {
            if a == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
                RT_SCOPE_HOST
            } else if a[0] == 0xfe && (a[1] & 0xc0) == 0x80 {
                RT_SCOPE_LINK
            } else {
                RT_SCOPE_UNIVERSE
            }
        }
        _ => RT_SCOPE_UNIVERSE,
    }
}

/// Linux's `AF_INET`/`AF_INET6`, from the host's.
///
/// **Darwin's `AF_INET6` is 30 and Linux's is 10.** Passed through unmapped,
/// `ip addr` printed `family 30 ???/128` for every v6 address — the same
/// mistake as handing over the flag word, one field along, and it went in
/// even after the comment on [`linux_flags`] was written. A number that means
/// something on both sides and means something *different* is the shape.
pub fn linux_family(host: u8) -> u8 {
    match host as i32 {
        libc::AF_INET => 2,
        libc::AF_INET6 => 10,
        _ => 0, // AF_UNSPEC, which a reader skips
    }
}

/// A netmask as the prefix length netlink carries.
pub fn prefix_len(mask: &[u8]) -> u8 {
    mask.iter().map(|b| b.count_ones() as u8).sum()
}

/// RFC 2863's operational state, as Linux reports it: `DOWN` (2) for an
/// interface that is not up or has no carrier, `UP` (6) for one that is
/// running, and `UNKNOWN` (0) for the loopback, whose driver does not manage
/// a carrier at all -- which is what `ip link` shows for Linux's `lo`.
fn operstate(i: &Iface) -> u8 {
    const UNKNOWN: u8 = 0;
    const DOWN: u8 = 2;
    const UP: u8 = 6;
    if i.flags & IFF_UP == 0 {
        DOWN
    } else if i.loopback {
        UNKNOWN
    } else if i.flags & IFF_RUNNING != 0 {
        UP
    } else {
        DOWN
    }
}

/// The `RTM_GETLINK` dump.
pub fn links(ifaces: &[Iface], seq: u32, pid: u32) -> Vec<u8> {
    let mut out = Vec::new();
    for i in ifaces {
        let kind = if i.loopback {
            ARPHRD_LOOPBACK
        } else {
            ARPHRD_ETHER
        };
        let mut m = Message::new(&mut out, RTM_NEWLINK, NLM_F_MULTI, seq, pid);
        m.body(&ifinfomsg(i.index, kind, i.flags));
        // The name is NUL-terminated in the attribute, which is what a reader
        // strips -- Go takes the bytes up to the first NUL and a name without
        // one runs into the padding.
        let mut name = i.name.clone().into_bytes();
        name.push(0);
        m.attr(IFLA_IFNAME, &name);
        m.attr(IFLA_MTU, &i.mtu.to_le_bytes());
        m.attr(IFLA_TXQLEN, &1000u32.to_le_bytes());
        m.attr(IFLA_OPERSTATE, &[operstate(i)]);
        if !i.mac.is_empty() {
            m.attr(IFLA_ADDRESS, &i.mac);
        }
        m.finish(&mut out);
    }
    done(&mut out, seq, pid);
    out
}

/// The `RTM_GETADDR` dump.
pub fn addrs(ifaces: &[Iface], seq: u32, pid: u32) -> Vec<u8> {
    let mut out = Vec::new();
    for i in ifaces {
        for (family, prefix, bytes) in &i.addrs {
            let mut m = Message::new(&mut out, RTM_NEWADDR, NLM_F_MULTI, seq, pid);
            // From the *address*, not the interface: a link-local on an
            // otherwise-global interface is still link-local. See `scope_of`.
            let scope = scope_of(*family, bytes);
            m.body(&ifaddrmsg(linux_family(*family), *prefix, scope, i.index));
            // IFA_ADDRESS *and* IFA_LOCAL: on a point-to-point interface the
            // first is the peer's and the second is this end's, and Go reads
            // IFA_LOCAL when it is there. Equal for everything else, which is
            // what Linux sends.
            m.attr(IFA_ADDRESS, bytes);
            m.attr(IFA_LOCAL, bytes);
            let mut label = i.name.clone().into_bytes();
            label.push(0);
            m.attr(IFA_LABEL, &label);
            m.finish(&mut out);
        }
    }
    done(&mut out, seq, pid);
    out
}

/// `struct rtmsg`, the body of an `RTM_NEWROUTE`. Twelve bytes.
pub const RTMSG_LEN: usize = 12;

/// `rtm_table` / `rtm_protocol` / `rtm_scope` / `rtm_type`, of the values a
/// dump of a real table uses.
pub const RT_TABLE_MAIN: u8 = 254;
pub const RTPROT_KERNEL: u8 = 2;
pub const RTPROT_BOOT: u8 = 3;
pub const RTN_UNICAST: u8 = 1;

/// `rtmsg`'s attributes, of the four a reader wants.
pub const RTA_DST: u16 = 1;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;

/// One `struct rtmsg`.
pub fn rtmsg(family: u8, dst_len: u8, scope: u8, protocol: u8) -> [u8; RTMSG_LEN] {
    let mut b = [0u8; RTMSG_LEN];
    b[0] = family;
    b[1] = dst_len;
    // rtm_src_len and rtm_tos stay 0.
    b[4] = RT_TABLE_MAIN;
    b[5] = protocol;
    b[6] = scope;
    b[7] = RTN_UNICAST;
    b
}

/// The `RTM_GETROUTE` dump.
///
/// `ip route` answered `RTNETLINK answers: Not supported` without this, and
/// `route -n` read `/proc/net/route`, which is the same table through the other
/// interface.
///
/// **A default route has no `RTA_DST`.** Linux omits the attribute rather than
/// sending four zero bytes, and `ip` prints `default` for a route that has none
/// — send the zeroes and it prints `0.0.0.0/0`, which is the same route and not
/// the same output. The prefix length in the header is what says which it is.
/// `family` is the request's: `AF_INET` for `ip route`, `AF_INET6` for
/// `ip -6 route`, and `AF_UNSPEC` for "everything" — which is what a request
/// with no body means as well. Without the filter, `ip route` printed this
/// machine's IPv6 default routes among its IPv4 ones.
pub fn routes(routes: &[route::Route], family: u8, seq: u32, pid: u32) -> Vec<u8> {
    let mut out = Vec::new();
    for r in routes.iter().filter(|r| family == 0 || r.family == family) {
        let mut m = Message::new(&mut out, RTM_NEWROUTE, NLM_F_MULTI, seq, pid);
        // A route with a next hop reaches beyond this link; one without does
        // not, and `ip` prints `scope link` for the second. The protocol says
        // where the route came from, and a host's own table is boot's rather
        // than a routing daemon's -- except the on-link ones the kernel adds
        // when an address is configured.
        let (scope, protocol) = if r.gateway.is_empty() {
            (RT_SCOPE_LINK, RTPROT_KERNEL)
        } else {
            (RT_SCOPE_UNIVERSE, RTPROT_BOOT)
        };
        m.body(&rtmsg(r.family, r.prefix_len, scope, protocol));
        if r.prefix_len != 0 {
            m.attr(RTA_DST, &r.dst);
        }
        if !r.gateway.is_empty() {
            m.attr(RTA_GATEWAY, &r.gateway);
        }
        m.attr(RTA_OIF, &r.if_index.to_le_bytes());
        // Linux omits the attribute for a metric of zero, and `ip` prints
        // `metric 0` if it is there — a difference from a real kernel's output
        // for every route in the table.
        if r.metric != 0 {
            m.attr(RTA_PRIORITY, &r.metric.to_le_bytes());
        }
        m.finish(&mut out);
    }
    done(&mut out, seq, pid);
    out
}

/// The attributes in a message body, after a fixed-size struct.
///
/// The writing direction is [`Message::attr`]; this is the reading one, and it
/// is the first thing in this crate to read a *guest's* attributes rather than
/// write the kernel's. So the rules are the ones a wire format needs: a length
/// below the header is not a zero-length attribute but a walk that never ends,
/// and one past the buffer ends the walk rather than reading on.
pub fn attrs(body: &[u8], after: usize) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut rest = match body.get(after..) {
        Some(r) => r,
        None => return out,
    };
    while rest.len() >= RTA_HDRLEN {
        let len = u16::from_le_bytes(rest[0..2].try_into().unwrap()) as usize;
        if len < RTA_HDRLEN || len > rest.len() {
            break;
        }
        let kind = u16::from_le_bytes(rest[2..4].try_into().unwrap());
        out.push((kind, &rest[RTA_HDRLEN..len]));
        let step = align4(len);
        if step >= rest.len() {
            break;
        }
        rest = &rest[step..];
    }
    out
}

/// `ip route get <addr>`: the one route that address would take.
///
/// Not a dump — one `RTM_NEWROUTE` and no `NLMSG_DONE`, which is what a query
/// answers and what `ip` reads. The destination echoed back is the *queried*
/// address rather than the route's network, and `RTA_PREFSRC` is the source
/// address the chosen interface would use: both are what `ip` prints, and
/// without the second it prints the route with no `src`.
///
/// `None` when the request carries no destination or nothing matches, which the
/// caller turns into an `NLMSG_ERROR`.
pub fn route_get(
    table: &[route::Route],
    ifaces: &[Iface],
    req: &Request,
    seq: u32,
    pid: u32,
) -> Option<Vec<u8>> {
    let dst = attrs(&req.body, RTMSG_LEN)
        .into_iter()
        .find(|(k, _)| *k == RTA_DST)
        .map(|(_, v)| v.to_vec())?;
    let family = if dst.len() == 16 { 10 } else { 2 };
    let r = route::lookup(table, family, &dst)?;

    let mut out = Vec::new();
    let mut m = Message::new(&mut out, RTM_NEWROUTE, 0, seq, pid);
    let scope = if r.gateway.is_empty() {
        RT_SCOPE_LINK
    } else {
        RT_SCOPE_UNIVERSE
    };
    m.body(&rtmsg(family, (dst.len() * 8) as u8, scope, RTPROT_BOOT));
    m.attr(RTA_DST, &dst);
    if !r.gateway.is_empty() {
        m.attr(RTA_GATEWAY, &r.gateway);
    }
    m.attr(RTA_OIF, &r.if_index.to_le_bytes());
    if let Some(src) = route::preferred_src(ifaces, r.if_index, family) {
        m.attr(RTA_PREFSRC, &src);
    }
    m.finish(&mut out);
    Some(out)
}

/// `RTA_PREFSRC`: the source address a route would use.
pub const RTA_PREFSRC: u16 = 7;

/// `struct ndmsg`, the body of an `RTM_NEWNEIGH`. Twelve bytes.
pub const NDMSG_LEN: usize = 12;

/// `ndm_state`, of the two a host's cache distinguishes.
pub const NUD_INCOMPLETE: u16 = 0x01;
pub const NUD_REACHABLE: u16 = 0x02;

pub const NDA_DST: u16 = 1;
pub const NDA_LLADDR: u16 = 2;

/// One `struct ndmsg`.
pub fn ndmsg(family: u8, if_index: u32, state: u16) -> [u8; NDMSG_LEN] {
    let mut b = [0u8; NDMSG_LEN];
    b[0] = family;
    b[4..8].copy_from_slice(&(if_index as i32).to_le_bytes());
    b[8..10].copy_from_slice(&state.to_le_bytes());
    b[11] = RTN_UNICAST;
    b
}

/// The `RTM_GETNEIGH` dump: what `ip neigh` reads, and the same cache
/// `/proc/net/arp` shows.
///
/// **`NDA_LLADDR` is omitted for an entry that has not resolved**, where the
/// text file writes zeroes. The two files differ because the readers differ: a
/// column has to stay a column, and an attribute that is absent is how netlink
/// says "not known" — sending six zero bytes would make `ip neigh` print
/// `lladdr 00:00:00:00:00:00` for a neighbour that has never answered.
pub fn neighbours(ns: &[route::Neighbour], ifaces: &[Iface], seq: u32, pid: u32) -> Vec<u8> {
    let mut out = Vec::new();
    for n in ns {
        let index = ifaces
            .iter()
            .find(|i| i.name == n.if_name)
            .map(|i| i.index)
            .unwrap_or(0);
        let state = if n.mac.is_empty() {
            NUD_INCOMPLETE
        } else {
            NUD_REACHABLE
        };
        let mut m = Message::new(&mut out, RTM_NEWNEIGH, NLM_F_MULTI, seq, pid);
        m.body(&ndmsg(2, index, state));
        m.attr(NDA_DST, &n.addr);
        if !n.mac.is_empty() {
            m.attr(NDA_LLADDR, &n.mac);
        }
        m.finish(&mut out);
    }
    done(&mut out, seq, pid);
    out
}

#[cfg(test)]
mod tests;

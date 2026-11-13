use std::fmt::Write;
/// One TCP or UDP socket, as the file reports it.
pub struct Inet {
    /// The address in **network order**, four bytes for v4 and sixteen for v6.
    pub local: [u8; 16],
    pub lport: u16,
    pub remote: [u8; 16],
    pub rport: u16,
    /// A TCP state number: `0A` listening, `01` established, `07` closed.
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
    pub v6: bool,
}

/// TCP states, as `/proc/net/tcp` numbers them.
pub const TCP_ESTABLISHED: u8 = 0x01;
pub const TCP_CLOSE: u8 = 0x07;
pub const TCP_LISTEN: u8 = 0x0a;

/// One AF_UNIX socket.
pub struct Unix {
    pub refcount: u32,
    pub protocol: u32,
    pub flags: u32,
    /// `SOCK_STREAM` is 1, `SOCK_DGRAM` 2, `SOCK_SEQPACKET` 5 — the guest's
    /// numbers, which is what a reader expects.
    pub type_: u16,
    /// `01` unconnected, `03` connected. Linux's `SS_UNCONNECTED` and
    /// `SS_CONNECTED`.
    pub state: u8,
    pub inode: u64,
    /// The bound path, or empty for a socket that bound nothing. An abstract
    /// name is reported with a leading NUL as `@`, which is what Linux does.
    pub path: Vec<u8>,
}

/// `SO_ACCEPTCONN` in the flags column, which is how a reader tells a listening
/// socket from a connected one.
pub const UNIX_FLAG_LISTENING: u32 = 0x0001_0000;

pub const SS_UNCONNECTED: u8 = 0x01;
pub const SS_CONNECTED: u8 = 0x03;

/// Four network-order bytes as the word Linux prints.
fn word(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// One address, as many `%08X` groups as the family has.
pub(super) fn address(addr: &[u8; 16], v6: bool) -> String {
    if v6 {
        (0..4)
            .map(|i| format!("{:08X}", word(&addr[i * 4..])))
            .collect()
    } else {
        format!("{:08X}", word(&addr[..4]))
    }
}

/// The header of each of the four, byte for byte from an arm64 kernel.
///
/// **All four differ**, and not only in the address width: `udp` and `udp6`
/// have three extra columns and `udp`'s line starts with *three* spaces where
/// `tcp`'s starts with two. The v4 headers are padded to the file's line width
/// with `%-*s` and the v6 ones are not, because Linux writes those with
/// `seq_puts`. A parser taking fixed columns reads the wrong field if any of
/// that is guessed.
pub(crate) fn inet_header(v6: bool, udp: bool) -> &'static str {
    match (v6, udp) {
        (false, false) => concat!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt",
            "   uid  timeout inode                                                     \n",
        ),
        (true, false) => concat!(
            "  sl  local_address                         remote_address                ",
            "        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        ),
        (false, true) => concat!(
            "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt",
            "   uid  timeout inode ref pointer drops            \n",
        ),
        (true, true) => concat!(
            "  sl  local_address                         remote_address                ",
            "        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref ",
            "pointer drops\n",
        ),
    }
}

/// One line of `/proc/net/tcp` and its three relatives.
///
/// The columns after `inode` are a reference count, a kernel pointer and five
/// timer figures. They are constants here and are not a lie by omission: the
/// pointer is `%pK`, which `kptr_restrict` blanks for an unprivileged reader on
/// Linux too, and the timers describe a congestion-control state this kernel
/// does not have and no tool reads.
pub(crate) fn inet_line(sl: usize, inet: &Inet) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "{sl:4}: {}:{:04X} {}:{:04X} {:02X} 00000000:00000000 00:00000000 00000000 \
         {:5} {:8} {} 1 0000000000000000 100 0 0 10 0",
        address(&inet.local, inet.v6),
        inet.lport,
        address(&inet.remote, inet.v6),
        inet.rport,
        inet.state,
        inet.uid,
        0,
        inet.inode,
    );
    // Measured: a v4 line is 149 columns and a v6 line 178 -- Linux's
    // `seq_setwidth(seq, TMPSZ - 1)`, and the two TMPSZ differ by more than the
    // address width does. Reproduced because a parser taking fixed columns
    // rather than splitting on whitespace reads the padding as part of the
    // last field otherwise.
    let width = if inet.v6 { 178 } else { 149 };
    while out.len() < width {
        out.push(' ');
    }
    out.push('\n');
    out
}

/// `/proc/net/route`'s header and one line per IPv4 route.
///
/// Taken byte for byte from an arm64 container, because three things about it
/// are not guessable:
///
/// - **Every line is padded to 127 columns**, header included -- Linux writes
///   them with `seq_printf(seq, "%-127s\n", ...)`. `route -n` and busybox's
///   `route` split on whitespace and do not care; a reader taking fixed columns
///   does.
/// - **The addresses are the network-order bytes read as a little-endian
///   word**, the same as `/proc/net/tcp`: 192.168.215.1 prints as `01D7A8C0`.
/// - **`Gateway` in the header has a trailing space** and `Mask` is followed by
///   *two* tabs. Both are Linux's, and a parser counting tab-separated fields
///   sees a different number of columns without them.
///
/// IPv4 only. Linux keeps v6 routes in `/proc/net/ipv6_route`, in a different
/// format, and a v6 route in here would be read as a v4 one with a very odd
/// destination.
pub(crate) fn route_header() -> String {
    pad127("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT")
}

/// One route. `r.dst` and `r.gateway` are network-order bytes.
pub(crate) fn route_line(r: &netlink::route::Route) -> String {
    let mask: Vec<u8> = (0..4)
        .map(|i| {
            let bits = (r.prefix_len as i32 - i * 8).clamp(0, 8);
            (0xffu16 << (8 - bits)) as u8
        })
        .collect();
    let gw = if r.gateway.len() == 4 {
        word(&r.gateway)
    } else {
        0
    };
    pad127(&format!(
        "{}\t{:08X}\t{:08X}\t{:04X}\t0\t0\t{}\t{:08X}\t0\t0\t0",
        r.if_name,
        word(&r.dst),
        gw,
        r.flags,
        r.metric,
        word(&mask),
    ))
}

/// `/proc/net/arp`'s header and one line per neighbour.
///
/// Taken byte for byte from an arm64 container. Linux's format string is
/// `"%-16s 0x%-10x0x%-10x%s     *        %s\n"`, which is **not** the columns
/// the header suggests: the hardware address is unpadded and the two spacers
/// after it are literal runs, so a row is 76 columns for a six-byte MAC and
/// shorter for none. Neither the header nor the rows are padded to a width —
/// unlike `/proc/net/route`, three files along.
///
/// `arp -a` and `ip neigh` read it, and a program that wants the MAC of a
/// machine it has just talked to reads it.
pub(crate) fn arp_header() -> String {
    "IP address       HW type     Flags       HW address            Mask     Device\n".into()
}

pub(crate) fn arp_line(n: &netlink::route::Neighbour) -> String {
    let ip = n
        .addr
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(".");
    // **Zeroes, not an empty field**, for an entry that has been asked for and
    // not answered. Linux formats `dev->addr_len` bytes of `neigh->ha`
    // whatever the state, so an incomplete entry is `00:00:00:00:00:00` and
    // the columns after it stay where a reader expects them. Measured: an
    // empty field made busybox's `arp -a` read the `*` as the hardware address
    // and print `on -` for the interface.
    let mac: String = if n.mac.is_empty() {
        "00:00:00:00:00:00".into()
    } else {
        n.mac
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    // ARPHRD_ETHER, and ATF_COM only once the address is known -- which is the
    // one thing that *does* distinguish the two states in this file.
    let flags = if n.mac.is_empty() {
        0
    } else {
        netlink::route::ATF_COM
    };
    format!(
        "{ip:<16} 0x{:<10x}0x{flags:<10x}{mac}     *        {}\n",
        1, n.if_name
    )
}

/// The width Linux writes this file at, and the newline after it.
fn pad127(s: &str) -> String {
    let mut out = s.to_string();
    while out.len() < 127 {
        out.push(' ');
    }
    out.push('\n');
    out
}

pub(crate) fn unix_header() -> &'static str {
    "Num       RefCount Protocol Flags    Type St Inode Path\n"
}

/// One line of `/proc/net/unix`.
///
/// The first column is the socket's kernel address, which Linux prints with
/// `%pK` and blanks for an unprivileged reader. Sixteen zeros here, which is
/// what a guest would see on a hardened kernel and what every parser skips.
pub(crate) fn unix_line(unix: &Unix) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "0000000000000000: {:08X} {:08X} {:08X} {:04X} {:02X} {:5}",
        unix.refcount, unix.protocol, unix.flags, unix.type_, unix.state, unix.inode
    );
    if !unix.path.is_empty() {
        out.push(' ');
        // An abstract name has a leading NUL and Linux reports it as `@`.
        if unix.path[0] == 0 {
            out.push('@');
            out.push_str(&String::from_utf8_lossy(&unix.path[1..]));
        } else {
            out.push_str(&String::from_utf8_lossy(&unix.path));
        }
    }
    out.push('\n');
    out
}

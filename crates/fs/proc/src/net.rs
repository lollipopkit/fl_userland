//! `/proc/net/tcp`, `tcp6`, `udp`, `udp6` and `unix`.
//!
//! `netstat -an` in a guest answered
//! `netstat: /proc/net/tcp: No such file or directory` — the directory had one
//! entry, `dev`, and every tool that lists connections reads these five.
//!
//! # What is in them
//!
//! Every socket this kernel has, once each. Linux shows a network namespace's
//! sockets; here the guest's sockets **are** the namespace, so the answer is
//! exact rather than a sample — which matters, because a caller reads these
//! files to decide that something is *not* listening, and a partial list is a
//! wrong answer rather than a missing one.
//!
//! A socket appears once even when several descriptors name it: `fork` shares
//! the open file description, so the same socket is in two tables, and the
//! walk deduplicates on the description rather than the descriptor.
//!
//! # The format is a wire format
//!
//! Not in the offsets-and-alignment sense, but in the one that matters here:
//! `netstat`, `ss` and every health-check script parse these by column, so the
//! field order and the hex widths are the contract. Taken from a real arm64
//! kernel rather than from a man page — `Documentation/networking/proc_net_tcp`
//! is out of date and does not mention the trailing pad:
//!
//! ```text
//!    0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5733467 1 0000000000000000 100 0 0 10 0
//! ```
//!
//! **The address is the network-order bytes read as a little-endian word.**
//! 127.0.0.1 is `7F 00 00 01` on the wire and prints as `0100007F`, which looks
//! byte-swapped and is not: Linux prints a `__be32` with `%08X`, and on a
//! little-endian machine that is what comes out. Getting this backwards is
//! invisible for `0.0.0.0` and for any palindrome, which is most of what a test
//! would reach for.

#[path = "format.rs"]
mod format;
#[cfg(test)]
use format::address;
pub(crate) use format::{
    Inet, SS_CONNECTED, SS_UNCONNECTED, TCP_CLOSE, TCP_ESTABLISHED, TCP_LISTEN,
    UNIX_FLAG_LISTENING, Unix, arp_header, arp_line, inet_header, inet_line, route_header,
    route_line, unix_header, unix_line,
};

use crate::ffi;
use crate::pidsnap::Found;
use std::ffi::c_int;

/// Every socket description in the system, once each, with the uid of a task
/// that holds it.
///
/// **Thread-group leaders only**, which is not a gap: a thread shares its
/// group's descriptor table, so a socket a non-leader opened is in the leader's
/// table too. A process that unshared its files with `CLONE_FILES` and no
/// `CLONE_THREAD` is a *separate* leader and is walked in its own right.
///
/// Deduplicated on the **description**, not the descriptor: `fork` and `dup`
/// both give a second descriptor for one socket, and a socket listed twice is a
/// connection a reader counts twice.
///
/// `pids_lock` is held only for the length of one task's field read, and the
/// descriptor table is retained across the descriptor walk — the lock order
/// this crate already uses for `/proc/<pid>/fd`, and the reason the walk is
/// per-task rather than one hold over everything.
fn each_socket(mut f: impl FnMut(&ffi::fd, u32)) {
    let mut seen: Vec<usize> = Vec::new();
    let mut pid = 0;
    loop {
        pid = taskcalls::task_next_listed_pid(pid);
        if pid == 0 {
            return;
        }
        let Some((files, uid)) = (|| {
            let found = Found::for_pid(pid)?;
            let task = found.task();
            // Cloned under the guard, which `found` holds until it drops at
            // the end of this closure -- after the clone. `None` for a task
            // whose descriptors have gone.
            Some((task.files()?, task.uid()))
        })() else {
            continue;
        };
        // An allocation failure lists none of this process's sockets, as
        // the sizing loop this replaced did.
        let numbers = files.numbers().unwrap_or_default();

        for num in numbers {
            let Some(held) = files.lookup_retain(num) else {
                continue;
            };
            // SAFETY: `lookup_retain` holds a reference for as long as `held`
            // is alive, which is past every use of this borrow.
            let fd: &ffi::fd = &held;
            // The `S_IFMT` bits, which is how /proc/<pid>/fd already tells a
            // socket from a pipe. It read them through `fs_fdobj::fd_type`
            // until 2026-09-16 -- that is a `#[no_mangle] extern "C"` in
            // `iul.h` and stays for the embedder, but a Rust caller reaching
            // another Rust crate through the C ABI is the thing `CLAUDE.md`
            // spent 691 sites removing, and this was the last one for it.
            let is_socket = fd.type_ as u32 == libc::S_IFSOCK as u32;
            let at = std::ptr::from_ref(fd) as usize;
            if is_socket && !seen.contains(&at) {
                seen.push(at);
                f(fd, uid);
            }
            // `held` releases here, which is what the `fd_close` below the loop
            // body used to do -- including on the `continue` above, which it
            // did not.
        }
        drop(files);
    }
}

// ---------------------------------------------------------------------------
// The five files
// ---------------------------------------------------------------------------

/// A host `sockaddr` as the address and port `/proc/net/*` prints.
///
/// `None` for a family this file is not about, which is how one walk fills four
/// files: every socket is offered to each and answers for one.
fn inet_of(addr: &[u8], want_v6: bool) -> Option<([u8; 16], u16)> {
    // Darwin's `sockaddr` starts with a one-byte length and a one-byte family;
    // Linux's with a two-byte family. This is the host's, so it is Darwin's.
    if addr.len() < 4 {
        return None;
    }
    let family = addr[1] as i32;
    let port = u16::from_be_bytes([addr[2], addr[3]]);
    let mut out = [0u8; 16];
    match (family, want_v6) {
        (libc::AF_INET, false) if addr.len() >= 8 => {
            out[..4].copy_from_slice(&addr[4..8]);
            Some((out, port))
        }
        (libc::AF_INET6, true) if addr.len() >= 24 => {
            out.copy_from_slice(&addr[8..24]);
            Some((out, port))
        }
        _ => None,
    }
}

/// `/proc/net/tcp`, `tcp6`, `udp` and `udp6` — one walk, one file.
fn show_inet(buf: &mut ffi::proc_data, v6: bool, udp: bool) {
    let mut text = String::from(inet_header(v6, udp));
    let want_type = if udp {
        libc::SOCK_DGRAM
    } else {
        libc::SOCK_STREAM
    };
    let mut sl = 0;
    each_socket(|fd, uid| {
        let Some(info) = fs_sock::net_info(fd) else {
            return;
        };
        if info.type_ != want_type {
            return;
        }
        let Some((local, lport)) = inet_of(&info.local, v6) else {
            return;
        };
        let (remote, rport) = inet_of(&info.remote, v6).unwrap_or(([0u8; 16], 0));
        // Linux's state machine, as much of it as is observable from here: a
        // socket that accepts is listening, one with a peer is established, and
        // one with neither is closed. A guest reads the first two and branches
        // on them; the rest of the machine is TCP's own and the host keeps it.
        let state = if info.listening {
            TCP_LISTEN
        } else if rport != 0 {
            TCP_ESTABLISHED
        } else {
            TCP_CLOSE
        };
        text.push_str(&inet_line(
            sl,
            &Inet {
                local,
                lport,
                remote,
                rport,
                state,
                uid,
                inode: info.inode,
                v6,
            },
        ));
        sl += 1;
    });
    crate::root::out(buf, &text);
}

fn show_net_tcp(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    show_inet(buf, false, false);
    0
}

fn show_net_tcp6(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    show_inet(buf, true, false);
    0
}

fn show_net_udp(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    show_inet(buf, false, true);
    0
}

fn show_net_udp6(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    show_inet(buf, true, true);
    0
}

fn show_net_unix(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    let mut text = String::from(unix_header());
    each_socket(|fd, _uid| {
        let Some(info) = fs_sock::net_info(fd) else {
            return;
        };
        if info.domain != libc::AF_UNIX {
            return;
        }
        text.push_str(&unix_line(&Unix {
            // Two: the description and the table entry, which is what Linux
            // reports for an ordinary socket nobody has duplicated.
            refcount: 2,
            protocol: 0,
            flags: if info.listening {
                UNIX_FLAG_LISTENING
            } else {
                0
            },
            type_: info.type_ as u16,
            state: if info.unix_connected {
                SS_CONNECTED
            } else {
                SS_UNCONNECTED
            },
            inode: info.inode,
            path: info.unix_name.clone(),
        }));
    });
    crate::root::out(buf, &text);
    0
}

/// `/proc/net/raw` and `raw6`: a header and nothing else.
///
/// This kernel has no raw sockets — `socket(AF_INET, SOCK_RAW, ...)` needs a
/// privilege the host will not give an unsigned application — so the honest
/// answer is an empty list rather than a missing file. `netstat -an` reads all
/// four and reports `netstat: /proc/net/raw: No such file or directory` for a
/// missing one, which reads as a broken system rather than as an empty table.
fn show_net_raw(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    crate::root::out(
        buf,
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   \
         uid  timeout inode ref pointer drops\n",
    );
    0
}

fn show_net_raw6(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    crate::root::out(
        buf,
        "  sl  local_address                         remote_address                        \
         st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n",
    );
    0
}

/// `/proc/net/route`: the host's IPv4 table, which is the guest's, because a
/// guest's sockets *are* host sockets and the host does the routing.
///
/// `route -n` could not open this file and `ip route` answered `RTNETLINK
/// answers: Not supported`. What a reader wants from it is almost always one
/// number -- the default gateway -- and where that comes from is
/// `crates/fs/netlink`'s `route` module.
fn show_net_arp(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    crate::root::out(buf, &arp_header());
    for n in netlink::route::host_neighbours() {
        crate::root::out(buf, &arp_line(&n));
    }
    0
}

/// `/proc/net/arp`: the host's neighbour cache, which on Darwin lives in the
/// routing table as host routes with a link-level gateway — the entries
/// `route`'s dump has to exclude.
fn show_net_route(_e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    crate::root::out(buf, &route_header());
    for r in netlink::route::host_routes() {
        // v4 only: Linux keeps v6 routes in /proc/net/ipv6_route, and one in
        // here would read as a v4 route to a very odd destination.
        if r.dst.len() == 4 {
            crate::root::out(buf, &route_line(&r));
        }
    }
    0
}

/// The nine, for `crates/fs/proc`'s `/proc/net` directory.
pub(crate) const SHOWS: [(&std::ffi::CStr, crate::root::ShowFn); 9] = [
    (c"tcp", Some(show_net_tcp)),
    (c"tcp6", Some(show_net_tcp6)),
    (c"udp", Some(show_net_udp)),
    (c"udp6", Some(show_net_udp6)),
    (c"unix", Some(show_net_unix)),
    (c"raw", Some(show_net_raw)),
    (c"raw6", Some(show_net_raw6)),
    (c"route", Some(show_net_route)),
    (c"arp", Some(show_net_arp)),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: [u8; 4]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..4].copy_from_slice(&a);
        out
    }

    #[test]
    fn the_address_is_network_order_read_as_a_little_endian_word() {
        // 127.0.0.1 prints as 0100007F. This is the one thing in the format
        // that looks wrong and is right, and it is invisible for 0.0.0.0 --
        // which is what a test written from the listening case would use.
        assert_eq!(address(&v4([127, 0, 0, 1]), false), "0100007F");
        assert_eq!(address(&v4([0, 0, 0, 0]), false), "00000000");
        assert_eq!(address(&v4([10, 1, 2, 3]), false), "0302010A");
        assert_eq!(address(&v4([255, 255, 255, 255]), false), "FFFFFFFF");
    }

    #[test]
    fn a_v6_address_is_four_of_those() {
        assert_eq!(address(&[0u8; 16], true), "0".repeat(32));
        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        assert_eq!(address(&loopback, true), "00000000000000000000000001000000");
    }

    #[test]
    fn a_listening_socket_matches_a_real_kernels_line() {
        // Byte for byte from an arm64 container, with the inode and uid this
        // test supplies:
        //    0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 \
        //    00000000     0        0 5733467 1 0000000000000000 100 0 0 10 0
        let s = Inet {
            local: v4([127, 0, 0, 1]),
            lport: 8080,
            remote: [0; 16],
            rport: 0,
            state: TCP_LISTEN,
            uid: 0,
            inode: 5_733_467,
            v6: false,
        };
        let line = inet_line(0, &s);
        // The whole line, not a prefix: a `starts_with` over a string written
        // with a `\` continuation is a test of the continuation's indentation.
        let want = "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5733467 1 0000000000000000 100 0 0 10 0";
        assert_eq!(line.trim_end_matches([' ', '\n']), want);
        assert_eq!(line.len(), 150, "149 columns and a newline");
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn the_header_is_the_one_a_parser_expects() {
        // Every one of the four, measured. `udp`'s three leading spaces and
        // its three extra columns are the ones a reader would not guess.
        assert_eq!(inet_header(false, false).len(), 150, "149 and a newline");
        assert_eq!(inet_header(true, false).len(), 145);
        assert_eq!(inet_header(false, true).len(), 128);
        assert!(
            inet_header(false, true).starts_with("   sl  "),
            "three spaces"
        );
        assert!(inet_header(false, false).starts_with("  sl  "), "two");
        assert!(
            inet_header(false, true)
                .trim_end()
                .ends_with("ref pointer drops")
        );
        assert!(
            inet_header(true, true)
                .trim_end()
                .ends_with("ref pointer drops")
        );
        assert!(!inet_header(false, false).trim_end().ends_with("drops"));
        assert_eq!(
            unix_header(),
            "Num       RefCount Protocol Flags    Type St Inode Path\n"
        );
    }

    #[test]
    fn an_abstract_unix_name_is_reported_with_an_at_sign() {
        let s = Unix {
            refcount: 2,
            protocol: 0,
            flags: UNIX_FLAG_LISTENING,
            type_: 1,
            state: SS_UNCONNECTED,
            inode: 42,
            path: b"\0abstract".to_vec(),
        };
        let line = unix_line(&s);
        assert!(line.ends_with(" @abstract\n"), "got {line:?}");
        assert!(line.starts_with("0000000000000000: 00000002 00000000 00010000 0001 01 "));
    }

    #[test]
    fn an_arp_line_matches_a_real_kernels_byte_for_byte() {
        // Both rows from an arm64 container, which is where the format came
        // from. 76 columns each, and neither the header nor the rows are
        // padded to a width -- unlike /proc/net/route.
        let done = netlink::route::Neighbour {
            addr: vec![192, 168, 215, 1],
            mac: vec![0xca, 0x7e, 0x8f, 0x25, 0xd7, 0x09],
            if_name: "eth0".into(),
        };
        assert_eq!(
            arp_line(&done),
            "192.168.215.1    0x1         0x2         ca:7e:8f:25:d7:09     *        eth0\n"
        );
        assert_eq!(arp_line(&done).len(), 77, "76 columns and a newline");

        // And one that has not resolved: zeroes rather than an empty field, so
        // the two columns after it do not slide left.
        let waiting = netlink::route::Neighbour {
            addr: vec![192, 168, 215, 99],
            mac: vec![],
            if_name: "eth0".into(),
        };
        assert_eq!(
            arp_line(&waiting),
            "192.168.215.99   0x1         0x0         00:00:00:00:00:00     *        eth0\n"
        );
        assert_eq!(
            arp_line(&waiting).len(),
            arp_line(&done).len(),
            "the same width"
        );
        assert_eq!(arp_header().len(), 79, "78 columns and a newline");
    }

    #[test]
    fn a_route_line_matches_a_real_kernels_byte_for_byte() {
        // The default route from an arm64 container, which is where the format
        // was taken from:
        //   eth0\t00000000\t01D7A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0
        // padded to 127. The gateway is 192.168.215.1 and prints as 01D7A8C0,
        // which is the network-order bytes read as a little-endian word.
        let r = netlink::route::Route {
            family: 2,
            dst: vec![0, 0, 0, 0],
            prefix_len: 0,
            gateway: vec![192, 168, 215, 1],
            if_index: 2,
            if_name: "eth0".into(),
            flags: netlink::route::RTF_UP | netlink::route::RTF_GATEWAY,
            metric: 0,
        };
        let line = route_line(&r);
        assert_eq!(
            line.trim_end(),
            "eth0\t00000000\t01D7A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0"
        );
        assert_eq!(line.len(), 128, "127 columns and a newline");
    }

    #[test]
    fn a_prefix_length_becomes_the_mask_column() {
        // The on-link route from the same container: 192.168.215.0/24 with
        // mask 255.255.255.0, which prints as 00FFFFFF.
        let r = netlink::route::Route {
            family: 2,
            dst: vec![192, 168, 215, 0],
            prefix_len: 24,
            gateway: vec![],
            if_index: 2,
            if_name: "eth0".into(),
            flags: netlink::route::RTF_UP,
            metric: 0,
        };
        assert_eq!(
            route_line(&r).trim_end(),
            "eth0\t00D7A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0"
        );

        // And the two ends of the range, which a shift by 8 gets wrong: a /0
        // is all zeroes and a /32 is all ones. `0xff << 8` is 0 in a u8, so the
        // shift is done in a u16 -- the reason that cast is there.
        let mut r0 = r.clone();
        r0.prefix_len = 0;
        assert!(
            route_line(&r0).contains("\t00000000\t0\t0\t0"),
            "{}",
            route_line(&r0)
        );
        let mut r32 = r.clone();
        r32.prefix_len = 32;
        assert!(
            route_line(&r32).contains("\tFFFFFFFF\t0\t0\t0"),
            "{}",
            route_line(&r32)
        );
        // And one that is not a whole number of bytes: /12 is 255.240.0.0,
        // whose bytes are FF F0 00 00 and whose little-endian word is
        // 0000F0FF -- which reads backwards and is right, the same way
        // 127.0.0.1 prints as 0100007F.
        let mut r12 = r.clone();
        r12.prefix_len = 12;
        assert!(
            route_line(&r12).contains("\t0000F0FF\t"),
            "{}",
            route_line(&r12)
        );
    }

    #[test]
    fn the_route_header_is_the_one_a_parser_expects() {
        let h = route_header();
        assert_eq!(h.len(), 128, "127 and a newline");
        assert!(
            h.starts_with("Iface\tDestination\tGateway \tFlags"),
            "{h:?}"
        );
        assert!(h.contains("Mask\t\tMTU"), "two tabs after Mask: {h:?}");
    }

    #[test]
    fn a_socket_that_bound_nothing_has_no_path_column() {
        let s = Unix {
            refcount: 2,
            protocol: 0,
            flags: 0,
            type_: 1,
            state: SS_CONNECTED,
            inode: 7,
            path: Vec::new(),
        };
        let line = unix_line(&s);
        // No trailing space before the newline: a parser splitting on
        // whitespace gets seven fields rather than eight with an empty one.
        assert!(line.ends_with("    7\n"), "got {line:?}");
    }
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

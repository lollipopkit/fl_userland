//! What can be asked without a kernel: the address translation.
//!
//! The rest of this crate is `f_get`, `f_install` and the host's socket calls,
//! and its coverage is `tests/guest/src/bin/sock_{semantics,net,race}.rs`,
//! `fd_passing.rs` and `sock_probe.rs` -- 350-odd checks, and the probe is
//! compared against a real arm64 kernel. What is here is the part that is a
//! *wire format*, which is where the defects in this tree keep being.

use super::address::{SOCKADDR_DATA_MAX, host_addr_to_guest};
use super::*;

/// The host's `struct sockaddr_in`, filled the way the host lays one out --
/// each field at the host struct's own offset.
fn host_inet(port: u16, addr: [u8; 4]) -> Vec<u8> {
    use std::mem::offset_of;
    let mut sa = vec![0u8; size_of::<libc::sockaddr_in>()];
    sa[offset_of!(libc::sockaddr_in, sin_len)] = size_of::<libc::sockaddr_in>() as u8;
    crate::host::set_family(&mut sa, libc::AF_INET);
    let at = offset_of!(libc::sockaddr_in, sin_port);
    sa[at..at + 2].copy_from_slice(&port.to_be_bytes());
    let at = offset_of!(libc::sockaddr_in, sin_addr);
    sa[at..at + 4].copy_from_slice(&addr);
    sa
}

#[test]
fn an_inet_address_keeps_its_port_and_its_address() {
    let host = host_inet(8080, [127, 0, 0, 1]);
    let (out, report) = host_addr_to_guest(&host).expect("a translated inet address");

    // The guest's sockaddr_ is a little-endian family and then the body.
    assert_eq!(u16::from_le_bytes([out[0], out[1]]), guest::PF_INET as u16);
    // The port is network order on both sides and is not touched.
    assert_eq!(u16::from_be_bytes([out[2], out[3]]), 8080);
    assert_eq!(&out[4..8], &[127, 0, 0, 1]);
    assert_eq!(report, host.len());
}

/// The regression this whole split exists for.
///
/// Reading the family as a little-endian u16 gives 2 on Linux and 0x0210 on
/// Darwin, where the first byte is `sa_len`. The second is not a family, so
/// `family_from_real` answers NONE and the call became EINVAL.
#[test]
fn the_family_is_read_the_way_the_host_wrote_it() {
    let host = host_inet(1, [0, 0, 0, 0]);
    assert_ne!(
        host_addr_to_guest(&host).map(|(o, _)| o[0]),
        Err(Errno::EINVAL),
        "an inet address the host filled in has to translate"
    );

    // And the byte a naive reader would have used is not the family on every
    // host, which is what makes the assertion above worth having.
    let naive = u16::from_le_bytes([host[0], host[1]]) as c_int;
    assert_ne!(naive, libc::AF_INET, "Darwin's first byte is sa_len");
}

#[test]
fn a_unix_address_reports_the_family_and_nothing_else() {
    let mut host = vec![0u8; size_of::<libc::sockaddr_un>()];
    crate::host::set_family(&mut host, libc::AF_UNIX);
    // A host path that says nothing about what the guest bound.
    let path = b"/tmp/iulsock1.2";
    let at = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    host[at..at + path.len()].copy_from_slice(path);

    let (out, report) = host_addr_to_guest(&host).expect("a translated unix address");
    assert_eq!(out, (guest::PF_LOCAL as u16).to_le_bytes().to_vec());
    // Linux reports offsetof(sun_path). Reporting 16 -- the size of the struct
    // -- claims fourteen bytes of name that are not there, and a caller testing
    // `len > 2` to decide whether there is one was told yes.
    assert_eq!(report, 2);
}

#[test]
fn a_family_this_kernel_has_no_number_for_is_einval() {
    let mut host = vec![0u8; 16];
    crate::host::set_family(&mut host, libc::AF_APPLETALK);
    assert_eq!(host_addr_to_guest(&host), Err(Errno::EINVAL));
}

#[test]
fn an_address_too_short_to_have_a_family_is_einval() {
    assert_eq!(host_addr_to_guest(&[]), Err(Errno::EINVAL));
}

/// A long inet6 address is truncated to what a guest `sockaddr_` can hold, and
/// the length still reports what there was.
#[test]
fn the_body_is_bounded_by_what_the_guest_struct_holds() {
    let mut host = vec![0u8; 2 + SOCKADDR_DATA_MAX + 64];
    crate::host::set_family(&mut host, libc::AF_INET6);
    let (out, report) = host_addr_to_guest(&host).expect("a translated inet6 address");
    assert_eq!(out.len(), 2 + SOCKADDR_DATA_MAX);
    assert_eq!(report, host.len(), "the report is what there was");
}

/// Asking for the socket operation table tells `crates/fs/sockrestart` what a
/// socket is, and nothing else can catch it if it stops.
///
/// That crate brackets every blocking `accept` so a signal restarts it rather
/// than losing it, and it picks the descriptors to bracket by comparing
/// `fd->ops` against this table. With nothing installed the comparison is
/// against null, so **no descriptor is a socket** — every accept is bracketed
/// as if it were an ordinary file, silently, and the symptom is an `accept`
/// that returns `EINTR` where Linux restarts it. No unit test here can see it:
/// there are no sockets in one.
///
/// `socket_fdops_get` is the install point because it is the only way the
/// address is obtained and every socket descriptor goes through it.
#[test]
fn asking_for_the_socket_table_tells_sockrestart_what_a_socket_is() {
    let driver = super::socket_fdops_get();
    assert!(driver.is_some());
    assert!(sockrestart::socket_fdops_installed());
}

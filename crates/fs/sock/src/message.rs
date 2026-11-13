//! `sendmsg` and `recvmsg` with guest iovec and control-message translation.

use std::ffi::c_int;
use std::os::fd::{AsFd, BorrowedFd};

use sockabi::guest;
use strace::strace;
use usercopy::GuestMem;

use rustix::io::Errno as HostErrno;

use crate::{
    Errno, O_NONBLOCK_GUEST, SOCKADDR_MAX, Sock, host, netlink_send, put_u32, read_addr, rx_err,
    send_err, send_flags, sock_wait_readable_for_rs, to_real_flags, write_host_addr,
};

// Descriptors in flight over a unix socket.
//
// A host unix socket cannot carry this kernel's descriptors, so what goes over
// the wire is one *placeholder* host descriptor and the real ones travel beside
// it, in the receiving endpoint's queue. What sits in that queue is a
// `unixpeer::ControlMessage`: the `struct fd`s with a reference taken, which
// the receiver installs in its own table.
//
// **The queue owns them, since 2026-09-16.** `Table::queue` takes the
// `Vec<Owned>` and hands back a `ScmId`; every way a message can end -- taken
// by the receiver, taken back by a failed send, dropped when the endpoint
// closes -- is that value going out of scope and releasing what it holds.
//
// There was a `type Scm`, a `scm_into_raw` and a `scm_free` here, with the
// `Box::into_raw` address stored in the queue as a `usize` and doing double
// duty as the message's identity. Four of the five uses of that pair were a
// free, and one was `scm_free(scm_into_raw(scm))` -- an allocation made in
// order to be freed on the next line, because dropping the value was the thing
// wanted and there was no way to say it. The C had an intrusive `struct list`
// in the message too, left from when the queue was a list of these.

/// Linux's limit on the descriptors one `SCM_RIGHTS` message may carry.
const SCM_MAX_FD: usize = 253;

/// Held from queuing an SCM onto the peer until the `sendmsg` carrying it
/// returns.
///
/// The receiver takes the head of the peer's queue when it sees an `SCM_RIGHTS`
/// control message, so the queue order has to be the order the messages reach
/// the wire — two threads sending descriptors on one socket could otherwise
/// queue in one order and send in the other, handing each message the other's
/// descriptors.
///
/// Not one of the fd locks: the receiver holds the peer's while it pops, and a
/// `sendmsg` blocking on a full buffer with that held would wait for a reader
/// that is waiting for it.
static SCM_SEND: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The one host descriptor that stands in for however many are really being
/// sent. Opened once; a host unix socket refuses an `SCM_RIGHTS` with nothing
/// in it, so there has to be something.
fn placeholder_fd() -> BorrowedFd<'static> {
    static FD: std::sync::OnceLock<std::os::fd::OwnedFd> = std::sync::OnceLock::new();
    FD.get_or_init(|| {
        std::fs::File::open(".")
            .expect("no descriptor for the SCM_RIGHTS placeholder")
            .into()
    })
    .as_fd()
}

/// Reads the guest's iovec array and gives back `(guest base, length)` per
/// entry, with the running total checked against the crate's bound.
fn read_iovecs(hdr: &msghdr::Checked) -> Result<Vec<(u64, usize)>, Errno> {
    let n = hdr.iovlen as usize;
    let mut raw = vec![0u8; n * msghdr::IOVEC_SIZE];
    if n > 0 && GuestMem.read(hdr.iov, &mut raw) != 0 {
        return Err(Errno::EFAULT);
    }
    let mut out = Vec::with_capacity(n);
    let mut total = 0u64;
    for i in 0..n {
        let at = i * msghdr::IOVEC_SIZE;
        let base = u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
        let len = u64::from_le_bytes(raw[at + 8..at + 16].try_into().unwrap());
        msghdr::iov_entry(len, &mut total).map_err(Errno::from_negative_or_eio)?;
        out.push((base, len as usize));
    }
    Ok(out)
}

fn read_header(msghdr_addr: u64, dir: msghdr::Direction) -> Result<msghdr::Checked, Errno> {
    // Read as bytes rather than as a struct because two of its three lengths
    // are 64 bits wide and the comparisons that bound them have to see the
    // whole value -- narrowing first is how `msg_iovlen = 0x1_0000_0001` came
    // to send one vector.
    let mut bytes = [0u8; msghdr::SIZE];
    if GuestMem.read(msghdr_addr, &mut bytes) != 0 {
        return Err(Errno::EFAULT);
    }
    let raw = msghdr::Raw::decode(&bytes).ok_or(Errno::EINVAL)?;
    msghdr::check(&raw, dir).map_err(Errno::from_negative_or_eio)
}

pub fn sys_sendmsg(sock_fd: c_int, msghdr_addr: u64, flags: c_int) -> Result<i64, Errno> {
    strace!("sendmsg({sock_fd}, {msghdr_addr:#x}, {flags})");
    let sock = Sock::get(sock_fd)?;
    let hdr = read_header(msghdr_addr, msghdr::Direction::Send)?;

    // A unix stream socket does not take a destination address, and which error
    // it answers depends only on whether it is connected:
    //
    //     if (msg->msg_namelen) {
    //         err = sk->sk_state == TCP_ESTABLISHED ? -EISCONN : -EOPNOTSUPP;
    //
    // That is asked *before* the address is looked at, which is why it is here:
    // this used to read the address first, so `sendmsg` on a connected socket
    // with a 16-byte name tried to connect somewhere and reported ECONNREFUSED,
    // and with a 128-byte one reported EINVAL. Both are EISCONN.
    if sock.is_unix() && sock.ty() == guest::SOCK_STREAM && hdr.namelen != 0 {
        let connected = sock.real().is_ok_and(|h| host::peername(h).is_ok());
        return Err(if connected {
            Errno::EISCONN
        } else {
            Errno::EOPNOTSUPP
        });
    }

    // msg_name. A length of zero is "no address" rather than an error, which is
    // what `move_addr_to_kernel` does and what this refused: a connected socket
    // sent with `msg_namelen = 0` got EINVAL.
    // A netlink socket's `msg_name` is a `sockaddr_nl`, and `read_addr` refuses
    // it: `family_to_real(AF_NETLINK)` is NONE, which is EINVAL. `sendto`
    // answers netlink *before* reading the address for that reason and this did
    // not, so `ip route get 8.8.8.8` failed at its `sendmsg` with "can't talk
    // to rtnetlink: Invalid argument" — while `ip route`, whose request carries
    // no name, worked. Nothing in a netlink destination is actionable anyway:
    // the kernel is the only place a request can go, and it is this.
    let name = if sock.is_netlink() {
        None
    } else if hdr.name != 0 && hdr.namelen != 0 {
        Some(read_addr(hdr.name, hdr.namelen)?)
    } else {
        None
    };

    let entries = read_iovecs(&hdr)?;
    let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
    for (base, len) in &entries {
        let mut b = Vec::new();
        if b.try_reserve(*len).is_err() {
            return Err(Errno::ENOMEM);
        }
        b.resize(*len, 0u8);
        if *len > 0 && GuestMem.read(*base, &mut b) != 0 {
            return Err(Errno::EFAULT);
        }
        bufs.push(b);
    }

    // Netlink, answered here for the same reason `sendto` answers it: `ip`
    // sends its request with `sendmsg` and Go with `sendto`, so a route through
    // only one of them works for one of the two callers this exists for.
    if sock.is_netlink() {
        let flat: Vec<u8> = bufs.concat();
        return Errno::split(netlink_send(sock, &flat) as i64);
    }

    // msg_control. The crate has refused anything above INT_MAX with ENOBUFS,
    // which is where Linux refuses; below that the answer comes from the
    // allocation, exactly as `____sys_sendmsg` gets it from sock_kmalloc. A cap
    // of 2048 here was visible to the guest -- `msg_controllen = 2049` was
    // ENOBUFS where Linux allocates and then answers EINVAL for the malformed
    // message inside.
    let mut control = Vec::new();
    if hdr.controllen != 0 {
        if control.try_reserve(hdr.controllen as usize).is_err() {
            return Err(Errno::ENOBUFS);
        }
        control.resize(hdr.controllen as usize, 0u8);
        if GuestMem.read(hdr.control, &mut control) != 0 {
            return Err(Errno::EFAULT);
        }
    }

    // The descriptors, if any, and the placeholder message that stands in for
    // them on the wire.
    let mut queued: Option<unixpeer::ScmId> = None;
    let mut carry_placeholder = false;
    let _send_guard;
    if sock.is_unix() && !control.is_empty() {
        // A malformed message is an error here rather than at a second pass,
        // and both leave with the buffers already allocated: a guest could
        // otherwise leak a host buffer per vector on every bad control message
        // it sent.
        let guest_fds =
            cmsg::parse_rights(&control).map_err(Errno::from_negative_or_eio)?;
        if guest_fds.len() > SCM_MAX_FD {
            return Err(Errno::EINVAL);
        }
        if !guest_fds.is_empty() {
            let mut fds: Vec<fs_fdobj::Owned> = Vec::with_capacity(guest_fds.len());
            for num in &guest_fds {
                strace!(" sending fd {num}");
                // An invalid descriptor in SCM_RIGHTS crashed the emulator
                // once, where it should answer EBADF. The ones already taken
                // are released by `fds` going out of scope here.
                let sent = fs_fdobj::f_get(*num).ok_or(Errno::EBADF)?;
                fds.push(sent.retain());
            }

            carry_placeholder = true;

            // Taken before the queue and dropped after the sendmsg, so the
            // order of this peer's queue is the order the messages reach the
            // wire. See SCM_SEND.
            _send_guard = SCM_SEND.lock().unwrap_or_else(|p| p.into_inner());
            // To the peer's receive queue, or -- if nobody has accepted this
            // connection yet -- onto this socket's own list, which accept
            // splices onto the socket it creates. The message goes out on the
            // wire either way.
            //
            // This used to wait until a peer appeared. That wait is bounded by
            // the connection hanging up, which a listener that simply stops
            // accepting never does, so `sendmsg` hung for ever. Linux does not
            // wait here either.
            match unixpeer::with_table(|t| t.queue(sock.peer(), fds)) {
                Some(where_) => queued = Some(where_.id()),
                // Nowhere to put it: `queue` took the descriptors and released
                // them, and the message goes out without them.
                None => carry_placeholder = false,
            }
        }
    }

    let real_flags = send_flags(&sock, flags);

    // msg_flags in the guest's struct is an output field. Linux never reads it
    // on a send, and this did: a guest that left junk there had its message
    // refused, because a flag with no host equivalent came back negative.
    let to = name.as_ref().map(|(bytes, n)| &bytes[..*n as usize]);
    let rights = carry_placeholder.then(placeholder_fd);
    match sock.real().and_then(|h| host::send_msg(h, &bufs, to, rights, real_flags).map_err(|e| send_err(e, flags))) {
        Ok(n) => Ok(n as i64),
        Err(e) => {
            // Taken back out and dropped here, which releases the descriptors.
            if let Some(id) = queued {
                unixpeer::with_table(|t| t.unqueue(id));
            }
            Err(e)
        }
    }
}

pub fn sys_recvmsg(sock_fd: c_int, msghdr_addr: u64, flags: c_int) -> Result<i64, Errno> {
    strace!("recvmsg({sock_fd}, {msghdr_addr:#x}, {flags})");
    let sock = Sock::get(sock_fd)?;
    // On this side the crate *clamps* an over-large msg_namelen rather than
    // refusing it -- and refuses a negative one, which this read as unsigned
    // and accepted.
    let hdr = read_header(msghdr_addr, msghdr::Direction::Recv)?;
    let real_flags = to_real_flags(flags);

    // How much room the guest has. The host's `msg_namelen` is the buffer's
    // size on the way in and the address's real length on the way out, so by
    // the time the result is written back there is nothing left that says what
    // the guest asked for -- and the buffer's own size was passed as the
    // capacity instead, writing a full address into however little it had.
    let guest_namelen = hdr.namelen.min(SOCKADDR_MAX as u32);

    let entries = read_iovecs(&hdr)?;
    let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
    for (_, len) in &entries {
        let mut b = Vec::new();
        if b.try_reserve(*len).is_err() {
            return Err(Errno::ENOMEM);
        }
        b.resize(*len, 0u8);
        bufs.push(b);
    }

    // The same wait as sys_recvfrom, and for the same reason: only when the
    // caller actually wants blocking behaviour. musl's res_msend creates
    // nonblock sockets and calls recvmsg(fd, &mh, 0), relying on EAGAIN on an
    // empty buffer to end its "drain pending responses" loop.
    let host_nonblock = sock.host_nonblocking();
    let guest_nonblock = sock.flags() & O_NONBLOCK_GUEST != 0;
    let should_wait = real_flags & libc::MSG_DONTWAIT == 0 && !guest_nonblock && !host_nonblock;

    let real = sock.real()?;
    // A zero-length receive on a message socket still takes a message, so on
    // an empty socket Linux waits for one or answers EAGAIN. Darwin answers 0
    // at once, so `recvmsg(MSG_PEEK)` with no buffer -- how busybox `nc -l`
    // waits for its first datagram and learns who sent it -- returned before
    // anything arrived, and nc connected to garbage (`tests/guest`
    // udp_probe). Asked before the receive, because a zero-byte datagram is a
    // real one and also answers 0.
    let wants_message = bufs.iter().all(Vec::is_empty) && sock.ty() != guest::SOCK_STREAM;
    let receive = |bufs: &mut [Vec<u8>], flags: c_int| {
        if wants_message && !host::readable_now(real) {
            return Err(HostErrno::AGAIN);
        }
        host::recv_msg(real, bufs, hdr.name != 0, hdr.controllen != 0, flags)
    };
    let got: Result<host::Received, Errno> = if should_wait {
        loop {
            match receive(&mut bufs, real_flags | libc::MSG_DONTWAIT) {
                Ok(got) => break Ok(got),
                Err(HostErrno::INTR) => continue,
                Err(HostErrno::AGAIN) => {}
                Err(e) => break Err(rx_err(e)),
            }
            let wr = sock_wait_readable_for_rs(real);
            if wr < 0 {
                break Err(Errno::from_negative_or_eio(wr));
            }
        }
    } else {
        receive(&mut bufs, real_flags).map_err(rx_err)
    };
    let (res, err, got) = match got {
        Ok(got) => (got.bytes as isize, None, Some(got)),
        Err(e) => (-1, Some(e), None),
    };

    // The vectors, filled to whatever was received.
    let mut left = if res < 0 { 0 } else { res as usize };
    for (i, (base, _)) in entries.iter().enumerate() {
        let chunk = bufs[i].len().min(left);
        if chunk > 0 && GuestMem.write(*base, &bufs[i][..chunk]) != 0 {
            return Err(Errno::EFAULT);
        }
        left -= chunk;
    }

    // The control message. `hdr.controllen` is what the guest has room for and
    // `wrote` is what this call put there, which is what gets written back --
    // one field asking two questions is how the capacity used to be lost before
    // the answer needed it.
    let mut ctrunc = false;
    let mut wrote_controllen = 0u32;
    // The placeholder, closed as this binding drops -- on every path out,
    // which the explicit `close` it replaced was not on the ones that
    // returned early.
    let placeholder = got.as_ref().and_then(|g| g.rights.as_ref());
    if sock.is_unix() && placeholder.is_some() {

        // MSG_PEEK leaves the message -- placeholder and all -- in the socket,
        // so consuming the queued scm here would hand its descriptors over and
        // leave the next read of that same message with nothing to find. Linux
        // does not deliver ancillary data on a peek either. The placeholder is
        // closed regardless; only the queue is left alone.
        if real_flags & libc::MSG_PEEK == 0 {
            // The peer sends the placeholder and queues the scm separately, so
            // an empty queue here means the two disagree. That is a bug, but
            // not one worth aborting over: drop the control message and let the
            // data through.
            let scm = unixpeer::with_table(|t| t.take(sock.peer()));

            if res < 0 {
                // `scm` drops here, releasing whatever it held.
                return Err(err.unwrap_or(Errno::EIO));
            }

            if let Some(scm) = scm {
                // How many the guest has room to be *told* about. Working this
                // out first is what Linux's scm_detach_fds does, and what this
                // did not: it installed every descriptor and then truncated the
                // buffer, so the guest was left holding descriptors whose
                // numbers it had no way to learn and therefore no way to close.
                let room = cmsg::rights_capacity(hdr.controllen as usize);
                let to_install = scm.fds.len().min(room);
                if to_install < scm.fds.len() {
                    ctrunc = true;
                }

                // MSG_CMSG_CLOEXEC is the caller asking for these to arrive
                // with close-on-exec already set, so that no window exists
                // between the descriptor appearing and an fcntl closing it -- a
                // fork on another thread in that window leaks it into the child.
                let install_flags = if flags & MSG_CMSG_CLOEXEC != 0 {
                    O_CLOEXEC_GUEST
                } else {
                    0
                };
                let mut installed = Vec::with_capacity(to_install);
                let mut scm = scm;
                // Everything past the guest's control-buffer room is this
                // side's to release, and `drain` below only reaches what is
                // left -- so the tail is released by this binding going out of
                // scope rather than by a second loop over an index that the
                // error path below moves.
                let _no_room = scm.fds.split_off(to_install);
                for fd in scm.fds.drain(..) {
                    // `f_install` consumes the reference **however it ends**:
                    // it installs, or it releases and answers a negative errno.
                    let n = fs_fdobj::f_install(fd, install_flags);
                    if n < 0 {
                        // The fd table is full. Report the ones that made it and
                        // flag the control message truncated, which is what
                        // Linux's scm_detach_fds does -- the negative errno used
                        // to go into the array and reach the guest as a
                        // descriptor number.
                        //
                        // **The ones after it are released by the drain**, which
                        // drops whatever it has not yielded. This used to set
                        // `to_install = i` and then release from index `i`
                        // onward -- including the one `f_install` had just
                        // released, a double release of a live description.
                        ctrunc = true;
                        break;
                    }
                    strace!(" receiving fd {n}");
                    installed.push(n);
                }

                let whole = cmsg::build_rights(&installed);
                let write_len = whole.len().min(hdr.controllen as usize);
                if whole.len() > write_len {
                    ctrunc = true;
                }
                if write_len > 0 && GuestMem.write(hdr.control, &whole[..write_len]) != 0 {
                    return Err(Errno::EFAULT);
                }
                wrote_controllen = write_len as u32;
            }
        }
    }

    if res < 0 {
        // Set on every path that answers -1, which is the only way `res` is
        // negative -- the host's own count is never below that.
        return Err(err.unwrap_or(Errno::EIO));
    }

    // An internet socket's control messages, in Linux's terms; see
    // `crate::ancillary`. Written as far as the guest has room, and truncation
    // reported, as Linux's `put_cmsg` does.
    if !sock.is_unix()
        && hdr.controllen != 0
        && let Some(got) = &got
    {
        let v6 = (sock.domain() == guest::PF_INET6).then(|| sock.state().v6_wants());
        let whole = crate::ancillary::to_guest(&got.control, v6);
        let write_len = whole.len().min(hdr.controllen as usize);
        ctrunc |= whole.len() > write_len;
        if write_len > 0 && GuestMem.write(hdr.control, &whole[..write_len]) != 0 {
            return Err(Errno::EFAULT);
        }
        wrote_controllen = write_len as u32;
    }

    // msg_name. Only when the guest gave a buffer *and* the host put an address
    // in it: `msg_namelen` was written unconditionally, so a receive on a
    // connected socket -- which never has a peer address to report -- overwrote
    // whatever the guest had left in the field. Linux touches it only through
    // move_addr_to_user, which is not reached when msg_name is null.
    let mut wrote_namelen = 0u32;
    if sock.is_netlink() && hdr.name != 0 {
        // The sender is this kernel, and a netlink reader checks that: busybox
        // `ip` refuses anything whose `msg_namelen` is not a `sockaddr_nl`'s
        // twelve with "sender address length == 2" -- two being the unnamed
        // unix end the pair underneath reports. `sendto`'s side of this is the
        // same answer; `ip` uses `recvmsg` and Go uses `recvfrom`, so a route
        // through only one of them works for one of the two.
        let mut nl = [0u8; 12];
        nl[..2].copy_from_slice(&(guest::PF_NETLINK as u16).to_le_bytes());
        let copy = (guest_namelen as usize).min(nl.len());
        if copy > 0 && GuestMem.write(hdr.name, &nl[..copy]) != 0 {
            return Err(Errno::EFAULT);
        }
        wrote_namelen = nl.len() as u32;
    } else if let Some(got) = &got
        && hdr.name != 0
        && !got.name.as_slice().is_empty()
    {
        // Bounded by what the guest has room for. The translation copies
        // the smaller of that and the address's real length, and reports
        // the real one whether or not it all fitted -- which is what
        // Linux's move_addr_to_user does.
        wrote_namelen = write_host_addr(hdr.name, got.name.as_slice(), guest_namelen)?;
    }

    // msg_flags. Masked to the four bits that are a *report* about this
    // message, because Darwin echoes the input flags back here: a
    // recvmsg(MSG_DONTWAIT) came back with msg_flags == MSG_DONTWAIT, and a
    // guest reading that as "something happened" found something on every
    // ordinary receive. The truncation this call found is put back afterwards:
    // written the other way round, the host's flags overwrote MSG_CTRUNC and
    // the guest was told a control message was complete when descriptors had
    // been dropped from it.
    // The host's MSG_CTRUNC is about the host's buffer, not the guest's; this
    // call decided the guest's truncation above.
    let host_flags = got.as_ref().map_or(0, |g| g.flags & !libc::MSG_CTRUNC);
    let mut out_flags = msghdr::recv_flags(sockabi::flags_from_real(host_flags).real);
    if ctrunc {
        out_flags |= msghdr::MSG_CTRUNC;
    }

    // The three fields this call owns, each at its offset, rather than reading
    // the header again and putting it back whole.
    if hdr.name != 0 {
        put_u32(msghdr_addr + msghdr::NAMELEN_OFFSET, wrote_namelen)?;
    }
    put_u32(msghdr_addr + msghdr::CONTROLLEN_OFFSET, wrote_controllen)?;
    put_u32(msghdr_addr + msghdr::FLAGS_OFFSET, out_flags as u32)?;
    Ok(res as i64)
}

/// `MSG_CMSG_CLOEXEC`, from the guest's `sys/socket.h`.
const MSG_CMSG_CLOEXEC: c_int = 0x4000_0000;
/// The guest's `O_CLOEXEC`. 0o2000000 on aarch64.
const O_CLOEXEC_GUEST: c_int = 0o2000000;

/// Everything this endpoint is still holding, on the way out.
///
/// What it never received, and what it sent to a connection nobody accepted;
/// nothing will collect either now. Called from `sock_close` before the
/// endpoint goes, because an `Scm` holds retained descriptors.
///
/// # Safety
///
/// Called once per socket, from its close path.
pub(crate) fn sock_rs_drain_scm(handle: u64) {
    // Each one drops as the loop goes round, which is what releases its
    // descriptors -- it was `scm_free` on a raw pointer until 2026-09-16.
    while unixpeer::with_table(|t| t.drain_one(handle)).is_some() {}
}

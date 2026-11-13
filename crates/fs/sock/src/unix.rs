//! Guest UNIX address resolution and host socket path handling.

use std::ffi::{c_char, c_int, c_uint};

use strace::strace;
use usercopy::GuestMem;

use crate::state::Names;
use crate::{Errno, SOCKADDR_MAX, Sock, ffi};

/// `bind(fd, {AF_UNIX}, 2)` on a socket that already has a name.
///
/// **Zero, and nothing changes.** Linux's `unix_autobind` takes the socket's
/// `bindlock`, sees `u->addr` and jumps to a label that returns `err`, which is
/// still 0 — where every *other* second bind is `EINVAL`. Reading the function
/// is how the first attempt at this got it wrong; `sock_probe` measured it.
///
/// A separate two-byte read rather than a third outcome threaded through
/// [`read_addr_for`]'s return type, which two other callers share and neither
/// can produce.
pub(crate) fn autobind_on_named_socket(sock: &Sock<'_>, addr: u64, len: u32) -> bool {
    // `offsetof(struct sockaddr_un, sun_path)`: the family and nothing else,
    // which is the whole of an autobind address.
    if len != 2 || !sock.names().any() {
        return false;
    }
    let mut family = [0u8; 2];
    if GuestMem.read(addr, &mut family) != 0 {
        // Not this case. `read_addr_for` reads the same bytes and answers
        // `EFAULT` for them, which is the right answer and is not this one.
        return false;
    }
    let guest_family = u16::from_le_bytes(family) as c_int;
    sockabi::family_to_real(guest_family) == libc::PF_LOCAL
}

/// The socket id a filesystem path names, creating the node for a `bind`.
///
/// A unix socket bound to a path is a real inode with `S_IFSOCK`, and the id on
/// that inode is what the two ends find each other by. The host socket lives
/// somewhere else entirely — `/tmp/iulsock<pid>.<id>` — so the guest's path and
/// the host's path have nothing to do with each other.
///
/// `binding` is the bound socket's address **under its lock**, or `None` for a
/// lookup. A bind creates the node; a lookup only finds it. Taking the guard
/// rather than the socket is what says the caller holds it across the `mknod`.
fn unix_socket_id(
    path_raw: &[u8],
    binding: Option<&Names>,
) -> Result<(u32, fs_inode::Ref), Errno> {
    if path_raw.len() >= ffi::MAX_PATH as usize {
        return Err(Errno::ENAMETOOLONG);
    }
    // Up to the first NUL, which is where the C string this was copied into
    // ended.
    let name = path_raw.split(|&b| b == 0).next().unwrap_or_default();
    let resolved =
        fs_generic::normalize::resolve(ffi::At::Pwd, name, ffi::N_SYMLINK_FOLLOW as c_int)
            .map_err(Errno::from_negative_or_eio)?;
    // Terminated, because `find_mount_and_trim_path` trims it in place as a C
    // string.
    let mut path = resolved.path;
    path.push(0);

    // Held for the rest of the function and released by its own drop. It was
    // six explicit `release(mount)` calls on six paths until 2026-09-12, all
    // six correct — a seventh return would not have been.
    let mount_ref = fs_mounttable::find_mount_and_trim_path(&mut path);
    // The trim only moves the contents down, so the buffer still holds a C
    // string -- and `FsOps` takes one as a `&CStr` since 2026-09-14. No
    // `unsafe`: the array is zeroed above and `path_normalize` is bounded by
    // its length.
    let path_c = std::ffi::CStr::from_bytes_until_nul(&path).unwrap_or(c"");
    let mount: &ffi::mount = &mount_ref;
    let fs = mount.fs;
    // `EPERM` for a filesystem that cannot stat, which is this caller's
    // reading of the trait's `None`.
    let stat_it = || {
        fs.and_then(|fs| fs.stat(mount, path_c))
            .unwrap_or(Err(Errno::EPERM.as_c_int()))
    };
    let mut answer = stat_it();

    if let Some(names) = binding {
        // A bind has funny semantics: the name must not already exist, and if
        // it does not, this is what creates it.
        if answer.is_ok() {
            return Err(Errno::EADDRINUSE);
        }
        // Only now: a socket may be bound once, and in **this** namespace the
        // order is the other way round from the abstract one. Linux's
        // `unix_bind_bsd` resolves the path first and maps the `EEXIST` from
        // one that is already there to `EADDRINUSE`, and only then takes the
        // socket's `bindlock` and refuses an already-bound socket with
        // `EINVAL`. So a second bind to a *taken* path is `EADDRINUSE` and to
        // a *free* one is `EINVAL`, which is what `sock_probe` measures.
        //
        // Linux creates the node and unlinks it again on that path; refusing
        // here is the same answer with nothing to undo. The node used to be
        // left behind, because the refusal came from the *host* bind after
        // this function had already created it.
        if names.any() {
            return Err(Errno::EINVAL);
        }
        let mode: c_uint = taskview::with_current_fs(|fs| fs.apply_umask(0o777)).unwrap_or(0o777);
        let made = match fs {
            None => Errno::EPERM.as_c_int(),
            Some(fs) => fs.mknod(mount, path_c, (0o140000 | mode) as u16, 0), // S_IFSOCK
        };
        if made < 0 {
            return Err(Errno::from_negative_or_eio(made));
        }
        answer = stat_it();
    }
    let st = answer.map_err(Errno::from_negative_or_eio)?;
    // S_IFSOCK: a name that is not a socket cannot be one end of one.
    if st.mode & 0o170000 != 0o140000 {
        return Err(Errno::ENOTSOCK);
    }

    // The reference comes back with the id, and a lookup's is dropped on the
    // way out of this function -- which is what a null `keep` out-parameter
    // used to ask for.
    //
    // This was `mount.cast()`, with a comment saying `fs_inode` renders
    // `mount` as its own type. It does not and never did: that crate is
    // `pub use taskview::ffi;`, the same re-export this one reads, so the cast
    // was between a type and itself. A redundant `.cast()` out of a pointer
    // reads exactly like a necessary one, which is why it survived a comment
    // being written about it -- and taking a `&mount` is what made the
    // compiler say so.
    let (id, held) = fs_inode::unix_socket_id(mount, st.inode);
    Ok((id, held))
}

/// Reads the guest's address into a host one.
///
/// One buffer, read as the guest's shape and written back as the host's. They
/// agree on everything but the first two bytes, and how they disagree is worth
/// writing down because it works on both hosts for *different* reasons — so a
/// migration that "cleans it up" can break one of them without failing a test
/// on the other.
///
/// The guest's family is a 16-bit field at offset 0. Linux's `struct sockaddr`
/// is the same, so writing the family writes both bytes and there is nothing
/// more to say. Darwin's is `{ uint8_t sa_len; sa_family_t sa_family; }`, so it
/// writes byte *1* and leaves byte 0 holding the low byte of whatever family
/// the guest asked for — a `sa_len` of 2 for `AF_INET`. That does not matter
/// because XNU's `sockargs()` overwrites `sa_len` with the addrlen the syscall
/// was given, and the reverse direction cancels out the same way.
///
/// `bind_sock` is the socket being bound, or `None` for every other caller. A
/// bind is the only one that may create a name, autobind an unnamed address, or
/// record what it bound.
/// What an address is being read for. A `bind` records the name on the
/// socket and may autobind; a `connect` records who the peer will be; a send
/// does neither.
#[derive(Clone, Copy)]
pub(crate) enum AddrFor<'a> {
    Bind(&'a Sock<'a>),
    Connect(&'a Sock<'a>),
    Other,
}

impl<'a> AddrFor<'a> {
    fn bind_sock(self) -> Option<&'a Sock<'a>> {
        match self {
            AddrFor::Bind(sock) => Some(sock),
            _ => None,
        }
    }
}

pub(crate) fn read_addr_for(
    addr: u64,
    len: u32,
    purpose: AddrFor<'_>,
) -> Result<(Vec<u8>, u32), Errno> {
    let bind_sock = purpose.bind_sock();
    // The length rules are `crates/fs/sockaddr`. The bound here is what makes
    // the read safe; the per-family minimum comes after the family is known.
    if (len as usize) < 2 || len as usize > SOCKADDR_MAX {
        return Err(Errno::EINVAL);
    }
    let mut buf = vec![0u8; SOCKADDR_MAX.max(std::mem::size_of::<libc::sockaddr_un>())];
    if GuestMem.read(addr, &mut buf[..len as usize]) != 0 {
        return Err(Errno::EFAULT);
    }
    let guest_family = u16::from_le_bytes([buf[0], buf[1]]) as c_int;
    let real_family = sockabi::family_to_real(guest_family);
    if real_family == sockabi::NONE {
        return Err(Errno::EINVAL);
    }

    // An address of one family handed to a socket of another. Linux checks this
    // per family and answers *different* errnos: `unix_validate_addr` refuses
    // anything but `AF_UNIX` with `EINVAL`, and `__inet_bind` refuses anything
    // but `AF_INET` with `EAFNOSUPPORT`. Nothing checked it here, so the
    // address went to the host `bind` and the answer was whatever Darwin made
    // of it — `EAFNOSUPPORT` for the unix case, where Linux says `EINVAL`.
    // Measured by `tests/guest/src/bin/sock_probe.rs`.
    if let Some(sock) = bind_sock {
        let sock_family = sockabi::family_to_real(sock.domain());
        if sock_family != sockabi::NONE && real_family != sock_family {
            return Err(if sock_family == libc::PF_LOCAL {
                Errno::EINVAL
            } else {
                Errno::EAFNOSUPPORT
            });
        }
    }

    match real_family {
        libc::PF_INET | libc::PF_INET6 => {
            // Two different questions. What the guest may pass is a *minimum*,
            // and for IPv6 it is SIN6_LEN_RFC2133 (24) rather than the struct
            // (28) -- an address with no scope id, which inet6_bind accepts and
            // this used to refuse. What the *host* wants is exactly the struct:
            // Darwin's in_pcbbind checks `sa_len != sizeof`, and XNU sets
            // sa_len from the length passed. So the address is checked against
            // the minimum and then normalised to the size, with whatever was
            // added zeroed.
            let which = if real_family == libc::PF_INET {
                sockaddr::Family::Inet
            } else {
                sockaddr::Family::Inet6
            };
            sockaddr::check_len(which, len as usize).map_err(Errno::from_negative_or_eio)?;
            let want = sockaddr::host_len(which).unwrap_or(len as usize);
            write_family(&mut buf, real_family);
            buf.truncate(want.max(len as usize));
            buf.resize(want, 0);
            Ok((buf, want as u32))
        }
        libc::PF_LOCAL => read_unix_addr(&buf, len, purpose),
        _ => Err(Errno::EINVAL),
    }
}

/// Writes the host's family into an address. See [`read_addr_for`] for why
/// this is not simply a `u16` store.
fn write_family(buf: &mut [u8], family: c_int) {
    crate::host::set_family(buf, family);
}

fn read_unix_addr(
    buf: &[u8],
    len: u32,
    purpose: AddrFor<'_>,
) -> Result<(Vec<u8>, u32), Errno> {
    let bind_sock = purpose.bind_sock();
    // The socket's address, locked for the whole claim below.
    //
    // This is what makes "has it got a name already?" and "take this one" a
    // single operation, which they have to be: two threads that both find it
    // empty both claim, the loser's claim is stored over the winner's, and the
    // winner's name is then never released — 13 to 25 leaked names per 400
    // rounds, measured. Linux's `unix_sock::bindlock`, which it holds across
    // the same span for the same reason.
    //
    // Held across the VFS walk and the `mknod` in the path arm, because that is
    // what makes a refused bind create nothing. Nothing below here — the VFS,
    // `crates/fs/unixname`, `crates/fs/unixpeer` — knows sockets exist, so
    // there is no way back to this lock from inside any of them.
    let mut names = bind_sock.map(|sock| sock.names());
    let path = &buf[2..len as usize];
    let mut recorded: Vec<u8> = path.to_vec();

    let id = match sockaddr::unix_name(path) {
        sockaddr::Unix::Unnamed => {
            // The family and nothing else, which the two callers read
            // differently. For bind it is an *autobind*: Linux picks an unused
            // abstract name and the socket has an address it did not have to
            // choose. For anything else `unix_validate_addr` rejects the
            // length, because only `unix_bind` special-cases it before that
            // check. Both were ENOENT, which names a remedy neither caller has
            // -- there is nothing to create.
            let Some(names) = names.as_mut() else {
                return Err(Errno::EINVAL);
            };
            // A socket that already has one never reaches here: `sys_bind`
            // answers 0 for that, which is what `unix_autobind` does. See
            // [`autobind_on_named_socket`].
            let (claim, name, id) =
                unixname::autobind().map_err(Errno::from_negative_or_eio)?;
            strace!(" unix autobind {:?}", String::from_utf8_lossy(&name[1..]));
            // The name goes back so the recording below reports it from
            // getsockname, as Linux does.
            recorded = name;
            names.abstract_ = Some(claim);
            id
        }
        sockaddr::Unix::Path(bytes) => {
            strace!(" unix socket {:?}", String::from_utf8_lossy(bytes));
            // The path stops at its NUL: a `sockaddr_un` is a fixed buffer and
            // everything after the terminator is padding.
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            let (id, held) = unix_socket_id(&bytes[..end], names.as_deref())?;
            if let Some(names) = names.as_mut() {
                // The inode stays alive while there is a listener, and the
                // descriptor's close is what drops it. A lookup's `held` falls
                // out of scope here, which is the release.
                names.inode = Some(held);
            }
            id
        }
        sockaddr::Unix::Abstract(name) => {
            // The bytes after the leading NUL, and their length: an abstract
            // name is whatever the guest passed there, NULs and all.
            strace!(" unix abstract socket {:?}", String::from_utf8_lossy(name));
            match names.as_mut() {
                None => unixname::lookup(name).map_err(Errno::from_negative_or_eio)?,
                Some(names) => {
                    // A socket may be bound once, and in this namespace the
                    // refusal comes **before** the name is looked at:
                    // `unix_bind_abstract` takes the socket's `bindlock` and
                    // tests `u->addr` first, so a second bind is `EINVAL` even
                    // when the name it asks for is one another socket holds.
                    // Measured; the emulator answered `EADDRINUSE` for that
                    // case, which is the filesystem namespace's rule.
                    //
                    // And it has to be *before* the claim: this used to take
                    // the name and then store it over whatever the socket
                    // already held, so the old name was never released and
                    // stayed claimed for the life of the process.
                    if names.any() {
                        return Err(Errno::EINVAL);
                    }
                    let (claim, id) =
                        unixname::bind(name).map_err(Errno::from_negative_or_eio)?;
                    names.abstract_ = Some(claim);
                    id
                }
            }
        }
    };

    // Linux records the length of the *name*, not the length the caller
    // passed: `unix_bind_bsd` uses `strlen(sun_path) + offsetof + 1`. Almost
    // everything passes `sizeof(struct sockaddr_un)`, so recording that made
    // getsockname report 110 for a socket bound to /tmp/x.sock where Linux
    // reports 16 -- and the C idiom `path[len - offsetof] = '\0'` then
    // writes one byte past a 108-byte sun_path in the *guest*.
    let name_len = sockaddr::recorded_name_len(&recorded);
    match purpose {
        AddrFor::Bind(sock) => unixpeer::with_table(|t| {
            t.set_name(sock.peer(), &recorded[..name_len]);
            // And the socket id the name resolves to, which is how a client
            // connecting to it finds this endpoint.
            t.set_socket_id(sock.peer(), id as u64);
        }),
        // Who the peer will be, before anyone accepts: the listener's
        // credentials and the address connected to, as Linux copies onto the
        // client in `unix_stream_connect`. A client asking SO_PEERCRED or
        // getpeername before the accept used to be told nobody.
        AddrFor::Connect(sock) => unixpeer::with_table(|t| {
            t.expect_peer(sock.peer(), id as u64, &recorded[..name_len]);
        }),
        AddrFor::Other => {}
    }

    // The host address, which has nothing to do with the guest's: the socket
    // itself lives in /tmp.
    // Built as bytes in the host's own layout: the family where the host's
    // `sockaddr` has it, the path at `sun_path`'s offset, NUL-terminated by
    // the zeroes after it.
    const SUN_PATH_AT: usize = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    const SUN_PATH_LEN: usize = size_of::<libc::sockaddr_un>() - SUN_PATH_AT;
    let host = format!("{}{}.{}", tmp_prefix(), std::process::id(), id);
    if host.len() >= SUN_PATH_LEN {
        return Err(Errno::ENAMETOOLONG);
    }
    let mut bytes = vec![0u8; size_of::<libc::sockaddr_un>()];
    write_family(&mut bytes, libc::AF_UNIX);
    bytes[SUN_PATH_AT..SUN_PATH_AT + host.len()].copy_from_slice(host.as_bytes());
    if bind_sock.is_some() {
        // The real bind fails if the backing socket is left over from a
        // previous run. The guest-side name was just checked not to exist.
        let _ = std::fs::remove_file(&host);
    }
    Ok((bytes, (SUN_PATH_AT + host.len()) as u32))
}

/// Where the host sockets live.
///
/// A guest unix socket bound to a path is an inode in the guest tree with
/// `S_IFSOCK`; the *host* socket that actually carries the bytes is here, named
/// by pid and socket id. The two have nothing to do with each other, which is
/// why a guest can bind anywhere it has permission to.
///
/// An embedder points it at a directory of its own with
/// [`set_socket_prefix`] -- a writable `static mut` C string, `sock_tmp_prefix`,
/// until 2026-10-17. `sun_path` holds 104 bytes and the name below is checked
/// against that, which is what stops a long prefix from silently truncating.
static TMP_PREFIX: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Where the host sockets behind guest unix sockets are made; `None` restores
/// `/tmp/iulsock`.
pub fn set_socket_prefix(prefix: Option<&str>) {
    *TMP_PREFIX.write().unwrap_or_else(|e| e.into_inner()) = prefix.map(str::to_owned);
}

/// The C spelling of [`set_socket_prefix`], copied; null restores the default.
///
/// # Safety
/// `prefix` is null or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iul_set_socket_prefix(prefix: *const c_char) {
    // SAFETY: the caller's contract.
    let p = (!prefix.is_null()).then(|| unsafe { std::ffi::CStr::from_ptr(prefix) }.to_string_lossy());
    set_socket_prefix(p.as_deref());
}

fn tmp_prefix() -> String {
    TMP_PREFIX
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_else(|| "/tmp/iulsock".into())
}

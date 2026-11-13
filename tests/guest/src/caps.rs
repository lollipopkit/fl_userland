//! What the capability tests share: the sets through `capget`/`capset`, a
//! child that brings its answer back, and an exec that reports the sets the
//! new image starts with.

use std::ffi::CString;

pub const SETUID: u32 = 7;

pub const V3: u32 = 0x2008_0522;
pub const FULL: u64 = (1 << 41) - 1;
pub const CHOWN: u32 = 0;
pub const DAC_OVERRIDE: u32 = 1;
pub const DAC_READ_SEARCH: u32 = 2;
pub const KILL: u32 = 5;
pub const SETPCAP: u32 = 8;
pub const NET_BIND_SERVICE: u32 = 10;
pub const IPC_LOCK: u32 = 14;
pub const SYS_CHROOT: u32 = 18;
pub const SYS_PTRACE: u32 = 19;
pub const SYS_ADMIN: u32 = 21;
pub const SYS_NICE: u32 = 23;
pub const MKNOD: u32 = 27;
pub const SETFCAP: u32 = 31;
pub const X: u64 = 1 << NET_BIND_SERVICE;

pub fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

pub fn errno() -> i64 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64
}

/// 0, or the negative errno.
pub fn r(v: i64) -> i64 {
    if v < 0 { -errno() } else { 0 }
}

#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct Sets {
    pub e: u64,
    pub p: u64,
    pub i: u64,
}

pub fn capget(pid: i32) -> Sets {
    let mut h = [V3, pid as u32];
    let mut d = [0u32; 6];
    unsafe { libc::syscall(libc::SYS_capget, h.as_mut_ptr(), d.as_mut_ptr()) };
    let w = |n: usize| d[n] as u64 | (d[n + 3] as u64) << 32;
    Sets { e: w(0), p: w(1), i: w(2) }
}

pub fn capset(s: Sets) -> i64 {
    let mut h = [V3, 0];
    let d = [s.e as u32, s.p as u32, s.i as u32, (s.e >> 32) as u32, (s.p >> 32) as u32, (s.i >> 32) as u32];
    r(unsafe { libc::syscall(libc::SYS_capset, h.as_mut_ptr(), d.as_ptr()) })
}

pub fn bit(cap: u32) -> u64 {
    1 << cap
}

pub fn without(caps: &[u32]) {
    let mut s = capget(0);
    for &cap in caps {
        s.e &= !bit(cap);
    }
    capset(s);
}

pub fn prctl(op: i32, a2: u64, a3: u64) -> i64 {
    let v = unsafe { libc::prctl(op, a2, a3, 0, 0) } as i64;
    if v < 0 { -errno() } else { v }
}

pub fn ambient() -> u64 {
    (0..41).filter(|&cap| prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET as u64, cap) == 1).fold(0, |a, cap| a | 1 << cap)
}

pub fn set_inheritable(i: u64) {
    capset(Sets { i, ..capget(0) });
}

pub fn setresuid(id: u32) -> i64 {
    r(unsafe { libc::syscall(libc::SYS_setresuid, id, id, id) })
}

/// Run `f` in a child and bring back what it answers.
pub fn child<const N: usize>(f: impl FnOnce() -> [i64; N]) -> [i64; N] {
    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let out = f();
        unsafe {
            libc::write(p[1], out.as_ptr().cast(), N * 8);
            libc::_exit(0);
        }
    }
    let mut out = [i64::MIN; N];
    unsafe {
        libc::close(p[1]);
        libc::read(p[0], out.as_mut_ptr().cast(), N * 8);
        libc::close(p[0]);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
    out
}

pub fn one(f: impl FnOnce() -> i64) -> i64 {
    child(|| [f()])[0]
}

// ----------------------------------------------------------------- exec

/// What a test re-executed as `<itself> report` writes to descriptor 3: e, p, i, ambient,
/// AT_SECURE, euid.
pub fn report() {
    let s = capget(0);
    let out = [s.e, s.p, s.i, ambient(), unsafe { libc::getauxval(libc::AT_SECURE) }, unsafe { libc::geteuid() } as u64];
    unsafe { libc::write(3, out.as_ptr().cast(), out.len() * 8) };
}

/// Exec `path` after `setup`, in a child: the new image's sets, or the
/// errno of the exec in the first slot.
pub fn exec_as(path: &str, setup: impl FnOnce()) -> [i64; 6] {
    child(|| unsafe {
        let mut p = [0i32; 2];
        libc::pipe(p.as_mut_ptr());
        let pid = libc::fork();
        if pid == 0 {
            setup();
            libc::dup2(p[1], 3);
            let path = c(path);
            let argv = [path.as_ptr(), c"report".as_ptr(), std::ptr::null()];
            libc::execv(path.as_ptr(), argv.as_ptr());
            let e = [-errno(); 6];
            libc::write(3, e.as_ptr().cast(), 48);
            libc::_exit(0);
        }
        libc::close(p[1]);
        let mut out = [i64::MIN; 6];
        libc::read(p[0], out.as_mut_ptr().cast(), 48);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
        out
    })
}

pub fn copy_self(to: &str) {
    let bytes = std::fs::read("/proc/self/exe").unwrap();
    let _ = std::fs::remove_file(to);
    std::fs::write(to, bytes).unwrap();
    unsafe { libc::chmod(c(to).as_ptr(), 0o755) };
}

pub fn vfs_cap(eff: bool, p: u32, rootid: Option<u32>) -> Vec<u8> {
    let rev: u32 = if rootid.is_some() { 0x0300_0000 } else { 0x0200_0000 };
    let mut v = Vec::new();
    for w in [rev | eff as u32, p, 0, 0, 0] {
        v.extend_from_slice(&w.to_le_bytes());
    }
    if let Some(r) = rootid {
        v.extend_from_slice(&r.to_le_bytes());
    }
    v
}

pub fn setcap(path: &str, value: &[u8]) -> i64 {
    r(unsafe {
        libc::setxattr(c(path).as_ptr(), c"security.capability".as_ptr(), value.as_ptr().cast(), value.len(), 0)
    } as i64)
}

pub fn getcap_len(path: &str) -> i64 {
    let mut b = [0u8; 64];
    let n = unsafe { libc::getxattr(c(path).as_ptr(), c"security.capability".as_ptr(), b.as_mut_ptr().cast(), 64) };
    if n < 0 { -errno() } else { n as i64 }
}

pub fn owner_of(path: &str) -> u32 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::stat(c(path).as_ptr(), &mut st) };
    st.st_uid
}

pub fn mode_of(path: &str) -> u32 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::stat(c(path).as_ptr(), &mut st) };
    st.st_mode & 0o7777
}

/// The type `/proc/self/mounts` gives `/`.
pub fn root_mount_is(ty: &str) -> bool {
    std::fs::read_to_string("/proc/self/mounts")
        .unwrap_or_default()
        .lines()
        .any(|l| l.split(' ').nth(1) == Some("/") && l.split(' ').nth(2) == Some(ty))
}


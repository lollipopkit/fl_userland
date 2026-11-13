//! What the System V shared memory calls answer.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! `shmget`, `shmat`, `shmdt` and `shmctl` were stubs until 2026-09-04, and
//! PostgreSQL will not start without them. The cases are the key and flag
//! rules, what `IPC_STAT` reports, the attach address rules, the two ways a
//! segment goes (`IPC_RMID` with and without attaches), that a mapping is one
//! set of pages for two processes, and every errno the man page names.
//!
//! Every segment made here is removed, in a child where a case leaves it
//! attached, so a second run in the same kernel sees the same table.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<60} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EINVAL => "EINVAL",
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::EEXIST => "EEXIST",
        libc::ENOENT => "ENOENT",
        libc::EIDRM => "EIDRM",
        libc::EFAULT => "EFAULT",
        libc::ENOMEM => "ENOMEM",
        libc::ENOSPC => "ENOSPC",
        libc::ENOSYS => "ENOSYS",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

const KEY: i32 = 0x5348_0001;
// Not in the libc crate for this target.
const SHM_STAT: i32 = 13;
const SHM_INFO: i32 = 14;

fn shmget(key: i32, size: usize, flags: i32) -> Result<i32, i32> {
    let r = unsafe { libc::shmget(key, size, flags) };
    if r < 0 { Err(errno()) } else { Ok(r) }
}

fn get_line(what: &str, key: i32, size: usize, flags: i32) -> Option<i32> {
    match shmget(key, size, flags) {
        Ok(id) => {
            line(what, "ok");
            Some(id)
        }
        Err(e) => {
            line(what, named(e));
            None
        }
    }
}

fn shmat(id: i32, addr: usize, flags: i32) -> Result<*mut u8, i32> {
    let p = unsafe { libc::shmat(id, addr as *const libc::c_void, flags) };
    if p as isize == -1 { Err(errno()) } else { Ok(p.cast()) }
}

fn at_line(what: &str, id: i32, addr: usize, flags: i32) -> Option<*mut u8> {
    match shmat(id, addr, flags) {
        Ok(p) => {
            line(what, "ok");
            Some(p)
        }
        Err(e) => {
            line(what, named(e));
            None
        }
    }
}

fn result(r: i64) -> String {
    if r < 0 { named(errno()) } else if r == 0 { "ok".to_string() } else { r.to_string() }
}

fn shmdt(p: *mut u8) -> String {
    result(unsafe { libc::shmdt(p.cast()) } as i64)
}

fn rmid(id: i32) -> String {
    result(unsafe { libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()) } as i64)
}

fn stat(id: i32) -> Result<libc::shmid_ds, i32> {
    let mut ds = std::mem::MaybeUninit::<libc::shmid_ds>::uninit();
    let r = unsafe { libc::shmctl(id, libc::IPC_STAT, ds.as_mut_ptr()) };
    if r < 0 { Err(errno()) } else { Ok(unsafe { ds.assume_init() }) }
}

fn nattch(id: i32) -> String {
    match stat(id) {
        Ok(ds) => ds.shm_nattch.to_string(),
        Err(e) => named(e),
    }
}

/// The permissions and the name of the `/proc/self/maps` line that starts at
/// `p`; the address, offset, device and inode are left out.
fn maps_name(p: *mut u8) -> String {
    let start = format!("{:08x}-", p as usize);
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    match maps.lines().find(|l| l.starts_with(&start)) {
        Some(l) => {
            let f: Vec<&str> = l.split_whitespace().collect();
            format!("{} {}", f.get(1).unwrap_or(&""), f.get(5..).map(|n| n.join(" ")).unwrap_or_default())
        }
        None => "no line".into(),
    }
}

fn in_child(f: impl FnOnce()) {
    let _ = std::io::stdout().flush();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
}

fn main() {
    // Leftovers from a run that died.
    if let Ok(id) = shmget(KEY, 0, 0) {
        unsafe { libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
    }

    println!("## shmget");
    let id = get_line("shmget(KEY, 4096, IPC_CREAT|IPC_EXCL|0600)", KEY, 4096, libc::IPC_CREAT | libc::IPC_EXCL | 0o600);
    line("the same again", shmget(KEY, 4096, libc::IPC_CREAT | libc::IPC_EXCL | 0o600).map(|_| "ok".into()).unwrap_or_else(named));
    line("without IPC_EXCL", shmget(KEY, 4096, libc::IPC_CREAT | 0o600).map(|got| (Some(got) == id).to_string()).unwrap_or_else(named));
    line("without IPC_CREAT", shmget(KEY, 4096, 0o600).map(|got| (Some(got) == id).to_string()).unwrap_or_else(named));
    line("asking for size 0 of it", shmget(KEY, 0, 0).map(|got| (Some(got) == id).to_string()).unwrap_or_else(named));
    line("asking for more than it holds", shmget(KEY, 4097, 0).map(|_| "ok".into()).unwrap_or_else(named));
    line("asking for more with IPC_CREAT", shmget(KEY, 8192, libc::IPC_CREAT).map(|_| "ok".into()).unwrap_or_else(named));
    line("a key nobody made, no IPC_CREAT", shmget(KEY + 1, 4096, 0o600).map(|_| "ok".into()).unwrap_or_else(named));
    line("IPC_PRIVATE, size 0", shmget(libc::IPC_PRIVATE, 0, libc::IPC_CREAT | 0o600).map(|_| "ok".into()).unwrap_or_else(named));
    line("IPC_PRIVATE, size 1", {
        match shmget(libc::IPC_PRIVATE, 1, libc::IPC_CREAT | 0o600) {
            Ok(i) => {
                let sz = stat(i).map(|d| d.shm_segsz.to_string()).unwrap_or_else(named);
                rmid(i);
                format!("ok, segsz {sz}")
            }
            Err(e) => named(e),
        }
    });
    line("IPC_PRIVATE twice is two segments", {
        match (shmget(libc::IPC_PRIVATE, 4096, 0o600), shmget(libc::IPC_PRIVATE, 4096, 0o600)) {
            (Ok(a), Ok(b)) => {
                let r = (a != b).to_string();
                rmid(a);
                rmid(b);
                r
            }
            _ => "failed".into(),
        }
    });
    line("IPC_PRIVATE without IPC_CREAT", shmget(libc::IPC_PRIVATE, 4096, 0o600).map(|i| { rmid(i); "ok".into() }).unwrap_or_else(named));
    line("size 2^62", shmget(libc::IPC_PRIVATE, 1usize << 62, libc::IPC_CREAT | 0o600).map(|i| { rmid(i); "ok".into() }).unwrap_or_else(named));
    line("size usize::MAX", shmget(libc::IPC_PRIVATE, usize::MAX, libc::IPC_CREAT | 0o600).map(|i| { rmid(i); "ok".into() }).unwrap_or_else(named));
    line("SHM_HUGETLB", shmget(libc::IPC_PRIVATE, 4096, libc::IPC_CREAT | libc::SHM_HUGETLB | 0o600).map(|i| { rmid(i); "ok".into() }).unwrap_or_else(named));

    println!("## what IPC_STAT reports");
    if let Some(id) = id {
        match stat(id) {
            Ok(ds) => {
                // `libc` has deprecated the field's name, not the field: it
                // says it will become `__key`, which is Linux's spelling.
                #[allow(deprecated)]
                let key = ds.shm_perm.__ipc_perm_key;
                line("  shm_perm.__key", (key == KEY).to_string());
                line("  shm_perm.mode", format!("{:o}", ds.shm_perm.mode));
                line("  shm_perm.uid == getuid", (ds.shm_perm.uid == unsafe { libc::getuid() }).to_string());
                line("  shm_perm.cuid == uid", (ds.shm_perm.cuid == ds.shm_perm.uid).to_string());
                line("  shm_segsz", ds.shm_segsz.to_string());
                line("  shm_nattch", ds.shm_nattch.to_string());
                line("  shm_cpid == getpid", (ds.shm_cpid == unsafe { libc::getpid() }).to_string());
                line("  shm_lpid", ds.shm_lpid.to_string());
                line("  shm_atime", ds.shm_atime.to_string());
                line("  shm_dtime", ds.shm_dtime.to_string());
                line("  shm_ctime is recent", (ds.shm_ctime > 1_600_000_000).to_string());
            }
            Err(e) => line("  IPC_STAT", named(e)),
        }
        line("IPC_STAT into NULL", result(unsafe { libc::shmctl(id, libc::IPC_STAT, std::ptr::null_mut()) } as i64));
        line("IPC_STAT of id + 1", stat(id + 1).map(|_| "ok".into()).unwrap_or_else(named));
        line("IPC_STAT of -1", stat(-1).map(|_| "ok".into()).unwrap_or_else(named));
        line("shmctl(99) an unknown command", result(unsafe { libc::shmctl(id, 99, std::ptr::null_mut()) } as i64));
        line("SHM_STAT of index 0 answers an id", {
            let mut ds = std::mem::MaybeUninit::<libc::shmid_ds>::uninit();
            let r = unsafe { libc::shmctl(0, SHM_STAT, ds.as_mut_ptr()) };
            if r < 0 { named(errno()) } else { (r >= 0).to_string() }
        });
        line("SHM_STAT of index 4096", {
            let mut ds = std::mem::MaybeUninit::<libc::shmid_ds>::uninit();
            result(unsafe { libc::shmctl(4096, SHM_STAT, ds.as_mut_ptr()) } as i64)
        });
        line("IPC_INFO", {
            let mut info = [0u64; 9];
            let r = unsafe { libc::shmctl(0, libc::IPC_INFO, info.as_mut_ptr().cast()) };
            if r < 0 { named(errno()) } else { format!("shmmin {} shmmni {} shmseg {}", info[1], info[2], info[3]) }
        });
        line("SHM_INFO used_ids >= 1", {
            let mut info = [0u64; 6];
            let r = unsafe { libc::shmctl(0, SHM_INFO, info.as_mut_ptr().cast()) };
            if r < 0 { named(errno()) } else { ((info[0] as u32) >= 1).to_string() }
        });
        line("IPC_SET mode 0644", {
            let mut ds = stat(id).unwrap();
            ds.shm_perm.mode = 0o644;
            result(unsafe { libc::shmctl(id, libc::IPC_SET, &mut ds) } as i64)
        });
        line("  mode after", stat(id).map(|d| format!("{:o}", d.shm_perm.mode)).unwrap_or_else(named));
        line("SHM_LOCK", result(unsafe { libc::shmctl(id, libc::SHM_LOCK, std::ptr::null_mut()) } as i64));
        line("  mode after, SHM_LOCKED is 02000", stat(id).map(|d| format!("{:o}", d.shm_perm.mode)).unwrap_or_else(named));
        line("SHM_UNLOCK", result(unsafe { libc::shmctl(id, libc::SHM_UNLOCK, std::ptr::null_mut()) } as i64));
        line("  mode after", stat(id).map(|d| format!("{:o}", d.shm_perm.mode)).unwrap_or_else(named));
    }

    println!("## shmat and shmdt");
    if let Some(id) = id {
        let p = at_line("shmat(id, NULL, 0)", id, 0, 0);
        line("  nattch", nattch(id));
        line("  shm_lpid == getpid", stat(id).map(|d| (d.shm_lpid == unsafe { libc::getpid() }).to_string()).unwrap_or_else(named));
        line("  shm_atime is recent", stat(id).map(|d| (d.shm_atime > 1_600_000_000).to_string()).unwrap_or_else(named));
        if let Some(p) = p {
            unsafe { p.write_volatile(0xAB) };
            line("  a store and a load", format!("{:#x}", unsafe { p.read_volatile() }));
            line("  the page after it is not ours", {
                // The segment is one page; the next page is either unmapped
                // or something else's. Probed with mincore, which is ENOMEM
                // for an unmapped page.
                let mut vec = [0u8; 1];
                let r = unsafe { libc::mincore(p.add(4096).cast(), 4096, vec.as_mut_ptr()) };
                if r < 0 { named(errno()) } else { "mapped".into() }
            });
            let q = at_line("  shmat a second time", id, 0, 0);
            line("  nattch", nattch(id));
            if let Some(q) = q {
                line("  the second mapping sees the first's store", format!("{:#x}", unsafe { q.read_volatile() }));
                line("  shmdt of the second", shmdt(q));
            }
            line("  nattch", nattch(id));
            line("  shmdt of an address one page in", shmdt(unsafe { p.add(4096) }));
            line("  shmdt of an unaligned address", shmdt(unsafe { p.add(1) }));
            line("  shmdt of the first", shmdt(p));
            line("  nattch", nattch(id));
            line("  shmdt of it again", shmdt(p));
            line("  shmdt of NULL", shmdt(std::ptr::null_mut()));
            line("  shmdt of a plain mmap", {
                let m = unsafe { libc::mmap(std::ptr::null_mut(), 4096, 3, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
                let r = shmdt(m.cast());
                unsafe { libc::munmap(m, 4096) };
                r
            });
            line("  shm_dtime is recent", stat(id).map(|d| (d.shm_dtime > 1_600_000_000).to_string()).unwrap_or_else(named));
        }
        // Addresses.
        let hint = unsafe { libc::mmap(std::ptr::null_mut(), 8192, 0, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) } as usize;
        unsafe { libc::munmap(hint as *mut libc::c_void, 8192) };
        if let Some(p) = at_line("shmat at a free page-aligned address", id, hint, 0) {
            line("  landed there", (p as usize == hint).to_string());
            line("shmat at the same address again", shmat(id, hint, 0).map(|_| "ok".into()).unwrap_or_else(named));
            line("shmat at the same address with SHM_REMAP", shmat(id, hint, libc::SHM_REMAP).map(|_| "ok".into()).unwrap_or_else(named));
            line("  shmdt", shmdt(p));
            line("  nattch after the remap and one shmdt", nattch(id));
            if let Ok(p) = shmat(id, 0, 0) {
                line("  shmdt again", shmdt(p));
            } else {
                line("  shmdt again", "no second mapping");
            }
        }
        line("shmat at an unaligned address", shmat(id, hint + 1, 0).map(|_| "ok".into()).unwrap_or_else(named));
        line("shmat at an unaligned address with SHM_RND", shmat(id, hint + 1, libc::SHM_RND).map(|p| { let r = (p as usize == hint).to_string(); shmdt(p); r }).unwrap_or_else(named));
        line("shmat(NULL, SHM_REMAP)", shmat(id, 0, libc::SHM_REMAP).map(|_| "ok".into()).unwrap_or_else(named));
        line("shmat(1, SHM_RND|SHM_REMAP), rounds to zero", shmat(id, 1, libc::SHM_RND | libc::SHM_REMAP).map(|_| "ok".into()).unwrap_or_else(named));
        line("shmat with SHM_RDONLY then a store", {
            match shmat(id, 0, libc::SHM_RDONLY) {
                Ok(p) => {
                    // A store must fault; measure it in a child.
                    let _ = std::io::stdout().flush();
                    let pid = unsafe { libc::fork() };
                    if pid == 0 {
                        unsafe { p.write_volatile(1) };
                        unsafe { libc::_exit(0) };
                    }
                    let mut status = 0;
                    unsafe { libc::waitpid(pid, &mut status, 0) };
                    shmdt(p);
                    if libc::WIFSIGNALED(status) { format!("signal {}", libc::WTERMSIG(status)) } else { format!("exit {}", libc::WEXITSTATUS(status)) }
                }
                Err(e) => named(e),
            }
        });
        line("shmat of id + 1", shmat(id + 1, 0, 0).map(|_| "ok".into()).unwrap_or_else(named));
        line("shmat of -1", shmat(-1, 0, 0).map(|_| "ok".into()).unwrap_or_else(named));
    }

    println!("## two processes");
    if let Some(id) = id {
        if let Ok(p) = shmat(id, 0, 0) {
            unsafe { p.cast::<u32>().write_volatile(1) };
            in_child(|| {
                // Inherited across fork.
                let seen = unsafe { p.cast::<u32>().read_volatile() };
                unsafe { p.cast::<u32>().write_volatile(0xC0FFEE) };
                line("  the child sees the parent's store through the inherited attach", format!("{seen:#x}"));
                line("  nattch in the child", nattch(id));
            });
            line("  the parent sees the child's store", format!("{:#x}", unsafe { p.cast::<u32>().read_volatile() }));
            in_child(|| {
                // A fresh attach in another process.
                match shmat(id, 0, 0) {
                    Ok(q) => {
                        line("  a fresh attach in a child sees it too", format!("{:#x}", unsafe { q.cast::<u32>().read_volatile() }));
                        unsafe { q.cast::<u32>().write_volatile(0xBEEF) };
                        shmdt(q);
                    }
                    Err(e) => line("  a fresh attach in a child sees it too", named(e)),
                }
            });
            line("  and the parent sees that", format!("{:#x}", unsafe { p.cast::<u32>().read_volatile() }));
            line("  nattch back in the parent", nattch(id));
            shmdt(p);
        }
    }

    println!("## IPC_RMID");
    if let Some(id) = id {
        line("IPC_RMID with nothing attached", rmid(id));
        line("  IPC_STAT afterwards", stat(id).map(|_| "ok".into()).unwrap_or_else(named));
        line("  shmat afterwards", shmat(id, 0, 0).map(|_| "ok".into()).unwrap_or_else(named));
        line("  shmget(KEY) without IPC_CREAT afterwards", shmget(KEY, 0, 0).map(|_| "ok".into()).unwrap_or_else(named));
        line("  IPC_RMID again", rmid(id));
    }
    in_child(|| {
        // Marked while attached: the segment lives until the last detach, its
        // key is free at once, and its mode shows SHM_DEST.
        let Ok(id) = shmget(KEY, 4096, libc::IPC_CREAT | libc::IPC_EXCL | 0o600) else {
            line("a segment to mark", "could not make one");
            return;
        };
        let p = shmat(id, 0, 0).ok();
        line("IPC_RMID while attached", rmid(id));
        line("  IPC_STAT while marked", stat(id).map(|d| format!("mode {:o} nattch {}", d.shm_perm.mode, d.shm_nattch)).unwrap_or_else(named));
        line("  the key is free again", shmget(KEY, 4096, libc::IPC_CREAT | libc::IPC_EXCL | 0o600).map(|i2| { rmid(i2); "made a new one".into() }).unwrap_or_else(named));
        line("  a second attach of the marked one", shmat(id, 0, 0).map(|q| { shmdt(q); "ok".into() }).unwrap_or_else(named));
        if let Some(p) = p {
            line("  the store still reads back", { unsafe { p.write_volatile(7) }; unsafe { p.read_volatile() }.to_string() });
            line("  shmdt of the last attach", shmdt(p));
        }
        line("  IPC_STAT once detached", stat(id).map(|_| "ok".into()).unwrap_or_else(named));
    });
    line("IPC_RMID of an id nobody has", rmid(1 << 20));
    line("IPC_RMID of -1", rmid(-1));

    println!("## /proc/self/maps");
    // The name column of an attached segment's line: Linux names the file
    // behind a segment `SYSV<key as %08x>`, and it is unlinked from birth.
    for (what, key) in [
        ("a keyed segment", KEY),
        ("IPC_PRIVATE", libc::IPC_PRIVATE),
        ("a key with the top bit set", 0x8765_4321u32 as i32),
    ] {
        let Ok(id) = shmget(key, 8192, libc::IPC_CREAT | libc::IPC_EXCL | 0o600) else {
            line(what, "could not make one");
            continue;
        };
        if let Ok(p) = shmat(id, 0, 0) {
            line(&format!("{what}: perms and name"), maps_name(p));
            if key == KEY {
                rmid(id);
                line("  once IPC_RMID marked it", maps_name(p));
            }
            line(&format!("{what}: SHM_RDONLY"), {
                let q = shmat(id, 0, libc::SHM_RDONLY);
                q.map(|q| { let s = maps_name(q); shmdt(q); s }).unwrap_or_else(named)
            });
            shmdt(p);
        }
        rmid(id);
    }
    // Leave nothing behind.
    if let Ok(id) = shmget(KEY, 0, 0) {
        rmid(id);
    }
}

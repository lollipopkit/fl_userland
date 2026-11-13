//! `/proc/iul` — what this emulator says about itself.
//!
//! Six entries, and three kinds of thing among them. `colors` is a constant;
//! `objects` is the leak check; and `version`, `documents` and `defaults` are
//! answered by the **embedder**, through [`IulHost`], so that a guest can read
//! and write the host application's user defaults through the filesystem.
//!
//! # A trait, not writable globals
//!
//! Until 2026-10-17 the embedder plugged in by assigning eight `static mut`
//! symbols -- a version string and seven function pointers -- that every read
//! here went through in an `unsafe` block, and that the tests had to serialise
//! with a mutex of their own. The host is an [`IulHost`] now, installed with
//! [`set_iul_host`]; a C embedder fills an [`IulProcHost`] and calls
//! `iul_set_proc_host`, and the one place that handles its allocations is
//! [`CHost`].
use std::ffi::{CStr, CString, c_char, c_int, c_ulong};
use std::ptr::NonNull;
use std::sync::{Arc, RwLock};

use crate::ffi;
use crate::root::{Children, blank};
use kernel_epoll::epoll_live_count;

use guest_errno::c_int_::EIO;

// ---------------------------------------------------------------------------
// What the embedder hands back, and who frees it
// ---------------------------------------------------------------------------
//
// Four of the seven hooks answer memory the embedder allocated and this kernel
// must `free`. Until 2026-09-16 that was five hand-written pairs --
// `CStr::from_ptr(p)` and a `libc::free(p.cast())` a few lines apart, once per
// site, with the work in between. `defaults_unlink` calls back into the
// embedder between the two, which is the shape where an early return added
// later is a leak nothing would report.
//
// These three types are that pairing, once. Nothing below frees anything.

/// A NUL-terminated string the embedder allocated and this kernel frees.
struct HostString(NonNull<c_char>);

impl HostString {
    /// The answer of a hook that may also decline, which is a null.
    ///
    /// # Safety
    /// `p` is null, or a NUL-terminated string `libc::free` owns.
    unsafe fn take(p: *mut c_char) -> Option<HostString> {
        NonNull::new(p).map(HostString)
    }

    fn as_cstr(&self) -> &CStr {
        // SAFETY: the contract `take` carries -- NUL-terminated, and alive
        // until this value drops.
        unsafe { CStr::from_ptr(self.0.as_ptr()) }
    }
}

impl Drop for HostString {
    fn drop(&mut self) {
        // SAFETY: the embedder's allocation, ours by the hook's contract, and
        // `Drop` runs once.
        unsafe { libc::free(self.0.as_ptr().cast()) };
    }
}

/// A byte buffer the embedder allocated, as the `(pointer, length)` pair it
/// answers through two out-parameters.
///
/// A slice on the outside: `get_user_default`'s caller wants bytes, and the
/// two halves arriving separately is the C interface rather than anything this
/// side needs.
struct HostBuffer {
    ptr: NonNull<u8>,
    len: usize,
}

impl HostBuffer {
    /// Call `get_user_default`-shaped hook and adopt what it filled in.
    ///
    /// # Safety
    /// `f` writes an owned allocation and its length, or answers false.
    unsafe fn take(f: impl FnOnce(&mut *mut c_char, &mut usize) -> bool) -> Option<HostBuffer> {
        let (mut ptr, mut len) = (std::ptr::null_mut(), 0usize);
        if !f(&mut ptr, &mut len) {
            return None;
        }
        // A hook that answers true with a null buffer is answering an empty
        // one; `NonNull::new` is where that stops being a second case.
        Some(HostBuffer {
            ptr: NonNull::new(ptr.cast::<u8>())?,
            len,
        })
    }
}

impl std::ops::Deref for HostBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: the hook's contract -- `len` bytes at `ptr`, alive until this
        // value drops.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for HostBuffer {
    fn drop(&mut self) {
        // SAFETY: as `HostString`.
        unsafe { libc::free(self.ptr.as_ptr().cast()) };
    }
}

/// Every string in a NULL-terminated array the embedder allocated, copied out.
///
/// The array **and each string in it** are this kernel's to free, which was an
/// index loop with two `libc::free` in it and `*array.add(i)` for the walk.
/// Copying is what the caller wanted anyway -- it kept `CString`s.
///
/// # Safety
/// `array` is null, or a NULL-terminated array of NUL-terminated strings, all
/// of them and the array itself owned by `libc::free`.
unsafe fn host_string_list(array: *mut *mut c_char) -> Vec<CString> {
    let Some(array) = NonNull::new(array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    // SAFETY: the caller's contract. The walk stops at the NULL the array is
    // terminated by.
    unsafe {
        for i in 0.. {
            let Some(s) = HostString::take(*array.as_ptr().add(i)) else {
                break;
            };
            out.push(s.as_cstr().to_owned());
        }
        libc::free(array.as_ptr().cast());
    }
    out
}

// ---------------------------------------------------------------------------
// The embedder
// ---------------------------------------------------------------------------

/// What an embedder answers for `/proc/iul`. Every method defaults to "nothing
/// here", so an embedder implements what it has.
pub trait IulHost: Send + Sync {
    /// What `/proc/iul/version` prints.
    fn version(&self) -> Vec<u8> {
        Vec::new()
    }
    /// Where the host application keeps documents, for `/proc/iul/documents`.
    fn documents_directory(&self) -> Option<Vec<u8>> {
        None
    }
    /// Every user-default key there is.
    fn defaults_keys(&self) -> Vec<CString> {
        Vec::new()
    }
    /// The name `/proc/iul/defaults` shows for a key; `None` hides it.
    fn friendly_name(&self, _key: &CStr) -> Option<CString> {
        None
    }
    /// The key a friendly name stands for.
    fn underlying_name(&self, _friendly: &CStr) -> Option<CString> {
        None
    }
    fn get_default(&self, _key: &CStr) -> Option<Vec<u8>> {
        None
    }
    fn set_default(&self, _key: &CStr, _value: &[u8]) -> bool {
        false
    }
    fn remove_default(&self, _key: &CStr) -> bool {
        false
    }
}

static HOST: RwLock<Option<Arc<dyn IulHost>>> = RwLock::new(None);

/// Install the embedder's answers, or (`None`) take them away.
pub fn set_iul_host(host: Option<Arc<dyn IulHost>>) {
    *HOST.write().unwrap_or_else(|e| e.into_inner()) = host;
}

/// The host, cloned out so no lock is held while it answers.
fn host() -> Option<Arc<dyn IulHost>> {
    HOST.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The C embedder's half of [`IulHost`]: a version string and seven function
/// pointers, any of them null. `iul.h`'s `struct iul_proc_host`.
///
/// Every string and buffer a hook answers is `malloc`ed by the embedder and
/// freed here, by [`HostString`] and [`HostBuffer`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IulProcHost {
    pub version: *const c_char,
    pub all_defaults_keys: Option<extern "C" fn() -> *mut *mut c_char>,
    pub friendly_name: Option<extern "C" fn(*const c_char) -> *mut c_char>,
    pub underlying_name: Option<extern "C" fn(*const c_char) -> *mut c_char>,
    pub get_user_default: Option<extern "C" fn(*const c_char, *mut *mut c_char, *mut usize) -> bool>,
    pub set_user_default: Option<extern "C" fn(*const c_char, *const c_char, usize) -> bool>,
    pub remove_user_default: Option<extern "C" fn(*const c_char) -> bool>,
    pub documents_directory: Option<extern "C" fn() -> *mut c_char>,
}

/// [`IulProcHost`] as an [`IulHost`]: the version copied, the hooks kept.
///
/// `Send` and `Sync` are derived since 2026-10-17: it held the whole
/// `IulProcHost`, whose `version` pointer -- nulled, never read -- was what
/// made `unsafe impl`s necessary. The hooks are function pointers, which the
/// embedder's contract makes callable from any guest thread.
struct CHost {
    version: Vec<u8>,
    hooks: Hooks,
}

/// `IulProcHost` without `version`.
struct Hooks {
    all_defaults_keys: Option<extern "C" fn() -> *mut *mut c_char>,
    friendly_name: Option<extern "C" fn(*const c_char) -> *mut c_char>,
    underlying_name: Option<extern "C" fn(*const c_char) -> *mut c_char>,
    get_user_default: Option<extern "C" fn(*const c_char, *mut *mut c_char, *mut usize) -> bool>,
    set_user_default: Option<extern "C" fn(*const c_char, *const c_char, usize) -> bool>,
    remove_user_default: Option<extern "C" fn(*const c_char) -> bool>,
    documents_directory: Option<extern "C" fn() -> *mut c_char>,
}

impl IulHost for CHost {
    fn version(&self) -> Vec<u8> {
        self.version.clone()
    }
    fn documents_directory(&self) -> Option<Vec<u8>> {
        let get = self.hooks.documents_directory?;
        // SAFETY: the hook's contract -- an allocation this kernel frees.
        unsafe { HostString::take(get()) }.map(|d| d.as_cstr().to_bytes().to_vec())
    }
    fn defaults_keys(&self) -> Vec<CString> {
        let Some(all) = self.hooks.all_defaults_keys else {
            return Vec::new();
        };
        // SAFETY: the hook's contract -- a NULL-terminated array of C strings,
        // each of them and the array itself ours to free.
        unsafe { host_string_list(all()) }
    }
    fn friendly_name(&self, key: &CStr) -> Option<CString> {
        let f = self.hooks.friendly_name?;
        // SAFETY: as `documents_directory`.
        unsafe { HostString::take(f(key.as_ptr())) }.map(|s| s.as_cstr().to_owned())
    }
    fn underlying_name(&self, friendly: &CStr) -> Option<CString> {
        let f = self.hooks.underlying_name?;
        // SAFETY: as `documents_directory`.
        unsafe { HostString::take(f(friendly.as_ptr())) }.map(|s| s.as_cstr().to_owned())
    }
    fn get_default(&self, key: &CStr) -> Option<Vec<u8>> {
        let get = self.hooks.get_user_default?;
        // SAFETY: the hook's contract -- it fills in an owned allocation and
        // its length, or answers false.
        unsafe { HostBuffer::take(|p, n| get(key.as_ptr(), p, n)) }.map(|b| b.to_vec())
    }
    fn set_default(&self, key: &CStr, value: &[u8]) -> bool {
        self.hooks.set_user_default.is_some_and(|set| set(key.as_ptr(), value.as_ptr().cast(), value.len()))
    }
    fn remove_default(&self, key: &CStr) -> bool {
        self.hooks.remove_user_default.is_some_and(|remove| remove(key.as_ptr()))
    }
}

/// Install a C embedder's host, copied; null takes it away.
///
/// # Safety
/// `host` is null or a valid `struct iul_proc_host`, whose `version` is null
/// or a NUL-terminated string, and whose hooks keep the contracts `iul.h`
/// states.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iul_set_proc_host(host: *const IulProcHost) {
    // SAFETY: the caller's contract.
    let Some(h) = (unsafe { host.as_ref() }) else {
        set_iul_host(None);
        return;
    };
    let version = if h.version.is_null() {
        Vec::new()
    } else {
        // SAFETY: the caller's contract.
        unsafe { CStr::from_ptr(h.version) }.to_bytes().to_vec()
    };
    let hooks = Hooks {
        all_defaults_keys: h.all_defaults_keys,
        friendly_name: h.friendly_name,
        underlying_name: h.underlying_name,
        get_user_default: h.get_user_default,
        set_user_default: h.set_user_default,
        remove_user_default: h.remove_user_default,
        documents_directory: h.documents_directory,
    };
    set_iul_host(Some(Arc::new(CHost { version, hooks })));
}

// ---------------------------------------------------------------------------
// The constants
// ---------------------------------------------------------------------------

/// The sixteen ANSI colours and the sixteen bright ones, as a block a terminal
/// renders. `cat /proc/iul/colors` is how you see whether the emulator's
/// terminal handles them.
const COLORS: &str = concat!(
    "\x1B[30miul\x1B[39m \x1B[31miul\x1B[39m \x1B[32miul\x1B[39m \x1B[33miul\x1B[39m ",
    "\x1B[34miul\x1B[39m \x1B[35miul\x1B[39m \x1B[36miul\x1B[39m \x1B[37miul\x1B[39m",
    "\n\x1B[7m",
    "\x1B[40miul\x1B[39m \x1B[41miul\x1B[39m \x1B[42miul\x1B[39m \x1B[43miul\x1B[39m ",
    "\x1B[44miul\x1B[39m \x1B[45miul\x1B[39m \x1B[46miul\x1B[39m \x1B[47miul\x1B[39m",
    "\x1B[0m\x1B[1m\n",
    "\x1B[90miul\x1B[39m \x1B[91miul\x1B[39m \x1B[92miul\x1B[39m \x1B[93miul\x1B[39m ",
    "\x1B[94miul\x1B[39m \x1B[95miul\x1B[39m \x1B[96miul\x1B[39m \x1B[97miul\x1B[39m",
    "\n\x1B[7m",
    "\x1B[100miul\x1B[39m \x1B[101miul\x1B[39m \x1B[102miul\x1B[39m \x1B[103miul\x1B[39m ",
    "\x1B[104miul\x1B[39m \x1B[105miul\x1B[39m \x1B[106miul\x1B[39m \x1B[107miul\x1B[39m",
    "\x1B[0m\n",
);

fn append(data: &mut ffi::proc_data, text: &[u8]) {
    data.append(text);
}

fn show_colors(_e: &mut ffi::proc_entry, data: &mut ffi::proc_data) -> c_int {
    append(data, COLORS.as_bytes());
    0
}

fn show_version(_e: &mut ffi::proc_entry, data: &mut ffi::proc_data) -> c_int {
    if let Some(host) = host() {
        append(data, &host.version());
    }
    append(data, b"\n");
    0
}

fn show_documents(_e: &mut ffi::proc_entry, data: &mut ffi::proc_data) -> c_int {
    if let Some(dir) = host().and_then(|h| h.documents_directory()) {
        append(data, &dir);
    }
    append(data, b"\n");
    0
}

// ---------------------------------------------------------------------------
// /proc/iul/objects
// ---------------------------------------------------------------------------

/// How many Rust-owned kernel objects are allocated right now.
///
/// The fd-backed objects moved to Rust one at a time, and each one turned two
/// fields in a union into an allocation that something has to free. That is a
/// way to leak that the C did not have, and reading `fd_close` and believing it
/// is not a check. This makes it one a guest can make: open some, count, close
/// them, count again.
///
/// One line per kind, `name count`, so adding the next one does not change how
/// the file is parsed.
fn show_objects(_e: &mut ffi::proc_entry, data: &mut ffi::proc_data) -> c_int {
    let mut out = String::new();
    out.push_str(&format!("fd {}\n", fs_fdobj::fd_live_count()));
    out.push_str(&format!("epoll {}\n", epoll_live_count()));
    out.push_str(&format!(
        "eventfd {}\n",
        kernel_eventfd::eventfd_live_count()
    ));
    out.push_str(&format!("pidfd {}\n", kernel_pidfd::pidfd_live_count()));
    out.push_str(&format!(
        "timerfd {}\n",
        kernel_timerfd::timerfd_live_count()
    ));

    // The side tables. These are a *different* way to leak from the ones
    // above: those are an allocation per descriptor, these are an entry
    // keyed by an address that something else owns, and the table has to be
    // told when that address dies. The intrusive lists they replaced could
    // not have the problem -- the links were in the freed memory.
    //
    // `proctree_stale` is how often an address arrived that was still
    // registered, which is exactly "freed without saying so". It is always
    // zero.
    let (tasks, groups, stale) = proctree::counts();
    out.push_str(&format!("task {tasks}\n"));
    out.push_str(&format!("tgroup {groups}\n"));
    out.push_str(&format!("proctree_stale {stale}\n"));

    // The structs themselves, which is a **third** thing again: the two counts
    // above are *registry entries* keyed by an address, and a struct is freed
    // one step after its entry is forgotten -- `struct task` a whole round
    // later, because `task_destroy` defers the free by one. So a leak of the
    // allocation is invisible to `task` and `tgroup` above, and it was
    // invisible to everything until these four were allocated by Rust on
    // 2026-09-12. `tests/guest/src/bin/eventfd_leak.rs` is what asks.
    out.push_str(&format!(
        "task_struct {}\n",
        taskcalls::task_live_count()
    ));
    out.push_str(&format!("tlb {}\n", emu_tlb::tlb_live_count()));
    out.push_str(&format!(
        "task_cleanup {}\n",
        taskcalls::task_cleanup_live_count()
    ));
    out.push_str(&format!(
        "tgroup_struct {}\n",
        kernel_tgroup::tgroup_live_count()
    ));

    // Host mappings this process asked for and did not get. **Not a leak
    // counter like the ones above** -- it is the answer to a question the guest
    // cannot ask: a guest `ENOMEM` means either that its own address space is
    // full or that the host refused, and those were the same answer with
    // nothing to tell them apart until 2026-09-06. Zero on a healthy run; a
    // non-zero count says which, and names the host `errno` and the size.
    // The anonymous-page budget: how many pages are charged against the 4 GiB
    // cap, and how often it has refused. A refusal reaches the guest as a plain
    // `ENOMEM` -- or, from `brk`, as the current break -- so it is
    // indistinguishable from the guest genuinely running out, which is why the
    // count is here. Zero on a healthy run.
    out.push_str(&format!(
        "anon_pages {}\n",
        pagetable::anonbudget::anon_pages_used()
    ));
    out.push_str(&format!(
        "anon_refused {}\n",
        pagetable::anonbudget::anon_pages_refused()
    ));

    let (host_fail, host_errno, host_bytes) = pagetable::host_map_failures();
    out.push_str(&format!("host_map_failures {host_fail}\n"));
    out.push_str(&format!("host_map_last_errno {host_errno}\n"));
    out.push_str(&format!("host_map_last_bytes {host_bytes}\n"));

    // A Rust call rather than the C ABI: nothing in C names this any more,
    // which is what tools/dead-exports.py reported the moment fs/proc/iul.c
    // went.
    let (endpoints, pending) = unixpeer::counts();
    out.push_str(&format!("unixpeer {endpoints}\n"));
    out.push_str(&format!("unixpeer_pending {pending}\n"));

    // Every filesystem's inodes go through one table, so a count that only
    // grows is a reference nobody released -- and it would grow at the rate
    // the workload opens files.
    out.push_str(&format!("inode {}\n", fs_inode::inode_live_count()));
    // Not an object per descriptor and not a side table: a queue whose
    // consumer is the host application. It is here for the same reason -- a
    // number that only grows names something nobody is draining -- and
    // `fakechange_dropped` beside it says whether the bound was reached.
    out.push_str(&format!("fakechange {}\n", fakechange::depth()));
    out.push_str(&format!("fakechange_dropped {}\n", fakechange::dropped()));
    append(data, out.as_bytes());
    0
}

// ---------------------------------------------------------------------------
// The defaults directories
// ---------------------------------------------------------------------------

/// **This copied the whole key, terminator included, into a buffer whose size
/// it was not told**, and the key comes from an embedder hook with no length
/// rule anywhere — so a 257-byte one overran `find_child`'s stack buffer. It is
/// `put_name` like the other four now, which truncates against the buffer it
/// was given.
fn defaults_getname(entry: &mut ffi::proc_entry, buf: &mut [u8]) {
    let name = entry.name.as_ref();
    crate::entry::put_name(buf, name.map_or(b"", |n| n.to_bytes()));
}

/// `/proc/iul/defaults/<friendly>` is a symlink to the underlying key.
///
/// Reaching this entry means `get_all_defaults_keys` produced a name, which an
/// embedder would not normally do without setting the rest. Checked anyway.
fn defaults_readlink(entry: &mut ffi::proc_entry, buf: &mut [u8]) -> c_int {
    let Some(name) = host().zip(entry.name.as_deref()).and_then(|(h, n)| h.underlying_name(n)) else {
        return EIO;
    };
    let text = format!("../.defaults/{}", name.to_string_lossy());
    ffi::fill_path(buf, text.as_bytes())
}

fn underlying_show(entry: &mut ffi::proc_entry, data: &mut ffi::proc_data) -> c_int {
    let Some(bytes) = host().zip(entry.name.as_deref()).and_then(|(h, n)| h.get_default(n)) else {
        return EIO;
    };
    data.append(&bytes);
    0
}

fn underlying_update(entry: &mut ffi::proc_entry, data: &mut ffi::proc_data) -> c_int {
    // The `update` callback is handed the bytes the guest wrote, which the
    // buffer owns.
    let ok = host().zip(entry.name.as_deref()).is_some_and(|(h, n)| h.set_default(n, data.as_slice()));
    if ok { 0 } else { EIO }
}

fn underlying_unlink(entry: &mut ffi::proc_entry) -> c_int {
    let ok = host().zip(entry.name.as_deref()).is_some_and(|(h, n)| h.remove_default(n));
    if ok { 0 } else { EIO }
}

fn defaults_unlink(entry: &mut ffi::proc_entry) -> c_int {
    let (Some(host), Some(friendly)) = (host(), entry.name.as_deref()) else {
        return EIO;
    };
    let ok = host.underlying_name(friendly).is_some_and(|key| host.remove_default(&key));
    if ok { 0 } else { EIO }
}

/// The entry each name in `.defaults` gets.
#[unsafe(no_mangle)]
pub static proc_iul_underlying_defaults_fd: DirEntry = DirEntry(ffi::proc_dir_entry {
    getname: Some(defaults_getname),
    show: Some(underlying_show),
    update: Some(underlying_update),
    unlink: Some(underlying_unlink),
    ..blank()
});

/// The entry each name in `defaults` gets: a symlink to the one above.
#[unsafe(no_mangle)]
pub static proc_iul_defaults_fd: DirEntry = DirEntry(ffi::proc_dir_entry {
    mode: libc::S_IFLNK,
    getname: Some(defaults_getname),
    readlink: Some(defaults_readlink),
    unlink: Some(defaults_unlink),
    ..blank()
});

/// A `proc_dir_entry` built once and read for ever after.
#[repr(transparent)]
pub struct DirEntry(pub ffi::proc_dir_entry);

/// Refresh the child names at the start of a directory read.
///
/// Index zero means a new pass, and a pass with no names yet also has to ask —
/// the embedder may have gained keys since.
///
/// **The embedder's array is copied and freed here**, rather than held for the
/// life of the entry. Its contract is "every key, NULL-terminated, caller
/// frees", and the caller used to be `proc_entry_cleanup` fourteen call sites
/// away; it is this function, four lines down.
fn refresh_child_names(entry: &mut ffi::proc_entry, index: c_ulong) {
    let names = &mut entry.child_names;
    if index != 0 && !names.is_empty() {
        return;
    }
    names.clear();
    if let Some(host) = host() {
        names.extend(host.defaults_keys());
    }
}

/// The name at `index`, borrowed from the entry.
///
/// A `&proc_entry` rather than a `*mut`: the borrow's lifetime is the caller's
/// and the compiler checks it, where the raw pointer version had to invent one.
/// Sound because the refresh above has already finished by the time this is
/// called and nothing else writes a `/proc/iul/defaults` entry -- it belongs to
/// one descriptor, and every call here is on that descriptor's own thread.
fn name_at(entry: &ffi::proc_entry, index: c_ulong) -> Option<&CStr> {
    entry
        .child_names
        .get(index as usize)
        .map(std::ffi::CString::as_c_str)
}

fn underlying_defaults_readdir(
    entry: &mut ffi::proc_entry,
    index: &mut c_ulong,
) -> Option<ffi::proc_entry> {
    refresh_child_names(entry, *index);
    let name = name_at(entry, *index)?.to_owned();
    *index += 1;
    Some(ffi::proc_entry {
        meta: Some(&proc_iul_underlying_defaults_fd.0),
        name: Some(name),
        ..ffi::proc_entry::default()
    })
}

fn defaults_readdir(
    entry: &mut ffi::proc_entry,
    index: &mut c_ulong,
) -> Option<ffi::proc_entry> {
    refresh_child_names(entry, *index);
    let host = host()?;
    // A key with no friendly name is skipped rather than shown, so the loop
    // runs until it finds one or runs out.
    let friendly = loop {
        let name = name_at(entry, *index)?;
        let friendly = host.friendly_name(name);
        *index += 1;
        if let Some(friendly) = friendly {
            break friendly;
        }
    };
    Some(ffi::proc_entry {
        meta: Some(&proc_iul_defaults_fd.0),
        name: Some(friendly),
        ..ffi::proc_entry::default()
    })
}

// ---------------------------------------------------------------------------
// The directory
// ---------------------------------------------------------------------------

const IUL_LEN: usize = 6;

/// In alphabetical order, which is the order `readdir` reports them in.
#[unsafe(no_mangle)]
pub static proc_iul_children: Children<IUL_LEN> = Children([
        ffi::proc_dir_entry {
            name: Some(c"colors"),
            show: Some(show_colors),
            ..blank()
        },
        ffi::proc_dir_entry {
            name: Some(c".defaults"),
            mode: libc::S_IFDIR,
            readdir: Some(underlying_defaults_readdir),
            ..blank()
        },
        ffi::proc_dir_entry {
            name: Some(c"defaults"),
            mode: libc::S_IFDIR,
            readdir: Some(defaults_readdir),
            ..blank()
        },
        ffi::proc_dir_entry {
            name: Some(c"documents"),
            show: Some(show_documents),
            ..blank()
        },
        ffi::proc_dir_entry {
            name: Some(c"objects"),
            show: Some(show_objects),
            ..blank()
        },
        ffi::proc_dir_entry {
            name: Some(c"version"),
            show: Some(show_version),
            ..blank()
        },
    ]);

#[cfg(test)]
mod tests {
    use super::*;

    /// The host is process-wide and cargo runs these on threads of one
    /// process, so a test that installs one and a test that asserts there is
    /// none must not overlap. Poisoning is ignored: a test that panicked left
    /// the host as it found it, or the run is already red for a better reason.
    fn hooks() -> std::sync::MutexGuard<'static, ()> {
        static HOOKS: std::sync::Mutex<()> = std::sync::Mutex::new(());
        HOOKS.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// With no host every entry answers as an empty one would: `EIO` for a
    /// default, no names in a listing.
    #[test]
    fn with_no_host_nothing_is_answered() {
        let _installed = hooks();
        set_iul_host(None);
        let mut entry = ffi::proc_entry { name: Some(c"k".into()), ..Default::default() };
        let mut data = ffi::proc_data::default();
        assert_eq!(underlying_show(&mut entry, &mut data), EIO);
        assert_eq!(underlying_unlink(&mut entry), EIO);
        refresh_child_names(&mut entry, 0);
        assert!(entry.child_names.is_empty());
    }

    /// A Rust host: what a guest writes to `.defaults/<key>` is what it reads
    /// back, and removing the friendly name removes the key it stands for.
    #[test]
    fn a_host_answers_reads_writes_and_removes() {
        #[derive(Default)]
        struct Memory(std::sync::Mutex<std::collections::BTreeMap<CString, Vec<u8>>>);
        impl IulHost for Memory {
            fn defaults_keys(&self) -> Vec<CString> {
                self.0.lock().unwrap().keys().cloned().collect()
            }
            fn underlying_name(&self, friendly: &CStr) -> Option<CString> {
                Some(friendly.to_owned())
            }
            fn get_default(&self, key: &CStr) -> Option<Vec<u8>> {
                self.0.lock().unwrap().get(key).cloned()
            }
            fn set_default(&self, key: &CStr, value: &[u8]) -> bool {
                self.0.lock().unwrap().insert(key.to_owned(), value.to_vec());
                true
            }
            fn remove_default(&self, key: &CStr) -> bool {
                self.0.lock().unwrap().remove(key).is_some()
            }
        }

        let _installed = hooks();
        set_iul_host(Some(Arc::new(Memory::default())));
        let mut entry = ffi::proc_entry { name: Some(c"color".into()), ..Default::default() };
        let mut written = ffi::proc_data::default();
        written.append(b"blue");
        assert_eq!(underlying_update(&mut entry, &mut written), 0);
        let mut read = ffi::proc_data::default();
        assert_eq!(underlying_show(&mut entry, &mut read), 0);
        assert_eq!(read.as_slice(), b"blue");
        refresh_child_names(&mut entry, 0);
        assert_eq!(entry.child_names, [c"color".to_owned()]);
        assert_eq!(defaults_unlink(&mut entry), 0);
        assert_eq!(underlying_show(&mut entry, &mut read), EIO, "removed");
        set_iul_host(None);
    }

    /// Six entries, alphabetical, and each is either a file with a `show` or a
    /// directory with a `readdir`. An entry with neither is a name `readdir`
    /// reports and nothing can open.
    #[test]
    fn every_entry_is_a_file_or_a_directory() {
        assert_eq!(proc_iul_children.0.len(), IUL_LEN);
        let mut previous = "";
        for e in &proc_iul_children.0 {
            let name = e.name.unwrap_or(c"").to_str().expect("utf-8");
            // "." sorts before every letter, which is why `.defaults` is second
            // and not first: `colors` comes before it in the C's order too, and
            // readdir reports the table's order rather than a sorted one.
            if !name.starts_with('.') {
                assert!(name > previous, "{name} is not after {previous}");
                previous = name;
            }
            let is_dir = e.mode & libc::S_IFMT == libc::S_IFDIR;
            assert_eq!(
                is_dir,
                e.readdir.is_some(),
                "{name}: a directory is exactly a readdir"
            );
            assert!(is_dir || e.show.is_some(), "{name}: no show and no readdir");
        }
    }

    /// The two entries a defaults directory hands out. The first is a file the
    /// embedder answers for, the second a symlink to it.
    #[test]
    fn the_defaults_entries_are_a_file_and_a_link() {
        assert!(proc_iul_underlying_defaults_fd.0.show.is_some());
        assert!(proc_iul_underlying_defaults_fd.0.readlink.is_none());
        assert_eq!(proc_iul_defaults_fd.0.mode & libc::S_IFMT, libc::S_IFLNK);
        assert!(proc_iul_defaults_fd.0.readlink.is_some());
        // Both can be removed, which is what makes `rm /proc/iul/defaults/x`
        // clear a user default.
        assert!(proc_iul_underlying_defaults_fd.0.unlink.is_some());
        assert!(proc_iul_defaults_fd.0.unlink.is_some());
    }

    /// A key longer than the buffer is truncated rather than written past it.
    ///
    /// **The one hook here whose answer has no length rule anywhere.** An
    /// embedder returns whatever keys it has; `defaults_getname` copied all of
    /// them plus the terminator into the VFS's `MAX_NAME + 1` bytes, so a
    /// 257-byte key overran `descriptor::find_child`'s stack buffer — and the
    /// call site's comment said "getname writes at most MAX_NAME bytes plus a
    /// terminator", which was true of the other four implementations.
    ///
    /// The buffer here is deliberately *small*: what is being asserted is that
    /// the bound is the caller's slice and not a constant, so backing the fix
    /// out — `put_name` copying `name.len()` — goes red on the poison bytes
    /// rather than needing a 257-byte key to show anything.
    #[test]
    fn a_key_longer_than_the_buffer_is_truncated() {
        let key = std::ffi::CString::new("k".repeat(64)).unwrap();
        let mut entry = ffi::proc_entry {
            name: Some(key),
            ..Default::default()
        };

        let mut buf = [0xAAu8; 16];
        defaults_getname(&mut entry, &mut buf[..8]);
        assert_eq!(&buf[..8], b"kkkkkkk\0");
        assert_eq!(&buf[8..], [0xAA; 8], "wrote past the buffer");

        // And the absent name the hook can also produce, which is empty.
        entry.name = None;
        defaults_getname(&mut entry, &mut buf[..8]);
        assert_eq!(buf[0], 0);
    }

    /// The embedder's key array is copied into the entry and freed here.
    ///
    /// **This is the one place ownership crosses**, and it used to cross the
    /// other way: the array was stored in `entry.child_names` and freed by
    /// `proc_entry_cleanup`, fourteen call sites away, on whichever path the
    /// descriptor happened to leave by. Now the hook's contract — "every key,
    /// NULL-terminated, caller frees" — is discharged four lines after the
    /// call.
    ///
    /// **It does not see the `free`, and that was checked rather than
    /// assumed**: taking the `libc::free` out leaves this green. What it does
    /// see is the copy — that the names arrive, that a pass already under way
    /// does not ask again, and that index zero does — and a *double* free
    /// would crash it, because the last two cases run the release path twice.
    ///
    /// So the argument for the `free` being right is not this test; it is that
    /// the call and the release are four lines apart in one function, where
    /// they used to be a hook's contract discharged by `proc_entry_cleanup` at
    /// whichever of fourteen call sites the descriptor happened to leave by.
    /// Nothing in this tree can observe a `libc` leak; `/proc/iul/objects`
    /// counts Rust-owned objects, and this allocation is the embedder's.
    #[test]
    fn the_embedders_key_array_is_copied_and_released() {
        extern "C" fn keys() -> *mut *mut c_char {
            // Three keys and the NULL, in the shape the hook's contract names:
            // `malloc`'d, and the caller's to free.
            // A named element type, because `tools/hand-allocated-drop.py`
            // reads the type out of `size_of::<T>()` or `.cast::<T>()` and its
            // pattern is an identifier -- `*mut c_char` spelled inline is a
            // site it cannot check, so it fails the run rather than skipping
            // it. Which is the gate working: it caught this twice, once for
            // the spelling and once for the missing assertion below.
            type Key = *mut c_char;
            const _: () = assert!(
                !std::mem::needs_drop::<Key>(),
                "the hook's array is `libc::free`d element by element, which \
                 runs no destructor"
            );
            let names = [c"alpha", c"beta", c"gamma"];
            let array = unsafe { libc::calloc(names.len() + 1, size_of::<Key>()) }.cast::<Key>();
            for (i, n) in names.iter().enumerate() {
                unsafe { *array.add(i) = libc::strdup(n.as_ptr()) };
            }
            array
        }

        let _installed = hooks();
        let mut entry = ffi::proc_entry::default();
        let host = IulProcHost {
            version: std::ptr::null(),
            all_defaults_keys: Some(keys),
            friendly_name: None,
            underlying_name: None,
            get_user_default: None,
            set_user_default: None,
            remove_user_default: None,
            documents_directory: None,
        };
        // SAFETY: a valid host with no version string.
        unsafe { iul_set_proc_host(&host) };

        refresh_child_names(&mut entry, 0);
        assert_eq!(entry.child_names.len(), 3);
        assert_eq!(name_at(&entry, 1), Some(c"beta"));
        assert_eq!(name_at(&entry, 3), None, "past the end");

        // A pass already under way does not ask again...
        refresh_child_names(&mut entry, 2);
        assert_eq!(entry.child_names.len(), 3);
        // ...and a new one does, which is the second `free` of the array.
        refresh_child_names(&mut entry, 0);
        assert_eq!(entry.child_names.len(), 3);

        set_iul_host(None);
        // With no host there are no names, and the old ones are let go.
        refresh_child_names(&mut entry, 0);
        assert!(entry.child_names.is_empty());
    }

    /// **A hook that answers `true` with a null buffer is `EIO`, not a crash.**
    ///
    /// `underlying_show` built its slice with
    /// `slice::from_raw_parts(buffer.cast::<u8>(), size)` straight after the
    /// call. `from_raw_parts` requires a non-null pointer *whatever the
    /// length*, so an embedder answering true without filling the buffer in was
    /// undefined behaviour — at any size, including zero.
    ///
    /// No embedder in this tree does it, so this is hardening rather than a
    /// fix, and the reason it is now impossible is the type:
    /// [`HostBuffer::take`] asks `NonNull::new` and the `?` is where the case
    /// stops existing. The old shape could not have had this test written
    /// against it — it would not have failed, it would have been UB.
    #[test]
    fn a_hook_that_answers_true_with_no_buffer_is_refused() {
        extern "C" fn empty(_: *const c_char, buf: *mut *mut c_char, n: *mut usize) -> bool {
            // SAFETY: the caller's out-parameters.
            unsafe {
                *buf = std::ptr::null_mut();
                *n = 0;
            }
            true
        }

        let _installed = hooks();
        let host = IulProcHost {
            version: std::ptr::null(),
            all_defaults_keys: None,
            friendly_name: None,
            underlying_name: None,
            get_user_default: Some(empty),
            set_user_default: None,
            remove_user_default: None,
            documents_directory: None,
        };
        // SAFETY: a valid host with no version string.
        unsafe { iul_set_proc_host(&host) };
        let mut entry = ffi::proc_entry { name: Some(c"k".into()), ..Default::default() };
        let mut data = ffi::proc_data::default();
        assert_eq!(underlying_show(&mut entry, &mut data), EIO);
        assert!(data.as_slice().is_empty());
        set_iul_host(None);

        // And with no host at all, which is every build in this repository.
        assert_eq!(underlying_show(&mut entry, &mut data), EIO);
    }

    /// The colour block is four lines of eight, and every escape is closed.
    /// Unbalanced escapes leave the terminal in whatever mode the last one set.
    #[test]
    fn the_colour_block_closes_what_it_opens() {
        assert_eq!(COLORS.lines().count(), 4);
        assert!(COLORS.ends_with("\x1B[0m\n"), "the last escape resets");
        assert_eq!(COLORS.matches("iul").count(), 32);
    }
}

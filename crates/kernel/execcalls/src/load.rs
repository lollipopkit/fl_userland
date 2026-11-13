//! Putting a program in an address space: the ELF loader and the `#!` handler.
//!
//! Every decision about *what the file says* is `crates/kernel/elf` and
//! `crates/kernel/shebang`; every decision about *where the block at the top of
//! the stack goes* is `crates/kernel/initstack`. What is here is the part that
//! touches the process — opening files, replacing the address space, and
//! writing the guest's registers.
//!
//! # The point of no return
//!
//! [`elf_exec`] releases the old `mm` partway through, and after that a failure
//! cannot be reported to `execve`: the process has no program left to return
//! to. So everything that can be checked is checked *first* — that the file
//! parses, that the interpreter opens and parses, and that every `PT_LOAD` of
//! both fits the guest address space. Linux validates before `begin_new_exec`
//! for the same reason. Past that line a failure leaves the process to be
//! killed, which is what `Fatal` means below.
//!
//! The bias is not known at the check — for a dynamic image it comes from a
//! hole in an `mm` that does not exist yet — but it is only ever *added*, so a
//! segment that does not fit at bias 0 cannot fit at any bias.

use std::ffi::{CStr, CString, c_int};

use crate::ffi;
use crate::{Args, MemWrite, shebang};

#[path = "stack.rs"]
mod stack;
use stack::{finish_stack, place_image};

use guest_errno::c_int_::{EACCES, EFAULT, EINVAL, EIO, ELIBBAD, ELOOP, ENOEXEC, ENOMEM};

const O_RDONLY: c_int = 0;
/// `O_NONBLOCK_` and `O_NOFOLLOW_` in `kernel/fs.h`.
const O_NONBLOCK: c_int = 1 << 11;
const O_NOFOLLOW: c_int = 1 << 15;
const SEEK_SET: c_int = 0;

/// How deep a `#!` chain may go before it is refused. Linux nests one script
/// inside another and answers `ELOOP` past its own limit, and the limit is
/// **five** scripts: `exec_binprm` allows five binfmt rewrites (`depth > 5`
/// fails), and the ELF at the end of the chain is the sixth pass. Measured by
/// `exec_probe` -- a chain of five ran and a chain of six was `ELOOP` -- after
/// this said four, from a reading of the constant rather than the loop.
///
/// This used to be one level, because `shebang_exec` called `format_exec` and
/// `format_exec` only tried ELF: a script whose interpreter was a script failed
/// with `ENOEXEC`, which reads as "not a program" rather than "too many".
const MAX_NESTING: u32 = 5;

/// What a failure past the point of no return means.
///
/// Both are a negative guest errno to the caller; the distinction is that
/// `Fatal` has already replaced the address space, so the process cannot go on
/// whatever `execve` returns. The C carried this as a `goto beyond_hope` with a
/// `TODO force sigsegv` on it; the type says which errors are which, and since
/// 2026-09-04 `do_exec` acts on it — Linux's `force_sigsegv` past the point of
/// no return, so the process dies of `SIGSEGV` rather than running its old
/// registers over the new image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failed {
    /// The old image is intact; `execve` returns this and the process runs on.
    Recoverable(c_int),
    /// The address space is gone: a forced `SIGSEGV` goes with the errno.
    Fatal(c_int),
    /// At the point of no return the group was already exiting, or another
    /// thread's `execve` had it: this thread is one of those being ended, and
    /// leaves with this status rather than answering anything.
    Killed(c_int),
}

impl Failed {
    /// The errno, for the two that answer one.
    pub fn errno(self) -> Option<c_int> {
        match self {
            Failed::Recoverable(e) | Failed::Fatal(e) => Some(e),
            Failed::Killed(_) => None,
        }
    }
}

type Loaded = Result<(), Failed>;

/// An open file, closed when it goes out of scope.
///
/// The C had one `goto` chain per failure and a `interp_fd != NULL && !IS_ERR`
/// test at the end of it. There were nine exits from `elf_exec`.
///
/// It **owns** the reference, unlike `crates/kernel/rwcalls`' and
/// `crates/kernel/fdattr`' `Fd`, which borrow one the syscall exit releases.
/// A `usize` until 2026-09-16, a `NonNull` with its own `Deref` and `Drop`
/// until 2026-09-29, and [`fs_fdobj::Owned`] -- which is those two -- since.
pub struct File(fs_fdobj::Owned);

impl File {
    /// `generic_open`, whose errors come back in the pointer.
    ///
    /// Resolves against the task's working directory, which is what an
    /// `execve` and a `#!` interpreter both want: Linux resolves an
    /// interpreter against the process, not against whatever directory
    /// descriptor an `execveat` named.
    pub fn open(path: &CStr) -> Result<File, c_int> {
        File::openat(ffi::At::Pwd, path)
    }

    /// The same, relative to a directory descriptor — what `execveat` needs.
    ///
    /// `at` is `fs/path.h`'s sentinel or a `struct fd *`; `at_fd` produces
    /// either, and an absolute path ignores it.
    pub fn openat(at: ffi::At<'_>, path: &CStr) -> Result<File, c_int> {
        File::openat_flags(at, path, O_RDONLY | O_NONBLOCK)
    }

    fn openat_flags(at: ffi::At<'_>, path: &CStr, flags: c_int) -> Result<File, c_int> {
        let fd = fs_generic::generic_openat(at, path, flags, 0)
            .map_err(|e| e.as_c_int())?;
        Ok(File(fd))
    }

    /// Open a file **to run it**: Linux's `open_exec`, which is an open with
    /// `MAY_EXEC` and the two refusals `may_open` makes for that -- anything
    /// that is not a regular file is `EACCES`, whatever its mode, and so is a
    /// regular file nobody may execute. Both are asked of every file an exec
    /// opens: the program, a `#!` interpreter, and an ELF interpreter. A
    /// `#!` naming a directory used to be read and fail with `EIO`, and one
    /// naming a file with no execute bit used to run it.
    ///
    /// O_NONBLOCK because the file has not been looked at yet, and a FIFO
    /// opened for reading without it parks until a writer arrives -- so an
    /// `execve` of a named pipe hung the process where Linux answers `EACCES`
    /// before the open. The type is refused after this open, by the `fstat`;
    /// the flag makes the open come back so that it can be. A regular file is
    /// not affected by it.
    ///
    /// `nofollow` is `execveat`'s `AT_SYMLINK_NOFOLLOW`: a final component
    /// that is a symlink is `ELOOP` rather than followed.
    pub fn open_exec(
        at: ffi::At<'_>,
        path: &CStr,
        nofollow: bool,
    ) -> Result<(File, ffi::statbuf), c_int> {
        let mut flags = O_RDONLY | O_NONBLOCK;
        if nofollow {
            flags |= O_NOFOLLOW;
        }
        // Execute permission, not read: Linux's `MAY_EXEC`. Whether the
        // caller could also read it decides only `dumpable`.
        let how = fs_generic::OpenHow { exec: true, ..Default::default() };
        let fd = fs_generic::generic_openat2(at, path, flags, 0, how).map_err(|e| e.as_c_int())?;
        File(fd).checked_for_exec()
    }

    /// A descriptor the caller already holds, to run what it is open on:
    /// `execveat(fd, "", AT_EMPTY_PATH)`. Takes a reference of its own, which
    /// the `Drop` gives back, and asks the same questions `open_exec` asks of
    /// a file it opened. This is what lets a memfd, or a file that has been
    /// unlinked since it was opened, be executed -- neither has a name a
    /// second open could find.
    ///
    /// Safe since 2026-09-30: it took a `*mut ffi::fd` and a contract saying
    /// the caller held a reference, which an [`fs_fdobj::FdRef`] is.
    pub fn from_descriptor(fd: fs_fdobj::FdRef) -> Result<(File, ffi::statbuf), c_int> {
        File(fd.retain()).checked_for_exec()
    }

    /// `may_open`'s two refusals and `open_exec`'s write denial, on an open
    /// file.
    fn checked_for_exec(self) -> Result<(File, ffi::statbuf), c_int> {
        let file = self;
        let stat = file.stat()?;
        const S_IFMT: u32 = 0o170000;
        const S_IFREG: u32 = 0o100000;
        if stat.mode & S_IFMT != S_IFREG {
            return Err(EACCES);
        }
        // If nobody has permission to execute, it should be safe not to execute.
        if stat.mode & 0o111 == 0 {
            return Err(EACCES);
        }
        // A file some process holds open for writing is ETXTBSY, and while
        // this descriptor lives nobody may open it for writing: Linux's
        // `exe_file_deny_write_access`. The program's descriptor is retained
        // by the address space, so the denial lasts as long as the process
        // runs it, and is shared unchanged by a fork; an interpreter's is
        // dropped once the interpreter is loaded, which is when Linux allows
        // writes to it again. `close` undoes it, by the marker.
        if let Some(inode) = file.inode() {
            let err = fs_inode::inode_deny_write_access(inode);
            if err < 0 {
                return Err(err);
            }
            file.set_denies_write(true);
        }
        Ok((file, stat))
    }
}

/// The fields, read through `Owned`'s own `Deref`.
impl std::ops::Deref for File {
    type Target = ffi::fd;
    fn deref(&self) -> &ffi::fd {
        &self.0
    }
}

impl File {
    /// The mount's `fstat` of this descriptor.
    ///
    /// One of the three adapters the trait's `fstat` used to need, and now a
    /// `?` over what it answers: `EACCES` for a filesystem that does not do
    /// `fstat` at all, which is this caller's reading of `None`.
    fn stat(&self) -> Result<ffi::statbuf, c_int> {
        let mount = self.mount();
        mount.and_then(|m| m.fs).and_then(|fs| fs.fstat(self)).ok_or(EACCES)?
    }

    /// The description, as the pointer the callees that have not been
    /// converted still take.
    pub fn as_ptr(&self) -> *mut ffi::fd {
        self.0.as_ptr()
    }

    /// Another reference to the description, for `mem.image.exefile`.
    pub fn share(&self) -> fs_fdobj::Owned {
        self.0.clone()
    }

    /// The driver, if it can do what loading an image needs.
    ///
    /// `EIO` for one that cannot seek or cannot read: a file this kernel
    /// cannot walk is not a program it can start.
    fn driver(&self, want: fn(&ffi::Caps) -> bool) -> Result<&'static dyn ffi::FdOps, c_int> {
        self.ops.filter(|ops| want(&ops.caps())).ok_or(EIO)
    }

    fn seek(&self, off: i64) -> Result<(), c_int> {
        if self.driver(|c| c.seek)?.lseek(self, off, SEEK_SET) < 0 {
            return Err(EIO);
        }
        Ok(())
    }

    /// Reads at most `buf.len()` bytes from `off`. Answers how many.
    fn read_at(&self, off: i64, buf: &mut [u8]) -> Result<usize, c_int> {
        self.seek(off)?;
        let n = self.driver(|c| c.read)?.read(self, buf);
        if n < 0 {
            return Err(EIO);
        }
        Ok(n as usize)
    }

    /// Reads exactly `buf.len()` bytes, or answers `ENOEXEC` — a file too short
    /// for its own headers is not a program.
    fn read_exact_at(&self, off: i64, buf: &mut [u8]) -> Result<(), c_int> {
        if self.read_at(off, buf)? != buf.len() {
            return Err(ENOEXEC);
        }
        Ok(())
    }
}

/// The header and the program header table, both checked.
struct Image {
    header: elf::HeaderInfo,
    segments: Vec<elf::Segment>,
}

impl Image {
    /// The bytes of an ELF header, handed to the crate to check. It used to be
    /// read straight into a struct and the fields taken as they came;
    /// `crates/kernel/elf` says what that cost.
    fn read(file: &File) -> Result<Image, c_int> {
        let mut bytes = [0u8; 64];
        file.read_exact_at(0, &mut bytes)?;
        let header = elf::parse_header(&bytes)?;

        // `phnum` is bounded by parse_header, so this allocation is bounded
        // with it -- it used to be sized from a sixteen-bit count the file
        // chose.
        let want = elf::phdr_bytes(header.phnum);
        let mut table = Vec::new();
        table.try_reserve(want).map_err(|_| ENOMEM)?;
        table.resize(want, 0);
        file.read_exact_at(header.phoff as i64, &mut table)?;
        let segments = elf::parse_segments(&table, header.phnum, PAGE_SIZE)?;
        Ok(Image { header, segments })
    }

    /// Same, for an interpreter: an unparsable one is `ELIBBAD` rather than
    /// `ENOEXEC`, because the file the guest named *was* a program.
    fn read_interp(file: &File) -> Result<Image, c_int> {
        Image::read(file).map_err(|e| if e == ENOEXEC { ELIBBAD } else { e })
    }

    fn fits(&self) -> Result<(), c_int> {
        if elf::segments_fit(&self.segments, ffi::USER_ADDR_MAX_PAGE) {
            Ok(())
        } else {
            Err(EINVAL)
        }
    }

    /// A hole big enough for the whole image, in bytes.
    ///
    /// `vaddr + memsize` was added and rounded up without a check and a file
    /// chooses both numbers, so an end that wrapped asked for a hole the image
    /// does not fit in. 0 pages is what "nothing to place" comes to.
    fn find_hole(&self, held: &mut MemWrite) -> u64 {
        let pages = elf::span_pages(&self.segments, PAGE_SIZE).unwrap_or(0);
        let page = held.find_hole(pages);
        (page as u64) << ffi::PAGE_BITS
    }
}

const PAGE_SIZE: u64 = 4096;


/// One `PT_LOAD`, mapped where `crates/kernel/elf` says it goes.
///
/// Every number below arrives from the *file* — an overflowing `vaddr + bias`
/// that aliased onto a low page, a 32-bit bss difference that truncated four
/// gigabytes to none, a tail that was a whole page when the file ended exactly
/// on a boundary, and a text segment that was never marked executable — which
/// is why the arithmetic is somewhere it can be asserted rather than inline.
///
/// Called with `mem->lock` held for writing, and gives it up around the
/// zero-fill: the guest-memory helpers must not be called with it held.
fn load_entry(
    seg: &elf::Segment,
    bias: u64,
    file: &File,
    held: &mut MemWrite,
) -> Result<(), c_int> {
    let at = elf::place(seg, bias, PAGE_SIZE, ffi::USER_ADDR_MAX_PAGE)?;

    let mut flags = 0u32;
    if at.readable {
        flags |= ffi::P_READ;
    }
    if at.writable {
        flags |= ffi::P_WRITE;
    }
    if at.executable {
        flags |= ffi::P_EXEC;
    }

    if at.map_pages != 0 {
        let ops = file.ops.ok_or(EIO)?;
        // `EIO` and not `mmap(2)`'s `ENODEV`: this is not serving a guest's
        // `mmap` call, it is the loader failing to place a segment.
        let err = unsafe {
            ops.mmap(
                file,
                held.mem(),
                at.map_page,
                at.map_pages,
                at.file_offset as i64,
                flags as c_int,
                ffi::MMAP_PRIVATE as c_int,
            )
        }
        .ok_or(EIO)?;
        if err < 0 {
            return Err(err);
        }
        // Not shared: an ELF segment is mapped MAP_PRIVATE above. The
        // reference is taken by `set_file_backing` and given back by the
        // mapping's destructor.
        held.set_file_backing(at.map_page, file.share(), at.file_offset as usize, false);
    }

    if at.tail_len != 0 {
        held.without(|| user_memset(at.tail_at, 0, at.tail_len))?;
    }
    if at.bss_pages != 0 {
        held.map_nothing(at.bss_page, at.bss_pages, flags).map_err(guest_errno::Errno::as_c_int)?;
    }
    Ok(())
}

/// Zero a range of guest memory a byte at a time.
///
/// The tail of a segment, which is under a page and usually a few bytes. It is
/// bytewise because the range is not necessarily writable through one mapping.
fn user_memset(start: u64, val: u8, len: u64) -> Result<(), c_int> {
    let zeros = [val; 256];
    let mut at = start;
    let mut left = len;
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        if usercopy::GuestMem.write(at, &zeros[..n]) != 0 {
            return Err(EFAULT);
        }
        at += n as u64;
        left -= n as u64;
    }
    Ok(())
}

/// An ELF interpreter: the name `PT_INTERP` gave, the file it opened, and its
/// headers.
type Interpreter = (CString, File, Image);

/// Whether the caller may read a file the exec opened: Linux's `would_dump`,
/// asked of the program, of a `#!` interpreter and of an ELF interpreter. A
/// process may not read the memory of a program any one of them it could not
/// read, so one that is unreadable leaves the new image undumpable.
fn readable(stat: &ffi::statbuf) -> bool {
    taskview::with_current_creds(|c| c.may_read(stat.uid, stat.gid, stat.mode)).unwrap_or(false)
}

/// The interpreter a `PT_INTERP` segment names, if there is one, and whether
/// the caller may read it.
///
/// Two interpreters is `EINVAL`: a file cannot ask for two.
fn find_interpreter(file: &File, image: &Image) -> Result<Option<(Interpreter, bool)>, c_int> {
    let mut found: Option<(Interpreter, bool)> = None;
    for seg in &image.segments {
        if seg.kind != elf::PT_INTERP {
            continue;
        }
        if found.is_some() {
            return Err(EINVAL);
        }

        // The segment's size comes out of the file, and what is read from it is
        // used as a path. Unbounded, a large one is a large allocation; too
        // small, and there is no room for a name and its terminator. Linux
        // requires the same two bounds.
        let max_path = ffi::MAX_PATH as u64;
        if seg.filesize < 2 || seg.filesize > max_path {
            return Err(EINVAL);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve(seg.filesize as usize)
            .map_err(|_| ENOMEM)?;
        bytes.resize(seg.filesize as usize, 0);
        file.read_exact_at(seg.offset as i64, &mut bytes)
            .map_err(|e| if e == ENOEXEC { EIO } else { e })?;

        // `interp_path` finds the terminator inside the bytes that were read
        // and answers what precedes it. Taking the segment as a C string
        // instead -- which is what this did -- ran off the end of the
        // allocation when the file did not put a NUL there, confirmed under
        // AddressSanitizer as a read of the exact segment size.
        let name = elf::interp_path(&bytes)?;
        let name = CString::new(name).map_err(|_| EINVAL)?;

        let (interp, stat) = File::open_exec(ffi::At::Pwd, &name, false)?;
        let header = Image::read_interp(&interp)?;
        found = Some(((name, interp, header), readable(&stat)));
    }
    Ok(found)
}

/// What a loaded image leaves for the rest of `execve`: whether the caller
/// could read every interpreter, and the credentials the image runs with.
pub(crate) struct Started {
    pub interpreters_readable: bool,
    pub creds: kernel_creds::Exec,
}

/// The file's `security.capability`, decoded: `get_file_caps`. None for a file
/// without one and for a mount that keeps no attributes; `EINVAL` for one that
/// is malformed, which fails the exec as it does on Linux.
fn file_caps(file: &File) -> Result<Option<kernel_creds::caps::FileCaps>, c_int> {
    let mut value = [0u8; 64];
    let n = fs_generic::generic_fxattr(
        file,
        ffi::XattrCall::Get { name: c"security.capability", out: &mut value },
    );
    if n < 0 {
        // ENODATA, EOPNOTSUPP and the rest: no capabilities, as an attribute
        // Linux cannot read is none.
        return Ok(None);
    }
    kernel_creds::caps::file_caps_from_xattr(&value[..n as usize])
}

/// The credentials this file starts with, before anything is torn down: a
/// file whose capabilities cannot be honoured is `EPERM` to the caller, whose
/// program is still there to be told (`begin_new_exec` asks first too).
fn exec_creds(file: &File) -> Result<kernel_creds::Exec, c_int> {
    let stat = file.stat()?;
    let exec = kernel_creds::ExecFile {
        mode: stat.mode,
        uid: stat.uid,
        gid: stat.gid,
        caps: file_caps(file)?,
        no_new_privs: taskview::with_current_attr(|a| a.no_new_privs()).unwrap_or(false),
    };
    taskview::with_current_creds(|c| c.exec(&exec)).expect("execve runs in a task")
}

/// Load an ELF image over the calling process.
///
/// `ENOEXEC` means "not an ELF file", which is what sends the caller on to the
/// `#!` handler; anything else is a real failure. The credentials are this
/// file's: for a `#!` script, its interpreter's, so a set-id script is not
/// one, as on Linux.
fn elf_exec(file: &File, path: &CStr, argv: &Args, envp: &Args) -> Result<Started, Failed> {
    let image = Image::read(file).map_err(Failed::Recoverable)?;
    let (interp, interp_readable) = match find_interpreter(file, &image).map_err(Failed::Recoverable)? {
        Some((interp, readable)) => (Some(interp), readable),
        None => (None, true),
    };

    // The last moment at which saying "it does not fit" is any use. The
    // interpreter is checked too: it is named by the executable, so a crafted
    // image chooses it.
    image.fits().map_err(Failed::Recoverable)?;
    if let Some((_, _, ref h)) = interp {
        h.fits().map_err(Failed::Recoverable)?;
    }
    let creds = exec_creds(file).map_err(Failed::Recoverable)?;

    // ---------------------------------------------------------------- here
    // Free the process's memory. From this point on, if any error occurs the
    // process will have to be killed before it even starts. Please don't be too
    // sad about it, it's just a process.
    //
    // The other threads first, which is Linux's `begin_new_exec`: they end as
    // in a group exit and this one takes the leader's pid, so what follows
    // happens to a process of one thread. A group already exiting, or another
    // thread's exec, ends this one instead (`execthreads_probe`).
    let old_tid = exitcalls::de_thread().map_err(Failed::Killed)?;
    // A table shared with another *process* by CLONE_FILES is copied, so the
    // close-on-exec pass and the new program's descriptors are this
    // process's alone: Linux's `unshare_files`, measured.
    fdcalls::unshare_files().map_err(|e| Failed::Fatal(e.as_c_int()))?;

    // general_lock protects current->mm: otherwise procfs might read the
    // pointer before it is released and then try to lock it after.
    // The old address space is what the new one inherits its prctl flags
    // from -- MDWE and the THP setting survive an exec on Linux. Read here,
    // before the swap, while `mm` is still this thread's.
    // Read outside `general_lock`, which is where it always was: the lock below
    // is about the *swap*, and this is a read of the space this thread is still
    // running in. `Acquire` rather than a plain load because the group-exit
    // valve can null this word from another thread -- see the field comment.
    //
    // The robust list and any PI futex this thread holds go first, while the
    // old space is still there to walk: Linux's `exec_mm_release` does both,
    // and a list left registered would be walked at exit through the *new*
    // image's memory. Whether another process still uses the old space -- a
    // `vfork` parent, a CLONE_VM sibling -- decides whether the
    // `set_tid_address` word is written first, as `mm_users > 1` does for
    // Linux; the slot's count and this clone are the two that are not users.
    let mm_shared = taskview::with_current_task(|t| {
        let _held = taskcalls::GeneralGuard::of(t);
        // SAFETY: `general_lock` excludes the slot's other writers.
        unsafe { t.mm.clone_arc() }
    })
    .flatten()
    .is_some_and(|mm| std::sync::Arc::strong_count(&mm) > 2);
    futexcalls::futex_exec_release(old_tid, mm_shared);
    let new_mm = taskview::with_current_mm(|old| mmapcalls::mm::mm_new_from(Some(old)))
        .unwrap_or_else(|| mmapcalls::mm::mm_new_from(None));
    // The swap *is* the detach and the attach; the old space goes after
    // `general_lock` is released.
    drop(taskcalls::replace_current_mm(new_mm));

    let placed = place_image(file, path, &image, interp.as_ref())?;
    finish_stack(path, argv, envp, &image, &placed, &creds)?;
    Ok(Started { interpreters_readable: interp_readable, creds })
}

/// Try each format in turn: ELF, then `#!`. Answers whether the caller could
/// read every interpreter the image went through -- the program itself is the
/// caller's to ask about -- and the credentials it runs with.
pub(crate) fn format_exec(
    file: &File,
    path: &CStr,
    argv: &Args,
    envp: &Args,
    depth: u32,
) -> Result<Started, Failed> {
    match elf_exec(file, path, argv, envp) {
        Err(Failed::Recoverable(e)) if e == ENOEXEC => {}
        other => return other,
    }
    if depth >= MAX_NESTING {
        return Err(Failed::Recoverable(ELOOP));
    }
    shebang_exec(file, path, argv, envp, depth + 1)
}

/// A `#!` line: run the interpreter it names with the script as its argument.
///
/// The line itself is `crates/kernel/shebang`. Three things it settles that
/// were wrong here, all measured against a real arm64 kernel:
///
///   - The buffer is 256 bytes, which is Linux's `BINPRM_BUF_SIZE`. This read
///     128, so a longer line had its *argument* silently cut in half.
///   - A truncated interpreter path is `ENOEXEC` rather than something to
///     execute. Running whatever the shortened name happens to hit is running a
///     different program than the script asked for; the same script exited 127
///     here and 0 on Linux, where the `ENOEXEC` sends a shell back to
///     interpreting the file itself.
///   - A truncated *argument* is fine: the interpreter re-reads the script.
///
/// The read is **not padded**. A short read is how the crate knows the file
/// ended, and padding it would turn "no more file" into "we stopped looking".
fn shebang_exec(
    file: &File,
    path: &CStr,
    argv: &Args,
    envp: &Args,
    depth: u32,
) -> Result<Started, Failed> {
    let mut header = [0u8; 256];
    let n = file.read_at(0, &mut header).map_err(Failed::Recoverable)?;

    let line = shebang::parse(&header[..n]).ok_or(Failed::Recoverable(ENOEXEC))?;
    let span = |(at, len): (usize, usize)| &header[at..at + len];
    let interpreter = span(line.interp);
    let argument = line.argument.map(span);

    // The interpreter, its one optional argument, the script's path in place of
    // the caller's argv[0], and everything else the caller passed.
    // crates/kernel/execargs owns the arithmetic, because both defects this
    // rewrite has had were counting: an empty argv has no argv[0] to drop, and
    // `count - 1` on a size_t zero is about 2^64, which the size walk then
    // followed off the end of a 128 KB buffer. argc 0 is legal and Linux runs
    // the script.
    let (buf, count) = execargs::shebang(
        interpreter,
        argument,
        path.to_bytes(),
        argv.bytes(),
        argv.count,
        crate::arg_limit(),
    )
    .map_err(Failed::Recoverable)?;
    let new_argv = Args { buf, count };

    let interp_path = CString::new(interpreter).map_err(|_| Failed::Recoverable(ENOEXEC))?;
    let (interp, stat) =
        File::open_exec(ffi::At::Pwd, &interp_path, false).map_err(Failed::Recoverable)?;
    let interp_readable = readable(&stat);
    let mut started = format_exec(&interp, &interp_path, &new_argv, envp, depth)?;
    started.interpreters_readable &= interp_readable;
    Ok(started)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recoverable_failure_and_a_fatal_one_carry_the_same_errno() {
        // The distinction is what the caller may do next, not what the guest
        // is told: a fatal one has already replaced the address space.
        assert_eq!(Failed::Recoverable(ENOEXEC).errno(), Some(ENOEXEC));
        assert_eq!(Failed::Fatal(ENOMEM).errno(), Some(ENOMEM));
        assert_eq!(Failed::Killed(9).errno(), None, "a thread being ended answers nothing");
        assert_ne!(Failed::Recoverable(ENOMEM), Failed::Fatal(ENOMEM));
    }

    #[test]
    fn the_stack_addresses_of_a_flat_list_are_its_own_offsets() {
        // The C found each string's end with a per-byte read of *guest* memory
        // after copying it there. The buffer it was copied from has the same
        // layout, so the offsets are already known.
        let args = Args {
            buf: b"one\0two\0three\0\0".to_vec(),
            count: 3,
        };
        assert_eq!(
            stack::string_addrs(&args, 0x1000),
            vec![0x1000, 0x1004, 0x1008]
        );
    }

    #[test]
    fn an_empty_list_produces_no_addresses() {
        let args = Args {
            buf: b"\0".to_vec(),
            count: 0,
        };
        assert!(stack::string_addrs(&args, 0x1000).is_empty());
    }

    #[test]
    fn a_count_past_the_end_of_the_buffer_stops_at_the_buffer() {
        // A count that disagrees with its bytes is a value the caller has to
        // handle rather than a walk off the end.
        let args = Args {
            buf: b"one\0".to_vec(),
            count: 5,
        };
        assert_eq!(
            stack::string_addrs(&args, 0).len(),
            2,
            "one address, then the end"
        );
    }

    #[test]
    fn basename_of_a_bare_name_is_the_name() {
        assert_eq!(stack::basename(b"node"), b"node");
        assert_eq!(stack::basename(b"/usr/bin/node"), b"node");
        assert_eq!(stack::basename(b"/usr/bin/"), b"");
    }
}

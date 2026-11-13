//! Argument, environment, and execution tracing support.

use super::*;
use std::ffi::c_uint;

/// An argument or environment list: `count` NUL-terminated strings one after
/// another, and then one more NUL.
///
/// The format and every operation on it are `crates/kernel/execargs` — both
/// defects it has had were counting, and the crate's walk is bounded by the
/// buffer where the C's trusted the count.
///
/// A `Vec` rather than the C's `malloc(ARGV_MAX)`: `ARGV_MAX` is 128 KB and
/// there can be four of these live at once when `#!` nests, where the actual
/// list is usually a few hundred bytes. The bound is still 128 KB, and every
/// operation that grows the list is given it.
pub struct Args {
    pub buf: Vec<u8>,
    pub count: usize,
}

impl Args {
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    /// An empty list: no strings, and the terminator that ends one.
    pub(super) fn empty() -> Args {
        Args {
            buf: vec![0],
            count: 0,
        }
    }
}

/// An environment variable this kernel forces onto every `execve`.
///
/// `replace` says whether a value the caller set is overwritten or left alone.
///
/// **The name is not written down twice.** The C carried a byte count beside
/// each string saying how much of it was the variable's name, and
/// `PYTHONDONTWRITEBYTECODE=1`'s was 25 where it is 24 — so the "is it already
/// set" test compared the value as well as the name, and a guest that had set
/// that variable to anything else got a *second* copy appended. musl and glibc
/// both answer `getenv` with the first match, so the injection was inert and
/// the duplicate showed up in `env`.
pub(super) struct Inject {
    pub(super) kv: &'static [u8],
    pub(super) replace: bool,
}

impl Inject {
    /// How much of `kv` is the name and the `=`. Derived, so it cannot
    /// disagree with the string it describes; `GODEBUG=asyncpreemptoff=1` has
    /// two, and the first one is the one that ends the name.
    pub(super) fn prefix(&self) -> usize {
        self.kv
            .iter()
            .position(|&b| b == b'=')
            .expect("a NAME=value entry")
            + 1
    }
}

/// The list, with the reason for each.
pub(super) const INJECT_ENV: &[Inject] = &[
    // Bypass pymalloc's arenas. Always replaces: a caller that set it to
    // something else gets malloc anyway.
    Inject {
        kv: b"PYTHONMALLOC=malloc",
        replace: true,
    },
    Inject {
        kv: b"NO_COLOR=1",
        replace: false,
    },
    Inject {
        kv: b"PIP_PROGRESS_BAR=off",
        replace: false,
    },
    // Skip .pyc generation, to reduce allocations.
    Inject {
        kv: b"PYTHONDONTWRITEBYTECODE=1",
        replace: false,
    },
    // Go async preemption sends SIGURG and reads and modifies mcontext at a
    // fixed offset. This JIT delivers signals at gadget boundaries rather than
    // at the exact interrupted instruction, so the pc in the signal frame is
    // imprecise; cpu_poke reduces the latency but cannot fix the precision.
    // Cooperative preemption -- function-call checkpoints -- works correctly.
    Inject {
        kv: b"GODEBUG=asyncpreemptoff=1",
        replace: false,
    },
    // Limit Go threads, to reduce TLB stale-pointer crashes from concurrent
    // page table modifications. Two is enough for most Go CLI tools.
    Inject {
        kv: b"GOMAXPROCS=2",
        replace: false,
    },
    // libuv's default worker pool is four threads. On jitless node a short
    // script never uses them but pays the futex sync cost; one saves about a
    // second on `node -e 0`. A program that genuinely needs more can override
    // it, which is what replace: false means.
    Inject {
        kv: b"UV_THREADPOOL_SIZE=1",
        replace: false,
    },
];

/// V8 flags for `node`, to work around scope corruption under emulation.
///
/// `--jitless` disables V8's own code generation, which this JIT cannot run;
/// `--no-lazy` compiles eagerly, avoiding the Zone reuse patterns that corrupt
/// scopes; the three `--no-concurrent`/`--no-lazy-compile` flags and
/// `--predictable` make V8 single-threaded, because in jitless mode the worker
/// pool has no JIT work to do and its threads spend about three seconds per
/// startup blocked on futex and epoll waiting for the (slow, emulated) main
/// thread. Validated 2026-05-05 against a syscall profile: `node -e 0` went
/// from 2.3s to 0.35s.
const NODE_FLAGS: &[&[u8]] = &[
    b"--jitless",
    b"--no-lazy",
    b"--max-old-space-size=512",
    b"--no-concurrent-marking",
    b"--no-concurrent-recompilation",
    b"--no-lazy-compile-dispatcher",
    b"--predictable",
];

/// LD_PRELOAD for `zero_free.so`, which zeros blocks of 4096 bytes and up on
/// both malloc and free: V8's Zone allocator reuses freed memory without
/// zeroing, and a Zone segment is 8 KB or more, so a stale compressed pointer
/// survives into a real pointer field.
///
/// `replace: false` — an `LD_PRELOAD` the caller chose is one it needs, and
/// replacing it would be this kernel overruling the program it is running.
pub(super) const LD_PRELOAD: Inject = Inject {
    kv: b"LD_PRELOAD=/lib/zero_free.so",
    replace: false,
};

/// Polyfills injected only if the file is actually in the guest filesystem.
/// The WebAssembly shim must load first.
pub(super) const NODE_REQUIRES: &[(&[u8], &CStr)] = &[
    (b"--require=/lib/wasm-polyfill.js", c"/lib/wasm-polyfill.js"),
    (
        b"--require=/lib/fetch-polyfill.js",
        c"/lib/fetch-polyfill.js",
    ),
];

/// The most the arguments and environment of one `execve` may come to, in
/// bytes: Linux's `bprm_stack_limits`. A quarter of the stack limit, between
/// `ARG_MAX` (128 KB) and three quarters of `_STK_LIM` (6 MB) -- so 2 MB under
/// the usual 8 MB stack, and 6 MB under this kernel's 128 MB default. The
/// pointers the new program's `argv[]` and `envp[]` take come out of the same
/// allowance, which [`fits`] accounts for.
///
/// This was `ARGV_MAX`, 128 KB, for the total: a `find | xargs` that a real
/// kernel runs in one exec was `E2BIG` here at a tenth of the size.
pub(crate) fn arg_limit() -> usize {
    const ARG_MAX: u64 = 128 * 1024;
    const STK_LIM: u64 = 8 * 1024 * 1024;
    let limit = (STK_LIM / 4 * 3).min(stack_rlimit() / 4).max(ARG_MAX);
    usize::try_from(limit).unwrap_or(usize::MAX)
}

/// The calling process's `RLIMIT_STACK`, soft.
fn stack_rlimit() -> u64 {
    const RLIMIT_STACK: c_uint = 3;
    taskview::with_current_group(|g| g.limits.get(RLIMIT_STACK))
        .flatten()
        .map_or(8 * 1024 * 1024, |limit| limit.cur)
}

/// Whether two lists fit the allowance together, pointers included -- the
/// second half of `bprm_stack_limits`, asked once both have been read, since
/// each was read against the whole limit on its own.
pub(super) fn fits(argv: &Args, envp: &Args) -> bool {
    const PTR: usize = 8;
    let pointers = (argv.count.max(1) + envp.count) * PTR;
    let strings = argv.bytes().len() + envp.bytes().len();
    let limit = arg_limit();
    pointers < limit && strings <= limit - pointers
}

/// A bound for the injections: what is left of the allowance is theirs to
/// use, best-effort.
pub(super) fn argv_max() -> usize {
    arg_limit()
}

/// Apply every injection. Best-effort, as it was: one that does not fit leaves
/// the list alone and the `execve` goes ahead. Failing an `execve` because a
/// workaround did not fit would be worse than the workaround being absent.
pub(super) fn inject(path: &[u8], argv: &mut Args, envp: &mut Args) {
    for e in INJECT_ENV {
        if let Some((buf, count)) = execargs::set_env(
            envp.bytes(),
            envp.count,
            e.kv,
            e.prefix(),
            e.replace,
            argv_max(),
        ) {
            *envp = Args { buf, count };
        }
    }

    if basename(path) != b"node" {
        return;
    }
    // After argv[0], which is where an interpreter's own options belong:
    // before the script's arguments rather than after them.
    let mut flags: Vec<&[u8]> = NODE_FLAGS.to_vec();
    for (flag, file) in NODE_REQUIRES {
        if File::open(file).is_ok() {
            flags.push(flag);
        }
    }
    for f in flags {
        if let Some((buf, count)) = execargs::insert_arg(argv.bytes(), argv.count, f, argv_max()) {
            *argv = Args { buf, count };
        }
    }

    if let Some((buf, count)) = execargs::set_env(
        envp.bytes(),
        envp.count,
        LD_PRELOAD.kv,
        LD_PRELOAD.prefix(),
        false,
        argv_max(),
    ) {
        *envp = Args { buf, count };
    }
}

/// A guest `char *[]`, bounded by the argument limit.
///
/// One read at the limit: the buffer grows with what is read (see
/// `execargs::read_array`), so trying 128 KB first and the limit after, which
/// existed to zero less, buys nothing now.
pub(super) fn read_array(addr: u64) -> Result<Args, c_int> {
    let (buf, count) = execargs::read_array(&usercopy::GuestMem, addr, arg_limit())?;
    Ok(Args { buf, count })
}

/// `argv`, as Linux reads it since 5.18: a null pointer is an empty list, and
/// an empty list becomes one empty string, so that no program starts with
/// `argc` 0 and `argv[0]` null -- which is what a multi-call binary reads to
/// pick what it is, and what a `SIGSEGV` at start-up looked like here. A
/// null `envp` is an empty list too, and stays one.
pub(super) fn read_argv(addr: u64) -> Result<Args, c_int> {
    let argv = if addr == 0 {
        Args::empty()
    } else {
        read_array(addr)?
    };
    if argv.count == 0 {
        return Ok(Args {
            buf: vec![0, 0],
            count: 1,
        });
    }
    Ok(argv)
}

/// One line per exec, opt-in through `IUL_EXEC_TRACE`. Correlates a V8 crash
/// with the command that produced it.
pub(super) fn exec_trace(path: &CStr, argv: &Args) {
    if !util_iulenv::env().exec_trace {
        return;
    }
    let mut line = String::new();
    for (i, s) in argv
        .bytes()
        .split(|&b| b == 0)
        .take(argv.count.min(8))
        .enumerate()
    {
        if i > 0 {
            line.push(' ');
        }
        line.push_str(&String::from_utf8_lossy(&s[..s.len().min(200)]));
    }
    // Under `pids_lock`, which it did not take until 2026-09-30: a parent
    // found through the tree can be freed the moment the lookup returns, and
    // this read its pid after.
    let ppid = kernel_pids::PidsGuard::take()
        .me()
        .and_then(kernel_pids::Task::parent)
        .map_or(0, |p| p.pid());
    let msg = format!(
        "EXEC[pid={} ppid={ppid}]: {} [{line}]",
        taskview::current_pid(),
        path.to_string_lossy(),
    );
    logline::printk(&msg);
}

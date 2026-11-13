# CLAUDE.md

不需要时刻保持零回归; 保持在当前分支;
c都需要迁移到rust; 汇编只保留热路径 gadget 和调用约定跳板, 其余以后也迁到rust (见下文 Assembly); 如果迁移困难, 可以考虑重写, 写好测试;
移除不需要的unsafe,不要完全按照c一比一翻译,充分利用rust的语言特性;
然后优化crates的结构;

## What this repository is

A userspace Linux emulator engine for iOS: it runs an **AArch64 Linux guest** on Apple Silicon
through a threaded-code interpreter (*Asbestos*). Licensed AGPL-3.0 (`LICENSE`). A small part
descends from iSH and ish-arm64 and stays GPLv3 (`LICENSES/`); neither is an upstream to merge
from, and nothing here needs to keep their shape.

Everything except `asbestos/guest-arm64/gadgets-aarch64/*.S` is Rust. What is left of C:
`iul.h` (the embedder interface), the headers the assembly includes (`gadgets.h`,
`gadgets-generic.h`, `emu/interrupt.h`), `tests/integration/sbm_api_test.c` (checks that `iul.h`
compiles and links from C) and `tests/integration/unit.h`.

**Assembly** is to shrink, not a permanent exception. A gadget needs the gadget register
convention (`x1` cpu, `x2` tlb, `x28` the stream), no frame, and a `br` to the next one, which a
Rust function cannot give; so what stays hand-written is the hot path (ALU, load/store with the
inline TLB lookup, branches and chaining, compares), `fiber_enter`/`fiber_exit`, and the
trampolines between that convention and the C ABI. Slow paths (atomics, exclusives, LD2-4/ST2-4,
crypto, rare SIMD) are to become Rust behind **one** helper gadget that calls a function pointer
from the stream and owns the only segfault exit (`fault_code_pc`, the real fault address,
`was_write`): ten hand-copied exits missed `fault_code_pc`, see `fault_pc`. Measure a family
before taking it off the hot path. What is left may then move into `global_asm!`/`naked_asm!`, so
offsets come from `offset_of!` as `const` operands instead of `cpu-offsets.h`. The helper is
`slow_call` (`emu_abi::SlowFn`, `Gen::slow_call`); atomics, LDXP/STXP/CASP, LD2-4/ST2-4,
IC IVAU, the crypto/TBL group and the vector immediate shifts run through it (2026-10-17).
STXR stays in assembly: through `slow_call` it cost 6.5% on `atomic_bench`.

**Deliverable.** `.github/workflows/static-libs.yml` builds `libiul.a` for `iphoneos` and
`iphonesimulator` when a `vX.Y.Z` tag is pushed and publishes them, with `iul.h`, as that
release (`libiul-iphoneos.a`, `libiul-iphonesimulator.a`). An embedder links `libiul.a` plus `-lsqlite3` and includes `iul.h`. (`libish_emu.a` and `libfakefs.a` were
meson's split of the C; both became Rust inside `libiul.a` and were removed on 2026-09-30.)

No submodules. `docs/` and `benchmark/` were removed on 2026-09-30; comments still cite
`docs/...` files, which are readable with `git show d656e2d35:<path>`.

## Build

Host must be arm64 macOS (the only gadget set is `gadgets-aarch64`). Needs python3, clang + lld
(`brew install llvm lld`), sqlite3, cargo. There is no meson.

```bash
tools/build-all.sh                       # into build/
tools/build-all.sh build-release --release
cargo build -p iul-cli                   # the CLI
cargo build -p iul                  # libiul.a, the whole engine
```

`build-all.sh` produces `build/iul`, `build/libiul.a`,
`build/sbm_api_test`, `build/libfakefs_redirect.dylib`, `build/tools/{fakefsify,unfakefsify}` and
`build/iul-build.env` (the flags and environment it was built with, so integration scripts rebuild
the same configuration). Each piece has its own script, `tools/build-{libs,cli,embedder-example,
redirect-dylib,fakefsify}.sh`; shared logic is `tools/build-common.sh`.

`install_output` **renames** outputs into place: macOS caches a code signature per inode, and
`cp` over an executed binary gets the next `execve` SIGKILLed with no output.

**Build flags** are one environment variable, `TMPFS_RS_CLANG_ARGS`, read only by
`crates/util/buildcfg`, which turns `-DNAME` into `cfg(iul_name)`. Give each flag set its own
`CARGO_TARGET_DIR`, or switching flags rebuilds the tree.

**Outside the main checkout (a worktree, a copy), build with `KACHE_BUILD_SCRIPT_CACHE=0`.**
kache (`rustc-wrapper` in `~/.cargo/config.toml`) caches build-script runs and maps only the
package's own roots. `crates/asbestos/gadgets` declares `rerun-if-changed` on the repo root's
`gadgets.h` by absolute path, so a second checkout finds the first checkout's recorded run,
hashes the *first* checkout's files, and restores its `OUT_DIR`: stale gadgets linked to new
Rust, while `cargo` reports success. The replayed output also points `cargo`'s own rerun check
at the first checkout, so a build dir that was served once stays stale even with kache off:
use a fresh `CARGO_BUILD_BUILD_DIR` or `cargo clean -p asbestos-gadgets`. After changing a
`.S` or `gadgets.h`, `objdump -d` the result and find the change before timing or testing it.
The main checkout is not affected. Found 2026-09-30; a fix to kache is pending upstream.

### iOS

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
tools/build-libs.sh build-ios    --release --target aarch64-apple-ios
tools/build-libs.sh build-iossim --release --target aarch64-apple-ios-sim
tests/integration/simulator.sh           # guest suite + probes on the iOS simulator
tools/ios-symbol-floor.sh build-ios/libiul.a
```

`IPHONEOS_DEPLOYMENT_TARGET` defaults to 13.0 (`tools/build-common.sh`). A `cfg(target_os =
"macos")` means the *other* branch runs on a phone, and only `simulator.sh` executes it. Host
functions newer than the floor must be looked up with `dlsym` (see realfs's `mkfifoat`).

### Release profile

- One `staticlib` only: `crates/iul` (`["staticlib", "rlib"]`). A Rust staticlib bundles std and
  with LTO exports it as strong globals, so two in one link is a duplicate-symbol error. Add a
  dependency to `crates/iul` instead. Exception: `crates/tools/fakefsredirect`, linked alone into
  the `DYLD_INSERT_LIBRARIES` dylib.
- `opt-level = "z"` + `lto` (not thin). Hot loops may need a per-package override, measured first.
- **No `panic = "abort"`**: C ABI shims `catch_unwind` and return a guest errno, and unbounded
  allocations on such paths use `try_reserve`.

## Test

```bash
tools/checks.sh                    # 28 source analyses; prints "28 checks, 28 passed, 0 failed"
cargo test --workspace > /tmp/ct.log 2>&1; echo "exit $?"   # the exit code, not the count
tests/integration/smoke.sh         # embedder path + guest shell
tests/integration/guest_tests.sh   # tests/guest programs, realfs and fakefs
tests/integration/probe_diff.sh --recorded   # probes vs recorded Linux answers
tests/integration/differential.sh  # guest tests vs a real arm64 kernel (docker/OrbStack)
tests/integration/full.sh          # package managers, toolchains, PostgreSQL (nightly)
```

- `cargo test --workspace` stops at the first failing binary; a lower pass count is the only
  other sign. Check `$?`.
- `tools/checks.sh` also asserts every `tools/*.py` is registered. Each analysis must assert it
  found its subject: an empty scan passing reads as a clean one.
- By hand, not in the suite: `tools/lock-order.py --calls` (follows one call level; a clean run
  is not a proof), `tools/dup-stubs.py` (needs a link log), `cargo clippy --workspace
  --all-targets` (must be clean; rerun after `rustup update`), and
  `cargo clippy --workspace -- -A clippy::all -D clippy::missing_safety_doc`.
- After touching a lock or a layout, run the guest suite under `-DLOCK_DEBUG=1` and compare the
  instruction probes across both layouts with `tools/probe-both-layouts.sh`:

  ```bash
  TMPFS_RS_CLANG_ARGS='-DLOCK_DEBUG=1' CARGO_TARGET_DIR=target-lockdebug \
      tools/build-all.sh build-lockdebug --release
  tests/integration/guest_tests.sh -i build-lockdebug/iul
  ```

- `./build/iul -r <dir>` mounts realfs, `-f <dir>` mounts fakefs. Verifying a fakefs change with
  `-r` executes none of it. `fakefsify --index <fakefs>` writes a `meta.db` for an existing
  `<fakefs>/data`. Give each run a fresh scratch directory and a fresh fakefs image.

### Where a test goes

| Reaches | Home |
| --- | --- |
| A function only | the crate's `#[cfg(test)] mod` |
| Needs the booted kernel or `#[no_mangle]` symbols | the crate's `tests/`, with `iul` as dev-dependency (a `--lib` test compiles the crate twice and duplicates every export) |
| Embedder path | `tests/integration/sbm_api_test.c`, via `smoke.sh` |
| Guest behaviour, syscall semantics | `tests/guest/src/bin/` (Rust, `aarch64-unknown-linux-musl`, `rust-lld`) |
| "What does Linux do" | a probe in `tests/guest/src/bin/`, then `probe_diff.sh` / `differential.sh` |
| POSIX fs semantics on every mount type | `fs_conformance` |

### A finding is not a bug until a test says so

1. Verify the claim against the current code.
2. Write a test that fails without the fix: **back the fix out and watch it go red** (copy the
   file aside; do not use `git stash`/`checkout` for this). A test that passes first time is
   suspect; a test that accepts either answer is not a test.
3. If it cannot be reproduced, report the measurement and open no PR.

- Before asserting an errno, ask a real kernel (`differential.sh`, `probe_diff.sh --record`).
  Man pages have been wrong five times here. Docker's seccomp answers `EPERM` for some calls.
- A probe prints one line per case and asserts nothing; the diff is the finding. Write one
  before reading code.
- A single failure is not a regression and a clean re-run is not a fix. A flaky test makes
  `git bisect` converge on an arbitrary commit.
- Benchmarks need a control (`compute_bench`) and interleaved runs against a worktree at the
  previous commit, release build.

## Rust rules

**Rewrite, do not translate.** Preserve the Linux ABI (syscall semantics, errnos, wire formats)
and the fakefs on-disk format; nothing else is a contract. Use `Arc` over hand-rolled refcounts,
`Result` over sentinels, guards over paired lock/unlock, real collections over intrusive lists.
Where the old behaviour is wrong, fix it and write a test that fails against it.

**`unsafe`**
- The contract goes on the function (`# Safety`), not on every block.
  `clippy::missing_safety_doc` is 0 and `tools/safety-doc-allows.py` forbids suppressing it.
- An exported fn with no pointer parameter, no unsafe operation and no `# Safety` section must
  not be `unsafe`.
- Borrow once at the boundary (`let fd = unsafe { &*fd };`) only when the pointer never leaves
  the function **and** nothing else writes the object. A `&task` is sound (every field written
  after publication is an atomic, a lock, an `UnsafeCell` or an `ArcSlot`; keep it so); a
  `&mut` held across a callback that uses the raw pointer is the aliasing UB that hung release
  builds. Otherwise stay raw and name the other writer.
- Do not wrap `unsafe` in a helper that adds no invariant.
- `static mut`: ask on how many threads it is written. Embedder-assigned symbols, globals under
  `pids_lock`, and assembly-written buffers stay; anything else becomes an atomic or a lock.

**ABI**
- `#[no_mangle]` is an optimisation barrier and makes the symbol interposable. Keep it only for
  what C, assembly or `iul.h` names. `tools/dead-exports.py` reports the rest (reported, not
  failed: which symbols ServerBox links is not known here).
- `extern "C"` only where C calls it or a function pointer crosses a C boundary. Rust-to-Rust
  calls are direct; `tools/rust-c-abi.py` gates it.
- Never `transmute` between function pointers, and watch the places the compiler cannot check
  the convention: `sym f` in `global_asm!`, `f as *const ()` into an integer, and `interpose!`.
- One owner per type. Two Rust types for one layout joined by `.cast()` or `transmute` is a
  second rendering; merge them. Shared C types live in `crates/kernel/abi`, re-exported by
  `crates/kernel/taskview` as `ffi`. Opaque placeholders are gated by
  `tools/placeholder-owners.py`.
- `#[repr(C)]` stays on anything whose layout matters: guest wire formats, what the assembly
  indexes (`tlb_entry`, `cpu_state`), what `iul.h` names. Put a wire format where its offsets
  can be asserted, and decode from a length-checked slice.
- `iul.h` is hand-written; `tools/extern-signatures.py` and `tools/guessed-constants.py` check
  it against the Rust.

**Layering** (`tools/crate-layers.py`, `tools/crate-graph.py`): `util` → `emu` → `asbestos` →
`kernel` + `fs` → `tools`. Every crate is a workspace member and reachable from a shipped root.
When a lower crate needs something from above, in order:
1. Check whether the function is a wrapper over something below you.
2. Move the code to where it belongs.
3. A hook in the lower crate, installed where the first relevant object is created (or in
   `become_first_process` / `crates/kernel/boot`'s `install_run_hooks`). Test the wiring with a
   `hooks_installed()` assertion, because a missing hook and an absent task look the same.
4. Return the decision (an enum) instead of acting on it.

A `#[repr(C)]` table of `Option<fn>` filled only by Rust is a trait.

**Test doubles**: no `#[no_mangle]` stubs in tests (a second definition `ld` picks between);
substitute with a `use` behind `cfg`, a trait parameter, or depend on the real crate. No
`compile_fail` doctests in crates whose symbols need linking.

**Style**: the tree is not rustfmt-formatted; do not run `cargo fmt`. `cargo clippy --fix` has
applied wrong suggestions (`&*(&raw const x)` → `&x`); review every autofix. There are no
`dead_code`/`unused_*` warnings; keep it that way. `pub` does not mean reachable: narrow to
`pub(crate)` so `dead_code` applies.

## Architecture

- **`crates/tools/iul`**: host CLI. `mount_root()` → `become_first_process()` → `do_execve()` →
  `task_run_current()`. Sets up `/dev`, `/dev/fd`, stdio links and `/dev/shm` (a fakefs, so
  `mmap(MAP_SHARED)` works). An embedder reproduces this; `sbm_api_test.c` is the example.
  `become_first_process()` calls `umask(0)`; the engine applies the guest's umask itself.
- **Syscalls**: `crates/kernel/syscalldispatch`'s `handle_interrupt` dispatches through
  `crates/kernel/syscalltable`. `sys_*` return `Result`/negative guest errnos (`_EINVAL`, leading
  underscore = guest value). Guest memory only via `user_read`/`user_write`/`user_get`/`user_put`;
  never dereference a guest address. `f_get()` returns a referenced `fd` released by
  `syscall_refs_drain()` at syscall return; do not close it. Unimplemented: `syscall_stub`.
  `uname -r` is `7.0.0-iul` and the table covers every number Linux 7.0 assigns (0-471). A number
  left at `ENOSYS` has its reason at its table line (`rseq`: host preemption is not observable;
  `io_uring`, the new mount API, `fanotify`: not built); implement the call, do not lower the
  version.
- **fs**: VFS with fakefs (`crates/fs/fake`, `fakedb`, `fakefs`), realfs (host passthrough; fakefs
  forwards file I/O to it), procfs, sockets, tty/pty, tmpfs, pipes.
- **asbestos**: builds per-block arrays of gadget pointers that tail-call each other (no JIT).
  `crates/asbestos/gen` decodes, `blockcache` caches with RCU-like reclamation. Gadgets reach
  `cpu_state` through `cpu-offsets.h`, generated by `crates/tools/cpuoffsets`. Registers reserved
  by gadgets are in `gadgets.h`; clobbering one corrupts guest state far from the cause.
- **emu**: `cpu_state` (`crates/emu/abi`) and the software TLB (`crates/emu/tlb`).
- **`struct task`** is `#[repr(Rust)]` in `crates/kernel/taskview`; `current` is its
  `thread_local!`. `iul.h` keeps `#define current (task_self())` for embedders.

### fakefs

`data/` (host files, leading `/` stripped) plus `meta.db`: `paths` (path blob → inode) and
`stats` (inode → 16-byte packed stat). The root is the **empty blob**. The schema has one
definition, `crates/fs/fakeschema`; migrations are `crates/fs/fakefs/src/migrate.rs`, indexed by
source version, append-only. `rebuild.rs` runs when `meta.db`'s stored inode no longer matches
(a copied or restored fakefs). Bind mounts and the change-event ring are embedder APIs.

### Native offload

1. Binary: `crates/kernel/offloadexec` (execve of a registered name runs a handler or, on macOS,
   a host binary).
2. Symbol: `crates/asbestos/offloadsym`.
3. Prebuilt gadget: `crates/asbestos/offloadprebuilt`; specs from
   `tools/prebuilt_gadget_gen/gen.sh`.

Test handlers are cargo features of `crates/iul`: `offload-test-symbol`, `offload-test-prebuilt`.
A spec_fn must be optimised (the root `Cargo.toml` overrides it).

### Concurrency

`lock_t` is a pthread mutex with owner tracking (`crates/util/synctypes`). Fields carry
`// locked by X`; keep them accurate. `struct tgroup` has no lock; `task.general_lock` guards
`task.mm` across a swap. `wait_for()` is the interruptible wait and returns `_EINTR`/`_ETIMEDOUT`.
A destructor can take a lock too: `lock-order.py` cannot see a drop.

## Diagnostics

- Log channels (`verbose`, `instr`, `debug`, `strace`, `memory`) via
  `TMPFS_RS_CLANG_ARGS='-DDEBUG_strace=1'`; handler `-DLOG_HANDLER_{SYSLOG,STDERR,NSLOG,OS_LOG}=1`,
  default `dprintf`.
- Hangs with two threads in `__psynch_mutexwait`: build with
  `-DLOCK_SLOW_TRACE=1 -DLOCK_DEBUG=1` and run with `IUL_LOCK_TRACE=1`.
- Store watchpoint: `-DENABLE_WRITE_WATCHPOINT=1`.
- Runtime switches are `IUL_*` env vars; `rg '"IUL_'` for the set.
- `tools/decode-insn.sh` turns an "illegal instruction" word into a mnemonic.

## Conventions

- Commits: `type(scope): summary` (`fix(fs):`, `feat(epoll):`, `opt.:`, `docs:`).
- Comments explain *why*, especially the failure a fix addresses. Several record defects that
  were expensive to find; do not compress them away. A crate's reasoning goes in its module
  comment.
- A fixed defect records symptom, cause, fix and how it was verified in the commit message; if
  the cause was not established, say so, and say whether it was observed or found by reading.
- Non-trivial behaviour changes come with a test in the crate they are about, or a statement of
  why none can reach it.
- Verify in a detached worktree when a full run is needed; set `CARGO_TARGET_DIR` only for the
  cargo steps.

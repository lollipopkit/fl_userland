# iul — Linux on iOS via a native threaded-code interpreter

A userspace Linux emulator for iOS, running **Python, Node.js, Go, Rust and native CLI tools**
directly on iPhone and iPad, emulating an ARM64 Linux guest on Apple Silicon.

Apart from the gadget assembly, the engine is written in Rust.

中文版:**[README_zh.md](README_zh.md)**

There is no app here. What ships is the engine an embedder links — one static library,
`libiul.a`, published as a `vX.Y.Z` release on every push to `main`.

## How it works

For each guest basic block Asbestos builds a **gadget program**: an array of `unsigned long`
values alternating pointers to pre-compiled ARM64 assembly gadgets with inline operands.
Execution is a chain of tail calls — no executable memory is allocated, no machine code is
generated at runtime. The overhead per guest instruction is a few host instructions inside its
gadget.

- **Full NEON + crypto extensions**, block chaining, a persistent 8192-entry TLB, and
  SIGSEGV-based CoW crash recovery
- **48-bit address space** (4-level page table, `MAP_NORESERVE` lazy reservations) — what V8,
  Go and Rust need
- **Filesystems**: fakefs (SQLite metadata over host files), realfs passthrough, bind mounts,
  pty sessions
- **Native offload**: registered guest binaries run as host code instead of being emulated

## Compatibility

Working: apk/pip/npm, Python 3, Node.js 22, Go, Rust, Perl, Ruby, Lua, gcc/cmake/make, git,
sqlite3, ffmpeg (via native offload). Not: GUI apps (no X11/Wayland), Docker, kernel modules,
direct hardware access.

## Build

The host must be ARM64 — the gadget set is AArch64 and nothing else exists. Needs python3,
clang + lld (`brew install llvm lld`), sqlite3, cargo.

```bash
tools/build-all.sh                                                # everything, into build/
tools/build-libs.sh build-ios --release --target aarch64-apple-ios  # the library
```

Use `build-libs.sh` for the cross build (`fakefsify` is a host tool and is not built for a
phone). [ServerBox](https://github.com/lollipopkit/flutter_server_box) carries this
repository as a submodule and downloads the published artifacts rather than building them.

Build-time flags are one environment variable, `TMPFS_RS_CLANG_ARGS`, holding `-D` flags
(e.g. `-DDEBUG_strace=1` for the syscall-trace channel); runtime diagnostics are `IUL_*`
environment variables (`IUL_EXEC_TRACE`, `IUL_LOCK_TRACE`, …).

## Run

Download the Alpine minirootfs tarball for aarch64 from the
[Alpine website](https://alpinelinux.org/downloads/), convert it to a fakefs, and boot a shell:

```bash
./build/tools/fakefsify alpine-minirootfs.tar.gz alpine
./build/iul -f alpine /bin/sh
```

## Tests

```bash
tools/checks.sh             # the source analyses
cargo test --workspace      # the Rust side
tests/integration/smoke.sh  # end-to-end
```

## Links

- Consumer: [ServerBox](https://github.com/lollipopkit/flutter_server_box)

## License

GNU Affero General Public License, version 3: [LICENSE](LICENSE).

A small part of the code derives from iSH and ish-arm64 and stays under the GNU General Public
License, version 3; the texts are in [LICENSES](LICENSES).

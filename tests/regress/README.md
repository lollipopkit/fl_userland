# fs/wait syscall regression tests

These pin the observable behaviour of five fixes so a future change that
reintroduces one of them fails here instead of in a user's shell.

**The compiled half moved to `tests/guest` on 2026-09-09** and is
`tests/guest/src/bin/regress_syscall.rs` and `asimd_fcvt.rs`, which
`tests/integration/guest_tests.sh` builds and runs. What lives here is
`regress_cp.sh` and the script that stages it into a fakefs.

Moving it mattered for two reasons. It was C cross-compiled with
`aarch64-linux-musl-gcc`, and when that was absent -- which is the usual case --
`run.sh` skipped it and exited 0. And it is in `differential.sh`'s sweep now, so
every assertion is checked against a real arm64 Linux kernel; that found three
that were about this emulator rather than about Linux. See
`docs/changelog/2026-09-09-three-assertions-that-were-about-the-emulator.md`.

| Fix | What broke before it | Covered by |
| --- | --- | --- |
| #30 `O_DIRECTORY` flag value | `O_DIRECTORY_` carried the x86 value `1<<16` instead of aarch64's `0x4000`, so the `ENOTDIR` check never fired and `O_DIRECT` (`1<<16` on arm64) was misread as `O_DIRECTORY`. GNU `cp` over an existing file failed with `cannot create regular file '<dst>/<src>': Not a directory`. | `regress_syscall`, `regress_cp.sh` |
| #30 `O_NOFOLLOW` | Translated to the host `open()`, but `generic_openat()` resolves the last path component first, so the flag was a no-op and `open(symlink, O_NOFOLLOW)` returned an fd to the target. | `regress_syscall` |
| #31 fakefs `stat`/`fstat` | The hook-routed branch of `fakefs_stat()` never set `dev` (nor `nlink`/`blksize`), so `stat()` and `fstat()` disagreed on `st_dev` for one file. GNU `cp` reads that as `skipping file '...', as it was replaced while being copied`. | `regress_syscall`, `regress_cp.sh` |
| #29 `waitpid` EINTR | `do_wait()` treated its internal 1s timeout (`_ETIMEDOUT`) as a signal, so any child running longer than a second made its parent's wait fail with `EINTR`. gcc died with `failed to get exit status: Interrupted system call`. | `regress_syscall` |
| `waitid` siginfo | `sys_waitid` returned the raw wait status instead of decoding it: `si_status` was `7936` for `exit(31)` and `si_code` was always 0, so a killed child looked like an exited one. `si_uid` was never set at all. | `regress_syscall` |

## Running

```sh
tests/regress/run.sh                          # against alpine-arm64-321 via -r
tests/regress/run.sh -i build/iul -r myrootfs # pick binary / rootfs
tests/regress/run.sh -m -f -r alpine-arm64-fakefs   # fakefs: runs the cp cases
```

`run.sh` runs the `cp` cases only. `-f` mode exists for them: they need GNU
coreutils, which is usually only present in the fakefs rootfs.

`regress_cp.sh` needs GNU coreutils `cp`, not busybox `cp`: only GNU `cp` probes
its destination with `open(dst, O_PATH|O_DIRECTORY)` and compares
`(st_dev, st_ino)` across `stat`/`fstat`. Without it the `cp` cases skip.

To exercise #31 against a real fakefs mount point, pass the guest path of a file
under one:

```sh
tests/regress/run.sh -m -f -r alpine-arm64-fakefs -f /var/minis/shared/doc.txt
```

That requires a path-translate hook, which only the iOS app installs, so it is
optional — the `stat`/`fstat` assertions still run against the rootfs without it.

## Verifying the tests actually catch the bugs

Run the built binary against an iul built from a commit before these fixes; it
should report 16 failures across all five areas:

```sh
( cd tests/guest && cargo build --release --target aarch64-unknown-linux-musl )
cp tests/guest/target/aarch64-unknown-linux-musl/release/regress_syscall <rootfs>/tmp/
<old-iul> -r <rootfs> /bin/sh -c '/tmp/regress_syscall & wait'
```

And against a real kernel, which is the check the C version could not have:

```sh
docker run --rm --platform linux/arm64 \
    -v "$PWD/tests/guest/target/aarch64-unknown-linux-musl/release:/t" \
    alpine:latest /t/regress_syscall
```

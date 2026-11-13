//! Guest-visible memory policy built from host memory.

// ---------------------------------------------------------------------------
// What a guest is told the machine has
// ---------------------------------------------------------------------------

/// How much memory a guest is told the machine has, at most.
///
/// The host's real figure is a bad answer: 64 GB on a developer's machine makes
/// V8 set `heap_size_limit` to 4 GB, which exhausts the guest's address space,
/// and musl and the Go runtime size arenas from it too. Go needs about 1.1 GB
/// for its page summaries, so this leaves headroom.
///
/// **It lives here because two files answer this question.** `sysinfo(2)` and
/// `/proc/meminfo` are two views of one number, and until 2026-09-04 they were
/// two implementations: `sysinfo` reported the guest's own consumption against
/// the cap and `/proc/meminfo` reported the *host's* free memory capped to it —
/// which on any machine with more than 4 GB free is the cap, so `MemFree` was
/// always exactly `MemTotal` and every reader was told nothing was in use. The
/// comment on the constant in `crates/kernel/unamecalls` said it "must agree
/// with `MEMINFO_MAX_RAM` in fs/proc/root.c", a file that no longer exists.
pub const GUEST_MAX_RAM: u64 = 4 * 1024 * 1024 * 1024;

/// The host's memory, capped: `MemTotal` and `sysinfo`'s `totalram`.
pub fn guest_total_ram() -> u64 {
    host_total_ram().min(GUEST_MAX_RAM)
}

/// How much of `total` is free, from the **guest's** anonymous-page accounting
/// rather than the host's free memory.
///
/// The host's number says nothing a guest can act on — the pages it would need
/// are the ones this process has not asked for yet — where the guest's own
/// count is exactly "how much of what you were told you have is spoken for".
///
/// `used_pages` is -1 when that accounting is not compiled in, and then the
/// answer is half: a guess, but not zero, because a free figure of zero makes
/// every runtime that reads it believe memory is exhausted.
pub fn guest_free_ram(total: u64, used_pages: i64) -> u64 {
    if used_pages < 0 {
        return total / 2;
    }
    let used = (used_pages as u64).saturating_mul(4096);
    total.saturating_sub(used)
}

fn host_total_ram() -> u64 {
    crate::host::sysctl::<u64>("hw.memsize").unwrap_or(0)
}

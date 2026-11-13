//! Gadget call profile aggregation and reporting.

use super::*;

// ---------------------------------------------------------------------------
// The gadget call profile
// ---------------------------------------------------------------------------

/// What the `gret` gadget recorded: a ring of next-gadget pointers, one per
/// dispatch, wrapping at [`PROFILE_RING`].
///
/// This was 110 lines of `main.c` until 2026-09-03, and the shape is what
/// changed: the C bucketed by a **linear scan over every distinct address seen
/// so far** with a hard cap of 4096, then found each of the top twenty by
/// scanning the whole table again and zeroing the winner. The pair counts were
/// a hand-rolled 16384-slot linear-probe hash whose entries were silently
/// dropped when a probe ran the full table. Both are a `HashMap` and a sort
/// here, which has no cap and no probe to run out.
const PROFILE_RING: usize = 65536;

/// How many to print, of each kind.
const PROFILE_TOP: usize = 20;

/// The symbol containing `addr`, or `?`.
fn resolve_sym(addr: u64) -> String {
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    // SAFETY: `dladdr` reads the address without dereferencing it and fills
    // `info`; a name it answers with points into the image and outlives this.
    if unsafe { libc::dladdr(addr as *const libc::c_void, &mut info) } != 0
        && !info.dli_sname.is_null()
    {
        return unsafe { std::ffi::CStr::from_ptr(info.dli_sname) }
            .to_string_lossy()
            .into_owned();
    }
    "?".to_string()
}

/// `count` most common entries of `counts`, most first.
fn top<K: Copy + Ord>(counts: &std::collections::HashMap<K, u64>, n: usize) -> Vec<(K, u64)> {
    let mut v: Vec<(K, u64)> = counts.iter().map(|(k, c)| (*k, *c)).collect();
    v.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

/// Print the profile.
///
/// # Safety
/// `buf` points at [`PROFILE_RING`] readable `u64`s and `idx` is how many have
/// been written — which may exceed the ring, in which case it has wrapped and
/// the whole ring is samples.
#[unsafe(no_mangle)]
pub(super) unsafe fn gadget_profile(buf: *const u64, idx: u64) {
    if buf.is_null() {
        return;
    }
    let samples = (idx as usize).min(PROFILE_RING);
    let mut err = std::io::stderr().lock();
    if samples == 0 {
        let _ = writeln!(err, "[gadget-prof] no samples collected");
        return;
    }
    // SAFETY: the caller's contract.
    let ring = unsafe { std::slice::from_raw_parts(buf, samples) };

    let mut singles: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    for &a in ring {
        if a != 0 {
            *singles.entry(a).or_default() += 1;
        }
    }
    let mut pairs: std::collections::HashMap<(u64, u64), u64> = std::collections::HashMap::new();
    for w in ring.windows(2) {
        if w[0] != 0 && w[1] != 0 {
            *pairs.entry((w[0], w[1])).or_default() += 1;
        }
    }

    let pct = |c: u64| 100.0 * c as f64 / samples as f64;
    let _ = writeln!(
        err,
        "[gadget-prof] {idx} total dispatches, {samples} samples, {} distinct gadgets",
        singles.len()
    );
    let best = top(&singles, PROFILE_TOP);
    let _ = writeln!(err, "[gadget-prof] top {} singles:", best.len());
    for (rank, (addr, c)) in best.iter().enumerate() {
        let _ = writeln!(
            err,
            "[gadget-prof]  {:2}. {:<40} {c:8}  {:5.2}%",
            rank + 1,
            resolve_sym(*addr),
            pct(*c)
        );
    }

    let _ = writeln!(
        err,
        "[gadget-prof] {} distinct pairs; top {PROFILE_TOP}:",
        pairs.len()
    );
    for (rank, ((a, b), c)) in top(&pairs, PROFILE_TOP).iter().enumerate() {
        let ab = format!("{} + {}", resolve_sym(*a), resolve_sym(*b));
        let _ = writeln!(
            err,
            "[gadget-prof]  P{:2}. {ab:<72} {c:8}  {:5.2}%",
            rank + 1,
            pct(*c)
        );
    }
}

//! Dispatch block profile storage and reporting.

use super::*;

// ---------------------------------------------------------------------------
// The block profile
// ---------------------------------------------------------------------------

/// Two million entries of sixteen bytes: 32 MB, allocated on the first record
/// and only when `IUL_BLOCK_PROF_FILE` is set.
const PROF_SIZE: usize = 1 << 21;

/// One entry: the block's address, and its dispatch count with its instruction
/// length packed into the low byte.
///
/// Packed because the two are written together and read together, and an entry
/// that is two independent atomics can be seen half-updated by the dump.
struct ProfEntry {
    addr: AtomicU64,
    count_len: AtomicU64,
}

static PROF: std::sync::OnceLock<Vec<ProfEntry>> = std::sync::OnceLock::new();

fn prof() -> &'static Vec<ProfEntry> {
    PROF.get_or_init(|| {
        (0..PROF_SIZE)
            .map(|_| ProfEntry {
                addr: AtomicU64::new(0),
                count_len: AtomicU64::new(0),
            })
            .collect()
    })
}

/// Record one dispatch of the block at `addr`, which is `insns` long.
///
/// Open addressing with a bounded probe: a table this size is never full in
/// practice, and giving up after 64 probes loses a count rather than looping.
///
/// The caller has already tested `iul_env.block_prof_file`.
pub fn diag_block_prof(addr: u64, insns: u64) {
    let insns = insns.min(255);
    let table = prof();
    let h = (addr.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 43) as usize;
    for probe in 0..64 {
        let e = &table[(h + probe) & (PROF_SIZE - 1)];
        let cur = e.addr.load(RELAXED);
        if cur == addr {
            e.count_len.fetch_add(256, RELAXED);
            return;
        }
        if cur == 0 {
            // The length goes in with the first count, so an entry claimed by
            // another thread does not get it twice.
            match e
                .addr
                .compare_exchange(0, addr, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    e.count_len.fetch_add(256 + insns, RELAXED);
                    return;
                }
                Err(seen) if seen == addr => {
                    e.count_len.fetch_add(256, RELAXED);
                    return;
                }
                Err(_) => continue,
            }
        }
    }
}

/// Write every block and its count to `IUL_BLOCK_PROF_FILE`.
pub(super) fn dump_block_prof() {
    let Some(path) = util_iulenv::env().block_prof_file else {
        return;
    };
    let Some(table) = PROF.get() else {
        return; // nothing was ever recorded
    };
    let mut body = String::new();
    let mut n = 0usize;
    for e in table.iter() {
        let addr = e.addr.load(RELAXED);
        if addr == 0 {
            continue;
        }
        let packed = e.count_len.load(RELAXED);
        body.push_str(&format!("{addr:x} {} {}\n", packed >> 8, packed & 0xff));
        n += 1;
    }
    if std::fs::write(path, body).is_ok() {
        eprintln!("[block_prof] wrote {n} blocks to {path}");
    }
}

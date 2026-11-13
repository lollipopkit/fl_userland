//! Compiling a block so that what it caches is what the guest actually wrote.
//!
//! # The problem this exists for
//!
//! Guest JITs — JavaScriptCore under `bun`, V8 under `node` — patch their own
//! code pages in place: inline caches get rewritten, branches get repatched,
//! and none of it announces itself. A block compiled while such a patch is
//! mid-flight caches **torn bytes** and then keeps executing them for as long
//! as it stays in the cache. That was the root cause of the `claude-cli`
//! crashes, and the tell was that `IUL_NO_BLOCK_CACHE=2` made them disappear:
//! a cache that never reuses a block cannot serve a torn one twice.
//!
//! # The protocol
//!
//! It is a seqlock, with `mmu->changes` as the sequence and the page's `P_CODE`
//! bit as the thing being watched:
//!
//! 1. Mark the page `P_CODE` and bump `mmu->changes` **before** reading a
//!    single guest byte. Every thread's cached writable TLB entry for that page
//!    is now stale, so any store takes the `mem_ptr` write-miss path — which
//!    invalidates the page's blocks, clears `P_CODE`, and bumps `mmu->changes`
//!    again.
//! 2. Compile.
//! 3. Verify. If `mmu->changes` moved, or `P_CODE` is gone, a store may have
//!    landed inside the read: throw the block away and try again.
//!
//! The whole of that is [`compile_protected`], and it is written against a
//! [`CodePages`] trait rather than against `struct mmu` so that the
//! interleaving can be *tested* — a fake whose compile stores to its own page
//! is exactly the race, and there is no other way to produce one on demand.
//!
//! **The trait takes `&self`, not `&mut self`**, and that is the point rather
//! than an oversight: an address space is shared between every thread running
//! in it, `mmu_mark_code_page` is a compare-exchange on a page-table entry, and
//! a `&mut` would have been a claim of exclusivity that nothing holds. The
//! first version asked for one, and the consequence was immediate — the test
//! that matters could not be written, because the closure doing the compiling
//! could not reach the pages it was supposed to be disturbing. An API that
//! makes its own worst case unexpressible is the wrong API.
//!
//! # The two rules that are not the seqlock
//!
//! **A block that crosses a page boundary needs both pages marked**, and the
//! second one can only be known after compiling — the decoder is what decides
//! where the block ends. If marking the tail page *transitions* it, the tail
//! was unprotected while it was read and the block is recompiled with both
//! pages covered. A tail page that was already marked needs no second pass,
//! which matters: a hot loop straddling a boundary would otherwise recompile
//! on every entry.
//!
//! **An unmapped page is not protected at all.** `mark` answers negative and
//! the block is compiled without a seqlock, because there is nothing to tear:
//! the compile is about to fault instead.
//!
//! # Giving up
//!
//! After sixteen attempts the block is accepted anyway. That is the pre-W^X
//! behaviour and it is a deliberate bound: a page under continuous churn from
//! another thread can fail verification for ever, and looping there is a hang
//! where accepting is at worst the bug this file exists to fix. `ST_WX_GIVEUPS`
//! counts it, and a non-zero count in `dump_wx_stats` is the signal that a
//! guest is doing something this protocol handles badly.

use std::ffi::c_int;

/// `emu/mmu.h`: a guest page number. Sixty-four bits, because a 48-bit guest
/// address space has 36 bits of them and this is not the place to find that
/// out by truncation.
#[allow(non_camel_case_types)]
pub type page_t = u64;
use Ordering::Relaxed;
use std::sync::atomic::{AtomicU64, Ordering, fence};

/// What the protocol needs of an address space: mark a page as holding code,
/// ask whether the mark survived, and read the sequence. Shared, so `&self` —
/// see the module comment.
pub trait CodePages {
    /// Negative if the page is not mapped, positive if this call is what turned
    /// the mark on, zero if it was already on.
    fn mark(&self, page: page_t) -> c_int;
    /// Whether the mark is still in place.
    fn intact(&self, page: page_t) -> bool;
    /// `mmu->changes`, acquire-ordered.
    fn generation(&self) -> u64;
}

/// What a compiled block has to be able to say about itself: the page its last
/// instruction is on, which is what decides whether a second page needs marking.
pub trait Compiled {
    fn end_page(&self) -> page_t;
}

/// The counters `crates/asbestos/diag` owns and this increments.
pub struct Counters<'a> {
    pub marks: &'a AtomicU64,
    pub retries: &'a AtomicU64,
    pub giveups: &'a AtomicU64,
}

/// Sixteen. See the module comment: this is a bound on a livelock, not a
/// correctness parameter.
const MAX_ATTEMPTS: u32 = 16;

/// Compile the block at `page`, retrying until what was read is what the guest
/// had. `compile` returns `None` if the decoder refused, which is not a race
/// and is passed straight back.
///
/// `free` is called on a block that is thrown away. It has to be a parameter
/// rather than a `Drop`: the block is a C allocation the caller owns on the way
/// out, and only the discard path releases it.
pub fn compile_protected<P, B>(
    pages: &P,
    page: page_t,
    counters: &Counters<'_>,
    mut compile: impl FnMut() -> Option<B>,
    mut free: impl FnMut(B),
) -> Option<B>
where
    P: CodePages + ?Sized,
    B: Compiled,
{
    for attempt in 0.. {
        let marked = pages.mark(page);
        if marked < 0 {
            // Not mapped, so there is nothing to protect and nothing to tear.
            return compile();
        }
        if marked > 0 {
            counters.marks.fetch_add(1, Relaxed);
        }

        let before = pages.generation();
        let block = compile()?;

        // The tail page is only knowable now, and marking it is not enough on
        // its own: if this call is what turned the mark on, the tail was read
        // unprotected and has to be read again with both pages covered.
        let end = block.end_page();
        if end != page && pages.mark(end) > 0 {
            free(block);
            continue;
        }

        // The read of the sequence below must not be hoisted above the compile.
        fence(Ordering::SeqCst);
        let held = pages.generation() == before
            && pages.intact(page)
            && (end == page || pages.intact(end));
        if held {
            return Some(block);
        }
        if attempt >= MAX_ATTEMPTS {
            counters.giveups.fetch_add(1, Relaxed);
            return Some(block); // pathological churn; accept, as before W^X
        }
        counters.retries.fetch_add(1, Relaxed);
        free(block);
    }
    unreachable!("the loop above returns or continues")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// A page map a compile can store into, which is the race.
    #[derive(Default)]
    struct Fake {
        marked: RefCell<Vec<page_t>>,
        unmapped: Vec<page_t>,
        gen_: Cell<u64>,
    }

    impl Fake {
        /// What a guest store does: the write-miss path clears the mark and
        /// moves the sequence.
        fn store(&self, page: page_t) {
            self.marked.borrow_mut().retain(|&p| p != page);
            self.gen_.set(self.gen_.get() + 1);
        }
    }

    impl CodePages for Fake {
        fn mark(&self, page: page_t) -> c_int {
            if self.unmapped.contains(&page) {
                return -1;
            }
            let mut marked = self.marked.borrow_mut();
            if marked.contains(&page) {
                return 0;
            }
            marked.push(page);
            self.gen_.set(self.gen_.get() + 1);
            1
        }
        fn intact(&self, page: page_t) -> bool {
            self.marked.borrow().contains(&page)
        }
        fn generation(&self) -> u64 {
            self.gen_.get()
        }
    }

    struct Blk(page_t);
    impl Compiled for Blk {
        fn end_page(&self) -> page_t {
            self.0
        }
    }

    struct Counted(AtomicU64, AtomicU64, AtomicU64);
    impl Counted {
        fn new() -> Self {
            Counted(AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0))
        }
        fn as_ref(&self) -> Counters<'_> {
            Counters {
                marks: &self.0,
                retries: &self.1,
                giveups: &self.2,
            }
        }
        fn marks(&self) -> u64 {
            self.0.load(Relaxed)
        }
        fn retries(&self) -> u64 {
            self.1.load(Relaxed)
        }
        fn giveups(&self) -> u64 {
            self.2.load(Relaxed)
        }
    }

    #[test]
    fn an_undisturbed_compile_runs_once() {
        let c = Counted::new();
        let pages = Fake::default();
        let calls = Cell::new(0);
        let freed = Cell::new(0);
        let b = compile_protected(
            &pages,
            7,
            &c.as_ref(),
            || {
                calls.set(calls.get() + 1);
                Some(Blk(7))
            },
            |_| freed.set(freed.get() + 1),
        );
        assert!(b.is_some());
        assert_eq!(calls.get(), 1);
        assert_eq!(freed.get(), 0);
        assert_eq!(c.marks(), 1, "the page was marked");
        assert_eq!(c.retries(), 0);
    }

    /// The race the whole file exists for: a guest JIT patches the page while
    /// the decoder is reading it. Nothing but a fake can produce this on
    /// demand, which is why the trait exists at all.
    #[test]
    fn a_store_during_the_compile_forces_a_retry() {
        let c = Counted::new();
        let pages = Fake::default();
        let calls = Cell::new(0);
        let freed = Cell::new(0);
        let b = compile_protected(
            &pages,
            7,
            &c.as_ref(),
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    pages.store(7); // the patch lands inside the read
                }
                Some(Blk(7))
            },
            |_| freed.set(freed.get() + 1),
        );
        assert!(b.is_some());
        assert_eq!(calls.get(), 2, "the torn block was thrown away and reread");
        assert_eq!(freed.get(), 1);
        assert_eq!(c.retries(), 1);
        // And the second attempt re-marked the page the store cleared.
        assert_eq!(c.marks(), 2);
        assert!(pages.intact(7));
    }

    /// A store to a *different* page is not this block's problem. The sequence
    /// moves for it, so a verify that looked only at `mmu->changes` would
    /// retry for ever on a busy address space — the `intact` check is not
    /// redundant with it, and neither is redundant with the other.
    #[test]
    fn a_store_elsewhere_still_costs_a_retry_but_settles() {
        let c = Counted::new();
        let pages = Fake::default();
        pages.mark(9);
        let calls = Cell::new(0);
        let b = compile_protected(
            &pages,
            7,
            &c.as_ref(),
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    pages.store(9);
                }
                Some(Blk(7))
            },
            |_| {},
        );
        assert!(b.is_some());
        assert_eq!(
            calls.get(),
            2,
            "conservative: the sequence is address-space wide"
        );
        assert_eq!(c.retries(), 1);
    }

    #[test]
    fn an_unmapped_page_is_compiled_without_protection() {
        let c = Counted::new();
        let pages = Fake {
            unmapped: vec![7],
            ..Fake::default()
        };
        let calls = Cell::new(0);
        let b = compile_protected(
            &pages,
            7,
            &c.as_ref(),
            || {
                calls.set(calls.get() + 1);
                Some(Blk(7))
            },
            |_| unreachable!("nothing to throw away"),
        );
        assert!(b.is_some());
        assert_eq!(calls.get(), 1);
        assert_eq!(c.marks(), 0, "an unmapped page is not marked");
        assert!(!pages.intact(7));
    }

    /// A block whose last instruction is on the next page: the tail was read
    /// before it was protected, so it is read again.
    #[test]
    fn a_block_crossing_into_an_unmarked_page_is_recompiled() {
        let c = Counted::new();
        let pages = Fake::default();
        let calls = Cell::new(0);
        let freed = Cell::new(0);
        let b = compile_protected(
            &pages,
            7,
            &c.as_ref(),
            || {
                calls.set(calls.get() + 1);
                Some(Blk(8))
            },
            |_| freed.set(freed.get() + 1),
        );
        assert!(b.is_some());
        assert_eq!(calls.get(), 2, "the tail page forced one recompile");
        assert_eq!(freed.get(), 1);
        assert!(pages.intact(8), "and the tail is marked now");
        assert_eq!(
            c.marks(),
            1,
            "page 7 transitioned once; page 8 is not counted"
        );
        assert_eq!(c.retries(), 0, "a tail recompile is not a seqlock failure");
    }

    /// A tail page that was already code needs no second pass — this is the
    /// common case for a hot loop that straddles a boundary, and a recompile
    /// per entry would be a real cost.
    #[test]
    fn a_block_crossing_into_an_already_marked_page_is_kept() {
        let c = Counted::new();
        let pages = Fake::default();
        pages.mark(8);
        let calls = Cell::new(0);
        let b = compile_protected(
            &pages,
            7,
            &c.as_ref(),
            || {
                calls.set(calls.get() + 1);
                Some(Blk(8))
            },
            |_| unreachable!("nothing thrown away"),
        );
        assert!(b.is_some());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn a_decoder_refusal_is_not_a_race() {
        let c = Counted::new();
        let pages = Fake::default();
        let calls = Cell::new(0);
        let b = compile_protected::<_, Blk>(
            &pages,
            7,
            &c.as_ref(),
            || {
                calls.set(calls.get() + 1);
                None
            },
            |_| unreachable!(),
        );
        assert!(b.is_none());
        assert_eq!(calls.get(), 1, "not retried");
        assert_eq!(c.retries(), 0);
    }

    /// Continuous churn is bounded rather than looped on. This fake never lets
    /// a mark survive, which is a page being stored to as fast as it is marked.
    #[test]
    fn pathological_churn_gives_up_and_accepts() {
        struct Churn(Cell<u64>);
        impl CodePages for Churn {
            fn mark(&self, _page: page_t) -> c_int {
                self.0.set(self.0.get() + 1);
                1
            }
            fn intact(&self, _page: page_t) -> bool {
                false
            }
            fn generation(&self) -> u64 {
                self.0.get()
            }
        }
        let c = Counted::new();
        let pages = Churn(Cell::new(0));
        let calls = Cell::new(0);
        let freed = Cell::new(0);
        let b = compile_protected(
            &pages,
            7,
            &c.as_ref(),
            || {
                calls.set(calls.get() + 1);
                Some(Blk(7))
            },
            |_| freed.set(freed.get() + 1),
        );
        assert!(b.is_some(), "accepted rather than looping for ever");
        assert_eq!(calls.get(), MAX_ATTEMPTS as i32 + 1);
        assert_eq!(c.giveups(), 1);
        assert_eq!(freed.get(), MAX_ATTEMPTS as i32, "the accepted one is kept");
    }
}

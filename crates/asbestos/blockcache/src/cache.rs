//! Block cache indexes and ownership.

use super::*;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// The page a guest address is in. Blocks are indexed by page so that
/// invalidating a mapping does not walk every block there is.
fn page_of(addr: u64) -> u64 {
    addr >> ffi::PAGE_BITS
}

/// How many page buckets. `FIBER_PAGE_HASH_SIZE` in `asbestos/asbestos.h`,
/// which the C used for the same index.
const PAGE_BUCKETS: usize = ffi::FIBER_PAGE_HASH_SIZE as usize;

pub(crate) fn bucket(page: u64) -> usize {
    (page as usize) % PAGE_BUCKETS
}

/// How many blocks a bucket holds without allocating.
///
/// **This is the whole of the page index's cost.** A `Vec` that starts empty
/// allocates on its first push, and one `execve` of `/bin/true` compiles 679
/// blocks — so 679 `malloc`s per address space that the C's intrusive lists did
/// not do. Measured by removing the pushes altogether, which closed the entire
/// remaining gap against the C: 1.23 s against 1.22 on an exec-heavy loop where
/// the version with them was 1.27.
///
/// Two, because a page usually holds one block and sometimes a block that spans
/// into it. `struct list blocks[2]` in the C was 32 bytes a bucket and this is
/// 48, which is the trade.
const INLINE: usize = 2;

/// The blocks indexed under one page bucket.
///
/// `inline` is filled first and `spill` only when it is full, so `spill` is
/// non-empty exactly when `inline` is full — which is what makes [`is_empty`]
/// one comparison. Nothing here allocates on the common path, in either
/// direction: the first version's `retain` collected into a temporary `Vec`,
/// which made every removal a `malloc` and the exec loop 1.40 s against 1.22.
///
/// [`is_empty`]: Bucket::is_empty
struct Bucket {
    inline: [Option<Held>; INLINE],
    inline_n: usize,
    spill: Vec<Held>,
}

impl Bucket {
    const fn new() -> Bucket {
        Bucket {
            inline: [None; INLINE],
            inline_n: 0,
            spill: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.inline_n == 0
    }

    fn push(&mut self, block: Held) {
        if self.inline_n < INLINE {
            self.inline[self.inline_n] = Some(block);
            self.inline_n += 1;
        } else {
            self.spill.push(block);
        }
    }

    fn iter(&self) -> impl Iterator<Item = Held> + '_ {
        self.inline[..self.inline_n].iter().flatten().chain(&self.spill).copied()
    }

    /// Keep only what `f` says, in place.
    fn retain(&mut self, f: impl Fn(Held) -> bool) {
        let mut w = 0;
        for r in 0..self.inline_n {
            if self.inline[r].is_some_and(&f) {
                self.inline[w] = self.inline[r];
                w += 1;
            }
        }
        self.inline_n = w;
        if self.spill.is_empty() {
            return;
        }
        self.spill.retain(|&b| f(b));
        // Refill the inline slots the removals opened, so the invariant holds:
        // `spill` is non-empty only when `inline` is full.
        while self.inline_n < INLINE && !self.spill.is_empty() {
            self.inline[self.inline_n] = Some(self.spill.remove(0));
            self.inline_n += 1;
        }
    }

    fn clear(&mut self) {
        self.inline_n = 0;
        self.spill.clear();
    }
}

/// A block this cache holds.
///
/// **The one place the cache's ownership is a type.** Made only by
/// [`Cache::insert`], which took the block fresh from the compiler, and by
/// following `hash_next`, which only ever names one; a block leaves only
/// through `Block::free` in this file. So every `Held` the cache stores names
/// a live block, and reading its header is safe -- what other threads touch
/// while it is shared is the code after the header, and the header's one
/// mutable field, `hash_next`, is written only through `&mut Cache`.
///
/// It was `usize` and `*mut Block` until 2026-10-18, each read of a header an
/// `unsafe` block repeating that argument.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Held(NonNull<Block>);

// SAFETY: a `Held` is an address the cache's lock serialises access through;
// the block itself is shared between threads by design.
unsafe impl Send for Held {}

impl Held {
    pub fn as_ptr(self) -> *mut Block {
        self.0.as_ptr()
    }

    /// The block after this one in its address chain.
    fn next(self, cache: &Cache) -> Option<Held> {
        NonNull::new(cache.header(self).hash_next).map(Held)
    }
}

/// Everything one address space's compiled blocks are held in.
///
/// # `by_page` is the owner and `by_addr` is a lookup
///
/// Every live block is in `by_page`, under each of the one or two pages it
/// touches; `by_addr` says which block a *dispatch* should run for an address,
/// and there can be a block it no longer names. `IUL_NO_BLOCK_CACHE=2` compiles
/// a fresh block on every dispatch, so the previous one becomes unreachable by
/// lookup while a thread may still be executing it — the C left it in the hash
/// chain for an invalidation to find, and this leaves it in `by_page` for the
/// same reason.
///
/// Getting that wrong is a use-after-free rather than a leak, which is what
/// `a_second_block_for_one_address_stays_until_its_page_is_invalidated` is for:
/// the first version of this retired the shadowed block straight to jetsam
/// while `by_page` still pointed at it, and `free_jetsam` would then have freed
/// something an invalidation was about to walk.
pub struct Cache {
    /// Which block a dispatch runs for an address: a direct-mapped table of
    /// chain heads, `addr % by_addr.len()`, threaded through each block's
    /// `hash_next`. A subset of `by_page`.
    ///
    /// **Not a `HashMap`**, and the reason is measured: hashbrown's insert and
    /// lookup against `addr % size` and four pointer stores cost 4% on a
    /// workload that is nothing but `execve`, and closing that was the last
    /// thing between this crate and parity with the C. Two things it needs from
    /// a hash table it does not have — an owned key and safety — it does not
    /// need: the key is in the block, and the whole cache is behind
    /// `asbestos->lock`.
    by_addr: Vec<Option<Held>>,
    /// How many blocks the table holds, for the resize.
    count: usize,
    /// **Every** live block, under each page it touches. The owner.
    ///
    /// Direct-mapped rather than a `HashMap`, and the C's shape: `page % 1024`
    /// into a fixed array, so asking whether a page holds anything is an index
    /// and a length rather than a hash. That question is asked on **every store
    /// to a code page** — `mem_ptr`'s W^X path calls
    /// `asbestos_invalidate_page` — and on every page of an `munmap`. A bucket
    /// can hold blocks from other pages, so the walk filters, exactly as the
    /// C's chain did.
    by_page: Vec<Bucket>,
    /// Whether each `by_page` bucket is non-empty, for the one question asked
    /// **without** the lock: [`Asbestos::page_has_blocks`]. Written here, under
    /// the lock, after every change to a bucket; shared with [`Asbestos`] so the
    /// reader never forms a reference to this struct while a writer holds
    /// `&mut` to it -- which is what it did until 2026-10-01, a `&Cache` read
    /// of `inline_n` racing the push that wrote it.
    occupied: Arc<[AtomicBool]>,
    /// Disconnected, and waiting for every thread to leave the JIT before it
    /// can be freed. `asbestos->jetsam_lock` is what makes that wait; this is
    /// only the list.
    jetsam: Vec<Held>,
    /// How much gadget memory the live blocks take, for the resize trace.
    mem_used: usize,
    /// The chaining graph: for each block, the predecessors patched to jump
    /// straight into it, and through which of their two slots. See
    /// [`Cache::try_chain`].
    pub(crate) preds: HashMap<usize, Preds, BuildHasherDefault<BlockHasher>>,
}

/// One block's predecessors, as `(block, slot)`: inline up to two, which is
/// nearly every block -- a `Vec` per chained block was a `malloc` per edge, and
/// measured at 5% on an exec loop where the intrusive lists it replaced cost
/// nothing. [`Bucket`]'s shape, for the same reason.
#[derive(Default)]
pub(crate) struct Preds {
    inline: [(usize, usize); 2],
    inline_n: usize,
    spill: Vec<(usize, usize)>,
}

impl Preds {
    fn push(&mut self, edge: (usize, usize)) {
        if self.inline_n < self.inline.len() {
            self.inline[self.inline_n] = edge;
            self.inline_n += 1;
        } else {
            self.spill.push(edge);
        }
    }

    fn iter(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.inline[..self.inline_n].iter().chain(&self.spill).copied()
    }

    pub(crate) fn len(&self) -> usize {
        self.inline_n + self.spill.len()
    }

    /// Drop `edge`, refilling its place from the end so `inline` stays the
    /// full part. Order is not kept, and nothing reads it.
    fn remove(&mut self, edge: (usize, usize)) {
        if let Some(at) = self.spill.iter().position(|&e| e == edge) {
            self.spill.swap_remove(at);
        } else if let Some(at) = self.inline[..self.inline_n].iter().position(|&e| e == edge) {
            self.inline[at] = match self.spill.pop() {
                Some(last) => last,
                None => {
                    self.inline_n -= 1;
                    self.inline[self.inline_n]
                }
            };
        }
    }
}

/// The hash for a block address: a multiply. The keys are heap pointers, so
/// the low bits are alignment and the high bits are the same for every block;
/// SipHash's resistance to chosen keys buys nothing against keys the guest
/// cannot choose, and costs on the path every new chain takes.
#[derive(Default)]
pub(crate) struct BlockHasher(u64);

impl Hasher for BlockHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    fn write_usize(&mut self, n: usize) {
        self.0 = (n as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

impl Default for Cache {
    fn default() -> Cache {
        Cache::new()
    }
}

impl Cache {
    pub fn new() -> Cache {
        Cache {
            // Sized up front, as the C's was: the blocks one `execve` compiles
            // -- 679 for `/bin/true` -- go in without a rehash.
            by_addr: vec![None; ffi::FIBER_INITIAL_HASH_SIZE as usize],
            count: 0,
            // A Vec rather than a boxed array, so 1024 buckets are built on
            // the heap instead of on the stack on the way there.
            by_page: (0..PAGE_BUCKETS).map(|_| Bucket::new()).collect(),
            occupied: (0..PAGE_BUCKETS).map(|_| AtomicBool::new(false)).collect(),
            jetsam: Vec::new(),
            mem_used: 0,
            preds: HashMap::default(),
        }
    }

    /// The occupancy bits, shared with the [`Asbestos`] that asks them
    /// without the lock.
    pub(crate) fn occupancy(&self) -> Arc<[AtomicBool]> {
        Arc::clone(&self.occupied)
    }

    /// Whether any retired blocks are waiting for reclamation.
    pub fn has_jetsam(&self) -> bool {
        !self.jetsam.is_empty()
    }

    /// A held block's header. See [`Held`] for why this is safe.
    fn header(&self, b: Held) -> &Block {
        // SAFETY: `Held`'s invariant.
        unsafe { b.0.as_ref() }
    }

    /// Point `b`'s chain link at `next`.
    fn set_next(&mut self, b: Held, next: Option<Held>) {
        // SAFETY: `Held`'s invariant; `&mut self` is the cache lock, which
        // every writer of `hash_next` holds.
        unsafe { (*b.as_ptr()).hash_next = next.map_or(std::ptr::null_mut(), Held::as_ptr) };
    }

    /// The block compiled for `addr`, or null.
    pub fn lookup(&self, addr: u64) -> *mut Block {
        let mut p = self.by_addr[(addr as usize) % self.by_addr.len()];
        while let Some(b) = p {
            if self.header(b).addr == addr {
                return b.as_ptr();
            }
            p = b.next(self);
        }
        std::ptr::null_mut()
    }

    /// Double the table when the average chain reaches two, which is what the
    /// C did and for the same reason: a longer chain is a walk on the
    /// block-cache miss path.
    fn grow_if_full(&mut self) {
        if self.count < self.by_addr.len() * 2 {
            return;
        }
        let mut chained = Vec::with_capacity(self.count);
        for &head in &self.by_addr {
            let mut p = head;
            while let Some(b) = p {
                chained.push(b);
                p = b.next(self);
            }
        }
        self.by_addr = vec![None; self.by_addr.len() * 2];
        for b in chained {
            let at = self.slot_of(b);
            self.set_next(b, self.by_addr[at]);
            self.by_addr[at] = Some(b);
        }
    }

    /// Where `b`'s address chain starts.
    fn slot_of(&self, b: Held) -> usize {
        (self.header(b).addr as usize) % self.by_addr.len()
    }

    /// Take `block` out of its address chain, if it is the one there.
    fn unchain(&mut self, block: Held) {
        let at = self.slot_of(block);
        let mut current = self.by_addr[at];
        let mut previous: Option<Held> = None;
        while let Some(b) = current {
            let next = b.next(self);
            if b == block {
                match previous {
                    Some(previous) => self.set_next(previous, next),
                    None => self.by_addr[at] = next,
                }
                self.set_next(block, None);
                self.count -= 1;
                return;
            }
            previous = Some(b);
            current = next;
        }
    }

    /// The pages a block touches: one, or two when it spans a boundary.
    fn pages(&self, b: Held) -> (u64, Option<u64>) {
        let header = self.header(b);
        let (a, e) = (page_of(header.addr), page_of(header.end_addr));
        (a, (a != e).then_some(e))
    }

    /// Take ownership of a freshly compiled block.
    ///
    /// # Safety
    /// `block` came from the compiler and is not in any cache; the caller
    /// holds `asbestos->lock`.
    pub unsafe fn insert(&mut self, block: *mut Block) -> Held {
        let block = Held(NonNull::new(block).expect("a compiled block is not null"));
        self.mem_used += self.header(block).used;
        let (first, second) = self.pages(block);
        self.push_page(bucket(first), block);
        if let Some(p) = second {
            // A block spanning two pages that fall in the same bucket goes in
            // once: the walk deduplicates, but pushing twice would make the
            // bucket grow without bound under a repeatedly recompiled block.
            if bucket(p) != bucket(first) {
                self.push_page(bucket(p), block);
            }
        }
        // Last writer wins: prepended, so a lookup finds the newest, and the
        // block it displaces stays in `by_page` for an invalidation to find.
        self.grow_if_full();
        let at = self.slot_of(block);
        self.set_next(block, self.by_addr[at]);
        self.by_addr[at] = Some(block);
        self.count += 1;
        block
    }

    /// Take a block out of both indexes, without freeing it.
    fn unindex(&mut self, block: Held) {
        self.mem_used = self.mem_used.saturating_sub(self.header(block).used);
        self.unchain(block);
        let (first, second) = self.pages(block);
        let mut buckets = vec![bucket(first)];
        if let Some(p) = second
            && bucket(p) != bucket(first)
        {
            buckets.push(bucket(p));
        }
        for b in buckets {
            self.by_page[b].retain(|x| x != block);
            self.occupied[b].store(!self.by_page[b].is_empty(), Ordering::Relaxed);
        }
    }

    /// Retire a block: out of the chaining graph and the indexes, marked dead,
    /// and onto the jetsam list.
    ///
    /// It is **not** freed: another thread may be executing it right now, and
    /// what makes the wait is `asbestos->jetsam_lock`, held for reading for as
    /// long as a thread is in the JIT.
    pub(crate) fn retire(&mut self, block: Held) {
        self.disconnect(block);
        self.unindex(block);
        self.header(block).is_jetsam.store(true, Ordering::Relaxed);
        self.jetsam.push(block);
    }

    fn push_page(&mut self, b: usize, block: Held) {
        self.by_page[b].push(block);
        self.occupied[b].store(true, Ordering::Relaxed);
    }

    /// Does a block touch this page? With the lock held; [`Asbestos`] answers
    /// the same question without it.
    pub fn page_has_blocks(&self, page: u64) -> bool {
        // The bucket is shared with every page congruent to this one mod 1024,
        // so a non-empty bucket does not prove a block is on *this* page --
        // which is what the C's `list_null` check answered too. A false
        // positive costs the slow path; a false negative is impossible,
        // because a block is indexed before anything can reach it.
        !self.by_page[bucket(page)].is_empty()
    }

    /// Every block that touches a page in `start .. end`.
    pub(crate) fn blocks_in(&self, start: u64, end: u64) -> Vec<Held> {
        // Over the buckets the range can reach, filtering by the block's own
        // pages -- a bucket holds blocks from every page congruent to it. A
        // range wider than the table reaches all of them.
        let wide = end.saturating_sub(start) as usize >= PAGE_BUCKETS;
        let mut found: Vec<Held> = Vec::new();
        let visit = |b: usize, out: &mut Vec<Held>| {
            for block in self.by_page[b].iter() {
                let (first, second) = self.pages(block);
                let hit = (first >= start && first < end)
                    || second.is_some_and(|p| p >= start && p < end);
                if hit {
                    out.push(block);
                }
            }
        };
        if wide {
            for b in 0..PAGE_BUCKETS {
                visit(b, &mut found);
            }
        } else {
            for page in start..end {
                visit(bucket(page), &mut found);
            }
        }
        // A block spanning two pages of the range can be seen twice, and
        // retiring it twice would put it on the jetsam list twice and free it
        // twice.
        found.sort_unstable();
        found.dedup();
        found
    }

    /// Every block there is, each once.
    pub(crate) fn all(&self) -> Vec<Held> {
        let mut found: Vec<Held> = self.by_page.iter().flat_map(Bucket::iter).collect();
        found.sort_unstable();
        found.dedup();
        found
    }

    /// Free everything on the jetsam list. The caller has established that no
    /// thread is in the JIT.
    ///
    /// # Safety
    /// Nothing is executing any of them.
    pub unsafe fn free_jetsam(&mut self) {
        for block in self.jetsam.drain(..) {
            // SAFETY: the caller's contract, and `Held`'s: retired here, so
            // in no index, and freed once because drained.
            unsafe { Block::free(block.as_ptr()) };
        }
    }

    /// Patch `from`'s exit to jump straight into `to`, for each of the two
    /// slots that still holds `to`'s *address*.
    ///
    /// A slot that has already been chained holds a code pointer instead, so
    /// running twice does nothing the second time -- which is what keeps a
    /// predecessor in at most one destination's list per slot.
    ///
    /// The graph was two intrusive lists per block until 2026-10-17, four
    /// list nodes in every block header and 28 `unsafe` operations on them,
    /// kept on the argument that this runs "on every dispatch". It runs on
    /// every dispatch that follows an *unchained* exit: once chained, the
    /// gadget jumps straight to `to` and the dispatch loop never sees the
    /// edge again. So a map insert per new edge, under the lock this already
    /// held.
    ///
    /// # Safety
    /// Both are live blocks this cache owns or a dispatch is about to run, and
    /// neither has been freed.
    pub unsafe fn try_chain(&mut self, from: *mut Block, to: *mut Block) {
        // SAFETY: the caller's contract; the slots point into `from`'s code.
        unsafe {
            // A block marked jetsam is assumed to have no pointers left, so
            // none may be minted to or from it: it would outlive the free.
            if (*from).is_jetsam.load(Ordering::Relaxed) || (*to).is_jetsam.load(Ordering::Relaxed) {
                return;
            }
            for i in 0..2 {
                let slot = (*from).jump_ip[i];
                if slot.is_null() || *slot & chain::FAKE_IP_PC_MASK != (*to).addr {
                    continue;
                }
                *slot = (*to).code.as_ptr() as usize as u64;
                self.preds.entry(to as usize).or_default().push((from as usize, i));
            }
        }
    }

    /// Undo the chaining for one block: everything that jumped straight into
    /// it gets the original address back, and it is taken out of the lists of
    /// whatever it was jumping into. Called **before** it leaves the indexes.
    pub(crate) fn disconnect(&mut self, block: Held) {
        let block = block.as_ptr();
        // SAFETY: `Held`'s invariant for `block`; every slot points into its
        // own block's code, as the compiler made it; and every block the graph
        // names is live, because a retired block is disconnected first.
        unsafe {
            for i in 0..2 {
                let slot = (*block).jump_ip[i];
                // Chained exactly when the slot no longer holds what the
                // compiler wrote, which is then the target's code.
                if slot.is_null() || *slot == (*block).old_jump_ip[i] {
                    continue;
                }
                let target = chain::block_of_code(*slot);
                if let Some(list) = self.preds.get_mut(&target) {
                    list.remove((block as usize, i));
                    if list.len() == 0 {
                        self.preds.remove(&target);
                    }
                }
            }
            if let Some(list) = self.preds.remove(&(block as usize)) {
                for (from, i) in list.iter() {
                    let from = from as *mut Block;
                    *(*from).jump_ip[i] = (*from).old_jump_ip[i];
                }
            }
        }
    }

    /// How many blocks are live, and how much gadget memory they hold.
    pub fn size(&self) -> (usize, usize) {
        (self.all().len(), self.mem_used)
    }
}

impl Drop for Cache {
    /// Frees every block, live and jetsam alike. Reached from `asbestos_free`,
    /// which runs when the address space is gone.
    fn drop(&mut self) {
        for block in self.all() {
            // SAFETY: `Held`'s invariant; `all` names each once, and nothing
            // runs in a dropped address space.
            unsafe { Block::free(block.as_ptr()) };
        }
        for (v, o) in self.by_page.iter_mut().zip(self.occupied.iter()) {
            v.clear();
            o.store(false, Ordering::Relaxed);
        }
        self.by_addr.fill(None);
        self.count = 0;
        for block in self.jetsam.drain(..) {
            // SAFETY: as above, for the retired ones.
            unsafe { Block::free(block.as_ptr()) };
        }
    }
}

#[cfg(test)]
mod preds_tests {
    use super::Preds;

    /// Removal refills from the end, so what is left is exactly what was not
    /// removed, whichever half it was in.
    #[test]
    fn removing_an_edge_keeps_the_rest() {
        let mut p = Preds::default();
        for e in [(1, 0), (2, 1), (3, 0), (4, 1)] {
            p.push(e);
        }
        p.remove((2, 1));
        p.remove((9, 9));
        let mut left: Vec<_> = p.iter().collect();
        left.sort_unstable();
        assert_eq!(left, [(1, 0), (3, 0), (4, 1)]);
        for e in [(1, 0), (3, 0), (4, 1)] {
            p.remove(e);
        }
        assert_eq!(p.len(), 0);
    }
}

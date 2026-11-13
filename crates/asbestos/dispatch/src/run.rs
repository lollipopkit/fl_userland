//! The guest dispatch loop and its per-quantum state.

use super::*;

fn page_of(addr: u64) -> ffi::page_t {
    addr >> PAGE_BITS
}

/// The address space, as the W^X protocol sees it: a page can be marked as
/// holding code, the mark can be checked, and `changes` is the sequence.
struct Pages(*mut ffi::mmu);

impl compile::CodePages for Pages {
    fn mark(&self, page: ffi::page_t) -> c_int {
        unsafe { pagetable::mmu_mark_code_page(self.0, page) }
    }
    fn intact(&self, page: ffi::page_t) -> bool {
        unsafe { pagetable::mmu_code_page_intact(self.0, page) }
    }
    fn generation(&self) -> u64 {
        unsafe { (*self.0).changes.load(Ordering::Acquire) }
    }
}

/// A compiled block, as the protocol sees it: the page its last instruction is
/// on, which is what decides whether a second page needs covering.
struct Fresh(std::ptr::NonNull<Block>);

impl compile::Compiled for Fresh {
    fn end_page(&self) -> ffi::page_t {
        page_of(unsafe { (*self.0.as_ptr()).end_addr })
    }
}

/// Compile the block at `ip` under the W^X seqlock. See [`compile`].
///
/// `_cache` is the proof the cache lock is held, which freeing a discarded
/// block's chain links asks for.
///
/// # Safety
/// `tlb` is live.
unsafe fn compile_protected(
    asbestos: &Asbestos,
    _cache: &mut asbestos_blockcache::Cache,
    ip: u64,
    tlb: *mut Tlb,
) -> *mut Block {
    let pages = Pages(asbestos.mmu);
    let counters = compile::Counters {
        marks: &ST_WX_MARKS,
        retries: &ST_WX_RETRIES,
        giveups: &ST_WX_GIVEUPS,
    };
    let block = compile::compile_protected(
        &pages,
        page_of(ip),
        &counters,
        || {
            let b = unsafe { asbestos_gen::compile::compile_raw(ip, tlb) };
            std::ptr::NonNull::new(b).map(Fresh)
        },
        // SAFETY: a block no index ever held, under the cache lock.
        |b| unsafe { asbestos_blockcache::chain::free_orphan(b.0.as_ptr()) },
    );
    block.map_or(std::ptr::null_mut(), |b| b.0.as_ptr())
}

/// The two block counts that end a quantum, and why there are two.
///
/// With nobody waiting for the address space, letting go costs a lock release
/// and re-acquire for nothing, and eight threads doing that on one rwlock is
/// most of what they could have been computing: 815 ns per unit of work against
/// 3148 when the quantum was 1024 blocks. So the long bound is what runs.
///
/// With somebody waiting, the **short** bound runs and the writer is in within
/// about a thousand blocks. It used to be neither: the check was
/// `(++cpu.cycle & 0x3ff) == 0`, and the gadget's chained fast path returns
/// here with the counter already at a multiple of 1024, so the `++` moved it
/// off and the test never fired. A guest thread that stayed in the JIT
/// therefore never let go at all, and one compute-bound thread starved every
/// `mmap` in its address space — a `pthread_create` took over twenty seconds
/// where it takes 330 µs with nothing else running.
///
/// A **delta** rather than a mask, so it does not matter which of the two
/// counters moved or by how much. Unsigned wraparound is not a concern: the
/// difference is what is compared and it is right across a wrap.
const QUANTUM_BLOCKS_IDLE: u64 = 1 << 16;
const QUANTUM_BLOCKS_WANTED: u64 = 1 << 10;

/// Has this thread held the address space long enough?
///
/// # Safety
/// `mmu` is live.
unsafe fn quantum_over(mmu: *mut ffi::mmu, cycle: i64, since: i64) -> bool {
    let ran = cycle.wrapping_sub(since) as u64;
    if ran >= QUANTUM_BLOCKS_IDLE {
        return true;
    }
    if ran < QUANTUM_BLOCKS_WANTED {
        return false;
    }
    // The JIT's dispatch loop sees a writer waiting without reaching for the
    // lock itself; see `struct mmu`.
    // SAFETY: null, or the counter inside the address space's live lock.
    unsafe { (*mmu).writers_waiting.as_ref() }.is_some_and(|w| w.load(Ordering::Acquire) != 0)
}

/// Which of the 4096 per-thread cache slots a pc uses.
fn cache_slot(ip: u64) -> usize {
    ((ip ^ (ip >> 12)) & (ffi::FIBER_CACHE_SIZE as u64 - 1)) as usize
}

/// Everything a thread needs while it is in the JIT.
///
/// **The one place the loop's pointers are promised.** [`Run::new`] takes the
/// promise -- the CPU, the TLB and the frame are this thread's and live for the
/// quantum -- and every method below reads or writes one field through it and
/// lets go. Nothing here holds a reference across [`Run::enter`]: the gadgets
/// write the frame and the TLB through their own pointers while it runs, and a
/// `&mut` held over that is the aliasing release builds act on. The loop was
/// seventy-odd `unsafe` blocks repeating the promise until 2026-10-18.
struct Run<'a> {
    cpu: *mut Cpu,
    tlb: *mut Tlb,
    /// The address space's JIT, live for the quantum: `mem_destroy` waits for
    /// the address-space lock this thread's caller holds.
    asbestos: &'a Asbestos,
    frame: *mut Frame,
    /// The per-thread facts a crash handler reads. One pointer, taken once
    /// per quantum, where this was two raw pointers into C `__thread`
    /// variables until 2026-09-06 — see `crates/asbestos/jitstate` for why the
    /// address has to be keepable and why a `thread_local!` is not. Null only
    /// if `pthread_setspecific` failed, and then the thread looks like an
    /// embedder's and a fault in it is a real crash, which is the safe answer.
    jit: *mut jitstate::JitState,
    /// Whether any of the counters above are being kept, which is a build flag
    /// plus an environment variable and so is read once.
    counting: bool,
}

impl<'a> Run<'a> {
    /// Take the quantum's state, holding `jetsam_lock` for reading until
    /// [`Run::leave`]: that is what stops jetsam cleanup freeing a block this
    /// thread is executing.
    ///
    /// # Safety
    /// `cpu` and `tlb` are this guest thread's own and `frame` a frame it owns,
    /// all live until the `Run` is left.
    unsafe fn new(cpu: *mut Cpu, tlb: *mut Tlb, asbestos: &'a Asbestos, frame: *mut Frame) -> Run<'a> {
        locks::wrlock::read_lock(&asbestos.jetsam_lock);
        Run {
            cpu,
            tlb,
            asbestos,
            frame,
            jit: jitstate::install(),
            counting: util_iulenv::env().dispatch_count || stage_trace_on() != 0,
        }
    }

    /// Has the cache been invalidated since this thread's slots were filled?
    #[inline]
    fn block_cache_stale(&self) -> bool {
        // SAFETY: `new`'s contract.
        unsafe { (*self.tlb).block_cache_gen != self.asbestos.invalidate_gen.load(Ordering::Relaxed) }
    }

    /// Throw away everything that describes blocks: the per-thread cache and
    /// the frame's return targets, which hold pointers into block code.
    fn drop_block_caches(&self) {
        // SAFETY: `new`'s contract.
        unsafe {
            (*self.tlb).block_cache.fill(std::ptr::null_mut());
            (*self.tlb).block_cache_gen = self.asbestos.invalidate_gen.load(Ordering::Relaxed);
            (*self.frame).ret_cache.fill(0);
        }
    }

    /// And the TLB with them, for when the *mapping* changed rather than the
    /// blocks.
    fn drop_everything(&self) {
        // SAFETY: `new`'s contract.
        unsafe { emu_tlb::tlb_flush(self.tlb) };
        self.drop_block_caches();
        self.set_last_block(std::ptr::null_mut());
    }

    /// Has another thread remapped a page since this thread last looked?
    #[inline]
    fn mappings_moved(&self) -> bool {
        // SAFETY: `new`'s contract; the TLB's address space is live with it.
        unsafe { (*self.tlb).mem_changes as u64 != (*(*self.tlb).mmu).changes.load(Ordering::Acquire) }
    }

    /// The block in the per-thread cache slot `ip` uses.
    #[inline]
    fn cached(&self, ip: u64) -> *mut Block {
        // SAFETY: `new`'s contract.
        unsafe { (*self.tlb).block_cache[cache_slot(ip)] }
    }

    #[inline]
    fn set_cached(&self, ip: u64, block: *mut Block) {
        // SAFETY: `new`'s contract.
        unsafe { (*self.tlb).block_cache[cache_slot(ip)] = block };
    }

    /// The guest pc the next block starts at.
    #[inline]
    fn pc(&self) -> u64 {
        // SAFETY: `new`'s contract.
        unsafe { (*self.frame).cpu.pc }
    }

    #[inline]
    fn last_block(&self) -> *mut Block {
        // SAFETY: `new`'s contract.
        unsafe { (*self.frame).last_block }
    }

    #[inline]
    fn set_last_block(&self, block: *mut Block) {
        // SAFETY: `new`'s contract.
        unsafe { (*self.frame).last_block = block };
    }

    /// Advance the block counter, answering the new count.
    #[inline]
    fn tick(&self) -> i64 {
        // SAFETY: `new`'s contract.
        unsafe {
            (*self.frame).cpu.cycle += 1;
            (*self.frame).cpu.cycle
        }
    }

    #[inline]
    fn cycle(&self) -> i64 {
        // SAFETY: `new`'s contract.
        unsafe { (*self.frame).cpu.cycle }
    }

    /// Take the poke flag if it is set: another thread sets it to make this
    /// one leave the JIT at the next block boundary rather than at the next
    /// quantum.
    #[inline]
    fn take_poke(&self) -> bool {
        // SAFETY: `new`'s contract; `poked_ptr` is null or a live flag.
        unsafe { (*self.frame).cpu.poked_ptr.as_ref() }.is_some_and(|p| p.swap(false, Ordering::Acquire))
    }

    /// Whether the poke came through another CPU's flag than the caller's,
    /// for the counter that tells the two apart.
    fn poked_from_elsewhere(&self) -> bool {
        // SAFETY: `new`'s contract.
        unsafe { (*self.frame).cpu.poked_ptr != &raw mut (*self.cpu)._poked }
    }

    /// Has this thread held the address space long enough?
    #[inline]
    fn quantum_over(&self, since: i64) -> bool {
        // SAFETY: `new`'s contract; the CPU's address space is live with it.
        unsafe { quantum_over((*self.cpu).mmu, self.cycle(), since) }
    }

    /// A fault with no address, recorded in the frame for `handle_interrupt`.
    fn fault_at_nothing(&self) {
        // SAFETY: `new`'s contract.
        unsafe {
            (*self.frame).cpu.segfault_addr = 0;
            (*self.frame).cpu.segfault_was_write = false;
        }
    }

    /// The return targets, forgotten.
    fn clear_ret_cache(&self) {
        // SAFETY: `new`'s contract.
        unsafe { (*self.frame).ret_cache.fill(0) };
    }

    /// The guest CPU, for the diagnostics that print it.
    fn guest(&self) -> &Cpu {
        // SAFETY: `new`'s contract; read between blocks, when nothing writes it.
        unsafe { &(*self.frame).cpu }
    }

    /// Run `block` until it leaves, with the crash handler told this thread is
    /// in the JIT and where the block started.
    ///
    /// # Safety
    /// `block` is a block of this address space, as `block_for` answers one.
    unsafe fn enter(&self, block: *mut Block) -> c_int {
        // SAFETY: `jit` is null or this thread's slot.
        let jit = unsafe { self.jit.as_ref() };
        if let Some(jit) = jit {
            jit.saved_pc.store(self.pc(), Ordering::Relaxed);
            jit.in_jit.store(1, Ordering::Relaxed);
        }
        // SAFETY: the caller's contract and `new`'s.
        let interrupt = unsafe { fiber_enter(block, self.frame, self.tlb) };
        if let Some(jit) = jit {
            jit.in_jit.store(0, Ordering::Relaxed);
        }
        interrupt
    }

    /// Leave the JIT with `interrupt`, handing the CPU back.
    ///
    /// `_poked` is **not** copied back. It belongs to the `poked_ptr` channel,
    /// and a copy would resurrect a stale `true` taken at loop entry: the
    /// exchange cleared the live byte and returned `INT_TIMER`, and the
    /// copy-back would re-arm it — making every block dispatch interrupt for
    /// ever, and a `fork` inherit the storm. `copy_state` leaves it out; this
    /// read it, copied the whole struct and wrote the old value back until
    /// 2026-10-16, which lost a poke another thread stored between the read
    /// and the write-back.
    fn leave(self, interrupt: c_int) -> c_int {
        // SAFETY: `new` took the read side; `new`'s contract for the copy.
        unsafe {
            locks::wrlock::read_unlock(&self.asbestos.jetsam_lock);
            ffi::copy_state(self.cpu, &raw const (*self.frame).cpu);
        }
        interrupt
    }

    /// Leave with `INT_GPF` for a pc nothing can be compiled from, reporting
    /// `addr` and resuming the caller at `pc`.
    ///
    /// **Into the frame**, which `leave` copies over the caller's CPU. Until
    /// 2026-10-18 the address went onto the caller's CPU *before* that copy,
    /// which overwrote it, and the guest's `si_addr` for a branch to
    /// 0x0001_0000_0000_4000 came out as 0x4000 (`tests/guest` bad_pc_addr).
    fn leave_on_bad_pc(self, addr: u64, pc: u64) -> c_int {
        // SAFETY: `new`'s contract.
        unsafe {
            (*self.frame).cpu.segfault_addr = addr;
            (*self.frame).cpu.segfault_was_write = false;
            (*self.frame).cpu.pc = pc;
        }
        self.leave(INT_GPF)
    }

    fn count(&self, counter: &AtomicU64) {
        if self.counting {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The block to run at `ip`, compiling one if there is none.
///
/// Null means the compile failed, which the caller turns into `INT_GPF`.
fn block_for(run: &Run<'_>, ip: u64) -> *mut Block {
    let env = *util_iulenv::env();

    // IUL_NO_BLOCK_CACHE=2 never reuses a translated block, and IUL_NO_JIT_REUSE
    // does the same for the address range a guest JIT allocates from. Both are
    // for localising a stale-translation suspect; the blocks pile up until an
    // invalidation takes them.
    let fresh =
        env.no_block_cache >= 2 || (env.no_jit_reuse && (0xc000_0000..0xe000_0000).contains(&ip));
    if fresh {
        let mut cache = run.asbestos.cache();
        // SAFETY: the TLB is this thread's (`Run::new`).
        let block = unsafe { asbestos_gen::compile::compile_raw(ip, run.tlb) };
        if !block.is_null() {
            // SAFETY: just compiled, owned by nothing else.
            unsafe { cache.insert(block) };
        }
        return block;
    }

    let cached = run.cached(ip);
    // SAFETY: a slot holds null or a block of this address space, and nothing
    // frees one while this thread holds `jetsam_lock` for reading.
    if !cached.is_null() && unsafe { (*cached).addr } == ip {
        return cached;
    }
    run.count(&ST_BLOCK_CACHE_MISS);

    // One release however many ways out: the compile failure below used to
    // write its own, four lines from the other.
    let mut cache = run.asbestos.cache();
    let mut block = cache.lookup(ip);
    if block.is_null() {
        // SAFETY: as above.
        block = unsafe { compile_protected(run.asbestos, &mut cache, ip, run.tlb) };
        if block.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: just compiled, owned by nothing else.
        unsafe { cache.insert(block) };
        run.count(&ST_BLOCK_COMPILE);
    }
    run.set_cached(ip, block);
    block
}

/// Patch the previous block's exit to jump straight into this one.
///
/// Skipped when the lock is held: a chain is an optimisation, and waiting for
/// it would put the dispatch loop behind whatever is compiling.
fn chain(run: &Run<'_>, last: *mut Block, block: *mut Block) {
    if util_iulenv::env().no_chain || last.is_null() || block.is_null() {
        return;
    }
    // A block marked jetsam is assumed to have no pointers left, so no new one
    // may be minted to or from it.
    // SAFETY: both are blocks of this address space, and nothing frees a block
    // while a thread holds `jetsam_lock` for reading, as this one does.
    let usable = unsafe {
        !(*last).is_jetsam.load(Ordering::Relaxed)
            && !(*block).is_jetsam.load(Ordering::Relaxed)
            && (!(*last).jump_ip[0].is_null() || !(*last).jump_ip[1].is_null())
    };
    if !usable {
        return;
    }
    run.count(&ST_CHAIN_ATTEMPTS);
    if let Some(mut cache) = run.asbestos.try_cache() {
        // SAFETY: as above.
        unsafe { cache.try_chain(last, block) };
    }
}

/// Run until something interrupts, and answer what.
///
/// # Safety
/// Called on a guest thread, with `cpu` and `tlb` its own.
/* Not `extern "C"`: nothing outside this crate calls it. It was exported while
 * `asbestos/asbestos.c` held `cpu_run_to_interrupt`, and `dead_exports` went on
 * passing afterwards only because a *comment* in that file still named it --
 * which is a gap in what the tool models, and is why the entry disappeared the
 * day the comment did. */
pub(super) unsafe fn cpu_step_to_interrupt(cpu: *mut Cpu, tlb: *mut Tlb) -> c_int {
    // SAFETY: the running address space's JIT; see `cpu_run_to_interrupt`.
    let asbestos = unsafe { Asbestos::of((*(*cpu).mmu).asbestos) }.expect("a running address space has a JIT");

    // The frame is kept on the TLB and reused: it is about 48 KB, and
    // allocating and zeroing one per syscall was most of the cost of a short
    // one.
    //
    // **Except when this is re-entered**, which [`prebuilt_call`] does: a
    // prebuilt spec_fn that hits a guest `bl` runs the callee through the
    // ordinary dispatch loop, on a thread already inside it. One frame per TLB
    // means the nested call writes over the outer one, and `hand_back` on the
    // way out restores the *inner* CPU into the outer run — which is a hang,
    // and is what `tests/offload/prebuilt/run.sh`'s mixed-execution case did
    // the first time it was able to reach this path at all, on 2026-09-08. A
    // nested call allocates and frees, which costs what the C did before the
    // reuse and happens only under an offload handler.
    let depth = prebuilt::current_depth();
    let frame: *mut Frame = if depth == 0 {
        // SAFETY: this thread's own TLB, which nothing else touches.
        let owned = unsafe { (*tlb).frame.get_or_insert_with(Frame::new_boxed) };
        &raw mut **owned
    } else {
        prebuilt::nested_frame(depth)
    };

    // SAFETY: the caller's contract, and `frame` is this thread's.
    let run = unsafe { Run::new(cpu, tlb, asbestos, frame) };
    if run.block_cache_stale() {
        run.drop_block_caches();
    }
    run.set_last_block(std::ptr::null_mut());
    // SAFETY: both this thread's, and no gadget is running.
    unsafe { ffi::copy_state(&raw mut (*frame).cpu, cpu) };
    debug_assert_eq!(asbestos.mmu, unsafe { (*cpu).mmu });

    let mut interrupt = INT_NONE;
    let mut crash_retries = 0;
    // Where this quantum started. See `quantum_over` for why a delta.
    let mut quantum_start = run.cycle();

    while interrupt == INT_NONE {
        // Inside the loop and not only at entry: an invalidation can land
        // between two `fiber_enter` calls.
        if run.block_cache_stale() {
            run.drop_block_caches();
        }

        let ip = run.pc();
        if util_iulenv::env().pc_trace_file.is_some() {
            asbestos_diag::diag_pc_trace(ip);
        }

        // A pc with any of the top sixteen bits set is corrupted state: a
        // `blr`/`ret` landed on a `fake_ip` tag, or a sentinel pointer leaked
        // through guest memory -- a zero-initialised V8 heap slot plus pointer
        // tagging does it. Report it as a fault at the tagged address rather
        // than compiling from it, which would read unmapped memory for ever.
        //
        // The pc stays as it is, as Linux leaves it in the signal frame: it
        // was masked to 48 bits here, and the fault handler then rewrote the
        // fault address from that masked pc.
        if ip & 0xffff_0000_0000_0000 != 0 {
            return run.leave_on_bad_pc(ip, ip);
        }

        // A null pc is corrupted state too -- a `ret` with `x30` clobbered to
        // zero. Linux would deliver `SIGSEGV`; here the address resolves to the
        // zero page this kernel maps below 1 MB, so nothing faults and
        // `handle_interrupt` would re-enter for ever.
        if ip == 0 {
            if util_iulenv::env().nullpc_dbg {
                let c = run.guest();
                let regs = c.regs;
                eprintln!(
                    "[NULLPC] lr(x30)={:#x} sp={:#x} x0={:#x} x1={:#x} x2={:#x} x16={:#x} x17={:#x}",
                    regs[30], c.sp, regs[0], regs[1], regs[2], regs[16], regs[17]
                );
            }
            return run.leave_on_bad_pc(0, 0);
        }

        // A prebuilt gadget's `spec_fn` hit a guest call: it set the link
        // register to this sentinel and re-entered here to run the callee, and
        // the callee has now returned.
        if ip == ffi::PREBUILT_SENTINEL {
            return run.leave(INT_PREBUILT_RET);
        }

        // Symbol-level offload, if an embedder registered anything. Lossless:
        // nothing registered, no match, or a handler that declines all fall
        // through to the gadgets.
        if offloadsym::native_offload_sym_active() {
            // A handler copies guest memory by value, so the TLB has to be
            // fresh: after a `fork` or an `mmap` its entries point into the
            // parent's copy-on-write pages.
            if run.mappings_moved() {
                run.drop_everything();
            }
            // SAFETY: this thread's CPU and TLB, between blocks.
            let dispatched =
                unsafe { offloadsym::native_offload_sym_dispatch(ip, &raw mut (*frame).cpu, tlb) };
            if dispatched {
                // The handler advanced the pc. Do what the gadget path would do
                // about pokes and the timer, and go round again.
                run.set_last_block(std::ptr::null_mut());
                interrupt = if run.take_poke() || run.tick() & ((1 << 10) - 1) == 0 {
                    INT_TIMER
                } else {
                    INT_NONE
                };
                continue;
            }
        }

        let block = block_for(&run, ip);
        if block.is_null() {
            run.fault_at_nothing();
            interrupt = INT_GPF;
            break;
        }

        // IUL_NO_RETCACHE makes every `ret` gadget miss, so it can never jump
        // through a cached target.
        if util_iulenv::env().no_retcache {
            run.clear_ret_cache();
        }
        chain(&run, run.last_block(), block);
        run.set_last_block(block);

        // The block may be jetsam, and that is fine: nothing frees one until
        // every thread on this address space has left the JIT.

        if util_iulenv::env().block_prof_file.is_some() {
            // SAFETY: as in `block_for`.
            let (addr, end) = unsafe { ((*block).addr, (*block).end_addr) };
            asbestos_diag::diag_block_prof(addr, (end - addr) >> 2);
        }
        run.count(&S_DISPATCH_ITERATIONS);

        // SAFETY: `block_for` answered it.
        interrupt = unsafe { run.enter(block) };

        // A host SIGSEGV inside gadget code: the handler redirected to a
        // trampoline that returns this, having already set `segfault_addr` and
        // the pc. Everything cached points at the old host pages.
        if interrupt == INT_JIT_CRASH {
            run.drop_everything();
            crash_retries += 1;
            if crash_retries >= 16 {
                interrupt = INT_GPF;
                crash_retries = 0;
            } else {
                interrupt = INT_NONE;
            }
        } else {
            crash_retries = 0;
        }

        // Every block, because another thread's `mmap` invalidates every host
        // pointer this thread has cached.
        if run.mappings_moved() {
            run.drop_everything();
        }

        if interrupt == INT_NONE && run.take_poke() {
            interrupt = INT_TIMER;
            run.count(&ST_INT_POKE);
            if run.counting && run.poked_from_elsewhere() {
                ST_INT_POKE_FOREIGN.fetch_add(1, Ordering::Relaxed);
            }
        }

        // The gadget's chained fast path advances the cycle itself and returns
        // here at every multiple of 1024; an unchained block never reaches that
        // code, so it is counted here. Both have to end the quantum, which is
        // what the delta in `quantum_over` is for.
        run.tick();
        if interrupt == INT_NONE && run.quantum_over(quantum_start) {
            quantum_start = run.cycle();
            interrupt = INT_TIMER;
            run.count(&ST_INT_CYCLE);
        }

        // The histogram samples on every block exit rather than on a timer, and
        // weights by the block's instruction count so the answer is a share of
        // instructions rather than of dispatches. Chained blocks skip this loop
        // entirely, which biases it towards code that cannot be chained -- V8's
        // computed-goto interpreter -- so a share measured here is a lower
        // bound on that code's real share.
        let last = run.last_block();
        if util_iulenv::env().pc_hist && !last.is_null() {
            // SAFETY: as in `block_for`.
            let (addr, end) = unsafe { ((*last).addr, (*last).end_addr) };
            asbestos_diag::diag_pc_hist(addr, ((end - addr) >> 2).max(1));
        }
    }

    // **After** the loop, not inside it. The body only fires on a fault, but
    // the *comparison* ran once per block, and one compare there is not free:
    // measured at 109 -> 112 ns on `getpid`, ten interleaved runs a side, with
    // `compute_bench` flat as the control. Out here it runs once per interrupt.
    if interrupt == INT_GPF {
        // SAFETY: this thread's frame and TLB, between blocks.
        unsafe { prebuilt::name_the_faulting_instruction(frame, tlb) };
    }

    run.leave(interrupt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_quantum_has_two_bounds_and_the_short_one_needs_a_waiter() {
        // Neither is a mask. The check used to be `(++cycle & 0x3ff) == 0`, and
        // the gadget's chained path returns with the counter already *at* a
        // multiple of 1024 -- so the `++` moved it off and the test never
        // fired. A guest thread that stayed in the JIT never let go of
        // `mem->lock`, and one compute-bound thread starved every mmap in its
        // address space: over twenty seconds for a `pthread_create` that takes
        // 330 us alone.
        assert_eq!(QUANTUM_BLOCKS_WANTED, 1024);
        assert_eq!(QUANTUM_BLOCKS_IDLE, 65536);
        const { assert!(QUANTUM_BLOCKS_WANTED < QUANTUM_BLOCKS_IDLE) };
    }

    #[test]
    fn the_cache_slot_spreads_the_blocks_a_program_actually_has() {
        // Blocks are a few instructions apart, and that is what has to spread:
        // the slot is the low twelve bits of the pc exclusive-ored with the
        // next twelve, so consecutive blocks land in consecutive slots.
        let size = ffi::FIBER_CACHE_SIZE as u64;
        assert_eq!(size, 4096);
        for ip in [0u64, 0x1000, 0x4000_0000, 0xdead_beef] {
            assert!(cache_slot(ip) < size as usize, "{ip:#x}");
        }
        let near: std::collections::BTreeSet<usize> =
            (0..64).map(|i| cache_slot(0x40_0000 + i * 16)).collect();
        assert_eq!(near.len(), 64, "sixty-four nearby blocks, sixty-four slots");

        // A stride of exactly 2^24 **does** alias to one slot, and that is a
        // real property of this hash rather than an oversight to fix: the two
        // halves being exclusive-ored are twelve bits apart, so a stride that
        // is a multiple of 2^24 leaves both unchanged. It is written down
        // because the first version of this test asserted the opposite and
        // failed -- nothing a guest does walks 16 MB at a time in the
        // instruction stream, where a page-granular walk (which is what the
        // *TLB*'s hash defends against, twelve bits apart there too) happens
        // constantly.
        let aliasing = 1u64 << 24;
        let same: std::collections::BTreeSet<usize> = (0..8)
            .map(|i| cache_slot(0x100_0000 + i * aliasing))
            .collect();
        assert_eq!(same.len(), 1);
    }

    #[test]
    fn a_tagged_pc_is_reported_at_the_address_it_was_tagged_with() {
        // The fault is reported at the *tagged* value, because that is what the
        // guest computed and what a person debugging it needs to see; the pc is
        // set to the low 48 bits so the recovery has somewhere to resume.
        let tagged = 0xdead_0000_0040_1000u64;
        assert_ne!(tagged & 0xffff_0000_0000_0000, 0);
        assert_eq!(tagged & 0xffff_ffff_ffff, 0x40_1000);
        assert_eq!(
            0x40_1000u64 & 0xffff_0000_0000_0000,
            0,
            "and a real pc is not tagged"
        );
    }
}

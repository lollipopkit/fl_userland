use super::*;
use kernel_sigdisp::SIG_DFL;

use kernel_sigqueue::Signals;

/// A test's queue, handed to a function that takes a [`Queue`].
fn qu<'a>(sh: &'a SigHand, q: &'a mut Signals) -> Queue<'a> {
    // SAFETY: the test owns `q` for the call, and `sh` is the lock the test
    // uses for it.
    unsafe { Queue::new(sh, q, Box::leak(Box::default())) }
}

/// One page of "guest" memory, as a [`usercopy::GuestIo`].
///
/// What is exercised is everything above it: the offsets, the order of the
/// reads and writes, and which errors stop which. The `EFAULT` boundary is
/// real — an address outside the page fails, so a test that walks off the end
/// reads its neighbour's bytes only if the code under test is wrong about a
/// length.
///
/// This used to replace usercopy entry points with linker symbols. The
/// functions under test now take guest memory as a generic parameter, so the
/// test supplies its own [`usercopy::GuestIo`] implementation and the product
/// call monomorphises to `GuestMem`.
mod fake_mem {
    use std::ffi::c_int;

    /// One page at guest address 0x1000.
    pub const BASE: u64 = 0x1000;
    pub const LEN: usize = 4096;
    pub use guest_errno::c_int_::EFAULT;
    /// The page's bytes. Locked per access; `SERIAL` is what keeps tests
    /// from sharing it.
    static BYTES: std::sync::Mutex<[u8; LEN]> = std::sync::Mutex::new([0; LEN]);

    pub fn bytes() -> std::sync::MutexGuard<'static, [u8; LEN]> {
        BYTES.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn offset(addr: u64, count: usize) -> Option<usize> {
        let off = addr.checked_sub(BASE)? as usize;
        (off.checked_add(count)? <= LEN).then_some(off)
    }

    /// The page, as the trait the functions under test are generic over.
    pub struct Page;

    impl usercopy::GuestIo for Page {
        fn read(&self, addr: u64, bytes: &mut [u8]) -> c_int {
            match offset(addr, bytes.len()) {
                Some(off) => {
                    bytes.copy_from_slice(&self::bytes()[off..off + bytes.len()]);
                    0
                }
                None => EFAULT,
            }
        }

        fn write(&self, addr: u64, bytes: &[u8]) -> c_int {
            match offset(addr, bytes.len()) {
                Some(off) => {
                    self::bytes()[off..off + bytes.len()].copy_from_slice(bytes);
                    0
                }
                None => EFAULT,
            }
        }

        fn read_u64(&self, addr: u64) -> Result<u64, c_int> {
            let mut word = [0u8; 8];
            match self.read(addr, &mut word) {
                0 => Ok(u64::from_le_bytes(word)),
                e => Err(e),
            }
        }

        fn write_u64(&self, addr: u64, value: u64) -> c_int {
            self.write(addr, &value.to_le_bytes())
        }

        fn read_string(&self, addr: u64, buf: &mut [u8]) -> Result<usize, c_int> {
            for (i, slot) in buf.iter_mut().enumerate() {
                let mut b = [0u8; 1];
                if self.read(addr + i as u64, &mut b) != 0 {
                    return Err(EFAULT);
                }
                *slot = b[0];
                if b[0] == 0 {
                    return Ok(i);
                }
            }
            Err(-36)
        }
    }
}

/// There is one page of it, because `user_read` reads `current` and there is
/// one of those. Tests run in parallel threads, so they take turns.
///
/// Found by a test that passed alone and failed in the suite: two of them wrote
/// `0x1000` at the same time and one read the other's bytes.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The lock and a zeroed page. Bind the guard to a **named** local: as a
/// temporary it is dropped at the end of the statement and the test runs
/// unlocked.
fn mem() -> (fake_mem::Page, std::sync::MutexGuard<'static, ()>) {
    // A panicking test poisons this, and every later test would then fail for a
    // reason that is not its own.
    let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    *fake_mem::bytes() = [0; fake_mem::LEN];
    (fake_mem::Page, guard)
}

fn poke(addr: u64, value: u64) {
    let off = (addr - fake_mem::BASE) as usize;
    fake_mem::bytes()[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn peek(addr: u64) -> u64 {
    let off = (addr - fake_mem::BASE) as usize;
    u64::from_le_bytes(fake_mem::bytes()[off..off + 8].try_into().unwrap())
}

fn sighand() -> std::sync::Arc<SigHand> {
    SigHand::new()
}

// --- sigset size --------------------------------------------------------

#[test]
fn only_eight_is_a_sigset() {
    assert!(sigset_size_valid(8));
    for bad in [0, 4, 12, 16, 24, 128] {
        assert!(!sigset_size_valid(bad), "size {bad} is not a sigset_t");
    }
}

#[test]
fn a_wrong_sigset_size_is_refused_before_anything_is_written() {
    let sh = sighand();
    let (m, _serial) = mem();
    poke(0x1000, 0xdead);
    // 16 was accepted by the C, which then looked at eight bytes and reported
    // success.
    assert_eq!(
        rt_sigprocmask(qu(&sh, &mut Signals::default()), &m, SIG_SETMASK, 0x1000, 0, 16),
        EINVAL
    );
    let mut q = Signals::default();
    assert_eq!(q.blocked(), 0, "and nothing was set");
    let _ = &mut q;
}

// --- rt_sigaction -------------------------------------------------------

#[test]
fn a_sigaction_round_trips_through_guest_memory() {
    let sh = sighand();
    let (m, _serial) = mem();
    let new = 0x1000;
    let old = 0x1000 + SigActionAbi::SIZE;

    poke(new + SigActionAbi::HANDLER, 0x400abc);
    poke(new + SigActionAbi::FLAGS, kernel_sigdisp::SA_ONSTACK as u64);
    poke(new + SigActionAbi::RESTORER, 0x400def);
    poke(new + SigActionAbi::MASK, 0xff);

    assert_eq!(rt_sigaction(&sh, &m, 10, new, 0, 8), 0);
    assert_eq!(sh.lock().table().handler(10), 0x400abc);
    assert_eq!(sh.lock().table().flags(10), kernel_sigdisp::SA_ONSTACK);
    assert_eq!(sh.lock().table().mask(10), 0xff);

    // Read it back out through the other pointer.
    assert_eq!(rt_sigaction(&sh, &m, 10, 0, old, 8), 0);
    assert_eq!(peek(old + SigActionAbi::HANDLER), 0x400abc);
    assert_eq!(
        peek(old + SigActionAbi::FLAGS),
        kernel_sigdisp::SA_ONSTACK as u64
    );
    assert_eq!(peek(old + SigActionAbi::RESTORER), 0x400def);
    assert_eq!(peek(old + SigActionAbi::MASK), 0xff);
}

#[test]
fn the_old_disposition_is_the_one_being_replaced() {
    let sh = sighand();
    let (m, _serial) = mem();
    let new = 0x1000;
    let old = 0x1000 + SigActionAbi::SIZE;

    poke(new + SigActionAbi::HANDLER, 0x111);
    poke(new + SigActionAbi::FLAGS, 0);
    poke(new + SigActionAbi::RESTORER, 0);
    poke(new + SigActionAbi::MASK, 0);
    assert_eq!(rt_sigaction(&sh, &m, 10, new, 0, 8), 0);

    poke(new + SigActionAbi::HANDLER, 0x222);
    assert_eq!(rt_sigaction(&sh, &m, 10, new, old, 8), 0);
    assert_eq!(peek(old + SigActionAbi::HANDLER), 0x111, "the previous one");
    assert_eq!(
        sh.lock().table().handler(10),
        0x222,
        "and the new one is in"
    );
}

/// The crash `rt_sigaction(0x80000000, ...)` used to be.
#[test]
fn a_signal_number_with_the_top_bit_set_is_refused() {
    let sh = sighand();
    let (m, _serial) = mem();
    poke(0x1000, 0x400abc);
    poke(0x1008, 0);
    poke(0x1010, 0);
    poke(0x1018, 0);
    assert_eq!(rt_sigaction(&sh, &m, 0x8000_0000, 0x1000, 0, 8), EINVAL);
    assert_eq!(rt_sigaction(&sh, &m, u32::MAX, 0x1000, 0, 8), EINVAL);
    assert_eq!(rt_sigaction(&sh, &m, 0, 0x1000, 0, 8), EINVAL, "and zero");
    assert_eq!(rt_sigaction(&sh, &m, 65, 0x1000, 0, 8), EINVAL, "and 65");
}

#[test]
fn sigkill_may_be_read_and_not_written() {
    let sh = sighand();
    let (m, _serial) = mem();
    poke(0x1000, 0x400abc);
    poke(0x1008, 0);
    poke(0x1010, 0);
    poke(0x1018, 0);
    assert_eq!(rt_sigaction(&sh, &m, 9, 0x1000, 0, 8), EINVAL);

    let old = 0x1000 + SigActionAbi::SIZE;
    assert_eq!(rt_sigaction(&sh, &m, 9, 0, old, 8), 0);
    assert_eq!(peek(old + SigActionAbi::HANDLER), SIG_DFL);
}

#[test]
fn an_unreadable_action_faults_without_changing_anything() {
    let sh = sighand();
    let (m, _serial) = mem();
    sh.lock().table_mut().set(
        10,
        Disposition {
            handler: 0x999,
            ..Disposition::default()
        },
    );
    // Below the mapped page.
    assert_eq!(rt_sigaction(&sh, &m, 10, 0x10, 0, 8), EFAULT);
    assert_eq!(sh.lock().table().handler(10), 0x999);
}

// --- rt_sigprocmask -----------------------------------------------------

#[test]
fn the_three_hows() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();

    poke(0x1000, 0b1100);
    assert_eq!(
        rt_sigprocmask(qu(&sh, &mut q), &m, SIG_SETMASK, 0x1000, 0, 8),
        0
    );
    assert_eq!(q.blocked(), 0b1100);

    poke(0x1000, 0b0011);
    assert_eq!(rt_sigprocmask(qu(&sh, &mut q), &m, SIG_BLOCK, 0x1000, 0, 8), 0);
    assert_eq!(q.blocked(), 0b1111);

    poke(0x1000, 0b0101);
    assert_eq!(
        rt_sigprocmask(qu(&sh, &mut q), &m, SIG_UNBLOCK, 0x1000, 0, 8),
        0
    );
    assert_eq!(q.blocked(), 0b1010);
}

#[test]
fn a_bad_how_changes_nothing() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    poke(0x1000, 0b1100);
    assert_eq!(
        rt_sigprocmask(qu(&sh, &mut q), &m, SIG_SETMASK, 0x1000, 0, 8),
        0
    );

    poke(0x1000, 0xff);
    assert_eq!(rt_sigprocmask(qu(&sh, &mut q), &m, 99, 0x1000, 0, 8), EINVAL);
    assert_eq!(q.blocked(), 0b1100, "the mask is what it was");
}

/// The copy happens first, so an unreadable `set` is `EFAULT` even when the
/// `how` is also wrong. Linux's order, and observable.
#[test]
fn an_unreadable_set_faults_before_the_how_is_judged() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    assert_eq!(rt_sigprocmask(qu(&sh, &mut q), &m, 99, 0x10, 0, 8), EFAULT);
}

/// A `how` nobody looks at, because there is nothing to apply it to.
#[test]
fn a_bad_how_with_no_set_still_reports_the_old_mask() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    q.set_blocked(0b1100);
    assert_eq!(rt_sigprocmask(qu(&sh, &mut q), &m, 99, 0, 0x1000, 8), 0);
    assert_eq!(peek(0x1000), 0b1100);
}

#[test]
fn the_reported_mask_is_the_one_before_the_change() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    q.set_blocked(0b1100);

    poke(0x1000, 0b0011);
    assert_eq!(
        rt_sigprocmask(qu(&sh, &mut q), &m, SIG_SETMASK, 0x1000, 0x1008, 8),
        0
    );
    assert_eq!(peek(0x1008), 0b1100, "what it was, not what it is");
    assert_eq!(q.blocked(), 0b0011);
}

#[test]
fn the_two_unblockable_signals_are_dropped_without_an_error() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    poke(0x1000, !0u64);
    assert_eq!(
        rt_sigprocmask(qu(&sh, &mut q), &m, SIG_SETMASK, 0x1000, 0, 8),
        0
    );
    assert_eq!(q.blocked() & (1 << 8), 0, "SIGKILL");
    assert_eq!(q.blocked() & (1 << 18), 0, "SIGSTOP");
}

// --- rt_sigpending ------------------------------------------------------

#[test]
fn pending_is_what_has_arrived_and_is_blocked() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    q.set_blocked(kernel_sigqueue::mask_of(10));
    q.arrive(10, Default::default(), true);
    q.arrive(11, Default::default(), true);

    assert_eq!(rt_sigpending(qu(&sh, &mut q), &m, 0x1000, 8), 0);
    assert_eq!(
        peek(0x1000),
        kernel_sigqueue::mask_of(10),
        "11 arrived but is not blocked, so it is not pending -- it is about to run"
    );
}

#[test]
fn pending_refuses_a_size_above_the_masks() {
    let sh = sighand();
    let (m, _serial) = mem();
    assert_eq!(
        rt_sigpending(qu(&sh, &mut Signals::default()), &m, 0x1000, 16),
        EINVAL
    );
    assert_eq!(
        rt_sigpending(qu(&sh, &mut Signals::default()), &m, 0x1000, 9),
        EINVAL
    );
}

/// **This one's rule is `>` where its neighbours' is `!=`.** Linux writes
/// `sigsetsize` bytes of the mask, so a smaller size is a request for a prefix
/// and is answered; `rt_sigprocmask` next door refuses anything but 8. Measured
/// against a real kernel by `tests/guest/src/bin/table_probe.rs`, which is what
/// found it: this refused every size but 8.
#[test]
fn pending_accepts_a_smaller_size_and_writes_that_many_bytes() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    q.set_blocked(!0);
    q.arrive(40, Default::default(), true);

    poke(0x1000, 0xdead_beef_dead_beef);
    assert_eq!(rt_sigpending(qu(&sh, &mut q), &m, 0x1000, 4), 0);
    let written = peek(0x1000);
    assert_eq!(
        written & 0xffff_ffff,
        kernel_sigqueue::mask_of(40) & 0xffff_ffff,
        "the low four bytes are the mask's"
    );
    assert_eq!(
        written >> 32,
        0xdead_beef,
        "and the four above them were not touched"
    );
}

/// A zero-length copy touches nothing, so the address is never looked at — the
/// probe asks this as `rt_sigpending(NULL, 0)`, which is 0 on a real kernel.
#[test]
fn pending_with_no_room_writes_nothing_and_succeeds() {
    let sh = sighand();
    let (m, _serial) = mem();
    assert_eq!(rt_sigpending(qu(&sh, &mut Signals::default()), &m, 0, 0), 0);
}

// --- sigaltstack --------------------------------------------------------

#[test]
fn an_alternate_stack_round_trips() {
    let sh = sighand();
    let (m, _serial) = mem();
    let ss = 0x1000;
    let old = 0x1000 + StackTAbi::BYTES;

    poke(ss + StackTAbi::SP, 0x50000);
    poke(ss + StackTAbi::FLAGS, 0);
    poke(ss + StackTAbi::SIZE, kernel_sigdisp::MINSIGSTKSZ);
    let mut q = Signals::default();
    assert_eq!(sigaltstack(qu(&sh, &mut q), &m, 0x90000, ss, 0), 0);

    assert_eq!(sigaltstack(qu(&sh, &mut q), &m, 0x90000, 0, old), 0);
    assert_eq!(peek(old + StackTAbi::SP), 0x50000);
    assert_eq!(peek(old + StackTAbi::SIZE), kernel_sigdisp::MINSIGSTKSZ);
    assert_eq!(
        peek(old + StackTAbi::FLAGS),
        0,
        "neither disabled nor on it"
    );
}

#[test]
fn no_alternate_stack_reports_ss_disable() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    assert_eq!(sigaltstack(qu(&sh, &mut q), &m, 0x90000, 0, 0x1000), 0);
    assert_eq!(
        peek(0x1000 + StackTAbi::FLAGS),
        kernel_sigdisp::SS_DISABLE as u64
    );
}

#[test]
fn running_on_it_reports_ss_onstack_and_refuses_a_change() {
    let sh = sighand();
    let (m, _serial) = mem();
    let ss = 0x1000;
    poke(ss + StackTAbi::SP, 0x50000);
    poke(ss + StackTAbi::FLAGS, 0);
    poke(ss + StackTAbi::SIZE, kernel_sigdisp::MINSIGSTKSZ);
    let mut q = Signals::default();
    assert_eq!(sigaltstack(qu(&sh, &mut q), &m, 0x90000, ss, 0), 0);

    // An sp inside it.
    let on_it = 0x50000 + kernel_sigdisp::MINSIGSTKSZ / 2;
    let old = 0x1000 + StackTAbi::BYTES;
    assert_eq!(sigaltstack(qu(&sh, &mut q), &m, on_it, 0, old), 0);
    assert_eq!(
        peek(old + StackTAbi::FLAGS),
        kernel_sigdisp::SS_ONSTACK as u64
    );

    // And it may not be moved out from under the frame that is on it.
    poke(ss + StackTAbi::SP, 0x60000);
    assert_eq!(sigaltstack(qu(&sh, &mut q), &m, on_it, ss, 0), -1, "EPERM");
}

#[test]
fn a_stack_below_the_minimum_is_enomem() {
    let sh = sighand();
    let (m, _serial) = mem();
    let ss = 0x1000;
    poke(ss + StackTAbi::SP, 0x50000);
    poke(ss + StackTAbi::FLAGS, 0);
    poke(ss + StackTAbi::SIZE, kernel_sigdisp::MINSIGSTKSZ - 1);
    assert_eq!(
        sigaltstack(qu(&sh, &mut Signals::default()), &m, 0x90000, ss, 0),
        -12
    );
}

/// The padding above `ss_flags` is not part of the value.
#[test]
fn the_flags_word_is_four_bytes() {
    let sh = sighand();
    let (m, _serial) = mem();
    let ss = 0x1000;
    poke(ss + StackTAbi::SP, 0x50000);
    // SS_DISABLE in the low half, rubbish in the padding above it.
    poke(
        ss + StackTAbi::FLAGS,
        kernel_sigdisp::SS_DISABLE as u64 | 0xdead_0000_0000,
    );
    poke(ss + StackTAbi::SIZE, 0);
    let mut q = Signals::default();
    q.altstack_mut()
        .set(0x50000, kernel_sigdisp::MINSIGSTKSZ, 0, 0)
        .unwrap();
    assert_eq!(sigaltstack(qu(&sh, &mut q), &m, 0x90000, ss, 0), 0);
    assert_eq!(
        q.altstack().bounds(),
        (0, 0),
        "SS_DISABLE was read despite the padding"
    );
}

#[test]
fn an_unwritable_old_stack_faults() {
    let sh = sighand();
    let (m, _serial) = mem();
    assert_eq!(
        sigaltstack(qu(&sh, &mut Signals::default()), &m, 0x90000, 0, 0x10),
        EFAULT
    );
}

// --- rt_sigtimedwait ----------------------------------------------------

/// The address of a `Signals` value a second thread also touches, under
/// sighand's lock. It is converted back to a pointer only at `queue_mut`.
struct QueuePtr(usize);

#[test]
fn a_signal_already_queued_is_taken_without_waiting() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    // Blocked, which is what a thread calling sigwaitinfo does to the signal it
    // is about to wait for.
    q.set_blocked(kernel_sigqueue::mask_of(10));
    q.arrive(10, Default::default(), true);

    poke(0x1000, kernel_sigqueue::mask_of(10));
    let started = Instant::now();
    // A ten-second timeout it must not spend.
    let r = rt_sigtimedwait(
        qu(&sh, &mut q),
        &m,
        0x1000,
        0x1008,
        Some(Duration::from_secs(10)),
        8,
    );
    assert_eq!(r, 10, "the signal number");
    assert!(started.elapsed() < Duration::from_secs(1), "did not wait");
    assert_eq!(
        peek(0x1008) & 0xffff_ffff,
        10,
        "siginfo's first word is the signal"
    );
}

#[test]
fn an_empty_set_times_out_as_eagain() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    poke(0x1000, kernel_sigqueue::mask_of(10));
    let started = Instant::now();
    let r = rt_sigtimedwait(
        qu(&sh, &mut q),
        &m,
        0x1000,
        0,
        Some(Duration::from_millis(50)),
        8,
    );
    assert_eq!(r, EAGAIN);
    assert!(
        started.elapsed() >= Duration::from_millis(40),
        "it did wait"
    );
}

/// A deadline, not a duration: a wakeup that is not the signal must not re-arm
/// the whole timeout. Three spurious notifies against a 150 ms deadline, each
/// 50 ms apart — with the C's re-arming shape this waits 300 ms and with a
/// deadline it waits 150.
#[test]
fn a_spurious_wakeup_does_not_extend_the_deadline() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    poke(0x1000, kernel_sigqueue::mask_of(10));

    let waker = {
        let sh = std::sync::Arc::clone(&sh);
        std::thread::spawn(move || {
            for _ in 0..3 {
                std::thread::sleep(Duration::from_millis(50));
                sh.notify();
            }
        })
    };

    let started = Instant::now();
    let r = rt_sigtimedwait(
        qu(&sh, &mut q),
        &m,
        0x1000,
        0,
        Some(Duration::from_millis(150)),
        8,
    );
    let waited = started.elapsed();
    waker.join().unwrap();
    assert_eq!(r, EAGAIN);
    assert!(
        waited < Duration::from_millis(280),
        "waited {waited:?}, which is the timeout re-armed rather than a deadline"
    );
}

#[test]
fn a_signal_that_arrives_during_the_wait_is_taken() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    q.set_blocked(kernel_sigqueue::mask_of(10));
    poke(0x1000, kernel_sigqueue::mask_of(10));

    let ptr = QueuePtr(&mut q as *mut Signals as usize);
    let sender = {
        let sh = std::sync::Arc::clone(&sh);
        std::thread::spawn(move || {
            let ptr = ptr;
            std::thread::sleep(Duration::from_millis(30));
            {
                let mut guard = unsafe { sh.lock_queue(ptr.0 as *mut Signals, Box::leak(Box::default())) };
                guard.queue_mut().arrive(
                    10,
                    Default::default(),
                    true,
                );
            }
            sh.notify();
        })
    };

    let r = rt_sigtimedwait(qu(&sh, &mut q), &m, 0x1000, 0, Some(Duration::from_secs(10)), 8);
    sender.join().unwrap();
    assert_eq!(r, 10);
}

/// Naming them would let a thread swallow its own kill.
#[test]
fn sigkill_and_sigstop_are_dropped_from_the_set() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    q.set_blocked(!0);
    q.arrive(9, Default::default(), false); // SIGKILL
    q.arrive(19, Default::default(), false); // SIGSTOP

    poke(0x1000, !0u64);
    let r = rt_sigtimedwait(
        qu(&sh, &mut q),
        &m,
        0x1000,
        0,
        Some(Duration::from_millis(50)),
        8,
    );
    assert_eq!(r, EAGAIN, "neither may be taken off the queue");
    assert!(
        q.pending() & kernel_sigqueue::mask_of(9) != 0,
        "SIGKILL still queued"
    );
    assert!(
        q.pending() & kernel_sigqueue::mask_of(19) != 0,
        "SIGSTOP still queued"
    );
}

#[test]
fn an_unreadable_set_is_refused_before_the_wait() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    let started = Instant::now();
    assert_eq!(
        rt_sigtimedwait(qu(&sh, &mut q), &m, 0x10, 0, Some(Duration::from_secs(10)), 8),
        EFAULT
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn a_wrong_set_size_is_einval() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    assert_eq!(
        rt_sigtimedwait(qu(&sh, &mut q), &m, 0x1000, 0, None, 16),
        EINVAL
    );
}

/// The signal is off the queue by the time the copy runs, so a bad `info_addr`
/// cannot un-consume it. Linux has the same shape.
#[test]
fn a_bad_info_pointer_faults_and_the_signal_is_still_consumed() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    q.set_blocked(kernel_sigqueue::mask_of(10));
    q.arrive(10, Default::default(), true);
    poke(0x1000, kernel_sigqueue::mask_of(10));

    assert_eq!(
        rt_sigtimedwait(qu(&sh, &mut q), &m, 0x1000, 0x10, Some(Duration::ZERO), 8),
        EFAULT
    );
    assert_eq!(q.pending() & kernel_sigqueue::mask_of(10), 0, "consumed");
}

// --- rt_sigsuspend ------------------------------------------------------

#[test]
fn sigsuspend_refuses_a_bad_mask_pointer_without_waiting() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    let started = Instant::now();
    assert_eq!(rt_sigsuspend(qu(&sh, &mut q), &m, 0x10, 8), EFAULT);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(!q.has_saved_mask(), "and did not swap the mask");
}

#[test]
fn sigsuspend_refuses_a_wrong_size() {
    let sh = sighand();
    let (m, _serial) = mem();
    let mut q = Signals::default();
    assert_eq!(rt_sigsuspend(qu(&sh, &mut q), &m, 0x1000, 16), EINVAL);
}

/* `the_c_entry_points_reach_the_same_code` was here until 2026-09-09, driving
 * six `signalcalls_*` entry points that each did `&*(sh as *const SigHand)`,
 * `&GuestMem::current()` and a call to the function above.
 *
 * Those existed because the `sys_*` wrappers lived in
 * `crates/kernel/signaldeliver` and had to reach across a crate boundary. They
 * are in this file now, so the facade was a same-crate indirection and is
 * folded into its six callers — which is `CLAUDE.md`'s "a test that restates
 * its subject": what it asserted was that a wrapper calls the thing it wraps.
 *
 * And it only passed because of a defect: `&GuestMem::current()` reads the real
 * address space, and the `#[no_mangle] user_read` double in `fake_mem`
 * intercepted it. With the double gone — the functions take the memory as a
 * generic parameter now — it read a thread with no task and answered EFAULT.
 * The `sys_*` wrappers are covered by `guest_tests.sh`'s 42-check
 * `rt_sigprocmask and rt_sigaction at the syscall boundary` group, which drives
 * them through a real guest. */

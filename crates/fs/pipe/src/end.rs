//! Read, write, polling, and duplication semantics for one pipe end.

use super::*;

impl End {
    /// Reads into `buf`. Returns the byte count, 0 for end of file, or a
    /// negative errno.
    pub fn read(&self, buf: &mut [u8], nonblock: bool) -> isize {
        // The wrong end. A descriptor's access mode is what normally stops
        // this, and the object must not rely on the descriptor being right:
        // the first version asserted instead, and a `debug_assert` in an
        // `extern "C"` function is an **abort** -- so `write()` on the read end
        // of a pipe took the whole emulator down.
        if !self.reading {
            return EBADF;
        }
        let mut g = self.pipe.inner.lock();
        loop {
            if !g.buf.is_empty() {
                break;
            }
            // No data. With no writers left that is end of file, and it stays
            // end of file for every read after it -- not an error, which is
            // what makes a drained pipe distinguishable from a broken one.
            if g.writers == 0 {
                return 0;
            }
            if buf.is_empty() {
                // A zero-length read is a no-op even on a pipe with data, and
                // must not park waiting for bytes it would not take.
                return 0;
            }
            if nonblock {
                return EAGAIN;
            }
            if g.wait(READABLE, None) == Woke::Interrupted {
                return EINTR;
            }
        }
        if buf.is_empty() {
            return 0;
        }

        // See `Inner::take` for why these are two numbers.
        let (give, consume) = g.take(buf.len());
        // Iterated rather than indexed. `give` is derived from a record
        // length, and indexing on a number that came from somewhere else is
        // an abort waiting for the two to disagree; `zip` simply stops.
        for (slot, byte) in buf[..give].iter_mut().zip(g.buf.iter()) {
            *slot = *byte;
        }
        let consume = consume.min(g.buf.len());
        g.buf.drain(..consume);

        // Room appeared, so a blocked writer can go and a poller on the write
        // end can be told. Both, not either: the waiter is on this object's
        // condition and the poller is on the other description's list.
        g.owner().notify(WRITABLE);
        self.pipe
            .notify(&self.pipe.write_watchers, POLL_WRITE as u32);
        give as isize
    }

    /// Writes `buf`. Returns the byte count, or a negative errno. `EPIPE` also
    /// means the caller owes the guest a `SIGPIPE`.
    pub fn write(&self, buf: &[u8], nonblock: bool) -> isize {
        if !self.writing {
            return EBADF; // see read()
        }
        if buf.is_empty() {
            // Linux writes nothing and reports 0 even in packet mode, where a
            // zero-length record would otherwise be a real record -- and before
            // it looks for a reader, so there is no `EPIPE` and no `SIGPIPE`.
            return 0;
        }
        let mut g = self.pipe.inner.lock();
        if g.readers == 0 {
            return EPIPE;
        }

        // How much has to fit before anything may go in. A write of at most
        // PIPE_BUF is **atomic**: it waits for room for all of it rather than
        // putting part of it in, so two writers cannot interleave a record.
        // In packet mode every write is one record and so is atomic whatever
        // its size, up to the capacity. Read once: the mode is the write
        // end's and F_SETFL can change it, and a write that decided it was a
        // packet queues one.
        let packet = g.packet_mode;
        let atomic = buf.len() <= PIPE_BUF || packet;
        loop {
            if g.readers == 0 {
                return EPIPE;
            }
            let room = g.room();
            if atomic {
                if room >= buf.len() {
                    break;
                }
                // A record larger than the pipe can never fit. Linux waits for
                // ever in blocking mode; here it would be a deadlock with no
                // way out, so packet mode refuses it -- a record above the
                // capacity is a request the pipe cannot ever satisfy.
                if packet && buf.len() > g.capacity {
                    return EAGAIN;
                }
            } else if room > 0 {
                break;
            }
            if nonblock {
                return EAGAIN;
            }
            if g.wait(WRITABLE, None) == Woke::Interrupted {
                return EINTR;
            }
        }

        let room = g.room();
        let put = if atomic {
            buf.len()
        } else {
            buf.len().min(room)
        };
        g.push(&buf[..put], packet);

        g.owner().notify(READABLE);
        self.pipe.notify(&self.pipe.read_watchers, POLL_READ as u32);
        put as isize
    }

    /// What `poll` should report for this end.
    ///
    /// Four conditions, and **each is independent of the others**. `pipe_poll`:
    ///
    /// ```c
    /// if (filp->f_mode & FMODE_READ) {
    ///     if (!pipe_empty(head, tail))
    ///         mask |= EPOLLIN | EPOLLRDNORM;
    ///     if (!writers && filp->f_version != pipe->w_counter)
    ///         mask |= EPOLLHUP;
    /// }
    /// if (filp->f_mode & FMODE_WRITE) {
    ///     if (!pipe_full(head, tail, pipe->max_usage))
    ///         mask |= EPOLLOUT | EPOLLWRNORM;
    ///     if (!pipe->readers)
    ///         mask |= EPOLLERR;
    /// }
    /// ```
    ///
    /// The first version of this wrote the two write-end conditions as
    /// `if ... else if`, and added `POLL_READ` to a hung-up read end whether or
    /// not there was anything to read. Both passed the unit tests below,
    /// because those tests were written from the same misunderstanding, and
    /// both were caught by `epoll_semantics` — which had been written against a
    /// real kernel and says a broken write end reports `OUT|ERR` and a drained
    /// hung-up read end reports `HUP` alone.
    ///
    /// `pipe_probe`'s two measurements are consistent with this and did not
    /// distinguish it: its hung-up read end still had four unread bytes in it,
    /// so `POLLIN` was right there for a reason that had nothing to do with the
    /// hangup, and its broken write end was full, so `POLLOUT` was absent for a
    /// reason that had nothing to do with the reader.
    pub fn poll(&self) -> i32 {
        let g = self.pipe.inner.lock();
        let mut events = 0;
        if self.writing {
            if g.room() > 0 {
                events |= POLL_WRITE;
            }
            if g.readers == 0 {
                events |= POLL_ERR;
            }
        }
        if self.reading {
            if !g.buf.is_empty() {
                events |= POLL_READ;
            }
            if g.writers == 0 {
                events |= POLL_HUP;
            }
        }
        events
    }

    /// `FIONREAD`: how many bytes a read would find.
    pub fn queued(&self) -> usize {
        self.pipe.inner.lock().buf.len()
    }

    /// `F_GETPIPE_SZ`.
    pub fn capacity(&self) -> usize {
        self.pipe.inner.lock().capacity
    }

    /// `F_SETPIPE_SZ`. Returns the capacity actually set, or a negative errno.
    ///
    /// `want` is 32 bits because Linux's is: `fcntl`'s `unsigned long` is
    /// narrowed to `unsigned int` on the way into `pipe_set_size`, so
    /// `F_SETPIPE_SZ(1 << 32 | 4096)` asks for 4096 there and asks for it here.
    /// `privileged` is `CAP_SYS_RESOURCE`, which is what lets a size above
    /// `pipe_max_size` through; the capacity is a bound and not an allocation,
    /// so granting a large one costs nothing until bytes arrive.
    pub fn set_capacity(&self, want: u32, privileged: bool) -> isize {
        // round_pipe_size: above 2^31 rounds to nothing, which is EINVAL;
        // everything else is rounded **up** to a power of two, floored at one
        // page. Measured: F_SETPIPE_SZ(1) and F_SETPIPE_SZ(0) both answer 4096,
        // and 100000 answers 131072. The limit is compared against the
        // *rounded* size, so 1 MB + 1 is a 2 MB request and EPERM.
        let want = want as usize;
        if want > LARGEST_CAPACITY {
            return EINVAL;
        }
        let size = want.max(MIN_CAPACITY).next_power_of_two();
        if size > MAX_CAPACITY && !privileged {
            return EPERM;
        }
        let mut g = self.pipe.inner.lock();
        if size < g.buf.len() {
            // Shrinking below what is queued would have to throw bytes away.
            return EBUSY;
        }
        let grew = size > g.capacity;
        g.capacity = size;
        if grew {
            g.owner().notify(WRITABLE);
            self.pipe
                .notify(&self.pipe.write_watchers, POLL_WRITE as u32);
        }
        size as isize
    }

    /// `F_SETFL(O_DIRECT)` on the write end, on or off. Records already queued
    /// keep their boundaries and plain bytes stay plain -- the mode decides how
    /// the *next* write is queued, which is Linux's rule too. On the read end it
    /// changes nothing, as a reader's `O_DIRECT` changes nothing on Linux.
    pub fn set_packet_mode(&self, on: bool) {
        if self.writing {
            self.pipe.inner.lock().packet_mode = on;
        }
    }

    /// Whether this is the end writes go into.
    pub fn is_write_end(&self) -> bool {
        self.writing
    }

    /// Copies up to `len` bytes from this pipe into `other` **without
    /// consuming them** — `tee(2)`.
    ///
    /// Both must be pipes, they must be different pipes, and `self` must be a
    /// read end while `other` is a write end. Returns the byte count or a
    /// negative errno.
    pub fn tee(&self, other: &End, len: usize, nonblock: bool) -> isize {
        if !self.reading || !other.writing {
            return EINVAL;
        }
        if Arc::ptr_eq(&self.pipe, &other.pipe) {
            // Measured: tee() with both ends of one pipe is EINVAL.
            return EINVAL;
        }
        if len == 0 {
            return 0;
        }
        // Two locks, and the order matters. Taken source-then-destination
        // always: two threads teeing in opposite directions between the same
        // pair would otherwise deadlock, and the addresses give a total order
        // that both agree on.
        let (first, second) = if Arc::as_ptr(&self.pipe) < Arc::as_ptr(&other.pipe) {
            (&self.pipe, &other.pipe)
        } else {
            (&other.pipe, &self.pipe)
        };
        let mut g1 = first.inner.lock();
        let mut g2 = second.inner.lock();
        let (src, dst) = if Arc::ptr_eq(first, &self.pipe) {
            (&mut *g1, &mut *g2)
        } else {
            (&mut *g2, &mut *g1)
        };

        if dst.readers == 0 {
            return EPIPE;
        }
        if src.buf.is_empty() {
            return if src.writers == 0 {
                0
            } else if nonblock {
                EAGAIN
            } else {
                // Blocking tee would need to wait on the source's condition
                // while holding the destination's lock, which is the shape
                // that deadlocks. Callers get EAGAIN and poll; nothing in the
                // tree blocks on tee.
                EAGAIN
            };
        }
        let n = len.min(src.buf.len()).min(dst.room());
        if n == 0 {
            return EAGAIN;
        }
        // Copied, not moved: the source keeps every byte. Segment by segment,
        // because a tee'd buffer keeps its flags on Linux (`link_pipe` copies
        // the buffer and cuts only the last one's length): a record stays a
        // record in the destination and plain bytes stay plain, whatever mode
        // the destination's writer is in.
        let copied: Vec<u8> = src.buf.iter().take(n).copied().collect();
        let mut at = 0;
        for seg in src.segments.iter() {
            if at >= n {
                break;
            }
            let end = (at + seg.len).min(n);
            dst.push(&copied[at..end], seg.packet);
            at = end;
        }
        drop(g1);
        drop(g2);
        other.pipe.inner.notify(READABLE);
        other
            .pipe
            .notify(&other.pipe.read_watchers, POLL_READ as u32);
        n as isize
    }

    /// Another description on this pipe, open for reading, writing or both:
    /// `dup` and `fork` share a description and so do not come here, but
    /// opening `/proc/<pid>/fd/<n>` makes a new one, as Linux's `fifo_open`
    /// does. Counted, because the counts decide end-of-file and `EPIPE`.
    pub fn reopen(&self, reading: bool, writing: bool) -> End {
        let mut g = self.pipe.inner.lock();
        g.readers += u32::from(reading);
        g.writers += u32::from(writing);
        drop(g);
        End { pipe: self.pipe.clone(), reading, writing }
    }

    /// Wake `watchers` -- a description's poll list -- for this end's events
    /// until [`End::unwatch`].
    pub fn watch(&self, watchers: &Arc<Watchers>) {
        for (on, list) in self.lists() {
            if on {
                list.write().unwrap_or_else(PoisonError::into_inner).push(watchers.clone());
            }
        }
    }

    /// Stop waking `watchers`. Called before the description that owns the
    /// list is torn down, so a wake does not reach a list being freed.
    pub fn unwatch(&self, watchers: &Arc<Watchers>) {
        for (on, list) in self.lists() {
            if on {
                list.write().unwrap_or_else(PoisonError::into_inner).retain(|w| !Arc::ptr_eq(w, watchers));
            }
        }
    }

    fn lists(&self) -> [(bool, &RwLock<Vec<Arc<Watchers>>>); 2] {
        [(self.reading, &self.pipe.read_watchers), (self.writing, &self.pipe.write_watchers)]
    }

    /// This description has gone.
    pub(super) fn close(&self) {
        let mut g = self.pipe.inner.lock();
        if self.writing {
            g.writers = g.writers.saturating_sub(1);
            if g.writers == 0 {
                // Readers waiting for data will get end-of-file instead, and
                // pollers need to hear about the hangup.
                g.owner().notify(READABLE);
                self.pipe
                    .notify(&self.pipe.read_watchers, (POLL_READ | POLL_HUP) as u32);
            }
        }
        if self.reading {
            g.readers = g.readers.saturating_sub(1);
            if g.readers == 0 {
                g.owner().notify(WRITABLE);
                self.pipe
                    .notify(&self.pipe.write_watchers, (POLL_WRITE | POLL_ERR) as u32);
            }
        }
    }
}

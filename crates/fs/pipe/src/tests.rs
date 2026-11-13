//! Behavioral tests for pipe queue, end, and poll semantics.

use super::*;
// The six C lock symbols GuestLock calls. Linked for their side effect
// of existing; nothing here names one.
use kernel_sighand as _;
use kernel_sigqueue as _;

fn pair() -> (Box<End>, Box<End>) {
    new(false)
}

fn write(w: &End, n: usize) -> isize {
    w.write(&vec![0x5a; n], true)
}

fn read(r: &End, n: usize) -> isize {
    let mut buf = vec![0u8; n];
    r.read(&mut buf, true)
}

// ------------------------------------------------------ the basic queue

#[test]
fn bytes_come_back_in_order() {
    let (r, w) = pair();
    assert_eq!(w.write(b"hello", true), 5);
    let mut buf = [0u8; 8];
    assert_eq!(r.read(&mut buf, true), 5);
    assert_eq!(&buf[..5], b"hello");
}

#[test]
fn a_read_takes_only_what_it_asked_for() {
    let (r, w) = pair();
    w.write(b"0123456789", true);
    let mut buf = [0u8; 4];
    assert_eq!(r.read(&mut buf, true), 4);
    assert_eq!(&buf, b"0123");
    assert_eq!(r.read(&mut buf, true), 4);
    assert_eq!(&buf, b"4567");
    assert_eq!(r.read(&mut buf, true), 2);
}

#[test]
fn an_empty_pipe_with_a_writer_is_eagain() {
    let (r, _w) = pair();
    assert_eq!(read(&r, 8), EAGAIN);
}

// --------------------------------------------------------- the capacity

#[test]
fn the_default_capacity_is_the_one_linux_reports() {
    let (r, _w) = pair();
    assert_eq!(r.capacity(), 65536);
}

#[test]
fn a_full_pipe_refuses_a_non_blocking_write() {
    let (_r, w) = pair();
    assert_eq!(write(&w, DEFAULT_CAPACITY), DEFAULT_CAPACITY as isize);
    assert_eq!(write(&w, 1), EAGAIN);
}

#[test]
fn set_capacity_rounds_up_to_a_power_of_two() {
    // Every one of these is a line of pipe_probe's output from a real
    // arm64 kernel.
    let (_r, w) = pair();
    assert_eq!(w.set_capacity(4096, false), 4096);
    assert_eq!(w.set_capacity(1, false), 4096, "floored at one page");
    assert_eq!(w.set_capacity(0, false), 4096);
    assert_eq!(w.set_capacity(65536, false), 65536);
    assert_eq!(
        w.set_capacity(100_000, false),
        131_072,
        "rounded up, not down"
    );
}

#[test]
fn set_capacity_refuses_what_it_cannot_do() {
    let (_r, w) = pair();
    // Above 2^31 rounds to nothing: EINVAL for everyone, privileged or not.
    assert_eq!(w.set_capacity(u32::MAX, false), EINVAL);
    assert_eq!(w.set_capacity(u32::MAX, true), EINVAL);
    assert_eq!(w.set_capacity((1 << 31) + 1, true), EINVAL);
    // Above pipe_max_size is EPERM without CAP_SYS_RESOURCE -- fcntl_probe
    // measured 1 << 31 as EPERM, as an unprivileged user -- and the limit
    // is applied to the *rounded* size.
    assert_eq!(w.set_capacity(0x7fff_ffff, false), EPERM);
    assert_eq!(w.set_capacity(1 << 31, false), EPERM);
    assert_eq!(
        w.set_capacity((1 << 20) + 1, false),
        EPERM,
        "rounds to 2 MB first"
    );
    assert_eq!(w.set_capacity(1 << 20, false), 1 << 20);
}

#[test]
fn a_privileged_caller_may_go_above_pipe_max_size() {
    let (_r, w) = pair();
    assert_eq!(w.set_capacity(1 << 31, true), 1 << 31);
    assert_eq!(w.capacity(), 1 << 31);
    // A bound, not an allocation: nothing was reserved for it.
    assert_eq!(w.queued(), 0);
}

#[test]
fn shrinking_below_what_is_queued_is_ebusy() {
    let (_r, w) = pair();
    write(&w, 8192);
    assert_eq!(w.set_capacity(4096, false), EBUSY);
    // ...and the queued bytes are untouched.
    assert_eq!(w.capacity(), DEFAULT_CAPACITY);
}

#[test]
fn the_capacity_actually_bounds_the_pipe() {
    // The check on the answer above: a kernel may report a capacity it
    // does not have, which is what makes "how many bytes went in before
    // it was full" a separate question from F_GETPIPE_SZ.
    let (_r, w) = pair();
    w.set_capacity(4096, false);
    assert_eq!(write(&w, 4096), 4096);
    assert_eq!(write(&w, 1), EAGAIN);
}

// ------------------------------------------------------- PIPE_BUF

#[test]
fn a_write_up_to_pipe_buf_is_all_or_nothing() {
    // The defect this crate exists for. macOS's PIPE_BUF is 512, so a
    // 4096-byte write into a pipe with 100 bytes of room put 100 bytes in
    // and reported it -- splitting a record two writers were relying on
    // not being split.
    let (r, w) = pair();
    write(&w, DEFAULT_CAPACITY);
    read(&r, 100);
    assert_eq!(write(&w, PIPE_BUF), EAGAIN, "not a partial write");
    // With room for all of it, it goes in whole.
    read(&r, PIPE_BUF);
    assert_eq!(write(&w, PIPE_BUF), PIPE_BUF as isize);
}

#[test]
fn a_write_above_pipe_buf_may_be_partial() {
    let (r, w) = pair();
    write(&w, DEFAULT_CAPACITY);
    read(&r, 8192);
    let n = write(&w, PIPE_BUF * 4);
    assert_eq!(n, 8192, "as much as there was room for");
}

// ------------------------------------------------------ ends going away

#[test]
fn a_write_with_no_readers_is_epipe() {
    let (r, w) = pair();
    drop(r);
    assert_eq!(write(&w, 4), EPIPE);
}

#[test]
fn a_read_with_no_writers_is_end_of_file_for_ever() {
    let (r, w) = pair();
    w.write(b"abc", true);
    drop(w);
    // What is left comes out first.
    let mut buf = [0u8; 8];
    assert_eq!(r.read(&mut buf, true), 3);
    assert_eq!(r.read(&mut buf, true), 0);
    assert_eq!(r.read(&mut buf, true), 0, "and stays 0, rather than EAGAIN");
}

#[test]
fn a_duplicate_end_is_counted() {
    let (r, w) = pair();
    let w2 = w.clone();
    drop(w);
    // One writer left, so this is not end of file yet.
    assert_eq!(read(&r, 8), EAGAIN);
    drop(w2);
    assert_eq!(read(&r, 8), 0);
}

// ------------------------------------------------------------ poll

#[test]
fn poll_says_what_each_end_can_do() {
    let (r, w) = pair();
    // Measured: an empty pipe is 0 on the read end and POLLOUT on the
    // write end. This kernel used to report POLLOUT on the read end.
    assert_eq!(r.poll(), 0);
    assert_eq!(w.poll(), POLL_WRITE);
    write(&w, 4);
    assert_eq!(r.poll(), POLL_READ);
    assert_eq!(w.poll(), POLL_WRITE);
}

#[test]
fn a_full_pipe_is_not_writable() {
    let (r, w) = pair();
    write(&w, DEFAULT_CAPACITY);
    assert_eq!(w.poll(), 0);
    // Measured 8 (POLLERR) for a *full* pipe whose reader has gone; this
    // kernel said 12 by adding POLLOUT to a descriptor with no room.
    drop(r);
    assert_eq!(w.poll(), POLL_ERR);
}

#[test]
fn a_broken_write_end_with_room_is_writable_and_in_error() {
    // The one the first version got wrong, and the reason the two
    // conditions are separate `if`s. epoll_semantics asserts exactly this
    // against a real kernel: OUT and ERR together, without HUP.
    let (r, w) = pair();
    drop(r);
    assert_eq!(w.poll(), POLL_WRITE | POLL_ERR);
}

#[test]
fn a_drained_pipe_whose_writer_left_is_hung_up_and_nothing_else() {
    // HUP alone. POLLIN would be inventing data that is not there --
    // `pipe_poll` sets it only for a pipe that is not empty, and the first
    // version added it unconditionally at end of file.
    let (r, w) = pair();
    drop(w);
    assert_eq!(r.poll(), POLL_HUP);
    // ...but with bytes still in it, both. This is the state pipe_probe
    // measured as 17, and taking it as the rule for *every* hung-up read
    // end is what the mistake was.
    let (r, w) = pair();
    write(&w, 4);
    drop(w);
    assert_eq!(r.poll(), POLL_READ | POLL_HUP);
}

// ---------------------------------------------------------- packet mode

#[test]
fn packet_mode_gives_one_record_per_read() {
    // Measured: three writes of 10, 20 and 30 bytes read back as 10, then
    // 5 with the rest of that record discarded, then 30.
    let (r, w) = new(true);
    write(&w, 10);
    write(&w, 20);
    write(&w, 30);
    assert_eq!(read(&r, 100), 10);
    assert_eq!(read(&r, 5), 5, "a short read takes what it can");
    assert_eq!(read(&r, 100), 30, "and the rest of that record is gone");
    assert_eq!(read(&r, 100), EAGAIN);
}

#[test]
fn a_byte_mode_pipe_merges_writes() {
    let (r, w) = pair();
    write(&w, 10);
    write(&w, 20);
    assert_eq!(read(&r, 100), 30, "one read, both writes");
}

#[test]
fn a_record_larger_than_the_pipe_cannot_ever_fit() {
    let (_r, w) = new(true);
    w.set_capacity(4096, false);
    assert_eq!(write(&w, 8192), EAGAIN);
}

#[test]
fn packet_mode_is_the_write_ends_and_can_change() {
    // F_SETFL(O_DIRECT) on the write end turns it on for the writes after
    // it and leaves what is queued as it was: the two plain writes are one
    // run, and a read takes that run and the record after it, stopping at
    // the record's end as pipe_read does at a packet buffer.
    let (r, w) = pair();
    write(&w, 10);
    write(&w, 20);
    w.set_packet_mode(true);
    write(&w, 30);
    write(&w, 40);
    assert_eq!(
        read(&r, 100),
        60,
        "30 plain bytes and the 30-byte record, not the 40"
    );
    assert_eq!(read(&r, 7), 7, "a short read of a record discards its rest");
    w.set_packet_mode(false);
    write(&w, 5);
    write(&w, 6);
    assert_eq!(read(&r, 100), 11, "plain again, and merged again");
    assert_eq!(read(&r, 100), EAGAIN);
    // The read end has no say.
    r.set_packet_mode(true);
    write(&w, 10);
    write(&w, 10);
    assert_eq!(read(&r, 100), 20);
}

#[test]
fn a_read_runs_through_plain_bytes_into_the_packet_after_them() {
    // pipe_read copies buffer after buffer until it has what it asked for
    // or reaches the end of a packet buffer, whichever is first.
    let (r, w) = pair();
    write(&w, 10);
    w.set_packet_mode(true);
    write(&w, 20);
    write(&w, 30);
    assert_eq!(read(&r, 100), 30, "10 plain and the whole 20-byte record");
    assert_eq!(read(&r, 100), 30);
    assert!(w.is_write_end() && !r.is_write_end());
}

// ------------------------------------------------------------------ tee

#[test]
fn tee_copies_without_consuming() {
    let (r1, w1) = pair();
    let (r2, w2) = pair();
    w1.write(b"hello", true);
    assert_eq!(r1.tee(&w2, 5, true), 5);
    // Both ends have it.
    let mut a = [0u8; 8];
    let mut b = [0u8; 8];
    assert_eq!(r2.read(&mut b, true), 5);
    assert_eq!(&b[..5], b"hello");
    assert_eq!(r1.read(&mut a, true), 5, "the source still has it");
    assert_eq!(&a[..5], b"hello");
}

#[test]
fn tee_refuses_the_things_a_real_kernel_refuses() {
    let (r1, w1) = pair();
    let (r2, w2) = pair();
    // Both ends of one pipe.
    assert_eq!(r1.tee(&w1, 4, true), EINVAL);
    // The wrong direction on either side.
    assert_eq!(w1.tee(&w2, 4, true), EINVAL);
    assert_eq!(r1.tee(&r2, 4, true), EINVAL);
}

#[test]
fn tee_of_an_empty_pipe_says_so() {
    let (r1, w1) = pair();
    let (_r2, w2) = pair();
    assert_eq!(r1.tee(&w2, 4, true), EAGAIN);
    drop(w1);
    assert_eq!(r1.tee(&w2, 4, true), 0, "end of file, not an error");
}

#[test]
fn tee_is_bounded_by_both_pipes() {
    let (r1, w1) = pair();
    let (_r2, w2) = pair();
    w2.set_capacity(4096, false);
    write(&w1, 8192);
    assert_eq!(r1.tee(&w2, 8192, true), 4096, "what the destination holds");
}

#[test]
fn tee_keeps_a_record_a_record() {
    // link_pipe copies each buffer with its flags, so the destination sees
    // the source's records whatever its own writer's mode is.
    let (r1, w1) = new(true);
    let (r2, w2) = pair();
    write(&w1, 10);
    write(&w1, 20);
    assert_eq!(r1.tee(&w2, 100, true), 30);
    assert_eq!(read(&r2, 100), 10, "one record per read, in a plain pipe");
    assert_eq!(read(&r2, 100), 20);
    // And a record cut by the length asked for is a shorter record.
    let (r3, w3) = pair();
    assert_eq!(r1.tee(&w3, 15, true), 15);
    assert_eq!(read(&r3, 100), 10);
    assert_eq!(read(&r3, 100), 5);
}

#[test]
fn tee_into_a_pipe_with_no_readers_is_epipe() {
    let (r1, w1) = pair();
    let (r2, w2) = pair();
    w1.write(b"x", true);
    drop(r2);
    assert_eq!(r1.tee(&w2, 4, true), EPIPE);
}

// ------------------------------------------------- the zero-length cases

#[test]
fn zero_length_transfers_do_nothing() {
    let (r, w) = pair();
    assert_eq!(w.write(b"", true), 0);
    assert_eq!(r.queued(), 0, "not even a zero-length packet");
    let mut empty: [u8; 0] = [];
    assert_eq!(r.read(&mut empty, true), 0);
    w.write(b"x", true);
    assert_eq!(
        r.read(&mut empty, true),
        0,
        "and takes nothing from a full one"
    );
    assert_eq!(r.queued(), 1);
}

#[test]
fn fionread_counts_what_is_there() {
    let (r, w) = pair();
    assert_eq!(r.queued(), 0);
    write(&w, 100);
    assert_eq!(r.queued(), 100);
    read(&r, 40);
    assert_eq!(r.queued(), 60);
}

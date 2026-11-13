//! The guest's wire formats and the arithmetic Linux applies to them:
//! `struct iocb`, `struct io_event`, the `struct aio_ring` header, how big a
//! ring `io_setup` makes, and what a timeout means.
//!
//! Everything here is a pure function or a layout with its offsets asserted,
//! so the rules have unit tests that need no guest.

use guest_errno::Errno;

/// `struct iocb`, as `include/uapi/linux/aio_abi.h` lays it out on a
/// little-endian 64-bit target: `aio_key` before `aio_rw_flags`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Iocb {
    pub data: u64,
    pub key: u32,
    pub rw_flags: i32,
    pub opcode: u16,
    pub reqprio: i16,
    pub fildes: u32,
    pub buf: u64,
    pub nbytes: u64,
    pub offset: i64,
    pub reserved2: u64,
    pub flags: u32,
    pub resfd: u32,
}

pub(crate) const IOCB_SIZE: usize = 64;
/// Where `aio_key` is: `io_submit` writes `KIOCB_KEY` (0) there and
/// `io_cancel` reads it back before anything else.
pub(crate) const KEY_OFFSET: u64 = 8;

const _: () = {
    assert!(std::mem::size_of::<Iocb>() == IOCB_SIZE);
    assert!(std::mem::offset_of!(Iocb, key) == KEY_OFFSET as usize);
    assert!(std::mem::offset_of!(Iocb, rw_flags) == 12);
    assert!(std::mem::offset_of!(Iocb, opcode) == 16);
    assert!(std::mem::offset_of!(Iocb, reqprio) == 18);
    assert!(std::mem::offset_of!(Iocb, fildes) == 20);
    assert!(std::mem::offset_of!(Iocb, buf) == 24);
    assert!(std::mem::offset_of!(Iocb, nbytes) == 32);
    assert!(std::mem::offset_of!(Iocb, offset) == 40);
    assert!(std::mem::offset_of!(Iocb, reserved2) == 48);
    assert!(std::mem::offset_of!(Iocb, flags) == 56);
    assert!(std::mem::offset_of!(Iocb, resfd) == 60);
};

fn u64_at(raw: &[u8; IOCB_SIZE], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().expect("eight bytes"))
}

fn u32_at(raw: &[u8; IOCB_SIZE], at: usize) -> u32 {
    u32::from_le_bytes(raw[at..at + 4].try_into().expect("four bytes"))
}

fn u16_at(raw: &[u8; IOCB_SIZE], at: usize) -> u16 {
    u16::from_le_bytes(raw[at..at + 2].try_into().expect("two bytes"))
}

impl Iocb {
    /// From the 64 bytes the guest handed over. A fixed-size array, so the
    /// length check is the type.
    pub fn decode(raw: &[u8; IOCB_SIZE]) -> Iocb {
        Iocb {
            data: u64_at(raw, 0),
            key: u32_at(raw, 8),
            rw_flags: u32_at(raw, 12) as i32,
            opcode: u16_at(raw, 16),
            reqprio: u16_at(raw, 18) as i16,
            fildes: u32_at(raw, 20),
            buf: u64_at(raw, 24),
            nbytes: u64_at(raw, 32),
            offset: u64_at(raw, 40) as i64,
            reserved2: u64_at(raw, 48),
            flags: u32_at(raw, 56),
            resfd: u32_at(raw, 60),
        }
    }
}

/// `IOCB_CMD_*`. 4 was `IOCB_CMD_PREADX` and was never implemented; 6,
/// `IOCB_CMD_NOOP`, is in the header and has no case in `__io_submit_one`, so
/// it is `EINVAL` on Linux and here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Opcode {
    Pread,
    Pwrite,
    Fsync,
    Fdsync,
    Poll,
    Preadv,
    Pwritev,
}

impl Opcode {
    pub fn of(raw: u16) -> Option<Opcode> {
        Some(match raw {
            0 => Opcode::Pread,
            1 => Opcode::Pwrite,
            2 => Opcode::Fsync,
            3 => Opcode::Fdsync,
            5 => Opcode::Poll,
            7 => Opcode::Preadv,
            8 => Opcode::Pwritev,
            _ => return None,
        })
    }
}

/// `IOCB_FLAG_RESFD`: signal the eventfd in `aio_resfd` on completion.
pub(crate) const FLAG_RESFD: u32 = 1;
/// `IOCB_FLAG_IOPRIO`: `aio_reqprio` is an I/O priority to check. Without it
/// the field is ignored, whatever it holds.
pub(crate) const FLAG_IOPRIO: u32 = 2;

/// `struct io_event`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct IoEvent {
    pub data: u64,
    pub obj: u64,
    pub res: i64,
    pub res2: i64,
}

pub(crate) const EVENT_SIZE: usize = 32;

const _: () = {
    assert!(std::mem::size_of::<IoEvent>() == EVENT_SIZE);
    assert!(std::mem::offset_of!(IoEvent, obj) == 8);
    assert!(std::mem::offset_of!(IoEvent, res) == 16);
    assert!(std::mem::offset_of!(IoEvent, res2) == 24);
};

impl IoEvent {
    pub fn words(&self) -> [u64; 4] {
        [self.data, self.obj, self.res as u64, self.res2 as u64]
    }

    pub fn from_words(w: [u64; 4]) -> IoEvent {
        IoEvent { data: w[0], obj: w[1], res: w[2] as i64, res2: w[3] as i64 }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        for w in self.words() {
            out.extend_from_slice(&w.to_le_bytes());
        }
    }
}

/// The `struct aio_ring` header, as word indices. 32 bytes, then the events.
pub(crate) mod header {
    pub const ID: usize = 0;
    pub const NR: usize = 1;
    pub const HEAD: usize = 2;
    pub const TAIL: usize = 3;
    pub const MAGIC: usize = 4;
    pub const COMPAT_FEATURES: usize = 5;
    pub const INCOMPAT_FEATURES: usize = 6;
    pub const HEADER_LENGTH: usize = 7;
    pub const BYTES: usize = 32;
}

/// `AIO_RING_MAGIC`. libaio and fio reap from the ring themselves when they
/// find it, which is why the ring has to be the real one.
pub(crate) const RING_MAGIC: u32 = 0xa10a10a1;
pub(crate) const RING_COMPAT_FEATURES: u32 = 1;
pub(crate) const RING_INCOMPAT_FEATURES: u32 = 0;

/// `/proc/sys/fs/aio-max-nr`'s default. A container may show a raised one;
/// this kernel has no sysctl to raise it with.
pub(crate) const AIO_MAX_NR: u64 = 65536;

pub(crate) const PAGE: u64 = 4096;

/// What `ioctx_alloc` and `aio_setup_ring` make of `io_setup(nr_events)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Geometry {
    /// What the context charges against `aio-max-nr`: the caller's number.
    pub max_reqs: u32,
    /// How many events the ring holds, which is what `ring.nr` says: more
    /// than asked, because the kernel doubles it and fills the last page.
    pub nr: u32,
    pub pages: u64,
}

/// `ioctx_alloc`'s arithmetic, **in `unsigned` as Linux does it**: the
/// request is raised to four per possible CPU and doubled, and the doubling
/// wraps. So `0x80000000` doubles to 0 and is `EAGAIN`, while `0xffffffff`
/// doubles to `0xfffffffe` and trips the overflow guard as `EINVAL`. Measured
/// by `aio_probe`.
pub(crate) fn geometry(nr_events: u32, cpus: u32) -> Result<Geometry, Errno> {
    let doubled = nr_events.max(cpus.wrapping_mul(4)).wrapping_mul(2);
    if doubled > 0x1000_0000 / EVENT_SIZE as u32 {
        return Err(Errno::EINVAL);
    }
    if doubled == 0 || u64::from(nr_events) > AIO_MAX_NR {
        return Err(Errno::EAGAIN);
    }
    let bytes = header::BYTES as u64 + EVENT_SIZE as u64 * u64::from(doubled);
    let pages = bytes.div_ceil(PAGE);
    let nr = ((pages * PAGE - header::BYTES as u64) / EVENT_SIZE as u64) as u32;
    Ok(Geometry { max_reqs: nr_events, nr, pages })
}

/// What a `struct __kernel_timespec` timeout means to `io_getevents`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Timeout {
    /// `{0, 0}`: read what is there and do not wait.
    Poll,
    /// A relative wait of this many nanoseconds.
    After(u64),
    /// No timeout, or one Linux turns into none.
    Never,
}

/// `KTIME_SEC_MAX`.
const KTIME_SEC_MAX: u64 = i64::MAX as u64 / 1_000_000_000;

/// `get_timespec64` validates nothing, and `timespec64_to_ktime` and the
/// hrtimer's `ktime_add_safe` decide the rest: a negative `tv_sec` is at or
/// above `KTIME_SEC_MAX` as unsigned and means **for ever**, and so does any
/// value whose nanosecond total is negative -- `{0, -1}` included, because
/// adding it to the current time saturates. Both were measured as waits that
/// only a signal ended. `{0, 1e9}` is one second, not `EINVAL`.
pub(crate) fn timeout(sec: i64, nsec: i64) -> Timeout {
    if sec as u64 >= KTIME_SEC_MAX {
        return Timeout::Never;
    }
    let total = sec.wrapping_mul(1_000_000_000).wrapping_add(nsec);
    match total {
        0 => Timeout::Poll,
        t if t < 0 => Timeout::Never,
        t => Timeout::After(t as u64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_iocb_decodes_field_by_field() {
        let mut raw = [0u8; IOCB_SIZE];
        raw[0..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        raw[8..12].copy_from_slice(&0xdeadu32.to_le_bytes());
        raw[12..16].copy_from_slice(&(-1i32).to_le_bytes());
        raw[16..18].copy_from_slice(&7u16.to_le_bytes());
        raw[18..20].copy_from_slice(&(-2i16).to_le_bytes());
        raw[20..24].copy_from_slice(&9u32.to_le_bytes());
        raw[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        raw[32..40].copy_from_slice(&3u64.to_le_bytes());
        raw[40..48].copy_from_slice(&(-5i64).to_le_bytes());
        raw[48..56].copy_from_slice(&1u64.to_le_bytes());
        raw[56..60].copy_from_slice(&1u32.to_le_bytes());
        raw[60..64].copy_from_slice(&4u32.to_le_bytes());
        let cb = Iocb::decode(&raw);
        assert_eq!(
            cb,
            Iocb {
                data: 0x1122_3344_5566_7788,
                key: 0xdead,
                rw_flags: -1,
                opcode: 7,
                reqprio: -2,
                fildes: 9,
                buf: 0x1000,
                nbytes: 3,
                offset: -5,
                reserved2: 1,
                flags: 1,
                resfd: 4,
            }
        );
    }

    #[test]
    fn the_opcodes_are_linuxs_and_noop_is_not_one() {
        assert_eq!(Opcode::of(0), Some(Opcode::Pread));
        assert_eq!(Opcode::of(5), Some(Opcode::Poll));
        assert_eq!(Opcode::of(8), Some(Opcode::Pwritev));
        for missing in [4, 6, 9, 0xffff] {
            assert_eq!(Opcode::of(missing), None, "{missing}");
        }
    }

    #[test]
    fn an_event_round_trips() {
        let ev = IoEvent { data: 1, obj: 2, res: -14, res2: 0 };
        assert_eq!(IoEvent::from_words(ev.words()), ev);
        let mut out = Vec::new();
        ev.encode(&mut out);
        assert_eq!(out.len(), EVENT_SIZE);
        assert_eq!(&out[16..24], &(-14i64).to_le_bytes());
    }

    /// The numbers `aio_probe` measured on a five-CPU kernel.
    #[test]
    fn the_ring_is_sized_as_linux_sizes_it() {
        // max(1, 20) * 2 = 40 events, one page, 127 slots.
        assert_eq!(geometry(1, 5), Ok(Geometry { max_reqs: 1, nr: 127, pages: 1 }));
        // 2000 events is 64032 bytes, sixteen pages, 2047 slots.
        assert_eq!(geometry(1000, 5), Ok(Geometry { max_reqs: 1000, nr: 2047, pages: 16 }));
        assert_eq!(geometry(1000, 18).map(|g| g.nr), Ok(2047));
    }

    #[test]
    fn the_doubling_wraps_as_unsigned_arithmetic_does() {
        assert_eq!(geometry(4_194_305, 5), Err(Errno::EINVAL));
        assert_eq!(geometry(0x8000_0000, 5), Err(Errno::EAGAIN));
        assert_eq!(geometry(0xffff_ffff, 5), Err(Errno::EINVAL));
        assert_eq!(geometry(65537, 5), Err(Errno::EAGAIN));
        assert!(geometry(65536, 5).is_ok());
    }

    #[test]
    fn a_timeout_is_ktime_arithmetic() {
        assert_eq!(timeout(0, 0), Timeout::Poll);
        assert_eq!(timeout(0, 30_000_000), Timeout::After(30_000_000));
        assert_eq!(timeout(0, 1_000_000_000), Timeout::After(1_000_000_000));
        assert_eq!(timeout(-1, 0), Timeout::Never);
        assert_eq!(timeout(0, -1), Timeout::Never);
        assert_eq!(timeout(i64::MAX, 0), Timeout::Never);
        assert_eq!(timeout(1, -1_000_000_000), Timeout::Poll);
    }
}

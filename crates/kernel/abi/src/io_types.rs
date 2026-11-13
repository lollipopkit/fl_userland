//! Guest I/O wire layouts used by syscall and descriptor operations.

use crate::{addr_t, dword_t, off_t_, pid_t_, uint_t, word_t};

/// The **internal** form: a 32-bit length, which is what the older calls take.
/// `read_iovec` pulls an array of [`iovec64_`] out of guest memory and converts
/// into these; `iovec64_` is the wire format `readv` and `writev` read.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct iovec_ {
    pub base: addr_t,
    pub len: uint_t,
}
const _: () = {
    assert!(std::mem::size_of::<iovec_>() == 16, "Size of iovec_");
    assert!(std::mem::align_of::<iovec_>() == 8, "Alignment of iovec_");
    assert!(
        std::mem::offset_of!(iovec_, base) == 0,
        "Offset of field: iovec_::base"
    );
    assert!(
        std::mem::offset_of!(iovec_, len) == 8,
        "Offset of field: iovec_::len"
    );
};

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct iovec64_ {
    pub base: u64,
    pub len: u64,
}
const _: () = {
    assert!(std::mem::size_of::<iovec64_>() == 16, "Size of iovec64_");
    assert!(
        std::mem::align_of::<iovec64_>() == 8,
        "Alignment of iovec64_"
    );
    assert!(
        std::mem::offset_of!(iovec64_, base) == 0,
        "Offset of field: iovec64_::base"
    );
    assert!(
        std::mem::offset_of!(iovec64_, len) == 8,
        "Offset of field: iovec64_::len"
    );
};

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct flock_ {
    pub type_: word_t,
    pub whence: word_t,
    pub _pad0: dword_t,
    pub start: off_t_,
    pub len: off_t_,
    pub pid: pid_t_,
    pub _pad1: dword_t,
}
const _: () = {
    assert!(std::mem::size_of::<flock_>() == 32, "Size of flock_");
    assert!(std::mem::align_of::<flock_>() == 8, "Alignment of flock_");
    assert!(
        std::mem::offset_of!(flock_, type_) == 0,
        "Offset of field: flock_::type_"
    );
    assert!(
        std::mem::offset_of!(flock_, whence) == 2,
        "Offset of field: flock_::whence"
    );
    assert!(
        std::mem::offset_of!(flock_, _pad0) == 4,
        "Offset of field: flock_::_pad0"
    );
    assert!(
        std::mem::offset_of!(flock_, start) == 8,
        "Offset of field: flock_::start"
    );
    assert!(
        std::mem::offset_of!(flock_, len) == 16,
        "Offset of field: flock_::len"
    );
    assert!(
        std::mem::offset_of!(flock_, pid) == 24,
        "Offset of field: flock_::pid"
    );
    assert!(
        std::mem::offset_of!(flock_, _pad1) == 28,
        "Offset of field: flock_::_pad1"
    );
};

plain::plain! {
    flock_ { type_, whence, _pad0, start, len, pid, _pad1 }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct epoll_ready_event {
    pub events: u32,
    pub pad: u32,
    pub data: u64,
}
const _: () = {
    assert!(
        std::mem::size_of::<epoll_ready_event>() == 16,
        "Size of epoll_ready_event"
    );
    assert!(
        std::mem::align_of::<epoll_ready_event>() == 8,
        "Alignment of epoll_ready_event"
    );
    assert!(
        std::mem::offset_of!(epoll_ready_event, events) == 0,
        "Offset of field: epoll_ready_event::events"
    );
    assert!(
        std::mem::offset_of!(epoll_ready_event, pad) == 4,
        "Offset of field: epoll_ready_event::pad"
    );
    assert!(
        std::mem::offset_of!(epoll_ready_event, data) == 8,
        "Offset of field: epoll_ready_event::data"
    );
};

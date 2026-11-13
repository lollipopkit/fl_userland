//! Guest socket address and peer credential ABI layouts.

use crate::{pid_t_, uid_t_};

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct sockaddr_ {
    pub family: u16,
    pub data: [std::ffi::c_char; 14usize],
}
const _: () = {
    assert!(std::mem::size_of::<sockaddr_>() == 16, "Size of sockaddr_");
    assert!(
        std::mem::align_of::<sockaddr_>() == 2,
        "Alignment of sockaddr_"
    );
    assert!(
        std::mem::offset_of!(sockaddr_, family) == 0,
        "Offset of field: sockaddr_::family"
    );
    assert!(
        std::mem::offset_of!(sockaddr_, data) == 2,
        "Offset of field: sockaddr_::data"
    );
};
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_max_ {
    pub family: u16,
    pub data: [std::ffi::c_char; 108usize],
}
const _: () = {
    assert!(
        std::mem::size_of::<sockaddr_max_>() == 110,
        "Size of sockaddr_max_"
    );
    assert!(
        std::mem::align_of::<sockaddr_max_>() == 2,
        "Alignment of sockaddr_max_"
    );
    assert!(
        std::mem::offset_of!(sockaddr_max_, family) == 0,
        "Offset of field: sockaddr_max_::family"
    );
    assert!(
        std::mem::offset_of!(sockaddr_max_, data) == 2,
        "Offset of field: sockaddr_max_::data"
    );
};
impl Default for sockaddr_max_ {
    fn default() -> Self {
        Self {
            family: 0,
            data: [0; 108],
        }
    }
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ucred_ {
    pub pid: pid_t_,
    pub uid: uid_t_,
    pub gid: uid_t_,
}
const _: () = {
    assert!(std::mem::size_of::<ucred_>() == 12, "Size of ucred_");
    assert!(std::mem::align_of::<ucred_>() == 4, "Alignment of ucred_");
    assert!(
        std::mem::offset_of!(ucred_, pid) == 0,
        "Offset of field: ucred_::pid"
    );
    assert!(
        std::mem::offset_of!(ucred_, uid) == 4,
        "Offset of field: ucred_::uid"
    );
    assert!(
        std::mem::offset_of!(ucred_, gid) == 8,
        "Offset of field: ucred_::gid"
    );
};

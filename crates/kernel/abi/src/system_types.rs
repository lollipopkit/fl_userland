//! Guest system information layouts shared with host-facing APIs.

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct uname {
    pub system: [std::ffi::c_char; 65usize],
    pub hostname: [std::ffi::c_char; 65usize],
    pub release: [std::ffi::c_char; 65usize],
    pub version: [std::ffi::c_char; 65usize],
    pub arch: [std::ffi::c_char; 65usize],
    pub domain: [std::ffi::c_char; 65usize],
}
const _: () = {
    assert!(std::mem::size_of::<uname>() == 390, "Size of uname");
    assert!(std::mem::align_of::<uname>() == 1, "Alignment of uname");
    assert!(
        std::mem::offset_of!(uname, system) == 0,
        "Offset of field: uname::system"
    );
    assert!(
        std::mem::offset_of!(uname, hostname) == 65,
        "Offset of field: uname::hostname"
    );
    assert!(
        std::mem::offset_of!(uname, release) == 130,
        "Offset of field: uname::release"
    );
    assert!(
        std::mem::offset_of!(uname, version) == 195,
        "Offset of field: uname::version"
    );
    assert!(
        std::mem::offset_of!(uname, arch) == 260,
        "Offset of field: uname::arch"
    );
    assert!(
        std::mem::offset_of!(uname, domain) == 325,
        "Offset of field: uname::domain"
    );
};
impl Default for uname {
    fn default() -> Self {
        Self {
            system: [0; 65],
            hostname: [0; 65],
            release: [0; 65],
            version: [0; 65],
            arch: [0; 65],
            domain: [0; 65],
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct sys_info {
    pub uptime: u64,
    pub loads: [u64; 3usize],
    pub totalram: u64,
    pub freeram: u64,
    pub sharedram: u64,
    pub bufferram: u64,
    pub totalswap: u64,
    pub freeswap: u64,
    pub procs: u16,
    pub _pad1: u16,
    pub _pad2: u32,
    pub totalhigh: u64,
    pub freehigh: u64,
    pub mem_unit: u32,
    pub _pad3: u32,
}
const _: () = {
    assert!(std::mem::size_of::<sys_info>() == 112, "Size of sys_info");
    assert!(
        std::mem::align_of::<sys_info>() == 8,
        "Alignment of sys_info"
    );
    assert!(
        std::mem::offset_of!(sys_info, uptime) == 0,
        "Offset of field: sys_info::uptime"
    );
    assert!(
        std::mem::offset_of!(sys_info, loads) == 8,
        "Offset of field: sys_info::loads"
    );
    assert!(
        std::mem::offset_of!(sys_info, totalram) == 32,
        "Offset of field: sys_info::totalram"
    );
    assert!(
        std::mem::offset_of!(sys_info, freeram) == 40,
        "Offset of field: sys_info::freeram"
    );
    assert!(
        std::mem::offset_of!(sys_info, sharedram) == 48,
        "Offset of field: sys_info::sharedram"
    );
    assert!(
        std::mem::offset_of!(sys_info, bufferram) == 56,
        "Offset of field: sys_info::bufferram"
    );
    assert!(
        std::mem::offset_of!(sys_info, totalswap) == 64,
        "Offset of field: sys_info::totalswap"
    );
    assert!(
        std::mem::offset_of!(sys_info, freeswap) == 72,
        "Offset of field: sys_info::freeswap"
    );
    assert!(
        std::mem::offset_of!(sys_info, procs) == 80,
        "Offset of field: sys_info::procs"
    );
    assert!(
        std::mem::offset_of!(sys_info, _pad1) == 82,
        "Offset of field: sys_info::_pad1"
    );
    assert!(
        std::mem::offset_of!(sys_info, _pad2) == 84,
        "Offset of field: sys_info::_pad2"
    );
    assert!(
        std::mem::offset_of!(sys_info, totalhigh) == 88,
        "Offset of field: sys_info::totalhigh"
    );
    assert!(
        std::mem::offset_of!(sys_info, freehigh) == 96,
        "Offset of field: sys_info::freehigh"
    );
    assert!(
        std::mem::offset_of!(sys_info, mem_unit) == 104,
        "Offset of field: sys_info::mem_unit"
    );
    assert!(
        std::mem::offset_of!(sys_info, _pad3) == 108,
        "Offset of field: sys_info::_pad3"
    );
};

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct cpu_usage {
    pub user_ticks: u64,
    pub system_ticks: u64,
    pub idle_ticks: u64,
    pub nice_ticks: u64,
}
const _: () = {
    assert!(std::mem::size_of::<cpu_usage>() == 32, "Size of cpu_usage");
    assert!(
        std::mem::align_of::<cpu_usage>() == 8,
        "Alignment of cpu_usage"
    );
    assert!(
        std::mem::offset_of!(cpu_usage, user_ticks) == 0,
        "Offset of field: cpu_usage::user_ticks"
    );
    assert!(
        std::mem::offset_of!(cpu_usage, system_ticks) == 8,
        "Offset of field: cpu_usage::system_ticks"
    );
    assert!(
        std::mem::offset_of!(cpu_usage, idle_ticks) == 16,
        "Offset of field: cpu_usage::idle_ticks"
    );
    assert!(
        std::mem::offset_of!(cpu_usage, nice_ticks) == 24,
        "Offset of field: cpu_usage::nice_ticks"
    );
};

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct mem_usage {
    pub total: u64,
    pub free: u64,
    pub active: u64,
    pub inactive: u64,
}
const _: () = {
    assert!(std::mem::size_of::<mem_usage>() == 32, "Size of mem_usage");
    assert!(
        std::mem::align_of::<mem_usage>() == 8,
        "Alignment of mem_usage"
    );
    assert!(
        std::mem::offset_of!(mem_usage, total) == 0,
        "Offset of field: mem_usage::total"
    );
    assert!(
        std::mem::offset_of!(mem_usage, free) == 8,
        "Offset of field: mem_usage::free"
    );
    assert!(
        std::mem::offset_of!(mem_usage, active) == 16,
        "Offset of field: mem_usage::active"
    );
    assert!(
        std::mem::offset_of!(mem_usage, inactive) == 24,
        "Offset of field: mem_usage::inactive"
    );
};

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct uptime_info {
    pub uptime_ticks: u64,
    pub load_1m: u64,
    pub load_5m: u64,
    pub load_15m: u64,
}
const _: () = {
    assert!(
        std::mem::size_of::<uptime_info>() == 32,
        "Size of uptime_info"
    );
    assert!(
        std::mem::align_of::<uptime_info>() == 8,
        "Alignment of uptime_info"
    );
    assert!(
        std::mem::offset_of!(uptime_info, uptime_ticks) == 0,
        "Offset of field: uptime_info::uptime_ticks"
    );
    assert!(
        std::mem::offset_of!(uptime_info, load_1m) == 8,
        "Offset of field: uptime_info::load_1m"
    );
    assert!(
        std::mem::offset_of!(uptime_info, load_5m) == 16,
        "Offset of field: uptime_info::load_5m"
    );
    assert!(
        std::mem::offset_of!(uptime_info, load_15m) == 24,
        "Offset of field: uptime_info::load_15m"
    );
};

plain::plain! {
    uname { system, hostname, release, version, arch, domain }
    sys_info {
        uptime, loads, totalram, freeram, sharedram, bufferram, totalswap, freeswap, procs,
        _pad1, _pad2, totalhigh, freehigh, mem_unit, _pad3,
    }
}

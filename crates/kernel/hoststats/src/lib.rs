//! What the host can say about the whole machine: processor time, memory and
//! uptime.
//!
//! This is what `/proc/stat`, `/proc/meminfo`, `/proc/uptime` and
//! `/proc/loadavg` are filled from, and what a task records at creation for
//! `/proc/<pid>/stat`'s `starttime`. From `platform/darwin.c`, which is gone,
//! over Mach calls and sysctls.
//!
//! There was a second reader over the host's own `/proc` and `sysinfo(2)`,
//! from `platform/linux.c`, until 2026-09-29. The host is Apple -- iOS for the
//! product, macOS to develop on -- and nothing compiled that module, so it went
//! with the other non-Apple branches.
//!
//! # Not to be confused with the per-thread numbers
//!
//! `crates/kernel/hostrusage` answers what one *thread* has used, which is a
//! different question with a different answer: a guest process is a set of
//! host threads in one host process, so the host's per-process totals count
//! every guest process at once and are useless. These are the *machine's*
//! totals, which is exactly what a guest reading `/proc/stat` is asking for.
//!
//! # The port name, and why it is cached
//!
//! `mach_host_self()` adds a user reference to the host port name **on every
//! call**. Calling it per read saturates the name's reference count under a
//! guest that polls `/proc/meminfo` — node and V8 do — after which `host_info`
//! and `host_statistics64` start failing outright and `/proc/meminfo` goes
//! blank.
//!
//! The C cached it in a function-local `static` with no synchronisation, which
//! is the thing the cache exists to prevent, one race away: two threads both
//! see `HOST_NULL`, both call `mach_host_self()`, and one reference is leaked
//! for ever. A `OnceLock` makes the call happen once by construction.
//!
//! # A failed read is the last good one
//!
//! `host_info` can fail transiently — it did on an OS beta — and the C's answer
//! was to serve the previous reading rather than let `/proc/meminfo` return
//! nonsense or take the process down. That is kept, behind a `Mutex` rather
//! than a pair of `static`s a torn read could reach in the middle.


mod ffi {
    pub use libc::{
        CPU_STATE_IDLE, CPU_STATE_NICE, CPU_STATE_SYSTEM, CPU_STATE_USER, HOST_CPU_LOAD_INFO,
        HOST_VM_INFO64, KERN_SUCCESS, host_cpu_load_info as host_cpu_load_info_data_t,
        host_statistics, host_statistics64, host_t, integer_t, kern_return_t,
        mach_msg_type_number_t, vm_statistics64 as vm_statistics64_data_t,
    };

    // `libc` exposes the Mach constants that are common to its bindings but
    // not this host-info flavor.
    pub const HOST_BASIC_INFO: libc::host_flavor_t = 1;

    #[repr(C, packed(4))]
    #[derive(Clone, Copy, Default)]
    pub struct host_basic_info_data_t {
        pub max_cpus: integer_t,
        pub avail_cpus: integer_t,
        pub memory_size: libc::natural_t,
        pub cpu_type: integer_t,
        pub cpu_subtype: integer_t,
        pub cpu_threadtype: integer_t,
        pub physical_cpu: integer_t,
        pub physical_cpu_max: integer_t,
        pub logical_cpu: integer_t,
        pub logical_cpu_max: integer_t,
        pub max_mem: u64,
    }

    unsafe extern "C" {
        pub fn mach_host_self() -> host_t;

        pub fn host_info(
            host: host_t,
            flavor: libc::host_flavor_t,
            host_info_out: libc::host_info_t,
            host_info_out_count: *mut mach_msg_type_number_t,
        ) -> kern_return_t;
    }
}

/// A tick is 10 ms, which is what Linux's `/proc/stat` is written in.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CpuUsage {
    pub user_ticks: u64,
    pub system_ticks: u64,
    pub idle_ticks: u64,
    pub nice_ticks: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MemUsage {
    pub total: u64,
    pub free: u64,
    pub active: u64,
    pub inactive: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UptimeInfo {
    /// Hundredths of a second since boot — Linux's jiffies at 100 Hz, which is
    /// the unit `/proc/uptime` and `/proc/stat`'s `btime` are written in.
    pub uptime_ticks: u64,
    pub load_1m: u64,
    pub load_5m: u64,
    pub load_15m: u64,
}

/// The Apple reader: Mach calls and sysctls.
mod host {
    use super::{CpuUsage, MemUsage, UptimeInfo, ffi};
    use std::sync::{Mutex, OnceLock};

    /// How many `integer_t` a Mach info struct is, which is what every one of
    /// these calls wants as its count.
    ///
    /// **Computed from the struct, not written down.** The SDK spells it
    /// `sizeof(T) / sizeof(integer_t)` in a C macro, and the alternative —
    /// copying the number — is a constant that silently disagrees with the
    /// layout the next SDK ships. A count that is too small makes the call
    /// answer `KERN_INVALID_ARGUMENT`; one that is too large makes it write
    /// past the struct.
    pub(crate) const fn info_count<T>() -> ffi::mach_msg_type_number_t {
        (size_of::<T>() / size_of::<ffi::integer_t>()) as ffi::mach_msg_type_number_t
    }

    /// The host port, resolved once. See the module comment.
    pub(crate) fn host_port() -> ffi::host_t {
        static PORT: OnceLock<u32> = OnceLock::new();
        *PORT.get_or_init(|| unsafe { ffi::mach_host_self() })
    }

    /// Read a `sysctl` by name into a value of `T`, answering whether it worked.
    ///
    /// The length is passed in and checked on the way out: a `sysctl` that returns
    /// fewer bytes than asked for has left the rest of the value untouched, and
    /// treating that as success is how a partially-filled `timeval` gets read as a
    /// whole one.
    ///
    /// `T` is a [`SysctlValue`] since 2026-10-17: the bytes the kernel writes
    /// become a `T` unchecked, and the bound was any `T` at all.
    pub(crate) fn sysctl<T: SysctlValue>(name: &str) -> Option<T> {
        let c = std::ffi::CString::new(name).ok()?;
        let mut value = std::mem::MaybeUninit::<T>::zeroed();
        let mut len = size_of::<T>();
        // SAFETY: `value` is `len` writable bytes, and `len` is a local the
        // kernel writes the count back into.
        let ok = unsafe {
            libc::sysctlbyname(
                c.as_ptr(),
                value.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        // SAFETY: every byte was written, and `SysctlValue` says any bytes
        // are a `T`.
        (ok == 0 && len == size_of::<T>()).then(|| unsafe { value.assume_init() })
    }

    /// A type every bit pattern of which is a value: what a `sysctl` may be
    /// read into.
    ///
    /// # Safety
    /// Integers, and `#[repr(C)]` structs of them.
    pub(crate) unsafe trait SysctlValue: Copy {}
    // SAFETY: an integer.
    unsafe impl SysctlValue for u64 {}

    /// What the machine's processors have been doing since boot.
    pub fn cpu_usage() -> CpuUsage {
        // These SDK structs contain only integer fields; zero is a valid
        // initial value and gives Mach a fully initialized output buffer.
        let mut load: ffi::host_cpu_load_info_data_t = unsafe { std::mem::zeroed() };
        let mut count = info_count::<ffi::host_cpu_load_info_data_t>();
        let kr = unsafe {
            ffi::host_statistics(
                host_port(),
                ffi::HOST_CPU_LOAD_INFO,
                (&raw mut load).cast(),
                &mut count,
            )
        };
        if kr != ffi::KERN_SUCCESS as ffi::kern_return_t {
            return CpuUsage::default();
        }
        let t = &load.cpu_ticks;
        CpuUsage {
            user_ticks: t[ffi::CPU_STATE_USER as usize] as u64,
            system_ticks: t[ffi::CPU_STATE_SYSTEM as usize] as u64,
            idle_ticks: t[ffi::CPU_STATE_IDLE as usize] as u64,
            nice_ticks: t[ffi::CPU_STATE_NICE as usize] as u64,
        }
    }

    /// The last reading that worked, served when one does not.
    static LAST_GOOD: Mutex<Option<MemUsage>> = Mutex::new(None);

    /// How much memory the machine has and how much of it is doing what.
    pub fn mem_usage() -> MemUsage {
        let mut basic = ffi::host_basic_info_data_t::default();
        let mut count = info_count::<ffi::host_basic_info_data_t>();
        let mut kr = unsafe {
            ffi::host_info(
                host_port(),
                ffi::HOST_BASIC_INFO,
                (&raw mut basic).cast(),
                &mut count,
            )
        };
        let mut vm: ffi::vm_statistics64_data_t = unsafe { std::mem::zeroed() };
        if kr == ffi::KERN_SUCCESS as ffi::kern_return_t {
            count = info_count::<ffi::vm_statistics64_data_t>();
            kr = unsafe {
                ffi::host_statistics64(
                    host_port(),
                    ffi::HOST_VM_INFO64,
                    (&raw mut vm).cast(),
                    &mut count,
                )
            };
        }

        if kr != ffi::KERN_SUCCESS as ffi::kern_return_t {
            eprintln!(
                "WARNING: mem_usage: host_info/host_statistics64 failed (kr={kr}), using fallback"
            );
            if let Some(last) = *LAST_GOOD.lock().unwrap() {
                return last;
            }
            // Nothing has ever worked, so answer from the one thing that cannot
            // fail this way. Quarters rather than zeroes: a guest that divides by
            // `free` should not divide by zero because a Mach call was refused.
            let total: u64 = sysctl("hw.memsize")
                .filter(|&m: &u64| m != 0)
                .unwrap_or(4 << 30);
            return MemUsage {
                total,
                free: total / 4,
                active: total / 4,
                inactive: total / 4,
            };
        }

        let page = rustix::param::page_size() as u64;
        let usage = MemUsage {
            total: basic.max_mem,
            free: vm.free_count as u64 * page,
            active: vm.active_count as u64 * page,
            inactive: vm.inactive_count as u64 * page,
        };
        *LAST_GOOD.lock().unwrap() = Some(usage);
        usage
    }

    /// Hundredths of a second since the machine booted.
    ///
    /// `CLOCK_MONOTONIC` is the clock the kernel defines in terms of uptime. It
    /// avoids reading `kern.boottime`, which can be unavailable in a sandbox,
    /// and cannot jump when wall time is adjusted.
    pub fn uptime_ticks() -> u64 {
        let Ok((sec, nsec)) = util_timeabi::host_clock(libc::CLOCK_MONOTONIC) else {
            return 0;
        };
        (sec as u64)
            .saturating_mul(100)
            .saturating_add(nsec as u64 / 10_000_000)
    }

    /// The load averages, rescaled to Linux's fixed point.
    ///
    /// Darwin reports them against its own `fscale`, which the sysctl returns
    /// alongside; Linux's `/proc/loadavg` readers expect sixteen fractional bits.
    pub fn uptime() -> UptimeInfo {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Loadavg {
            ldavg: [u32; 3],
            scale: libc::c_long,
        }
        // SAFETY: integers, `#[repr(C)]`.
        unsafe impl SysctlValue for Loadavg {}
        let mut load = [0u64; 3];
        if let Some(l) = sysctl::<Loadavg>("vm.loadavg") {
            // The shift is `log2(scale)`. The C hard-coded `FSHIFT`, which is the
            // same number on every Darwin so far; taking it from the value the
            // kernel just handed over cannot be wrong on the next one.
            let shift = (l.scale.max(1) as u64).trailing_zeros();
            for (i, output) in load.iter_mut().enumerate() {
                let v = l.ldavg[i] as u64;
                *output = if shift < 16 {
                    v << (16 - shift)
                } else {
                    v >> (shift - 16)
                };
            }
        }
        UptimeInfo {
            uptime_ticks: uptime_ticks(),
            load_1m: load[0],
            load_5m: load[1],
            load_15m: load[2],
        }
    }
}

pub use host::{cpu_usage, mem_usage, uptime, uptime_ticks};

#[path = "guest.rs"]
mod guest;
pub use guest::{GUEST_MAX_RAM, guest_free_ram, guest_total_ram};

// ---------------------------------------------------------------------------
// The C ABI, which `fs/proc` and `kernel/task.c` reach these through.
// ---------------------------------------------------------------------------

/// Not `#[unsafe(no_mangle)]` since 2026-09-06. No C source calls it, no
/// `ffi::` reaches it, and no header the embedder example compiles against
/// declares it -- so the export was a second interface with nobody on the
/// other side, and an optimisation barrier: LTO must emit an externally
/// visible function as written and cannot specialise the call.
pub fn get_cpu_usage() -> CpuUsage {
    cpu_usage()
}

pub fn get_mem_usage() -> MemUsage {
    mem_usage()
}

pub fn get_uptime() -> UptimeInfo {
    uptime()
}

pub fn get_uptime_ticks() -> u64 {
    uptime_ticks()
}

#[cfg(test)]
mod tests;

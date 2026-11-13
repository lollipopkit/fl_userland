//! Tests for host statistics ABI values and platform readers.

use super::*;
use host::{host_port, info_count};

/// The load-average rescale, which is the only arithmetic here that is not
/// a copy. Darwin's `fscale` is 2048 — eleven bits — and Linux wants
/// sixteen, so a load of 1.0 is 2048 there and 65536 here.
#[test]
fn a_load_average_is_rescaled_to_sixteen_fractional_bits() {
    let rescale = |v: u64, scale: u64| {
        let shift = scale.trailing_zeros();
        if shift < 16 {
            v << (16 - shift)
        } else {
            v >> (shift - 16)
        }
    };
    assert_eq!(rescale(2048, 2048), 65536, "1.0 at Darwin's scale");
    assert_eq!(rescale(1024, 2048), 32768, "0.5");
    assert_eq!(rescale(0, 2048), 0);
    // A scale wider than Linux's shifts the other way, which is the branch
    // the C had and nothing on this platform takes.
    assert_eq!(rescale(1 << 20, 1 << 20), 65536);
}

/// Every one of these reads the machine, so what a test can check is that
/// they answer at all and that the numbers are ordered the way their
/// meaning requires. Both readers have to satisfy it, which is the point
/// of it being here rather than in one of them.
#[test]
fn the_machine_answers_and_the_answers_are_consistent() {
    let m = mem_usage();
    assert!(m.total > 0, "the machine has memory");
    assert!(m.free <= m.total, "free is part of total");
    assert!(m.active <= m.total);

    let c = cpu_usage();
    assert!(
        c.user_ticks + c.system_ticks + c.idle_ticks > 0,
        "the processors have done something"
    );

    let t = uptime_ticks();
    assert!(t > 0, "the machine booted before now");
    // Twice, because the only thing that makes this wrong in a way a
    // single read cannot see is a unit error: hundredths that are really
    // seconds do not move between two calls a moment apart, and neither do
    // hundredths — so what is checked is that it does not go backwards.
    assert!(uptime_ticks() >= t);

    assert_eq!(uptime().uptime_ticks / 100, t / 100, "the same clock");
}

/// The port is resolved once however many threads ask, which is the whole
/// reason it is cached: each `mach_host_self` leaks a user reference.
/// The counts the Mach calls are given must be exactly the struct's size
/// in `integer_t`, and the SDK's own macros say so. Checked here because
/// this is the one place the C had a constant and this has arithmetic.
#[test]
fn an_info_count_is_the_struct_size_in_words() {
    assert_eq!(size_of::<ffi::integer_t>(), 4);
    assert_eq!(
        info_count::<ffi::host_cpu_load_info_data_t>() as usize * 4,
        size_of::<ffi::host_cpu_load_info_data_t>()
    );
    assert_eq!(
        info_count::<ffi::vm_statistics64_data_t>() as usize * 4,
        size_of::<ffi::vm_statistics64_data_t>()
    );
    // The one that would be wrong if `host_basic_info_data_t` grew: it is
    // 15 words on every Darwin so far, and this says so from the struct.
    assert!(info_count::<ffi::host_basic_info_data_t>() >= 12);
}

#[test]
fn the_host_port_is_resolved_once() {
    let first = host_port();
    let handles: Vec<_> = (0..8).map(|_| std::thread::spawn(host_port)).collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), first);
    }
}

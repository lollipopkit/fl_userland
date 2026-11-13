//! Guest CPU features beyond ARMv8.0, and what the guest is told about them.
//!
//! [`caps`] is the table `AT_HWCAP`, the ID registers and `/proc/cpuinfo` are
//! all read from. The other modules are the instructions done in software
//! because the host CPU (an A9 at the iOS 13 floor: ARMv8.0-A, AdvSIMD and
//! crypto only) cannot do them natively, reached through [`slow`].

pub mod bf16;
pub mod caps;
pub mod frint;
pub mod fp16;
pub mod fpops;
pub mod jscvt;
pub mod slow;
pub mod softfloat;

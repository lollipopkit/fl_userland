//! `Identity<T>` and the one alias whose pointee is this crate's.
//!
//! The type itself is `crates/util/identity` since 2026-09-16: it is
//! `NonNull<T>` and a `PhantomData`, so it belongs at the layer that uses it
//! rather than in the shared *kernel* types. `crates/fs/tty` wanted one for
//! "which terminal does this thread group hold" and could not have it without
//! depending on this crate — which would have cemented the `tty` placeholder
//! below, since the edge back is what keeps it opaque.
//!
//! Re-exported here, so `kernel_abi::Identity` and `MountId` still resolve and
//! no call site moved. That is what `crates/util/synctypes` and
//! `crates/emu/abi` did for `lock_t` and `cpu_state`.

pub use util_identity::Identity;

/// Which filesystem instance: a [`crate::Superblock`], which every copy of a
/// mount shares. See [`Identity`].
///
/// The task and thread-group aliases are `crates/kernel/taskview`'s, because
/// `struct task` and `struct tgroup` are — they moved up out of this crate on
/// 2026-09-09 and only `mount` is still defined here.
pub type MountId = Identity<crate::Superblock>;

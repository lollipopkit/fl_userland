//! Convert between a rootfs tarball and a fakefs directory.
//!
//! A fakefs is a `data/` directory of real files plus `meta.db`, a SQLite
//! database carrying the ownership, modes and device numbers iOS will not give
//! an app for real. See CLAUDE.md and `crates/fs/fakedb`.
//!
//! This is a library so the integration tests can build archives with the same
//! code the tool writes them with; `src/main.rs` is the CLI over it.

pub mod archive;
pub mod db;
pub mod error;
pub mod export;
pub mod import;
pub mod index;
pub mod path;

pub use error::{Error, Result};
pub use export::export;
pub use import::import;
pub use index::index;

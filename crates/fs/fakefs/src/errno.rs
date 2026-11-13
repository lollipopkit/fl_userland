//! Guest errno values and the error type these operations fail with.

use std::fmt;

use libc::c_int;

/// I/O error, and out of memory. The guest's numbers, from
/// `crates/util/errno`.
pub use guest_errno::c_int_::{EIO, ENOMEM};

#[derive(Debug)]
pub enum Error {
    Sql(rusqlite::Error),
    OutOfMemory,
}

impl Error {
    /// The guest errno the C caller expects back.
    pub fn errno(&self) -> c_int {
        match self {
            Error::Sql(_) => EIO,
            Error::OutOfMemory => ENOMEM,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Wording kept from the C version, which logged
        // "fakefs <what>: sqlite error: <msg>" and "fakefs <what>: out of
        // memory"; `run` supplies the "fakefs <what>: " prefix.
        match self {
            Error::Sql(e) => write!(f, "sqlite error: {e}"),
            Error::OutOfMemory => write!(f, "out of memory"),
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sql(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_values_are_the_ones_a_guest_expects() {
        // These cross the FFI boundary as plain ints, so a wrong one reaches
        // the caller as an unrelated failure. Written out rather than read
        // from the owner, which would make this a copy compared with itself.
        assert_eq!(EIO, -5);
        assert_eq!(ENOMEM, -12);
        assert_eq!(Error::OutOfMemory.errno(), ENOMEM);
        assert_eq!(
            Error::Sql(rusqlite::Error::QueryReturnedNoRows).errno(),
            EIO
        );
    }
}

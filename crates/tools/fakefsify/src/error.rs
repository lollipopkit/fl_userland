//! Error type for fakefs import/export.
//!
//! The C version filled in a `struct fakefsify_error` with `__LINE__` and
//! returned false, which meant every error path also leaked the database
//! handle, the archive and any open fd. Here the failure carries what it was
//! doing instead of where it was written, and the cleanup is the `Drop` impls
//! on `Reader`, `Writer` and `Connection`.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Reading or writing the archive failed. `code` is the OS error, or 0.
    Archive { code: i32, message: String },
    /// A database operation failed.
    Sqlite(rusqlite::Error),
    /// A host filesystem operation failed. `doing` names the operation and
    /// its target, since one archive entry does several.
    Io {
        doing: String,
        source: std::io::Error,
    },
    /// A `meta.db` row is not shaped the way the schema says it is.
    Corrupt(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Archive { code, message } => write!(f, "archive error {code}: {message}"),
            Error::Sqlite(e) => write!(f, "database error: {e}"),
            Error::Io { doing, source } => write!(f, "{doing}: {source}"),
            Error::Corrupt(what) => write!(f, "corrupt fakefs: {what}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Sqlite(e) => Some(e),
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sqlite(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Attach "what was being done" to a failed host operation.
///
/// Covers both `std::io::Error` and `rustix::io::Errno`, since the extraction
/// path mixes `std::fs` with the `*at()` calls.
pub trait IoContext<T> {
    fn doing(self, what: impl FnOnce() -> String) -> Result<T>;
}

impl<T, E: Into<std::io::Error>> IoContext<T> for std::result::Result<T, E> {
    fn doing(self, what: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|source| Error::Io {
            doing: what(),
            source: source.into(),
        })
    }
}

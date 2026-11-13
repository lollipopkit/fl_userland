//! The allocation count, in a test binary of its own.
//!
//! `LIVE` is a process-wide counter, so an assertion about its absolute value
//! is only true if nothing else is creating eventfds at the same time — and
//! cargo runs a crate's unit tests in parallel threads of one process. This
//! started life beside the others in `src/blocking_tests.rs` and failed with
//! `left: 5, right: 4`, which was the test racing its neighbours rather than
//! anything wrong with the counter.
//!
//! An integration test is a separate binary, which is what makes "nothing else
//! is creating eventfds" true.

use kernel_sighand as _;
use kernel_sigqueue as _;

use kernel_eventfd::{Descriptor, eventfd_live_count};
use pollset::Watchers;
use std::sync::Arc;

fn make() -> *mut Descriptor {
    Box::into_raw(Descriptor::new(0, false, Arc::new(Watchers::default())))
}

#[test]
fn the_live_count_follows_new_and_free() {
    // The leak check the C could not have: its counter was two fields in a
    // union, so there was nothing to free and nothing to lose. Moving the state
    // introduced a way to leak that did not exist before, and this is what
    // makes the close path checkable rather than something to read and believe.
    assert_eq!(eventfd_live_count(), 0, "something is already live");

    let a = make();
    assert_eq!(eventfd_live_count(), 1);
    let b = make();
    assert_eq!(eventfd_live_count(), 2);

    unsafe { drop(Box::from_raw(a)) };
    assert_eq!(eventfd_live_count(), 1);
    unsafe { drop(Box::from_raw(b)) };
    assert_eq!(eventfd_live_count(), 0);
}

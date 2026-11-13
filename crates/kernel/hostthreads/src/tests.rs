use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn a_new_group_has_no_threads() {
    assert_eq!(HostThreads::new().live(), 0);
}

#[test]
fn started_and_finished_balance() {
    let g = HostThreads::new();
    let a = g.started();
    let b = g.started();
    assert_eq!(g.live(), 2);
    a.finished();
    assert_eq!(g.live(), 1);
    b.finished();
    assert_eq!(g.live(), 0);
}

#[test]
fn a_wait_that_is_already_satisfied_does_not_block() {
    let g = HostThreads::new();
    let me = g.started();
    // want == 1 is "me and nobody else", which is already true.
    assert!(g.wait_for(1, Duration::from_millis(0)));
    me.finished();
}

#[test]
fn the_wait_ends_when_the_last_thread_reports_in() {
    let g = HostThreads::new();
    let me = g.started();
    let other = g.started();
    let g2 = Arc::clone(&g);
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        other.finished();
        let _ = g2;
    });
    let start = Instant::now();
    assert!(
        g.wait_for(1, Duration::from_secs(5)),
        "should not have timed out"
    );
    let waited = start.elapsed();
    assert!(waited < Duration::from_secs(1), "waited {waited:?}");
    assert_eq!(g.live(), 1);
    t.join().unwrap();
    me.finished();
}

#[test]
fn a_thread_that_never_reports_times_out() {
    // The stuck-in-a-host-syscall case, which is what the force-kill path
    // downstream is for. A timeout must be a `false`, not a hang.
    let g = HostThreads::new();
    let _me = g.started();
    let _stuck = g.started();
    let start = Instant::now();
    assert!(!g.wait_for(1, Duration::from_millis(30)));
    assert!(
        start.elapsed() >= Duration::from_millis(25),
        "returned too early"
    );
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "waited far past the timeout"
    );
}

#[test]
fn a_thread_outlives_the_group() {
    // The reason for the Arc. The exit path gives up on a stuck thread,
    // frees the group -- dropping its reference -- and the thread reports
    // in afterwards. Nothing here may touch freed memory.
    let g = HostThreads::new();
    let stuck = g.started();
    assert_eq!(g.live(), 1);
    drop(g); // the thread group is freed
    stuck.finished(); // and the thread finally returns
}

#[test]
fn many_threads_reporting_at_once() {
    let g = HostThreads::new();
    let me = g.started();
    let counter = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..32 {
        let h = g.started();
        let c = Arc::clone(&counter);
        handles.push(std::thread::spawn(move || {
            c.fetch_add(1, Ordering::SeqCst);
            h.finished();
        }));
    }
    assert!(g.wait_for(1, Duration::from_secs(10)));
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(counter.load(Ordering::SeqCst), 32);
    assert_eq!(g.live(), 1);
    me.finished();
}

#[test]
fn an_unbalanced_finish_does_not_wrap_the_count() {
    // A count of usize::MAX would make every later wait time out rather
    // than only being wrong once.
    let g = HostThreads::new();
    Arc::clone(&g).finished();
    assert_eq!(g.live(), 0);
    assert!(g.wait_for(0, Duration::from_millis(0)));
}

/// The group's reference goes first, and the last thread still reports in.
#[test]
fn a_thread_outlives_its_groups_reference() {
    let g = HostThreads::new();
    assert_eq!(g.live(), 0);
    let a = g.started();
    let b = g.started();
    assert_eq!(g.live(), 2);
    assert!(!g.wait_for(1, Duration::from_millis(10)));
    a.finished();
    assert!(g.wait_for(1, Duration::from_millis(10)));
    drop(g);
    b.finished();
}

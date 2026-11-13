//! Linux permits one epoll instance to watch another and propagates readiness
//! through the nesting graph. It rejects only cycles (and excessive depth), not
//! every epoll member.
//!
//! The cases here exercise delivery after an outer wait has blocked as well as
//! graph lifetime and depth. Testing only an inner set that was already ready
//! before the outer wait misses the wake-propagation half of nesting.

use guest_tests::{Harness, check, check_fails, sys};

const EPOLLEXCLUSIVE: u32 = 1 << 28;

fn epoll() -> i32 {
    unsafe { libc::epoll_create1(0) }
}

fn pipe() -> Option<(i32, i32)> {
    let mut fds = [0i32; 2];
    (unsafe { libc::pipe(fds.as_mut_ptr()) } == 0).then_some((fds[0], fds[1]))
}

fn event(events: u32, data: u64) -> libc::epoll_event {
    libc::epoll_event { events, u64: data }
}

fn add(ep: i32, fd: i32, data: u64) -> i32 {
    let mut ev = event(libc::EPOLLIN as u32, data);
    unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) }
}

fn wait_one(ep: i32, timeout: i32) -> (i32, libc::epoll_event) {
    let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::epoll_wait(ep, &raw mut ev, 1, timeout) };
    (result, ev)
}

fn close_all(fds: &[i32]) {
    for &fd in fds {
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
}

fn main() {
    let mut h = Harness::new();
    let outer = epoll();
    let inner = epoll();
    let Some((read_end, write_end)) = pipe() else {
        h.group("nested-epoll-delivery");
        check!(h, false, "create the member pipe");
        std::process::exit(h.finish());
    };
    check!(
        h,
        outer >= 0 && inner >= 0,
        "create outer={outer} and inner={inner} epoll sets"
    );

    h.group("nested-epoll-delivery");
    check!(
        h,
        add(inner, read_end, 0x11) == 0,
        "ADD a pipe to the inner set: errno {}",
        sys::errno()
    );
    check!(
        h,
        add(outer, inner, 0x22) == 0,
        "Linux permits the outer set to watch the inner set: errno {}",
        sys::errno()
    );
    check!(
        h,
        unsafe { libc::write(write_end, c"x".as_ptr().cast(), 1) } == 1,
        "make the inner member ready"
    );
    let (outer_result, outer_event) = wait_one(outer, 500);
    check!(
        h,
        outer_result == 1
            && outer_event.events & libc::EPOLLIN as u32 != 0
            && outer_event.u64 == 0x22,
        "readiness propagates to the outer registration: r={outer_result} event={outer_event:?} errno {}",
        sys::errno()
    );
    let (inner_result, inner_event) = wait_one(inner, 500);
    check!(
        h,
        inner_result == 1
            && inner_event.events & libc::EPOLLIN as u32 != 0
            && inner_event.u64 == 0x11,
        "the original event remains on the inner set: r={inner_result} event={inner_event:?} errno {}",
        sys::errno()
    );

    h.group("nested-epoll-cycle");
    check_fails!(
        h,
        add(inner, outer, 0x33),
        libc::ELOOP,
        "adding the outer set back into its child would create a cycle"
    );

    h.group("graph-accounting");
    let graph_outer = epoll();
    let graph_inner = epoll();
    check!(h, graph_outer >= 0 && graph_inner >= 0,
        "create isolated epoll sets for graph accounting");
    check!(h, add(graph_outer, graph_inner, 0x43) == 0,
        "create the graph edge under test: errno {}", sys::errno());
    check_fails!(
        h,
        add(graph_outer, graph_inner, 0x44),
        libc::EEXIST,
        "a duplicate ADD leaves the existing graph edge intact"
    );
    check_fails!(
        h,
        add(graph_inner, graph_outer, 0x45),
        libc::ELOOP,
        "the failed duplicate ADD did not remove the live edge"
    );

    let alias = unsafe { libc::dup(graph_inner) };
    check!(h, alias >= 0, "duplicate the inner epoll fd");
    if alias >= 0 {
        check!(h, add(graph_outer, alias, 0x46) == 0,
            "the alias is a distinct epoll registration: errno {}", sys::errno());
        check!(h, unsafe { libc::epoll_ctl(graph_outer, libc::EPOLL_CTL_DEL, graph_inner, std::ptr::null_mut()) } == 0,
            "delete one nested alias: errno {}", sys::errno());
        check_fails!(h, add(graph_inner, graph_outer, 0x47), libc::ELOOP,
            "the surviving alias keeps the graph edge live");
        check!(h, unsafe {
            libc::epoll_ctl(graph_outer, libc::EPOLL_CTL_DEL, alias, std::ptr::null_mut())
        } == 0, "delete the final nested alias: errno {}", sys::errno());
        // The final alias DEL succeeds and the Rust unit test checks its graph
        // count. Linux keeps additional global nesting bookkeeping that makes a
        // reverse-ADD assertion after this sequence environment-dependent.

    }

    close_all(&[graph_outer, graph_inner]);
    h.group("nested-exclusive");
    let exclusive_outer = epoll();
    let exclusive_inner = epoll();
    if exclusive_outer >= 0 && exclusive_inner >= 0 {
        let mut exclusive = event(libc::EPOLLIN as u32 | EPOLLEXCLUSIVE, 0x48);
        check_fails!(
            h,
            unsafe {
                libc::epoll_ctl(
                    exclusive_outer,
                    libc::EPOLL_CTL_ADD,
                    exclusive_inner,
                    &raw mut exclusive,
                )
            },
            libc::EINVAL,
            "EPOLLEXCLUSIVE cannot be used for a nested epoll target"
        );
    } else {
        check!(h, false, "create epoll sets for EPOLLEXCLUSIVE");
    }
    close_all(&[exclusive_outer, exclusive_inner]);

    h.group("nesting-depth");
    let chain = [epoll(), epoll(), epoll(), epoll(), epoll(), epoll()];
    check!(h, chain.iter().all(|&fd| fd >= 0), "create a six-instance chain");
    if chain.iter().all(|&fd| fd >= 0) {
        for edge in 0..4 {
            check!(h, add(chain[edge], chain[edge + 1], edge as u64) == 0,
                "edge {edge} of the maximum-depth chain: errno {}", sys::errno());
        }
        check_fails!(h, add(chain[4], chain[5], 5), libc::ELOOP,
            "a fifth nested edge exceeds Linux's depth limit");
    }

    h.group("delayed-nested-wake");
    let delayed_outer = epoll();
    let delayed_inner = epoll();
    let leaf = pipe();
    let rescue = pipe();
    if delayed_outer >= 0 && delayed_inner >= 0 && leaf.is_some() && rescue.is_some() {
        let (leaf_r, leaf_w) = leaf.unwrap();
        let (rescue_r, rescue_w) = rescue.unwrap();
        check!(h, add(delayed_inner, leaf_r, 0x51) == 0,
            "watch the delayed leaf: errno {}", sys::errno());
        check!(h, add(delayed_outer, delayed_inner, 0x52) == 0,
            "watch the delayed inner epoll: errno {}", sys::errno());
        check!(h, add(delayed_outer, rescue_r, 0x53) == 0,
            "watch a rescue pipe: errno {}", sys::errno());
        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(80));
            unsafe { libc::write(leaf_w, c"l".as_ptr().cast(), 1) };
            std::thread::sleep(std::time::Duration::from_millis(720));
            unsafe { libc::write(rescue_w, c"r".as_ptr().cast(), 1) };
            close_all(&[leaf_w, rescue_w]);
        });
        let started = std::time::Instant::now();
        let (n, ev) = wait_one(delayed_outer, 1500);
        let elapsed = started.elapsed();
        check!(h, n == 1 && ev.u64 == 0x52 && elapsed < std::time::Duration::from_millis(700),
            "an inner transition wakes a blocked outer wait promptly: n={n} event={ev:?} elapsed={elapsed:?}");
        writer.join().unwrap();
        close_all(&[leaf_r, rescue_r]);
    } else {
        check!(h, false, "create delayed-wake epolls and pipes");
    }
    close_all(&[delayed_outer, delayed_inner]);

    close_all(&chain);
    close_all(&[alias, read_end, write_end, inner, outer]);
    std::process::exit(h.finish());
}

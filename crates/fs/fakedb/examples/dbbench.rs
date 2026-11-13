//! How long a `meta.db` lookup takes, and which part of it.
//!
//! Not a gate: a measurement, run by hand against a real fakefs.
//!
//!   cargo run --release -p fs-fakedb --example dbbench -- <meta.db> [/some/path]

fn bench(name: &str, n: u32, mut f: impl FnMut()) {
    for _ in 0..n / 10 + 1 {
        f();
    }
    let t = std::time::Instant::now();
    for _ in 0..n {
        f();
    }
    println!(
        "  {name:<34} {:>7.0} ns",
        t.elapsed().as_nanos() as f64 / n as f64
    );
}

fn main() {
    let db = std::env::args().nth(1).expect("meta.db path");
    let path: Vec<u8> = std::env::args()
        .nth(2)
        .unwrap_or("/bin/sh".into())
        .into_bytes();
    let d = fakedb::Db::open(&db, rustix::fs::CWD).expect("open");
    println!(
        "lookup shapes (found: {:?}):",
        d.lookup_path(&path).is_some()
    );

    let n = 100_000;
    bench("lookup_path (join, blob)", n, || {
        let _ = d.lookup_path(&path);
    });
    bench("lookup_inode (one table, i64)", n, || {
        let _ = d.lookup_inode(&path);
    });
    bench("begin + select + commit", n, || {
        let tx = d.read();
        let _ = tx.path_stat(&path);
        tx.commit();
    });
    bench("lookup_stat by inode", n, || {
        let _ = d.lookup_stat(2);
    });
}

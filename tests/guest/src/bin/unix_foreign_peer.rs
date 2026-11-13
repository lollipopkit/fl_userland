//! A guest server whose listener a **host** process connects to and then says
//! nothing.
//!
//! Driven by `tests/integration/guest_tests.sh`, which is the half that knows
//! the emulator's host pid and so where the host socket is: a guest unix
//! listener is a host socket at `/tmp/iulsock<host pid>.<id>`, under a
//! directory every process on the host can reach. Two guest sockets that
//! connect find each other's endpoint through a handshake over that socket,
//! and `accept` used to read the handshake from *every* peer -- so a foreign
//! one that connected and sent nothing parked every accept on the listener
//! for ever, holding no lock and making no progress. A peer outside the
//! emulator's own host process is not asked for one now.
//!
//! The order is enforced by a file rather than by timing: the client half
//! connects only after the server has accepted its first connection, so that
//! first one is the host's whatever the host's timing. A kernel that waits on
//! the silent peer never accepts a second connection, and the line the client
//! sends is never printed.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

const SOCKET: &str = "/tmp/ufp.sock";
const GO: &str = "/tmp/ufp.go";

fn main() {
    let _ = std::fs::remove_file(SOCKET);
    let _ = std::fs::remove_file(GO);
    let listener = UnixListener::bind(SOCKET).expect("bind");
    println!("listening");
    std::io::stdout().flush().unwrap();

    let client = unsafe { libc::fork() };
    if client == 0 {
        // Up to a minute, which is the host script's deadline too.
        for _ in 0..6000 {
            if Path::new(GO).exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut stream = UnixStream::connect(SOCKET).expect("connect");
        stream.write_all(b"hello\n").expect("write");
        unsafe { libc::_exit(0) };
    }

    let (_silent, _) = listener.accept().expect("first accept");
    println!("first connection accepted");
    std::io::stdout().flush().unwrap();
    std::fs::File::create(GO).expect("go");

    let (second, _) = listener.accept().expect("second accept");
    let mut greeting = String::new();
    BufReader::new(second).read_line(&mut greeting).expect("read");
    println!("served after a silent peer: {}", greeting.trim_end());

    let mut st = 0;
    unsafe { libc::waitpid(client, &mut st, 0) };
    let _ = std::fs::remove_file(SOCKET);
    let _ = std::fs::remove_file(GO);
}

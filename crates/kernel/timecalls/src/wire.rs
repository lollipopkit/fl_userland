use guest_errno::Errno;
use usercopy::GuestMem;

// ---------------------------------------------------------------------------
// The guest's time structures, as offsets
// ---------------------------------------------------------------------------

/// `struct timespec_`: `{ i64 sec; i64 nsec; }`.
pub(super) fn put_timespec(addr: u64, sec: i64, nsec: i64) -> Result<(), Errno> {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&sec.to_le_bytes());
    b[8..].copy_from_slice(&nsec.to_le_bytes());
    if GuestMem.write(addr, &b) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

pub(super) fn get_timespec(addr: u64) -> Result<(i64, i64), Errno> {
    let mut b = [0u8; 16];
    if GuestMem.read(addr, &mut b) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok((
        i64::from_le_bytes(b[..8].try_into().unwrap()),
        i64::from_le_bytes(b[8..].try_into().unwrap()),
    ))
}

/// `struct timeval_`: the same shape, microseconds.
pub(super) fn put_timeval(addr: u64, sec: i64, usec: i64) -> Result<(), Errno> {
    put_timespec(addr, sec, usec)
}

/// The guest's `struct itimerval`: `{ timeval interval; timeval value; }`, and
/// its `itimerspec` is the same shape in nanoseconds. Interval **first**.
pub(super) fn read_pair(addr: u64) -> Result<[i64; 4], Errno> {
    let mut b = [0u8; 32];
    if GuestMem.read(addr, &mut b) != 0 {
        return Err(Errno::EFAULT);
    }
    let at = |o: usize| i64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    Ok([at(0), at(8), at(16), at(24)])
}

pub(super) fn write_pair(addr: u64, v: [i64; 4]) -> Result<(), Errno> {
    let mut b = [0u8; 32];
    for (i, x) in v.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&x.to_le_bytes());
    }
    if GuestMem.write(addr, &b) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

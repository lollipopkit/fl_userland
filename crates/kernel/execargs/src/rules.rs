use super::{E2BIG, EINVAL};
use std::ffi::c_int;

/// The bytes `count` strings occupy, **including the terminator after the
/// last one**, or `None` if they do not fit in `buf`.
///
/// A zero count is one byte: the terminator on its own, which is what an empty
/// argument list is.
pub fn size(buf: &[u8], count: usize) -> Option<usize> {
    let mut at = 0usize;
    for _ in 0..count {
        let end = buf.get(at..)?.iter().position(|&b| b == 0)?;
        at += end + 1;
    }
    // The extra NUL that ends the list. `at` is the byte after the last
    // string's terminator, and that byte has to be there and has to be zero.
    match buf.get(at) {
        Some(0) => Some(at + 1),
        _ => None,
    }
}

/// The list with its first entry removed, as a slice of the same buffer.
///
/// `None` when there is nothing to remove — which is not the same as an error:
/// see [`shebang`], which is the only caller and treats it as "nothing to drop
/// and nothing to append".
pub(super) fn without_first(buf: &[u8], count: usize) -> Option<(&[u8], usize)> {
    if count == 0 {
        return None;
    }
    let first = buf.iter().position(|&b| b == 0)?;
    Some((&buf[first + 1..], count - 1))
}

/// The argument list a `#!` line produces.
///
/// `interpreter`, then the optional single argument, then the script's own
/// path, then everything the caller passed **except its `argv[0]`** — which the
/// script's path has just replaced.
///
/// Answers the bytes and the count, or `E2BIG` if they do not fit in `max`.
/// The bound is checked before anything is written, as Linux's is.
pub fn shebang(
    interpreter: &[u8],
    argument: Option<&[u8]>,
    file: &[u8],
    rest: &[u8],
    rest_count: usize,
    max: usize,
) -> Result<(Vec<u8>, usize), c_int> {
    let (rest, rest_count) = match without_first(rest, rest_count) {
        Some(r) => r,
        // An empty argv: nothing to drop, and nothing of the caller's to keep.
        None => (&b"\0"[..], 0),
    };
    let rest_size = size(rest, rest_count).ok_or(EINVAL)?;

    let mut head: Vec<&[u8]> = Vec::with_capacity(3);
    head.push(interpreter);
    if let Some(a) = argument {
        head.push(a);
    }
    head.push(file);

    // `>=`, not `>`: the total has to leave room for the terminator that
    // `rest_size` already counts, and Linux refuses a list that exactly fills
    // the buffer.
    let head_size: usize = head.iter().map(|s| s.len() + 1).sum();
    if head_size + rest_size >= max {
        return Err(E2BIG);
    }

    let mut out = Vec::new();
    if out.try_reserve(head_size + rest_size).is_err() {
        return Err(E2BIG);
    }
    for s in &head {
        out.extend_from_slice(s);
        out.push(0);
    }
    out.extend_from_slice(&rest[..rest_size]);
    Ok((out, head.len() + rest_count))
}
/// Sets an environment entry, if it is not already there.
///
/// `prefix` is how many bytes of `entry` are the *name*, including the `=`:
/// `NO_COLOR=1` with a prefix of 9 matches any `NO_COLOR=` whatever follows.
/// `replace` removes an existing one first, for a setting that has to win
/// rather than defer.
///
/// `None` means **the list is unchanged**, which covers both "already there
/// and not replacing" and "would not fit". They are one answer because they
/// have one consequence: `execve` goes ahead with what the caller passed.
/// Injecting an environment variable is best-effort, and failing an `execve`
/// because a workaround did not fit would be worse than the workaround being
/// absent.
pub fn set_env(
    list: &[u8],
    count: usize,
    entry: &[u8],
    prefix: usize,
    replace: bool,
    max: usize,
) -> Option<(Vec<u8>, usize)> {
    let mut kept: Vec<&[u8]> = Vec::with_capacity(count);
    let mut present = false;
    for s in entries(list, count)? {
        if s.len() >= prefix && s[..prefix] == entry[..prefix.min(entry.len())] {
            present = true;
            if replace {
                continue; // dropped, and appended again below
            }
        }
        kept.push(s);
    }
    if present && !replace {
        return None;
    }
    kept.push(entry);
    build(&kept, max)
}

/// Inserts `entry` immediately after the first string, unless an identical one
/// is already somewhere in the list.
///
/// After the first because the first is `argv[0]`: an interpreter's own flags
/// go before the script's arguments, not after them.
///
/// `None` means the list is unchanged, for the same two reasons as
/// [`set_env`].
pub fn insert_arg(list: &[u8], count: usize, entry: &[u8], max: usize) -> Option<(Vec<u8>, usize)> {
    let all = entries(list, count)?;
    if all.contains(&entry) {
        return None;
    }
    let mut out: Vec<&[u8]> = Vec::with_capacity(count + 1);
    let mut it = all.into_iter();
    // An empty list has no argv[0] to go after, and nothing to insert flags
    // for either -- there is no program being invoked.
    out.push(it.next()?);
    out.push(entry);
    out.extend(it);
    build(&out, max)
}

/// How many strings are in the list, walking to the terminator.
///
/// `None` when there is no terminator inside `buf` — which is the bound the C's
/// `while (*p) { count++; p += strlen(p) + 1; }` did not have. Every caller of
/// that shape was walking a buffer on the strength of a terminator it had not
/// looked for.
pub fn count(buf: &[u8]) -> Option<usize> {
    let mut n = 0usize;
    let mut at = 0usize;
    loop {
        match buf.get(at) {
            None => return None,
            Some(0) => return Some(n),
            Some(_) => {}
        }
        at += buf.get(at..)?.iter().position(|&b| b == 0)? + 1;
        n += 1;
    }
}

/// The `i`th string, or `None` past the end.
pub fn at(buf: &[u8], count: usize, i: usize) -> Option<&[u8]> {
    entries(buf, count)?.into_iter().nth(i)
}

/// Every string in the list, or `None` if the count and the bytes disagree.
fn entries(list: &[u8], count: usize) -> Option<Vec<&[u8]>> {
    let mut out = Vec::with_capacity(count);
    let mut at = 0usize;
    for _ in 0..count {
        let end = at + list.get(at..)?.iter().position(|&b| b == 0)?;
        out.push(&list[at..end]);
        at = end + 1;
    }
    match list.get(at) {
        Some(0) => Some(out),
        _ => None,
    }
}

/// The strings back into one buffer, or `None` if they do not fit in `max`.
fn build(strings: &[&[u8]], max: usize) -> Option<(Vec<u8>, usize)> {
    let size: usize = strings.iter().map(|s| s.len() + 1).sum::<usize>() + 1;
    if size > max {
        return None;
    }
    let mut out = Vec::new();
    out.try_reserve(size).ok()?;
    for s in strings {
        out.extend_from_slice(s);
        out.push(0);
    }
    out.push(0);
    Some((out, strings.len()))
}

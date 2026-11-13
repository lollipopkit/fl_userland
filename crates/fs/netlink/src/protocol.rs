//! Netlink message encoding and request decoding.

use super::*;

// ---------------------------------------------------------------- the encoder

/// A message being built. `finish` writes the length back into the header,
/// which is why the header cannot simply be pushed.
pub struct Message {
    buf: Vec<u8>,
    start: usize,
}

impl Message {
    pub fn new(out: &mut Vec<u8>, kind: u16, flags: u16, seq: u32, pid: u32) -> Message {
        let start = out.len();
        out.extend_from_slice(&0u32.to_le_bytes()); // length, filled by `finish`
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&pid.to_le_bytes());
        Message {
            buf: Vec::new(),
            start,
        }
    }

    /// One `struct rtattr`: a length that **includes the four-byte header**,
    /// a type, the payload, and padding to the next multiple of four.
    ///
    /// The length excludes the padding and the *next* attribute starts after
    /// it, which is the rule a reader applies in the opposite direction — a
    /// length that included the padding would put every later attribute four
    /// bytes late on an odd-sized one.
    pub fn attr(&mut self, kind: u16, payload: &[u8]) {
        let len = RTA_HDRLEN + payload.len();
        self.buf.extend_from_slice(&(len as u16).to_le_bytes());
        self.buf.extend_from_slice(&kind.to_le_bytes());
        self.buf.extend_from_slice(payload);
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }

    pub fn body(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }

    /// Append the body and write the length into the header.
    ///
    /// Each message is padded to a four-byte boundary so the next one's header
    /// is aligned, and the length **does not** include that padding: a reader
    /// steps by `NLMSG_ALIGN(len)`, so a length that counted the padding would
    /// make it step twice.
    pub fn finish(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.buf);
        let len = out.len() - self.start;
        out[self.start..self.start + 4].copy_from_slice(&(len as u32).to_le_bytes());
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }
}

/// `struct ifinfomsg`, as bytes.
pub fn ifinfomsg(index: u32, kind: u16, flags: u32) -> [u8; IFINFOMSG_LEN] {
    let mut b = [0u8; IFINFOMSG_LEN];
    b[0] = libc::AF_UNSPEC as u8;
    b[2..4].copy_from_slice(&kind.to_le_bytes());
    b[4..8].copy_from_slice(&(index as i32).to_le_bytes());
    b[8..12].copy_from_slice(&flags.to_le_bytes());
    // `ifi_change` is 0xffffffff in a dump, which is what a reader ignores.
    b[12..16].copy_from_slice(&0u32.to_le_bytes());
    b
}

/// `struct ifaddrmsg`, as bytes.
pub(crate) fn ifaddrmsg(family: u8, prefixlen: u8, scope: u8, index: u32) -> [u8; IFADDRMSG_LEN] {
    let mut b = [0u8; IFADDRMSG_LEN];
    b[0] = family;
    b[1] = prefixlen;
    // Permanent: the host configured it and a guest cannot. Without the bit
    // every address reads as `dynamic` -- one with a lifetime, which will
    // expire.
    b[2] = IFA_F_PERMANENT;
    b[3] = scope;
    b[4..8].copy_from_slice(&index.to_le_bytes());
    b
}

/// The `NLMSG_DONE` that ends a dump.
///
/// A dump without one leaves a reader waiting: `NLM_F_MULTI` says "more
/// follows" and this is the only thing that says it does not.
pub fn done(out: &mut Vec<u8>, seq: u32, pid: u32) {
    let mut m = Message::new(out, NLMSG_DONE, NLM_F_MULTI, seq, pid);
    // The payload is an `int` of 0, which is what `NLMSG_DONE` carries.
    m.body(&0i32.to_le_bytes());
    m.finish(out);
}

/// An `NLMSG_ERROR`, which is how a netlink kernel refuses.
///
/// The payload is a **negative** errno and then the header of the message being
/// refused — a caller matches the sequence number in that copy, so leaving it
/// out makes the error look like it belongs to some other request. Zero is not
/// an error but an acknowledgement, which is what `NLM_F_ACK` asks for.
pub fn error(out: &mut Vec<u8>, err: i32, seq: u32, pid: u32, request: &[u8]) {
    let mut m = Message::new(out, NLMSG_ERROR, 0, seq, pid);
    let mut payload = Vec::with_capacity(4 + NLMSG_HDRLEN);
    payload.extend_from_slice(&(-err.abs()).to_le_bytes());
    let n = request.len().min(NLMSG_HDRLEN);
    payload.extend_from_slice(&request[..n]);
    payload.resize(4 + NLMSG_HDRLEN, 0);
    m.body(&payload);
    m.finish(out);
}

// ---------------------------------------------------------------- the decoder

/// One request, as much of it as this answers.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
    /// The whole header, for the copy an `NLMSG_ERROR` carries.
    pub header: [u8; NLMSG_HDRLEN],
    /// The first byte of the body, which for every request this answers is the
    /// **family** — `rtgenmsg`, `ifinfomsg` and `rtmsg` all start with one, and
    /// it is how `ip route` asks for v4 and `ip -6 route` for v6. 0 is
    /// `AF_UNSPEC`: everything.
    ///
    /// The first byte of [`Request::body`], named because every request this
    /// answers begins with one.
    pub family: u8,
    /// Everything after the header, bounded by the message's own length.
    ///
    /// Needed since `ip route get`, which carries the destination it is asking
    /// about as an `RTA_DST` attribute — a dump needs no more than the family
    /// byte, and a *query* needs what is being queried.
    pub body: Vec<u8>,
}

/// Every message in a buffer a guest sent.
///
/// A caller may batch several, and a length shorter than the header or longer
/// than what is left ends the walk — **not** an error, because a netlink kernel
/// ignores a malformed tail rather than refusing everything before it, and a
/// caller that sent one good message and a truncated one expects the first to
/// have been acted on.
pub fn parse(mut buf: &[u8]) -> Vec<Request> {
    let mut out = Vec::new();
    while buf.len() >= NLMSG_HDRLEN {
        let len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        if len < NLMSG_HDRLEN || len > buf.len() {
            break;
        }
        let mut header = [0u8; NLMSG_HDRLEN];
        header.copy_from_slice(&buf[..NLMSG_HDRLEN]);
        out.push(Request {
            kind: u16::from_le_bytes(buf[4..6].try_into().unwrap()),
            flags: u16::from_le_bytes(buf[6..8].try_into().unwrap()),
            seq: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            pid: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            header,
            // A request with no body at all asks for everything, which is what
            // a zero here means anyway.
            family: buf.get(NLMSG_HDRLEN).copied().unwrap_or(0),
            // `len`, not the buffer: a batch puts the next message straight
            // after this one, and taking the rest of the buffer would hand a
            // reader the message behind it as attributes.
            body: buf[NLMSG_HDRLEN..len].to_vec(),
        });
        let step = align4(len);
        if step >= buf.len() {
            break;
        }
        buf = &buf[step..];
    }
    out
}

//! In-memory Linux kernel keyring subsystem (`add_key`, `request_key`, `keyctl`).
//!
//! Keys and keyrings are scoped by thread, process, session, and user so that
//! credentials remain isolated across users and sessions.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use guest_errno::Errno;
use strace::strace;
use usercopy::GuestMem;

const KEY_SPEC_THREAD_KEYRING: i32 = -1;
const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
const KEY_SPEC_SESSION_KEYRING: i32 = -3;
const KEY_SPEC_USER_KEYRING: i32 = -4;
const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;

const KEYCTL_GET_KEYRING_ID: u32 = 0;
const KEYCTL_JOIN_SESSION_KEYRING: u32 = 1;
const KEYCTL_UPDATE: u32 = 2;
const KEYCTL_REVOKE: u32 = 3;
const KEYCTL_CHOWN: u32 = 4;
const KEYCTL_SETPERM: u32 = 5;
const KEYCTL_DESCRIBE: u32 = 6;
const KEYCTL_CLEAR: u32 = 7;
const KEYCTL_LINK: u32 = 8;
const KEYCTL_UNLINK: u32 = 9;
const KEYCTL_SEARCH: u32 = 10;
const KEYCTL_READ: u32 = 11;
const KEYCTL_SET_TIMEOUT: u32 = 15;
const KEYCTL_INVALIDATE: u32 = 21;

const KEY_POS_VIEW: u32 = 0x0100_0000;
const KEY_POS_READ: u32 = 0x0200_0000;
const KEY_POS_WRITE: u32 = 0x0400_0000;
const KEY_POS_SEARCH: u32 = 0x0800_0000;
const KEY_POS_LINK: u32 = 0x1000_0000;
const KEY_POS_SETATTR: u32 = 0x2000_0000;
const KEY_POS_ALL: u32 = 0x3f00_0000;

const KEY_USR_VIEW: u32 = 0x0001_0000;
const KEY_USR_READ: u32 = 0x0002_0000;
const KEY_USR_WRITE: u32 = 0x0004_0000;
const KEY_USR_SEARCH: u32 = 0x0008_0000;
const KEY_USR_LINK: u32 = 0x0010_0000;
const KEY_USR_SETATTR: u32 = 0x0020_0000;
const KEY_USR_ALL: u32 = 0x003f_0000;

const DEFAULT_KEY_PERM: u32 = KEY_POS_ALL | KEY_USR_ALL;
const MAX_KEY_PAYLOAD: usize = 1024 * 1024;
const MAX_KEY_COUNT: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PermKind {
    View,
    Read,
    Write,
    Search,
    Link,
    Setattr,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Scope {
    Thread(i32),
    Process(i32),
    Session(i32),
    User(u32),
    UserSession(u32),
}

#[derive(Clone)]
struct KeyEntry {
    serial: i32,
    key_type: String,
    description: String,
    payload: Vec<u8>,
    uid: u32,
    gid: u32,
    perm: u32,
    revoked: bool,
    expiry: Option<Instant>,
    children: Vec<i32>,
}

impl KeyEntry {
    fn is_keyring(&self) -> bool {
        self.key_type == "keyring"
    }

    fn is_expired(&self, now: Instant) -> bool {
        self.expiry.is_some_and(|exp| now >= exp)
    }
}

struct CredContext {
    tid: i32,
    tgid: i32,
    sid: i32,
    uid: u32,
    gid: u32,
    is_root: bool,
}

fn current_context() -> CredContext {
    let pids = kernel_pids::PidsGuard::take();
    if let Some(me) = pids.me() {
        let tid = me.pid();
        let tgid = me.tgid();
        let sid = me.group().map(|g| g.sid()).unwrap_or(tgid);
        let creds = me.creds();
        let uid = creds.fsuid();
        let gid = creds.fsgid();
        let is_root = uid == 0 || creds.capable(taskview::caps::CAP_SYS_ADMIN);
        CredContext {
            tid,
            tgid,
            sid,
            uid,
            gid,
            is_root,
        }
    } else {
        let tid = taskview::current_pid();
        let tgid = tid;
        CredContext {
            tid,
            tgid,
            sid: tgid,
            uid: 0,
            gid: 0,
            is_root: true,
        }
    }
}

struct KeyStore {
    next_serial: i32,
    keys: HashMap<i32, KeyEntry>,
    scopes: HashMap<Scope, i32>,
    named_sessions: HashMap<(u32, String), i32>,
    process_sessions: HashMap<i32, i32>,
}

impl KeyStore {
    fn new() -> Self {
        Self {
            next_serial: 1,
            keys: HashMap::new(),
            scopes: HashMap::new(),
            named_sessions: HashMap::new(),
            process_sessions: HashMap::new(),
        }
    }

    fn session_ring_id(&self, ctx: &CredContext) -> Option<i32> {
        if let Some(&id) = self.process_sessions.get(&ctx.tgid)
            && self.keys.contains_key(&id)
        {
            return Some(id);
        }
        self.scopes
            .get(&Scope::Session(ctx.sid))
            .copied()
            .filter(|id| self.keys.contains_key(id))
    }

    fn is_key_referenced(&self, id: i32) -> bool {
        self.scopes.values().any(|&v| v == id)
            || self.process_sessions.values().any(|&v| v == id)
            || self.named_sessions.values().any(|&v| v == id)
            || self.keys.values().any(|k| k.children.contains(&id))
    }

    fn reap_dead_scopes_with(
        &mut self,
        mut task_alive: impl FnMut(i32) -> bool,
        mut session_alive: impl FnMut(i32) -> bool,
    ) {
        let mut dead_roots = Vec::new();
        self.scopes.retain(|&scope, &mut ring_id| {
            let alive = match scope {
                Scope::Thread(tid) => task_alive(tid),
                Scope::Process(tgid) => task_alive(tgid),
                Scope::Session(sid) => session_alive(sid),
                Scope::User(_) | Scope::UserSession(_) => true,
            };
            if !alive {
                dead_roots.push(ring_id);
            }
            alive
        });
        self.process_sessions.retain(|&tgid, &mut ring_id| {
            let alive = task_alive(tgid);
            if !alive {
                dead_roots.push(ring_id);
            }
            alive
        });

        let mut candidates = Vec::new();
        for ring_id in dead_roots {
            if self.is_key_referenced(ring_id) {
                continue;
            }
            let is_auto_scope = self.keys.get(&ring_id).is_some_and(|e| {
                e.is_keyring()
                    && (e.description.starts_with("_tid.")
                        || e.description.starts_with("_pid.")
                        || e.description.starts_with("_ses."))
            });
            if is_auto_scope && let Some(removed) = self.keys.remove(&ring_id) {
                candidates.extend(removed.children);
            }
        }

        let mut seen_orphans = HashSet::new();
        while let Some(cid) = candidates.pop() {
            if !seen_orphans.insert(cid) || self.is_key_referenced(cid) {
                continue;
            }
            if let Some(removed) = self.keys.remove(&cid) {
                candidates.extend(removed.children);
            }
        }
    }

    fn reap_dead_scopes(&mut self) {
        if taskview::current().is_null() {
            return;
        }
        let pids = kernel_pids::PidsGuard::take();
        let held = pids.held();
        let mut dead_tasks = Vec::new();
        let mut dead_sessions = Vec::new();
        for &scope in self.scopes.keys() {
            match scope {
                Scope::Thread(tid) | Scope::Process(tid) => {
                    if kernel_pids::pidreg_task(held, tid).is_null() {
                        dead_tasks.push(tid);
                    }
                }
                Scope::Session(sid) => {
                    if kernel_pids::pidreg_session_len(held, sid) == 0 {
                        dead_sessions.push(sid);
                    }
                }
                Scope::User(_) | Scope::UserSession(_) => {}
            }
        }
        for &tgid in self.process_sessions.keys() {
            if kernel_pids::pidreg_task(held, tgid).is_null() {
                dead_tasks.push(tgid);
            }
        }
        drop(pids);
        if dead_tasks.is_empty() && dead_sessions.is_empty() {
            return;
        }
        let dead_task_set: HashSet<i32> = dead_tasks.into_iter().collect();
        let dead_session_set: HashSet<i32> = dead_sessions.into_iter().collect();
        self.reap_dead_scopes_with(
            |id| !dead_task_set.contains(&id),
            |sid| !dead_session_set.contains(&sid),
        );
    }

    fn prune_expired(&mut self) {
        let now = Instant::now();
        let expired: HashSet<i32> = self
            .keys
            .iter()
            .filter_map(|(&id, k)| k.is_expired(now).then_some(id))
            .collect();
        if expired.is_empty() {
            return;
        }
        self.keys.retain(|id, _| !expired.contains(id));
        for k in self.keys.values_mut() {
            k.children.retain(|cid| !expired.contains(cid));
        }
        self.scopes.retain(|_, v| !expired.contains(v));
        self.named_sessions.retain(|_, v| !expired.contains(v));
        self.process_sessions.retain(|_, v| !expired.contains(v));
    }

    fn invalidate_id(&mut self, id: i32) {
        self.keys.remove(&id);
        for k in self.keys.values_mut() {
            k.children.retain(|&c| c != id);
        }
        self.scopes.retain(|_, &mut v| v != id);
        self.named_sessions.retain(|_, &mut v| v != id);
        self.process_sessions.retain(|_, &mut v| v != id);
    }

    fn join_named_session(&mut self, name: &str, ctx: &CredContext) -> Result<i32, Errno> {
        let key = (ctx.uid, name.to_string());
        if let Some(&existing) = self.named_sessions.get(&key) {
            let live_entry = self.keys.get(&existing).and_then(|entry| {
                (entry.is_keyring() && !entry.revoked && !entry.is_expired(Instant::now()))
                    .then(|| entry.clone())
            });
            if let Some(entry) = live_entry {
                self.check_perm(&entry, ctx, PermKind::Search)?;
                self.process_sessions.insert(ctx.tgid, existing);
                return Ok(existing);
            }
            if self
                .keys
                .get(&existing)
                .is_some_and(|entry| entry.is_expired(Instant::now()))
            {
                self.invalidate_id(existing);
            } else {
                self.named_sessions.remove(&key);
            }
        }
        let serial = self.alloc_serial()?;
        self.keys.insert(
            serial,
            KeyEntry {
                serial,
                key_type: "keyring".to_string(),
                description: name.to_string(),
                payload: Vec::new(),
                uid: ctx.uid,
                gid: ctx.gid,
                perm: DEFAULT_KEY_PERM,
                revoked: false,
                expiry: None,
                children: Vec::new(),
            },
        );
        self.process_sessions.insert(ctx.tgid, serial);
        self.named_sessions.insert(key, serial);
        Ok(serial)
    }

    fn alloc_serial(&mut self) -> Result<i32, Errno> {
        self.reap_dead_scopes();
        if self.keys.len() >= MAX_KEY_COUNT {
            self.prune_expired();
        }
        if self.keys.len() >= MAX_KEY_COUNT {
            return Err(Errno::EDQUOT);
        }
        loop {
            let id = self.next_serial;
            self.next_serial = self.next_serial.checked_add(1).unwrap_or(1);
            if !self.keys.contains_key(&id) {
                return Ok(id);
            }
        }
    }

    fn get_or_create_scope(&mut self, scope: Scope, create: bool, ctx: &CredContext) -> Result<i32, Errno> {
        if let Some(&id) = self.scopes.get(&scope)
            && self.keys.contains_key(&id)
        {
            return Ok(id);
        }
        if !create {
            return Err(Errno::ENOKEY);
        }
        let desc = match scope {
            Scope::Thread(tid) => format!("_tid.{tid}"),
            Scope::Process(pid) => format!("_pid.{pid}"),
            Scope::Session(sid) => format!("_ses.{sid}"),
            Scope::User(uid) => format!("_uid.{uid}"),
            Scope::UserSession(uid) => format!("_uid_ses.{uid}"),
        };
        let serial = self.alloc_serial()?;
        self.keys.insert(
            serial,
            KeyEntry {
                serial,
                key_type: "keyring".to_string(),
                description: desc,
                payload: Vec::new(),
                uid: ctx.uid,
                gid: ctx.gid,
                perm: DEFAULT_KEY_PERM,
                revoked: false,
                expiry: None,
                children: Vec::new(),
            },
        );
        self.scopes.insert(scope, serial);
        Ok(serial)
    }

    fn resolve_ring_id(&mut self, id: i32, create: bool, ctx: &CredContext) -> Result<i32, Errno> {
        match id {
            KEY_SPEC_THREAD_KEYRING => self.get_or_create_scope(Scope::Thread(ctx.tid), create, ctx),
            KEY_SPEC_PROCESS_KEYRING => self.get_or_create_scope(Scope::Process(ctx.tgid), create, ctx),
            KEY_SPEC_SESSION_KEYRING => {
                if let Some(&id) = self.process_sessions.get(&ctx.tgid)
                    && self.keys.contains_key(&id)
                {
                    return Ok(id);
                }
                self.get_or_create_scope(Scope::Session(ctx.sid), create, ctx)
            }
            KEY_SPEC_USER_KEYRING => self.get_or_create_scope(Scope::User(ctx.uid), create, ctx),
            KEY_SPEC_USER_SESSION_KEYRING => {
                self.get_or_create_scope(Scope::UserSession(ctx.uid), create, ctx)
            }
            n if n > 0 => {
                if self.keys.contains_key(&n) {
                    Ok(n)
                } else {
                    Err(Errno::ENOKEY)
                }
            }
            _ => Err(Errno::ENOKEY),
        }
    }

    fn is_possessed(&self, target: i32, ctx: &CredContext) -> bool {
        let ring_ids = [
            self.scopes.get(&Scope::Thread(ctx.tid)).copied(),
            self.scopes.get(&Scope::Process(ctx.tgid)).copied(),
            self.session_ring_id(ctx),
            self.scopes.get(&Scope::User(ctx.uid)).copied(),
            self.scopes.get(&Scope::UserSession(ctx.uid)).copied(),
        ];
        for ring_id in ring_ids.into_iter().flatten() {
            if ring_id == target || self.search_ring_contains(ring_id, target, 0) {
                return true;
            }
        }
        false
    }

    fn search_ring_contains(&self, ring_id: i32, target: i32, depth: usize) -> bool {
        if depth > 8 {
            return false;
        }
        let Some(ring) = self.keys.get(&ring_id) else {
            return false;
        };
        if !ring.is_keyring() {
            return false;
        }
        for &child in &ring.children {
            if child == target || self.search_ring_contains(child, target, depth + 1) {
                return true;
            }
        }
        false
    }

    fn check_perm(&self, entry: &KeyEntry, ctx: &CredContext, kind: PermKind) -> Result<(), Errno> {
        let now = Instant::now();
        if entry.revoked {
            return Err(Errno::EKEYREVOKED);
        }
        if entry.is_expired(now) {
            return Err(Errno::EKEYEXPIRED);
        }
        if ctx.is_root {
            return Ok(());
        }
        let possessed = self.is_possessed(entry.serial, ctx);
        let (pos_bit, usr_bit, grp_bit, oth_bit) = match kind {
            PermKind::View => (KEY_POS_VIEW, KEY_USR_VIEW, KEY_USR_VIEW >> 8, KEY_USR_VIEW >> 16),
            PermKind::Read => (KEY_POS_READ, KEY_USR_READ, KEY_USR_READ >> 8, KEY_USR_READ >> 16),
            PermKind::Write => (KEY_POS_WRITE, KEY_USR_WRITE, KEY_USR_WRITE >> 8, KEY_USR_WRITE >> 16),
            PermKind::Search => (
                KEY_POS_SEARCH,
                KEY_USR_SEARCH,
                KEY_USR_SEARCH >> 8,
                KEY_USR_SEARCH >> 16,
            ),
            PermKind::Link => (KEY_POS_LINK, KEY_USR_LINK, KEY_USR_LINK >> 8, KEY_USR_LINK >> 16),
            PermKind::Setattr => (
                KEY_POS_SETATTR,
                KEY_USR_SETATTR,
                KEY_USR_SETATTR >> 8,
                KEY_USR_SETATTR >> 16,
            ),
        };
        let mask = entry.perm;
        let allowed = (possessed && (mask & pos_bit != 0))
            || (entry.uid == ctx.uid && (mask & usr_bit != 0))
            || (entry.gid == ctx.gid && (mask & grp_bit != 0))
            || (mask & oth_bit != 0);
        if allowed {
            Ok(())
        } else {
            Err(Errno::EACCES)
        }
    }

    fn search_in_ring(
        &self,
        ring_id: i32,
        key_type: &str,
        desc: &str,
        ctx: &CredContext,
        depth: usize,
    ) -> Option<i32> {
        if depth > 8 {
            return None;
        }
        let ring = self.keys.get(&ring_id)?;
        if !ring.is_keyring() || self.check_perm(ring, ctx, PermKind::Search).is_err() {
            return None;
        }
        for &child_id in &ring.children {
            let Some(child) = self.keys.get(&child_id) else {
                continue;
            };
            if child.key_type == key_type
                && child.description == desc
                && self.check_perm(child, ctx, PermKind::Search).is_ok()
            {
                return Some(child_id);
            }
            if child.is_keyring()
                && let Some(found) = self.search_in_ring(child_id, key_type, desc, ctx, depth + 1)
            {
                return Some(found);
            }
        }
        None
    }

    fn reaches_ring(&self, start_id: i32, target_id: i32, depth: usize) -> bool {
        if start_id == target_id {
            return true;
        }
        if depth >= 16 {
            return false;
        }
        let Some(entry) = self.keys.get(&start_id) else {
            return false;
        };
        if !entry.is_keyring() {
            return false;
        }
        entry
            .children
            .iter()
            .any(|&child| self.reaches_ring(child, target_id, depth + 1))
    }

    fn link_child(&mut self, ring_id: i32, key_id: i32) -> Result<(), Errno> {
        if !self.keys.get(&ring_id).is_some_and(KeyEntry::is_keyring) {
            return Err(if self.keys.contains_key(&ring_id) {
                Errno::ENOTDIR
            } else {
                Errno::ENOKEY
            });
        }
        if self.reaches_ring(key_id, ring_id, 0) {
            return Err(Errno::EDEADLK);
        }
        let ring = self.keys.get_mut(&ring_id).ok_or(Errno::ENOKEY)?;
        if !ring.children.contains(&key_id) {
            ring.children.push(key_id);
        }
        Ok(())
    }

    fn unlink_child(&mut self, ring_id: i32, key_id: i32) -> Result<(), Errno> {
        let Some(ring) = self.keys.get_mut(&ring_id) else {
            return Err(Errno::ENOKEY);
        };
        if !ring.is_keyring() {
            return Err(Errno::ENOTDIR);
        }
        if let Some(pos) = ring.children.iter().position(|&id| id == key_id) {
            ring.children.remove(pos);
            Ok(())
        } else {
            Err(Errno::ENOKEY)
        }
    }
}

fn store() -> &'static Mutex<KeyStore> {
    static STORE: OnceLock<Mutex<KeyStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(KeyStore::new()))
}

fn read_cstr(addr: u64, max_len: usize) -> Result<String, Errno> {
    if addr == 0 {
        return Err(Errno::EFAULT);
    }
    let mut buf = vec![0u8; max_len + 1];
    match GuestMem::current().read_string(addr, &mut buf) {
        Ok(n) => Ok(String::from_utf8_lossy(&buf[..n]).into_owned()),
        Err(e) if e == guest_errno::c_int_::ENAMETOOLONG => Err(Errno::EINVAL),
        Err(_) => Err(Errno::EFAULT),
    }
}

fn read_payload(addr: u64, plen: usize) -> Result<Vec<u8>, Errno> {
    if plen > MAX_KEY_PAYLOAD {
        return Err(Errno::EINVAL);
    }
    if plen == 0 {
        return Ok(Vec::new());
    }
    if addr == 0 {
        return Err(Errno::EFAULT);
    }
    let mut data = vec![0u8; plen];
    if GuestMem::current().read(addr, &mut data) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(data)
}

fn validate_key_type(key_type: &str) -> Result<(), Errno> {
    match key_type {
        "user" | "logon" | "keyring" | "big_key" => Ok(()),
        "" => Err(Errno::EINVAL),
        _ => Err(Errno::ENODEV),
    }
}

pub fn sys_add_key(
    type_addr: u64,
    desc_addr: u64,
    payload_addr: u64,
    plen: u64,
    ringid: i32,
) -> Result<i64, Errno> {
    let key_type = read_cstr(type_addr, 32)?;
    let desc = read_cstr(desc_addr, 4096)?;
    strace!("add_key({key_type:?}, {desc:?}, {payload_addr:#x}, {plen}, {ringid})");
    validate_key_type(&key_type)?;
    if desc.is_empty() {
        return Err(Errno::EINVAL);
    }
    let plen_usize = usize::try_from(plen).map_err(|_| Errno::EINVAL)?;
    if key_type == "keyring" && plen_usize != 0 {
        return Err(Errno::EINVAL);
    }
    let payload = read_payload(payload_addr, plen_usize)?;

    let ctx = current_context();
    let mut ks = store().lock().map_err(|_| Errno::EIO)?;
    let target_ring = ks.resolve_ring_id(ringid, true, &ctx)?;
    let ring = ks.keys.get(&target_ring).ok_or(Errno::ENOKEY)?.clone();
    if !ring.is_keyring() {
        return Err(Errno::ENOTDIR);
    }
    ks.check_perm(&ring, &ctx, PermKind::Write)?;

    for &child_id in &ring.children {
        if let Some(existing) = ks.keys.get(&child_id)
            && existing.key_type == key_type
            && existing.description == desc
        {
            let existing_clone = existing.clone();
            ks.check_perm(&existing_clone, &ctx, PermKind::Write)?;
            if let Some(entry) = ks.keys.get_mut(&child_id)
                && !entry.is_keyring()
            {
                entry.payload = payload;
                entry.expiry = None;
            }
            return Ok(i64::from(child_id));
        }
    }

    let serial = ks.alloc_serial()?;
    ks.keys.insert(
        serial,
        KeyEntry {
            serial,
            key_type,
            description: desc,
            payload,
            uid: ctx.uid,
            gid: ctx.gid,
            perm: DEFAULT_KEY_PERM,
            revoked: false,
            expiry: None,
            children: Vec::new(),
        },
    );
    ks.link_child(target_ring, serial)?;
    Ok(i64::from(serial))
}

pub fn sys_request_key(
    type_addr: u64,
    desc_addr: u64,
    _callout_addr: u64,
    dest_ringid: i32,
) -> Result<i64, Errno> {
    let key_type = read_cstr(type_addr, 32)?;
    let desc = read_cstr(desc_addr, 4096)?;
    strace!("request_key({key_type:?}, {desc:?}, {dest_ringid})");
    validate_key_type(&key_type)?;
    if desc.is_empty() {
        return Err(Errno::EINVAL);
    }

    let ctx = current_context();
    let mut ks = store().lock().map_err(|_| Errno::EIO)?;
    let search_rings = [
        ks.scopes.get(&Scope::Thread(ctx.tid)).copied(),
        ks.scopes.get(&Scope::Process(ctx.tgid)).copied(),
        ks.session_ring_id(&ctx),
        ks.scopes.get(&Scope::User(ctx.uid)).copied(),
        ks.scopes.get(&Scope::UserSession(ctx.uid)).copied(),
    ];
    let mut found = None;
    for ring_id in search_rings.into_iter().flatten() {
        if let Some(id) = ks.search_in_ring(ring_id, &key_type, &desc, &ctx, 0) {
            found = Some(id);
            break;
        }
    }
    let key_id = found.ok_or(Errno::ENOKEY)?;
    if dest_ringid != 0 {
        let dest = ks.resolve_ring_id(dest_ringid, true, &ctx)?;
        let dest_entry = ks.keys.get(&dest).ok_or(Errno::ENOKEY)?.clone();
        ks.check_perm(&dest_entry, &ctx, PermKind::Write)?;
        ks.link_child(dest, key_id)?;
    }
    Ok(i64::from(key_id))
}

pub fn sys_keyctl(cmd: u32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<i64, Errno> {
    strace!("keyctl({cmd}, {arg2:#x}, {arg3:#x}, {arg4:#x}, {arg5:#x})");
    let ctx = current_context();
    let mut ks = store().lock().map_err(|_| Errno::EIO)?;

    match cmd {
        KEYCTL_GET_KEYRING_ID => {
            let id = arg2 as i32;
            let create = arg3 != 0;
            let resolved = ks.resolve_ring_id(id, create, &ctx)?;
            Ok(i64::from(resolved))
        }
        KEYCTL_JOIN_SESSION_KEYRING => {
            if arg2 != 0 {
                let s = read_cstr(arg2, 4096)?;
                if s.is_empty() {
                    return Err(Errno::EINVAL);
                }
                return ks.join_named_session(&s, &ctx).map(i64::from);
            }
            let serial = ks.alloc_serial()?;
            let desc = format!("_ses.{}", ctx.tgid);
            ks.keys.insert(
                serial,
                KeyEntry {
                    serial,
                    key_type: "keyring".to_string(),
                    description: desc,
                    payload: Vec::new(),
                    uid: ctx.uid,
                    gid: ctx.gid,
                    perm: DEFAULT_KEY_PERM,
                    revoked: false,
                    expiry: None,
                    children: Vec::new(),
                },
            );
            ks.process_sessions.insert(ctx.tgid, serial);
            Ok(i64::from(serial))
        }
        KEYCTL_UPDATE => {
            let id = ks.resolve_ring_id(arg2 as i32, false, &ctx)?;
            let plen = usize::try_from(arg4).map_err(|_| Errno::EINVAL)?;
            let entry = ks.keys.get(&id).ok_or(Errno::ENOKEY)?.clone();
            if entry.is_keyring() {
                return Err(Errno::EOPNOTSUPP);
            }
            ks.check_perm(&entry, &ctx, PermKind::Write)?;
            let payload = read_payload(arg3, plen)?;
            if let Some(e) = ks.keys.get_mut(&id) {
                e.payload = payload;
            }
            Ok(0)
        }
        KEYCTL_REVOKE => {
            let id = ks.resolve_ring_id(arg2 as i32, false, &ctx)?;
            let entry = ks.keys.get(&id).ok_or(Errno::ENOKEY)?.clone();
            ks.check_perm(&entry, &ctx, PermKind::Write)?;
            if let Some(e) = ks.keys.get_mut(&id) {
                e.revoked = true;
            }
            Ok(0)
        }
        KEYCTL_CHOWN => {
            let id = ks.resolve_ring_id(arg2 as i32, false, &ctx)?;
            let new_uid = arg3 as i32;
            let new_gid = arg4 as i32;
            let entry = ks.keys.get(&id).ok_or(Errno::ENOKEY)?.clone();
            ks.check_perm(&entry, &ctx, PermKind::Setattr)?;
            if !ctx.is_root && ((new_uid != -1 && new_uid as u32 != ctx.uid) || (new_gid != -1 && new_gid as u32 != ctx.gid)) {
                return Err(Errno::EACCES);
            }
            if let Some(e) = ks.keys.get_mut(&id) {
                if new_uid != -1 {
                    e.uid = new_uid as u32;
                }
                if new_gid != -1 {
                    e.gid = new_gid as u32;
                }
            }
            Ok(0)
        }
        KEYCTL_SETPERM => {
            let id = ks.resolve_ring_id(arg2 as i32, false, &ctx)?;
            let perm = arg3 as u32;
            if perm & !0x3f3f_3f3f != 0 {
                return Err(Errno::EINVAL);
            }
            let entry = ks.keys.get(&id).ok_or(Errno::ENOKEY)?.clone();
            ks.check_perm(&entry, &ctx, PermKind::Setattr)?;
            if let Some(e) = ks.keys.get_mut(&id) {
                e.perm = perm;
            }
            Ok(0)
        }
        KEYCTL_DESCRIBE => {
            let id = ks.resolve_ring_id(arg2 as i32, false, &ctx)?;
            let entry = ks.keys.get(&id).ok_or(Errno::ENOKEY)?;
            ks.check_perm(entry, &ctx, PermKind::View)?;
            let desc = format!(
                "{};{};{};{:08x};{}\0",
                entry.key_type, entry.uid, entry.gid, entry.perm, entry.description
            );
            let bytes = desc.as_bytes();
            let buflen = usize::try_from(arg4).unwrap_or(usize::MAX);
            if arg3 != 0 && buflen > 0 {
                let copy = bytes.len().min(buflen);
                if GuestMem::current().write(arg3, &bytes[..copy]) != 0 {
                    return Err(Errno::EFAULT);
                }
            }
            Ok(bytes.len() as i64)
        }
        KEYCTL_CLEAR => {
            let id = ks.resolve_ring_id(arg2 as i32, false, &ctx)?;
            let entry = ks.keys.get(&id).ok_or(Errno::ENOKEY)?.clone();
            if !entry.is_keyring() {
                return Err(Errno::ENOTDIR);
            }
            ks.check_perm(&entry, &ctx, PermKind::Write)?;
            if let Some(e) = ks.keys.get_mut(&id) {
                e.children.clear();
            }
            Ok(0)
        }
        KEYCTL_LINK => {
            let key_id = ks.resolve_ring_id(arg2 as i32, false, &ctx)?;
            let ring_id = ks.resolve_ring_id(arg3 as i32, true, &ctx)?;
            let key = ks.keys.get(&key_id).ok_or(Errno::ENOKEY)?.clone();
            let ring = ks.keys.get(&ring_id).ok_or(Errno::ENOKEY)?.clone();
            ks.check_perm(&key, &ctx, PermKind::Link)?;
            ks.check_perm(&ring, &ctx, PermKind::Write)?;
            ks.link_child(ring_id, key_id)?;
            Ok(0)
        }
        KEYCTL_UNLINK => {
            let key_id = ks.resolve_ring_id(arg2 as i32, false, &ctx)?;
            let ring_id = ks.resolve_ring_id(arg3 as i32, false, &ctx)?;
            let ring = ks.keys.get(&ring_id).ok_or(Errno::ENOKEY)?.clone();
            ks.check_perm(&ring, &ctx, PermKind::Write)?;
            ks.unlink_child(ring_id, key_id)?;
            Ok(0)
        }
        KEYCTL_SEARCH => {
            let ring_id = ks.resolve_ring_id(arg2 as i32, false, &ctx)?;
            let key_type = read_cstr(arg3, 32)?;
            let desc = read_cstr(arg4, 4096)?;
            validate_key_type(&key_type)?;
            let found = ks
                .search_in_ring(ring_id, &key_type, &desc, &ctx, 0)
                .ok_or(Errno::ENOKEY)?;
            let dest_ringid = arg5 as i32;
            if dest_ringid != 0 {
                let dest = ks.resolve_ring_id(dest_ringid, true, &ctx)?;
                let dest_entry = ks.keys.get(&dest).ok_or(Errno::ENOKEY)?.clone();
                ks.check_perm(&dest_entry, &ctx, PermKind::Write)?;
                ks.link_child(dest, found)?;
            }
            Ok(i64::from(found))
        }
        KEYCTL_READ => {
            let id = ks.resolve_ring_id(arg2 as i32, false, &ctx)?;
            let entry = ks.keys.get(&id).ok_or(Errno::ENOKEY)?;
            ks.check_perm(entry, &ctx, PermKind::Read)?;
            let data: Vec<u8> = if entry.is_keyring() {
                entry
                    .children
                    .iter()
                    .flat_map(|c| c.to_le_bytes())
                    .collect()
            } else {
                entry.payload.clone()
            };
            let buflen = usize::try_from(arg4).unwrap_or(usize::MAX);
            if arg3 != 0 && buflen > 0 && !data.is_empty() {
                let copy = data.len().min(buflen);
                if GuestMem::current().write(arg3, &data[..copy]) != 0 {
                    return Err(Errno::EFAULT);
                }
            }
            Ok(data.len() as i64)
        }
        KEYCTL_SET_TIMEOUT => {
            let id = ks.resolve_ring_id(arg2 as i32, false, &ctx)?;
            let entry = ks.keys.get(&id).ok_or(Errno::ENOKEY)?.clone();
            ks.check_perm(&entry, &ctx, PermKind::Setattr)?;
            let secs = arg3;
            if let Some(e) = ks.keys.get_mut(&id) {
                e.expiry = if secs == 0 {
                    None
                } else {
                    Instant::now().checked_add(Duration::from_secs(secs))
                };
            }
            Ok(0)
        }
        KEYCTL_INVALIDATE => {
            let id = ks.resolve_ring_id(arg2 as i32, false, &ctx)?;
            let entry = ks.keys.get(&id).ok_or(Errno::ENOKEY)?.clone();
            ks.check_perm(&entry, &ctx, PermKind::Search)?;
            ks.invalidate_id(id);
            Ok(0)
        }
        _ => Err(Errno::EOPNOTSUPP),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_store_isolates_scopes_and_permissions() {
        let mut ks = KeyStore::new();
        let root_ctx = CredContext {
            tid: 1,
            tgid: 1,
            sid: 1,
            uid: 0,
            gid: 0,
            is_root: true,
        };
        let user_ctx = CredContext {
            tid: 2,
            tgid: 2,
            sid: 2,
            uid: 1000,
            gid: 1000,
            is_root: false,
        };

        let root_ring = ks
            .resolve_ring_id(KEY_SPEC_USER_KEYRING, true, &root_ctx)
            .unwrap();
        let user_ring = ks
            .resolve_ring_id(KEY_SPEC_USER_KEYRING, true, &user_ctx)
            .unwrap();
        assert_ne!(root_ring, user_ring);

        let key_serial = ks.alloc_serial().unwrap();
        ks.keys.insert(
            key_serial,
            KeyEntry {
                serial: key_serial,
                key_type: "user".to_string(),
                description: "secret".to_string(),
                payload: b"topsecret".to_vec(),
                uid: 0,
                gid: 0,
                perm: KEY_USR_ALL,
                revoked: false,
                expiry: None,
                children: Vec::new(),
            },
        );
        ks.link_child(root_ring, key_serial).unwrap();

        assert_eq!(
            ks.search_in_ring(user_ring, "user", "secret", &user_ctx, 0),
            None
        );
        let entry = ks.keys.get(&key_serial).unwrap();
        assert_eq!(
            ks.check_perm(entry, &user_ctx, PermKind::Read),
            Err(Errno::EACCES)
        );
        assert_eq!(ks.check_perm(entry, &root_ctx, PermKind::Read), Ok(()));
    }

    #[test]
    fn joined_session_keyring_overrides_possession_and_clears_on_invalidate() {
        let mut ks = KeyStore::new();
        let owner_ctx = CredContext {
            tid: 10,
            tgid: 10,
            sid: 10,
            uid: 1000,
            gid: 1000,
            is_root: false,
        };
        let other_ctx = CredContext {
            tid: 20,
            tgid: 20,
            sid: 10,
            uid: 1001,
            gid: 1001,
            is_root: false,
        };

        let sid_ring = ks
            .resolve_ring_id(KEY_SPEC_SESSION_KEYRING, true, &owner_ctx)
            .unwrap();
        let sid_key = ks.alloc_serial().unwrap();
        ks.keys.insert(
            sid_key,
            KeyEntry {
                serial: sid_key,
                key_type: "user".to_string(),
                description: "old-sid-key".to_string(),
                payload: b"old".to_vec(),
                uid: 1000,
                gid: 1000,
                perm: KEY_POS_ALL,
                revoked: false,
                expiry: None,
                children: Vec::new(),
            },
        );
        ks.link_child(sid_ring, sid_key).unwrap();

        let joined_ring = ks.alloc_serial().unwrap();
        ks.keys.insert(
            joined_ring,
            KeyEntry {
                serial: joined_ring,
                key_type: "keyring".to_string(),
                description: "_ses.20".to_string(),
                payload: Vec::new(),
                uid: 1001,
                gid: 1001,
                perm: DEFAULT_KEY_PERM,
                revoked: false,
                expiry: None,
                children: Vec::new(),
            },
        );
        let joined_key = ks.alloc_serial().unwrap();
        ks.keys.insert(
            joined_key,
            KeyEntry {
                serial: joined_key,
                key_type: "user".to_string(),
                description: "joined-key".to_string(),
                payload: b"new".to_vec(),
                uid: 1000,
                gid: 1000,
                perm: KEY_POS_ALL,
                revoked: false,
                expiry: None,
                children: Vec::new(),
            },
        );
        ks.link_child(joined_ring, joined_key).unwrap();
        ks.process_sessions.insert(other_ctx.tgid, joined_ring);

        assert!(ks.is_possessed(joined_key, &other_ctx));
        assert!(!ks.is_possessed(sid_key, &other_ctx));
        assert_eq!(
            ks.check_perm(ks.keys.get(&joined_key).unwrap(), &other_ctx, PermKind::Read),
            Ok(())
        );
        assert_eq!(
            ks.check_perm(ks.keys.get(&sid_key).unwrap(), &other_ctx, PermKind::Read),
            Err(Errno::EACCES)
        );
        assert_eq!(
            ks.session_ring_id(&other_ctx).and_then(|r| ks.search_in_ring(r, "user", "joined-key", &other_ctx, 0)),
            Some(joined_key)
        );

        ks.invalidate_id(joined_ring);
        assert!(!ks.process_sessions.contains_key(&other_ctx.tgid));
        assert_eq!(ks.resolve_ring_id(KEY_SPEC_SESSION_KEYRING, false, &other_ctx), Ok(sid_ring));

        ks.reap_dead_scopes_with(|_| false, |_| false);
        assert!(!ks.keys.contains_key(&sid_ring));
        assert!(!ks.keys.contains_key(&sid_key));
    }

    #[test]
    fn named_session_keyring_skips_revoked_expired_and_checks_perm() {
        let mut ks = KeyStore::new();
        let ctx1 = CredContext {
            tid: 30,
            tgid: 30,
            sid: 30,
            uid: 1000,
            gid: 1000,
            is_root: false,
        };
        let ctx2 = CredContext {
            tid: 31,
            tgid: 31,
            sid: 31,
            uid: 1000,
            gid: 1000,
            is_root: false,
        };

        let first = ks.join_named_session("app-ses", &ctx1).unwrap();
        assert_eq!(ks.join_named_session("app-ses", &ctx2), Ok(first));

        // Revoked keyring must not be rejoined; a fresh one is allocated.
        ks.keys.get_mut(&first).unwrap().revoked = true;
        let second = ks.join_named_session("app-ses", &ctx2).unwrap();
        assert_ne!(second, first);

        // Expired keyring must not be rejoined and is invalidated.
        ks.keys.get_mut(&second).unwrap().expiry =
            Some(Instant::now() - std::time::Duration::from_secs(1));
        let third = ks.join_named_session("app-ses", &ctx2).unwrap();
        assert_ne!(third, second);
        assert!(!ks.keys.contains_key(&second));

        // Live named session keyring without Search permission denies join.
        ks.keys.get_mut(&third).unwrap().perm = 0;
        ks.process_sessions.remove(&ctx1.tgid);
        assert_eq!(ks.join_named_session("app-ses", &ctx1), Err(Errno::EACCES));
    }
}

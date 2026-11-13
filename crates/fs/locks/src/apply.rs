//! POSIX lock-set transformations.

use std::cmp::Ordering;

use super::{Applied, Kind, Owner, Record, Set};

impl Set {
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The first lock that would prevent `request` from being granted.
    pub fn conflict(&self, request: &Record) -> Option<&Record> {
        self.records.iter().find(|held| held.conflicts(request))
    }

    /// Take, downgrade or drop a lock.
    ///
    /// `kind` of `None` is `F_UNLCK`, which never conflicts and never fails.
    pub fn apply(&mut self, request: &Record, kind: Option<Kind>) -> Applied {
        if kind.is_some() && self.conflict(request).is_some() {
            return Applied::Blocked;
        }

        let mut released = false;
        let mut split = Vec::new();
        // Only this owner's locks are affected: another owner's are either
        // compatible or would have been caught as a conflict above.
        self.records.retain_mut(|held| {
            if held.owner != request.owner || !held.overlaps(request) {
                return true;
            }
            if Some(held.kind) == kind {
                // Same type. Left alone here and absorbed by the merge below,
                // which is where the range it covers is taken account of —
                // dropping it here instead would shrink a lock the request
                // sits inside of, turning "lock byte 0" on a file already
                // locked whole into a lock on byte 0 alone.
                return true;
            }
            // A different type replaces the old one over the overlap, so some
            // region is losing the lock it had.
            released = true;
            match (held.start < request.start, held.end > request.end) {
                // The held lock sticks out at both ends: keep the head here
                // and remember the tail.
                (true, true) => {
                    split.push(Record {
                        start: request.end + 1,
                        ..*held
                    });
                    held.end = request.start - 1;
                    true
                }
                (true, false) => {
                    held.end = request.start - 1;
                    true
                }
                (false, true) => {
                    held.start = request.end + 1;
                    true
                }
                // Entirely covered.
                (false, false) => false,
            }
        });
        self.records.append(&mut split);

        if let Some(kind) = kind {
            // Absorb this owner's touching locks of the same type, so the set
            // does not grow one entry per call for a file being locked a
            // record at a time.
            //
            // Repeated to a fixed point rather than done in one pass: absorbing
            // a lock extends the range, and the extended range may now touch
            // one that an earlier pass walked past. The sets here hold a
            // handful of records, so this converges immediately; getting it
            // wrong would leave two records that should have been one, and the
            // set would grow without bound for a file locked a record at a
            // time in descending order.
            let mut merged = Record { kind, ..*request };
            loop {
                let before = self.records.len();
                self.records.retain(|held| {
                    if held.owner != request.owner || held.kind != kind {
                        return true;
                    }
                    if !held.overlaps(&merged) && !held.adjacent(&merged) {
                        return true;
                    }
                    merged.start = merged.start.min(held.start);
                    merged.end = merged.end.max(held.end);
                    false
                });
                if self.records.len() == before {
                    break;
                }
            }
            self.records.push(merged);
        }

        // Kept sorted so that `conflict` reports the lowest-addressed
        // conflicting lock, which is what F_GETLK is expected to describe.
        self.records.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| a.owner.cmp(&b.owner))
                .then(Ordering::Equal)
        });
        Applied::Granted { released }
    }

    /// Every record, lowest-addressed first.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Drop everything held by one owner. Returns true if anything went.
    pub fn remove_owner(&mut self, owner: Owner) -> bool {
        let before = self.records.len();
        self.records.retain(|held| held.owner != owner);
        self.records.len() != before
    }
}

//! Pure memfd flag, seal, mapping, and size rules.

use super::*;

// ---------------------------------------------------------------- the rules
//
// Pure, and tested below, because each is a place a program's expectations can
// be got wrong quietly.

/// `memfd_create`'s flag check. `Ok(())` or the errno.
pub(crate) fn flags_ok(flags: u32) -> Result<(), Errno> {
    let allowed = if flags & mfd::HUGETLB != 0 {
        mfd::ALL | mfd::HUGE_MASK
    } else {
        mfd::ALL
    };
    if flags & !allowed != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & mfd::EXEC != 0 && flags & mfd::NOEXEC_SEAL != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// The seals a fresh memfd starts with. Sealing is only possible when asked
/// for, and `MFD_NOEXEC_SEAL` both asks for it and applies `F_SEAL_EXEC`.
pub(crate) fn initial_seals(flags: u32) -> u32 {
    let mut seals = 0;
    if flags & (mfd::ALLOW_SEALING | mfd::NOEXEC_SEAL) == 0 {
        seals |= seal::SEAL;
    }
    if flags & mfd::NOEXEC_SEAL != 0 {
        seals |= seal::EXEC;
    }
    seals
}

/// The file mode a fresh memfd has: every bit, less execute under
/// `MFD_NOEXEC_SEAL`.
pub(crate) fn initial_mode(flags: u32) -> u32 {
    if flags & mfd::NOEXEC_SEAL != 0 {
        0o666
    } else {
        0o777
    }
}

/// `F_ADD_SEALS`: the new seal set, or the errno. Linux's order: an unknown
/// seal is `EINVAL`, a sealed set is `EPERM`, and `F_SEAL_WRITE` is `EBUSY`
/// while a shared mapping exists. `F_SEAL_EXEC` on an executable file brings
/// the four write seals with it -- W^X from the start, `memfd_add_seals`'s
/// comment -- which is why `executable` is an input. The mode itself is not
/// changed; what the seal stops is a later `chmod` of the execute bits.
pub fn add_seals(
    current: u32,
    adding: u32,
    executable: bool,
    shared_maps: u32,
) -> Result<u32, Errno> {
    if adding & !seal::ALL != 0 {
        return Err(Errno::EINVAL);
    }
    if current & seal::SEAL != 0 {
        return Err(Errno::EPERM);
    }
    let mut adding = adding;
    if adding & seal::EXEC != 0 && executable {
        adding |= seal::SHRINK | seal::GROW | seal::WRITE | seal::FUTURE_WRITE;
    }
    if adding & seal::WRITE != 0 && current & seal::WRITE == 0 && shared_maps > 0 {
        return Err(Errno::EBUSY);
    }
    Ok(current | adding)
}

/// Whether a `chmod` to `new` is refused: under `F_SEAL_EXEC`, one that
/// changes any execute bit.
pub(crate) fn chmod_refused(seals: u32, old: u32, new: u32) -> bool {
    seals & seal::EXEC != 0 && (old ^ new) & 0o111 != 0
}

/// Whether a new `MAP_SHARED` mapping counts against `F_SEAL_WRITE`: it
/// could be written through, unless a write seal already made it read-only
/// -- Linux clears `VM_MAYWRITE` on one made under a write seal.
pub(crate) fn mapping_counts(seals: u32, shared: bool) -> bool {
    shared && seals & (seal::WRITE | seal::FUTURE_WRITE) == 0
}

/// Whether a `write` of `len` bytes at `pos` is refused, given the size.
pub(crate) fn write_refused(seals: u32, pos: i64, len: usize, size: i64) -> bool {
    if seals & (seal::WRITE | seal::FUTURE_WRITE) != 0 {
        return true;
    }
    seals & seal::GROW != 0 && pos.saturating_add(len as i64) > size
}

/// Whether `ftruncate` to `new` is refused, given the size.
pub(crate) fn truncate_refused(seals: u32, new: i64, size: i64) -> bool {
    (new < size && seals & seal::SHRINK != 0) || (new > size && seals & seal::GROW != 0)
}

/// Whether a mapping is refused: a **shared** mapping that could be written
/// through, under either write seal. `shared` and `writable` are the request's.
pub(crate) fn mmap_refused(seals: u32, shared: bool, writable: bool) -> bool {
    seals & (seal::WRITE | seal::FUTURE_WRITE) != 0 && shared && writable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flags_are_linuxs() {
        assert_eq!(flags_ok(0), Ok(()));
        assert_eq!(flags_ok(mfd::CLOEXEC | mfd::ALLOW_SEALING), Ok(()));
        assert_eq!(flags_ok(0x20), Err(Errno::EINVAL), "a bit past the five");
        assert_eq!(
            flags_ok(0x4000_0000),
            Err(Errno::EINVAL),
            "a huge-page size without HUGETLB"
        );
        assert_eq!(flags_ok(mfd::HUGETLB | 0x4000_0000), Ok(()), "and with it");
        assert_eq!(
            flags_ok(mfd::EXEC | mfd::NOEXEC_SEAL),
            Err(Errno::EINVAL),
            "exec and no-exec at once"
        );
    }

    #[test]
    fn a_memfd_that_did_not_ask_for_sealing_is_sealed_against_it() {
        assert_eq!(initial_seals(0), seal::SEAL);
        assert_eq!(initial_seals(mfd::ALLOW_SEALING), 0);
        assert_eq!(
            initial_seals(mfd::NOEXEC_SEAL),
            seal::EXEC,
            "NOEXEC_SEAL implies ALLOW_SEALING"
        );
        assert_eq!(initial_mode(0), 0o777);
        assert_eq!(initial_mode(mfd::NOEXEC_SEAL), 0o666);
        assert_eq!(initial_mode(mfd::EXEC), 0o777);
    }

    #[test]
    fn adding_seals_checks_the_bits_before_the_seal() {
        assert_eq!(add_seals(0, seal::SHRINK, false, 0), Ok(seal::SHRINK));
        assert_eq!(
            add_seals(seal::SHRINK, seal::GROW, false, 0),
            Ok(seal::SHRINK | seal::GROW)
        );
        assert_eq!(
            add_seals(seal::SEAL, seal::SHRINK, false, 0),
            Err(Errno::EPERM)
        );
        assert_eq!(
            add_seals(seal::SEAL, 0x40, false, 0),
            Err(Errno::EINVAL),
            "EINVAL before EPERM"
        );
        assert_eq!(add_seals(0, 0, false, 0), Ok(0), "adding nothing is fine");
        assert_eq!(
            add_seals(0, seal::SEAL, false, 0),
            Ok(seal::SEAL),
            "and so is sealing the seals"
        );
    }

    /// `F_SEAL_WRITE` is `EBUSY` while a shared mapping exists -- once. A
    /// file already write-sealed is not asked again, and the other seals do
    /// not care.
    #[test]
    fn a_write_seal_waits_for_the_mappings() {
        assert_eq!(add_seals(0, seal::WRITE, false, 1), Err(Errno::EBUSY));
        assert_eq!(add_seals(0, seal::WRITE, false, 0), Ok(seal::WRITE));
        assert_eq!(
            add_seals(seal::WRITE, seal::WRITE | seal::SHRINK, false, 3),
            Ok(seal::WRITE | seal::SHRINK)
        );
        assert_eq!(
            add_seals(0, seal::SHRINK | seal::GROW, false, 3),
            Ok(seal::SHRINK | seal::GROW)
        );
        assert_eq!(
            add_seals(0, seal::FUTURE_WRITE, false, 3),
            Ok(seal::FUTURE_WRITE),
            "FUTURE_WRITE is about new mappings"
        );
    }

    /// `F_SEAL_EXEC` on an executable file is W^X from then on: the four
    /// write seals come with it. On a file with no execute bit it is itself.
    #[test]
    fn an_exec_seal_on_an_executable_file_brings_the_write_seals() {
        let wx = seal::EXEC | seal::SHRINK | seal::GROW | seal::WRITE | seal::FUTURE_WRITE;
        assert_eq!(add_seals(0, seal::EXEC, true, 0), Ok(wx));
        assert_eq!(add_seals(0, seal::EXEC, false, 0), Ok(seal::EXEC));
        assert_eq!(
            add_seals(0, seal::EXEC, true, 1),
            Err(Errno::EBUSY),
            "and so is asked about the mappings"
        );
    }

    #[test]
    fn an_exec_seal_stops_a_chmod_of_the_execute_bits_only() {
        assert!(chmod_refused(seal::EXEC, 0o777, 0o666));
        assert!(chmod_refused(seal::EXEC, 0o666, 0o777));
        assert!(chmod_refused(seal::EXEC, 0o777, 0o767), "one bit is enough");
        assert!(!chmod_refused(seal::EXEC, 0o777, 0o777));
        assert!(
            !chmod_refused(seal::EXEC, 0o777, 0o711),
            "the other bits are free"
        );
        assert!(!chmod_refused(seal::WRITE, 0o777, 0o666));
    }

    #[test]
    fn which_mappings_count() {
        assert!(mapping_counts(0, true));
        assert!(!mapping_counts(0, false), "a private mapping never");
        assert!(
            !mapping_counts(seal::WRITE, true),
            "nor one made read-only by a seal"
        );
        assert!(!mapping_counts(seal::FUTURE_WRITE, true));
        assert!(mapping_counts(seal::SHRINK | seal::GROW, true));
    }

    #[test]
    fn the_write_seals() {
        assert!(!write_refused(0, 0, 10, 0));
        assert!(write_refused(seal::WRITE, 0, 1, 100));
        assert!(write_refused(seal::FUTURE_WRITE, 0, 1, 100));
        assert!(
            !write_refused(seal::GROW, 90, 10, 100),
            "up to the end is fine under GROW"
        );
        assert!(write_refused(seal::GROW, 91, 10, 100), "past it is not");
        assert!(
            write_refused(seal::GROW, i64::MAX, 1, 100),
            "and the sum does not wrap"
        );
        assert!(
            !write_refused(seal::SHRINK, 0, 1000, 100),
            "SHRINK says nothing about writes"
        );
    }

    #[test]
    fn the_truncate_seals() {
        assert!(!truncate_refused(0, 0, 100));
        assert!(truncate_refused(seal::SHRINK, 50, 100));
        assert!(
            !truncate_refused(seal::SHRINK, 100, 100),
            "the same size is neither"
        );
        assert!(!truncate_refused(seal::SHRINK, 200, 100));
        assert!(truncate_refused(seal::GROW, 200, 100));
        assert!(!truncate_refused(seal::GROW, 50, 100));
        assert!(
            !truncate_refused(seal::WRITE, 50, 100),
            "WRITE says nothing about truncation"
        );
    }

    #[test]
    fn a_write_seal_refuses_a_writable_shared_mapping_only() {
        assert!(mmap_refused(seal::WRITE, true, true));
        assert!(mmap_refused(seal::FUTURE_WRITE, true, true));
        assert!(
            !mmap_refused(seal::WRITE, true, false),
            "a read-only shared mapping is fine"
        );
        assert!(
            !mmap_refused(seal::WRITE, false, true),
            "and so is a private writable one"
        );
        assert!(!mmap_refused(seal::SHRINK | seal::GROW, true, true));
    }
}

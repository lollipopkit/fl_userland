//! `fs.suid_dumpable` is process-wide state, so the one test that changes it
//! is a binary of its own: in the unit tests it would race every test that
//! reads it.

use kernel_procattr::{ProcAttr, set_suid_dumpable, suid_dumpable};

#[test]
fn each_value_is_what_a_change_of_identity_and_a_privileged_exec_leave() {
    assert_eq!(suid_dumpable(), 0, "Linux's default");
    for v in [3, -1, i64::from(i32::MAX) + 1] {
        assert!(set_suid_dumpable(v).is_err(), "{v}");
    }
    assert_eq!(suid_dumpable(), 0, "a refusal changed it");
    for v in [1, 2, 0] {
        set_suid_dumpable(v).unwrap();
        let p = ProcAttr::default();
        p.on_identity_change();
        assert_eq!(i64::from(p.dumpable()), v, "after a change of identity");
        p.set_dumpable(1).unwrap();
        p.on_exec(true);
        assert_eq!(i64::from(p.dumpable()), v, "after a privileged exec");
        p.on_exec(false);
        assert_eq!(p.dumpable(), 1, "an ordinary exec is 1 whatever the knob says");
    }
}

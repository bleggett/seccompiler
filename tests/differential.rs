// Copyright 2026 Edera. SPDX-License-Identifier: Apache-2.0
//
// Differential tests: build the same logical filter with seccompiler's native
// API (using per-syscall actions) and with libseccomp, then evaluate the compiled results
// over a battery of `seccomp_data` inputs and assert identical returns.
//
// libseccomp's outputs are the only thing we use. Gated behind `--features differential-test`.
#![cfg(feature = "differential-test")]

mod common;

use common::{eval, native_audit, seccomp_data, AUDIT_ARCH_I386};
use libseccomp::{
    ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall,
};
use seccompiler::{
    sock_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule,
};
use std::collections::BTreeMap;
use std::convert::TryInto;

#[derive(Clone, Copy)]
enum Act {
    Allow,
    Errno(u16),
    KillProcess,
    Trap,
    Log,
}

#[derive(Clone, Copy)]
enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    /// (mask, datum): (arg & mask) == datum
    MaskedEq(u64),
}

#[derive(Clone, Copy)]
struct Cond {
    index: u32,
    op: Op,
    value: u64,
}

/// One syscall entry: an action plus an OR of AND-groups of conditions.
struct Entry {
    nr: i64,
    action: Act,
    rules: Vec<Vec<Cond>>,
}

struct Spec {
    default: Act,
    entries: Vec<Entry>,
}

fn scl_action(a: Act) -> SeccompAction {
    match a {
        Act::Allow => SeccompAction::Allow,
        Act::Errno(e) => SeccompAction::Errno(u32::from(e)),
        Act::KillProcess => SeccompAction::KillProcess,
        Act::Trap => SeccompAction::Trap,
        Act::Log => SeccompAction::Log,
    }
}

fn scl_condition(c: &Cond) -> SeccompCondition {
    let (op, datum) = match c.op {
        Op::Eq => (SeccompCmpOp::Eq, c.value),
        Op::Ne => (SeccompCmpOp::Ne, c.value),
        Op::Lt => (SeccompCmpOp::Lt, c.value),
        Op::Le => (SeccompCmpOp::Le, c.value),
        Op::Gt => (SeccompCmpOp::Gt, c.value),
        Op::Ge => (SeccompCmpOp::Ge, c.value),
        Op::MaskedEq(mask) => (SeccompCmpOp::MaskedEq(mask), c.value),
    };
    SeccompCondition::new(c.index as u8, SeccompCmpArgLen::Qword, op, datum).unwrap()
}

fn build_seccompiler(spec: &Spec) -> BpfProgram {
    let mut map: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for e in &spec.entries {
        let action = scl_action(e.action);
        let rules = e
            .rules
            .iter()
            .map(|group| {
                let conds: Vec<_> = group.iter().map(scl_condition).collect();
                SeccompRule::new_with_action(conds, action.clone()).unwrap()
            })
            .collect();
        map.entry(e.nr).or_default().extend::<Vec<_>>(rules);
    }
    // Every rule carries its own action, so match_action is unused; pick one
    // distinct from the default to satisfy the validator.
    let default = scl_action(spec.default);
    let match_fallback = if default == SeccompAction::Allow {
        SeccompAction::Trap
    } else {
        SeccompAction::Allow
    };
    SeccompFilter::new(
        map,
        default,
        match_fallback,
        std::env::consts::ARCH.try_into().unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap()
}

fn lsc_action(a: Act) -> ScmpAction {
    match a {
        Act::Allow => ScmpAction::Allow,
        Act::Errno(e) => ScmpAction::Errno(i32::from(e)),
        Act::KillProcess => ScmpAction::KillProcess,
        Act::Trap => ScmpAction::Trap,
        Act::Log => ScmpAction::Log,
    }
}

fn lsc_condition(c: &Cond) -> ScmpArgCompare {
    match c.op {
        Op::Eq => ScmpArgCompare::new(c.index, ScmpCompareOp::Equal, c.value),
        Op::Ne => ScmpArgCompare::new(c.index, ScmpCompareOp::NotEqual, c.value),
        Op::Lt => ScmpArgCompare::new(c.index, ScmpCompareOp::Less, c.value),
        Op::Le => ScmpArgCompare::new(c.index, ScmpCompareOp::LessOrEqual, c.value),
        Op::Gt => ScmpArgCompare::new(c.index, ScmpCompareOp::Greater, c.value),
        Op::Ge => ScmpArgCompare::new(c.index, ScmpCompareOp::GreaterEqual, c.value),
        Op::MaskedEq(mask) => {
            ScmpArgCompare::new(c.index, ScmpCompareOp::MaskedEqual(mask), c.value)
        }
    }
}

fn build_libseccomp(spec: &Spec) -> BpfProgram {
    let mut ctx = ScmpFilterContext::new(lsc_action(spec.default)).unwrap();
    ctx.set_act_badarch(ScmpAction::KillProcess).unwrap();
    for e in &spec.entries {
        let action = lsc_action(e.action);
        let sc = ScmpSyscall::from(e.nr as i32);
        for group in &e.rules {
            if group.is_empty() {
                ctx.add_rule(action, sc).unwrap();
            } else {
                let cmps: Vec<_> = group.iter().map(lsc_condition).collect();
                ctx.add_rule_conditional(action, sc, &cmps).unwrap();
            }
        }
    }
    let bytes = ctx.export_bpf_mem().unwrap();
    // export_bpf_mem yields the raw sock_filter array; reinterpret 8-byte records.
    bytes
        .chunks_exact(8)
        .map(|c| sock_filter {
            code: u16::from_le_bytes([c[0], c[1]]),
            jt: c[2],
            jf: c[3],
            k: u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
        })
        .collect()
}

// ---- comparison -----------------------------------------------------------

fn probe_values() -> [u64; 8] {
    [
        0,
        1,
        15,
        16,
        17,
        0xffff_ffff,
        0x1_0000_0000,
        0xffff_ffff_ffff_ffff,
    ]
}

fn assert_equivalent(spec: &Spec) {
    let ours = build_seccompiler(spec);
    let theirs = build_libseccomp(spec);

    let mut nrs: Vec<u32> = spec.entries.iter().map(|e| e.nr as u32).collect();
    nrs.push(999_999); // a syscall not in the filter -> default path

    for &nr in &nrs {
        for a0 in probe_values() {
            for a1 in probe_values() {
                let data = seccomp_data(nr, native_audit(), [a0, a1, 0, 0, 0, 0]);
                let (ours_ret, _) = eval(&ours, &data);
                let (theirs_ret, _) = eval(&theirs, &data);
                assert_eq!(ours_ret, theirs_ret, "mismatch nr={nr} a0={a0:#x} a1={a1:#x}");
            }
        }
        // Foreign arch: both must kill.
        let data = seccomp_data(nr, AUDIT_ARCH_I386, [0; 6]);
        assert_eq!(
            eval(&ours, &data).0,
            eval(&theirs, &data).0,
            "foreign-arch mismatch nr={nr}"
        );
    }
}

fn e(nr: i64, action: Act, rules: Vec<Vec<Cond>>) -> Entry {
    Entry { nr, action, rules }
}
fn c(index: u32, op: Op, value: u64) -> Cond {
    Cond { index, op, value }
}

#[test]
fn allowlist_default_deny() {
    assert_equivalent(&Spec {
        default: Act::Errno(1),
        entries: vec![
            e(0, Act::Allow, vec![vec![]]),
            e(1, Act::Allow, vec![vec![]]),
            e(2, Act::Allow, vec![vec![]]),
        ],
    });
}

#[test]
fn mixed_per_syscall_actions() {
    assert_equivalent(&Spec {
        default: Act::Errno(1),
        entries: vec![
            e(0, Act::Allow, vec![vec![]]),
            e(1, Act::Errno(38), vec![vec![]]), // clone3 -> ENOSYS style
            e(2, Act::KillProcess, vec![vec![]]),
            e(3, Act::Trap, vec![vec![]]),
            e(4, Act::Log, vec![vec![]]),
        ],
    });
}

#[test]
fn all_operators() {
    for op in [Op::Eq, Op::Ne, Op::Lt, Op::Le, Op::Gt, Op::Ge] {
        assert_equivalent(&Spec {
            default: Act::Errno(1),
            entries: vec![e(0, Act::Allow, vec![vec![c(0, op, 16)]])],
        });
    }
}

#[test]
fn masked_eq() {
    assert_equivalent(&Spec {
        default: Act::Errno(1),
        entries: vec![e(
            0,
            Act::Allow,
            vec![vec![c(0, Op::MaskedEq(0x1000_0000), 0)]],
        )],
    });
}

#[test]
fn anded_and_ored_conditions() {
    assert_equivalent(&Spec {
        default: Act::Errno(1),
        entries: vec![
            // AND: two different-index conditions in one group.
            e(0, Act::Allow, vec![vec![c(0, Op::Eq, 2), c(1, Op::Eq, 1)]]),
            // OR: two single-condition groups on the same syscall.
            e(1, Act::Allow, vec![vec![c(0, Op::Eq, 2)], vec![c(0, Op::Eq, 10)]]),
        ],
    });
}

#[test]
fn large_allowlist_forces_tree_and_relaxation() {
    // ~120 unconditional syscalls with mixed actions: deep enough that the tree
    // exceeds the 8-bit jump range, exercising branch relaxation. Non-contiguous
    // numbers so the binary search actually partitions.
    let entries: Vec<Entry> = (0..120i64)
        .map(|i| {
            let nr = i * 3 + 1; // spread out
            let action = match i % 4 {
                0 => Act::Allow,
                1 => Act::Errno(38),
                2 => Act::KillProcess,
                _ => Act::Log,
            };
            e(nr, action, vec![vec![]])
        })
        .collect();
    assert_equivalent(&Spec {
        default: Act::Errno(1),
        entries,
    });
}

#[test]
fn mixed_conditional_and_unconditional() {
    // Conditional entries (linear) alongside unconditional ones (tree), to
    // exercise the fall-through from the conditional chains into the tree.
    assert_equivalent(&Spec {
        default: Act::Errno(1),
        entries: vec![
            e(10, Act::Allow, vec![vec![c(0, Op::Eq, 2)]]), // conditional
            e(20, Act::Allow, vec![vec![]]),                // unconditional
            e(30, Act::Errno(38), vec![vec![]]),            // unconditional
            e(40, Act::Allow, vec![vec![c(0, Op::Ne, 5)]]), // conditional
            e(50, Act::KillProcess, vec![vec![]]),          // unconditional
        ],
    });
}

#[test]
fn permissive_default() {
    assert_equivalent(&Spec {
        default: Act::Allow,
        entries: vec![
            e(0, Act::Errno(13), vec![vec![]]),
            e(1, Act::KillProcess, vec![vec![]]),
        ],
    });
}

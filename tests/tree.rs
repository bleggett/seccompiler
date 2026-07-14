// Copyright 2026 Edera. SPDX-License-Identifier: Apache-2.0
//
// Correctness of the binary-search syscall dispatch, verified WITHOUT libseccomp
// (so it runs under a plain `cargo test`). Each leaf's expected return is the
// filter's own action->u32 mapping; the test proves the tree routes each syscall
// number to the correct leaf and misses to the default. The `differential` test
// additionally cross-checks these decisions against libseccomp.

mod common;

use common::{eval, native_audit, seccomp_data};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
use std::convert::TryInto;

const DEFAULT: SeccompAction = SeccompAction::Errno(1);

/// Build a filter whose syscalls are all unconditional per-syscall actions
/// (so every one goes through the binary-search tree).
fn tree(entries: &[(i64, SeccompAction)]) -> BpfProgram {
    let map = entries
        .iter()
        .map(|(nr, a)| (*nr, vec![SeccompRule::always(a.clone())]))
        .collect();
    SeccompFilter::new(
        map,
        DEFAULT,
        SeccompAction::Log, // match fallback; unused (every rule sets its action)
        std::env::consts::ARCH.try_into().unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap()
}

fn ret(prog: &BpfProgram, nr: i64) -> u32 {
    eval(prog, &seccomp_data(nr as u32, native_audit(), [0; 6])).0
}

/// Every listed syscall returns its own action; a set of misses return the default.
fn assert_routes(entries: &[(i64, SeccompAction)], misses: &[i64]) {
    let prog = tree(entries);
    for (nr, action) in entries {
        assert_eq!(
            ret(&prog, *nr),
            u32::from(action.clone()),
            "syscall {nr} routed to the wrong action",
        );
    }
    for &nr in misses {
        assert_eq!(
            ret(&prog, nr),
            u32::from(DEFAULT),
            "absent syscall {nr} should hit the default",
        );
    }
}

#[test]
fn single_leaf() {
    assert_routes(&[(42, SeccompAction::Allow)], &[0, 41, 43, 1_000_000]);
}

#[test]
fn two_leaves() {
    assert_routes(
        &[(10, SeccompAction::Allow), (20, SeccompAction::Errno(38))],
        &[0, 9, 11, 19, 21, 999],
    );
}

#[test]
fn odd_count_unbalanced_split() {
    assert_routes(
        &[
            (1, SeccompAction::Allow),
            (2, SeccompAction::Errno(13)),
            (3, SeccompAction::KillProcess),
        ],
        &[0, 4, 100],
    );
}

#[test]
fn mixed_actions_are_per_leaf() {
    // Distinct action per syscall must survive the routing, not collapse.
    let entries: Vec<(i64, SeccompAction)> = (0..50i64)
        .map(|i| {
            let action = match i % 4 {
                0 => SeccompAction::Allow,
                1 => SeccompAction::Errno(38),
                2 => SeccompAction::KillProcess,
                _ => SeccompAction::Trap,
            };
            (i * 5 + 2, action) // leaves are exactly the numbers where nr % 5 == 2
        })
        .collect();
    // Misses (none of the form i*5+2): below all, between neighbors, above all.
    let misses = [0, 1, 3, 6, 8, 248, 1_000];
    assert_routes(&entries, &misses);
}

#[test]
fn boundary_numbers() {
    assert_routes(
        &[
            (0, SeccompAction::Allow),
            (1, SeccompAction::Trap),
            (100_000, SeccompAction::KillProcess),
        ],
        &[2, 99_999, 100_001],
    );
}

#[test]
fn large_tree_routes_every_leaf() {
    // Big enough to force multiple levels and far-jump relaxation; every leaf
    // must still be reachable with its own action.
    let entries: Vec<(i64, SeccompAction)> = (0..200i64)
        .map(|i| (i * 3 + 1, if i % 2 == 0 { SeccompAction::Allow } else { SeccompAction::Errno(38) }))
        .collect();
    let misses: Vec<i64> = (0..200i64).map(|i| i * 3).collect(); // the gaps between leaves
    assert_routes(&entries, &misses);
}

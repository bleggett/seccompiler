// Copyright 2026 Edera. SPDX-License-Identifier: Apache-2.0
//
// Baseline size / eval-cost metrics for the current codegen.
// These numbers are the "before" that optimization passes are measured against:
// run with `cargo test --test metrics -- --nocapture` to see the table.

mod common;

use common::{measure, native_audit, seccomp_data};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
use std::convert::TryInto;

/// A default-deny allowlist of `n` syscalls, each allowed unconditionally via a
/// per-syscall action - the shape a real OCI profile compiles to.
fn allowlist(n: i64) -> BpfProgram {
    let map = (0..n)
        .map(|nr| (nr, vec![SeccompRule::always(SeccompAction::Allow)]))
        .collect();
    SeccompFilter::new(
        map,
        SeccompAction::Errno(1), // mismatch / default-deny
        SeccompAction::Trap,     // match fallback; unused (every rule sets Allow)
        std::env::consts::ARCH.try_into().unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap()
}

/// Inputs covering every listed syscall plus one miss (the full-scan worst case).
fn inputs_for(n: i64) -> Vec<[u8; 64]> {
    let mut v: Vec<[u8; 64]> = (0..n)
        .map(|nr| seccomp_data(nr as u32, native_audit(), [0; 6]))
        .collect();
    v.push(seccomp_data((n + 1000) as u32, native_audit(), [0; 6]));
    v
}

#[test]
fn allowlist_dispatch_is_logarithmic() {
    println!("\n{:>8} | {:>6} | {:>11} | {:>10}", "syscalls", "size", "worst-steps", "mean-steps");
    println!("{}", "-".repeat(44));

    let mut worst_by_n: Vec<(i64, usize)> = Vec::new();
    for &n in &[10i64, 50, 100, 300] {
        let m = measure(&allowlist(n), &inputs_for(n));
        println!("{n:>8} | {:>6} | {:>11} | {:>10.1}", m.size, m.worst_steps, m.mean_steps);
        assert!(m.size < 4096, "filter must stay under BPF_MAXINSNS");
        worst_by_n.push((n, m.worst_steps));
    }
    println!();

    // Binary search: a 30x growth in syscall count should not come close to a 30x
    // growth in worst-case eval, or we are almost certainly doing something wrong.
    let (n_small, worst_small) = worst_by_n[0];
    let (n_big, worst_big) = *worst_by_n.last().unwrap();
    assert!(
        worst_big < worst_small * 3,
        "worst-case {worst_big} at n={n_big} vs {worst_small} at n={n_small}: not logarithmic",
    );
}

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
        .map(|nr| {
            (
                nr,
                vec![SeccompRule::new_with_action(vec![], SeccompAction::Allow).unwrap()],
            )
        })
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
fn baseline_allowlist_metrics() {
    println!(
        "\n{:>8} | {:>6} | {:>11} | {:>10}",
        "syscalls", "size", "worst-steps", "mean-steps"
    );
    println!("{}", "-".repeat(44));

    let mut prev_worst = 0;
    for &n in &[10i64, 50, 100, 300] {
        let prog = allowlist(n);
        let m = measure(&prog, &inputs_for(n));
        println!(
            "{n:>8} | {:>6} | {:>11} | {:>10.1}",
            m.size, m.worst_steps, m.mean_steps
        );

        // Sanity + documents today's characteristics:
        assert!(m.size < 4096, "filter must stay under BPF_MAXINSNS");
        assert!(m.worst_steps <= m.size, "cannot execute more than it contains");
        // Worst case is the full linear scan: it grows with syscall count. This
        // is exactly the O(n) behavior optimization (tree dispatch) will fix; the
        // assertion is a marker so the "after" run visibly breaks the trend.
        assert!(
            m.worst_steps > prev_worst,
            "unoptimized worst-case should grow with syscall count"
        );
        prev_worst = m.worst_steps;
    }
    println!();
}

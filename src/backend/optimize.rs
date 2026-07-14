// Copyright 2026 Edera. SPDX-License-Identifier: Apache-2.0
//
// Optimized dispatch: a binary search over syscall numbers instead of a linear
// scan, turning the worst-case from O(n) comparisons into O(log n).
//
// Classic-BPF conditional jumps carry 8-bit offsets, so a label-based assembler
// resolves symbolic targets and, when a conditional's target is out of 8-bit
// range, relaxes it into a short conditional plus 32-bit `JA` trampolines
// (branch relaxation). All jumps produced here are forward, matching the tree's
// top-down layout.

use crate::backend::bpf::*;
use crate::backend::SeccompAction;

pub(crate) type Label = usize;

/// One assembler item.
/// - `Cond` references labels
/// - `Mark` is a zero-width label definition
/// - `Ins` is a fully-formed instruction embedded verbatim, its own
/// relative offsets are already correct and are never rewritten.
pub(crate) enum Item {
    Ins(sock_filter),
    Cond {
        code: u16,
        k: u32,
        jt: Label,
        jf: Label,
    },
    Mark(Label),
}

/// Resolve labels and emit the final program.
pub(crate) fn assemble(items: &[Item], n_labels: usize) -> Vec<sock_filter> {
    let mut relaxed = vec![false; items.len()];

    loop {
        // Positions of every item and label under the current relaxation state.
        let mut label_pos = vec![0usize; n_labels];
        let mut item_pos = vec![0usize; items.len()];
        let mut p = 0usize;
        for (i, it) in items.iter().enumerate() {
            item_pos[i] = p;
            match it {
                Item::Mark(l) => label_pos[*l] = p,
                Item::Ins(_) => p += 1,
                Item::Cond { .. } => p += if relaxed[i] { 3 } else { 1 },
            }
        }

        // A conditional whose target is not a forward jump within 8 bits must relax.
        let mut changed = false;
        for (i, it) in items.iter().enumerate() {
            if let Item::Cond { jt, jf, .. } = it {
                if !relaxed[i] {
                    let next = item_pos[i] + 1;
                    let jt_off = label_pos[*jt] as isize - next as isize;
                    let jf_off = label_pos[*jf] as isize - next as isize;
                    if !(0..=255).contains(&jt_off) || !(0..=255).contains(&jf_off) {
                        relaxed[i] = true;
                        changed = true;
                    }
                }
            }
        }
        if changed {
            continue;
        }

        // Stable: emit.
        let mut out = Vec::with_capacity(p);
        for (i, it) in items.iter().enumerate() {
            match it {
                Item::Mark(_) => {}
                Item::Ins(s) => out.push(s.clone()),
                Item::Cond { code, k, jt, jf } => {
                    if relaxed[i] {
                        // Cond k, 0, 1 ; JA jt ; JA jf
                        out.push(bpf_jump(*code, *k, 0, 1));
                        let off = label_pos[*jt] - (out.len() + 1);
                        out.push(bpf_stmt(BPF_JMP | BPF_JA, off as u32));
                        let off = label_pos[*jf] - (out.len() + 1);
                        out.push(bpf_stmt(BPF_JMP | BPF_JA, off as u32));
                    } else {
                        let next = out.len() + 1;
                        let jt_off = (label_pos[*jt] - next) as u8;
                        let jf_off = (label_pos[*jf] - next) as u8;
                        out.push(bpf_jump(*code, *k, jt_off, jf_off));
                    }
                }
            }
        }
        return out;
    }
}

/// Append a balanced binary-search dispatch over `leaves` (sorted ascending by
/// syscall number).
pub(crate) fn build_bst(
    leaves: &[(i64, SeccompAction)],
    items: &mut Vec<Item>,
    next_label: &mut usize,
    default_label: Label,
) {
    debug_assert!(leaves.windows(2).all(|w| w[0].0 < w[1].0), "leaves must be sorted");
    emit(leaves, items, next_label, default_label);
}

fn fresh(next_label: &mut usize) -> Label {
    let l = *next_label;
    *next_label += 1;
    l
}

fn emit(leaves: &[(i64, SeccompAction)], items: &mut Vec<Item>, next: &mut usize, default: Label) {
    if leaves.len() == 1 {
        let (nr, action) = &leaves[0];
        let hit = fresh(next);
        // A miss means the syscall is absent.
        items.push(Item::Cond {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            k: u32::try_from(*nr).unwrap(),
            jt: hit,
            jf: default,
        });
        items.push(Item::Mark(hit));
        items.push(Item::Ins(bpf_stmt(BPF_RET | BPF_K, u32::from(action.clone()))));
        return;
    }

    let mid = leaves.len() / 2;
    let pivot = leaves[mid].0;
    let right = fresh(next);
    let left = fresh(next);
    items.push(Item::Cond {
        code: BPF_JMP | BPF_JGE | BPF_K,
        k: u32::try_from(pivot).unwrap(),
        jt: right,
        jf: left,
    });
    items.push(Item::Mark(left));
    emit(&leaves[..mid], items, next, default);
    items.push(Item::Mark(right));
    emit(&leaves[mid..], items, next, default);
}

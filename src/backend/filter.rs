// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::collections::BTreeMap;

use crate::backend::bpf::*;
use crate::backend::optimize::{assemble, build_bst, Item};
use crate::backend::rule::SeccompRule;
use crate::backend::{Error, Result, SeccompAction, TargetArch};

/// Filter containing rules assigned to syscall numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeccompFilter {
    /// Map of syscall numbers and corresponding rule chains.
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    /// Default action to apply to syscalls that do not match the filter.
    mismatch_action: SeccompAction,
    /// Filter action to apply to syscalls that match the filter.
    match_action: SeccompAction,
    /// Target architecture of the generated BPF filter.
    target_arch: TargetArch,
}

impl SeccompFilter {
    /// Creates a new filter with a set of rules, an on-match and default action.
    ///
    /// # Arguments
    ///
    /// * `rules` - Map containing syscall numbers and their respective [`SeccompRule`]s.
    /// * `mismatch_action` - [`SeccompAction`] taken for all syscalls that do not match the filter.
    /// * `match_action` - [`SeccompAction`] taken for system calls that match the filter.
    /// * `target_arch` - Target architecture of the generated BPF filter.
    ///
    /// # Example
    ///
    /// ```
    /// use seccompiler::{
    ///     SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    /// };
    /// use std::convert::TryInto;
    ///
    /// let filter = SeccompFilter::new(
    ///     vec![
    ///         (libc::SYS_accept4, vec![]),
    ///         (
    ///             libc::SYS_fcntl,
    ///             vec![
    ///                 SeccompRule::new(vec![
    ///                     SeccompCondition::new(
    ///                         1,
    ///                         SeccompCmpArgLen::Dword,
    ///                         SeccompCmpOp::Eq,
    ///                         libc::F_SETFD as u64,
    ///                     )
    ///                     .unwrap(),
    ///                     SeccompCondition::new(
    ///                         2,
    ///                         SeccompCmpArgLen::Dword,
    ///                         SeccompCmpOp::Eq,
    ///                         libc::FD_CLOEXEC as u64,
    ///                     )
    ///                     .unwrap(),
    ///                 ])
    ///                 .unwrap(),
    ///                 SeccompRule::new(vec![SeccompCondition::new(
    ///                     1,
    ///                     SeccompCmpArgLen::Dword,
    ///                     SeccompCmpOp::Eq,
    ///                     libc::F_GETFD as u64,
    ///                 )
    ///                 .unwrap()])
    ///                 .unwrap(),
    ///             ],
    ///         ),
    ///     ]
    ///     .into_iter()
    ///     .collect(),
    ///     SeccompAction::Trap,
    ///     SeccompAction::Allow,
    ///     std::env::consts::ARCH.try_into().unwrap(),
    /// );
    /// ```
    ///
    /// [`SeccompRule`]: struct.SeccompRule.html
    /// [`SeccompAction`]: enum.SeccompAction.html
    pub fn new(
        rules: BTreeMap<i64, Vec<SeccompRule>>,
        mismatch_action: SeccompAction,
        match_action: SeccompAction,
        target_arch: TargetArch,
    ) -> Result<Self> {
        let instance = Self {
            rules,
            mismatch_action,
            match_action,
            target_arch,
        };

        instance.validate()?;

        Ok(instance)
    }

    /// Compile the filter to BPF. Syscall dispatch is a binary search over
    /// syscall numbers (O(log n)): unconditional per-syscall actions form the
    /// search tree, while conditional syscalls keep their linear rule chains,
    /// emitted ahead of the tree so a miss falls through into it.
    fn compile(self) -> Result<BpfProgram> {
        let mut prefix = build_arch_validation_sequence(self.target_arch);
        if self.rules.is_empty() {
            prefix.push(bpf_stmt(BPF_RET | BPF_K, u32::from(self.mismatch_action)));
            return Ok(prefix);
        }
        prefix.push(bpf_stmt(
            BPF_LD | BPF_W | BPF_ABS,
            u32::from(SECCOMP_DATA_NR_OFFSET),
        ));

        let mut unconditional: Vec<(i64, SeccompAction)> = Vec::new();
        let mut conditional: Vec<(i64, Vec<SeccompRule>)> = Vec::new();
        for (nr, chain) in self.rules {
            if chain.len() == 1 && chain[0].is_unconditional() {
                if let Some(action) = chain[0].action() {
                    unconditional.push((nr, action));
                    continue;
                }
            }
            conditional.push((nr, chain));
        }

        // A mismatched syscall number escapes each chain to the next
        // block and ultimately into the tree below.
        let mut cond_blocks: Vec<Vec<sock_filter>> = Vec::new();
        for (nr, chain) in conditional {
            Self::append_syscall_chain(
                nr,
                chain,
                self.mismatch_action.clone(),
                self.match_action.clone(),
                &mut cond_blocks,
            )?;
        }

        // Fixed prefix + conditional blocks are embedded verbatim.
        let mut items: Vec<Item> = Vec::new();
        for ins in prefix {
            items.push(Item::Ins(ins));
        }
        for block in cond_blocks {
            for ins in block {
                items.push(Item::Ins(ins));
            }
        }

        let default_label = 0usize;
        let mut next_label = 1usize;
        unconditional.sort_by_key(|(nr, _)| *nr);
        if !unconditional.is_empty() {
            build_bst(&unconditional, &mut items, &mut next_label, default_label);
        }
        items.push(Item::Mark(default_label));
        items.push(Item::Ins(bpf_stmt(
            BPF_RET | BPF_K,
            u32::from(self.mismatch_action),
        )));

        let prog = assemble(&items, next_label);
        if prog.len() >= BPF_MAX_LEN {
            return Err(Error::FilterTooLarge(prog.len()));
        }
        Ok(prog)
    }

    /// Performs semantic checks on the SeccompFilter.
    fn validate(&self) -> Result<()> {
        // Doesn't make sense to have equal default and on-match actions.
        if self.mismatch_action == self.match_action {
            return Err(Error::IdenticalActions);
        }

        Ok(())
    }

    /// Appends a chain of rules to an accumulator, updating the length of the filter.
    ///
    /// # Arguments
    ///
    /// * `syscall_number` - The syscall to which the rules apply.
    /// * `chain` - The chain of rules for the specified syscall.
    /// * `mismatch_action` - The action to be taken in none of the rules apply.
    /// * `accumulator` - The expanding BPF program.
    fn append_syscall_chain(
        syscall_number: i64,
        chain: Vec<SeccompRule>,
        mismatch_action: SeccompAction,
        match_action: SeccompAction,
        accumulator: &mut Vec<Vec<sock_filter>>,
    ) -> Result<()> {
        // The rules of the chain are translated into BPF statements.
        let chain: Vec<_> = chain
            .into_iter()
            .map(|rule| {
                // Each rule returns its own action if it set one, else the
                // filter's match_action. This is what lets a single filter carry
                // distinct per-syscall actions.
                let action = rule.action().unwrap_or_else(|| match_action.clone());
                let mut bpf: BpfProgram = rule.into();
                bpf.push(bpf_stmt(BPF_RET | BPF_K, u32::from(action)));
                bpf
            })
            .collect();
        let chain_len: usize = chain.iter().map(Vec::len).sum();

        // The chain starts with a comparison checking the loaded syscall number against the
        // syscall number of the chain.
        let mut built_syscall = Vec::with_capacity(chain_len + 2);
        built_syscall.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            // Safe because linux system call numbers are nowhere near the u32::MAX value.
            syscall_number.try_into().unwrap(),
            0,
            1,
        ));

        if chain.is_empty() {
            built_syscall.push(bpf_stmt(BPF_JMP | BPF_JA, 1));
            built_syscall.push(bpf_stmt(BPF_JMP | BPF_JA, 2));
            // If the chain is empty, we only need to append the on-match action.
            built_syscall.push(bpf_stmt(BPF_RET | BPF_K, u32::from(match_action)));
        } else {
            // The rules of the chain are appended.
            chain
                .into_iter()
                .for_each(|mut rule| built_syscall.append(&mut rule));
        }

        // The default action is appended, if the syscall number comparison matched and then all
        // rules fail to match, the default action is reached.
        built_syscall.push(bpf_stmt(BPF_RET | BPF_K, mismatch_action.into()));

        accumulator.push(built_syscall);

        Ok(())
    }
}

impl TryFrom<SeccompFilter> for BpfProgram {
    type Error = Error;
    fn try_from(filter: SeccompFilter) -> Result<Self> {
        filter.compile()
    }
}

#[cfg(test)]
mod tests {
    use super::SeccompFilter;
    use crate::backend::bpf::*;
    use crate::backend::condition::SeccompCondition as Cond;
    use crate::backend::SeccompCmpArgLen as ArgLen;
    use crate::backend::SeccompCmpOp::*;
    use crate::backend::{Error, SeccompAction, SeccompRule};
    use std::collections::BTreeMap;
    use std::convert::TryInto;
    use std::env::consts::ARCH;

    fn create_test_bpf_filter(arg_len: ArgLen) -> SeccompFilter {
        SeccompFilter::new(
            vec![
                (
                    1,
                    vec![
                        SeccompRule::new(vec![
                            Cond::new(2, arg_len.clone(), Le, 14).unwrap(),
                            Cond::new(2, arg_len.clone(), Ne, 10).unwrap(),
                        ])
                        .unwrap(),
                        SeccompRule::new(vec![
                            Cond::new(2, arg_len.clone(), Gt, 20).unwrap(),
                            Cond::new(2, arg_len.clone(), Lt, 30).unwrap(),
                        ])
                        .unwrap(),
                        SeccompRule::new(vec![Cond::new(2, arg_len.clone(), Ge, 42).unwrap()])
                            .unwrap(),
                    ],
                ),
                (
                    9,
                    vec![SeccompRule::new(vec![
                        Cond::new(1, arg_len, MaskedEq(0b100), 36).unwrap()
                    ])
                    .unwrap()],
                ),
                (10, vec![]),
            ]
            .into_iter()
            .collect(),
            SeccompAction::Trap,
            SeccompAction::Allow,
            ARCH.try_into().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_seccomp_filter_validate() {
        // Filter has identical on-match and default actions.
        assert_eq!(
            SeccompFilter::new(
                BTreeMap::new(),
                SeccompAction::Allow,
                SeccompAction::Allow,
                ARCH.try_into().unwrap()
            )
            .unwrap_err(),
            Error::IdenticalActions
        );
    }

    #[test]
    fn test_seccomp_filter_too_large() {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for _ in 1..1000 {
            rules
                .entry(1)
                .or_default()
                .append(&mut vec![SeccompRule::new(vec![Cond::new(
                    2,
                    ArgLen::Dword,
                    Le,
                    14,
                )
                .unwrap()])
                .unwrap()]);
        }

        let filter = SeccompFilter::new(
            rules.into_iter().collect(),
            SeccompAction::Allow,
            SeccompAction::Trap,
            ARCH.try_into().unwrap(),
        )
        .unwrap();

        assert_eq!(
            TryInto::<BpfProgram>::try_into(filter).unwrap_err(),
            Error::FilterTooLarge(5002)
        );
    }

    #[test]
    fn test_per_syscall_actions() {
        // Distinct actions for two syscalls in one filter - impossible in the
        // original two-bucket model, and the reason for `new_with_action`.
        let filter = SeccompFilter::new(
            vec![
                (
                    1,
                    vec![SeccompRule::new_with_action(vec![], SeccompAction::Errno(1)).unwrap()],
                ),
                (
                    2,
                    vec![SeccompRule::new_with_action(vec![], SeccompAction::Errno(38)).unwrap()],
                ),
            ]
            .into_iter()
            .collect(),
            SeccompAction::Allow, // mismatch (default)
            SeccompAction::Trap,  // match fallback; unused since both rules set actions
            ARCH.try_into().unwrap(),
        )
        .unwrap();

        let prog: BpfProgram = filter.try_into().unwrap();
        let rets: Vec<u32> = prog
            .iter()
            .filter(|i| i.code == (BPF_RET | BPF_K))
            .map(|i| i.k)
            .collect();

        // Both per-syscall actions are emitted...
        assert!(rets.contains(&u32::from(SeccompAction::Errno(1))));
        assert!(rets.contains(&u32::from(SeccompAction::Errno(38))));
        // ...and the (differing) errno data survives, not collapsed to one value.
        assert_ne!(
            u32::from(SeccompAction::Errno(1)),
            u32::from(SeccompAction::Errno(38))
        );
        // The match fallback is never reached because every rule set its own action.
        // (KillProcess would collide with the arch-guard's return, so Trap is used.)
        assert!(!rets.contains(&u32::from(SeccompAction::Trap)));
    }

    #[test]
    fn test_empty_filter_output() {
        // An empty filter should just validate the architecture and return the mismatch_action.
        let mut expected_program = Vec::new();
        expected_program.extend(build_arch_validation_sequence(ARCH.try_into().unwrap()));
        expected_program.extend(vec![bpf_stmt(BPF_RET, 0x7fff_0000)]);

        let filter = SeccompFilter::new(
            BTreeMap::new(),
            SeccompAction::Allow,
            SeccompAction::Trap,
            ARCH.try_into().unwrap(),
        )
        .unwrap();
        let prog: BpfProgram = filter.try_into().unwrap();

        assert_eq!(expected_program, prog);
    }

    #[test]
    fn test_filter_bpf_output_dword() {
        // Compares translated filter with hardcoded BPF program.
        let filter = create_test_bpf_filter(ArgLen::Dword);

        let mut instructions = Vec::new();
        instructions.extend(build_arch_validation_sequence(ARCH.try_into().unwrap()));
        instructions.extend(vec![
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 6),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 10, 3, 0),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 14, 1, 0),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 6),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGE | BPF_K, 30, 3, 0),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 20, 0, 1),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 4),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGE | BPF_K, 42, 0, 1),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 9, 0, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 5),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 24),
            bpf_stmt(BPF_ALU | BPF_AND | BPF_K, 0b100),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 36 & 0b100, 0, 1),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 10, 0, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 2),
            bpf_stmt(BPF_RET | BPF_K, 0x7fff_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
        ]);

        let bpfprog: BpfProgram = filter.try_into().unwrap();

        assert_eq!(bpfprog, instructions);
    }

    #[test]
    fn test_filter_bpf_output_qword() {
        let filter = create_test_bpf_filter(ArgLen::Qword);

        let mut instructions = Vec::new();
        instructions.extend(build_arch_validation_sequence(ARCH.try_into().unwrap()));
        instructions.extend(vec![
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 11),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 36),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 10, 6, 0),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 36),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 0, 4, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 14, 1, 0),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 12),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 36),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 0, 9, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGE | BPF_K, 30, 6, 0),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 36),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 0, 3, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 20, 0, 1),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 7),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 36),
            bpf_jump(BPF_JMP | BPF_JGT | BPF_K, 0, 3, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 32),
            bpf_jump(BPF_JMP | BPF_JGE | BPF_K, 42, 0, 1),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 9, 0, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 8),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 28),
            bpf_stmt(BPF_ALU | BPF_AND | BPF_K, 0),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 4),
            bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 24),
            bpf_stmt(BPF_ALU | BPF_AND | BPF_K, 0b100),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 36 & 0b100, 0, 1),
            bpf_stmt(BPF_RET, 0x7fff_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
            bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 10, 0, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 1),
            bpf_stmt(BPF_JMP | BPF_JA, 2),
            bpf_stmt(BPF_RET | BPF_K, 0x7fff_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
            bpf_stmt(BPF_RET, 0x0003_0000),
        ]);

        let bpfprog: BpfProgram = filter.try_into().unwrap();
        assert_eq!(bpfprog, instructions);
    }
}

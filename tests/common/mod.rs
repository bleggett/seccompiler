// Copyright 2026 Edera. SPDX-License-Identifier: Apache-2.0
//
// Shared test support: a classic-BPF interpreter over `seccomp_data` plus
// size/eval-cost metrics. Used by the metrics and differential harnesses.
//
// The interpreter reports both the returned action and the number of
// instructions executed, so optimization passes can be measured (static size
// and worst-case/mean executed steps) without any external reference.

#![allow(dead_code)]

use seccompiler::sock_filter;

pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
pub const AUDIT_ARCH_I386: u32 = 0x4000_0003; // a foreign arch, for guard tests

pub fn native_audit() -> u32 {
    if cfg!(target_arch = "x86_64") {
        AUDIT_ARCH_X86_64
    } else {
        AUDIT_ARCH_AARCH64
    }
}

/// Build a 64-byte `struct seccomp_data` image (little-endian).
pub fn seccomp_data(nr: u32, arch: u32, args: [u64; 6]) -> [u8; 64] {
    let mut d = [0u8; 64];
    d[0..4].copy_from_slice(&nr.to_le_bytes());
    d[4..8].copy_from_slice(&arch.to_le_bytes());
    for (i, a) in args.iter().enumerate() {
        let off = 16 + i * 8;
        d[off..off + 8].copy_from_slice(&a.to_le_bytes());
    }
    d
}

fn load_u32(data: &[u8; 64], off: u32) -> u32 {
    let o = off as usize;
    u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]])
}

/// Evaluate a classic-BPF seccomp program, returning `(SECCOMP_RET value,
/// instructions executed)`. Covers the full cBPF subset seccomp can emit.
pub fn eval(prog: &[sock_filter], data: &[u8; 64]) -> (u32, usize) {
    let mut a: u32 = 0;
    let mut x: u32 = 0;
    let mut mem = [0u32; 16];
    let mut pc: usize = 0;
    let mut steps = 0usize;

    loop {
        steps += 1;
        assert!(steps < 1_000_000, "cBPF program did not terminate");
        let ins = &prog[pc];
        pc += 1;
        let class = ins.code & 0x07;
        match class {
            0x00 | 0x01 => {
                let mode = ins.code & 0xe0;
                let val = match mode {
                    0x00 => ins.k,                 // IMM
                    0x20 => load_u32(data, ins.k), // ABS (W)
                    0x60 => mem[ins.k as usize],   // MEM
                    0x80 => data.len() as u32,     // LEN
                    other => panic!("unhandled LD mode {other:#x}"),
                };
                if class == 0x00 {
                    a = val;
                } else {
                    x = val;
                }
            }
            0x02 => mem[ins.k as usize] = a,
            0x03 => mem[ins.k as usize] = x,
            0x04 => {
                let op = ins.code & 0xf0;
                let src = if ins.code & 0x08 != 0 { x } else { ins.k };
                a = match op {
                    0x00 => a.wrapping_add(src),
                    0x10 => a.wrapping_sub(src),
                    0x20 => a.wrapping_mul(src),
                    0x30 => a / src,
                    0x40 => a | src,
                    0x50 => a & src,
                    0x60 => a << src,
                    0x70 => a >> src,
                    0x80 => (!a).wrapping_add(1),
                    0xa0 => a ^ src,
                    other => panic!("unhandled ALU op {other:#x}"),
                };
            }
            0x05 => {
                let op = ins.code & 0xf0;
                if op == 0x00 {
                    pc += ins.k as usize; // JA
                    continue;
                }
                let cmp = if ins.code & 0x08 != 0 { x } else { ins.k };
                let take = match op {
                    0x10 => a == cmp,
                    0x20 => a > cmp,
                    0x30 => a >= cmp,
                    0x40 => (a & cmp) != 0,
                    other => panic!("unhandled JMP op {other:#x}"),
                };
                pc += if take { ins.jt as usize } else { ins.jf as usize };
            }
            0x06 => return (if ins.code & 0x18 == 0x10 { a } else { ins.k }, steps),
            0x07 => {
                if ins.code & 0x80 == 0 {
                    x = a;
                } else {
                    a = x;
                }
            }
            other => panic!("unhandled BPF class {other:#x}"),
        }
    }
}

/// Size (instruction count) and evaluation-cost metrics for a program.
#[derive(Clone, Copy, Debug)]
pub struct Metrics {
    pub size: usize,
    pub worst_steps: usize,
    pub mean_steps: f64,
}

/// Measure a program over a set of inputs: static size, worst-case executed
/// instructions, and mean executed instructions across the inputs.
pub fn measure(prog: &[sock_filter], inputs: &[[u8; 64]]) -> Metrics {
    let mut worst = 0usize;
    let mut total = 0usize;
    for data in inputs {
        let (_ret, steps) = eval(prog, data);
        worst = worst.max(steps);
        total += steps;
    }
    Metrics {
        size: prog.len(),
        worst_steps: worst,
        mean_steps: if inputs.is_empty() {
            0.0
        } else {
            total as f64 / inputs.len() as f64
        },
    }
}

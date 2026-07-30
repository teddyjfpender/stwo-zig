//! Reference interpreter for witness-JIT bytecode.
//!
//! Executes a [`WitnessProgram`] for a single row with exact M31 and wrapping-integer
//! arithmetic, returning the committed columns, multiplicity pushes, and lookup words.
//!
//! This is the **local soundness instrument**: with no pod, the CUDA-vs-host proof
//! byte-equality gate cannot run, so correctness of a recorded program is established
//! here by differential test against the native Rust reference of each component
//! ([`super::programs`]). The field formulas are self-contained (no crate-graph
//! dependency) and are the *same* formulas the CUDA preamble in [`super::codegen`]
//! emits — so an interpreter match is evidence for a codegen match, to be confirmed by
//! the pod gate.

use std::collections::HashMap;

use super::isa::{WitnessOp, WitnessProgram, M31_P};

/// Exact M31 addition of canonical inputs.
#[inline]
pub(crate) fn m31_add(a: u32, b: u32) -> u32 {
    let s = a + b;
    if s >= M31_P {
        s - M31_P
    } else {
        s
    }
}

#[inline]
pub(crate) fn m31_sub(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        a + M31_P - b
    }
}

#[inline]
pub(crate) fn m31_neg(a: u32) -> u32 {
    let n = M31_P - a;
    if n == M31_P {
        0
    } else {
        n
    }
}

#[inline]
/// x^(P-2) by square-and-multiply over the fixed exponent 2^31 - 3 — the same
/// schedule the CUDA helper emits, total (inverse(0) = 0).
pub(crate) fn m31_inverse(a: u32) -> u32 {
    let mut result = a; // consumes exponent bit 30
    for bit in (0..=29).rev() {
        result = m31_mul(result, result);
        if bit != 1 {
            result = m31_mul(result, a);
        }
    }
    result
}

pub(crate) fn m31_mul(a: u32, b: u32) -> u32 {
    // Same reduction as the CUDA preamble `stwo_m31_mul`.
    let product = a as u64 * b as u64;
    (((((product >> 31) + product + 1) >> 31) + product) & M31_P as u64) as u32
}

/// A resolved `deduce_output` table: given `(table, key, limb)` return the limb value.
/// In production this is a device-resident LUT read; in tests it is a synthetic memory
/// image (see [`super::programs`]).
pub trait TableOracle {
    fn table_limb(&self, table: u32, key: u32, limb: u32) -> u32;
}

impl<F: Fn(u32, u32, u32) -> u32> TableOracle for F {
    fn table_limb(&self, table: u32, key: u32, limb: u32) -> u32 {
        self(table, key, limb)
    }
}

/// Host implementations of the COMPUTED deduces (ISA-V3 `DeduceCall`). The interpreter
/// delegates so its reference semantics come from the CALLER's own host functions
/// (stwo-cairo's `fast_deduction`) — never a duplicated reimplementation the
/// differential could not catch drifting.
pub trait DeduceHost {
    /// `kind` is the [`super::isa::DeduceKind`] discriminant; `args`/return follow the
    /// fixed per-kind widths (felts flattened to 28 canonical limbs).
    fn deduce(&mut self, kind: u32, args: &[u32]) -> Vec<u32>;
}

/// The no-deduce host: panics on any `DeduceCall`. For programs recorded from
/// opcode-family bodies (which contain none) and legacy call sites.
pub struct NoDeduceHost;
impl DeduceHost for NoDeduceHost {
    fn deduce(&mut self, kind: u32, _args: &[u32]) -> Vec<u32> {
        panic!("program contains DeduceCall(kind={kind}) but no DeduceHost was provided")
    }
}

/// The per-row outputs of an interpreted witness program.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RowOutputs {
    /// `columns[col]` = committed trace value.
    pub columns: Vec<u32>,
    /// `(table, key)` multiplicity pushes in emission order.
    pub mults: Vec<(u32, u32)>,
    /// `lookup_words[word_index]` = emitted lookup coordinate.
    pub lookup_words: Vec<u32>,
    /// `sub_words[word_index]` = emitted sub-component input word.
    pub sub_words: Vec<u32>,
}

/// Interpret `program` for one row.
///
/// `inputs[slot]` supplies each [`WitnessOp::Input`]. Panics (in debug) on a malformed
/// program (out-of-range register) — the recorder guarantees SSA well-formedness, so a
/// panic here is a recorder bug, exactly the class the differential tests catch.
pub fn interpret_row(
    program: &WitnessProgram,
    inputs: &[u32],
    tables: &dyn TableOracle,
) -> RowOutputs {
    interpret_row_with(program, inputs, tables, &mut NoDeduceHost)
}

/// [`interpret_row`] with a [`DeduceHost`] for ISA-V3 computed deduces.
pub fn interpret_row_with(
    program: &WitnessProgram,
    inputs: &[u32],
    tables: &dyn TableOracle,
    host: &mut dyn DeduceHost,
) -> RowOutputs {
    let mut regs = vec![0u32; program.n_regs as usize];
    let mut deduce_args: Vec<u32> = Vec::new();
    let mut out = RowOutputs {
        columns: vec![0u32; program.n_cols as usize],
        mults: Vec::new(),
        lookup_words: vec![0u32; program.n_lookup_words as usize],
        sub_words: vec![0u32; program.n_sub_words as usize],
    };

    for inst in &program.insts {
        let a = inst.a as usize;
        let b = inst.b as usize;
        let op = WitnessOp::from_raw(inst.op).expect("valid opcode");
        let value = match op {
            WitnessOp::Input => inputs[inst.a as usize],
            WitnessOp::Const => inst.imm,
            WitnessOp::M31Add => m31_add(regs[a], regs[b]),
            WitnessOp::M31Sub => m31_sub(regs[a], regs[b]),
            WitnessOp::M31Mul => m31_mul(regs[a], regs[b]),
            WitnessOp::M31Neg => m31_neg(regs[a]),
            WitnessOp::U16Add => (regs[a].wrapping_add(regs[b])) & 0xFFFF,
            WitnessOp::U16Shl => (regs[a] << inst.imm) & 0xFFFF,
            WitnessOp::U16Shr => (regs[a] & 0xFFFF) >> inst.imm,
            WitnessOp::U16And => regs[a] & inst.imm,
            WitnessOp::U32Add => regs[a].wrapping_add(regs[b]),
            WitnessOp::U32Sub => regs[a].wrapping_sub(regs[b]),
            WitnessOp::U32Mul => regs[a].wrapping_mul(regs[b]),
            WitnessOp::U32Shl => regs[a].wrapping_shl(inst.imm),
            WitnessOp::U32Shr => regs[a].wrapping_shr(inst.imm),
            WitnessOp::U32And => regs[a] & inst.imm,
            WitnessOp::U32Xor => regs[a] ^ regs[b],
            WitnessOp::AsM31 => regs[a] % M31_P,
            WitnessOp::Trunc16 => regs[a] & 0xFFFF,
            WitnessOp::M31Inverse => m31_inverse(regs[a]),
            WitnessOp::M31Eq => u32::from(regs[a] == regs[b]),
            WitnessOp::TableLimb => tables.table_limb(inst.b, regs[a], inst.imm),
            WitnessOp::ColWrite => {
                out.columns[inst.imm as usize] = regs[a];
                continue;
            }
            WitnessOp::MultPush => {
                out.mults.push((inst.imm, regs[a]));
                continue;
            }
            WitnessOp::LookupWord => {
                out.lookup_words[inst.imm as usize] = regs[a];
                continue;
            }
            WitnessOp::SubWord => {
                out.sub_words[inst.imm as usize] = regs[a];
                continue;
            }
            WitnessOp::DeduceArg => {
                deduce_args.push(regs[a]);
                continue;
            }
            WitnessOp::DeduceCall => {
                let outs = host.deduce(inst.imm, &deduce_args);
                assert_eq!(
                    outs.len(),
                    inst.b as usize,
                    "DeduceHost returned wrong output width for kind {}",
                    inst.imm
                );
                let base = inst.dst as usize;
                regs[base..base + outs.len()].copy_from_slice(&outs);
                deduce_args.clear();
                continue;
            }
        };
        regs[inst.dst as usize] = value;
    }
    out
}

/// Interpret over many rows (convenience for column-major differential comparison).
pub fn interpret_rows(
    program: &WitnessProgram,
    row_inputs: &[Vec<u32>],
    tables: &dyn TableOracle,
) -> Vec<RowOutputs> {
    row_inputs
        .iter()
        .map(|inputs| interpret_row(program, inputs, tables))
        .collect()
}

/// [`interpret_rows`] with a [`DeduceHost`].
pub fn interpret_rows_with(
    program: &WitnessProgram,
    row_inputs: &[Vec<u32>],
    tables: &dyn TableOracle,
    host: &mut dyn DeduceHost,
) -> Vec<RowOutputs> {
    row_inputs
        .iter()
        .map(|inputs| interpret_row_with(program, inputs, tables, host))
        .collect()
}

/// Column-major materialization (what the committed device buffers look like), keyed by
/// column index — useful for byte-compare against a host writer's columns.
pub fn columns_major(rows: &[RowOutputs], n_cols: usize) -> HashMap<usize, Vec<u32>> {
    let mut cols: HashMap<usize, Vec<u32>> = HashMap::new();
    for c in 0..n_cols {
        cols.insert(c, rows.iter().map(|r| r.columns[c]).collect());
    }
    cols
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m31_formulas_match_naive_reduction() {
        // Cross-check the fast reduction against the naive `(a*b) % P` on edge values.
        for &(a, b) in &[
            (0u32, 0u32),
            (1, 1),
            (M31_P - 1, M31_P - 1),
            (2147483646, 2),
            (123456789, 987654321 % M31_P),
        ] {
            assert_eq!(m31_mul(a, b), ((a as u64 * b as u64) % M31_P as u64) as u32);
            assert_eq!(m31_add(a, b), ((a as u64 + b as u64) % M31_P as u64) as u32);
        }
    }

    #[test]
    fn m31_inverse_matches_field_inverse() {
        // The fixed square-and-multiply schedule computes x^(P-2); total at 0.
        assert_eq!(m31_inverse(0), 0);
        assert_eq!(m31_inverse(1), 1);
        for x in [2u32, 3, 7, 65536, M31_P - 1, 0x12345678 % M31_P] {
            assert_eq!(m31_mul(m31_inverse(x), x), 1, "inv({x})*{x} != 1");
        }
    }
}

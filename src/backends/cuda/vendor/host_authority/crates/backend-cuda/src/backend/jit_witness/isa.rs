//! Witness-JIT V1 bytecode ISA.
//!
//! The constraint-JIT lane ([`super::super::jit`]) records a component's *constraint*
//! tree to bytecode and JIT-compiles a fused CUDA kernel. Witness writers have the same
//! per-row shape — decode + M31/integer arithmetic + column writes + lookup-tuple
//! emission + multiplicity pushes — but the arithmetic domain is wider: the generated
//! `write_trace_simd` bodies work in `PackedUInt16` (16-bit wrapping) and `PackedM31`
//! (field), with instruction-decode shifts/masks and memory-table `deduce_output`
//! lookups.
//!
//! This module defines a *separate*, self-contained bytecode for that domain. It is
//! deliberately dependency-light (std only, self-contained M31 arithmetic matching the
//! CUDA preamble in `super::codegen`) so the recorder, reference interpreter, and
//! CUDA codegen can be unit-tested as pure logic without a GPU and without the
//! prover-side crate graph — the local soundness instrument while the pod
//! byte-equality gate (`STWO_CUDA_WITNESS_JIT` + the stwo-cairo differential) is out
//! of reach.
//!
//! Register model: a single flat u32 register file per row-thread (SSA — every
//! register written exactly once by the recorder). A register's *interpretation*
//! (canonical M31 in `[0, P)`, 16-bit raw, or 32-bit raw) is implied by the opcode
//! that produced/consumes it, exactly as the source Rust's `PackedM31` / `PackedUInt16`
//! types imply it. Keeping one register file (rather than the constraint lane's
//! base/ext split) mirrors the fact that a witness row is all base-field/integer work
//! — there is no secure-field extension tower here.

#![allow(dead_code)]

/// Mersenne-31 prime, `2^31 - 1`. Field values are canonical in `[0, P)`.
pub const M31_P: u32 = (1 << 31) - 1;

/// Witness-JIT opcodes. `#[repr(u8)]` so the instruction is a fixed-layout POD shared
/// with the CUDA codegen and (eventually) an FFI upload.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum WitnessOp {
    // --- Leaves ---
    /// Read packed input field `a` (e.g. CasmState pc=0/ap=1/fp=2) for this row.
    Input = 0,
    /// Materialize the constant in `imm`.
    Const = 1,

    // --- M31 field arithmetic (operands canonical in [0, P), result canonical) ---
    M31Add = 2,
    M31Sub = 3,
    M31Mul = 4,
    M31Neg = 5,

    // --- 16-bit wrapping / bit ops (PackedUInt16 semantics) ---
    /// `(a + b) mod 2^16`.
    U16Add = 6,
    /// `(a << imm) mod 2^16`.
    U16Shl = 7,
    /// `a >> imm` (logical).
    U16Shr = 8,
    /// `a & imm`.
    U16And = 9,

    // --- 32-bit wrapping / bit ops (for wider writers: blake g, triple-xor, …) ---
    U32Add = 10,
    U32Sub = 11,
    U32Mul = 12,
    U32Shl = 13,
    U32Shr = 14,
    U32And = 15,
    U32Xor = 16,

    // --- Conversions ---
    /// Reinterpret a raw value as M31 by canonical reduction (`a mod P`). For 16-bit
    /// inputs this is the identity (`a < 2^16 < P`), matching `PackedUInt16::as_m31`.
    AsM31 = 17,
    /// Truncate an M31/other value to 16 bits (`a & 0xFFFF`), matching
    /// `PackedUInt16::from_m31`. Identity for the 9-bit memory limbs the decoders read.
    Trunc16 = 18,

    // --- Table reads (deduce_output modelled as a device-resident LUT) ---
    /// Read limb `imm` of table `b` at key = register `a`. Models
    /// `<sub_state>.deduce_output(key)` once the sibling component's table is
    /// device-resident: `memory_address_to_id` returns the id in limb 0;
    /// `memory_id_to_big` returns the value's 9-bit limbs in `imm`. This is the
    /// opcode that turns a host `HashMap` lookup into a device indexed read — see the
    /// module-level blocker note in `super`.
    TableLimb = 19,

    // --- Outputs ---
    /// Commit register `a` to trace column `imm`.
    ColWrite = 20,
    /// Push a multiplicity: `atomicAdd(&counts[table=imm][key=reg a], 1)`.
    MultPush = 21,
    /// Emit a lookup-tuple word: term `imm` carries the value of register `a`
    /// (element-major store into the component's logup-input buffer). The recorder
    /// emits one per tuple coordinate; the finalize lane consumes them exactly as the
    /// host `lookup_data.X_k[row]` arrays are consumed.
    LookupWord = 22,
    /// Emit a sub-component input word: word `imm` carries register `a` (element-major
    /// store into the flat sub-input buffer, `row * n_sub_words + imm`). These carry
    /// the values the host writer pushes into `SubComponentInputs` (the feeds for
    /// memory/range-check/verify_instruction multiplicity counting) — NOT derivable
    /// from the lookup words in general (e.g. add_opcode's verify_instruction
    /// sub-tuple uses different intermediates than its lookup tuple).
    SubWord = 23,
    /// dst = a^(P-2) — total (inverse(0) = 0), matching `FieldExpOps::inverse` power
    /// semantics on canonical inputs.
    M31Inverse = 24,
    /// dst = (a == b) ? 1 : 0 — the 0/1-register mask representation (ISA-V2).
    M31Eq = 25,

    // --- Computed deduces (ISA-V3, the fp256/EC/blake family — DEDUCE_DESIGN.md) ---
    /// Push register `a` as the NEXT argument of the pending [`Self::DeduceCall`]
    /// (argument order = push order). Writes no register.
    DeduceArg = 26,
    /// Run computed deduce `imm` (a [`DeduceKind`] discriminant) over the accumulated
    /// [`Self::DeduceArg`]s (consumed), defining `b` consecutive OUTPUT registers
    /// `dst..dst+b`. The device lowering calls a `__device__` function transcribed
    /// from the corresponding host `fast_deduction` routine; the interpreter delegates
    /// to a caller-supplied [`super::interp::DeduceHost`] (so the reference
    /// implementation is the HOST's own, never a duplicate).
    DeduceCall = 27,
}

/// Computed-deduce discriminants (the `imm` of [`WitnessOp::DeduceCall`]). Arg/output
/// widths are FIXED per kind — a mismatch is a recorder bug, asserted at record time.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DeduceKind {
    /// `fast_deduction::blake::PackedBlakeG`: `[a,b,c,d,m0,m1] -> [a',b',c',d']`
    /// (full 32-bit words).
    BlakeG = 0,
    /// `fast_deduction::blake::PackedBlakeRoundSigma`: `round -> [sigma; 16]` (M31s).
    BlakeRoundSigma = 1,
    /// `fast_deduction::pedersen::PackedPartialEcMulWindowBits18`: one windowed EC-mul
    /// round; args = chain, round, 14 windows, 2 accumulator felts as 28 limbs each
    /// (2+14+56 = 72), outputs the same shape (72).
    PartialEcMulW18 = 2,
    /// `fast_deduction::pedersen::PackedPedersenPointsTableWindowBits18`:
    /// `index -> [x_felt, y_felt]` as 56 limb words.
    PedersenPointsTableW18 = 3,
    /// fp256 body arithmetic (the partial_ec_mul writers' inline `Felt252`
    /// operators): args = `[a limbs | b limbs]` (56), out = result limbs (28).
    /// Host semantics = `Felt252`'s canonical-value field ops (cpu.rs).
    FeltAdd = 4,
    FeltSub = 5,
    FeltMul = 6,
    /// Division by zero panics on the host; the writers only divide by EC slope
    /// denominators, never zero on valid traces.
    FeltDiv = 7,
    /// Cairo Poseidon fast-deduction primitives. Width27 felts use ten canonical
    /// M31 words throughout; chain outputs preserve `(chain, round, state)` shape.
    PoseidonRoundKeys = 8,
    Cube252 = 9,
    PoseidonFullRoundChain = 10,
    Poseidon3PartialRoundsChain = 11,
}

/// Runtime state a computed deduce reads outside its explicit arguments.
///
/// This classification is exhaustive by design: adding a deduce kind must
/// choose a state contract before codegen or a compiled proof can admit it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DeduceModuleState {
    SelfContained,
    PedersenTableColumnsAndRowsV1,
}

impl DeduceKind {
    pub const fn from_raw(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::BlakeG,
            1 => Self::BlakeRoundSigma,
            2 => Self::PartialEcMulW18,
            3 => Self::PedersenPointsTableW18,
            4 => Self::FeltAdd,
            5 => Self::FeltSub,
            6 => Self::FeltMul,
            7 => Self::FeltDiv,
            8 => Self::PoseidonRoundKeys,
            9 => Self::Cube252,
            10 => Self::PoseidonFullRoundChain,
            11 => Self::Poseidon3PartialRoundsChain,
            _ => return None,
        })
    }
    /// (n_args, n_outs) — the fixed widths.
    pub const fn shape(self) -> (usize, usize) {
        match self {
            Self::BlakeG => (6, 4),
            Self::BlakeRoundSigma => (1, 16),
            Self::PartialEcMulW18 => (72, 72),
            Self::PedersenPointsTableW18 => (1, 56),
            Self::FeltAdd | Self::FeltSub | Self::FeltMul | Self::FeltDiv => (56, 28),
            Self::PoseidonRoundKeys => (1, 30),
            Self::Cube252 => (10, 10),
            Self::PoseidonFullRoundChain => (32, 32),
            Self::Poseidon3PartialRoundsChain => (42, 42),
        }
    }

    pub const fn module_state(self) -> DeduceModuleState {
        match self {
            Self::PartialEcMulW18 | Self::PedersenPointsTableW18 => {
                DeduceModuleState::PedersenTableColumnsAndRowsV1
            }
            Self::BlakeG
            | Self::BlakeRoundSigma
            | Self::FeltAdd
            | Self::FeltSub
            | Self::FeltMul
            | Self::FeltDiv
            | Self::PoseidonRoundKeys
            | Self::Cube252
            | Self::PoseidonFullRoundChain
            | Self::Poseidon3PartialRoundsChain => DeduceModuleState::SelfContained,
        }
    }
}

impl WitnessOp {
    pub const fn from_raw(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Input,
            1 => Self::Const,
            2 => Self::M31Add,
            3 => Self::M31Sub,
            4 => Self::M31Mul,
            5 => Self::M31Neg,
            6 => Self::U16Add,
            7 => Self::U16Shl,
            8 => Self::U16Shr,
            9 => Self::U16And,
            10 => Self::U32Add,
            11 => Self::U32Sub,
            12 => Self::U32Mul,
            13 => Self::U32Shl,
            14 => Self::U32Shr,
            15 => Self::U32And,
            16 => Self::U32Xor,
            17 => Self::AsM31,
            18 => Self::Trunc16,
            19 => Self::TableLimb,
            20 => Self::ColWrite,
            21 => Self::MultPush,
            22 => Self::LookupWord,
            23 => Self::SubWord,
            24 => Self::M31Inverse,
            25 => Self::M31Eq,
            26 => Self::DeduceArg,
            27 => Self::DeduceCall,
            _ => return None,
        })
    }

    /// True for opcodes that write a new SSA register in `dst` (`DeduceCall` defines
    /// a BANK of `b` registers starting at `dst`; `DeduceArg` defines none).
    pub const fn writes_dst(self) -> bool {
        !matches!(
            self,
            Self::ColWrite | Self::MultPush | Self::LookupWord | Self::SubWord | Self::DeduceArg
        )
    }
}

/// One witness-JIT instruction. Fixed 16-byte C-compatible layout: `op`, one pad byte,
/// a `u16` destination register, two `u32` source-register operands, and a `u32`
/// immediate (constant / shift amount / mask / column index / table id / limb index).
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WitnessInst {
    pub op: u8,
    pub pad: u8,
    pub dst: u16,
    pub a: u32,
    pub b: u32,
    pub imm: u32,
}

impl WitnessInst {
    pub const fn new(op: WitnessOp, dst: u16, a: u32, b: u32, imm: u32) -> Self {
        Self {
            op: op as u8,
            pad: 0,
            dst,
            a,
            b,
            imm,
        }
    }
}

/// A recorded witness program: the per-row instruction stream plus the shape metadata
/// the codegen and dispatch need. Statement-independent by construction — it depends
/// only on the component's decode structure, never on the trace being proven — so its
/// [`semantic_hash`](Self::semantic_hash) is a stable kernel-cache key across
/// statements, inputs, and processes (the same property the constraint lane relies on).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessProgram {
    /// Human-readable component label (for logs / cache diagnostics only — NOT hashed).
    pub label: String,
    pub insts: Vec<WitnessInst>,
    /// Number of SSA registers (max `dst` + 1).
    pub n_regs: u32,
    /// Number of packed input fields read via [`WitnessOp::Input`].
    pub n_inputs: u32,
    /// Number of committed trace columns (max `ColWrite` column index + 1).
    pub n_cols: u32,
    /// Number of distinct multiplicity tables fed via [`WitnessOp::MultPush`].
    pub n_mult_tables: u32,
    /// Number of lookup words emitted per row via [`WitnessOp::LookupWord`].
    pub n_lookup_words: u32,
    /// Number of sub-component input words emitted per row via [`WitnessOp::SubWord`].
    pub n_sub_words: u32,
}

impl WitnessProgram {
    /// Collision-resistant identity of the exact typed program body. The
    /// human label is deliberately excluded; instruction count, every encoded
    /// instruction field, and all six structural counts are domain-separated.
    pub fn semantic_identity(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"stwo-cuda-witness-program-semantic-identity-v1\0");
        hasher.update(
            &u64::try_from(self.insts.len())
                .expect("witness instruction count fits u64")
                .to_le_bytes(),
        );
        for inst in &self.insts {
            hasher.update(&[inst.op, inst.pad]);
            hasher.update(&inst.dst.to_le_bytes());
            hasher.update(&inst.a.to_le_bytes());
            hasher.update(&inst.b.to_le_bytes());
            hasher.update(&inst.imm.to_le_bytes());
        }
        for count in [
            self.n_regs,
            self.n_inputs,
            self.n_cols,
            self.n_mult_tables,
            self.n_lookup_words,
            self.n_sub_words,
        ] {
            hasher.update(&count.to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// Non-authoritative FNV-1a cache key over the instruction stream and
    /// structural counts (not the label). Authority must use
    /// [`semantic_identity`](Self::semantic_identity).
    pub fn semantic_hash(&self) -> u64 {
        let mut hash = 0xcbf29ce484222325u64;
        let mut mix = |bytes: &[u8]| {
            for byte in bytes {
                hash ^= *byte as u64;
                hash = hash.wrapping_mul(0x100000001b3);
            }
        };
        for inst in &self.insts {
            mix(&[inst.op, inst.pad]);
            mix(&inst.dst.to_le_bytes());
            mix(&inst.a.to_le_bytes());
            mix(&inst.b.to_le_bytes());
            mix(&inst.imm.to_le_bytes());
        }
        for count in [
            self.n_regs,
            self.n_inputs,
            self.n_cols,
            self.n_mult_tables,
            self.n_lookup_words,
            self.n_sub_words,
        ] {
            mix(&count.to_le_bytes());
        }
        hash
    }

    /// Total instruction count — the size-governor metric (shared with the constraint
    /// lane's `STWO_JIT_MAX_KERNEL_INSTRS` cap).
    pub fn n_instrs(&self) -> usize {
        self.insts.len()
    }
}

/// ABI layout invariants asserted before any codegen/upload — the same guard the
/// constraint lane runs (`validate_eval_program_abi_layout_v1`). A layout drift here
/// would silently corrupt an uploaded instruction stream.
pub fn validate_isa_layout() -> Result<(), String> {
    use core::mem::{align_of, offset_of, size_of};
    if size_of::<WitnessInst>() != 16 {
        return Err(format!(
            "WitnessInst size {} != 16",
            size_of::<WitnessInst>()
        ));
    }
    if align_of::<WitnessInst>() != 4 {
        return Err(format!(
            "WitnessInst align {} != 4",
            align_of::<WitnessInst>()
        ));
    }
    if offset_of!(WitnessInst, op) != 0
        || offset_of!(WitnessInst, pad) != 1
        || offset_of!(WitnessInst, dst) != 2
        || offset_of!(WitnessInst, a) != 4
        || offset_of!(WitnessInst, b) != 8
        || offset_of!(WitnessInst, imm) != 12
    {
        return Err("WitnessInst field offset mismatch".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_deduce_kind_has_exact_module_state() {
        for raw in 0..=11 {
            let kind = DeduceKind::from_raw(raw).unwrap();
            assert_eq!(
                kind.module_state(),
                if matches!(
                    kind,
                    DeduceKind::PartialEcMulW18 | DeduceKind::PedersenPointsTableW18
                ) {
                    DeduceModuleState::PedersenTableColumnsAndRowsV1
                } else {
                    DeduceModuleState::SelfContained
                }
            );
        }
        assert_eq!(DeduceKind::from_raw(12), None);
    }

    #[test]
    fn abi_layout_is_stable() {
        validate_isa_layout().unwrap();
    }

    #[test]
    fn opcode_roundtrip_is_total() {
        // Every discriminant round-trips, and the first unused value is rejected.
        for raw in 0u8..=27 {
            let op = WitnessOp::from_raw(raw).expect("known opcode");
            assert_eq!(op as u8, raw);
        }
        assert!(WitnessOp::from_raw(28).is_none());
    }

    #[test]
    fn semantic_hash_is_content_addressed_and_label_independent() {
        let base = WitnessProgram {
            label: "add_opcode".to_string(),
            insts: vec![
                WitnessInst::new(WitnessOp::Input, 0, 0, 0, 0),
                WitnessInst::new(WitnessOp::ColWrite, 0, 0, 0, 0),
            ],
            n_regs: 1,
            n_inputs: 1,
            n_cols: 1,
            n_mult_tables: 0,
            n_lookup_words: 0,
            n_sub_words: 0,
        };
        // Renaming the component must not change the cache key (kernels are shared by
        // structure, not by name).
        let mut relabeled = base.clone();
        relabeled.label = "assert_eq_opcode".to_string();
        assert_eq!(base.semantic_hash(), relabeled.semantic_hash());
        assert_eq!(base.semantic_identity(), relabeled.semantic_identity());
        assert_eq!(
            base.semantic_identity()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "259930b2e215076bccab908784c41a8837ec01f85689a7d4dbcf7d944ef2622d"
        );

        // A real bytecode difference must change it.
        let mut mutated = base.clone();
        mutated.insts[0].imm = 1;
        assert_ne!(base.semantic_hash(), mutated.semantic_hash());
        assert_ne!(base.semantic_identity(), mutated.semantic_identity());

        for field in 0..5 {
            let mut mutated = base.clone();
            match field {
                0 => mutated.insts[0].op += 1,
                1 => mutated.insts[0].pad += 1,
                2 => mutated.insts[0].dst += 1,
                3 => mutated.insts[0].a += 1,
                4 => mutated.insts[0].b += 1,
                _ => unreachable!(),
            }
            assert_ne!(base.semantic_identity(), mutated.semantic_identity());
        }
        for count in 0..6 {
            let mut mutated = base.clone();
            match count {
                0 => mutated.n_regs += 1,
                1 => mutated.n_inputs += 1,
                2 => mutated.n_cols += 1,
                3 => mutated.n_mult_tables += 1,
                4 => mutated.n_lookup_words += 1,
                5 => mutated.n_sub_words += 1,
                _ => unreachable!(),
            }
            assert_ne!(base.semantic_identity(), mutated.semantic_identity());
        }
    }
}

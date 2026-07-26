//! [`RecordingWitnessEval`] records a generic witness row as scalar SSA.
//!
//! Instantiating a transformed row body on this evaluator emits a deterministic
//! [`WitnessProgram`]. Unsupported operations poison their dependent effects, and the
//! exporter rejects every recording with poison; partial programs never enter a
//! released bundle.
//!
//! # Value handles
//!
//! Values are opaque SSA-register handles wrapped in [`RecVal`]. Any operation
//! consuming [`RecVal::Poison`] also produces poison, preserving an exact census of
//! missing instruction-set coverage in [`RecordingOutput::poison_ops`].

use std::collections::{BTreeMap, BTreeSet};

use super::bytecode::isa::{DeduceKind, WitnessProgram};
use super::bytecode::recording::{Val, WitnessRecorder};

use crate::witness::witness_eval::{
    WitnessEval, FELT_N_LIMBS, SLOT_ENABLER, TABLE_ADDR_TO_ID, TABLE_ID_TO_BIG,
};

/// An SSA-register handle, or a poison marker for an op the 32-bit ISA cannot express.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RecVal {
    Ok(Val),
    Poison,
}

/// A recorded felt handle: either a keyed table read (`memory_id_to_big`) whose limbs are
/// materialized lazily, or an explicit bundle of limb handles (`felt_from_limbs`).
#[derive(Clone, Debug)]
pub enum RecFelt {
    /// `mem_id_to_value` result — `felt_get_m31(_, i)` reads `table_limb(TABLE_ID_TO_BIG,
    /// key, i)`.
    Deduced { key: Val },
    /// `felt_from_limbs` bookkeeping — `felt_get_m31(_, i)` is `v[i]` (no emit).
    Limbs(Vec<RecVal>),
}

/// The output of recording one per-row body: the [`WitnessProgram`] plus the honest
/// census of what could NOT be recorded (the ISA-V2 backlog, not a failure).
#[derive(Clone, Debug)]
pub struct RecordingOutput {
    /// The recorded per-row bytecode.
    pub program: WitnessProgram,
    /// Columns whose value was poisoned (not committed to the program).
    pub poisoned_cols: BTreeSet<usize>,
    /// Lookup words whose value was poisoned (not emitted).
    pub poisoned_lookup_words: BTreeSet<usize>,
    /// Sub-input words whose value was poisoned (not emitted).
    pub poisoned_sub_words: BTreeSet<usize>,
    /// Census of EXTENDED / poison-producing ops encountered: op name → count.
    pub poison_ops: BTreeMap<&'static str, usize>,
}

/// Records a generic per-row witness body into [`WitnessProgram`] bytecode.
pub struct RecordingWitnessEval {
    recorder: WitnessRecorder,
    poisoned_cols: BTreeSet<usize>,
    poisoned_lookup_words: BTreeSet<usize>,
    poisoned_sub_words: BTreeSet<usize>,
    poison_ops: BTreeMap<&'static str, usize>,
    /// `enabler()` input slot. Opcodes: `SLOT_ENABLER` (= 3, right after pc/ap/fp).
    /// Builtins: the slot right after the flattened input words (the lane feeds the
    /// enabler column there).
    enabler_slot: u32,
    /// `iota()` input slot (the row-index column the builtin lane feeds), or `None` —
    /// opcode bodies never call `iota()`; if one somehow does, `None` poisons honestly.
    iota_slot: Option<u32>,
}

impl RecordingWitnessEval {
    pub fn new(label: impl Into<String>) -> Self {
        Self::with_slots(label, SLOT_ENABLER, None)
    }

    /// Builtin-lane constructor: the flattened input words occupy slots `0..K`, the
    /// enabler and iota columns the slots the transformer assigned after them.
    pub fn with_slots(label: impl Into<String>, enabler_slot: u32, iota_slot: Option<u32>) -> Self {
        Self {
            recorder: WitnessRecorder::new(label),
            poisoned_cols: BTreeSet::new(),
            poisoned_lookup_words: BTreeSet::new(),
            poisoned_sub_words: BTreeSet::new(),
            poison_ops: BTreeMap::new(),
            enabler_slot,
            iota_slot,
        }
    }

    /// Finish recording and package the program + poison census.
    pub fn finish(self) -> RecordingOutput {
        RecordingOutput {
            program: self.recorder.finish(),
            poisoned_cols: self.poisoned_cols,
            poisoned_lookup_words: self.poisoned_lookup_words,
            poisoned_sub_words: self.poisoned_sub_words,
            poison_ops: self.poison_ops,
        }
    }

    /// Census a poison-producing EXTENDED op and return the poison marker (emits nothing).
    #[inline]
    fn poison(&mut self, op: &'static str) -> RecVal {
        *self.poison_ops.entry(op).or_insert(0) += 1;
        RecVal::Poison
    }

    /// Poison-propagating unary ISA-core op.
    #[inline]
    fn un(&mut self, a: RecVal, f: impl FnOnce(&mut WitnessRecorder, Val) -> Val) -> RecVal {
        match a {
            RecVal::Ok(x) => RecVal::Ok(f(&mut self.recorder, x)),
            RecVal::Poison => RecVal::Poison,
        }
    }

    /// Flatten a felt handle to 28 limb registers for a deduce argument: `Limbs` uses
    /// the handles directly; `Deduced` materializes each limb as a `TableLimb` read
    /// (the same op `felt_get_m31` emits). `None` if any limb is poisoned.
    fn felt_arg_limbs(&mut self, f: &RecFelt) -> Option<Vec<Val>> {
        match f {
            RecFelt::Deduced { key } => Some(
                (0..FELT_N_LIMBS)
                    .map(|i| self.recorder.table_limb(TABLE_ID_TO_BIG, *key, i as u32))
                    .collect(),
            ),
            RecFelt::Limbs(v) => v
                .iter()
                .map(|r| match r {
                    RecVal::Ok(x) => Some(*x),
                    RecVal::Poison => None,
                })
                .collect(),
        }
    }

    /// fp256 body arithmetic: one `DeduceCall` of the given felt kind on
    /// `[a limbs | b limbs]` (56 args), returning the 28 result limbs. Poison in
    /// either operand degrades to an all-poison bundle (censused under `op`).
    fn felt_bin(
        &mut self,
        kind: DeduceKind,
        op: &'static str,
        a: &RecFelt,
        b: &RecFelt,
    ) -> RecFelt {
        let args = (|| {
            let mut args = self.felt_arg_limbs(a)?;
            args.extend(self.felt_arg_limbs(b)?);
            Some(args)
        })();
        let Some(args) = args else {
            let p = self.poison(op);
            return RecFelt::Limbs(vec![p; FELT_N_LIMBS]);
        };
        let outs = self.recorder.deduce(kind, &args);
        RecFelt::Limbs(outs.into_iter().map(RecVal::Ok).collect())
    }

    fn windowed_ec_deduce<const N: usize>(
        &mut self,
        op: &'static str,
        kind: DeduceKind,
        chain: RecVal,
        round: RecVal,
        windows: [RecVal; N],
        acc: [RecFelt; 2],
    ) -> (RecVal, RecVal, ([RecVal; N], [RecFelt; 2])) {
        let args = (|| {
            let mut args = Self::plain_args(&[chain, round])?;
            args.extend(Self::plain_args(&windows)?);
            args.extend(self.felt_arg_limbs(&acc[0])?);
            args.extend(self.felt_arg_limbs(&acc[1])?);
            Some(args)
        })();
        let Some(args) = args else {
            let p = self.poison(op);
            return (
                p,
                p,
                (
                    [p; N],
                    [
                        RecFelt::Limbs(vec![p; FELT_N_LIMBS]),
                        RecFelt::Limbs(vec![p; FELT_N_LIMBS]),
                    ],
                ),
            );
        };

        let outs = self.recorder.deduce(kind, &args);
        let ok = |i: usize| RecVal::Ok(outs[i]);
        let felt_base = 2 + N;
        (
            ok(0),
            ok(1),
            (
                std::array::from_fn(|i| ok(2 + i)),
                [
                    RecFelt::Limbs((0..FELT_N_LIMBS).map(|i| ok(felt_base + i)).collect()),
                    RecFelt::Limbs(
                        (0..FELT_N_LIMBS)
                            .map(|i| ok(felt_base + FELT_N_LIMBS + i))
                            .collect(),
                    ),
                ],
            ),
        )
    }

    fn points_table_deduce(
        &mut self,
        op: &'static str,
        kind: DeduceKind,
        index: RecVal,
    ) -> [RecFelt; 2] {
        let RecVal::Ok(index) = index else {
            let p = self.poison(op);
            return [
                RecFelt::Limbs(vec![p; FELT_N_LIMBS]),
                RecFelt::Limbs(vec![p; FELT_N_LIMBS]),
            ];
        };
        let outs = self.recorder.deduce(kind, &[index]);
        [
            RecFelt::Limbs((0..FELT_N_LIMBS).map(|i| RecVal::Ok(outs[i])).collect()),
            RecFelt::Limbs(
                (0..FELT_N_LIMBS)
                    .map(|i| RecVal::Ok(outs[FELT_N_LIMBS + i]))
                    .collect(),
            ),
        ]
    }

    fn poseidon_deduce(
        &mut self,
        kind: DeduceKind,
        head: &[RecVal],
        state: &[[RecVal; 10]],
    ) -> Option<Vec<RecVal>> {
        let mut args = Self::plain_args(head)?;
        for value in state {
            args.extend(Self::plain_args(value)?);
        }
        Some(
            self.recorder
                .deduce(kind, &args)
                .into_iter()
                .map(RecVal::Ok)
                .collect(),
        )
    }

    /// Unwrap plain deduce args; `None` on any poison (the caller falls back to the
    /// poisoned result, keeping poison-propagation semantics).
    fn plain_args(args: &[RecVal]) -> Option<Vec<Val>> {
        args.iter()
            .map(|r| match r {
                RecVal::Ok(x) => Some(*x),
                RecVal::Poison => None,
            })
            .collect()
    }

    /// Poison-propagating binary ISA-core op.
    #[inline]
    fn bin(
        &mut self,
        a: RecVal,
        b: RecVal,
        f: impl FnOnce(&mut WitnessRecorder, Val, Val) -> Val,
    ) -> RecVal {
        match (a, b) {
            (RecVal::Ok(x), RecVal::Ok(y)) => RecVal::Ok(f(&mut self.recorder, x, y)),
            _ => RecVal::Poison,
        }
    }
}

impl WitnessEval for RecordingWitnessEval {
    type M31 = RecVal;
    type U16 = RecVal;
    type Mask = RecVal;
    type Felt = RecFelt;
    type U32 = RecVal;

    // ---- Leaves ----------------------------------------------------------------

    #[inline]
    fn input(&mut self, slot: u32) -> RecVal {
        RecVal::Ok(self.recorder.input(slot))
    }
    #[inline]
    fn m31_const(&mut self, value: u32) -> RecVal {
        RecVal::Ok(self.recorder.constant(value))
    }
    #[inline]
    fn enabler(&mut self) -> RecVal {
        let slot = self.enabler_slot;
        RecVal::Ok(self.recorder.input(slot))
    }

    // ---- u32 integer ops (blake family) — bit-exact ISA lowerings of the
    // ---- PackedUInt32 semantics (common prover_types/simd.rs:192-209) -------------

    #[inline]
    fn u32_from_limbs(&mut self, low: RecVal, high: RecVal) -> RecVal {
        // low + (high << 16): both operands canonical 16-bit, so the raw u32 ops are
        // exact (no overflow below 2^32).
        let shifted = self.un(high, |r, x| r.u32_shl(x, 16));
        self.bin(low, shifted, |r, x, y| r.u32_add(x, y))
    }
    #[inline]
    fn u32_low(&mut self, a: RecVal) -> RecVal {
        self.un(a, |r, x| r.u32_and(x, 0xFFFF))
    }
    #[inline]
    fn u32_high(&mut self, a: RecVal) -> RecVal {
        self.un(a, |r, x| r.u32_shr(x, 16))
    }
    #[inline]
    fn input_u32(&mut self, slot: u32) -> RecVal {
        // Same Input op — the kernel reads the raw u32 word from the input column;
        // M31-vs-u32 is a transformer-side typing distinction only.
        RecVal::Ok(self.recorder.input(slot))
    }

    fn u32_from_m31(&mut self, a: RecVal) -> RecVal {
        // Canonical M31 register value IS the 32-bit word — identity.
        a
    }
    fn u32_const(&mut self, v: u32) -> RecVal {
        RecVal::Ok(self.recorder.constant(v))
    }
    fn u32_add(&mut self, a: RecVal, b: RecVal) -> RecVal {
        self.bin(a, b, |r, x, y| r.u32_add(x, y))
    }
    fn u32_sub(&mut self, a: RecVal, b: RecVal) -> RecVal {
        self.bin(a, b, |r, x, y| r.u32_sub(x, y))
    }
    fn u32_mul(&mut self, a: RecVal, b: RecVal) -> RecVal {
        self.bin(a, b, |r, x, y| r.u32_mul(x, y))
    }
    fn u32_and_imm(&mut self, a: RecVal, mask: u32) -> RecVal {
        self.un(a, |r, x| r.u32_and(x, mask))
    }
    fn u32_shl_imm(&mut self, a: RecVal, amount: u32) -> RecVal {
        self.un(a, |r, x| r.u32_shl(x, amount))
    }
    fn u32_shr_imm(&mut self, a: RecVal, amount: u32) -> RecVal {
        self.un(a, |r, x| r.u32_shr(x, amount))
    }

    // ---- Builtin-lane leaves ----------------------------------------------------

    #[inline]
    fn iota(&mut self) -> RecVal {
        match self.iota_slot {
            Some(slot) => RecVal::Ok(self.recorder.input(slot)),
            // No iota column configured (opcode layout) — an honest poison, censused.
            None => self.poison("iota (no slot configured)"),
        }
    }

    // ---- Computed deduces: NOT recordable yet (need a computed-deduce ISA op backed
    // ---- by the device EC functions, or device-to-device feeding — G5). All-poison
    // ---- results + a poison_ops census entry = the pinned manifest. ---------------

    fn deduce_partial_ec_mul_w18(
        &mut self,
        chain: RecVal,
        round: RecVal,
        windows: [RecVal; 14],
        acc: [RecFelt; 2],
    ) -> (RecVal, RecVal, ([RecVal; 14], [RecFelt; 2])) {
        self.windowed_ec_deduce(
            "deduce_partial_ec_mul_w18",
            DeduceKind::PartialEcMulW18,
            chain,
            round,
            windows,
            acc,
        )
    }

    fn deduce_pedersen_points_table_w18(&mut self, index: RecVal) -> [RecFelt; 2] {
        self.points_table_deduce(
            "deduce_pedersen_points_table_w18",
            DeduceKind::PedersenPointsTableW18,
            index,
        )
    }

    fn deduce_partial_ec_mul_w9(
        &mut self,
        chain: RecVal,
        round: RecVal,
        windows: [RecVal; 28],
        acc: [RecFelt; 2],
    ) -> (RecVal, RecVal, ([RecVal; 28], [RecFelt; 2])) {
        self.windowed_ec_deduce(
            "deduce_partial_ec_mul_w9",
            DeduceKind::PartialEcMulW9,
            chain,
            round,
            windows,
            acc,
        )
    }

    fn deduce_pedersen_points_table_w9(&mut self, index: RecVal) -> [RecFelt; 2] {
        self.points_table_deduce(
            "deduce_pedersen_points_table_w9",
            DeduceKind::PedersenPointsTableW9,
            index,
        )
    }

    fn deduce_partial_ec_mul_generic(
        &mut self,
        chain: RecVal,
        round: RecVal,
        scalar: [RecVal; 10],
        point: [RecFelt; 2],
        accumulator: [RecFelt; 2],
        counter: RecVal,
    ) -> (
        RecVal,
        RecVal,
        ([RecVal; 10], [RecFelt; 2], [RecFelt; 2], RecVal),
    ) {
        let args = (|| {
            let mut args = Self::plain_args(&[chain, round])?;
            args.extend(Self::plain_args(&scalar)?);
            args.extend(self.felt_arg_limbs(&point[0])?);
            args.extend(self.felt_arg_limbs(&point[1])?);
            args.extend(self.felt_arg_limbs(&accumulator[0])?);
            args.extend(self.felt_arg_limbs(&accumulator[1])?);
            args.extend(Self::plain_args(&[counter])?);
            Some(args)
        })();
        let Some(args) = args else {
            let poison = self.poison("deduce_partial_ec_mul_generic");
            let poison_felt = || RecFelt::Limbs(vec![poison; FELT_N_LIMBS]);
            return (
                poison,
                poison,
                (
                    [poison; 10],
                    [poison_felt(), poison_felt()],
                    [poison_felt(), poison_felt()],
                    poison,
                ),
            );
        };

        let outputs = self.recorder.deduce(DeduceKind::PartialEcMulGeneric, &args);
        let ok = |index: usize| RecVal::Ok(outputs[index]);
        let scalar_base = 2;
        let point_base = scalar_base + 10;
        let accumulator_base = point_base + 2 * FELT_N_LIMBS;
        let counter_index = accumulator_base + 2 * FELT_N_LIMBS;
        let felt_at =
            |base: usize| RecFelt::Limbs((0..FELT_N_LIMBS).map(|index| ok(base + index)).collect());
        (
            ok(0),
            ok(1),
            (
                std::array::from_fn(|index| ok(scalar_base + index)),
                [felt_at(point_base), felt_at(point_base + FELT_N_LIMBS)],
                [
                    felt_at(accumulator_base),
                    felt_at(accumulator_base + FELT_N_LIMBS),
                ],
                ok(counter_index),
            ),
        )
    }

    fn deduce_add_mod_is_zero(
        &mut self,
        a: [RecFelt; 4],
        b: [RecFelt; 4],
        c: [RecFelt; 4],
    ) -> RecVal {
        let args = (|| {
            let mut args = Vec::with_capacity(3 * 4 * FELT_N_LIMBS);
            for felt in a.iter().chain(&b).chain(&c) {
                args.extend(self.felt_arg_limbs(felt)?);
            }
            Some(args)
        })();
        let Some(args) = args else {
            return self.poison("deduce_add_mod_is_zero");
        };
        RecVal::Ok(self.recorder.deduce(DeduceKind::AddModIsZero, &args)[0])
    }

    fn deduce_mul_mod_quotient(
        &mut self,
        p: [RecFelt; 4],
        a: [RecFelt; 4],
        b: [RecFelt; 4],
        c: [RecFelt; 4],
    ) -> [RecVal; 32] {
        let args = (|| {
            let mut args = Vec::with_capacity(4 * 4 * FELT_N_LIMBS);
            for felt in p.iter().chain(&a).chain(&b).chain(&c) {
                args.extend(self.felt_arg_limbs(felt)?);
            }
            Some(args)
        })();
        let Some(args) = args else {
            let poison = self.poison("deduce_mul_mod_quotient");
            return [poison; 32];
        };
        let outputs = self.recorder.deduce(DeduceKind::MulModQuotient, &args);
        std::array::from_fn(|index| RecVal::Ok(outputs[index]))
    }

    fn deduce_blake_g(&mut self, input: [RecVal; 6]) -> [RecVal; 4] {
        let Some(args) = Self::plain_args(&input) else {
            let p = self.poison("deduce_blake_g");
            return [p; 4];
        };
        let outs = self.recorder.deduce(DeduceKind::BlakeG, &args);
        std::array::from_fn(|i| RecVal::Ok(outs[i]))
    }

    fn deduce_blake_round_sigma(&mut self, round: RecVal) -> [RecVal; 16] {
        let RecVal::Ok(r) = round else {
            let p = self.poison("deduce_blake_round_sigma");
            return [p; 16];
        };
        let outs = self.recorder.deduce(DeduceKind::BlakeRoundSigma, &[r]);
        std::array::from_fn(|i| RecVal::Ok(outs[i]))
    }

    fn deduce_poseidon_round_keys(&mut self, round: RecVal) -> [[RecVal; 10]; 3] {
        let Some(outputs) = self.poseidon_deduce(DeduceKind::PoseidonRoundKeys, &[round], &[])
        else {
            let poison = self.poison("deduce_poseidon_round_keys");
            return [[poison; 10]; 3];
        };
        std::array::from_fn(|value| std::array::from_fn(|word| outputs[value * 10 + word]))
    }

    fn deduce_poseidon_cube(&mut self, value: [RecVal; 10]) -> [RecVal; 10] {
        let Some(outputs) = self.poseidon_deduce(DeduceKind::PoseidonCube, &[], &[value]) else {
            let poison = self.poison("deduce_poseidon_cube");
            return [poison; 10];
        };
        std::array::from_fn(|word| outputs[word])
    }

    fn deduce_poseidon_full_round_chain(
        &mut self,
        chain: RecVal,
        round: RecVal,
        state: [[RecVal; 10]; 3],
    ) -> (RecVal, RecVal, [[RecVal; 10]; 3]) {
        let Some(outputs) =
            self.poseidon_deduce(DeduceKind::PoseidonFullRoundChain, &[chain, round], &state)
        else {
            let poison = self.poison("deduce_poseidon_full_round_chain");
            return (poison, poison, [[poison; 10]; 3]);
        };
        (
            outputs[0],
            outputs[1],
            std::array::from_fn(|value| std::array::from_fn(|word| outputs[2 + value * 10 + word])),
        )
    }

    fn deduce_poseidon_3_partial_rounds_chain(
        &mut self,
        chain: RecVal,
        round: RecVal,
        state: [[RecVal; 10]; 4],
    ) -> (RecVal, RecVal, [[RecVal; 10]; 4]) {
        let Some(outputs) = self.poseidon_deduce(
            DeduceKind::Poseidon3PartialRoundsChain,
            &[chain, round],
            &state,
        ) else {
            let poison = self.poison("deduce_poseidon_3_partial_rounds_chain");
            return (poison, poison, [[poison; 10]; 4]);
        };
        (
            outputs[0],
            outputs[1],
            std::array::from_fn(|value| std::array::from_fn(|word| outputs[2 + value * 10 + word])),
        )
    }

    // ---- M31 field ops (ISA-core) ----------------------------------------------

    #[inline]
    fn m31_add(&mut self, a: RecVal, b: RecVal) -> RecVal {
        self.bin(a, b, |r, x, y| r.m31_add(x, y))
    }
    #[inline]
    fn m31_sub(&mut self, a: RecVal, b: RecVal) -> RecVal {
        self.bin(a, b, |r, x, y| r.m31_sub(x, y))
    }
    #[inline]
    fn m31_mul(&mut self, a: RecVal, b: RecVal) -> RecVal {
        self.bin(a, b, |r, x, y| r.m31_mul(x, y))
    }

    // ---- EXTENDED (ISA-V2: masks are 0/1 registers; `m31_eq` produces one,
    // ---- the mask combinators lower to plain field arithmetic on 0/1 values,
    // ---- and the conversions are identities — byte-identical to the SIMD
    // ---- PackedBool semantics on every path the writers exercise) --------------

    #[inline]
    fn m31_inverse(&mut self, a: RecVal) -> RecVal {
        self.un(a, |r, x| r.m31_inverse(x))
    }
    #[inline]
    fn m31_eq(&mut self, a: RecVal, b: RecVal) -> RecVal {
        self.bin(a, b, |r, x, y| r.m31_eq(x, y))
    }
    #[inline]
    fn mask_and(&mut self, a: RecVal, b: RecVal) -> RecVal {
        // AND of 0/1 masks == product.
        self.bin(a, b, |r, x, y| r.m31_mul(x, y))
    }
    #[inline]
    fn mask_as_m31(&mut self, a: RecVal) -> RecVal {
        a
    }
    #[inline]
    fn mask_from_m31(&mut self, a: RecVal) -> RecVal {
        // The writers only convert 0/1 factors (`PackedBool::from_m31`'s own
        // contract), so the register already IS the mask representation.
        a
    }
    #[inline]
    fn select(&mut self, m: RecVal, a: RecVal, b: RecVal) -> RecVal {
        // Lane-safe conditional over a 0/1 mask: m*a + (1-m)*b.
        let one = self.m31_const(1);
        let not_m = self.bin(one, m, |r, x, y| r.m31_sub(x, y));
        let ma = self.bin(m, a, |r, x, y| r.m31_mul(x, y));
        let nb = self.bin(not_m, b, |r, x, y| r.m31_mul(x, y));
        self.bin(ma, nb, |r, x, y| r.m31_add(x, y))
    }

    // ---- u16 integer / bit ops (ISA-core) --------------------------------------

    #[inline]
    fn u16_from_m31(&mut self, a: RecVal) -> RecVal {
        self.un(a, |r, x| r.from_m31(x))
    }
    #[inline]
    fn u16_as_m31(&mut self, a: RecVal) -> RecVal {
        self.un(a, |r, x| r.as_m31(x))
    }
    #[inline]
    fn u16_add(&mut self, a: RecVal, b: RecVal) -> RecVal {
        self.bin(a, b, |r, x, y| r.u16_add(x, y))
    }
    #[inline]
    fn u16_shl(&mut self, a: RecVal, imm: u32) -> RecVal {
        self.un(a, |r, x| r.u16_shl(x, imm))
    }
    #[inline]
    fn u16_shr(&mut self, a: RecVal, imm: u32) -> RecVal {
        self.un(a, |r, x| r.u16_shr(x, imm))
    }
    #[inline]
    fn u16_and(&mut self, a: RecVal, mask: u32) -> RecVal {
        self.un(a, |r, x| r.u16_and(x, mask))
    }
    #[inline]
    fn u16_xor(&mut self, a: RecVal, b: RecVal) -> RecVal {
        // Bit-identical to a dedicated U16Xor because both operands are `< 2^16`.
        self.bin(a, b, |r, x, y| r.u32_xor(x, y))
    }

    // ---- Felt (bookkeeping) ----------------------------------------------------

    #[inline]
    fn felt_from_limbs(&mut self, limbs: [RecVal; FELT_N_LIMBS]) -> RecFelt {
        RecFelt::Limbs(limbs.to_vec())
    }
    #[inline]
    fn felt_get_m31(&mut self, felt: &RecFelt, i: usize) -> RecVal {
        match felt {
            RecFelt::Deduced { key } => {
                RecVal::Ok(self.recorder.table_limb(TABLE_ID_TO_BIG, *key, i as u32))
            }
            RecFelt::Limbs(v) => v[i],
        }
    }

    fn felt_from_m31(&mut self, value: RecVal) -> RecFelt {
        let RecVal::Ok(value) = value else {
            let p = self.poison("felt_from_m31");
            return RecFelt::Limbs(vec![p; FELT_N_LIMBS]);
        };

        let mut limbs = Vec::with_capacity(FELT_N_LIMBS);
        for i in 0..4u32 {
            let shifted = if i == 0 {
                value
            } else {
                self.recorder.u32_shr(value, 9 * i)
            };
            limbs.push(RecVal::Ok(self.recorder.u32_and(shifted, 0x1FF)));
        }
        let zero = RecVal::Ok(self.recorder.constant(0));
        limbs.resize(FELT_N_LIMBS, zero);
        RecFelt::Limbs(limbs)
    }

    fn felt_from_w27_words(&mut self, words: [RecVal; 10]) -> RecFelt {
        // Exact 27->9 regroup on raw registers: limb 3j+t = (w[j] >> 9t) & 0x1FF
        // (j < 9); limb 27 = w[9] & 0x1FF (top word is 9 bits — mask is identity,
        // kept for uniformity). Any poisoned word degrades the whole felt.
        let Some(w): Option<Vec<Val>> = words
            .iter()
            .map(|r| match r {
                RecVal::Ok(x) => Some(*x),
                RecVal::Poison => None,
            })
            .collect()
        else {
            let p = self.poison("felt_from_w27_words");
            return RecFelt::Limbs(vec![p; FELT_N_LIMBS]);
        };
        let mut limbs = Vec::with_capacity(FELT_N_LIMBS);
        for word in w.iter().take(9).copied() {
            for t in 0..3u32 {
                let shifted = if t == 0 {
                    word
                } else {
                    self.recorder.u32_shr(word, 9 * t)
                };
                limbs.push(RecVal::Ok(self.recorder.u32_and(shifted, 0x1FF)));
            }
        }
        limbs.push(RecVal::Ok(self.recorder.u32_and(w[9], 0x1FF)));
        RecFelt::Limbs(limbs)
    }

    // ---- Felt field arithmetic: DeduceKind::Felt{Add,Sub,Mul,Div} ---------------

    fn felt_add(&mut self, a: RecFelt, b: RecFelt) -> RecFelt {
        self.felt_bin(DeduceKind::FeltAdd, "felt_add", &a, &b)
    }
    fn felt_sub(&mut self, a: RecFelt, b: RecFelt) -> RecFelt {
        self.felt_bin(DeduceKind::FeltSub, "felt_sub", &a, &b)
    }
    fn felt_mul(&mut self, a: RecFelt, b: RecFelt) -> RecFelt {
        self.felt_bin(DeduceKind::FeltMul, "felt_mul", &a, &b)
    }
    fn felt_div(&mut self, a: RecFelt, b: RecFelt) -> RecFelt {
        self.felt_bin(DeduceKind::FeltDiv, "felt_div", &a, &b)
    }

    // ---- Memory ops (`mem_read` uses the trait default) ------------------------

    #[inline]
    fn mem_addr_to_id(&mut self, addr: RecVal) -> RecVal {
        match addr {
            RecVal::Ok(a) => RecVal::Ok(self.recorder.table_limb(TABLE_ADDR_TO_ID, a, 0)),
            RecVal::Poison => RecVal::Poison,
        }
    }
    #[inline]
    fn mem_id_to_value(&mut self, id: RecVal) -> RecFelt {
        match id {
            RecVal::Ok(key) => RecFelt::Deduced { key },
            // No Val to key the table read on: degrade to an all-poison limb bundle.
            RecVal::Poison => RecFelt::Limbs(vec![RecVal::Poison; FELT_N_LIMBS]),
        }
    }

    // ---- Effects ---------------------------------------------------------------

    #[inline]
    fn set_col(&mut self, col: usize, value: RecVal) {
        match value {
            RecVal::Ok(val) => self.recorder.col_write(col as u32, val),
            RecVal::Poison => {
                self.poisoned_cols.insert(col);
            }
        }
    }
    #[inline]
    fn set_lookup_word(&mut self, word: usize, value: RecVal) {
        match value {
            RecVal::Ok(val) => self.recorder.lookup_word(word as u32, val),
            RecVal::Poison => {
                self.poisoned_lookup_words.insert(word);
            }
        }
    }
    #[inline]
    fn set_sub_input_word_u32(&mut self, word: usize, value: RecVal) {
        // Same SubWord op — raw register store; the flat word is full 32-bit.
        self.set_sub_input_word(word, value);
    }
    fn set_sub_input_word(&mut self, word: usize, value: RecVal) {
        // Sub-component inputs are first-class ISA effects (`WitnessOp::SubWord`): the
        // kernel stores them into a flat per-row buffer that the prove-path hook D2H\'s
        // and feeds to the sibling generators exactly as the host writer\'s
        // `SubComponentInputs` drain does. NOT derivable from lookup words in general
        // (add_opcode\'s verify_instruction sub-tuple uses different intermediates than
        // its lookup tuple), hence the dedicated effect. Poison keeps the word out of
        // the recording, matching the lookup-word rule.
        match value {
            RecVal::Ok(val) => self.recorder.sub_word(word as u32, val),
            RecVal::Poison => {
                self.poisoned_sub_words.insert(word);
            }
        }
    }
}

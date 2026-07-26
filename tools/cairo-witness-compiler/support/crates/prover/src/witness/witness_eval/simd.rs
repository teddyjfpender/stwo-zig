//! [`SimdWitnessEval`] — the zero-cost passthrough [`WitnessEval`] impl.
//!
//! Every method is `#[inline(always)]` and lowers directly to the exact `PackedM31` /
//! `PackedUInt16` / `PackedBool` / `PackedFelt252` operation the original monomorphic
//! `write_trace_simd` body used. Instantiating a generic per-row body on this evaluator
//! therefore reproduces the original host SIMD writer **byte-for-byte** (the safety gate
//! — see [`super`] and `witness_eval::differential_test`).
//!
//! # Effects
//!
//! `set_col(i, v)` writes `*self.row[i] = v` straight into the committed
//! [`ComponentTrace`](stwo_air_utils::trace::component_trace::ComponentTrace) column.
//! The lookup-tuple words and sub-component-input words, however, are addressed by *flat
//! index* through the trait (the driver reconstructs the concrete typed `LookupData` /
//! `SubComponentInputs` only after the row body finishes), so they land in flat scratch
//! [`Vec`]s that the driver reads back and reshapes. See
//! [`SimdWitnessEval::lookup_scratch`] / [`SimdWitnessEval::sub_scratch`].

use stwo_cairo_common::prover_types::simd::SIMD_ENUMERATION_0;

use crate::witness::components::{memory_address_to_id, memory_id_to_big};
use crate::witness::fast_deduction::blake::{PackedBlakeG, PackedBlakeRoundSigma};
use crate::witness::fast_deduction::ec_op::PackedPartialEcMulGeneric;
use crate::witness::fast_deduction::pedersen::{
    PackedPartialEcMulWindowBits18, PackedPartialEcMulWindowBits9,
    PackedPedersenPointsTableWindowBits18, PackedPedersenPointsTableWindowBits9,
};
use crate::witness::fast_deduction::poseidon::{
    PackedCube252, PackedPoseidon3PartialRoundsChain, PackedPoseidonFullRoundChain,
    PackedPoseidonRoundKeys,
};
use crate::witness::prelude::*;
use crate::witness::witness_eval::{WitnessEval, FELT_N_LIMBS, SLOT_AP, SLOT_FP, SLOT_PC};

/// This packed row's `input()` source: the opcode `PackedCasmState` (slots
/// `SLOT_PC/AP/FP`), or a BUILTIN's flattened input words (slot `k` = the k-th M31
/// leaf of the component's `PackedInputType`, depth-first — the same order the
/// transformer's slot map assigns and the device lane feeds its input columns).
pub enum SimdInputs {
    Casm(PackedCasmState),
    /// Flattened input words as RAW 32-bit lanes: M31 slots hold canonical values,
    /// u32 slots (blake message words) hold full 32-bit words that do NOT fit in
    /// `PackedM31` — the raw transport is what the device lane's u32 input columns
    /// carry, so both evaluators read the same bytes.
    Flat(Vec<Simd<u32, N_LANES>>),
}

#[inline(always)]
fn w27_from_words(words: [PackedM31; 10]) -> PackedFelt252Width27 {
    PackedFelt252Width27::from_limbs(words)
}

#[inline(always)]
fn w27_to_words(value: PackedFelt252Width27) -> [PackedM31; 10] {
    std::array::from_fn(|index| value.get_m31(index))
}

impl From<PackedCasmState> for SimdInputs {
    fn from(input: PackedCasmState) -> Self {
        Self::Casm(input)
    }
}

impl From<Vec<PackedM31>> for SimdInputs {
    fn from(words: Vec<PackedM31>) -> Self {
        Self::Flat(words.into_iter().map(PackedM31::into_simd).collect())
    }
}

impl From<Vec<Simd<u32, N_LANES>>> for SimdInputs {
    fn from(words: Vec<Simd<u32, N_LANES>>) -> Self {
        Self::Flat(words)
    }
}

/// Passthrough [`WitnessEval`] holding the mutable handles for one packed row.
///
/// `'trace` is the lifetime of the committed trace column borrows, `'a` the lifetime of
/// the borrowed sibling-component deduce states, and `N` the trace column count.
pub struct SimdWitnessEval<'a, 'trace, const N: usize> {
    /// Mutable handle to the current packed row's `N` trace columns (`set_col` target).
    row: Box<[&'trace mut PackedM31; N]>,
    /// `memory_address_to_id.deduce_output` device/host table (`None` for components
    /// whose writer takes no such state — their bodies never call `mem_addr_to_id`).
    mem_addr_state: Option<&'a memory_address_to_id::ClaimGenerator>,
    /// `memory_id_to_big.deduce_output` device/host table (`None` when absent).
    mem_big_state: Option<&'a memory_id_to_big::ClaimGenerator>,
    /// This packed row's `input()` source (opcode CasmState or builtin flat words).
    input: SimdInputs,
    /// This packed row's index (for the enabler column).
    row_index: usize,
    /// The enabler column (1 for real rows, 0 for padding).
    enabler: &'a Enabler,
    /// Flat lookup-tuple words written by `set_lookup_word`, reshaped by the driver.
    lookup_scratch: Vec<PackedM31>,
    /// Flat sub-component-input words (RAW 32-bit lanes: M31 words canonical, u32
    /// words full-width) written by `set_sub_input_word{,_u32}`, reshaped by the
    /// driver with the per-shape types.
    sub_scratch: Vec<Simd<u32, N_LANES>>,
}

impl<'a, 'trace, const N: usize> SimdWitnessEval<'a, 'trace, N> {
    /// Construct the evaluator for one packed row. `n_lookup_words` / `n_sub_words` size
    /// the flat scratch to the component's `LookupData` / `SubComponentInputs` word count
    /// (the driver knows these).
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        row: Box<[&'trace mut PackedM31; N]>,
        mem_addr_state: impl Into<Option<&'a memory_address_to_id::ClaimGenerator>>,
        mem_big_state: impl Into<Option<&'a memory_id_to_big::ClaimGenerator>>,
        input: impl Into<SimdInputs>,
        row_index: usize,
        enabler: &'a Enabler,
        n_lookup_words: usize,
        n_sub_words: usize,
    ) -> Self {
        Self {
            row,
            mem_addr_state: mem_addr_state.into(),
            mem_big_state: mem_big_state.into(),
            input: input.into(),
            row_index,
            enabler,
            lookup_scratch: vec![PackedM31::zero(); n_lookup_words],
            sub_scratch: vec![Simd::splat(0); n_sub_words],
        }
    }

    /// Flat lookup-tuple words (declaration order across `LookupData`).
    #[inline(always)]
    pub fn lookup_scratch(&self) -> &[PackedM31] {
        &self.lookup_scratch
    }

    /// Flat sub-component-input words (declaration order across `SubComponentInputs`),
    /// as raw 32-bit lanes; the driver rebuilds the typed values per shape.
    #[inline(always)]
    pub fn sub_scratch(&self) -> &[Simd<u32, N_LANES>] {
        &self.sub_scratch
    }
}

impl<const N: usize> WitnessEval for SimdWitnessEval<'_, '_, N> {
    type M31 = PackedM31;
    type U16 = PackedUInt16;
    type Mask = PackedBool;
    type Felt = PackedFelt252;
    type U32 = PackedUInt32;

    // ---- Leaves ----------------------------------------------------------------

    #[inline(always)]
    fn input(&mut self, slot: u32) -> PackedM31 {
        match &self.input {
            SimdInputs::Casm(input) => match slot {
                SLOT_PC => input.pc,
                SLOT_AP => input.ap,
                SLOT_FP => input.fp,
                _ => panic!("SimdWitnessEval::input: unexpected CasmState slot {slot}"),
            },
            // Slot typing contract: M31 slots carry canonical (< P) values — the
            // transformer only emits `input(slot)` for M31-typed leaves.
            SimdInputs::Flat(words) => unsafe {
                PackedM31::from_simd_unchecked(words[slot as usize])
            },
        }
    }

    #[inline(always)]
    fn m31_const(&mut self, value: u32) -> PackedM31 {
        PackedM31::broadcast(M31::from(value))
    }

    #[inline(always)]
    fn enabler(&mut self) -> PackedM31 {
        self.enabler.packed_at(self.row_index)
    }

    // ---- M31 field ops (ISA-core) ----------------------------------------------

    #[inline(always)]
    fn m31_add(&mut self, a: PackedM31, b: PackedM31) -> PackedM31 {
        a + b
    }
    #[inline(always)]
    fn m31_sub(&mut self, a: PackedM31, b: PackedM31) -> PackedM31 {
        a - b
    }
    #[inline(always)]
    fn m31_mul(&mut self, a: PackedM31, b: PackedM31) -> PackedM31 {
        a * b
    }

    // ---- M31 field ops (EXTENDED) ----------------------------------------------

    #[inline(always)]
    fn m31_inverse(&mut self, a: PackedM31) -> PackedM31 {
        a.inverse()
    }
    #[inline(always)]
    fn m31_eq(&mut self, a: PackedM31, b: PackedM31) -> PackedBool {
        EqExtend::eq(&a, b)
    }

    // ---- Masks + lane-wise select (EXTENDED) -----------------------------------

    #[inline(always)]
    fn mask_and(&mut self, a: PackedBool, b: PackedBool) -> PackedBool {
        a & b
    }
    #[inline(always)]
    fn mask_as_m31(&mut self, a: PackedBool) -> PackedM31 {
        a.as_m31()
    }
    #[inline(always)]
    fn mask_from_m31(&mut self, a: PackedM31) -> PackedBool {
        PackedBool::from_m31(a)
    }
    #[inline(always)]
    fn select(&mut self, m: PackedBool, a: PackedM31, b: PackedM31) -> PackedM31 {
        // Lane-wise `m ? a : b`: `f*a + (1 - f)*b` where `f` is the 0/1 mask factor.
        let f = m.as_m31();
        let one = PackedM31::broadcast(M31::from(1));
        f * a + (one - f) * b
    }

    // ---- u16 integer / bit ops (ISA-core) --------------------------------------

    #[inline(always)]
    fn u16_from_m31(&mut self, a: PackedM31) -> PackedUInt16 {
        PackedUInt16::from_m31(a)
    }
    #[inline(always)]
    fn u16_as_m31(&mut self, a: PackedUInt16) -> PackedM31 {
        a.as_m31()
    }
    #[inline(always)]
    fn u16_add(&mut self, a: PackedUInt16, b: PackedUInt16) -> PackedUInt16 {
        a + b
    }
    #[inline(always)]
    fn u16_shl(&mut self, a: PackedUInt16, imm: u32) -> PackedUInt16 {
        a << PackedUInt16::broadcast(UInt16::from(imm as u16))
    }
    #[inline(always)]
    fn u16_shr(&mut self, a: PackedUInt16, imm: u32) -> PackedUInt16 {
        a >> PackedUInt16::broadcast(UInt16::from(imm as u16))
    }
    #[inline(always)]
    fn u16_and(&mut self, a: PackedUInt16, mask: u32) -> PackedUInt16 {
        a & PackedUInt16::broadcast(UInt16::from(mask as u16))
    }
    #[inline(always)]
    fn u16_xor(&mut self, a: PackedUInt16, b: PackedUInt16) -> PackedUInt16 {
        a ^ b
    }

    // ---- Felt (bookkeeping) ----------------------------------------------------

    #[inline(always)]
    fn felt_from_limbs(&mut self, limbs: [PackedM31; FELT_N_LIMBS]) -> PackedFelt252 {
        PackedFelt252::from_limbs(limbs)
    }
    #[inline(always)]
    fn felt_get_m31(&mut self, felt: &PackedFelt252, i: usize) -> PackedM31 {
        felt.get_m31(i)
    }
    #[inline(always)]
    fn felt_from_m31(&mut self, value: PackedM31) -> PackedFelt252 {
        PackedFelt252::from_m31(value)
    }

    fn felt_from_w27_words(&mut self, words: [PackedM31; 10]) -> PackedFelt252 {
        PackedFelt252::from_packed_felt252width27(PackedFelt252Width27::from_limbs(words))
    }

    fn felt_add(&mut self, a: PackedFelt252, b: PackedFelt252) -> PackedFelt252 {
        a + b
    }
    fn felt_sub(&mut self, a: PackedFelt252, b: PackedFelt252) -> PackedFelt252 {
        a - b
    }
    fn felt_mul(&mut self, a: PackedFelt252, b: PackedFelt252) -> PackedFelt252 {
        a * b
    }
    fn felt_div(&mut self, a: PackedFelt252, b: PackedFelt252) -> PackedFelt252 {
        a / b
    }

    // ---- Memory ops (keystone binding; `mem_read` uses the trait default) ------

    #[inline(always)]
    fn mem_addr_to_id(&mut self, addr: PackedM31) -> PackedM31 {
        self.mem_addr_state
            .expect("component writer has no memory_address_to_id state")
            .deduce_output(addr)
    }
    #[inline(always)]
    fn mem_id_to_value(&mut self, id: PackedM31) -> PackedFelt252 {
        self.mem_big_state
            .expect("component writer has no memory_id_to_big state")
            .deduce_output(id)
    }

    // ---- u32 integer ops (blake family) ------------------------------------------

    #[inline(always)]
    fn u32_from_limbs(&mut self, low: PackedM31, high: PackedM31) -> PackedUInt32 {
        PackedUInt32::from_limbs([low, high])
    }
    #[inline(always)]
    fn u32_low(&mut self, a: PackedUInt32) -> PackedUInt16 {
        a.low()
    }
    #[inline(always)]
    fn u32_high(&mut self, a: PackedUInt32) -> PackedUInt16 {
        a.high()
    }
    #[inline(always)]
    fn input_u32(&mut self, slot: u32) -> PackedUInt32 {
        match &self.input {
            SimdInputs::Casm(_) => panic!("input_u32 on an opcode CasmState input"),
            SimdInputs::Flat(words) => PackedUInt32::from_simd(words[slot as usize]),
        }
    }

    fn u32_from_m31(&mut self, a: PackedM31) -> PackedUInt32 {
        PackedUInt32::from_m31(a)
    }
    fn u32_const(&mut self, v: u32) -> PackedUInt32 {
        PackedUInt32::broadcast(UInt32::from(v))
    }
    fn u32_add(&mut self, a: PackedUInt32, b: PackedUInt32) -> PackedUInt32 {
        a + b
    }
    fn u32_sub(&mut self, a: PackedUInt32, b: PackedUInt32) -> PackedUInt32 {
        // PackedUInt32 has no Sub operator; wrapping lane-wise sub on the raw
        // simd matches the ISA's C-unsigned `(a - b)` exactly.
        PackedUInt32 {
            simd: a.simd - b.simd,
        }
    }
    fn u32_mul(&mut self, a: PackedUInt32, b: PackedUInt32) -> PackedUInt32 {
        PackedUInt32 {
            simd: a.simd * b.simd,
        }
    }
    fn u32_and_imm(&mut self, a: PackedUInt32, mask: u32) -> PackedUInt32 {
        a & PackedUInt32::broadcast(UInt32::from(mask))
    }
    fn u32_shl_imm(&mut self, a: PackedUInt32, amount: u32) -> PackedUInt32 {
        a << PackedUInt32::broadcast(UInt32::from(amount))
    }
    fn u32_shr_imm(&mut self, a: PackedUInt32, amount: u32) -> PackedUInt32 {
        a >> PackedUInt32::broadcast(UInt32::from(amount))
    }

    // ---- Builtin-lane leaves ----------------------------------------------------

    /// Bit-identical to `Seq::packed_at(self.row_index)` (common
    /// `preprocessed_columns/preprocessed_trace.rs`): `broadcast(16 * vec_row) + [0..16)`.
    #[inline(always)]
    fn iota(&mut self) -> PackedM31 {
        PackedM31::broadcast(M31::from(self.row_index * N_LANES))
            + unsafe { PackedM31::from_simd_unchecked(SIMD_ENUMERATION_0) }
    }

    // ---- Computed deduces (the REAL fast_deduction calls — byte-identical to the
    // ---- original writer, which calls these exact functions) ---------------------

    #[inline(always)]
    fn deduce_partial_ec_mul_w18(
        &mut self,
        chain: PackedM31,
        round: PackedM31,
        windows: [PackedM31; 14],
        acc: [PackedFelt252; 2],
    ) -> (PackedM31, PackedM31, ([PackedM31; 14], [PackedFelt252; 2])) {
        PackedPartialEcMulWindowBits18::deduce_output((chain, round, (windows, acc)))
    }

    #[inline(always)]
    fn deduce_pedersen_points_table_w18(&mut self, index: PackedM31) -> [PackedFelt252; 2] {
        PackedPedersenPointsTableWindowBits18::deduce_output([index])
    }

    #[inline(always)]
    fn deduce_partial_ec_mul_w9(
        &mut self,
        chain: PackedM31,
        round: PackedM31,
        windows: [PackedM31; 28],
        acc: [PackedFelt252; 2],
    ) -> (PackedM31, PackedM31, ([PackedM31; 28], [PackedFelt252; 2])) {
        PackedPartialEcMulWindowBits9::deduce_output((chain, round, (windows, acc)))
    }

    #[inline(always)]
    fn deduce_pedersen_points_table_w9(&mut self, index: PackedM31) -> [PackedFelt252; 2] {
        PackedPedersenPointsTableWindowBits9::deduce_output([index])
    }

    #[inline(always)]
    fn deduce_partial_ec_mul_generic(
        &mut self,
        chain: PackedM31,
        round: PackedM31,
        scalar: [PackedM31; 10],
        point: [PackedFelt252; 2],
        accumulator: [PackedFelt252; 2],
        counter: PackedM31,
    ) -> (
        PackedM31,
        PackedM31,
        (
            [PackedM31; 10],
            [PackedFelt252; 2],
            [PackedFelt252; 2],
            PackedM31,
        ),
    ) {
        let (chain, round, (scalar, point, accumulator, counter)) =
            *PackedPartialEcMulGeneric::deduce_output((
                chain,
                round,
                (w27_from_words(scalar), point, accumulator, counter),
            ));
        (
            chain,
            round,
            (w27_to_words(scalar), point, accumulator, counter),
        )
    }

    #[inline(always)]
    fn deduce_add_mod_is_zero(
        &mut self,
        a: [PackedFelt252; 4],
        b: [PackedFelt252; 4],
        c: [PackedFelt252; 4],
    ) -> PackedBool {
        let difference = (PackedBigUInt::<384, 6, 32>::from_packed_felt252_array(&a)
            + PackedBigUInt::<384, 6, 32>::from_packed_felt252_array(&b))
            - PackedBigUInt::<384, 6, 32>::from_packed_felt252_array(&c);
        difference.eq(PackedBigUInt::<384, 6, 32>::broadcast(BigUInt::default()))
    }

    #[inline(always)]
    fn deduce_mul_mod_quotient(
        &mut self,
        p: [PackedFelt252; 4],
        a: [PackedFelt252; 4],
        b: [PackedFelt252; 4],
        c: [PackedFelt252; 4],
    ) -> [PackedM31; 32] {
        let product = PackedBigUInt::<384, 6, 32>::from_packed_felt252_array(&a)
            .widening_mul::<768, 12, 64>(
                PackedBigUInt::<384, 6, 32>::from_packed_felt252_array(&b),
            );
        let c = PackedBigUInt::<768, 12, 64>::from_packed_biguint(
            PackedBigUInt::<384, 6, 32>::from_packed_felt252_array(&c),
        );
        let p = PackedBigUInt::<768, 12, 64>::from_packed_biguint(
            PackedBigUInt::<384, 6, 32>::from_packed_felt252_array(&p),
        );
        let quotient =
            PackedBigUInt::<384, 6, 32>::from_packed_biguint((product - c) / p);
        std::array::from_fn(|index| quotient.get_m31(index))
    }

    #[inline(always)]
    fn deduce_blake_g(&mut self, input: [PackedUInt32; 6]) -> [PackedUInt32; 4] {
        PackedBlakeG::deduce_output(input)
    }

    #[inline(always)]
    fn deduce_blake_round_sigma(&mut self, round: PackedM31) -> [PackedM31; 16] {
        PackedBlakeRoundSigma::deduce_output(round)
    }

    #[inline(always)]
    fn deduce_poseidon_round_keys(&mut self, round: PackedM31) -> [[PackedM31; 10]; 3] {
        PackedPoseidonRoundKeys::deduce_output([round]).map(w27_to_words)
    }

    #[inline(always)]
    fn deduce_poseidon_cube(&mut self, value: [PackedM31; 10]) -> [PackedM31; 10] {
        w27_to_words(PackedCube252::deduce_output(w27_from_words(value)))
    }

    #[inline(always)]
    fn deduce_poseidon_full_round_chain(
        &mut self,
        chain: PackedM31,
        round: PackedM31,
        state: [[PackedM31; 10]; 3],
    ) -> (PackedM31, PackedM31, [[PackedM31; 10]; 3]) {
        let (chain, round, state) =
            PackedPoseidonFullRoundChain::deduce_output((chain, round, state.map(w27_from_words)));
        (chain, round, state.map(w27_to_words))
    }

    #[inline(always)]
    fn deduce_poseidon_3_partial_rounds_chain(
        &mut self,
        chain: PackedM31,
        round: PackedM31,
        state: [[PackedM31; 10]; 4],
    ) -> (PackedM31, PackedM31, [[PackedM31; 10]; 4]) {
        let (chain, round, state) = PackedPoseidon3PartialRoundsChain::deduce_output((
            chain,
            round,
            state.map(w27_from_words),
        ));
        (chain, round, state.map(w27_to_words))
    }

    // ---- Effects ---------------------------------------------------------------

    #[inline(always)]
    fn set_col(&mut self, col: usize, value: PackedM31) {
        *self.row[col] = value;
    }
    #[inline(always)]
    fn set_lookup_word(&mut self, word: usize, value: PackedM31) {
        self.lookup_scratch[word] = value;
    }
    #[inline(always)]
    fn set_sub_input_word(&mut self, word: usize, value: PackedM31) {
        self.sub_scratch[word] = value.into_simd();
    }
    #[inline(always)]
    fn set_sub_input_word_u32(&mut self, word: usize, value: PackedUInt32) {
        self.sub_scratch[word] = value.simd;
    }
}

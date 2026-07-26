//! Backend-neutral evaluation of a generated Stwo-Cairo witness row.
//!
//! A transformed component has one straight-line row body over [`WitnessEval`].
//! [`simd::SimdWitnessEval`] executes that body with official packed SIMD types;
//! [`recording::RecordingWitnessEval`] records the same body as a scalar SSA program
//! consumed by Zig backends. The trait is a source compiler boundary, not a released
//! Rust runtime dependency.
//!
//! The SIMD implementation is an inlined passthrough to `PackedM31`,
//! `PackedUInt16`, and the original component effects. Exact column, lookup-data,
//! sub-input, and interaction parity against the unmodified official writer is the
//! permanent transformation oracle. The recorder is deterministic and
//! statement-independent: its output depends on component semantics, never on a
//! particular proof input.
//!
//! # Value model — masks, not branches
//!
//! SIMD values are packed (16 lanes per value): a scalar Rust branch cannot
//! represent per-lane divergence. The generated writers therefore contain NO
//! data-dependent control flow in their per-row bodies. All data dependence is expressed
//! as MASKED ARITHMETIC: `.eq()` produces a lane-mask which flows through `&` /
//! `.as_m31()` into 0/1 field factors. The trait mirrors exactly that: comparisons
//! return an opaque [`WitnessEval::Mask`] (never a host `bool`), and the lane-wise
//! [`WitnessEval::select`] is the only conditional combinator. A writer containing a
//! genuine Rust `if`/`match` on row data is NOT expressible against this trait and must
//! be a loud transformer skip — never lowered to a scalar branch.
//!
//! The witness program is a per-row scalar `u32` SSA machine. Trait methods map
//! directly to recorder operations, preserving single assignment and semantic hashes.
//! An operation outside the current instruction set poisons its dependent effects and
//! prevents export; incomplete programs can never be admitted silently.
//!
//! # Memory operations
//!
//! The `mem_*` methods mirror
//! `stwo_cairo_adapter::memory::EncodedMemoryValueId::decode`:
//!   * [`WitnessEval::mem_addr_to_id`]: dense-array read `address_to_raw_id[addr]` → encoded id.
//!   * [`WitnessEval::mem_id_to_value`]: decode `tag = id >> 30`, `val = id & 0x3FFF_FFFF` — tag 0
//!     → Small(val): 4 u32 words, split limbs 8..28 ZERO; tag 1 → F252(val): 8 u32 words; encoded
//!     `0x3FFF_FFFF` (`DEFAULT_ID`) → Empty (host panics; never reached for valid traces). Words
//!     split into 28 nine-bit limbs (`split_f252`).
//!   * [`WitnessEval::mem_read`]: the composed operation. Its default implementation
//!     chains the two fine-grained operations used by official generated writers.
//!
//! # Immediates
//!
//! `u16_shl`/`u16_shr`/`u16_and` take a `u32` immediate (shift amount / mask), matching
//! the ISA (`U16Shl`/`U16Shr`/`U16And` carry `imm`, not a register). In the source
//! writers these come from broadcast constants
//! (`PackedUInt16::broadcast(UInt16::from(k))`); the transformer resolves the constant
//! binding to the literal `k`.

pub mod bytecode;
pub mod recording;
pub mod simd;

/// Input-field slot ordering for the opcode family (`PackedCasmState`).
pub const SLOT_PC: u32 = 0;
pub const SLOT_AP: u32 = 1;
pub const SLOT_FP: u32 = 2;
/// The per-row enabler value (1 for real rows, 0 for padding) is fed as an extra input
/// slot in the recording lane.
pub const SLOT_ENABLER: u32 = 3;

/// Stable table identifiers for the two memory relations.
pub const TABLE_ADDR_TO_ID: u32 = 0;
pub const TABLE_ID_TO_BIG: u32 = 1;

/// Number of 9-bit limbs a `memory_id_to_big` value decodes to (`FELT252_N_WORDS`).
pub const FELT_N_LIMBS: usize = 28;

/// The abstraction a generic per-row witness body is written against.
///
/// A body is a straight-line sequence of method calls on `&mut impl WitnessEval` — no
/// data-dependent Rust control flow (see module docs: masks + `select`, never
/// branches). All arithmetic is routed through methods (the witness ISA uses explicit
/// builder calls, not operator overloading). Effects (`set_col` / `set_lookup_word` /
/// `set_sub_input_word`) are addressed by *flat index*; the SIMD driver reconstructs
/// the concrete typed `LookupData` / `SubComponentInputs` from those flat slots, and
/// the recorder maps them to `col_write` / `lookup_word` / `mult_push`.
pub trait WitnessEval {
    /// Arithmetic-domain value (SIMD: `PackedM31`; recording: SSA register).
    type M31: Copy;
    /// 16-bit integer / bit-domain value (SIMD: `PackedUInt16`; recording: SSA register).
    type U16: Copy;
    /// Per-lane comparison mask (SIMD: `PackedBool` — 16 lanes; recording: poisoned —
    /// no ISA support yet). NEVER a host `bool`: masks combine via `mask_*`/`select`,
    /// they are not branch conditions.
    type Mask: Copy;
    /// felt252 value — a bundle of 28 M31 limbs. Bodies only construct/extract limbs
    /// (no felt arithmetic), so this is pure bookkeeping (SIMD: `PackedFelt252`).
    type Felt: Clone;
    /// 32-bit integer value (SIMD: `PackedUInt32`; recording: a raw SSA register).
    type U32: Copy;

    // ---- Leaves ----------------------------------------------------------------

    /// Read packed input field `slot` for this row (`SLOT_PC`/`AP`/`FP`).
    fn input(&mut self, slot: u32) -> Self::M31;
    /// Materialize a canonical M31 constant.
    fn m31_const(&mut self, value: u32) -> Self::M31;
    /// The per-row enabler (1 real / 0 padding).
    fn enabler(&mut self) -> Self::M31;

    // ---- M31 field ops (ISA-core) ----------------------------------------------

    fn m31_add(&mut self, a: Self::M31, b: Self::M31) -> Self::M31;
    fn m31_sub(&mut self, a: Self::M31, b: Self::M31) -> Self::M31;
    fn m31_mul(&mut self, a: Self::M31, b: Self::M31) -> Self::M31;

    // ---- M31 field ops (EXTENDED — not in the 32-bit witness ISA; poisoned when
    // ---- recording; each use is an ISA-V2 backlog datum) -------------------------

    /// Multiplicative inverse (`FieldExpOps::inverse`).
    fn m31_inverse(&mut self, a: Self::M31) -> Self::M31;
    /// Lane-wise equality → mask (`PackedM31::eq`).
    fn m31_eq(&mut self, a: Self::M31, b: Self::M31) -> Self::Mask;

    // ---- Masks + lane-wise select (EXTENDED) -------------------------------------

    /// Lane-wise AND of masks.
    fn mask_and(&mut self, a: Self::Mask, b: Self::Mask) -> Self::Mask;
    /// Mask → 0/1 M31 factor (`PackedBool::as_m31`).
    fn mask_as_m31(&mut self, a: Self::Mask) -> Self::M31;
    /// 0/1 M31 factor → mask (`PackedBool::from_m31`; used by `blake_compress_opcode`).
    fn mask_from_m31(&mut self, a: Self::M31) -> Self::Mask;
    /// Lane-wise conditional: per lane, `m ? a : b`. The ONLY conditional combinator —
    /// transformed writers never branch on row data. (No pilot writer exercises it
    /// today; the generated code expresses selection as masked arithmetic, which the
    /// transformer preserves verbatim. `select` exists so future idioms have a lane-safe
    /// target, never a scalar branch.)
    fn select(&mut self, m: Self::Mask, a: Self::M31, b: Self::M31) -> Self::M31;

    // ---- u16 integer / bit ops (ISA-core) --------------------------------------

    fn u16_from_m31(&mut self, a: Self::M31) -> Self::U16;
    fn u16_as_m31(&mut self, a: Self::U16) -> Self::M31;
    fn u16_add(&mut self, a: Self::U16, b: Self::U16) -> Self::U16;
    fn u16_shl(&mut self, a: Self::U16, imm: u32) -> Self::U16;
    fn u16_shr(&mut self, a: Self::U16, imm: u32) -> Self::U16;
    fn u16_and(&mut self, a: Self::U16, mask: u32) -> Self::U16;
    /// Recording lane lowers this to `U32Xor` — bit-identical because both operands are
    /// `< 2^16` (the ISA has no dedicated `U16Xor`).
    fn u16_xor(&mut self, a: Self::U16, b: Self::U16) -> Self::U16;

    // ---- Felt (bookkeeping) ----------------------------------------------------

    fn felt_from_limbs(&mut self, limbs: [Self::M31; FELT_N_LIMBS]) -> Self::Felt;
    fn felt_get_m31(&mut self, felt: &Self::Felt, i: usize) -> Self::M31;
    /// Embed the canonical 31-bit M31 integer into Felt252. This is an integer
    /// embedding, not an M31-field conversion: limbs 0..3 hold consecutive 9-bit
    /// windows and limbs 4..27 are zero.
    fn felt_from_m31(&mut self, value: Self::M31) -> Self::Felt;

    /// Reassemble a `Felt252` from the 10 words of a `Felt252Width27` input —
    /// an EXACT regroup (27 = 3x9): 9-bit limb `3j+t` = `(w[j] >> 9t) & 0x1FF`
    /// for `j < 9`, limb 27 = `w[9]` (its top word is 9 bits). SIMD uses the
    /// production conversion pair (`PackedFelt252Width27::from_limbs` +
    /// `PackedFelt252::from_packed_felt252width27`) — byte-identical by
    /// construction; the recording lowers the schoolbook shifts.
    fn felt_from_w27_words(&mut self, words: [Self::M31; 10]) -> Self::Felt;

    // ---- Felt field arithmetic (fp256 body ops — the partial_ec_mul writers'
    // ---- inline `Felt252` operators; recording = DeduceKind::Felt{Add,Sub,Mul,Div}).

    fn felt_add(&mut self, a: Self::Felt, b: Self::Felt) -> Self::Felt;
    fn felt_sub(&mut self, a: Self::Felt, b: Self::Felt) -> Self::Felt;
    fn felt_mul(&mut self, a: Self::Felt, b: Self::Felt) -> Self::Felt;
    /// Host semantics panic on division by zero (`Felt252`'s `Div`); the
    /// writers only divide by EC slope denominators.
    fn felt_div(&mut self, a: Self::Felt, b: Self::Felt) -> Self::Felt;

    // ---- Memory ops (the keystone binding — see module docs) --------------------

    /// `memory_address_to_id.deduce_output(addr)` → encoded id.
    /// Host: dense `address_to_raw_id[addr]` read. Device/recording:
    /// `table_limb(TABLE_ADDR_TO_ID, addr, 0)` — the exec-tables addr→id column.
    fn mem_addr_to_id(&mut self, addr: Self::M31) -> Self::M31;
    /// `memory_id_to_big.deduce_output(id)` → felt (28 nine-bit limbs).
    /// Host: `EncodedMemoryValueId(id).decode()` — tag `id >> 30`: 0 → Small (4 u32
    /// words; split limbs 8..28 are ZERO), 1 → F252 (8 u32 words), `0x3FFF_FFFF` →
    /// Empty (panic); then `split_f252`. Device/recording: `felt_get_m31(_, i)` on the
    /// result is `table_limb(TABLE_ID_TO_BIG, id, i)`; the composed device kernel
    /// (`DeviceExecutionTables`) implements the same dispatch in-kernel.
    fn mem_id_to_value(&mut self, id: Self::M31) -> Self::Felt;
    /// Composed read: `(id, value)` — 1:1 with the hardware-proven
    /// `DeviceExecutionTables::deduce_output_device`. Default: chain the two ops.
    fn mem_read(&mut self, addr: Self::M31) -> (Self::M31, Self::Felt) {
        let id = self.mem_addr_to_id(addr);
        let value = self.mem_id_to_value(id);
        (id, value)
    }

    // ---- u32 integer ops (the blake family; full 32-bit words) -------------------

    /// `PackedUInt32::from_limbs([low, high])`: `low + (high << 16)` (both operands
    /// canonical 16-bit M31 values; common `prover_types/simd.rs:204`).
    fn u32_from_limbs(&mut self, low: Self::M31, high: Self::M31) -> Self::U32;
    /// `PackedUInt32::low()`: `a & 0xFFFF` (simd.rs:192).
    fn u32_low(&mut self, a: Self::U32) -> Self::U16;
    /// `PackedUInt32::high()`: `a >> 16` (simd.rs:198).
    fn u32_high(&mut self, a: Self::U32) -> Self::U16;

    /// Read the full-32-bit input word at `slot` (the blake message words; the device
    /// lane's input columns are raw u32 buffers, so the same column serves both).
    fn input_u32(&mut self, slot: u32) -> Self::U32;

    /// `PackedUInt32::from_m31(a)`: the canonical M31 value as a 32-bit word (pure
    /// widening — the recording reuses the register, whose value is already < P).
    fn u32_from_m31(&mut self, a: Self::M31) -> Self::U32;
    /// A broadcast u32 constant (`PackedUInt32::broadcast(UInt32::from(v))`).
    fn u32_const(&mut self, v: u32) -> Self::U32;
    /// Wrapping 32-bit arithmetic (`PackedUInt32` operator semantics).
    fn u32_add(&mut self, a: Self::U32, b: Self::U32) -> Self::U32;
    fn u32_sub(&mut self, a: Self::U32, b: Self::U32) -> Self::U32;
    fn u32_mul(&mut self, a: Self::U32, b: Self::U32) -> Self::U32;
    fn u32_and_imm(&mut self, a: Self::U32, mask: u32) -> Self::U32;
    fn u32_shl_imm(&mut self, a: Self::U32, amount: u32) -> Self::U32;
    fn u32_shr_imm(&mut self, a: Self::U32, amount: u32) -> Self::U32;

    // ---- Builtin-lane leaves (the fp256/EC family; opcode bodies never call these) --

    /// The packed row index (`seq.packed_at(row_index)` — the iota column the builtin
    /// writers read). SIMD: derived from `row_index` bit-identically to
    /// `Seq::packed_at`. Recording: an `Input` read of the lane's designated iota slot
    /// (the device lane feeds an iota column), or poison when no slot is configured.
    fn iota(&mut self) -> Self::M31;

    // ---- Computed deduces (G5 — the EC/blake deduce family) -----------------------
    //
    // Each hook mirrors ONE `witness/fast_deduction` signature exactly (host tuple
    // shape), so emitted projections on the result compile natively on both
    // evaluators. SIMD: the REAL fast_deduction call — byte-identical to the original
    // writer by construction. Recording: an all-poison result + a `poison_ops` census
    // entry: the honest, pinned manifest of operations still requiring backend
    // implementation or direct component-to-component feeding.

    /// `PackedPartialEcMulWindowBits18::deduce_output` (fast_deduction/pedersen.rs):
    /// one windowed EC-mul round; `(chain, round, ([window; 14], [accumulator; 2]))`.
    #[allow(clippy::type_complexity)]
    fn deduce_partial_ec_mul_w18(
        &mut self,
        chain: Self::M31,
        round: Self::M31,
        windows: [Self::M31; 14],
        acc: [Self::Felt; 2],
    ) -> (Self::M31, Self::M31, ([Self::M31; 14], [Self::Felt; 2]));

    /// `PackedPedersenPointsTableWindowBits18::deduce_output` (fast_deduction/
    /// pedersen.rs): the pedersen points-table row `[x, y]` for a window index.
    fn deduce_pedersen_points_table_w18(&mut self, index: Self::M31) -> [Self::Felt; 2];

    /// Nine-bit-window variant: 28 shifted windows and the same two-felt accumulator.
    #[allow(clippy::type_complexity)]
    fn deduce_partial_ec_mul_w9(
        &mut self,
        chain: Self::M31,
        round: Self::M31,
        windows: [Self::M31; 28],
        acc: [Self::Felt; 2],
    ) -> (Self::M31, Self::M31, ([Self::M31; 28], [Self::Felt; 2]));

    /// Nine-bit Pedersen points-table row `[x, y]`.
    fn deduce_pedersen_points_table_w9(&mut self, index: Self::M31) -> [Self::Felt; 2];

    /// `PackedPartialEcMulGeneric::deduce_output` (fast_deduction/ec_op.rs):
    /// one bit-at-a-time EC-mul round. The width-27 scalar is represented by its ten
    /// canonical M31 words so the recording and device lanes share an explicit ABI.
    #[allow(clippy::type_complexity)]
    fn deduce_partial_ec_mul_generic(
        &mut self,
        chain: Self::M31,
        round: Self::M31,
        scalar: [Self::M31; 10],
        point: [Self::Felt; 2],
        accumulator: [Self::Felt; 2],
        counter: Self::M31,
    ) -> (
        Self::M31,
        Self::M31,
        ([Self::M31; 10], [Self::Felt; 2], [Self::Felt; 2], Self::M31),
    );

    /// `PackedBlakeG::deduce_output` (fast_deduction/blake.rs): the blake g-function,
    /// `[a, b, c, d, m0, m1] -> [a', b', c', d']` on full 32-bit words.
    fn deduce_blake_g(&mut self, input: [Self::U32; 6]) -> [Self::U32; 4];

    /// `PackedBlakeRoundSigma::deduce_output` (fast_deduction/blake.rs): the sigma
    /// permutation row for a round index (`[M31; 16]`).
    fn deduce_blake_round_sigma(&mut self, round: Self::M31) -> [Self::M31; 16];

    fn deduce_poseidon_round_keys(&mut self, round: Self::M31) -> [[Self::M31; 10]; 3];
    fn deduce_poseidon_cube(&mut self, value: [Self::M31; 10]) -> [Self::M31; 10];
    fn deduce_poseidon_full_round_chain(
        &mut self,
        chain: Self::M31,
        round: Self::M31,
        state: [[Self::M31; 10]; 3],
    ) -> (Self::M31, Self::M31, [[Self::M31; 10]; 3]);
    fn deduce_poseidon_3_partial_rounds_chain(
        &mut self,
        chain: Self::M31,
        round: Self::M31,
        state: [[Self::M31; 10]; 4],
    ) -> (Self::M31, Self::M31, [[Self::M31; 10]; 4]);

    // ---- Effects (flat-indexed) ------------------------------------------------

    /// Commit `value` to trace column `col`.
    fn set_col(&mut self, col: usize, value: Self::M31);
    /// Emit lookup-tuple word `word` (flat index across all `LookupData` fields in
    /// declaration order).
    fn set_lookup_word(&mut self, word: usize, value: Self::M31);
    /// Emit sub-component-input word `word` (flat index across all `SubComponentInputs`
    /// tuple/array scalars in declaration order; a felt-valued sub-input occupies 28
    /// consecutive words — its canonical 9-bit limbs).
    fn set_sub_input_word(&mut self, word: usize, value: Self::M31);
    /// Emit a FULL-32-BIT sub-component-input word (the blake_g feeds). Same flat
    /// index space as `set_sub_input_word`; the word is raw u32, not M31.
    fn set_sub_input_word_u32(&mut self, word: usize, value: Self::U32);
}

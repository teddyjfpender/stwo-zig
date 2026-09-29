//! The builder circuits of rungs R1 and R2.
//!
//! Every case is written once, generically over the builder value type, and is built both in
//! value mode (`QM31`) and topology mode (`NoValue`). Inputs enter only through the public
//! guessing API (`guess`, `Guess` impls of the wrappers), exactly as upstream verifier circuits
//! introduce witness data, so every case is a well-formed circuit after `finalize`.

use circuit_verifier::circuit_hash::compute_circuit_hash;
use circuits::blake::{HashValue, blake2s, blake2s_m31, blake2s_u32s, reduce_hash_value};
use circuits::context::{Context, Var};
use circuits::eval;
use circuits::extract_bits::extract_bits;
use circuits::ivalue::{IValue, qm31_from_u32s};
use circuits::ops::{
    Guess, add, cond_flip, conj, div, eq, from_partial_evals, guess, im, inv, mul, permute,
    pointwise_mul, sub,
};
use circuits::simd::Simd;
use circuits::utils::select_by_index;
use circuits::wrappers::{M31Wrapper, U16Wrapper, U32Wrapper};
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::QM31;

use crate::goldens;

/// A builder circuit. `outputs` lists the variables whose values the checkpoint records.
#[derive(Clone, Copy)]
pub enum Case {
    DefaultContext,
    ReservedOutputs,
    ArithmeticPeepholes,
    Constants,
    Wrappers,
    Blake2sU32s(usize),
    Blake2sQm31 { n_bytes: usize, reduce: bool },
    ExtractBits { n_bits: u32 },
    SimdOps,
    SelectByIndex,
    SortByUPermutation,
    ReduceHashValue,
    CircuitHash,
}

pub const CASES: [Case; 20] = [
    Case::DefaultContext,
    Case::ReservedOutputs,
    Case::ArithmeticPeepholes,
    Case::Constants,
    Case::Wrappers,
    Case::Blake2sU32s(0),
    Case::Blake2sU32s(4),
    Case::Blake2sU32s(44),
    Case::Blake2sU32s(64),
    Case::Blake2sU32s(65),
    Case::Blake2sU32s(128),
    Case::Blake2sQm31 {
        n_bytes: 44,
        reduce: false,
    },
    Case::Blake2sQm31 {
        n_bytes: 66,
        reduce: true,
    },
    Case::ExtractBits { n_bits: 8 },
    Case::ExtractBits { n_bits: 31 },
    Case::SimdOps,
    Case::SelectByIndex,
    Case::SortByUPermutation,
    Case::ReduceHashValue,
    Case::CircuitHash,
];

fn value<V: IValue>(a: u32, b: u32, c: u32, d: u32) -> V {
    V::from_qm31(qm31_from_u32s(a, b, c, d))
}

/// Hash words at or above `P`, so the in-circuit `reduce_hash_value` must reduce.
pub const REDUCE_HASH_WORDS: [u32; 8] = [P, P + 1, u32::MAX, 0x8000_0000, P - 1, 0, 1, 0xdead_beef];

fn guess_u32<V: IValue>(ctx: &mut Context<V>, word: u32) -> U32Wrapper<Var> {
    U32Wrapper::<V>::from_u32wrapper_qm31(QM31::pack_u32(word)).guess(ctx)
}

fn guess_hash<V: IValue>(ctx: &mut Context<V>, words: [u32; 8]) -> HashValue<Var> {
    HashValue(words.map(|w| U32Wrapper::<V>::from_u32wrapper_qm31(QM31::pack_u32(w)))).guess(ctx)
}

fn guess_m31s<V: IValue>(ctx: &mut Context<V>, values: &[u32]) -> Simd {
    let packed: Vec<V> = values
        .chunks(4)
        .map(|chunk| {
            let lane = |i: usize| chunk.get(i).copied().unwrap_or(0);
            value(lane(0), lane(1), lane(2), lane(3))
        })
        .collect();
    Simd::from_packed(packed.guess(ctx), values.len())
}

/// Deterministic message bytes: `(7 * i + 3) mod 256`.
pub fn message_bytes(n_bytes: usize) -> Vec<u8> {
    (0..n_bytes).map(|i| (7 * i + 3) as u8).collect()
}

/// Little-endian words of `bytes`, zero-padding the last word.
pub fn message_words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(4)
        .map(|chunk| {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            u32::from_le_bytes(word)
        })
        .collect()
}

/// M31-valued message words for the QM31-input Blake2s gadgets (each word below `P`).
pub fn m31_message_words(n_bytes: usize) -> Vec<u32> {
    let mut words: Vec<u32> = (0..n_bytes.div_ceil(4) as u32)
        .map(|i| (0x0101_0101u32.wrapping_mul(i + 3)) & P)
        .collect();
    let tail = n_bytes % 4;
    if tail != 0 {
        let last = words.last_mut().unwrap();
        *last &= (1u32 << (8 * tail)) - 1;
    }
    words
}

impl Case {
    pub fn name(self) -> String {
        match self {
            Case::DefaultContext => "default_context".into(),
            Case::ReservedOutputs => "reserved_outputs".into(),
            Case::ArithmeticPeepholes => "arithmetic_peepholes".into(),
            Case::Constants => "constants".into(),
            Case::Wrappers => "wrappers".into(),
            Case::Blake2sU32s(n) => format!("blake2s_u32s_{n}b"),
            Case::Blake2sQm31 {
                n_bytes,
                reduce: false,
            } => format!("blake2s_qm31_{n_bytes}b"),
            Case::Blake2sQm31 {
                n_bytes,
                reduce: true,
            } => format!("blake2s_m31_{n_bytes}b"),
            Case::ExtractBits { n_bits } => format!("extract_bits_{n_bits}"),
            Case::SimdOps => "simd_ops".into(),
            Case::SelectByIndex => "select_by_index".into(),
            Case::SortByUPermutation => "sort_by_u_permutation".into(),
            Case::ReduceHashValue => "reduce_hash_value".into(),
            Case::CircuitHash => "circuit_hash".into(),
        }
    }

    pub fn rung(self) -> &'static str {
        match self {
            Case::DefaultContext
            | Case::ReservedOutputs
            | Case::ArithmeticPeepholes
            | Case::Constants => "r1",
            _ => "r2",
        }
    }

    /// `Context::new(n_reserved)` argument.
    pub fn n_reserved(self) -> usize {
        match self {
            Case::ReservedOutputs => 8,
            _ => 0,
        }
    }

    pub fn build<V: IValue>(self, ctx: &mut Context<V>) -> Vec<Var> {
        match self {
            Case::DefaultContext => vec![],
            Case::ReservedOutputs => {
                let digest = std::array::from_fn(|i| 0x0f0e_0d0c ^ (i as u32 * 0x1111_1111));
                let vars: Vec<Var> = guess_hash(ctx, digest).iter().map(|w| *w.get()).collect();
                ctx.set_outputs(&vars);
                vars
            }
            Case::ArithmeticPeepholes => arithmetic_peepholes(ctx),
            Case::Constants => constants(ctx),
            Case::Wrappers => wrappers(ctx),
            Case::Blake2sU32s(n_bytes) => {
                let words = message_words(&message_bytes(n_bytes))
                    .into_iter()
                    .map(|word| guess_u32(ctx, word))
                    .collect();
                blake2s_u32s(ctx, words, n_bytes)
                    .iter()
                    .map(|w| *w.get())
                    .collect()
            }
            Case::Blake2sQm31 { n_bytes, reduce } => {
                let words = m31_message_words(n_bytes);
                let input: Vec<Var> = guess_m31s(ctx, &words).get_packed().to_vec();
                if reduce {
                    let hash = blake2s_m31(ctx, &input, n_bytes);
                    vec![hash.0, hash.1]
                } else {
                    blake2s(ctx, &input, n_bytes)
                        .iter()
                        .map(|w| *w.get())
                        .collect()
                }
            }
            Case::ExtractBits { n_bits } => {
                let lanes: Vec<u32> = if n_bits == 31 {
                    vec![0, 1, P - 1, 0x5555_5555, 0x4000_0000]
                } else {
                    vec![0, 1, 0x80, 0xff, 0x5a]
                };
                let input = guess_m31s(ctx, &lanes);
                extract_bits(ctx, &input, n_bits)
                    .iter()
                    .flat_map(|bit| bit.get_packed().to_vec())
                    .collect()
            }
            Case::SimdOps => simd_ops(ctx),
            Case::SelectByIndex => {
                let values: Vec<Var> = (0..8).map(|i| guess(ctx, value(10 + i, i, 0, 1))).collect();
                // Index 5 = 0b101, little-endian bits.
                let bits: Vec<Var> = [1, 0, 1]
                    .into_iter()
                    .map(|b| guess(ctx, value(b, 0, 0, 0)))
                    .collect();
                vec![select_by_index(ctx, &values, &bits)]
            }
            Case::SortByUPermutation => {
                let inputs: Vec<Var> = [(1, 9), (2, 3), (3, 7), (4, 3), (5, 0)]
                    .into_iter()
                    .map(|(a, u)| guess(ctx, value(a, 0, u, 0)))
                    .collect();
                permute(ctx, &inputs, |values| V::sort_by_u_coordinate(values))
            }
            Case::ReduceHashValue => {
                let hash = guess_hash(ctx, REDUCE_HASH_WORDS);
                let reduced = reduce_hash_value(ctx, hash);
                vec![reduced.0, reduced.1]
            }
            Case::CircuitHash => {
                let root = guess_hash(ctx, std::array::from_fn(|i| i as u32));
                compute_circuit_hash(
                    ctx,
                    &goldens::component_sizes(goldens::CIRCUIT_HASH_TEST_GATES),
                    goldens::CIRCUIT_HASH_TEST_LOG_BLOWUP,
                    &root,
                )
                .iter()
                .map(|w| *w.get())
                .collect()
            }
        }
    }
}

fn arithmetic_peepholes<V: IValue>(ctx: &mut Context<V>) -> Vec<Var> {
    let zero = ctx.zero();
    let one = ctx.one();
    let a = guess(ctx, value(7, 0, 0, 0));
    let b = guess(ctx, value(3, 1, 4, 1));
    let c = guess(ctx, value(P - 1, 5, 0, 9));
    let selector = guess(ctx, value(1, 0, 0, 0));

    // Index-only peepholes: none of these emits a gate.
    let a0 = add(ctx, a, zero);
    let b0 = add(ctx, zero, b);
    let a1 = mul(ctx, a, one);
    let b1 = mul(ctx, one, b);
    let z = mul(ctx, zero, c);
    // `sub` and `pointwise_mul` never elide.
    let a_minus_zero = sub(ctx, a, zero);
    let pw_one = pointwise_mul(ctx, b, one);

    let sum = add(ctx, a0, b0);
    let sum_swapped = add(ctx, b1, a1);
    eq(ctx, sum, sum_swapped);
    let expr = eval!(ctx, ((a) * (b)) - (1));
    let negated = eval!(ctx, -(c));
    let quotient = div(ctx, a, b);
    let inverse = inv(ctx, c);
    let conjugate = conj(ctx, b);
    let imaginary = im(ctx, c);
    let combined = from_partial_evals(ctx, [a, a_minus_zero, pw_one, sum]);
    let (flip_a, flip_b) = cond_flip(ctx, selector, a, b);
    vec![
        z, expr, negated, quotient, inverse, conjugate, imaginary, combined, flip_a, flip_b,
    ]
}

fn constants<V: IValue>(ctx: &mut Context<V>) -> Vec<Var> {
    let qm31_constants = [
        qm31_from_u32s(2, 0, 0, 0),
        qm31_from_u32s(4, 0, 0, 0),
        qm31_from_u32s(37, 0, 0, 0),
        qm31_from_u32s(300, 0, 0, 0),
        qm31_from_u32s(1_000_000, 0, 0, 0),
        qm31_from_u32s(P - 1, 0, 0, 0),
        qm31_from_u32s(11, 11, 11, 11),
        qm31_from_u32s(0, 1, 0, 0),
        qm31_from_u32s(0, 0, 0, 1),
        qm31_from_u32s(1, 2, 3, 4),
        qm31_from_u32s(0, 7, 0, 0),
        // Interned: the second request returns the first variable.
        qm31_from_u32s(37, 0, 0, 0),
    ];
    let x = guess(ctx, value(5, 6, 7, 8));
    qm31_constants
        .into_iter()
        .map(|constant| {
            let var = ctx.constant(constant);
            mul(ctx, x, var)
        })
        .collect()
}

fn wrappers<V: IValue>(ctx: &mut Context<V>) -> Vec<Var> {
    let u16_value = U16Wrapper::new_unsafe(value::<V>(0xbeef, 0, 0, 0)).guess(ctx);
    let u32_value = guess_u32(ctx, 0xdead_beef);
    let u32_const = U32Wrapper::const_u32(ctx, 0x0001_0002);
    let m31_value = M31Wrapper::<V>::from_m31(M31::from(P - 2)).guess(ctx);
    let m31_const = M31Wrapper::const_m31(ctx, M31::from(12345));
    let m31_product = M31Wrapper::mul(ctx, m31_value.clone(), m31_const);
    vec![
        *u16_value.get(),
        *u32_value.get(),
        *u32_const.get(),
        *m31_value.get(),
        *m31_product.get(),
    ]
}

fn simd_ops<V: IValue>(ctx: &mut Context<V>) -> Vec<Var> {
    let a = guess_m31s(ctx, &[1, 2, 3, 4, 5, 6]);
    let b = guess_m31s(ctx, &[7, 9, 11, 13, 15, 17]);
    let bits = guess_m31s(ctx, &[1, 0, 1, 1, 0, 1]);
    let high_bits = guess_m31s(ctx, &[0, 1, 1, 0, 0, 1]);

    let sum = Simd::add(ctx, &a, &b);
    let difference = Simd::sub(ctx, &b, &a);
    let product = Simd::mul(ctx, &a, &b);
    let three = M31Wrapper::const_m31(ctx, M31::from(3));
    let scaled = Simd::scalar_mul(ctx, &a, &three);
    let inverse = b.inv(ctx);
    let selected = Simd::select(ctx, &bits, &a, &b);
    bits.assert_bits(ctx);
    let powers = Simd::pow2(ctx, &[bits.clone(), high_bits.clone()]);
    let combined = Simd::combine_bits(ctx, &[bits, high_bits]);
    let repeated = Simd::repeat(ctx, M31::from(9), 6);
    let lane = Simd::unpack_idx(ctx, &sum, 5);
    let unpacked = Simd::unpack(ctx, &product);
    let wrapped: Vec<M31Wrapper<Var>> = unpacked
        .iter()
        .map(|v| M31Wrapper::new_unsafe(*v))
        .collect();
    let repacked = Simd::pack(ctx, &wrapped);
    Simd::eq(ctx, &repacked, &product);

    let mut outputs = vec![lane];
    for simd in [
        sum, difference, scaled, inverse, selected, powers, combined, repeated,
    ] {
        outputs.extend_from_slice(simd.get_packed());
    }
    outputs
}

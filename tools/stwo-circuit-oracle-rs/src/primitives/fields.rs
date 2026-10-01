//! M31 reduction and QM31 operation vectors, including the circuit-local pointwise operations of
//! `circuits::ivalue::IValue` and the `u32` limb packing used by every u32 gadget.

use circuits::ivalue::{IValue, qm31_from_u32s};
use num_traits::Zero;
use serde::Serialize;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::QM31;

use crate::checkpoint::qm31;

#[derive(Serialize)]
pub struct M31FromU32 {
    pub input: u32,
    pub output: u32,
}

#[derive(Serialize)]
pub struct M31ReduceU64 {
    pub input: String,
    pub output: u32,
}

#[derive(Serialize)]
pub struct Qm31FromU32s {
    pub input: [u32; 4],
    pub output: [u32; 4],
}

#[derive(Serialize)]
pub struct Qm31Pair {
    pub a: [u32; 4],
    pub b: [u32; 4],
    pub add: [u32; 4],
    pub sub: [u32; 4],
    pub mul: [u32; 4],
    pub pointwise_mul: [u32; 4],
}

#[derive(Serialize)]
pub struct Qm31Unary {
    pub a: [u32; 4],
    pub neg: [u32; 4],
    /// `None` for zero, which has no inverse.
    pub inverse: Option<[u32; 4]>,
    pub pointwise_inv_or_zero: [u32; 4],
    pub pointwise_lsb: [u32; 4],
}

#[derive(Serialize)]
pub struct M31ToU32Limbs {
    /// The base-field input `(x, 0, 0, 0)`.
    pub input: u32,
    /// `IValue::m31_to_u32`: `(x & 0xFFFF, x >> 16, 0, 0)`.
    pub output: [u32; 4],
}

#[derive(Serialize)]
pub struct PackU32 {
    pub value: u32,
    /// `IValue::pack_u32`: `(value & 0xFFFF, value >> 16, 0, 0)`; `unpack_u32` inverts it.
    pub packed: [u32; 4],
}

#[derive(Serialize)]
pub struct FieldsSection {
    pub m31_from_u32: Vec<M31FromU32>,
    pub m31_reduce_u64: Vec<M31ReduceU64>,
    pub qm31_from_u32s: Vec<Qm31FromU32s>,
    pub qm31_binary: Vec<Qm31Pair>,
    pub qm31_unary: Vec<Qm31Unary>,
    pub m31_to_u32: Vec<M31ToU32Limbs>,
    pub pack_u32: Vec<PackU32>,
}

const U32_EDGES: [u32; 11] = [
    0,
    1,
    2,
    0xffff,
    0x1_0000,
    0x1234_5678,
    P - 1,
    P,
    P + 1,
    0xffff_fffe,
    u32::MAX,
];

fn sample_qm31s() -> Vec<QM31> {
    vec![
        QM31::zero(),
        qm31_from_u32s(1, 0, 0, 0),
        qm31_from_u32s(0, 1, 0, 0),
        qm31_from_u32s(0, 0, 1, 0),
        qm31_from_u32s(0, 0, 0, 1),
        qm31_from_u32s(P - 1, P - 1, P - 1, P - 1),
        qm31_from_u32s(2, 3, 5, 7),
        qm31_from_u32s(1_659_099_300, 905_558_730, 651_199_673, 1_375_009_625),
        qm31_from_u32s(474_642_921, 876_336_632, 1_911_695_779, 974_600_512),
        qm31_from_u32s(0xffff, 0x7fff, 0, 0),
        qm31_from_u32s(0, 0, 1 << 30, 3),
    ]
}

pub fn fields_section() -> FieldsSection {
    let m31_from_u32 = U32_EDGES
        .iter()
        .map(|&input| M31FromU32 {
            input,
            output: M31::from(input).0,
        })
        .collect();

    let p = P as u64;
    let m31_reduce_u64 = [
        0,
        p,
        p + 1,
        2 * p,
        p * p - 1,
        (p - 1) * (p - 1),
        u32::MAX as u64 * 3,
    ]
    .into_iter()
    .map(|input| M31ReduceU64 {
        input: input.to_string(),
        output: M31::reduce(input).0,
    })
    .collect();

    let from_u32s: Vec<Qm31FromU32s> = [[P, P + 1, u32::MAX, 5], [0, P - 1, 0x8000_0000, 1]]
        .into_iter()
        .map(|input: [u32; 4]| Qm31FromU32s {
            input,
            output: qm31(qm31_from_u32s(input[0], input[1], input[2], input[3])),
        })
        .collect();

    let samples = sample_qm31s();
    let mut qm31_binary = Vec::new();
    for (i, &a) in samples.iter().enumerate() {
        for &b in samples.iter().skip(i) {
            qm31_binary.push(Qm31Pair {
                a: qm31(a),
                b: qm31(b),
                add: qm31(a + b),
                sub: qm31(a - b),
                mul: qm31(a * b),
                pointwise_mul: qm31(<QM31 as IValue>::pointwise_mul(a, b)),
            });
        }
    }

    let qm31_unary = samples
        .iter()
        .map(|&a| Qm31Unary {
            a: qm31(a),
            neg: qm31(-a),
            inverse: (!a.is_zero()).then(|| qm31(a.inverse())),
            pointwise_inv_or_zero: qm31(a.pointwise_inv_or_zero()),
            pointwise_lsb: qm31(a.pointwise_lsb()),
        })
        .collect();

    let m31_to_u32 = [0, 1, 0xffff, 0x1_0000, 0x1234_5678, P - 1]
        .into_iter()
        .map(|input| M31ToU32Limbs {
            input,
            output: qm31(qm31_from_u32s(input, 0, 0, 0).m31_to_u32()),
        })
        .collect();

    let pack_u32 = U32_EDGES
        .iter()
        .map(|&value| {
            let packed = *<QM31 as IValue>::pack_u32(value).get();
            assert_eq!(packed.unpack_u32(), value, "pack_u32/unpack_u32 round trip");
            PackU32 {
                value,
                packed: qm31(packed),
            }
        })
        .collect();

    FieldsSection {
        m31_from_u32,
        m31_reduce_u64,
        qm31_from_u32s: from_u32s,
        qm31_binary,
        qm31_unary,
        m31_to_u32,
        pack_u32,
    }
}

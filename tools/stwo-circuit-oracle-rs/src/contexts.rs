//! The small test circuits of `crates/circuit_prover/src/prover_test.rs`.
//!
//! Upstream keeps `build_{fibonacci,permutation,blake,triple_xor,m31_to_u32,blake_g_gate}_context`
//! in a `#[cfg(test)]` module, so the oracle cannot call them. They are transcribed here call for
//! call, generic over `IValue` so that the same builder produces the value-mode and the
//! topology-mode circuit (upstream builds them in `Context<QM31>` only). In value mode each
//! builder re-asserts the upstream `expect!` snapshots, which pins the transcription; `prove-small`
//! additionally asserts the upstream preprocessed-root snapshots of the proven circuits.

use anyhow::{Result, ensure};
use circuit_common::N_RESERVED;
use circuits::blake::{blake_g_gate, blake2s_m31, m31_to_u32, triple_xor};
use circuits::context::{Context, FinalizedContext, Var};
use circuits::eval;
use circuits::ivalue::{IValue, NoValue, qm31_from_u32s};
use circuits::ops::{Guess, guess, permute};
use circuits::wrappers::U32Wrapper;
use stwo::core::fields::qm31::QM31;

use crate::checkpoint::values_sha256;

/// The value-mode-only operations of a context: no-ops (or `None`) in topology mode.
pub trait Mode: IValue {
    fn enable_assert_eq_on_eval(context: &mut Context<Self>);
    fn is_circuit_valid(context: &FinalizedContext<Self>) -> bool;
    fn values_sha256(values: &[Self]) -> Option<String>;
}

impl Mode for QM31 {
    fn enable_assert_eq_on_eval(context: &mut Context<Self>) {
        context.enable_assert_eq_on_eval();
    }

    fn is_circuit_valid(context: &FinalizedContext<Self>) -> bool {
        context.is_circuit_valid()
    }

    fn values_sha256(values: &[Self]) -> Option<String> {
        Some(values_sha256(values))
    }
}

impl Mode for NoValue {
    fn enable_assert_eq_on_eval(_: &mut Context<Self>) {}

    fn is_circuit_valid(_: &FinalizedContext<Self>) -> bool {
        true
    }

    fn values_sha256(_: &[Self]) -> Option<String> {
        None
    }
}

/// `N` of `prover_test.rs`: not a power of 2, so that component padding is exercised.
const FIBONACCI_N: usize = 1030;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestContext {
    Fibonacci,
    Permutation,
    Blake,
    TripleXor,
    M31ToU32,
    BlakeGGate,
}

pub const ALL: [TestContext; 6] = [
    TestContext::Fibonacci,
    TestContext::Permutation,
    TestContext::Blake,
    TestContext::TripleXor,
    TestContext::M31ToU32,
    TestContext::BlakeGGate,
];

/// A value-mode `expect!` snapshot of `prover_test.rs`: the `Debug` text of a builder value.
struct Snapshot {
    actual: String,
    expected: &'static str,
}

impl TestContext {
    pub fn name(self) -> &'static str {
        match self {
            Self::Fibonacci => "fibonacci",
            Self::Permutation => "permutation",
            Self::Blake => "blake",
            Self::TripleXor => "triple_xor",
            Self::M31ToU32 => "m31_to_u32",
            Self::BlakeGGate => "blake_g_gate",
        }
    }

    /// The `n_reserved` of the upstream builder (`Context::new(N_RESERVED)` or `default()`).
    pub fn n_reserved(self) -> usize {
        match self {
            Self::Permutation | Self::Blake => 0,
            _ => N_RESERVED,
        }
    }

    /// Builds the context. Value-mode snapshots are checked only when `V` carries values.
    pub fn build<V: IValue>(self, context: &mut Context<V>, check_values: bool) -> Result<()> {
        let mut snapshots = Vec::new();
        match self {
            Self::Fibonacci => fibonacci(context, &mut snapshots),
            Self::Permutation => permutation(context),
            Self::Blake => blake(context),
            Self::TripleXor => triple_xor_context(context, &mut snapshots),
            Self::M31ToU32 => m31_to_u32_context(context, &mut snapshots),
            Self::BlakeGGate => blake_g_gate_context(context, &mut snapshots),
        }
        if check_values {
            for Snapshot { actual, expected } in snapshots {
                ensure!(
                    actual == expected,
                    "{}: builder value {actual} differs from the prover_test.rs snapshot {expected}",
                    self.name()
                );
            }
        }
        Ok(())
    }

    /// A fresh context of the upstream shape, built.
    pub fn context<V: Mode>(self, check_values: bool) -> Result<Context<V>> {
        let mut context = Context::<V>::new(self.n_reserved());
        if self == Self::Blake {
            V::enable_assert_eq_on_eval(&mut context);
        }
        self.build(&mut context, check_values)?;
        Ok(context)
    }
}

fn snapshot<V: IValue>(
    snapshots: &mut Vec<Snapshot>,
    context: &Context<V>,
    var: Var,
    expected: &'static str,
) {
    snapshots.push(Snapshot {
        actual: format!("{:?}", context.get(var)),
        expected,
    });
}

fn u32_snapshot<V: IValue>(
    snapshots: &mut Vec<Snapshot>,
    context: &Context<V>,
    word: U32Wrapper<Var>,
    expected: &'static str,
) {
    snapshots.push(Snapshot {
        actual: format!("{:?}", word.get_value(context)),
        expected,
    });
}

/// `set_digest_outputs`: cycles `words` through the `N_RESERVED` reserved output wires.
fn set_digest_outputs<V: IValue>(context: &mut Context<V>, words: &[U32Wrapper<Var>]) {
    let outputs: Vec<Var> = words
        .iter()
        .cycle()
        .take(N_RESERVED)
        .map(|w| *w.get())
        .collect();
    context.set_outputs(&outputs);
}

fn fibonacci<V: IValue>(context: &mut Context<V>, snapshots: &mut Vec<Snapshot>) {
    let (mut a, mut b) = (
        guess(context, V::from_qm31(qm31_from_u32s(0, 0, 0, 0))),
        guess(context, V::from_qm31(qm31_from_u32s(1, 0, 0, 0))),
    );
    for _ in 2..FIBONACCI_N {
        (a, b) = (b, eval!(context, (a) + (b)));
    }
    snapshot(snapshots, context, b, "(809871181 + 0i) + (0 + 0i)u");
    let out = m31_to_u32(context, b);
    set_digest_outputs(context, &[out]);
}

fn permutation<V: IValue>(context: &mut Context<V>) {
    let a = guess(context, V::from_qm31(qm31_from_u32s(0, 2, 0, 2)));
    let b = guess(context, V::from_qm31(qm31_from_u32s(1, 1, 1, 1)));
    let outputs = permute(context, &[a, b], IValue::sort_by_u_coordinate);
    let _outputs = permute(context, &outputs, IValue::sort_by_u_coordinate);
}

fn blake<V: IValue>(context: &mut Context<V>) {
    let n_inputs = 9u32;
    let n_bytes = n_inputs * 16;
    let n_blakes = 15;
    let inputs: Vec<Var> = (0..n_inputs)
        .map(|i| {
            guess(
                context,
                V::from_qm31(qm31_from_u32s(
                    4 * i + 82,
                    4 * i + 83,
                    4 * i + 84,
                    4 * i + 85,
                )),
            )
        })
        .collect();
    for _ in 0..n_blakes {
        let output = blake2s_m31(context, &inputs, n_bytes as usize);
        eval!(context, (output.0) + (output.1));
    }
}

fn guess_u32<V: IValue>(context: &mut Context<V>, value: u32) -> U32Wrapper<Var> {
    V::pack_u32(value).guess(context)
}

fn triple_xor_context<V: IValue>(context: &mut Context<V>, snapshots: &mut Vec<Snapshot>) {
    let mut out = None;
    for ([a, b, c], expected) in [
        ([42, 17, 55], "U32((12 + 0i) + (0 + 0i)u)"),
        ([0x10000, 0x20000, 0x30001], "U32((1 + 0i) + (0 + 0i)u)"),
        ([0x30005, 0x10007, 0x4000b], "U32((9 + 6i) + (0 + 0i)u)"),
    ] {
        let a = guess_u32(context, a);
        let b = guess_u32(context, b);
        let c = guess_u32(context, c);
        let word = triple_xor(context, a, b, c);
        u32_snapshot(snapshots, context, word, expected);
        out = Some(word);
    }
    set_digest_outputs(context, &[out.expect("three triple_xor gates")]);
}

fn m31_to_u32_context<V: IValue>(context: &mut Context<V>, snapshots: &mut Vec<Snapshot>) {
    let mut outs = Vec::new();
    for (value, expected) in [
        (42, "U32((42 + 0i) + (0 + 0i)u)"),
        (100_000, "U32((34464 + 1i) + (0 + 0i)u)"),
        (2_000_042, "U32((33962 + 30i) + (0 + 0i)u)"),
    ] {
        let input = guess(context, V::from_qm31(QM31::from(value)));
        let out = m31_to_u32(context, input);
        u32_snapshot(snapshots, context, out, expected);
        outs.push(out);
    }
    set_digest_outputs(context, &outs);
}

fn blake_g_gate_context<V: IValue>(context: &mut Context<V>, snapshots: &mut Vec<Snapshot>) {
    let [a, b, c, d, f0, f1] = [
        305419896u32,
        4294967295,
        2147483647,
        123456789,
        987654321,
        468798,
    ]
    .map(|value| guess_u32(context, value));
    let outs = blake_g_gate(context, a, b, c, d, f0, f1);
    for (out, expected) in outs.iter().zip([
        "U32((49809 + 43146i) + (0 + 0i)u)",
        "U32((53691 + 63264i) + (0 + 0i)u)",
        "U32((464 + 51992i) + (0 + 0i)u)",
        "U32((46984 + 55514i) + (0 + 0i)u)",
    ]) {
        u32_snapshot(snapshots, context, *out, expected);
    }
    set_digest_outputs(context, &outs);
}

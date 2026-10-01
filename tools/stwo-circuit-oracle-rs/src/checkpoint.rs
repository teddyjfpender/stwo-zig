//! Checkpoint envelope, value encodings and the digest contracts shared by every subcommand.
//!
//! Every checkpoint is one pretty JSON document (`serde_json::to_writer_pretty` plus a trailing
//! newline). Field values are encoded as follows:
//!
//! - M31: canonical `u32` (`0 <= x < 2^31 - 1`);
//! - QM31: `[a, b, c, d]` for `(a + b*i) + (c + d*i)*u`, each a canonical M31;
//! - byte digests (Blake2s, SHA-256): 64 lowercase hex characters;
//! - `u64` values (PoW nonces): decimal strings, plus their `hi`/`lo` `u32` halves.
//!
//! Gate lists and variable values are summarized by domain-separated SHA-256 digests over
//! little-endian binary records; see [`circuit_summary`].

use circuits::circuit::Circuit;
use serde::Serialize;
use sha2::{Digest, Sha256};
use stwo::core::fields::qm31::QM31;

pub const SCHEMA: &str = "stwo-circuit-oracle-checkpoint-v1";
pub const PROVING_REPOSITORY: &str = "https://github.com/starkware-libs/proving";
pub const PROVING_REVISION: &str = "5a7c5ede4299c91a61df19a07cba4f7502c14230";

const GATE_KIND_DOMAIN: &[u8] = b"STWO_CIRCUIT_GATE_KIND_V1\0";
const GATE_LIST_DOMAIN: &[u8] = b"STWO_CIRCUIT_GATE_LIST_V1\0";
const VALUES_DOMAIN: &[u8] = b"STWO_CIRCUIT_VALUES_V1\0";

/// The upstream source every checkpoint is derived from.
#[derive(Serialize)]
pub struct Authority {
    pub repository: &'static str,
    pub revision: &'static str,
}

/// An upstream data file read by the oracle, addressed relative to the `proving` checkout root.
#[derive(Serialize, Clone)]
pub struct InputRecord {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

/// The common checkpoint envelope.
#[derive(Serialize)]
pub struct Envelope<T: Serialize> {
    pub schema: &'static str,
    pub rung: &'static str,
    pub subcommand: &'static str,
    pub authority: Authority,
    pub inputs: Vec<InputRecord>,
    pub body: T,
}

impl<T: Serialize> Envelope<T> {
    pub fn new(
        rung: &'static str,
        subcommand: &'static str,
        inputs: Vec<InputRecord>,
        body: T,
    ) -> Self {
        Self {
            schema: SCHEMA,
            rung,
            subcommand,
            authority: Authority {
                repository: PROVING_REPOSITORY,
                revision: PROVING_REVISION,
            },
            inputs,
            body,
        }
    }
}

pub fn qm31(value: QM31) -> [u32; 4] {
    value.to_m31_array().map(|m| m.0)
}

pub fn hex32(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    assert_eq!(bytes.len(), 32, "digest must be 32 bytes");
    hex::encode(bytes)
}

pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(data))
}

/// A `u64` rendered losslessly for JSON consumers that parse numbers as doubles.
#[derive(Serialize)]
pub struct U64Record {
    pub value: String,
    pub hi: u32,
    pub lo: u32,
}

impl From<u64> for U64Record {
    fn from(value: u64) -> Self {
        Self {
            value: value.to_string(),
            hi: (value >> 32) as u32,
            lo: value as u32,
        }
    }
}

/// Per-kind gate digest.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct KindSummary {
    pub kind: &'static str,
    pub count: u64,
    pub sha256: String,
}

/// The gate lists of a [`Circuit`], independent of any variable values: [`CircuitSummary`]
/// without the `Debug` text, cheap enough to take at every stage of a multi-million-gate build.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct GateSummary {
    pub n_vars: u64,
    pub kinds: Vec<KindSummary>,
    /// SHA-256 over `GATE_LIST_DOMAIN || n_vars (u64) || kind digests in `kinds` order`.
    pub gate_list_sha256: String,
}

/// A structural summary of a [`Circuit`], independent of any variable values.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct CircuitSummary {
    pub n_vars: u64,
    pub kinds: Vec<KindSummary>,
    /// SHA-256 over `GATE_LIST_DOMAIN || n_vars (u64) || kind digests in `kinds` order`.
    pub gate_list_sha256: String,
    /// SHA-256 of the upstream `Debug` rendering of the circuit (`format!("{circuit:?}")`).
    pub debug_text_sha256: String,
}

fn var_u32(idx: usize) -> u32 {
    u32::try_from(idx).expect("circuit variable index exceeds u32")
}

struct KindHasher {
    kind: &'static str,
    count: u64,
    hasher: Sha256,
}

impl KindHasher {
    fn new(kind: &'static str) -> Self {
        Self {
            kind,
            count: 0,
            hasher: Sha256::new(),
        }
    }

    fn record(&mut self, fields: &[usize]) {
        self.count += 1;
        for &field in fields {
            self.hasher.update(var_u32(field).to_le_bytes());
        }
    }

    fn record_list(&mut self, inputs: &[usize], outputs: &[usize]) {
        self.count += 1;
        for list in [inputs, outputs] {
            self.hasher.update(var_u32(list.len()).to_le_bytes());
            for &var in list {
                self.hasher.update(var_u32(var).to_le_bytes());
            }
        }
    }

    /// `SHA-256(GATE_KIND_DOMAIN || kind || 0x00 || count (u64) || records)`.
    fn finish(self) -> KindSummary {
        let mut outer = Sha256::new();
        outer.update(GATE_KIND_DOMAIN);
        outer.update(self.kind.as_bytes());
        outer.update([0u8]);
        outer.update(self.count.to_le_bytes());
        outer.update(self.hasher.finalize());
        KindSummary {
            kind: self.kind,
            count: self.count,
            sha256: hex::encode(outer.finalize()),
        }
    }
}

/// Summarizes the gate lists of `circuit`.
///
/// Kinds are hashed in `Circuit` field order (add, sub, mul, pointwise_mul, eq, triple_xor,
/// m31_to_u32, blake_g_gate, permutation, output). A gate record is its variable indices in
/// struct field order, each a little-endian `u32`; a permutation record is
/// `len(inputs), inputs.., len(outputs), outputs..`. The kind digest is
/// `SHA-256(GATE_KIND_DOMAIN || kind || 0x00 || count (u64 LE) || SHA-256(records))`.
pub fn circuit_summary(circuit: &Circuit) -> CircuitSummary {
    let GateSummary {
        n_vars,
        kinds,
        gate_list_sha256,
    } = gate_summary(circuit);
    CircuitSummary {
        n_vars,
        kinds,
        gate_list_sha256,
        debug_text_sha256: sha256_hex(debug_text(circuit)),
    }
}

/// [`circuit_summary`] without the `Debug` text digest.
pub fn gate_summary(circuit: &Circuit) -> GateSummary {
    let mut hashers = GATE_KINDS.map(KindHasher::new);
    visit_gates(circuit, [0; GATE_KINDS.len()], |kind, gate| match gate {
        Gate::Fields(fields) => hashers[kind].record(fields),
        Gate::Lists(inputs, outputs) => hashers[kind].record_list(inputs, outputs),
    });
    let kinds: Vec<KindSummary> = hashers.into_iter().map(KindHasher::finish).collect();

    let n_vars = circuit.n_vars as u64;
    let mut list = Sha256::new();
    list.update(GATE_LIST_DOMAIN);
    list.update(n_vars.to_le_bytes());
    for kind in &kinds {
        list.update(hex::decode(&kind.sha256).expect("kind digest is hex"));
    }

    GateSummary {
        n_vars,
        kinds,
        gate_list_sha256: hex::encode(list.finalize()),
    }
}

/// The gate kinds in `Circuit` field order, the order of every per-kind digest.
pub const GATE_KINDS: [&str; 10] = [
    "add",
    "sub",
    "mul",
    "pointwise_mul",
    "eq",
    "triple_xor",
    "m31_to_u32",
    "blake_g_gate",
    "permutation",
    "output",
];

/// One gate's variable indices: struct fields in declaration order, or a permutation's lists.
pub enum Gate<'a> {
    Fields(&'a [usize]),
    Lists(&'a [usize], &'a [usize]),
}

/// The per-kind gate counts of `circuit`, in [`GATE_KINDS`] order.
pub fn gate_counts(circuit: &Circuit) -> [usize; GATE_KINDS.len()] {
    [
        circuit.add.len(),
        circuit.sub.len(),
        circuit.mul.len(),
        circuit.pointwise_mul.len(),
        circuit.eq.len(),
        circuit.triple_xor.len(),
        circuit.m31_to_u32.len(),
        circuit.blake_g_gate.len(),
        circuit.permutation.len(),
        circuit.output.len(),
    ]
}

/// Visits every gate of kind `k` from index `start[k]` on, kind by kind in [`GATE_KINDS`] order.
pub fn visit_gates(
    circuit: &Circuit,
    start: [usize; GATE_KINDS.len()],
    mut visit: impl FnMut(usize, Gate<'_>),
) {
    for g in &circuit.add[start[0]..] {
        visit(0, Gate::Fields(&[g.in0, g.in1, g.out]));
    }
    for g in &circuit.sub[start[1]..] {
        visit(1, Gate::Fields(&[g.in0, g.in1, g.out]));
    }
    for g in &circuit.mul[start[2]..] {
        visit(2, Gate::Fields(&[g.in0, g.in1, g.out]));
    }
    for g in &circuit.pointwise_mul[start[3]..] {
        visit(3, Gate::Fields(&[g.in0, g.in1, g.out]));
    }
    for g in &circuit.eq[start[4]..] {
        visit(4, Gate::Fields(&[g.in0, g.in1]));
    }
    for g in &circuit.triple_xor[start[5]..] {
        visit(5, Gate::Fields(&[g.input_a, g.input_b, g.input_c, g.out]));
    }
    for g in &circuit.m31_to_u32[start[6]..] {
        visit(6, Gate::Fields(&[g.input, g.out]));
    }
    for g in &circuit.blake_g_gate[start[7]..] {
        visit(
            7,
            Gate::Fields(&[
                g.input_a, g.input_b, g.input_c, g.input_d, g.input_f0, g.input_f1, g.out_a,
                g.out_b, g.out_c, g.out_d,
            ]),
        );
    }
    for g in &circuit.permutation[start[8]..] {
        visit(8, Gate::Lists(&g.inputs, &g.outputs));
    }
    for g in &circuit.output[start[9]..] {
        visit(9, Gate::Fields(&[g.in0]));
    }
}

/// The upstream `Debug` rendering of a circuit: one gate per line, in `Circuit::all_gates` order.
pub fn debug_text(circuit: &Circuit) -> String {
    format!("{circuit:?}")
}

/// `SHA-256(VALUES_DOMAIN || count (u64 LE) || each value as four canonical u32 LE)`.
pub fn values_sha256(values: &[QM31]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(VALUES_DOMAIN);
    hasher.update((values.len() as u64).to_le_bytes());
    for value in values {
        for limb in qm31(*value) {
            hasher.update(limb.to_le_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use circuits::context::{Context, TraceContext};
    use circuits::ivalue::{IValue, NoValue, qm31_from_u32s};
    use circuits::ops::{add, eq, guess, mul, permute};

    use super::*;

    // The expected digests were computed independently from the contract documented above
    // (Python `hashlib`), so they pin the documentation to the implementation.

    #[test]
    fn default_context_digests() {
        let context = TraceContext::default();
        let summary = circuit_summary(&context.circuit);
        assert_eq!(summary.n_vars, 3);
        assert_eq!(
            summary.gate_list_sha256,
            "169eb78a79a183ddc6318834166cff7cb16d01678810674657b47d2bd3c7d843"
        );
        assert_eq!(
            values_sha256(context.values()),
            "5602189d215b41df4588507ecb0d1da66e765d33fc84b32445b37961049b7eb6"
        );
    }

    fn small_circuit<V: IValue>(context: &mut Context<V>) {
        let a = guess(context, V::from_qm31(qm31_from_u32s(2, 0, 0, 0)));
        let b = guess(context, V::from_qm31(qm31_from_u32s(2, 0, 0, 0)));
        let sum = add(context, a, b);
        let product = mul(context, a, b);
        eq(context, sum, product);
        let u = context.u();
        permute(context, &[u, a], |values| values.to_vec());
    }

    #[test]
    fn small_circuit_digest_is_value_independent() {
        let mut values = TraceContext::default();
        small_circuit(&mut values);
        let mut topology = Context::<NoValue>::default();
        small_circuit(&mut topology);

        let summary = circuit_summary(&values.circuit);
        assert_eq!(summary, circuit_summary(&topology.circuit));
        assert_eq!(
            summary.gate_list_sha256,
            "e00e30382723ad2a33676fefbfe3b1d4fa43324a68273029398398b3c50a08be"
        );
        let counts: Vec<u64> = summary.kinds.iter().map(|kind| kind.count).collect();
        assert_eq!(counts, [1, 0, 1, 0, 1, 0, 0, 0, 1, 1]);
    }
}

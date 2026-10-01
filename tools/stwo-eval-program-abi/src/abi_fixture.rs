//! The ABI byte-compare gate (design §4.2).
//!
//! Both consumers of this directory record the same small `FrameworkEval` and encode it. They
//! build against different Stwo revisions (`7b211ed` for the Cairo AIR compiler, `proving@5a7c5ed`
//! for the circuit oracle), so the encoded bytes are compared with [`EXPECTED_PROGRAM_HEX`] at the
//! start of every run of either tool: a divergence in the recorder, the lowering, the encoding or
//! the framework's `EvalAtRow` driving fails both tools instead of silently forking the ABI.
//!
//! The evaluator reads a preprocessed column, a trace column at two offsets, adds two base
//! constraints and two logup terms of opposite multiplicity, and finalizes the logup in pairs.

use anyhow::{Result, anyhow, ensure};
use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval, ORIGINAL_TRACE_IDX, RelationEntry};

use super::encoding;
use super::program::lower_framework_eval_to_v1_with_logup;

stwo_constraint_framework::relation!(AbiFixtureRelation, 3);

const LOG_SIZE: u32 = 4;
const CLAIMED_SUM: SecureField = SecureField::from_u32_unchecked(3, 5, 7, 11);

/// The encoded fixture program (`encoding::program`), as lowercase hex.
pub const EXPECTED_PROGRAM_HEX: &str = concat!(
    "5354503101000000050000000100000033911afe78d66d760700000000000000030000000000000000000000",
    "0300000013000000290000000400000004000000000000000000000000000000000000000000000000000000",
    "0000000000000000010000000400000000000000000000000000000000000000020000001000000000000000",
    "0000000000000000000000000300000010000000000000000000000013000000000000000400000014000000",
    "3001000000000000290000000000000005000000040000006404000000000000030000000000000000000000",
    "0000000000000000000000000001010000000000000000000000000000010200010000000000000000000000",
    "0001030001000000000000000100000006000400010000000200000000000000050005000400000000000000",
    "0000000003000600070000000000000000000000040007000500000006000000000000000300080000000000",
    "00000000000000000600090001000000010000000000000005000a0003000000090000000000000000020b00",
    "0000000000000000ffffffff00020c0000000000000000000000000000020d000100000000000000ffffffff",
    "00020e0001000000000000000000000000020f000200000000000000ffffffff000210000200000000000000",
    "00000000000211000300000000000000ffffffff000212000300000000000000000000000000000007000000",
    "080000000800000008000000000001000a000000080000000800000008000000020002000100000000000000",
    "0000000000000000000003000100000008000000080000000800000005000400020000000300000000000000",
    "0000000002000500040000000300000002000000010000000000060002000000080000000800000008000000",
    "0500070005000000060000000000000000000000030008000400000007000000000000000000000002000900",
    "09000000230000000a0000001400000000000a000000000008000000080000000800000005000b0009000000",
    "0a000000000000000000000003000c00080000000b000000000000000000000002000d000100000002000000",
    "030000000400000004000e000c0000000d000000000000000000000002000f00010000000000000000000000",
    "000000000000100002000000080000000800000008000000050011000f000000100000000000000000000000",
    "0200120004000000030000000200000001000000000013000100000008000000080000000800000005001400",
    "1200000013000000000000000000000003001500110000001400000000000000000000000200160009000000",
    "230000000a000000140000000000170000000000080000000800000008000000050018001600000017000000",
    "0000000000000000030019001500000018000000000000000000000002001a00010000000200000003000000",
    "0400000004001b00190000001a000000000000000000000002001c0001000000000000000000000000000000",
    "05001d001b0000001c000000000000000000000002001e00feffff7f00000000000000000000000005001f00",
    "0e0000001e0000000000000000000000030020001d0000001f0000000000000000000000050021000e000000",
    "1b0000000000000000000000000022000b0000000d0000000f00000011000000000023000c0000000e000000",
    "1000000012000000040024002300000022000000000000000000000002002500000000180000002800000038",
    "0000005803002600240000002500000000000000000000000500270026000000210000000000000000000000",
    "0400280027000000200000000000000000000000000000000100000028000000",
);

struct AbiFixtureEval {
    lookup: AbiFixtureRelation,
}

impl FrameworkEval for AbiFixtureEval {
    fn log_size(&self) -> u32 {
        LOG_SIZE
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        LOG_SIZE + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let seq = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "abi_fixture_seq".into(),
        });
        let a = eval.next_trace_mask();
        let [b, b_next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);
        eval.add_constraint(a.clone() * b.clone() - seq.clone() + E::F::from(BaseField::from(7)));
        eval.add_constraint(b_next - a.clone() * a.clone());
        eval.add_to_relation(RelationEntry::new(
            &self.lookup,
            E::EF::one(),
            &[a.clone(), b.clone(), seq.clone()],
        ));
        eval.add_to_relation(RelationEntry::new(
            &self.lookup,
            -E::EF::one(),
            &[b, a, seq],
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The encoded fixture program.
pub fn program_bytes() -> Result<Vec<u8>> {
    let eval = AbiFixtureEval {
        lookup: AbiFixtureRelation::dummy(),
    };
    let program = lower_framework_eval_to_v1_with_logup(&eval, 3, 0, 0, CLAIMED_SUM, LOG_SIZE)
        .map_err(|error| anyhow!("ABI fixture lowering: {error:?}"))?;
    encoding::program(&program)
}

/// Encodes the fixture and requires the committed bytes; returns them as hex.
pub fn check() -> Result<String> {
    let actual = hex(&program_bytes()?);
    ensure!(
        actual == EXPECTED_PROGRAM_HEX,
        "evaluation-program ABI fixture drifted: encoded {actual}, expected {EXPECTED_PROGRAM_HEX}"
    );
    Ok(actual)
}

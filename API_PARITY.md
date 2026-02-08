# API_PARITY.md

This ledger maps every public export in the Zig root/module API surface to the pinned Rust parity target
(or records a compatibility rationale when no direct upstream exported symbol exists).

- Pinned upstream commit: `a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2`
- Validation gate: `python3 scripts/check_api_parity.py`

<!-- API_PARITY_JSON_START -->
```json
{
  "scope": "public exports from src/stwo.zig and major module surfaces",
  "symbols": {
    "stwo.core": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/stwo.zig"
    },
    "stwo.core.ColumnVec": {
      "kind": "fn",
      "rationale": "Zig container helper aliases that preserve upstream component/column indexing semantics without direct Rust exported symbol names.",
      "rust_path": null,
      "source": "src/core/mod.zig"
    },
    "stwo.core.ComponentVec": {
      "kind": "fn",
      "rationale": "Zig container helper aliases that preserve upstream component/column indexing semantics without direct Rust exported symbol names.",
      "rust_path": null,
      "source": "src/core/mod.zig"
    },
    "stwo.core.air": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/air-utils/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.air.Air": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/air-utils/src/lib.rs",
      "source": "src/core/air/mod.zig"
    },
    "stwo.core.air.AirVTable": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/air-utils/src/lib.rs",
      "source": "src/core/air/mod.zig"
    },
    "stwo.core.air.Component": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/air-utils/src/lib.rs",
      "source": "src/core/air/mod.zig"
    },
    "stwo.core.air.Components": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/air-utils/src/lib.rs",
      "source": "src/core/air/mod.zig"
    },
    "stwo.core.air.accumulation": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/air-utils/src/lib.rs",
      "source": "src/core/air/mod.zig"
    },
    "stwo.core.air.components": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/air-utils/src/lib.rs",
      "source": "src/core/air/mod.zig"
    },
    "stwo.core.air.derive": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/air-utils-derive/src/lib.rs",
      "source": "src/core/air/mod.zig"
    },
    "stwo.core.air.lookup_data": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/air-utils/src/lookup_data/mod.rs",
      "source": "src/core/air/mod.zig"
    },
    "stwo.core.air.trace": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/air-utils/src/trace/mod.rs",
      "source": "src/core/air/mod.zig"
    },
    "stwo.core.air.utils": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/air-utils/src/lib.rs",
      "source": "src/core/air/mod.zig"
    },
    "stwo.core.channel": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.channel.blake2s": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/channel/mod.zig"
    },
    "stwo.core.channel.transcript": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/channel/mod.zig"
    },
    "stwo.core.circle": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.constraint_framework": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/constraint-framework/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.constraint_framework.Assignment": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/constraint-framework/src/lib.rs",
      "source": "src/core/constraint_framework/mod.zig"
    },
    "stwo.core.constraint_framework.BaseExpr": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/constraint-framework/src/lib.rs",
      "source": "src/core/constraint_framework/mod.zig"
    },
    "stwo.core.constraint_framework.ExprArena": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/constraint-framework/src/lib.rs",
      "source": "src/core/constraint_framework/mod.zig"
    },
    "stwo.core.constraint_framework.ExprEvaluator": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/constraint-framework/src/lib.rs",
      "source": "src/core/constraint_framework/mod.zig"
    },
    "stwo.core.constraint_framework.ExprVariables": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/constraint-framework/src/lib.rs",
      "source": "src/core/constraint_framework/mod.zig"
    },
    "stwo.core.constraint_framework.ExtExpr": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/constraint-framework/src/lib.rs",
      "source": "src/core/constraint_framework/mod.zig"
    },
    "stwo.core.constraint_framework.NamedExprs": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/constraint-framework/src/lib.rs",
      "source": "src/core/constraint_framework/mod.zig"
    },
    "stwo.core.constraint_framework.evaluator": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/constraint-framework/src/lib.rs",
      "source": "src/core/constraint_framework/mod.zig"
    },
    "stwo.core.constraint_framework.expr": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/constraint-framework/src/lib.rs",
      "source": "src/core/constraint_framework/mod.zig"
    },
    "stwo.core.constraints": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.crypto": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.crypto.hash256": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/crypto/mod.zig"
    },
    "stwo.core.fft": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.fields": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.fields.batchInverse": {
      "kind": "fn",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/fields/mod.zig"
    },
    "stwo.core.fields.batchInverseChunked": {
      "kind": "fn",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/fields/mod.zig"
    },
    "stwo.core.fields.batchInverseInPlace": {
      "kind": "fn",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/fields/mod.zig"
    },
    "stwo.core.fields.cm31": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/fields/mod.zig"
    },
    "stwo.core.fields.m31": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/fields/mod.zig"
    },
    "stwo.core.fields.qm31": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/fields/mod.zig"
    },
    "stwo.core.fraction": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.fri": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.pcs": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.pcs.CommitmentSchemeProof": {
      "kind": "fn",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/pcs/mod.zig"
    },
    "stwo.core.pcs.CommitmentSchemeProofAux": {
      "kind": "fn",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/pcs/mod.zig"
    },
    "stwo.core.pcs.ExtendedCommitmentSchemeProof": {
      "kind": "fn",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/pcs/mod.zig"
    },
    "stwo.core.pcs.PcsConfig": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/pcs/mod.zig"
    },
    "stwo.core.pcs.TreeSubspan": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/pcs/mod.zig"
    },
    "stwo.core.pcs.TreeVec": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/pcs/mod.zig"
    },
    "stwo.core.pcs.quotients": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/pcs/mod.zig"
    },
    "stwo.core.pcs.utils": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/pcs/mod.zig"
    },
    "stwo.core.pcs.verifier": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/pcs/mod.zig"
    },
    "stwo.core.poly": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.poly.circle": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/poly/mod.zig"
    },
    "stwo.core.poly.line": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/poly/mod.zig"
    },
    "stwo.core.poly.utils": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/poly/mod.zig"
    },
    "stwo.core.proof": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.proof_of_work": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.queries": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.test_utils": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.utils": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.vcs": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.vcs.blake2_hash": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/vcs/mod.zig"
    },
    "stwo.core.vcs.blake2_merkle": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/vcs/mod.zig"
    },
    "stwo.core.vcs.blake3_hash": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/vcs/mod.zig"
    },
    "stwo.core.vcs.hash": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/vcs/mod.zig"
    },
    "stwo.core.vcs.merkle": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/vcs/mod.zig"
    },
    "stwo.core.vcs.merkle_hasher": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/vcs/mod.zig"
    },
    "stwo.core.vcs.test_utils": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/vcs/mod.zig"
    },
    "stwo.core.vcs.utils": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/vcs/mod.zig"
    },
    "stwo.core.vcs.verifier": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/vcs/mod.zig"
    },
    "stwo.core.vcs_lifted": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.vcs_lifted.blake2_merkle": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/vcs_lifted/mod.zig"
    },
    "stwo.core.vcs_lifted.merkle_hasher": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/vcs_lifted/mod.zig"
    },
    "stwo.core.vcs_lifted.test_utils": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/vcs_lifted/mod.zig"
    },
    "stwo.core.vcs_lifted.verifier": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/vcs_lifted/mod.zig"
    },
    "stwo.core.verifier": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.core.verifier_types": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/core/mod.zig"
    },
    "stwo.examples": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/examples/src/lib.rs",
      "source": "src/stwo.zig"
    },
    "stwo.examples.blake": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/examples/src/lib.rs",
      "source": "src/examples/mod.zig"
    },
    "stwo.examples.plonk": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/examples/src/lib.rs",
      "source": "src/examples/mod.zig"
    },
    "stwo.examples.poseidon": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/examples/src/lib.rs",
      "source": "src/examples/mod.zig"
    },
    "stwo.examples.state_machine": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/examples/src/lib.rs",
      "source": "src/examples/mod.zig"
    },
    "stwo.examples.wide_fibonacci": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/examples/src/lib.rs",
      "source": "src/examples/mod.zig"
    },
    "stwo.examples.xor": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/examples/src/lib.rs",
      "source": "src/examples/mod.zig"
    },
    "stwo.interop": {
      "kind": "const",
      "rationale": "Zig/Rust interoperability wire helper for conformance harness; no direct upstream crate export symbol.",
      "rust_path": null,
      "source": "src/stwo.zig"
    },
    "stwo.interop.examples_artifact": {
      "kind": "const",
      "rationale": "Zig/Rust interoperability wire helper for conformance harness; no direct upstream crate export symbol.",
      "rust_path": null,
      "source": "src/interop/mod.zig"
    },
    "stwo.interop.proof_wire": {
      "kind": "const",
      "rationale": "Zig/Rust interoperability wire helper for conformance harness; no direct upstream crate export symbol.",
      "rust_path": null,
      "source": "src/interop/mod.zig"
    },
    "stwo.prover": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/stwo.zig"
    },
    "stwo.prover.air": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/mod.zig"
    },
    "stwo.prover.air.accumulation": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/air/mod.zig"
    },
    "stwo.prover.air.component_prover": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/air/mod.zig"
    },
    "stwo.prover.channel": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/mod.zig"
    },
    "stwo.prover.channel.logging_channel": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/channel/mod.zig"
    },
    "stwo.prover.fri": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/mod.zig"
    },
    "stwo.prover.line": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/mod.zig"
    },
    "stwo.prover.lookups": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/mod.zig"
    },
    "stwo.prover.lookups.gkr_prover": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/lookups/mod.zig"
    },
    "stwo.prover.lookups.gkr_verifier": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/lookups/mod.zig"
    },
    "stwo.prover.lookups.mle": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/lookups/mod.zig"
    },
    "stwo.prover.lookups.sumcheck": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/lookups/mod.zig"
    },
    "stwo.prover.lookups.utils": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/lookups/mod.zig"
    },
    "stwo.prover.pcs": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/mod.zig"
    },
    "stwo.prover.pcs.ColumnEvaluation": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/pcs/mod.zig"
    },
    "stwo.prover.pcs.CommitmentSchemeError": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/pcs/mod.zig"
    },
    "stwo.prover.pcs.CommitmentSchemeProver": {
      "kind": "fn",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/pcs/mod.zig"
    },
    "stwo.prover.pcs.CommitmentTreeProver": {
      "kind": "fn",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/pcs/mod.zig"
    },
    "stwo.prover.pcs.TreeBuilder": {
      "kind": "fn",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/pcs/mod.zig"
    },
    "stwo.prover.pcs.TreeDecommitmentResult": {
      "kind": "fn",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/pcs/mod.zig"
    },
    "stwo.prover.pcs.quotient_ops": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/pcs/mod.zig"
    },
    "stwo.prover.poly": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/mod.zig"
    },
    "stwo.prover.poly.BitReversedOrder": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/poly/mod.zig"
    },
    "stwo.prover.poly.NaturalOrder": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/poly/mod.zig"
    },
    "stwo.prover.poly.circle": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/poly/mod.zig"
    },
    "stwo.prover.poly.twiddles": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/poly/mod.zig"
    },
    "stwo.prover.prove": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/mod.zig"
    },
    "stwo.prover.secure_column": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/mod.zig"
    },
    "stwo.prover.vcs": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/mod.zig"
    },
    "stwo.prover.vcs.ops": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/vcs/mod.zig"
    },
    "stwo.prover.vcs.prover": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/vcs/mod.zig"
    },
    "stwo.prover.vcs_lifted": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/mod.zig"
    },
    "stwo.prover.vcs_lifted.ops": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/vcs_lifted/mod.zig"
    },
    "stwo.prover.vcs_lifted.prover": {
      "kind": "const",
      "rationale": null,
      "rust_path": "crates/stwo/src/lib.rs",
      "source": "src/prover/vcs_lifted/mod.zig"
    },
    "stwo.std_shims": {
      "kind": "const",
      "rationale": "Zig-specific freestanding verifier shim surface; behavior parity is enforced via std-shims behavior gate.",
      "rust_path": "crates/std-shims/src/lib.rs",
      "source": "src/stwo.zig"
    },
    "stwo.std_shims.verifier_profile": {
      "kind": "const",
      "rationale": "Zig-specific freestanding verifier shim surface; behavior parity is enforced via std-shims behavior gate.",
      "rust_path": "crates/std-shims/src/lib.rs",
      "source": "src/std_shims/mod.zig"
    },
    "stwo.tracing": {
      "kind": "const",
      "rationale": "Zig-specific instrumentation helper; does not alter proof semantics or verifier/prover API behavior.",
      "rust_path": null,
      "source": "src/stwo.zig"
    },
    "stwo.tracing.SpanAccumulator": {
      "kind": "const",
      "rationale": "Zig-specific instrumentation helper; does not alter proof semantics or verifier/prover API behavior.",
      "rust_path": null,
      "source": "src/tracing/mod.zig"
    },
    "stwo.tracing.SpanId": {
      "kind": "const",
      "rationale": "Zig-specific instrumentation helper; does not alter proof semantics or verifier/prover API behavior.",
      "rust_path": null,
      "source": "src/tracing/mod.zig"
    }
  },
  "upstream_commit": "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2"
}
```
<!-- API_PARITY_JSON_END -->

const base = @import("proof_ingress.zig");
const stwo_core = @import("stwo_core");
const statement_v2 = @import("../air/statement_v2.zig");
const postcard = @import("interop_postcard");
pub const RetirementSupplementV2 = base.RetirementSupplementV2;
pub const DEFAULT_MAX_PROOF_BYTES = base.DEFAULT_MAX_PROOF_BYTES;
pub const Error = base.Error;
pub const preflightShape = base.preflightShape;
pub const preflightShapeForVerifierConfig = base.preflightShapeForVerifierConfig;
pub const preflightShapeV2 = base.preflightShapeV2;
pub const preflightShapeV2ForVerifierConfig = base.preflightShapeV2ForVerifierConfig;
pub const preflightShapeV2WithRetirementSupplementV2ForVerifierConfig = base.preflightShapeV2WithRetirementSupplementV2ForVerifierConfig;
pub const preflightShapeV2WithCircuitLayout = base.preflightShapeV2WithCircuitLayout;
pub const validate = base.validate;
pub const validateForVerifierConfig = base.validateForVerifierConfig;
pub const validateV2 = base.validateV2;
pub const validateV2ForVerifierConfig = base.validateV2ForVerifierConfig;
pub fn preflightShapeV2WithCircuitProfileV1(statement: *const statement_v2.RiscVStatementV2, supplement: RetirementSupplementV2, pcs_config: stwo_core.pcs.PcsConfig, max_wire_bytes: usize, circuit_profile: @import("../prover/ethereum_circuit_profile.zig").CircuitProfileV1) Error!postcard.proof_preflight.Shape {
    return base.preflightShapeV2WithCircuitLayout(statement, supplement, pcs_config, max_wire_bytes, circuit_profile.layout());
}

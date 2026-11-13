//! Product compatibility component; shared declarations retain their canonical owners.
const neutral = @import("stwo_riscv_frontend");
pub const Cpu = neutral.Cpu;
pub const HostInterface = neutral.HostInterface;
pub const HostRuntime = neutral.HostRuntime;
pub const MAX_EXECUTION_STEPS = neutral.MAX_EXECUTION_STEPS;
pub const Memory = neutral.Memory;
pub const Opcode = neutral.Opcode;
pub const RiscVClaim = neutral.RiscVClaim;
pub const access_clock = neutral.access_clock;
pub const air = @import("frontend/air/mod.zig");
pub const diagnostics = @import("frontend/diagnostics/mod.zig");
pub const host = @import("frontend/host/mod.zig");
pub const infra_trace = neutral.infra_trace;
pub const isa = neutral.isa;
pub const opcode_manifest = neutral.opcode_manifest;
pub const owned_statement = neutral.owned_statement;
pub const process_usage = neutral.process_usage;
pub const proveAndVerifyElfWithEngine = neutral.proveAndVerifyElfWithEngine;
pub const proveEthereumWithEngine = prover_mod.proveEthereumWithEngine;
pub const proveEthereumWithEngineUsingExecution = prover_mod.proveEthereumWithEngineUsingExecution;
pub const provePoseidon2WithEngineAndPublicData = neutral.provePoseidon2WithEngineAndPublicData;
pub const provePoseidon2WithEngineAndPublicDataUsingChannelAndPhaseMeter = neutral.provePoseidon2WithEngineAndPublicDataUsingChannelAndPhaseMeter;
pub const proveRiscVSegmentV2WithEngine = neutral.proveRiscVSegmentV2WithEngine;
pub const proveRiscVTraceOnlyNoPublicIo = neutral.proveRiscVTraceOnlyNoPublicIo;
pub const proveRiscVWithEngineAndPublicData = neutral.proveRiscVWithEngineAndPublicData;
pub const proveRiscVWithEngineAndPublicDataWithExecution = neutral.proveRiscVWithEngineAndPublicDataWithExecution;
pub const prover_mod = @import("frontend/prover.zig");
pub const recursion = @import("frontend/recursion/mod.zig");
pub const runWithHost = neutral.runWithHost;
pub const runWithInput = neutral.runWithInput;
pub const runner = @import("frontend/runner/mod.zig");
pub const rv64 = @import("frontend/rv64/mod.zig");
pub const rv64_air = @import("frontend/rv64/air.zig");
pub const statement_shape_inspection = neutral.statement_shape_inspection;
pub const testing = @import("frontend/testing.zig");
pub const verifyEthereumWithEngine = prover_mod.verifyEthereumWithEngine;
pub const verifyPoseidon2WithEngine = neutral.verifyPoseidon2WithEngine;
pub const verifyRiscVSegmentV2WithEngine = neutral.verifyRiscVSegmentV2WithEngine;
pub const verifyRiscVSegmentV2WithEngineUsingChannelAndCapture = neutral.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture;
pub const verifyRiscVWithEngine = neutral.verifyRiscVWithEngine;
pub const verifyRiscVWithEngineUsingChannelAndProofCapture = neutral.verifyRiscVWithEngineUsingChannelAndProofCapture;
pub const verifyRiscVWithEngineUsingChannelAndQueryCapture = neutral.verifyRiscVWithEngineUsingChannelAndQueryCapture;
pub const witness_layout = neutral.witness_layout;

test {
    _ = @import("frontend/test_inventory.zig");
}

pub const csp_proof_harness = @import("frontend/harnesses/csp_ecdsa_proof_harness.zig");

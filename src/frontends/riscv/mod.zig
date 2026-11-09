//! Sail-authoritative RISC-V RV32IM zkVM frontend.
//!
//! Provides an execution runner for RISC-V RV32IM programs (ELF loading,
//! decode, execute) and AIR constraints for STARK proving of execution traces.

pub const runner = @import("runner/mod.zig");
/// Experimental RV64IM execution only; no RV32 proof or ABI compatibility.
pub const rv64 = @import("stwo_riscv_rv64").modules.implementation;
pub const rv64_air = @import("stwo_riscv_rv64").modules.air_mod;
pub const air = @import("compat/air/mod.zig");
pub const access_clock = @import("stwo_riscv_isa").modules.access_clock;
pub const diagnostics = @import("stwo_riscv_rv32").modules.diagnostics_mod;
pub const isa = @import("stwo_riscv_isa").modules.implementation;
pub const opcode_manifest = @import("stwo_riscv_isa").modules.opcode_manifest;
pub const witness_layout = @import("stwo_riscv_rv32").modules.witness_layout;
pub const prover_mod = @import("prover.zig");
pub const statement_shape_inspection =
    @import("stwo_riscv_rv32").modules.prover_statement_shape_inspection;
pub const owned_statement = @import("stwo_riscv_rv32").modules.owned_statement;
pub const infra_trace = @import("stwo_riscv_rv32").modules.infra_trace;
pub const host = @import("compat/host/mod.zig");
pub const recursion = @import("stwo_riscv_recursion").modules.implementation;
/// Shared process resource sampler used by authenticated benchmark capture.
/// It is measurement-only and does not participate in proof semantics.
pub const process_usage = @import("stwo_prover_engine").measurement.process_usage;
/// Explicitly unstable helpers used by the repository's adversarial corpus.
/// Downstream production code must stay on the package surface above.
pub const testing = @import("stwo_riscv_testing").modules.compatibility;

// Convenience re-exports.
pub const Cpu = runner.Cpu;
pub const Memory = runner.Memory;
pub const Opcode = runner.Opcode;
pub const HostInterface = host.HostInterface;
pub const HostRuntime = host.HostRuntime;
pub const runWithHost = runner.runWithHost;
pub const runWithInput = runner.runWithInput;
pub const RiscVClaim = air.claims.RiscVClaim;
pub const MAX_EXECUTION_STEPS = prover_mod.MAX_EXECUTION_STEPS;
pub const proveRiscVTraceOnlyNoPublicIo = prover_mod.proveRiscVTraceOnlyNoPublicIo;
pub const proveRiscVWithEngineAndPublicData = prover_mod.proveRiscVWithEngineAndPublicData;
pub const proveRiscVWithEngineAndPublicDataWithExecution =
    prover_mod.proveRiscVWithEngineAndPublicDataWithExecution;
pub const proveRiscVSegmentV2WithEngine =
    prover_mod.proveRiscVSegmentV2WithEngine;
pub const verifyRiscVWithEngine = prover_mod.verifyRiscVWithEngine;
pub const verifyRiscVSegmentV2WithEngine =
    prover_mod.verifyRiscVSegmentV2WithEngine;
pub const verifyRiscVSegmentV2WithEngineUsingChannelAndCapture =
    prover_mod.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture;
pub const verifyRiscVWithEngineUsingChannelAndQueryCapture =
    prover_mod.verifyRiscVWithEngineUsingChannelAndQueryCapture;
pub const verifyRiscVWithEngineUsingChannelAndProofCapture =
    prover_mod.verifyRiscVWithEngineUsingChannelAndProofCapture;
pub const provePoseidon2WithEngineAndPublicData =
    prover_mod.provePoseidon2WithEngineAndPublicData;
pub const provePoseidon2WithEngineAndPublicDataUsingChannelAndPhaseMeter =
    prover_mod.provePoseidon2WithEngineAndPublicDataUsingChannelAndPhaseMeter;
pub const verifyPoseidon2WithEngine = prover_mod.verifyPoseidon2WithEngine;
pub const proveEthereumWithEngine = prover_mod.proveEthereumWithEngine;
pub const proveEthereumWithEngineUsingExecution =
    prover_mod.proveEthereumWithEngineUsingExecution;
pub const verifyEthereumWithEngine = prover_mod.verifyEthereumWithEngine;
pub const proveAndVerifyElfWithEngine = prover_mod.proveAndVerifyElfWithEngine;

test "api signature: RISC-V facade preserves runner and prover entry points" {
    comptime {
        if (Opcode != runner.Opcode) @compileError("Opcode facade alias drifted");
        switch (@typeInfo(@TypeOf(runWithInput))) {
            .@"fn" => {},
            else => @compileError("runWithInput must remain a function"),
        }
        switch (@typeInfo(@TypeOf(proveRiscVWithEngineAndPublicData))) {
            .@"fn" => {},
            else => @compileError("proveRiscVWithEngineAndPublicData must remain a function"),
        }
        switch (@typeInfo(@TypeOf(proveRiscVTraceOnlyNoPublicIo))) {
            .@"fn" => {},
            else => @compileError("proveRiscVTraceOnlyNoPublicIo must remain a function"),
        }
    }
}

test {
    @import("std").testing.refAllDeclsRecursive(infra_trace);
    // Every test-bearing file in this package, named once. Without it the
    // compiler analyses only the files something happens to reference from a
    // test body, which silently left 142 of this package's named tests out of
    // every binary. See `test_inventory.zig` for the collection rule.
    _ = @import("test_inventory.zig");
    _ = @import("test_inventory_test.zig");
    _ = @import("stwo_riscv_rv32").modules.opcode_coverage_test;
    _ = @import("stwo_riscv_rv32").modules.air_extract_mod;
    _ = @import("stwo_riscv_rv32").modules.air_semantic_eval;
    // The Sail bridge's own two self-checks. A file's tests are collected
    // only when a `test` block names it; the file-scope `pub const
    // sail_oracle = @import("sail_oracle.zig")` in `runner/mod.zig` is not
    // enough, and until this line existed those two tests ran in no step at
    // all. The main build reaches them through `test-riscv-sail-oracle`,
    // which roots a test artifact at the file itself.
    _ = @import("stwo_riscv_rv32").modules.runner_sail_oracle;
}

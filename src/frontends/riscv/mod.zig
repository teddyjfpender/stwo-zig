//! Sail-authoritative RISC-V RV32IM zkVM frontend.
//!
//! Provides an execution runner for RISC-V RV32IM programs (ELF loading,
//! decode, execute) and AIR constraints for STARK proving of execution traces.

pub const runner = @import("runner/mod.zig");
pub const air = @import("air/mod.zig");
pub const access_clock = @import("access_clock.zig");
pub const diagnostics = @import("diagnostics/mod.zig");
pub const isa = @import("isa/mod.zig");
pub const opcode_manifest = @import("opcode_manifest.zig");
pub const witness_layout = @import("witness_layout.zig");
pub const prover_mod = @import("prover.zig");
pub const statement_shape_inspection =
    @import("prover/statement_shape_inspection.zig");
pub const owned_statement = @import("owned_statement.zig");
pub const infra_trace = @import("infra_trace.zig");
pub const host = @import("host/mod.zig");
pub const recursion = @import("recursion/mod.zig");
/// Shared process resource sampler used by authenticated benchmark capture.
/// It is measurement-only and does not participate in proof semantics.
pub const process_usage = @import("stwo_prover_engine").measurement.process_usage;
/// Explicitly unstable helpers used by the repository's adversarial corpus.
/// Downstream production code must stay on the package surface above.
pub const testing = @import("testing.zig");

// Convenience re-exports.
pub const Cpu = runner.Cpu;
pub const Memory = runner.Memory;
pub const Opcode = runner.Opcode;
pub const HostInterface = host.HostInterface;
pub const HostRuntime = host.HostRuntime;
pub const runWithHost = runner.runWithHost;
pub const runWithInput = runner.runWithInput;
pub const RiscVClaim = air.claims.RiscVClaim;
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
pub const verifyPoseidon2WithEngine = prover_mod.verifyPoseidon2WithEngine;
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
    _ = @import("opcode_coverage_test.zig");
    _ = @import("air/extract/mod.zig");
    _ = @import("air/semantic_eval.zig");
    // The Sail bridge's own two self-checks. A file's tests are collected
    // only when a `test` block names it; the file-scope `pub const
    // sail_oracle = @import("sail_oracle.zig")` in `runner/mod.zig` is not
    // enough, and until this line existed those two tests ran in no step at
    // all. The main build reaches them through `test-riscv-sail-oracle`,
    // which roots a test artifact at the file itself.
    _ = @import("runner/sail_oracle.zig");
}

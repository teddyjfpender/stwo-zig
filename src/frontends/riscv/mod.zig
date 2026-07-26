//! Sail-authoritative RISC-V RV32IM zkVM frontend.
//!
//! Provides an execution runner for RISC-V RV32IM programs (ELF loading,
//! decode, execute) and AIR constraints for STARK proving of execution traces.

pub const runner = @import("runner/mod.zig");
pub const air = @import("air/mod.zig");
pub const opcode_manifest = @import("opcode_manifest.zig");
pub const witness_layout = @import("witness_layout.zig");
pub const prover_mod = @import("prover.zig");
pub const owned_statement = @import("owned_statement.zig");
pub const infra_trace = @import("infra_trace.zig");
pub const host = @import("host/mod.zig");

// Convenience re-exports.
pub const Cpu = runner.Cpu;
pub const Memory = runner.Memory;
pub const Opcode = runner.Opcode;
pub const HostInterface = host.HostInterface;
pub const HostRuntime = host.HostRuntime;
pub const runWithHost = runner.runWithHost;
pub const runWithInput = runner.runWithInput;
pub const RiscVClaim = air.claims.RiscVClaim;
pub const proveRiscVWithEngine = prover_mod.proveRiscVWithEngine;
pub const proveRiscVWithEngineAndPublicData = prover_mod.proveRiscVWithEngineAndPublicData;
pub const verifyRiscVWithEngine = prover_mod.verifyRiscVWithEngine;
pub const proveAndVerifyElfWithEngine = prover_mod.proveAndVerifyElfWithEngine;

test {
    @import("std").testing.refAllDeclsRecursive(infra_trace);
    _ = @import("opcode_coverage_test.zig");
}

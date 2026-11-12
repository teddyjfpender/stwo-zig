//! Sail-authoritative RISC-V RV32IM zkVM frontend.
//!
//! Provides an execution runner for RISC-V RV32IM programs (ELF loading,
//! decode, execute) and AIR constraints for STARK proving of execution traces.

pub const runner = @import("runner/mod.zig");
/// Experimental RV64IM execution only; no RV32 proof or ABI compatibility.
pub const rv64 = @import("compat/assembly/rv64/implementation.zig");
pub const rv64_air = @import("compat/assembly/rv64/air.zig");
pub const air = @import("compat/air/mod.zig");
pub const access_clock = @import("stwo_riscv_isa").access_clock;
pub const diagnostics = @import("compat/assembly/rv32/diagnostics/mod.zig");
pub const isa = @import("stwo_riscv_isa").instruction_set;
pub const opcode_manifest = @import("stwo_riscv_isa").opcode_manifest;
pub const witness_layout = @import("stwo_riscv_rv32").witness_layout;
pub const prover_mod = @import("prover.zig");
pub const statement_shape_inspection =
    @import("stwo_riscv_rv32").prover.statement_shape_inspection;
pub const owned_statement = @import("stwo_riscv_rv32").owned_statement;
pub const infra_trace = @import("stwo_riscv_rv32").trace_layout.api;
pub const host = @import("compat/host/mod.zig");
pub const recursion = @import("compat/assembly/recursion/implementation.zig");
/// Shared process resource sampler used by authenticated benchmark capture.
/// It is measurement-only and does not participate in proof semantics.
pub const process_usage = @import("stwo_prover_engine").measurement.process_usage;
/// Explicitly unstable helpers used by the repository's adversarial corpus.
/// Downstream production code must stay on the package surface above.
pub const testing = @import("compat/testing.zig");

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
        if (Cpu != @import("stwo_riscv_isa").machine.cpu.Cpu) @compileError("Cpu canonical owner drifted");
        if (Memory != @import("stwo_riscv_isa").machine.memory.Memory) @compileError("Memory canonical owner drifted");
        if (HostInterface != @import("stwo_riscv_isa").host.interface.HostInterface) @compileError("HostInterface canonical owner drifted");
        if (rv64.machine.Cpu != @import("stwo_riscv_rv64").machine.Cpu) @compileError("RV64 Cpu canonical owner drifted");
        if (@import("compat/air/lang/mod.zig").ir.Arena != @import("stwo_riscv_air_lang").ir.Arena) @compileError("AIR arena canonical owner drifted");
        if (recursion.vm_air_profile_v2.ProfileV2 != @import("stwo_riscv_rv32").recursion.vm_air_profile_v2.ProfileV2) @compileError("VM profile canonical owner drifted");
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
    _ = @import("stwo_riscv_rv32");
    _ = @import("stwo_riscv_rv32");
    // The Sail bridge's own two self-checks. A file's tests are collected
    // only when a `test` block names it; the file-scope `pub const
    // sail_oracle = @import("sail_oracle.zig")` in `runner/mod.zig` is not
    // enough, and until this line existed those two tests ran in no step at
    // all. The main build reaches them through `test-riscv-sail-oracle`,
    // which roots a test artifact at the file itself.
    _ = @import("stwo_riscv_rv32");
}

test "api invariant: native and product VM authority bindings preserve canonical records" {
    const std = @import("std");
    const native = recursion.vm_air_profile_v2;
    const product = @import("compat/product_tree/recursion/ethereum_vm_air_profile_v2.zig");
    const Selector = @TypeOf(@as(native.ProfileV2, undefined).circuit_profile);
    try std.testing.expect(@typeInfo(Selector).@"enum".tag_type == u16);
    try std.testing.expectEqual(@as(usize, 1), @typeInfo(Selector).@"enum".fields.len);
    try std.testing.expectEqual(@as(u16, 0), @intFromEnum(Selector.legacy_v4));
    try std.testing.expect(@TypeOf(@as(product.ProfileV2, undefined).circuit_profile) == @import("stwo_riscv_air_lang").physical_profile.CircuitProfileV1);
    try std.testing.expect(native.ProfileV2 != product.ProfileV2);
    try std.testing.expect(native.EntryV2 == product.EntryV2 and native.TreeSpanV2 == product.TreeSpanV2 and native.InputProfileV2 == product.InputProfileV2);
    const Support = recursion.vm_composition_graph_support_v2;
    try std.testing.expect(Support.ForExtension(null) == Support.ForExtension(null));
    const no_extension = @TypeOf(@as(Support.ForExtension(null).SampleLayoutV2, undefined).extension);
    try std.testing.expect(no_extension == void);
    try std.testing.expect(@import("compat/product_tree/recursion/ethereum_vm_composition_graph_base.zig").Result == recursion.vm_composition_graph_base_v2.Result);
    const geometry = recursion.vm_composition_base_geometry_v2;
    const compiler = recursion.vm_selected_lookup_compiler_v2;
    try std.testing.expect(@TypeOf(geometry.ForProfile(product.ProfileV2).init) != @TypeOf(geometry.ForProfile(native.ProfileV2).init));
    try std.testing.expect(@TypeOf(compiler.ForProfile(product.ProfileV2).init) != @TypeOf(compiler.ForProfile(native.ProfileV2).init));
}

//! Original Ethereum leaf-context admission and geometry regressions.
const base_statement = @import("stwo_riscv_rv32").air.statement;
const std = @import("std");
const CircuitProfileV1 = @import("stwo_riscv_air_lang").physical_profile.CircuitProfileV1;
const statement_v2 = @import("stwo_riscv_rv32").air.statement_v2;
const lookup_physical_v2 = @import("stwo_riscv_rv32").air.lang.lookup_physical_manifest;
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const ethereum_assembly = @import("../../prover/guest_precompile/ethereum_assembly.zig");
const ethereum_transcript = @import("../../prover/guest_precompile/ethereum_transcript.zig");
const ContextV1 = @import("../ethereum_leaf_context.zig").ContextV1;
const physicalBaseComponentCount = @import("../ethereum_leaf_geometry.zig").physicalBaseComponentCount;

test "Ethereum leaf context log18 admission remains explicit through retained validation" {
    const allocator = std.testing.allocator;
    const public_data_v2 = @import("stwo_riscv_rv32").air.public_data_v2;
    const public_support = @import("stwo_riscv_rv32").testing.air.public_data_test_support;
    const context_support = @import("../ethereum_leaf_context_test_support.zig");
    var fixture = try public_support.Fixture.init();
    var source = fixture.leftSource();
    // Admission still requires every external call to fit the authenticated
    // segment clock. The shared two-cycle fixture is too small for log18.
    source.cycle_count = 10_000;
    source.base_statement.job.complete.total_cycles = 20_000;
    source.base_statement.body.executed.cycle_count = source.cycle_count;
    const words = try public_support.encode(allocator, &source);
    defer allocator.free(words);
    const public_data = try public_data_v2.PublicDataV2.authenticate(words);
    const projected = try statement_v2.canonicalCorePublicData(&public_data);
    var core = context_support.retainedSegmentZeroCore();
    core.initial_pc = projected.initial_pc;
    core.final_pc = projected.final_pc;
    core.total_steps = projected.clock;
    core.public_data = projected;
    const native = try statement_v2.RiscVStatementV2.init(core, public_data);
    const circuit_profile: CircuitProfileV1 = .fixed_program_narrow_v1;
    const extension = try ethereum_statement.Statement.canonicalV2WithCircuitProfileV1(&native, 9828, 0, context_support.emptySecpShapes(), circuit_profile);
    try std.testing.expectEqual(@as(u32, 18), extension.components[0].log_size);
    var claim = context_support.zeroExtensionClaim(&extension);
    claim.keccak_shard.call_count = extension.counts.keccak_calls;
    const relations = std.mem.zeroes(ethereum_transcript.Relations);
    const base_count = try physicalBaseComponentCount(&native.core);
    const base = try allocator.alloc(@import("stwo_core").air.components.Component, base_count);
    defer allocator.free(base);
    const manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(&native.core, &manifest);
    const assembly = try ethereum_assembly.Assembly(.verifier).createAuthenticatedLookupV2WithCircuitProfileV1(allocator, &native, &extension, &relations, base, &claim, &manifest, &authenticated, circuit_profile);
    defer assembly.destroy(allocator);
    try std.testing.expectError(error.InvalidComponentGeometry, ContextV1.initVerifiedAuthenticatedLookupV2(&native, &extension, &claim, &relations, assembly, base_count, &manifest, &authenticated));
    const context = try ContextV1.initVerifiedAuthenticatedLookupV2WithCircuitProfileV1(&native, &extension, &claim, &relations, assembly, base_count, &manifest, &authenticated, circuit_profile);
    try context.validateAgainstAuthenticatedLookupV2AuthorityWithCircuitProfileV1(&native, &extension, &claim, &relations, &manifest, &authenticated, circuit_profile);
    try std.testing.expectError(error.InvalidComponentGeometry, context.validateAgainstAuthenticatedLookupV2Authority(&native, &extension, &claim, &relations, &manifest, &authenticated));
    var changed = context;
    changed.components[0].log_size -= 1;
    try std.testing.expectError(error.EthereumContextMismatch, changed.validateAgainstAuthenticatedLookupV2AuthorityWithCircuitProfileV1(&native, &extension, &claim, &relations, &manifest, &authenticated, circuit_profile));
    // Geometry-only fixture: zero claims do not establish a native proof.
}

//! Ethereum Initial38 admission policy over the shared composition kernels.
//! The product selects a typed manifest; shared graph records retain identity.
const std = @import("std");
const native = @import("stwo_riscv_frontend").recursion.recursion_air_composition_circuit_v3;
const manifest_owner = @import("air/ethereum_initial_input_manifest.zig");
const ProgramDescriptorV3 = native.ProgramDescriptorV3;
const AirProgramId = native.AirProgramId;
const Error = native.Error;
const programDescriptorIdentity = native.programDescriptorIdentity;
comptime {
    if (manifest_owner.COMPONENT_COUNT != native.INITIAL_PHYSICAL_CLAIM_COUNT)
        @compileError("Initial38 manifest and native descriptor ABI differ");
}

pub fn sealAuthenticatedEthereumInitialWrapperV1(manifest: *const manifest_owner.Manifest, air_program_id: AirProgramId) Error!ProgramDescriptorV3 {
    return ProgramDescriptorV3.sealAuthenticatedInitialWrapper(manifest, air_program_id);
}

test "Initial38 composition descriptor authenticates exact capacity and rejects stale shape or policy" {
    const initial = @import("air/ethereum_initial_input_manifest.zig");
    const base = @import("stwo_riscv_air_lang").framework.universal_adapter_manifest;
    const profile = @import("incremental_ethereum_composition_profile.zig");
    var logs = [_]u32{4} ** base.COMPONENT_COUNT;
    logs[@intFromEnum(base.ComponentKey.range_check_8_8)] = @import("stwo_riscv_rv32").recursion.air.range_check_8_8_contract.LOG_SIZE;
    const ordinary = try @import("stwo_riscv_rv32").recursion.air.universal_manifest.buildForCatalog(profile.StatementRoutingOuterCatalog, logs);
    const first = try initial.build(&ordinary, 40);
    const second = try initial.build(&ordinary, 41);
    var air_id: AirProgramId = undefined;
    for (&air_id, 0..) |*word, index| word.* = 101 + @as(u32, @intCast(index));
    const descriptor = try sealAuthenticatedEthereumInitialWrapperV1(&first, air_id);
    try descriptor.validate();
    try std.testing.expectEqual(.ethereum_initial_wrapper_v1, descriptor.manifest_family);
    try std.testing.expectEqual(.ethereum_initial_wrapper_v1, descriptor.claim_policy);
    try std.testing.expectEqual(@as(u8, 38), descriptor.source_claim_count);
    try std.testing.expectEqual(@as(u8, 38), descriptor.program_roster_count);
    try std.testing.expectEqual(@as(u8, 2), descriptor.poseidon_partial_count);
    try std.testing.expectEqual(@as(u8, 41), descriptor.composition_claim_count);
    try std.testing.expectEqual(@as(u8, 34), descriptor.poseidon_roster_row);
    const another = try sealAuthenticatedEthereumInitialWrapperV1(&second, air_id);
    try std.testing.expectEqual(first.placements[36].?.geometry.log_size, second.placements[36].?.geometry.log_size);
    try std.testing.expect(!std.meta.eql(descriptor.identity, another.identity));
    try std.testing.expect(!std.meta.eql(descriptor.ordered_program_identity, another.ordered_program_identity));
    air_id[0] += 1;
    const another_program = try sealAuthenticatedEthereumInitialWrapperV1(&first, air_id);
    try std.testing.expect(!std.meta.eql(descriptor.identity, another_program.identity));
    inline for (.{ "source_claim_count", "program_roster_count", "poseidon_partial_count", "composition_claim_count", "poseidon_roster_row" }) |field| {
        var changed = descriptor;
        @field(changed, field) += 1;
        changed.identity = programDescriptorIdentity(changed);
        try std.testing.expectError(error.InvalidProgramRoster, changed.validate());
    }
    var wrong_policy = descriptor;
    wrong_policy.claim_policy = .universal_with_zero_tail;
    wrong_policy.identity = programDescriptorIdentity(wrong_policy);
    try std.testing.expectError(error.InvalidProgramRoster, wrong_policy.validate());
    var wrong_family = descriptor;
    wrong_family.manifest_family = .universal_v1;
    wrong_family.identity = programDescriptorIdentity(wrong_family);
    try std.testing.expectError(error.InvalidProgramRoster, wrong_family.validate());
    var stale = first;
    stale.input_capacity += 1;
    try std.testing.expectError(error.ManifestAuthorityMismatch, sealAuthenticatedEthereumInitialWrapperV1(&stale, air_id));
    stale = first;
    stale.roster_count = 36;
    try std.testing.expectError(error.ManifestAuthorityMismatch, sealAuthenticatedEthereumInitialWrapperV1(&stale, air_id));
    @memset(&air_id, 0);
    try std.testing.expectError(error.AirProgramIdentityMismatch, sealAuthenticatedEthereumInitialWrapperV1(&first, air_id));
    // Only a typed circuit manifest and a fixed program identity enter this API.
    const Admit = *const fn (*const initial.Manifest, AirProgramId) Error!ProgramDescriptorV3;
    const admit: Admit = sealAuthenticatedEthereumInitialWrapperV1;
    _ = admit;
}

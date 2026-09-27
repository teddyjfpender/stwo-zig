const std = @import("std");
const core = @import("stwo_core");
const runner = @import("../runner/mod.zig");
const statement_mod = @import("blake3_poseidon_statement.zig");
test "BLAKE3 execution commitment guest Poseidon witness closes shared relations" {
    try check(false, false, false);
}
test "BLAKE3 execution commitment guest Poseidon full proof independently verifies" {
    try check(true, false, false);
}
test "BLAKE3 execution commitment guest Poseidon canonical recursive parent independently verifies" {
    try check(true, true, false);
}
test "BLAKE3 guest Poseidon canonical parent row census" {
    try check(true, false, true);
}
fn check(comptime prove: bool, comptime recurse: bool, comptime census: bool) !void {
    return checkWithOptions(prove, recurse, census, std.testing.allocator, 4);
}
test "BLAKE3 guest Poseidon canonical parent ReleaseFast benchmark" {
    if (@import("builtin").mode != .ReleaseFast) return error.SkipZigTest;
    std.debug.print("BLAKE3_PARENT_BENCHMARK allocator=smp workers=16 samples=1 warmups=0\n", .{});
    try checkWithOptions(true, true, false, std.heap.smp_allocator, 16);
}
fn checkWithOptions(comptime prove: bool, comptime recurse: bool, comptime census: bool, a: std.mem.Allocator, workers: usize) !void {
    const instructions = [_]u32{ 0x0010_02b7, 0x1002_8293, @import("../isa/custom0.zig").encodePoseidon2(5), 0x0010_0537, 0x0005_2223, 0x0000_006f };
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 64, .rv32im_zkvm_poseidon2_v1);
    var run = try runner.runPoseidon2ExtensionWithInput(a, &elf, &.{}, 100);
    defer run.deinit();
    var owned = try @import("blake3_poseidon_witness.zig").Owner.initRun(a, &run);
    var owned_alive = true;
    defer if (owned_alive) owned.deinit();
    const pin = try owned.admission();
    _ = try @import("blake3_execution_source.zig").validateProfile(.rv32im_zkvm_poseidon2_v1, a, &elf, &.{}, &owned.native.statement.public_data);
    try std.testing.expectEqual(@as(u32, 1), owned.statement.counts.n_guest);
    try std.testing.expect(owned.native.tables_ready);
    try statement_mod.validate(&owned.statement, &owned.native.statement, pin, owned.hashes.logs);
    var invalid = owned.statement;
    invalid.admission.memory_relation_terms += 1;
    try std.testing.expectError(error.AdmissionCertificateMismatch, statement_mod.validate(&invalid, &owned.native.statement, pin, owned.hashes.logs));
    invalid = owned.statement;
    invalid.counts.frozen_call_count += 1;
    try std.testing.expectError(error.CallCountMismatch, statement_mod.validate(&invalid, &owned.native.statement, pin, owned.hashes.logs));
    try std.testing.expectError(error.InvalidStatement, owned.native.statement.validateBlake3Execution());
    for (owned.native.statement.infra_descs[0..owned.native.statement.n_infra]) |desc| switch (desc.kind) {
        .program, .memory, .merkle, .poseidon2 => return error.LegacyCommitmentInBlake3Execution,
        else => {},
    };
    for (run.execution_rows.rows()) |row| {
        const found = for (owned.memory.programs) |word| {
            if (word.address == row.pc) break true;
        } else false;
        try std.testing.expect(found);
    }
    if (comptime prove) {
        owned_alive = false;
        return @import("blake3_poseidon_proof_test_support.zig").checkWithWorkers(recurse, census, a, &owned, &elf, workers);
    }
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{0x50324233});
    const universal = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const shared = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&universal);
    const relations = try @import("../air/guest_precompile/relation_challenges.zig").Poseidon2V1Relations.drawAfterBase(a, &channel, shared.native);
    try owned.native.generateInteractions(&shared.native);
    var hashes = try owned.hashes.interactions(a, &universal);
    defer hashes.deinit();
    var extension = try @import("../air/guest_precompile/interaction.zig").generateBlake3(a, &owned.native.statement, pin, owned.hashes.logs, &owned.statement, &owned.extension, &relations);
    defer extension.deinit();
    try extension.verifyGuestCancellation();
    const shape = &owned.native.statement;
    const claims = &owned.native.claims;
    var total = (try @import("../air/public_logup.zig").blake3RelationSums(&shape.public_data, &shared.native)).total();
    for (shape.component_descs[0..shape.n_components], 0..) |desc, i| total = total.add(try claims.opcodeClaimTotal(desc.family, i));
    for (shape.infra_descs[0..shape.n_infra], 0..) |desc, i| total = total.add(try claims.infraClaimTotal(desc.kind, i));
    for (hashes.claims) |claim| total = total.add(claim);
    try std.testing.expect(!total.isZero());
    try std.testing.expect(total.add(extension.callerTotal()).add(extension.providerTotal()).isZero());
    std.debug.print("BLAKE3_GUEST_POSEIDON_WITNESS calls=1 legacy_commitments=0 shared_relations_closed=true\n", .{});
}

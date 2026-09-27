const std = @import("std");
const core = @import("stwo_core");
test "BLAKE3 unused public input closes memory relations" {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x00708093, 0x00100137, 0x00100193, 0x00312223, 0x00312423, 0x0000006f };
    var elf = @import("../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 8, .rv32im_zkvm_v1);
    declareInput(&elf);
    var run = try @import("../runner/mod.zig").runWithInput(a, &elf, &.{ 1, 2, 3, 4, 0, 0, 0, 0 }, 100);
    defer run.deinit();
    var owner = try @import("blake3_segment_execution.zig").Owner.initRun(a, &run);
    defer owner.deinit();
    var channel = core.proof_suites.Blake3.Channel{};
    const universal = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const shared = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&universal);
    try owner.native.generateInteractions(&shared.native);
    var hashes = try owner.hashes.interactions(a, &universal);
    defer hashes.deinit();
    const joined = try @import("blake3_execution_components.zig").Owner.init(a, &owner.native.statement, &owner.native.claims, universal, try owner.admission());
    defer joined.deinit();
    // The previous all-input compensation leaves precisely the untouched
    // input providers dangling, independently of the proving transcript.
    const old = (try @import("../air/public_logup.zig").blake3RelationSums(&owner.native.statement.public_data, &shared.native)).total();
    try std.testing.expect(!old.eql(try joined.publicCompensation()));
    try @import("blake3_execution_proof.zig").requireClosedWithExternal(joined, hashes.claims, core.fields.qm31.QM31.zero());
}

// Extend the shared tiny ELF's symbol table into its two reserved symbol slots.
fn declareInput(elf: []u8) void {
    const names = "\x00__text_start\x00__text_len\x00__input_start\x00__input_end\x00";
    @memcpy(elf[480..][0..names.len], names);
    std.mem.writeInt(u32, elf[308..312], names.len, .little);
    std.mem.writeInt(u32, elf[268..272], 5 * 16, .little);
    std.mem.writeInt(u32, elf[608..612], @intCast(std.mem.indexOf(u8, names, "__input_start").?), .little);
    std.mem.writeInt(u32, elf[612..616], 0x00100100, .little);
    std.mem.writeInt(u32, elf[624..628], @intCast(std.mem.indexOf(u8, names, "__input_end").?), .little);
    std.mem.writeInt(u32, elf[628..632], 0x00100108, .little);
}

test "BLAKE3 partial public input proof verifies native and recursive closure" {
    const a = std.testing.allocator;
    // Read one nonzero and one zero input separately. The other word stays
    // untouched in each case, exercising both values on each side of custody.
    for ([_]u32{ 0x10012203, 0x10412203, 0 }) |load| {
        // The third case reads both adjacent words: their excluded initial
        // leaves and their common all-zero parent must fold together.
        const instructions = [_]u32{ 0x00100137, if (load == 0) 0x10012203 else load, if (load == 0) 0x10412283 else 0x00000013, 0x00100193, 0x00312223, 0x00312423, 0x0000006f };
        var elf = @import("../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 8, .rv32im_zkvm_v1);
        declareInput(&elf);
        var run = try @import("../runner/mod.zig").runWithInput(a, &elf, &.{ 1, 2, 3, 4, 0, 0, 0, 0 }, 100);
        defer run.deinit();
        var owner = try @import("blake3_segment_execution.zig").Owner.initCompactRun(a, &run);
        defer owner.deinit();
        const Api = @import("blake3_execution_proof.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
        const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
        const admission = try owner.admission();
        const prepared = try Api.PreparedVerifier.initCompact(a, &owner.native.statement, admission, config, owner.native.compact_ranges.?.plan);
        defer prepared.deinit();
        const result = try Api.proveCompact(a, owner.native, owner.hashes, admission, config);
        try std.testing.expect(owner.hashes.source_released);
        try std.testing.expectEqual(@as(usize, 0), owner.hashes.columns[0].items.len);
        try std.testing.expectEqual(@as(usize, 0), owner.hashes.columns[1].items.len);
        try owner.hashes.releaseCommittedSource(); // idempotent
        try std.testing.expectError(error.CommitmentSourceReleased, owner.hashes.prepareMain(&owner.memory));
        var captured = try Api.verifyPreparedCaptureOwned(a, result.proof, prepared, prepared.id);
        defer captured.deinit();
        var arithmetic = try @import("../recursion/air/blake3_execution_composition.zig").prepare(a, prepared, &captured, prepared.id);
        defer arithmetic.deinit();
        try arithmetic.validate(a, prepared, &captured, prepared.id);
        // Omitting the one used input's initial provider must leave a nonzero
        // relation residual. The same claim is checked inside recursive closure.
        const relations = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&captured.relations);
        const sums = @import("../air/public_logup_arithmetic.zig");
        const valid = try sums.blake3ScheduledRelationSumsFor(core.fields.qm31.QM31, &prepared.shape.public_data, &relations.native, prepared.plan.memories);
        const missing = try sums.blake3ScheduledRelationSumsFor(core.fields.qm31.QM31, &prepared.shape.public_data, &relations.native, prepared.plan.memories[0..0]);
        try std.testing.expect(!valid.total().eql(missing.total()));
    }
}

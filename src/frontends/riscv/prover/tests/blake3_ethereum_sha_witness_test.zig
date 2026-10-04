const std = @import("std");
const core = @import("stwo_core");
const runner = @import("../../runner/mod.zig");
const fixture = @import("../../runner/guest_precompile/test_elf.zig");
const Witness = @import("../blake3_ethereum_witness.zig").ShaOwner;

test "SHA combined native leaf witness commits program fetches and closes every shared relation" {
    const a = std.testing.allocator;
    const work = @import("stwo_prover_engine").work_pool;
    var pool: work.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try work.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const elf = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    var session = try runner.EthereumShaExecutionSession.initLegacy(a, &elf, .{});
    defer session.deinit();
    var run = try session.runLegacy(16);
    defer run.deinit();
    var owner = try Witness.initRun(a, &run);
    defer owner.deinit();
    try std.testing.expectEqual(@as(u32, 3), owner.native.external_retirements);
    try std.testing.expectEqual(@as(u32, 2), owner.statement.sha.call_count);
    try std.testing.expect(owner.native.tables_ready);
    for (run.extension.sha_calls.records()) |entry| {
        var found = false;
        for (owner.memory.program.rows) |row| {
            if (row.addr != entry.call.pc) continue;
            try std.testing.expectEqualDeep(@import("../../air/program/decode.zig").ProgramValues{ 50, 0, entry.call.state_register, entry.call.block_register }, row.values);
            try std.testing.expectEqual(@as(u32, 1), row.multiplicity);
            found = true;
        }
        try std.testing.expect(found);
    }
    const saved_clock = run.extension.sha_calls.storage.items[1].call.execution_clock;
    run.extension.sha_calls.storage.items[1].call.execution_clock = run.extension.keccakf_calls.records()[0].execution_clock;
    try std.testing.expectError(error.DuplicateExternalClock, Witness.initRun(a, &run));
    run.extension.sha_calls.storage.items[1].call.execution_clock = saved_clock;
    try checkClosure(a, &owner, &pool);
}

fn checkClosure(a: std.mem.Allocator, owner: *Witness, pool: *@import("stwo_prover_engine").work_pool.WorkPool) !void {
    var channel = core.proof_suites.Blake3.Channel{};
    try owner.statement.mix(a, &channel, @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG, &owner.native.statement, try owner.admission(), owner.hashes.logs);
    const vm = try @import("../../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const shared = try @import("../../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&vm);
    const relations = try @import("../guest_precompile/ethereum_sha_relations.zig").Relations.drawAfterVm(a, &channel, vm);
    try owner.native.generateInteractions(&shared.native);
    var hashes = try owner.hashes.interactions(a, &vm);
    defer hashes.deinit();
    var extension = try @import("../guest_precompile/ethereum_sha_columns.zig").interactions(a, owner, &relations, pool);
    defer extension.deinit(a);
    try checkAssemblyAndWire(a, owner, vm, &relations, &hashes, &extension);

    const shape = &owner.native.statement;
    const claims = &owner.native.claims;
    var total = (try @import("../../air/public_logup_arithmetic.zig").blake3RelationSumsForProfile(core.fields.qm31.QM31, .rv32im_zkvm_ethereum_sha_v1, &shape.public_data, &shared.native)).total();
    for (shape.component_descs[0..shape.n_components], 0..) |desc, i| total = total.add(try claims.opcodeClaimTotal(desc.family, i));
    for (shape.infra_descs[0..shape.n_infra], 0..) |desc, i| total = total.add(try claims.infraClaimTotal(desc.kind, i));
    for (hashes.claims) |claim| total = total.add(claim);
    total = total.add(extension.claim.ethereum.componentSum());
    try std.testing.expect(!total.isZero());
    total = total.add(extension.sha_columns.total());
    if (!total.isZero()) std.debug.print("SHA_COMBINED_RESIDUAL {any}\n", .{total});
    try std.testing.expect(total.isZero());
    std.debug.print("SHA_COMBINED_WITNESS external={d} sha={d} keccak={d} shared_relations_closed=true proof_verified=false\n", .{ owner.native.external_retirements, owner.statement.sha.call_count, owner.statement.ethereum.counts.keccak_calls });
}

test "SHA combined leaf local witnesses close across a released segment boundary" {
    const a = std.testing.allocator;
    const work = @import("stwo_prover_engine").work_pool;
    var pool: work.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try work.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    for ([_]u64{ 3, 4 }) |first_steps| {
        const elf = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
        var session = try runner.EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
        defer session.deinit();
        const continuation = blk: {
            var segment = try session.startSegment(first_steps);
            defer segment.deinit();
            var owner = try Witness.initSegment(a, &segment);
            defer owner.deinit();
            try std.testing.expectEqual(@as(u32, if (first_steps == 3) 0 else 1), owner.statement.sha.call_count);
            try std.testing.expectEqual(@as(u32, 0), owner.statement.ethereum.counts.keccak_calls);
            try checkClosure(a, &owner, &pool);
            break :blk segment.base.continuation.?;
        };
        var segment = try session.resumeSegment(continuation, 4);
        defer segment.deinit();
        var owner = try Witness.initSegment(a, &segment);
        defer owner.deinit();
        try std.testing.expectEqual(@as(u32, if (first_steps == 3) 2 else 1), owner.statement.sha.call_count);
        try std.testing.expectEqual(@as(u32, 1), owner.statement.ethereum.counts.keccak_calls);
        try checkClosure(a, &owner, &pool);
    }
}

fn checkAssemblyAndWire(a: std.mem.Allocator, owner: *Witness, vm: @import("../../recursion/air/universal_challenges.zig").UniversalRelations, relations: *const @import("../guest_precompile/ethereum_sha_relations.zig").Relations, hashes: anytype, extension: anytype) !void {
    const engine = @import("stwo_prover_engine");
    const columns = @import("../guest_precompile/ethereum_sha_columns.zig");
    const pp = try columns.preprocessed(a, &owner.statement);
    defer {
        for (pp) |column| a.free(column.values);
        a.free(pp);
    }
    var main = try columns.main(a, owner);
    defer main.deinit(a);
    const joined = try @import("../blake3_execution_components.zig").Owner.initWithExternalForProfile(a, &owner.native.statement, &owner.native.claims, vm, try owner.admission(), owner.native.external_retirements, .rv32im_zkvm_ethereum_sha_v1);
    defer joined.deinit();
    try joined.bindCommitments(owner.hashes, hashes.claims);
    var provers: std.ArrayList(engine.air.component_prover.ComponentProver) = .empty;
    defer provers.deinit(a);
    try provers.appendSlice(a, joined.proving.components.active());
    try provers.appendSlice(a, &(try owner.hashes.provers()));
    var verifiers: std.ArrayList(core.air.components.Component) = .empty;
    defer verifiers.deinit(a);
    try verifiers.appendSlice(a, joined.verifying.components.active());
    try verifiers.appendSlice(a, &(try owner.hashes.verifiers()));
    const assembly = @import("../guest_precompile/ethereum_sha_assembly.zig");
    const prover = try assembly.Assembly(.prover).createBlake3WithRanges(a, &owner.native.statement, &owner.statement, try owner.admission(), owner.hashes.logs, relations, provers.items, &extension.claim, null);
    defer prover.destroy(a);
    const verifier = try assembly.Assembly(.verifier).createBlake3WithRanges(a, &owner.native.statement, &owner.statement, try owner.admission(), owner.hashes.logs, relations, verifiers.items, &extension.claim, null);
    defer verifier.destroy(a);
    try std.testing.expectEqual(prover.active().len, verifier.active().len);
    try std.testing.expectEqualDeep(prover.extensionPlacements(), verifier.extensionPlacements());
    const placements = prover.extensionPlacements();
    var offsets = placements[0];
    for (owner.statement.ethereum.components, 0..) |desc, i| {
        try std.testing.expectEqualDeep(offsets, placements[i]);
        offsets.preprocessed_offset += desc.preprocessed_columns;
        offsets.main_offset += desc.main_columns;
        offsets.interaction_offset += desc.interaction_columns;
    }
    for (owner.statement.sha.descriptors, 0..) |desc, i| {
        try std.testing.expectEqualDeep(offsets, placements[14 + i]);
        offsets.preprocessed_offset += desc.preprocessed_columns;
        offsets.main_offset += desc.main_columns;
        offsets.interaction_offset += desc.interaction_columns;
    }
    try std.testing.expectEqual(pp.len, offsets.preprocessed_offset - placements[0].preprocessed_offset);
    try std.testing.expectEqual(main.columns.len, offsets.main_offset - placements[0].main_offset);
    try std.testing.expectEqual(extension.columns.len, offsets.interaction_offset - placements[0].interaction_offset);
    const wire = @import("../guest_precompile/ethereum_sha_claim_wire.zig");
    var encoded: std.Io.Writer.Allocating = .init(a);
    defer encoded.deinit();
    try wire.encodeExtensionClaim(&encoded.writer, &owner.statement, &extension.claim);
    const Cursor = @import("../guest_precompile/proof_artifact_wire.zig").Cursor;
    var cursor = Cursor.init(encoded.written());
    const restored = try wire.decodeExtensionClaim(&cursor, &owner.statement);
    try cursor.requireDone();
    try std.testing.expectEqualDeep(extension.claim, restored);
    var first = core.proof_suites.Blake3.Channel{};
    var second = first;
    extension.claim.mixInto(&first);
    restored.mixInto(&second);
    try std.testing.expectEqualDeep(first.digestBytes(), second.digestBytes());
    const truncated = encoded.written()[0 .. encoded.written().len - 1];
    cursor = Cursor.init(truncated);
    if (wire.decodeExtensionClaim(&cursor, &owner.statement)) |_| return error.AcceptedTruncatedShaClaim else |_| {}
    // Canonical field validation rejects a modulus limb instead of reducing it.
    const bad = try a.dupe(u8, encoded.written());
    defer a.free(bad);
    std.mem.writeInt(u32, bad[bad.len - 4 ..][0..4], core.fields.m31.Modulus, .little);
    cursor = Cursor.init(bad);
    try std.testing.expectError(error.NonCanonicalM31, wire.decodeExtensionClaim(&cursor, &owner.statement));
}

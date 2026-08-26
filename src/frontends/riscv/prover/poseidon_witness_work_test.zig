const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_api = @import("stwo_prover_api");
const work_profile = prover_api.work_profile;
const memory_poseidon = @import("../air/memory_commitment/poseidon2.zig");
const poseidon_air = @import("../air/memory_commitment/poseidon2_air.zig");
const sparse_merkle = @import("../air/memory_commitment/sparse_merkle.zig");
const common_poseidon = @import("../common/poseidon2.zig");
const subject = @import("poseidon_witness_work.zig");

test "Poseidon work authority derives the two implementation schedules" {
    const authority = subject.Authority.init();
    try authority.validate();
    try std.testing.expectEqual(
        work_profile.FieldOperations{ .additions = 1_418, .multiplications = 650 },
        authority.stark_v_permutation,
    );
    try std.testing.expectEqual(
        work_profile.FieldOperations{ .additions = 1_382, .multiplications = 650 },
        authority.legacy_common_permutation,
    );
    try std.testing.expectEqual(
        subject.ExecutionCapability.shared_host_frontend,
        authority.capability,
    );
}

test "profiled sparse tree returns output parity and exact completed hashes" {
    const authority = subject.Authority.init();
    for ([_]usize{ 1, 2, 4 }) |leaf_count| {
        var leaves: [4]sparse_merkle.Leaf = undefined;
        for (leaves[0..leaf_count], 0..) |*leaf, index| {
            leaf.* = .{ .index = @intCast(3 * index), .value = @intCast(index + 1) };
        }
        var plain = try sparse_merkle.build(std.testing.allocator, leaves[0..leaf_count]);
        defer plain.deinit(std.testing.allocator);
        var profiled = try sparse_merkle.buildWithWorkReceipt(
            std.testing.allocator,
            leaves[0..leaf_count],
            &authority,
        );
        defer profiled.tree.deinit(std.testing.allocator);

        try std.testing.expectEqual(plain.root, profiled.tree.root);
        try std.testing.expectEqualDeep(plain.nodes, profiled.tree.nodes);
        try profiled.receipt.validate(&authority);
        try std.testing.expectEqual(
            @as(u64, @intCast(profiled.tree.nodes.len)),
            profiled.receipt.completed_permutations,
        );
        try std.testing.expectEqual(
            @as(u64, @intCast(profiled.tree.nodes.len)) * 1_418,
            profiled.receipt.operations.additions,
        );
    }
}

test "profiled AIR rows preserve columns and scale over active calls only" {
    const authority = subject.Authority.init();
    var calls: [4]poseidon_air.Call = undefined;
    for (&calls, 0..) |*call, index| {
        call.* = poseidon_air.Call.narrow(
            @intCast(index + 1),
            @intCast(index + 17),
        );
    }
    for ([_]usize{ 1, 2, 4 }) |call_count| {
        var plain = try poseidon_air.generateMain(
            std.testing.allocator,
            calls[0..call_count],
            3,
        );
        defer plain.deinit(std.testing.allocator);
        var profiled = try poseidon_air.generateMainWithWorkReceipt(
            std.testing.allocator,
            calls[0..call_count],
            3,
            &authority,
        );
        defer profiled.columns.deinit(std.testing.allocator);

        for (plain.values, profiled.columns.values) |expected, actual|
            try std.testing.expectEqualSlices(M31, expected, actual);
        try profiled.receipt.validate(&authority);
        try std.testing.expectEqual(
            @as(u64, @intCast(call_count)),
            profiled.receipt.completed_permutations,
        );
        try std.testing.expectEqual(
            @as(u64, @intCast(call_count)) * 650,
            profiled.receipt.operations.multiplications,
        );
    }
}

test "legacy common receipt is distinct and output-identical" {
    const authority = subject.Authority.init();
    var input = [_]M31{M31.zero()} ** common_poseidon.STATE_WIDTH;
    input[0] = M31.fromCanonical(41);
    input[7] = M31.fromCanonical(97);
    var expected = input;
    common_poseidon.permute(&expected);

    const completed = try common_poseidon.permuteWithWorkReceipt(input, &authority);
    try std.testing.expectEqualDeep(expected, completed.state);
    try completed.receipt.validate(&authority);
    try std.testing.expectEqual(
        subject.Algorithm.legacy_common_m31_width_16,
        completed.receipt.algorithm,
    );
    try std.testing.expectEqual(@as(u64, 1_382), completed.receipt.operations.additions);
}

test "subreceipt aggregation binds all active production phases" {
    const authority = subject.Authority.init();
    var shard = subject.Shard{};
    try shard.observe(
        &authority,
        try subject.complete(&authority, .sparse_tree_permutation, 7),
    );
    try shard.observe(
        &authority,
        try subject.complete(&authority, .base_air_row_materialization, 3),
    );
    try shard.observe(
        &authority,
        try subject.complete(&authority, .guest_provider_preflight, 2),
    );
    try shard.observe(
        &authority,
        try subject.complete(&authority, .guest_provider_materialization, 2),
    );
    const receipt = try subject.seal(&authority, shard);
    try receipt.validate(&authority);
    try std.testing.expectEqual(@as(u64, 14), try receipt.completed.counts.total());
    try std.testing.expectEqual(@as(u64, 14 * 1_418), receipt.completed.operations.additions);
    try std.testing.expectEqual(@as(u64, 14 * 650), receipt.completed.operations.multiplications);
    try std.testing.expectEqual(
        work_profile.Site.sparse_memory_and_guest_poseidon_witness,
        receipt.delta().site.?,
    );
}

test "Poseidon receipt mutation fleet and aggregation fail atomically" {
    const authority = subject.Authority.init();
    const honest = try subject.complete(&authority, .guest_provider_preflight, 2);
    var initial = subject.Shard{};
    try initial.observe(
        &authority,
        try subject.complete(&authority, .sparse_tree_permutation, 1),
    );

    const Mutation = enum {
        schema,
        algorithm,
        phase,
        count,
        additions,
        source_digest,
        receipt_digest,
    };
    for (std.enums.values(Mutation)) |mutation| {
        var forged = honest;
        switch (mutation) {
            .schema => forged.schema_version +%= 1,
            .algorithm => forged.algorithm = .legacy_common_m31_width_16,
            .phase => forged.phase = .legacy_common_trace,
            .count => forged.completed_permutations += 1,
            .additions => forged.operations.additions += 1,
            .source_digest => forged.source_digest[0] ^= 1,
            .receipt_digest => forged.receipt_digest[0] ^= 1,
        }
        var destination = initial;
        try std.testing.expectError(
            error.InvalidPoseidonWorkReceipt,
            destination.observe(&authority, forged),
        );
        try std.testing.expectEqualDeep(initial, destination);
    }

    var overflow = initial;
    overflow.counts.guest_provider_preflight_rows = std.math.maxInt(u64);
    const before = overflow;
    try std.testing.expectError(
        error.PoseidonWorkOverflow,
        overflow.observe(&authority, honest),
    );
    try std.testing.expectEqualDeep(before, overflow);
}

test "aggregate receipt and canonical publication reject mutation" {
    const authority = subject.Authority.init();
    var completed = subject.Shard{};
    try completed.observe(
        &authority,
        try subject.complete(&authority, .sparse_tree_permutation, 3),
    );
    const honest = try subject.seal(&authority, completed);

    const Mutation = enum { schema, count, additions, source_digest, receipt_digest };
    for (std.enums.values(Mutation)) |mutation| {
        var forged = honest;
        switch (mutation) {
            .schema => forged.schema_version +%= 1,
            .count => forged.completed.counts.sparse_tree_permutations += 1,
            .additions => forged.completed.operations.additions += 1,
            .source_digest => forged.source_digest[0] ^= 1,
            .receipt_digest => forged.receipt_digest[0] ^= 1,
        }
        try std.testing.expectError(
            error.InvalidPoseidonWorkReceipt,
            forged.validate(&authority),
        );
    }

    var recorder = prover_api.stage_profile.Recorder.initWithOptions(
        std.testing.allocator,
        "test",
        "poseidon-witness-publication",
        .{ .capture_work = true },
    );
    defer recorder.deinit();
    const planned = (try subject.plan(&recorder)) orelse unreachable;
    try std.testing.expectEqual(authority.source_digest, planned.source_digest);

    var forged = honest;
    forged.receipt_digest[0] ^= 1;
    try std.testing.expectError(
        error.InvalidPoseidonWorkReceipt,
        subject.publish(&recorder, forged),
    );
    try subject.publish(&recorder, honest);
    const work = recorder.workCaptureRecorder() orelse unreachable;
    const site_index = @intFromEnum(
        work_profile.Site.sparse_memory_and_guest_poseidon_witness,
    );
    try std.testing.expectEqual(@as(u64, 1), work.planned_sites[site_index]);
    try std.testing.expectEqual(@as(u64, 1), work.completed_sites[site_index]);
    const snapshot = try recorder.workSnapshot();
    try snapshot.validate();
}

test "invalid sparse producer input returns no receipt-bearing owner" {
    const authority = subject.Authority.init();
    try std.testing.expectError(
        error.DuplicateLeaf,
        sparse_merkle.buildWithWorkReceipt(
            std.testing.allocator,
            &.{
                .{ .index = 9, .value = 1 },
                .{ .index = 9, .value = 2 },
            },
            &authority,
        ),
    );
}

test "memory permutation output remains pinned beside receipt formulas" {
    try std.testing.expectEqual(@as(u32, 1_975_699_496), memory_poseidon.hashPair(1, 2));
}

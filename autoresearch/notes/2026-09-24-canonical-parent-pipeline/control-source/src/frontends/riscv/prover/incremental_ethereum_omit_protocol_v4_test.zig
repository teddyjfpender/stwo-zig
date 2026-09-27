//! Unit gates for the omitted-provider V4 route protocol (grafts G2 + G3).
//!
//! Nothing here proves. These pin the three things a later prove/verify pair
//! cannot re-derive on its own: that the residency request carries no host
//! knob, that the pre-Tree0 frame's transcript order and identity are exact,
//! and that the per-shard leaf authority binds all four of its inputs.

const std = @import("std");
const route = @import("incremental_ethereum_omit_protocol_v4.zig");
const bridge_external = @import("incremental_bridge_external_v3.zig");
const poseidon_channel = @import("../recursion/poseidon2_channel.zig");
const residency_shard_plan =
    @import("stwo_prover_engine").pcs.residency_shard_plan;
const omission =
    @import("memory_provider_shards/native_provider_omit_v1.zig");

const Pins = route.ProviderOmissionPinsV1;
const FrameV4 = route.IncrementalOmissionFrameV4;
const LeafAuthorityV4 = route.LeafOmissionAuthorityV4;

/// Provider call count of the retained V4 leaf statement (segment 1 of the
/// hoisted-release campaign): 6,671,301 narrow-memory Poseidon2 calls.
const retained_leaf_calls: u64 = 6_671_301;

const full_prefix = bridge_external.PrefixColumnsV3{
    .preprocessed = 100,
    .main = 4_000,
    .interaction = 200,
};
const projected_prefix = bridge_external.PrefixColumnsV3{
    .preprocessed = full_prefix.preprocessed - route.omitted_preprocessed_columns,
    .main = full_prefix.main - route.omitted_main_columns,
    .interaction = full_prefix.interaction - route.omitted_interaction_columns,
};
const bridge_rows: u32 = 1_000;

const projection_identity = [_]u8{0x11} ** 32;
const profile_identity = [_]u8{0x22} ** 32;
const shared_identity = [_]u8{0x33} ** 32;
const full_authority_id = [8]u32{ 7, 6, 5, 4, 3, 2, 1, 9 };

test "incremental omission route v4: residency request is a pure function of the call count" {
    // Pin-drift guard: a host knob edited into the pin set fails this build,
    // not a later proof identity comparison.
    comptime {
        if (Pins.shard_log_size != 18 or
            Pins.requested_parallel_shards != 18 or
            Pins.log_blowup_factor != 1 or
            Pins.retention_policy != .always or
            Pins.host_byte_budget != 51_539_607_552 or
            Pins.reserved_host_bytes != 8_589_934_592 or
            Pins.column_count != 445 or
            Pins.execution_owners != 18 or
            Pins.engine_workers_per_owner != 1 or
            Pins.non_column_reserve_per_owner != 536_870_912)
        {
            @compileError("provider omission pins drifted");
        }
        const probe = Pins.request(retained_leaf_calls);
        if (probe.min_shard_log_size != 18 or probe.max_shard_log_size != 18 or
            probe.column_count != 445 or probe.requested_parallel_shards != 18)
        {
            @compileError("pinned residency request drifted");
        }
    }

    const request = Pins.request(retained_leaf_calls);
    try std.testing.expect(std.meta.eql(
        request,
        Pins.request(retained_leaf_calls),
    ));
    try std.testing.expectEqual(
        retained_leaf_calls,
        request.logical_row_count,
    );
    try std.testing.expectEqual(
        @as(u64, 445),
        request.column_count,
    );
    try Pins.validateRequest(request, retained_leaf_calls);

    // Only the call count moves.
    var normalised = Pins.request(1);
    normalised.logical_row_count = request.logical_row_count;
    try std.testing.expect(std.meta.eql(normalised, request));

    // The request identity is a function of the call count alone, and the pin
    // identity does not move with the statement at all.
    const other = Pins.request(retained_leaf_calls + 1);
    const request_id = request.identity();
    const other_id = other.identity();
    try std.testing.expect(!std.mem.eql(u8, &request_id, &other_id));
    const pins_id = Pins.identity();
    const pins_id_again = Pins.identity();
    try std.testing.expectEqualSlices(u8, &pins_id, &pins_id_again);
    try std.testing.expect(!std.mem.eql(u8, &pins_id, &([_]u8{0} ** 32)));
}

test "incremental omission route v4: the retained leaf plans 26 log-18 shards" {
    const residency = try Pins.residencyAuthority(retained_leaf_calls);
    try residency.validate();
    try std.testing.expectEqual(@as(u32, 18), residency.result.shard_log_size);
    try std.testing.expectEqual(
        @as(u64, 1) << 18,
        residency.result.shard_capacity,
    );
    try std.testing.expectEqual(@as(u64, 26), residency.result.shard_count);
    try std.testing.expectEqual(
        @as(u32, 18),
        residency.result.requested_parallel_shards,
    );
    try std.testing.expectEqual(
        @as(u32, 18),
        residency.result.admitted_parallel_shards,
    );
    try std.testing.expectEqual(
        retained_leaf_calls,
        residency.result.logical_row_count,
    );
    const request_id = residency.request.identity();
    try std.testing.expectEqualSlices(
        u8,
        &request_id,
        &residency.result.request_identity,
    );
    try std.testing.expectError(
        error.EmptyProviderOmissionCallAuthorityV4,
        Pins.residencyAuthority(0),
    );
}

test "incremental omission route v4: every host-knob mutation is refused" {
    const canonical = Pins.request(retained_leaf_calls);
    try std.testing.expectError(
        error.EmptyProviderOmissionCallAuthorityV4,
        Pins.validateRequest(canonical, 0),
    );
    try std.testing.expectError(
        error.ProviderOmissionPinDriftV4,
        Pins.validateRequest(canonical, retained_leaf_calls - 1),
    );

    const Mutation = struct {
        name: []const u8,
        apply: *const fn (*residency_shard_plan.Request) void,
    };
    const mutations = [_]Mutation{
        .{ .name = "shard log", .apply = struct {
            fn f(r: *residency_shard_plan.Request) void {
                r.max_shard_log_size = 17;
            }
        }.f },
        .{ .name = "shard log floor", .apply = struct {
            fn f(r: *residency_shard_plan.Request) void {
                r.min_shard_log_size = 4;
            }
        }.f },
        .{ .name = "owner fan-out", .apply = struct {
            fn f(r: *residency_shard_plan.Request) void {
                r.requested_parallel_shards = 9;
            }
        }.f },
        .{ .name = "blowup", .apply = struct {
            fn f(r: *residency_shard_plan.Request) void {
                r.log_blowup_factor = 2;
            }
        }.f },
        .{ .name = "retention", .apply = struct {
            fn f(r: *residency_shard_plan.Request) void {
                r.retention_policy = .never;
            }
        }.f },
        .{ .name = "host budget", .apply = struct {
            fn f(r: *residency_shard_plan.Request) void {
                r.host_byte_budget = 64 * 1024 * 1024 * 1024;
            }
        }.f },
        .{ .name = "host reserve", .apply = struct {
            fn f(r: *residency_shard_plan.Request) void {
                r.reserved_host_bytes = 4 * 1024 * 1024 * 1024;
            }
        }.f },
        .{ .name = "column count", .apply = struct {
            fn f(r: *residency_shard_plan.Request) void {
                r.column_count = 444;
            }
        }.f },
        .{ .name = "row count", .apply = struct {
            fn f(r: *residency_shard_plan.Request) void {
                r.logical_row_count += 1;
            }
        }.f },
    };
    for (mutations) |mutation| {
        var mutated = canonical;
        mutation.apply(&mutated);
        std.testing.expectError(
            error.ProviderOmissionPinDriftV4,
            Pins.validateRequest(mutated, retained_leaf_calls),
        ) catch |err| {
            std.debug.print(
                "mutation \"{s}\" was admitted\n",
                .{mutation.name},
            );
            return err;
        };
    }
}

test "incremental omission route v4: projected bridge geometry removes exactly the poseidon2 columns" {
    const full = try bridge_external.GeometryV3.canonicalAfterPrefix(
        bridge_rows,
        full_prefix,
    );
    const projected = try route.projectedBridgeGeometryFromPrefix(
        &full,
        projected_prefix,
    );
    try std.testing.expectEqual(full.n_rows, projected.n_rows);
    try std.testing.expectEqual(full.log_size, projected.log_size);
    try std.testing.expectEqual(
        full.placement.is_first_col_idx - 2,
        projected.placement.is_first_col_idx,
    );
    try std.testing.expectEqual(
        full.placement.is_active_col_idx - 2,
        projected.placement.is_active_col_idx,
    );
    try std.testing.expectEqual(
        full.placement.main_col_offset - 445,
        projected.placement.main_col_offset,
    );
    try std.testing.expectEqual(
        full.placement.interaction_col_offset - 8,
        projected.placement.interaction_col_offset,
    );
    try std.testing.expectEqual(
        full.total_main_columns - 445,
        projected.total_main_columns,
    );
    try projected.validateAfterPrefix(projected_prefix);

    // Off-by-one in any of the three removals is refused.
    var wrong = projected_prefix;
    wrong.main += 1;
    try std.testing.expectError(
        error.InvalidIncrementalOmissionBridgeGeometryV4,
        route.projectedBridgeGeometryFromPrefix(&full, wrong),
    );
    wrong = projected_prefix;
    wrong.preprocessed -= 1;
    try std.testing.expectError(
        error.InvalidIncrementalOmissionBridgeGeometryV4,
        route.projectedBridgeGeometryFromPrefix(&full, wrong),
    );
    wrong = projected_prefix;
    wrong.interaction += 2;
    try std.testing.expectError(
        error.InvalidIncrementalOmissionBridgeGeometryV4,
        route.projectedBridgeGeometryFromPrefix(&full, wrong),
    );
    // The full prefix itself is not a projection of itself.
    try std.testing.expectError(
        error.InvalidIncrementalOmissionBridgeGeometryV4,
        route.projectedBridgeGeometryFromPrefix(&full, full_prefix),
    );
}

test "incremental omission route v4: frame identity and pre-Tree0 mix order are exact" {
    const frame = try FrameV4.canonicalFromProjectionIdentity(
        projection_identity,
        bridge_rows,
        projected_prefix,
    );
    try frame.validate();
    const again = try FrameV4.canonicalFromProjectionIdentity(
        projection_identity,
        bridge_rows,
        projected_prefix,
    );
    try std.testing.expect(std.meta.eql(frame, again));
    const pins_id = Pins.identity();
    try std.testing.expectEqualSlices(u8, &pins_id, &frame.pins_identity);

    // Exact transcript order: domain words, projection identity, pins
    // identity, projected bridge geometry field authority.
    var actual = poseidon_channel.Channel{};
    frame.mixInto(&actual);
    var expected = poseidon_channel.Channel{};
    expected.mixU32s(&[4]u32{ 0x5749_5453, 0x3456_4d4f, 1, 0 });
    mixDigestWords(&expected, projection_identity);
    mixDigestWords(&expected, pins_id);
    frame.projected_bridge_geometry.mixFieldAuthority(&expected);
    try std.testing.expectEqual(expected.digestWords(), actual.digestWords());

    // A different projection moves the transcript and the identity.
    var other_identity = projection_identity;
    other_identity[0] ^= 0xff;
    const other = try FrameV4.canonicalFromProjectionIdentity(
        other_identity,
        bridge_rows,
        projected_prefix,
    );
    try std.testing.expect(!std.mem.eql(u8, &frame.identity, &other.identity));
    var other_channel = poseidon_channel.Channel{};
    other.mixInto(&other_channel);
    try std.testing.expect(
        !std.meta.eql(actual.digestWords(), other_channel.digestWords()),
    );

    // So does a different bridge row count.
    const taller = try FrameV4.canonicalFromProjectionIdentity(
        projection_identity,
        bridge_rows + 1,
        projected_prefix,
    );
    try std.testing.expect(!std.mem.eql(u8, &frame.identity, &taller.identity));
}

test "incremental omission route v4: a mutated frame fails closed" {
    const frame = try FrameV4.canonicalFromProjectionIdentity(
        projection_identity,
        bridge_rows,
        projected_prefix,
    );

    var mutated = frame;
    mutated.projection_identity[3] ^= 0x01;
    try std.testing.expectError(
        error.InvalidIncrementalOmissionFrameV4,
        mutated.validate(),
    );

    mutated = frame;
    mutated.pins_identity[0] ^= 0x01;
    try std.testing.expectError(
        error.ProviderOmissionPinDriftV4,
        mutated.validate(),
    );

    mutated = frame;
    mutated.identity[31] ^= 0x01;
    try std.testing.expectError(
        error.InvalidIncrementalOmissionFrameV4,
        mutated.validate(),
    );

    mutated = frame;
    mutated.format = 2;
    try std.testing.expectError(
        error.InvalidIncrementalOmissionFrameV4,
        mutated.validate(),
    );

    mutated = frame;
    mutated.projection_identity = [_]u8{0} ** 32;
    try std.testing.expectError(
        error.InvalidIncrementalOmissionProjectionV4,
        mutated.validate(),
    );

    // Geometry surgery that keeps the frame identity consistent still fails on
    // the geometry's own canonical recomputation.
    mutated = frame;
    mutated.projected_bridge_geometry.total_main_columns += 1;
    mutated.identity = frame.identity;
    try std.testing.expectError(
        error.InvalidIncrementalBridgeGeometry,
        mutated.validate(),
    );

    // `validateAgainst` reads only the projection identity, so a synthetic
    // projection is enough to exercise the readmission it performs.
    var projection: omission.ProjectionV1 = undefined;
    projection.identity = projection_identity;
    try frame.validateAgainst(&projection, projected_prefix);

    // A frame built for a different prefix is not readmitted for this one.
    var shifted = projected_prefix;
    shifted.main += 1;
    const foreign = try FrameV4.canonicalFromProjectionIdentity(
        projection_identity,
        bridge_rows,
        shifted,
    );
    try std.testing.expectError(
        error.InvalidIncrementalOmissionBridgeGeometryV4,
        foreign.validateAgainst(&projection, projected_prefix),
    );

    // Nor is a frame that binds another projection.
    var foreign_projection: omission.ProjectionV1 = undefined;
    foreign_projection.identity = [_]u8{0x55} ** 32;
    try std.testing.expectError(
        error.InvalidIncrementalOmissionProjectionV4,
        frame.validateAgainst(&foreign_projection, projected_prefix),
    );
}

test "incremental omission route v4: the leaf authority binds all four inputs" {
    const frame = try FrameV4.canonicalFromProjectionIdentity(
        projection_identity,
        bridge_rows,
        projected_prefix,
    );
    const leaf = try LeafAuthorityV4.canonical(
        profile_identity,
        frame.identity,
        shared_identity,
        full_authority_id,
    );
    try leaf.validate();
    try leaf.validateAgainst(
        profile_identity,
        &frame,
        shared_identity,
        full_authority_id,
    );

    // Each of the four inputs moves the identity.
    var other_profile = profile_identity;
    other_profile[0] ^= 0xff;
    var other_shared = shared_identity;
    other_shared[31] ^= 0xff;
    var other_authority = full_authority_id;
    other_authority[7] += 1;
    const variants = [_]LeafAuthorityV4{
        try LeafAuthorityV4.canonical(
            other_profile,
            frame.identity,
            shared_identity,
            full_authority_id,
        ),
        try LeafAuthorityV4.canonical(
            profile_identity,
            [_]u8{0x44} ** 32,
            shared_identity,
            full_authority_id,
        ),
        try LeafAuthorityV4.canonical(
            profile_identity,
            frame.identity,
            other_shared,
            full_authority_id,
        ),
        try LeafAuthorityV4.canonical(
            profile_identity,
            frame.identity,
            shared_identity,
            other_authority,
        ),
    };
    for (variants) |variant| {
        try std.testing.expect(
            !std.mem.eql(u8, &leaf.identity, &variant.identity),
        );
        try std.testing.expectError(
            error.InvalidLeafOmissionAuthorityV4,
            variant.validateAgainst(
                profile_identity,
                &frame,
                shared_identity,
                full_authority_id,
            ),
        );
    }

    // Missing bindings and a mutated identity are refused.
    try std.testing.expectError(
        error.InvalidLeafOmissionAuthorityV4,
        LeafAuthorityV4.canonical(
            [_]u8{0} ** 32,
            frame.identity,
            shared_identity,
            full_authority_id,
        ),
    );
    try std.testing.expectError(
        error.InvalidLeafOmissionAuthorityV4,
        LeafAuthorityV4.canonical(
            profile_identity,
            frame.identity,
            shared_identity,
            [_]u32{0} ** 8,
        ),
    );
    var mutated = leaf;
    mutated.identity[0] ^= 0x01;
    try std.testing.expectError(
        error.InvalidLeafOmissionAuthorityV4,
        mutated.validate(),
    );

    // Shard-local prefix order: domain words, leaf identity, pin identity.
    var actual = poseidon_channel.Channel{};
    leaf.mixIntoLocalPrefix(&actual);
    var expected = poseidon_channel.Channel{};
    expected.mixU32s(&[4]u32{ 0x5749_5453, 0x3456_4c50, 1, 0 });
    mixDigestWords(&expected, leaf.identity);
    const pins_id = Pins.identity();
    mixDigestWords(&expected, pins_id);
    try std.testing.expectEqual(expected.digestWords(), actual.digestWords());

    // The leaf prefix frame is distinct from the pre-Tree0 frame domain.
    var frame_channel = poseidon_channel.Channel{};
    frame.mixInto(&frame_channel);
    try std.testing.expect(
        !std.meta.eql(actual.digestWords(), frame_channel.digestWords()),
    );
}

fn mixDigestWords(channel: *poseidon_channel.Channel, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, digest[index * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}

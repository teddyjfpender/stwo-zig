const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const frontend = @import("stwo_riscv_frontend");
const binary_outer = @import("recursive_binary_outer.zig");
const pair_authority = @import("recursive_temporal_pair_authority_v2.zig");
const temporal_nonfri = @import("recursive_temporal_nonfri_source_v2.zig");

const schedule = frontend.recursion.air.verifier_schedule;
const CHILD_COUNT = pair_authority.CHILD_COUNT;

pub fn temporalArtifacts(
    view: *const binary_outer.TemporalParentArtifactViewV1,
) [CHILD_COUNT]temporal_nonfri.TemporalChildArtifactV2 {
    var result: [CHILD_COUNT]temporal_nonfri.TemporalChildArtifactV2 =
        undefined;
    for (&result, view.children, view.segment_manifests) |
        *destination,
        child,
        manifest,
    | destination.* = .{
        .manifest = manifest,
        .publication = child.publication,
        .witness = child.recursive_witness,
        .capture = child.capture,
    };
    return result;
}

pub fn clonePlan(
    allocator: std.mem.Allocator,
    source: *const schedule.Plan,
) !schedule.Plan {
    try source.validate();
    const steps = try allocator.dupe(schedule.VerifierStep, source.steps);
    errdefer allocator.free(steps);
    const result = schedule.Plan{
        .allocator = allocator,
        .schema = source.schema,
        .spec = source.spec,
        .protocol_id = source.protocol_id,
        .shape_id = source.shape_id,
        .authority_digest = source.authority_digest,
        .steps = steps,
    };
    try result.validate();
    return result;
}

pub fn plansEqual(left: *const schedule.Plan, right: *const schedule.Plan) bool {
    if (left.schema != right.schema or
        !std.meta.eql(left.spec, right.spec) or
        !std.meta.eql(left.protocol_id, right.protocol_id) or
        !std.meta.eql(left.shape_id, right.shape_id) or
        !std.meta.eql(left.authority_digest, right.authority_digest) or
        left.steps.len != right.steps.len)
    {
        return false;
    }
    for (left.steps, right.steps) |left_step, right_step|
        if (!std.meta.eql(left_step, right_step)) return false;
    return true;
}

pub fn treeColumnCount(
    layout: *const temporal_nonfri.TemporalPrefixCommitmentLayoutV3,
    tree: usize,
) usize {
    return switch (tree) {
        temporal_nonfri.PREFIX_TREE0_INDEX => @intCast(layout.total_preprocessed_columns),
        temporal_nonfri.PREFIX_TREE1_INDEX => @intCast(layout.total_main_columns),
        temporal_nonfri.PREFIX_TREE2_INDEX => @intCast(layout.total_interaction_columns),
        else => 0,
    };
}

pub fn treeOffset(placement: anytype, tree: usize) usize {
    return switch (tree) {
        temporal_nonfri.PREFIX_TREE0_INDEX => @intCast(placement.preprocessed_offset),
        temporal_nonfri.PREFIX_TREE1_INDEX => @intCast(placement.main_offset),
        temporal_nonfri.PREFIX_TREE2_INDEX => @intCast(placement.interaction_offset),
        else => 0,
    };
}

pub fn treeGeometryColumns(placement: anytype, tree: usize) usize {
    return switch (tree) {
        temporal_nonfri.PREFIX_TREE0_INDEX => @intCast(placement.geometry.preprocessed_columns),
        temporal_nonfri.PREFIX_TREE1_INDEX => @intCast(placement.geometry.main_columns),
        temporal_nonfri.PREFIX_TREE2_INDEX => @intCast(placement.geometry.interaction_columns),
        else => 0,
    };
}

pub fn treeCellCount(
    layout: *const temporal_nonfri.TemporalPrefixCommitmentLayoutV3,
    tree: usize,
) !usize {
    if (tree >= temporal_nonfri.PREFIX_TREE_COUNT)
        return error.InvalidTreeStorage;
    var result: usize = 0;
    for (layout.placements) |placement| {
        const cells = std.math.mul(
            usize,
            treeGeometryColumns(placement, tree),
            @as(usize, 1) << @intCast(placement.geometry.log_size),
        ) catch return error.ArithmeticOverflow;
        result = std.math.add(usize, result, cells) catch
            return error.ArithmeticOverflow;
    }
    return result;
}

pub fn baseReceiptIdentity(authority_domain: []const u8, value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(authority_domain);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.padding);
    for (value.trees) |tree| hash.update(&tree.identity);
    return hash.finalResult();
}

pub fn ownerIdentity(authority_domain: []const u8, value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(authority_domain);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.padding);
    for (value.child_prepared_leaf_sha_ids) |identity| hash.update(&identity);
    for (value.child_publication_ids) |identity|
        for (identity) |word| hashInt(&hash, u32, word);
    for (value.segment_manifest_sha_ids) |identity| hash.update(&identity);
    hashInt(&hash, u32, value.shape.max_input_words);
    hashInt(&hash, u32, value.shape.max_output_words);
    for (value.vm_plan.authority_digest) |word| hashInt(&hash, u32, word);
    for (value.recursion_plan.authority_digest) |word|
        hashInt(&hash, u32, word);
    hash.update(&value.public_source.authority_seal);
    hash.update(&value.inactive_source.authority_seal);
    hash.update(&value.inactive_prepared.authority_seal);
    hash.update(&value.transcript_rows.authority_sha_id);
    for (value.rows_10_through_17.authority_id) |word|
        hashInt(&hash, u32, word);
    for (value.custody.custody_id) |word| hashInt(&hash, u32, word);
    hash.update(&value.writer.authority_sha_id);
    return hash.finalResult();
}

pub fn row35Identity(authority_domain: []const u8, value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(authority_domain);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.padding);
    hash.update(&value.prefix_authority_sha_id);
    for (value.statement_source_id) |word| hashInt(&hash, u32, word);
    hash.update(&value.source_authority_sha_id);
    hash.update(&value.provider_snapshot_sha_id);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

pub fn slicesOverlap(left: []const M31, right: []const M31) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_bytes = std.math.mul(
        usize,
        left.len,
        @sizeOf(M31),
    ) catch return true;
    const right_bytes = std.math.mul(
        usize,
        right.len,
        @sizeOf(M31),
    ) catch return true;
    const left_end = std.math.add(
        usize,
        left_start,
        left_bytes,
    ) catch return true;
    const right_end = std.math.add(
        usize,
        right_start,
        right_bytes,
    ) catch return true;
    return left_start < right_end and right_start < left_end;
}

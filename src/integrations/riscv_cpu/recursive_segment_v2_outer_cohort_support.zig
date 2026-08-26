const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const frontend = @import("stwo_riscv_frontend");
const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
const noncore_mod = @import("recursive_segment_v2_noncore_owner.zig");
const core_mod = @import("recursive_fri_outer.zig");

const recursion = frontend.recursion;
const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
const cohort_protocol = recursion.segment_outer_cohort_v2;
const public_native_sum = recursion.segment_public_native_sum_authority_v2;

pub fn coreInputs(
    prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
    transcript_prepared: *const recursion.segment_transcript_outer_source_v2.PreparedV2,
    public_native_sum_source: *const public_native_sum.SourceV2,
    public_native_sum_evaluation: *const public_native_sum.OwnedEvaluationV2,
) core_mod.NativeSegmentCoreAuthorityInputsV2 {
    return .{
        .captured = &prepared.captured_fri,
        .vm_air = &prepared.vm_air,
        .transcript_prepared = transcript_prepared,
        .transcript_program = &prepared.transcript_program,
        .transcript_execution = &prepared.transcript_execution,
        .transcript_plan = &prepared.vm_plan,
        .public_native_sum_source = public_native_sum_source,
        .public_native_sum_evaluation = public_native_sum_evaluation,
        .verifier_plans = .{
            .vm = &prepared.vm_plan,
            .recursion = &prepared.recursion_plan,
        },
        .boundary_layout = &prepared.shared_poseidon_layout,
        .boundary_calls = prepared.row34_boundary_prefix_calls,
    };
}

pub fn generatedEnvelope(
    comptime Generated: type,
    cohort: anytype,
    noncore: noncore_mod.GeneratedInteractionsV2,
    core: core_mod.NativeSegmentCoreGeneratedV2,
) Generated {
    var result = Generated{
        .cohort_id = cohort.authority_id,
        .manifest_seal = cohort.complete_manifest.seal,
        .noncore = noncore,
        .core = core,
        .identity = undefined,
    };
    result.identity = generatedIdentity(&result);
    return result;
}

pub fn generatedIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/segment-v2-outer-generated/v1\x00");
    hashInt(&hash, u16, value.format_version);
    hash.update(&value.padding);
    hash.update(&value.cohort_id);
    hash.update(&value.manifest_seal);
    hash.update(&value.noncore.identity);
    hash.update(&value.core.identity);
    return hash.finalResult();
}

pub fn cohortIdentity(
    cohort: anytype,
    format_version: u16,
    provider_instance_count: usize,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/segment-v2-outer-cohort/v1\x00");
    hashInt(&hash, u16, format_version);
    hash.update(&cohort.prepared_identity);
    hash.update(&cohort.complete_manifest.seal);
    hash.update(&cohort.plan.identity);
    hash.update(&cohort.noncore_authority_id);
    hash.update(&cohort.core_authority_id);
    hashInt(&hash, u32, cohort_protocol.MEASURED_TOTAL_POSEIDON_CALLS);
    hashInt(&hash, u8, provider_instance_count);
    return hash.finalResult();
}

pub fn preflightTree(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: [][]M31,
) !void {
    if (destination.len != treeColumnCount(manifest, tree))
        return error.DestinationShapeMismatch;

    var canonical_contiguous = destination.len != 0;
    var prior_end: usize = 0;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const offset = treeOffset(placement, tree);
        const count = treeGeometryColumns(placement.geometry, tree);
        const expected_rows = @as(usize, 1) <<
            @intCast(placement.geometry.log_size);
        for (destination[offset..][0..count]) |column| {
            if (column.len != expected_rows)
                return error.DestinationShapeMismatch;
            for (column) |value| if (!value.isZero())
                return error.DestinationNotFresh;
            const start = @intFromPtr(column.ptr);
            const bytes = std.math.mul(
                usize,
                column.len,
                @sizeOf(M31),
            ) catch return error.ArithmeticOverflow;
            const end = std.math.add(usize, start, bytes) catch
                return error.ArithmeticOverflow;
            if (prior_end != 0 and start != prior_end)
                canonical_contiguous = false;
            prior_end = end;
        }
    }
    if (canonical_contiguous) return;

    // General caller-owned columns may be separately allocated. The engine's
    // canonical slab takes the linear fast path above; this no-allocation slow
    // path protects arbitrary integrations from overlapping destinations.
    for (destination, 0..) |left, left_index| {
        const left_start = @intFromPtr(left.ptr);
        const left_bytes = std.math.mul(
            usize,
            left.len,
            @sizeOf(M31),
        ) catch return error.ArithmeticOverflow;
        const left_end = std.math.add(usize, left_start, left_bytes) catch
            return error.ArithmeticOverflow;
        for (destination[left_index + 1 ..]) |right| {
            const right_start = @intFromPtr(right.ptr);
            const right_bytes = std.math.mul(
                usize,
                right.len,
                @sizeOf(M31),
            ) catch return error.ArithmeticOverflow;
            const right_end = std.math.add(usize, right_start, right_bytes) catch
                return error.ArithmeticOverflow;
            if (left_start < right_end and right_start < left_end)
                return error.DestinationAlias;
        }
    }
}

pub fn clearTree(destination: [][]M31) void {
    for (destination) |column| @memset(column, M31.zero());
}

fn treeColumnCount(manifest: *const manifest_mod.Manifest, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
    };
}

fn treeOffset(placement: manifest_mod.Placement, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

fn treeGeometryColumns(geometry: manifest_mod.Geometry, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}

pub fn digestWords(value: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index| word.* = std.mem.readInt(
        u32,
        value[index * @sizeOf(u32) ..][0..@sizeOf(u32)],
        .little,
    );
    return result;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

pub fn componentBit(index: anytype) u64 {
    return @as(u64, 1) << @intCast(index);
}

pub fn rangeMask(comptime first: usize, comptime end: usize) u64 {
    var result: u64 = 0;
    inline for (first..end) |index| result |= componentBit(index);
    return result;
}

pub fn allZero(bytes: []const u8) bool {
    var aggregate: u8 = 0;
    for (bytes) |byte| aggregate |= byte;
    return aggregate == 0;
}

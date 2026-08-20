//! Manifest-generic PCS/FRI adapter for the SegmentV2 publication publisher.
//!
//! The append-only 39-row V2 manifest instantiates `AdapterForManifest` at row
//! 38 and uses the exact source-owned geometry below; the generic factory keeps
//! the component equations independent of protocol-version bookkeeping.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;

const air = @import("segment_publication_input_provider_v2.zig");
const binding = @import("segment_publication_input_provider_relation_v2.zig");
const authority = @import("../segment_publication_input_provider_authority_v2.zig");
const framework = @import("framework_interaction.zig");
const segment_manifest = @import("segment_outer_adapter_manifest_v2.zig");
const typed_component = @import("universal_typed_component.zig");
const universal = @import("universal_challenges.zig");

pub const PROPOSED_ROSTER_ROW: u8 = authority.PROPOSED_ROSTER_ROW;
pub const PROPOSED_COMPONENT_COUNT: usize = PROPOSED_ROSTER_ROW + 1;
pub const APPEND_AFTER_ROW: u8 = 37;
pub const HOT_HEAP_ALLOCATIONS: usize = 0;
pub const ROSTER_INTEGRATION_AVAILABLE = true;

const Relation = struct {
    pub const Runtime = binding.Runtime;
};

pub fn AdapterForManifest(comptime manifest_mod: type) type {
    return typed_component.ComponentForManifest(air, Relation, manifest_mod);
}

pub fn initForManifest(
    comptime manifest_mod: type,
    comptime roster_key: manifest_mod.ComponentKey,
    source: *const authority.AuthorityV2,
    prepared: *const authority.PreparedAuthorityV2,
    relations: *const universal.UniversalRelations,
    manifest: *const manifest_mod.Manifest,
) !AdapterForManifest(manifest_mod) {
    try source.validate();
    try prepared.validate();
    if (manifest_mod.keyIndex(roster_key) != PROPOSED_ROSTER_ROW or
        prepared.roster_row != PROPOSED_ROSTER_ROW or
        prepared.trace_log_size != authority.TRACE_LOG_SIZE)
    {
        return error.InvalidProofShape;
    }
    const Adapter = AdapterForManifest(manifest_mod);
    const parameters =
        [_]M31{M31.zero()} ** Adapter.PARAMETER_COLUMN_COUNT;
    return Adapter.init(
        &source.definition,
        source.relation_plan,
        manifest,
        roster_key,
        authority.TRACE_LOG_SIZE,
        parameters,
        relations,
        prepared.claimed_sum,
    );
}

/// Exact source-column installation for one appended placement. Every shape,
/// offset, alias and destination-zero condition is checked before any copy.
pub fn fillTreeInto(
    comptime manifest_mod: type,
    comptime roster_key: manifest_mod.ComponentKey,
    manifest: *const manifest_mod.Manifest,
    traces: authority.TraceV2,
    tree_index: usize,
    destination: [][]M31,
) !void {
    try manifest.validate();
    if (manifest_mod.keyIndex(roster_key) != PROPOSED_ROSTER_ROW)
        return error.InvalidProofShape;
    const placement = try manifest.placement(roster_key);
    const expected = typed_component.manifestGeometryForAir(
        air,
        manifest_mod,
        roster_key,
        authority.TRACE_LOG_SIZE,
    );
    if (!std.meta.eql(placement.geometry, expected))
        return error.InvalidProofShape;
    const expected_columns: usize = switch (tree_index) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => return error.InvalidProofShape,
    };
    if (destination.len != expected_columns)
        return error.InvalidProofShape;

    const sources: []const []M31 = switch (tree_index) {
        manifest_mod.PREPROCESSED_TREE_INDEX => &traces.preprocessed,
        manifest_mod.MAIN_TREE_INDEX => &traces.main,
        manifest_mod.INTERACTION_TREE_INDEX => &traces.interaction,
        else => unreachable,
    };
    const offset: usize = switch (tree_index) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
    const end = std.math.add(usize, offset, sources.len) catch
        return error.InvalidProofShape;
    if (end > destination.len) return error.InvalidProofShape;
    for (sources, destination[offset..end]) |source, target| {
        if (source.len != authority.TRACE_ROW_COUNT or
            target.len != authority.TRACE_ROW_COUNT or
            overlap(std.mem.sliceAsBytes(source), std.mem.sliceAsBytes(target)))
        {
            return error.InvalidProofShape;
        }
        for (target) |word| if (!word.isZero())
            return error.InvalidProofShape;
    }
    for (sources, destination[offset..end]) |source, target|
        installColumn(
            manifest_mod,
            tree_index,
            placement.geometry.log_size,
            source,
            target,
        );
}

/// Main and preprocessed witnesses are produced in logical trace order. The
/// framework interaction writer already emits canonical circle-domain commit
/// order, so applying the permutation to Tree 2 a second time would corrupt
/// its previous-row recurrence.
fn installColumn(
    comptime manifest_mod: type,
    tree_index: usize,
    log_size: u32,
    source: []const M31,
    target: []M31,
) void {
    if (tree_index == manifest_mod.INTERACTION_TREE_INDEX) {
        @memcpy(target, source);
        return;
    }
    for (source, 0..) |value, logical_row|
        target[framework.committedRow(logical_row, log_size)] = value;
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

comptime {
    if (PROPOSED_ROSTER_ROW != 38 or PROPOSED_COMPONENT_COUNT != 39 or
        APPEND_AFTER_ROW + 1 != PROPOSED_ROSTER_ROW or
        air.PREPROCESSED_COLUMN_COUNT != 4 or
        air.PHYSICAL_MAIN_COLUMN_COUNT != 1 or
        air.INTERACTION_COLUMN_COUNT != 4 or HOT_HEAP_ALLOCATIONS != 0 or
        !ROSTER_INTEGRATION_AVAILABLE)
    {
        @compileError("publication-input provider adapter contract drifted");
    }
}

test "publication provider installs logical and interaction orders exactly once" {
    const log_size: u32 = 3;
    const size: usize = 1 << log_size;
    var source: [size]M31 = undefined;
    for (&source, 0..) |*value, index|
        value.* = M31.fromCanonical(@intCast(index + 1));

    var main = [_]M31{M31.zero()} ** size;
    installColumn(
        segment_manifest,
        segment_manifest.MAIN_TREE_INDEX,
        log_size,
        &source,
        &main,
    );
    var observed_nontrivial_scatter = false;
    for (source, 0..) |value, logical_row| {
        const committed = framework.committedRow(logical_row, log_size);
        observed_nontrivial_scatter = observed_nontrivial_scatter or
            committed != logical_row;
        try std.testing.expect(main[committed].eql(value));
    }
    try std.testing.expect(observed_nontrivial_scatter);

    var preprocessed = [_]M31{M31.zero()} ** size;
    installColumn(
        segment_manifest,
        segment_manifest.PREPROCESSED_TREE_INDEX,
        log_size,
        &source,
        &preprocessed,
    );
    try std.testing.expectEqualDeep(main, preprocessed);

    var interaction = [_]M31{M31.zero()} ** size;
    installColumn(
        segment_manifest,
        segment_manifest.INTERACTION_TREE_INDEX,
        log_size,
        &source,
        &interaction,
    );
    try std.testing.expectEqualDeep(source, interaction);
}

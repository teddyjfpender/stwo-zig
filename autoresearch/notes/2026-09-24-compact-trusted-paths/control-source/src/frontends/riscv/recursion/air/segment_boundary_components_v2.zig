//! Concrete typed-component adapters for the two V2 boundary sources.
//!
//! These adapters reuse the universal evaluator against the versioned
//! 38-component manifest. They add no equations and perform no hot-path
//! allocation: the statement and public-LogUp programs, relation plans,
//! traces, and claims all come from `segment_leaf_outer_authority_v2`.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;

const air_v2 = @import("../segment_leaf_outer_air_v2.zig");
const authority_v2 = @import("../segment_leaf_outer_authority_v2.zig");
const manifest_v2 = @import("segment_outer_adapter_manifest_v2.zig");
const typed_component = @import("universal_typed_component.zig");
const universal = @import("universal_challenges.zig");

const StatementRelation = struct {
    pub const Runtime = air_v2.Statement.Runtime;
};

const PublicLogUpRelation = struct {
    pub const Runtime = air_v2.PublicLogUp.Runtime;
};

pub const StatementAdapter = typed_component.ComponentForManifest(
    air_v2.Statement,
    StatementRelation,
    manifest_v2,
);

pub const PublicLogUpAdapter = typed_component.ComponentForManifest(
    air_v2.PublicLogUp,
    PublicLogUpRelation,
    manifest_v2,
);

pub const HOT_HEAP_ALLOCATIONS: usize = 0;
pub const SOURCE_COMPONENT_COUNT: usize = 2;
pub const PRODUCTION_ACTIVATION = false;

pub const Error = error{
    BoundaryManifestMismatch,
    InvalidTraceShape,
};

/// Stable-address concrete component owners. `AuthorityV2`, `relations`, and
/// the manifest must outlive this value and the complete prove/verify call.
pub const Components = struct {
    statement: StatementAdapter,
    public_logup: PublicLogUpAdapter,

    pub fn init(
        authority: *const authority_v2.AuthorityV2,
        prepared: *const authority_v2.PreparedNativeVerifierOuterAuthorityV2,
        relations: *const universal.UniversalRelations,
        manifest: *const manifest_v2.Manifest,
    ) !Components {
        try authority.validate();
        try prepared.validate();
        try relations.validate();
        try manifest.validate();
        if (!std.meta.eql(
            manifest.boundary_manifest_id,
            prepared.manifest.identity,
        ) or !std.mem.eql(
            u8,
            &manifest.boundary_authority_sha_id,
            &prepared.manifest.authority_sha_id,
        )) {
            return error.BoundaryManifestMismatch;
        }

        const statement_log = prepared.manifest.components[0].trace_log_size;
        const public_logup_log = prepared.manifest.components[1].trace_log_size;
        const statement_parameters =
            [_]M31{M31.zero()} ** StatementAdapter.PARAMETER_COLUMN_COUNT;
        const public_logup_parameters =
            [_]M31{M31.zero()} ** PublicLogUpAdapter.PARAMETER_COLUMN_COUNT;
        return .{
            .statement = try StatementAdapter.init(
                &authority.statement_definition,
                authority.statement_plan,
                manifest,
                .statement_source_v2,
                statement_log,
                statement_parameters,
                relations,
                prepared.statement_claim,
            ),
            .public_logup = try PublicLogUpAdapter.init(
                &authority.public_logup_definition,
                authority.public_logup_plan,
                manifest,
                .public_logup_source_v2,
                public_logup_log,
                public_logup_parameters,
                relations,
                prepared.public_logup_claim,
            ),
        };
    }

    /// Appends indices 36 and 37 after the universal roster. The gate's exact
    /// order check rejects an early, reversed, duplicated, or omitted source.
    pub fn appendToGate(
        self: *const Components,
        manifest: *const manifest_v2.Manifest,
        gate: *manifest_v2.ProofGate,
    ) !void {
        try gate.append(manifest, try self.statement.binding(manifest));
        try gate.append(manifest, try self.public_logup.binding(manifest));
    }
};

/// Exact source-column installation into a caller-owned global committed
/// tree. Every destination shape and zero precondition is checked before the
/// first write, so a rejected publication leaves the complete tree unchanged.
pub fn fillTreeInto(
    manifest: *const manifest_v2.Manifest,
    traces: authority_v2.TracesV2,
    tree_index: usize,
    destination: [][]M31,
) !void {
    try manifest.validate();
    const expected_columns: usize = switch (tree_index) {
        manifest_v2.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_v2.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_v2.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => return error.InvalidTraceShape,
    };
    if (destination.len != expected_columns)
        return error.InvalidTraceShape;

    const statement = try manifest.placement(.statement_source_v2);
    const public_logup = try manifest.placement(.public_logup_source_v2);
    // Keep the descriptor arrays borrowed from `traces` for the complete
    // preflight-and-copy transaction. Returning `&trace.preprocessed` from a
    // by-value helper would instead return a slice into that helper's expired
    // local copy, which is observably dangling under ReleaseFast.
    const statement_sources = sourceColumns(&traces.statement, tree_index);
    const public_sources = sourceColumns(&traces.public_logup, tree_index);
    const statement_offset: usize = switch (tree_index) {
        manifest_v2.PREPROCESSED_TREE_INDEX => statement.preprocessed_offset,
        manifest_v2.MAIN_TREE_INDEX => statement.main_offset,
        manifest_v2.INTERACTION_TREE_INDEX => statement.interaction_offset,
        else => unreachable,
    };
    const public_offset: usize = switch (tree_index) {
        manifest_v2.PREPROCESSED_TREE_INDEX => public_logup.preprocessed_offset,
        manifest_v2.MAIN_TREE_INDEX => public_logup.main_offset,
        manifest_v2.INTERACTION_TREE_INDEX => public_logup.interaction_offset,
        else => unreachable,
    };

    try preflightColumns(
        destination,
        statement_offset,
        statement_sources,
        statement.geometry,
        tree_index,
    );
    try preflightColumns(
        destination,
        public_offset,
        public_sources,
        public_logup.geometry,
        tree_index,
    );
    copyColumns(destination, statement_offset, statement_sources);
    copyColumns(destination, public_offset, public_sources);
}

fn sourceColumns(trace: anytype, tree_index: usize) []const []M31 {
    comptime {
        switch (@typeInfo(@TypeOf(trace))) {
            .pointer => {},
            else => @compileError("boundary trace descriptors must be borrowed"),
        }
    }
    return switch (tree_index) {
        manifest_v2.PREPROCESSED_TREE_INDEX => &trace.preprocessed,
        manifest_v2.MAIN_TREE_INDEX => &trace.main,
        manifest_v2.INTERACTION_TREE_INDEX => &trace.interaction,
        else => unreachable,
    };
}

fn preflightColumns(
    destination: [][]M31,
    offset: usize,
    sources: []const []M31,
    geometry: manifest_v2.Geometry,
    tree_index: usize,
) !void {
    const expected_count: usize = switch (tree_index) {
        manifest_v2.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_v2.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_v2.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => return error.InvalidTraceShape,
    };
    if (geometry.log_size >= @bitSizeOf(usize) or
        sources.len != expected_count)
    {
        return error.InvalidTraceShape;
    }
    const expected_rows = @as(usize, 1) << @intCast(geometry.log_size);
    const end = std.math.add(usize, offset, sources.len) catch
        return error.InvalidTraceShape;
    if (end > destination.len)
        return error.InvalidTraceShape;
    for (sources, destination[offset..end]) |source, target| {
        if (source.len != expected_rows or target.len != expected_rows or overlap(
            std.mem.sliceAsBytes(source),
            std.mem.sliceAsBytes(target),
        )) {
            return error.InvalidTraceShape;
        }
        for (target) |value| if (!value.isZero())
            return error.InvalidTraceShape;
    }
}

fn copyColumns(
    destination: [][]M31,
    offset: usize,
    sources: []const []M31,
) void {
    for (sources, destination[offset .. offset + sources.len]) |source, target|
        @memcpy(target, source);
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0)
        return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch
        return true;
    const right_end = std.math.add(usize, right_start, right.len) catch
        return true;
    return left_start < right_end and right_start < left_end;
}

comptime {
    if (StatementAdapter.PARAMETER_COLUMN_COUNT != 0 or
        PublicLogUpAdapter.PARAMETER_COLUMN_COUNT != 0 or
        SOURCE_COMPONENT_COUNT != manifest_v2.SOURCE_COMPONENT_COUNT)
    {
        @compileError("V2 boundary component ABI drifted");
    }
}

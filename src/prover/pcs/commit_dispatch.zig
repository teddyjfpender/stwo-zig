//! Optional commitment fast paths kept outside the size-bounded scheme driver.

const std = @import("std");
const work_profile = @import("stwo_prover_api").work_profile;
const column_preparation = @import("columns/preparation.zig");
const column_storage = @import("columns/storage.zig");
const commitment_tree = @import("commitment_tree.zig");

pub fn commitConstant(
    comptime B: type,
    comptime H: type,
    scheme: anytype,
    allocator: std.mem.Allocator,
    owned_columns: []commitment_tree.ColumnEvaluation,
    work_recorder: ?*work_profile.Recorder(true),
    channel: anytype,
) !void {
    const BackendCommitmentTree = commitment_tree.CommitmentTreeProverForBackend(B, H);
    errdefer column_storage.freeOwnedColumnEvaluations(allocator, owned_columns);
    var prepared = try column_preparation.prepareConstantColumnsForCommitOwned(
        allocator,
        owned_columns,
        scheme.config.fri_config.log_blowup_factor,
        scheme.coefficient_retention_policy,
    );
    errdefer prepared.deinit(allocator);
    var tree = try BackendCommitmentTree.initOwnedWithBackingAndWorkRecorder(
        allocator,
        prepared.columns,
        prepared.coefficients,
        null,
        null,
        work_recorder,
    );
    errdefer tree.deinit(allocator);
    return scheme.appendCommittedTree(allocator, tree, channel);
}

pub fn tryPrecommitted(
    comptime B: type,
    comptime H: type,
    allocator: std.mem.Allocator,
    owned_columns: []commitment_tree.ColumnEvaluation,
    log_blowup_factor: u32,
    retention_policy: anytype,
    twiddle_source: anytype,
    source_backing_buffers: ?[][]@import("stwo_core").fields.m31.M31,
    source: @import("column_source.zig").ColumnSource,
    work_recorder: ?*work_profile.Recorder(true),
) !?commitment_tree.CommitmentTreeProverForBackend(B, H) {
    if (comptime !@hasDecl(B, "prepareAndCommitOwned")) return null;
    // Until the specialized transaction returns its own exact work delta, the
    // attempt is non-publishable even when the hook eventually declines. A
    // backend may inspect, stage, or dispatch before returning null; marking
    // only the adopted result would silently omit that executed work.
    if (work_recorder) |active| active.markIncomplete();
    // The public commit contract owns `owned_columns` on every error.  A
    // backend returns `null` without consuming them, but an allocation error
    // cannot fall through to the generic path and must release them here.
    errdefer if (source_backing_buffers) |buffers| {
        allocator.free(owned_columns);
        for (buffers) |buffer| allocator.free(buffer);
        allocator.free(buffers);
    } else column_storage.freeOwnedColumnEvaluations(allocator, owned_columns);
    const prepared = (try B.prepareAndCommitOwned(
        H,
        allocator,
        owned_columns,
        log_blowup_factor,
        retention_policy,
        twiddle_source,
        source_backing_buffers,
        source,
    )) orelse return null;
    const backing_teardown = if (comptime @hasField(@TypeOf(prepared), "backing_teardown"))
        prepared.backing_teardown
    else
        null;
    return commitment_tree.CommitmentTreeProverForBackend(B, H).initPrecommittedWithTeardown(
        prepared.columns,
        prepared.coefficients,
        prepared.column_backing_buffers,
        prepared.coefficient_backing_buffers,
        prepared.commitment,
        backing_teardown,
    );
}

pub fn tryPrecommittedPolys(
    comptime B: type,
    comptime H: type,
    allocator: std.mem.Allocator,
    polys: []const @import("../poly/circle/mod.zig").CircleCoefficients,
    log_blowup_factor: u32,
    retention_policy: anytype,
    twiddle_source: anytype,
    work_recorder: ?*work_profile.Recorder(true),
) !?commitment_tree.CommitmentTreeProverForBackend(B, H) {
    if (comptime !@hasDecl(B, "prepareAndCommitPolys")) return null;
    // See `tryPrecommitted`: a declined specialized attempt is still executed
    // work and therefore cannot be represented by the generic fallback's
    // counters alone.
    if (work_recorder) |active| active.markIncomplete();
    const prepared = (try B.prepareAndCommitPolys(
        H,
        allocator,
        polys,
        log_blowup_factor,
        retention_policy,
        twiddle_source,
    )) orelse return null;
    const backing_teardown = if (comptime @hasField(@TypeOf(prepared), "backing_teardown"))
        prepared.backing_teardown
    else
        null;
    return commitment_tree.CommitmentTreeProverForBackend(B, H).initPrecommittedWithTeardown(
        prepared.columns,
        prepared.coefficients,
        prepared.column_backing_buffers,
        prepared.coefficient_backing_buffers,
        prepared.commitment,
        backing_teardown,
    );
}

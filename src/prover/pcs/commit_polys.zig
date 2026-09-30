//! Coefficient-form polynomial commitment orchestration.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const stage_profile = @import("stwo_prover_api").stage_profile;
const prover_circle = @import("../poly/circle/mod.zig");
const circle_transforms = @import("columns/circle_transforms.zig");
const column_storage = @import("columns/storage.zig");
const commit_dispatch = @import("commit_dispatch.zig");
const tiled_commit = @import("tiled_commit.zig");

/// Whether `polys` fit `tiled_commit` (as coefficient columns).
fn tiledPolys(polys: []const prover_circle.CircleCoefficients, log_blowup: u32, compact_min_log: u32) bool {
    if (polys.len == 0) return false;
    var any_large = false;
    for (polys) |poly| {
        if (poly.log_size == 0) return false;
        if (poly.log_size + log_blowup >= compact_min_log) any_large = true;
    }
    return any_large;
}

pub fn commit(
    comptime B: type,
    comptime H: type,
    comptime BackendCommitmentTree: type,
    self: anytype,
    allocator: std.mem.Allocator,
    polys: []const prover_circle.CircleCoefficients,
    recorder: ?*stage_profile.Recorder,
    channel: anytype,
) !void {
    var timing: ?std.time.Timer = if (std.process.hasEnvVarConstant("STWO_ZIG_PCS_TIMING"))
        std.time.Timer.start() catch null
    else
        null;
    const blowup = self.config.fri_config.log_blowup_factor;
    const work_recorder = if (recorder) |active|
        active.workCaptureRecorder()
    else
        null;
    if (self.retained_column_allocator != null and self.coefficient_retention_policy != .never)
        return error.UnsupportedRetainedColumnStorage;
    const native_compact = comptime if (@hasDecl(B, "supportsCompactStreaming")) B.supportsCompactStreaming(H) else false;
    // Compact storage on a host tree: commit tile by tile from the
    // coefficients (`tiled_commit`), never holding every column's extension
    // or the Merkle layers compaction drops. Same tree, same root.
    if (comptime !native_compact and tiled_commit.hostTree(B, H)) {
        if (self.compact_polynomial_storage and self.retained_column_allocator == null and
            tiledPolys(polys, blowup, self.compact_polynomial_min_log_size))
        {
            const columns = try allocator.alloc(@import("commitment_tree.zig").ColumnEvaluation, polys.len);
            var filled: usize = 0;
            defer if (filled != polys.len) {
                for (columns[0..filled]) |column| allocator.free(column.values);
                allocator.free(columns);
            };
            for (polys, columns) |poly, *column| {
                column.* = .{ .log_size = poly.log_size, .values = try allocator.dupe(M31, poly.coefficients()) };
                filled += 1;
            }
            // Consumes `columns` on success and on error.
            try tiled_commit.commit(B, H, self, allocator, columns, .owned_coefficients, .{}, channel);
            if (timing) |*clock| std.log.info("pcs coefficient commit: path=tiled columns={} total_ns={}", .{ polys.len, clock.read() });
            return;
        }
    }
    if (self.retained_column_allocator == null and !(native_compact and self.compact_polynomial_storage)) {
        if (try commit_dispatch.tryPrecommittedPolys(
            B,
            H,
            allocator,
            polys,
            blowup,
            self.coefficient_retention_policy,
            &self.twiddle_source,
            work_recorder,
        )) |committed| {
            var tree = committed;
            errdefer tree.deinit(allocator);
            try self.appendCommittedTree(allocator, tree, channel);
            if (timing) |*clock| std.log.info("pcs coefficient commit: path=backend_precommitted columns={} total_ns={} includes_append_join=true", .{ polys.len, clock.read() });
            return;
        }
    }
    if (work_recorder) |work| try work.expectProducer(.polynomial_commit_forward_fft);
    // work-profile-plan:polynomial-commit-forward-fft
    const extension_start_ns = if (timing) |*clock| clock.read() else 0;
    var columns = try circle_transforms.extendCoefficientColumnsByGroupForBackend(
        B,
        allocator,
        polys,
        blowup,
        &self.twiddle_source,
        work_recorder,
        .polynomial_commit_forward_fft,
    );
    const extension_end_ns = if (timing) |*clock| clock.read() else 0;
    if (self.retained_column_allocator) |retained_allocator|
        columns = try @import("commitment_tree.zig").relocateOwnedColumns(allocator, retained_allocator, columns);
    var columns_owned = true;
    errdefer if (columns_owned) @import("commitment_tree.zig").freeRetainedColumns(allocator, self.retained_column_allocator orelse allocator, columns);
    // work-profile-complete:polynomial-commit-forward-fft

    var stored_coefficients: ?[]prover_circle.CircleCoefficients = null;
    errdefer if (columns_owned) if (stored_coefficients) |coefficients|
        column_storage.deinitOwnedCoefficientColumns(allocator, coefficients);
    if (column_storage.shouldRetainPolynomialCoefficients(polys, self.coefficient_retention_policy)) {
        const coeffs = try allocator.alloc(prover_circle.CircleCoefficients, polys.len);
        var initialized_coeffs: usize = 0;
        errdefer {
            for (coeffs[0..initialized_coeffs]) |*coeff| coeff.deinit(allocator);
            allocator.free(coeffs);
        }
        for (polys, 0..) |poly, index| {
            coeffs[index] = try prover_circle.CircleCoefficients.initOwned(
                try allocator.dupe(M31, poly.coefficients()),
            );
            initialized_coeffs += 1;
        }
        stored_coefficients = coeffs;
    }

    if (native_compact and self.compact_polynomial_storage) {
        // Coefficient commitments enter after interpolation, so keep that basis
        // and hash their GPU extensions directly. No resident tree may borrow
        // an LDE that compaction is about to retire.
        columns_owned = false;
        return commitNativeCompact(B, H, BackendCommitmentTree, self, allocator, columns, stored_coefficients, channel);
    }

    if (work_recorder) |work| try work.expectProducer(.commitment_tree_merkle);
    var column_payload_bytes: u128 = 0;
    var coefficient_payload_bytes: u128 = 0;
    if (timing != null) {
        for (columns) |column| column_payload_bytes += @as(u128, column.values.len) * @sizeOf(M31);
        if (stored_coefficients) |coefficients| for (coefficients) |coefficient| {
            coefficient_payload_bytes += @as(u128, coefficient.coefficients().len) * @sizeOf(M31);
        };
    }
    const merkle_start_ns = if (timing) |*clock| clock.read() else 0;
    // work-profile-plan:commitment-tree-merkle
    var tree = try BackendCommitmentTree.initOwnedWithBackingAndWorkRecorder(
        allocator,
        columns,
        stored_coefficients,
        null,
        null,
        work_recorder,
    );
    columns_owned = false;
    tree.retained_column_allocator = self.retained_column_allocator;
    errdefer tree.deinit(allocator);
    const merkle_end_ns = if (timing) |*clock| clock.read() else 0;
    try self.appendCommittedTree(allocator, tree, channel);
    if (timing) |*clock| std.log.info("pcs coefficient commit: path=expanded columns={} setup_ns={} extension_ns={} retention_ns={} merkle_ns={} append_join_ns={} column_payload_bytes={} coefficient_payload_bytes={} payload_is_allocator_live=false", .{
        polys.len, extension_start_ns, extension_end_ns - extension_start_ns, merkle_start_ns - extension_end_ns, merkle_end_ns - merkle_start_ns, clock.read() - merkle_end_ns, column_payload_bytes, coefficient_payload_bytes,
    });
}

fn commitNativeCompact(comptime B: type, comptime H: type, comptime BackendTree: type, scheme: anytype, a: std.mem.Allocator, columns: []@import("commitment_tree.zig").ColumnEvaluation, coefficients: ?[]prover_circle.CircleCoefficients, channel: anytype) !void {
    const Host = @import("commitment_tree.zig").CommitmentTreeProver(H);
    var host = Host{ .columns = columns, .coefficients = coefficients, .commitment = .{ .layers = &.{}, .layer_allocator = a } };
    errdefer host.deinit(a);
    var committer = B.CompactStreamingCommitter(H).init(a);
    var owns_committer = true;
    defer if (owns_committer) committer.deinit();
    if (comptime @hasDecl(B.CompactStreamingCommitter(H), "planColumnCount"))
        try committer.planColumnCount(columns.len);
    const values = try a.alloc([]const M31, columns.len);
    defer a.free(values);
    for (columns, values) |column, *value| value.* = column.values;
    const Tree = @import("../vcs_lifted/prover.zig").MerkleProverLifted(H);
    const sorted = try Tree.sortColumnsByLogSizeAsc(a, values);
    defer a.free(sorted);
    try committer.addColumns(sorted);
    host.commitment = try committer.finalize();
    owns_committer = false;
    try host.compactPolynomialStorage(a, scheme.compact_polynomial_min_log_size);
    const tree = BackendTree{
        .columns = host.columns,
        .coefficients = host.coefficients,
        .compact_polynomials = true,
        .commitment = B.adoptNativeStreamingMerkle(H, host.commitment),
    };
    try scheme.appendCommittedTree(a, tree, channel);
}

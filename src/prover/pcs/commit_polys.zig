//! Coefficient-form polynomial commitment orchestration.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const stage_profile = @import("stwo_prover_api").stage_profile;
const prover_circle = @import("../poly/circle/mod.zig");
const circle_transforms = @import("columns/circle_transforms.zig");
const column_storage = @import("columns/storage.zig");
const commit_dispatch = @import("commit_dispatch.zig");

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
    if (self.retained_column_allocator == null) {
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
    if (column_storage.shouldRetainPolynomialCoefficients(polys, self.coefficient_retention_policy)) {
        const coeffs = try allocator.alloc(prover_circle.CircleCoefficients, polys.len);
        errdefer allocator.free(coeffs);
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

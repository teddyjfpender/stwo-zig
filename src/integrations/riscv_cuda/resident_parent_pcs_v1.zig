//! Original execution-parent PCS plans and actual resident BLAKE3 commitment
//! dispatch. The circuit CUDA implementation supplies only numerical kernels;
//! every column, mask and transcript shape comes from ParentProgram.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const B3 = cuda.runtime.stages.blake3;
const ABI = cuda.abi.stages.blake3;
const Program = @import("resident_parent_program_v1.zig");
const Geometry = @import("../circuit_cuda/geometry.zig");
pub const Commit = @import("../circuit_cuda/resident_commit.zig");
pub const Oods = @import("../circuit_cuda/resident_oods.zig");
pub const Quotient = @import("../circuit_cuda/resident_quotient.zig");
pub const Fri = @import("../circuit_cuda/resident_fri.zig");
pub const Decommit = @import("../circuit_cuda/resident_decommit.zig");
pub const ProofLayout = @import("../circuit_cuda/resident_proof_layout.zig");
const Topology = @import("stwo_cairo_cuda_integration").executor.quotient.types.Topology;

/// Representation adapter only: common.Hashes is the hash-agnostic 32-byte
/// opening/arena view. No Blake2s state, transcript, or kernel is used here.
/// Deliberately omit mixedPrefix: the old builder's optional progressive state
/// is Blake2s-specific. BLAKE3 mixed leaves execute the complete original message.
pub const Blake3Commitment = struct {
    pub fn contiguousLeaves(session: anytype, stage: cuda.runtime.telemetry.Stage, size: u32, columns: common.WordMatrix, output: common.Hashes) !void {
        try B3.Native.contiguousLeaves(session, stage, size, columns, try output.cast(ABI.Hash));
    }
    pub fn mixedLeaves(session: anytype, stage: cuda.runtime.telemetry.Stage, size: u32, segments: anytype, output: common.Hashes) !void {
        try B3.Native.mixedLeaves(session, stage, size, segments, try output.cast(ABI.Hash));
    }
    pub fn layer(session: anytype, stage: cuda.runtime.telemetry.Stage, previous: common.Hashes, output: common.Hashes, append_columns: bool) !void {
        if (append_columns) return error.InvalidKernelDescriptor;
        try B3.Native.reduceNodes(session, stage, try previous.cast(ABI.Hash), try output.cast(ABI.Hash));
    }
    pub fn contiguousTail(session: anytype, stage: cuda.runtime.telemetry.Stage, previous: common.Hashes, output: common.Hashes, levels: u32) !void {
        try B3.Native.contiguousTail(session, stage, try previous.cast(ABI.Hash), try output.cast(ABI.Hash), levels);
    }
    pub fn friLeaves(session: anytype, coordinates: common.WordMatrix, size: u32, log_rows_per_leaf: u32, output: common.Hashes) !void {
        try B3.Native.friLeaves(session, coordinates, size, log_rows_per_leaf, try output.cast(ABI.Hash));
    }
};
pub const CommitOps = struct {
    pub const Transform = @import("resident_parent_transform_v1.zig");
    pub const Commitment = Blake3Commitment;
};
pub fn commit(bound: *Commit.Bound, session: anytype) !void {
    try bound.executeWith(CommitOps, session);
}
pub fn commitEvaluations(bound: *Commit.Bound, session: anytype, columns: []const common.Words) !void {
    try bound.loadEvaluations(session, columns);
    try commit(bound, session);
}

pub const Plans = struct {
    allocator: std.mem.Allocator,
    geometry: Geometry.Geometry,
    commitments: [4]Commit.Plan,
    oods: Oods.Plan,
    quotient: Topology,
    owns_quotient: bool = true,
    fri: Fri.Plan,
    decommit: Decommit.Plan,
    proof_layout: ProofLayout.Layout,
    /// All polynomial, Merkle and numerical plan scratch below is accounted
    /// separately from witness/interaction/composition/transcript device storage.
    numerical_bytes_lower_bound: usize,

    pub fn init(a: std.mem.Allocator, program: *const Program.Owned, maximum_bytes: usize) !Plans {
        const p = program.view();
        var geometry: Geometry.Geometry = .{ .allocator = a, .trees = undefined, .fri_layers = try a.alloc(Geometry.FriLayer, p.fri_layers.len), .composition_evaluation_log = p.composition_log, .fri_input_log = p.fri_log, .identity = p.identity };
        errdefer a.free(geometry.fri_layers);
        // Column arrays remain borrowed from the immutable Program until this
        // Plans owner is destroyed. We do not call Geometry.deinit on borrows.
        for (p.trees, &geometry.trees, 0..) |tree, *out, i| out.* = .{ .role = @enumFromInt(i), .column_logs = tree.column_logs, .lifted_log = tree.lifted_log };
        for (p.fri_layers, geometry.fri_layers) |layer, *out| out.* = .{ .evaluation_log = layer.evaluation_log, .fold_step = layer.fold_step, .cumulative_fold = layer.cumulative_fold, .leaf_log = layer.leaf_log };
        var commitments: [4]Commit.Plan = undefined;
        var ready: usize = 0;
        errdefer for (commitments[0..ready]) |*item| item.deinit();
        for (geometry.trees, &commitments) |tree, *out| {
            out.* = try Commit.Plan.init(a, tree, p.admission.key.config.fri_config.log_blowup_factor);
            ready += 1;
        }
        var column_count: usize = 0;
        for (p.trees) |tree| column_count = try std.math.add(usize, column_count, tree.masks.len);
        const offsets = try a.alloc([]const i32, column_count);
        defer a.free(offsets);
        var cursor: usize = 0;
        for (p.trees) |tree| for (tree.masks) |*mask| {
            offsets[cursor] = mask.offsets[0..mask.count];
            cursor += 1;
        };
        const config = p.admission.key.config;
        const blowup = config.fri_config.log_blowup_factor;
        var oods = try Oods.Plan.initForOffsets(a, &geometry, offsets, blowup, p.mask_log);
        errdefer oods.deinit();
        var quotient = try Quotient.deriveForOffsets(a, &geometry, &oods, blowup, offsets, p.mask_log);
        errdefer quotient.deinit();
        var fri = try Fri.Plan.init(a, &geometry, config, @as(usize, 1) << @intCast(@max(p.fri_log, p.composition_log) - 1));
        errdefer fri.deinit();
        var decommit = try Decommit.Plan.init(a, &geometry, config);
        errdefer decommit.deinit();
        var layout = try ProofLayout.Layout.init(a, &geometry, &oods, config);
        errdefer layout.deinit(a);
        var bytes = p.polynomial_bytes;
        // QM31 factors/reduction and native-height quotient partials. Other
        // controller allocations are explicitly still required in arena plan.
        bytes = try std.math.add(usize, bytes, try std.math.mul(usize, 16, try std.math.add(usize, oods.factor_count, try std.math.mul(usize, 2, oods.scratch_count))));
        bytes = try std.math.add(usize, bytes, try std.math.mul(usize, 16, @intCast(quotient.partial_offsets[quotient.partial_offsets.len - 1])));
        if (bytes > maximum_bytes) return error.ResidentParentResourceLimit;
        return .{ .allocator = a, .geometry = geometry, .commitments = commitments, .oods = oods, .quotient = quotient, .fri = fri, .decommit = decommit, .proof_layout = layout, .numerical_bytes_lower_bound = bytes };
    }
    pub fn takeQuotient(self: *Plans) !Topology {
        if (!self.owns_quotient) return error.InvalidResidentParentGeometry;
        self.owns_quotient = false;
        return self.quotient;
    }
    pub fn deinit(self: *Plans) void {
        self.proof_layout.deinit(self.allocator);
        self.decommit.deinit();
        self.fri.deinit();
        if (self.owns_quotient) self.quotient.deinit();
        self.oods.deinit();
        for (&self.commitments) |*p| p.deinit();
        self.allocator.free(self.geometry.fri_layers);
        self.* = undefined;
    }
};

test "resident parent numerical plans retain original masks and bounded source topology" {
    const a = std.testing.allocator;
    const program = try Program.Owned.derive(a, try Program.fixtureAdmission(), .{});
    defer program.deinit();
    var plans = try Plans.init(a, program, 96 << 30);
    defer plans.deinit();
    const p = program.view();
    try std.testing.expectEqual(p.trees[0].column_logs.len, plans.commitments[0].column_logs.len);
    try std.testing.expectEqual(plans.oods.sources.len, plans.quotient.sampled_value_count);
    try std.testing.expectEqual(@as(usize, 4), plans.quotient.source_trees.len);
    var samples: usize = 0;
    for (p.trees) |tree| for (tree.masks) |mask| {
        samples += mask.count;
    };
    try std.testing.expectEqual(samples, plans.proof_layout.sample_total);
    // Original fold-one FRI has one row per leaf. Keep commitment allocation,
    // opening records and terminal decoder on precisely the same geometry.
    try std.testing.expectEqual(@as(u32, 1), p.admission.key.config.fri_config.fold_step);
    for (p.fri_layers, plans.fri.layers, plans.decommit.topology.fri_openings, plans.proof_layout.fri_trees) |source, layer, opening, encoded| {
        try std.testing.expectEqual(source.evaluation_log, source.leaf_log);
        try std.testing.expectEqual(@as(u32, 0), layer.log_rows_per_leaf);
        try std.testing.expectEqual(@as(usize, source.evaluation_log + 1), layer.merkle_count);
        try std.testing.expectEqual(@as(u32, 0), opening.log_rows_per_leaf);
        try std.testing.expectEqual(@as(u32, 0), encoded.log_rows_per_leaf);
    }
    var packed_config = p.admission.key.config;
    packed_config.fri_config.fold_step = 4;
    packed_config.fri_config.log_last_layer_degree_bound = 0;
    packed_config.fri_config.log_blowup_factor = 1;
    var packed_layers = [_]Geometry.FriLayer{
        .{ .evaluation_log = 9, .fold_step = 4, .cumulative_fold = 0, .leaf_log = 7 },
        .{ .evaluation_log = 5, .fold_step = 4, .cumulative_fold = 4, .leaf_log = 3 },
    };
    const packed_geometry = .{ .fri_input_log = @as(u32, 9), .fri_layers = packed_layers[0..] };
    var packed_plan = try Fri.Plan.init(a, packed_geometry, packed_config, 256);
    defer packed_plan.deinit();
    for (packed_plan.layers) |layer| try std.testing.expectEqual(@as(u32, 2), layer.log_rows_per_leaf);
    packed_layers[0].leaf_log = 9;
    try std.testing.expectError(error.InvalidCircuitFriGeometry, Fri.Plan.init(a, packed_geometry, packed_config, 256));
    try std.testing.expectError(error.ResidentParentResourceLimit, Plans.init(a, program, 1));
}

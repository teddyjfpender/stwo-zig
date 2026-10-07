//! Focused fixed-column parity helpers for the real q193 recursion diagnostic.
const std = @import("std");
const recursion = @import("stwo_riscv_frontend").recursion;
const M31 = @import("stwo_core").fields.m31.M31;

/// Test-only nonconstant challenge draw bound to the independently pinned
/// native key and Tree0. The production wrapper must draw after committing
/// its own complete physical Tree0 and main roots instead.
pub fn diagnosticRelations(
    allocator: std.mem.Allocator,
    pinned_key_id: [32]u8,
    pinned_tree0: [8]u32,
) !recursion.air.universal_challenges.UniversalRelations {
    var channel = recursion.poseidon2_channel.Channel{};
    channel.mixU32s(&.{0x5235_3044}); // R50D: diagnostic only.
    var key_limbs: [16]u32 = undefined;
    for (&key_limbs, 0..) |*limb, index|
        limb.* = std.mem.readInt(u16, pinned_key_id[index * 2 ..][0..2], .little);
    channel.mixU32s(&key_limbs);
    channel.mixU32s(&pinned_tree0);
    return recursion.air.universal_challenges.UniversalRelations.draw(allocator, &channel);
}

pub fn checkV12SelectedFixedWire(
    allocator: std.mem.Allocator,
    verified: anytype,
    selected_core: *const recursion.air.segment_leaf_wrapper_template_v6.CoreProfileV6,
    pinned_tree0: [8]u32,
) !void {
    // Exact q193 fixture geometry, selected before native proof inspection.
    // The larger SegmentProfileV1 wire (871 columns) is a different key.
    const dimensions = recursion.fixed_wire.Dimensions{
        .commitment_count = 4,
        .claimed_sum_count = 28,
        .sampled_value_count = 754,
        .queried_value_count = 654 * recursion.protocol.FRI_QUERY_COUNT,
        .trace_path_count = 4 * recursion.protocol.FRI_QUERY_COUNT,
        .fri_layer_count = 5,
        .query_count = recursion.protocol.FRI_QUERY_COUNT,
        .maximum_fold_width = 16,
        .last_layer_coefficient_count = 1,
        .maximum_merkle_depth = 21,
    };
    const native = &verified.native.capture;
    const statement = try native.vm_air.reconstructStatement(&native.public_data.data);
    const selected_shape = try recursion.leaf_profile_selected_v12.deriveSegmentV2(
        dimensions,
        allocator,
        &statement.core,
        selected_core,
        pinned_tree0,
    );
    const captured_shape = try recursion.leaf_profile.deriveShape(dimensions, &statement.core, &native.proof);
    try std.testing.expectEqualDeep(captured_shape, selected_shape);
    const Wire = recursion.fixed_wire.FixedStarkProofWire(dimensions);
    const wire = try allocator.create(Wire);
    defer allocator.destroy(wire);
    try recursion.fixed_wire_adapter.populateVerifiedSegmentV2(dimensions, wire, selected_shape, &statement.core, verified);
    try wire.validateAgainstShape(selected_shape);

    var altered = selected_shape;
    altered.table_layout_id[0] ^= 1;
    @memset(std.mem.asBytes(wire), 0xa5);
    var before: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.asBytes(wire), &before, .{});
    try std.testing.expectError(error.CaptureShapeMismatch, recursion.fixed_wire_adapter.populateVerifiedSegmentV2(
        dimensions,
        wire,
        altered,
        &statement.core,
        verified,
    ));
    var after: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.asBytes(wire), &after, .{});
    try std.testing.expectEqual(before, after);
    var altered_statement = statement.core;
    altered_statement.total_steps ^= 1;
    try std.testing.expectError(error.CaptureShapeMismatch, recursion.fixed_wire_adapter.populateVerifiedSegmentV2(
        dimensions,
        wire,
        selected_shape,
        &altered_statement,
        verified,
    ));
    std.crypto.hash.sha2.Sha256.hash(std.mem.asBytes(wire), &after, .{});
    try std.testing.expectEqual(before, after);
    altered_statement = statement.core;
    altered_statement.public_data.io_entries.input_start ^= 4;
    try std.testing.expectError(error.CaptureShapeMismatch, recursion.fixed_wire_adapter.populateVerifiedSegmentV2(
        dimensions,
        wire,
        selected_shape,
        &altered_statement,
        verified,
    ));
    std.crypto.hash.sha2.Sha256.hash(std.mem.asBytes(wire), &after, .{});
    try std.testing.expectEqual(before, after);
}

pub fn allocateV8StatementColumns(allocator: std.mem.Allocator, count: usize) ![][]M31 {
    const columns = try allocator.alloc([]M31, count);
    var written: usize = 0;
    errdefer {
        for (columns[0..written]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = try allocator.alloc(M31, recursion.air.segment_leaf_statement_source_direct_v8.CAPACITY);
        @memset(column.*, M31.zero());
        written += 1;
    }
    return columns;
}

pub fn freeV8StatementColumns(allocator: std.mem.Allocator, columns: [][]M31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

pub fn buildV11SegmentV2PreleafLayout(
    allocator: std.mem.Allocator,
    capture: anytype,
    selected_core: *const recursion.air.segment_leaf_wrapper_template_v6.CoreProfileV6,
) !recursion.segment_core_expected_layout_from_statement_v11.OwnedLayout {
    const statement = try capture.vm_air.reconstructStatement(&capture.public_data.data);
    const logs = capture.proof.column_log_sizes;
    if (logs.len != recursion.segment_core_expected_layout_from_statement_v11.TREE_COUNT)
        return error.V11PreleafLayoutMismatch;
    var selected = try recursion.segment_core_expected_layout_from_statement_v11.OwnedLayout.buildSegmentV2FromCoreProfile(
        allocator,
        &statement.core,
        selected_core,
    );
    errdefer selected.deinit();
    for (selected.views, logs, 0..) |expected, actual, tree| {
        if (!std.mem.eql(u32, expected, actual)) {
            var first: usize = 0;
            while (first < @min(expected.len, actual.len) and expected[first] == actual[first]) : (first += 1) {}
            std.debug.print("V11_PRELEAF_LAYOUT_MISMATCH tree={d} expected_len={d} actual_len={d} first={d} expected={d} actual={d}\n", .{
                tree,                                             expected.len,                                 actual.len, first,
                if (first < expected.len) expected[first] else 0, if (first < actual.len) actual[first] else 0,
            });
            return error.V11PreleafLayoutMismatch;
        }
    }
    return selected;
}

pub fn buildV12PreleafPcsMasks(
    allocator: std.mem.Allocator,
    capture: anytype,
    selected_core: *const recursion.air.segment_leaf_wrapper_template_v6.CoreProfileV6,
    tree_logs: *const recursion.segment_core_expected_layout_from_statement_v11.OwnedLayout,
) !recursion.segment_core_expected_pcs_masks_v12.OwnedMasks {
    const statement = try capture.vm_air.reconstructStatement(&capture.public_data.data);
    return recursion.segment_core_expected_pcs_masks_v12.OwnedMasks.build(
        allocator,
        &statement.core,
        selected_core,
        tree_logs,
    );
}

pub fn checkV9CoreFriControlFixedParity(
    allocator: std.mem.Allocator,
    v9_template: *const recursion.air.segment_leaf_wrapper_template_v9.TemplateManifestV9,
    writer: *const recursion.segment_core_fri_row28_fixed_v8.Writer,
    old_plan: *const recursion.segment_leaf_wrapper_roster_direct_v5.Plan,
    old_tree: [][]M31,
) !void {
    const old = old_plan.placements[28].?;
    const current = v9_template.placements[28];
    if (!std.meta.eql(old.geometry, current.geometry)) return error.V9CoreFriControlFixedGeometryMismatch;
    const width = current.geometry.preprocessed_columns;
    const capacity = @as(usize, 1) << @intCast(current.geometry.log_size);
    const scratch = try allocator.alloc([]M31, width);
    var initialized: usize = 0;
    defer {
        for (scratch[0..initialized]) |column| allocator.free(column);
        allocator.free(scratch);
    }
    for (scratch) |*column| {
        column.* = try allocator.alloc(M31, capacity);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    try writer.writePhysical(current.geometry, scratch);
    if (old.preprocessed_offset > old_tree.len or width > old_tree.len - old.preprocessed_offset)
        return error.V9CoreFriControlFixedSourceMismatch;
    for (scratch, old_tree[old.preprocessed_offset..][0..width]) |expected, actual| {
        if (actual.len != capacity) return error.V9CoreFriControlFixedSourceMismatch;
        for (expected, actual) |a, b| if (!a.eql(b)) return error.V9CoreFriControlFixedSourceMismatch;
    }
}

pub fn checkV9CoreFriAnchorFixedParity(
    allocator: std.mem.Allocator,
    key: *const recursion.air.segment_leaf_wrapper_template_v9.TemplateManifestV9,
    old_plan: *const recursion.segment_leaf_wrapper_roster_direct_v5.Plan,
    old_tree: [][]M31,
) !void {
    var writer = try recursion.segment_core_fri_row27_fixed_v9.Writer.initFromVerifierTemplate(allocator, key);
    defer writer.deinit();
    const descriptor = try writer.descriptor(key);
    const old = old_plan.placements[27].?;
    if (!std.meta.eql(old.geometry, descriptor.geometry)) return error.V9CoreFriAnchorFixedGeometryMismatch;
    const width = descriptor.geometry.preprocessed_columns;
    const capacity = @as(usize, 1) << @intCast(descriptor.geometry.log_size);
    const scratch = try allocator.alloc([]M31, width);
    var initialized: usize = 0;
    defer {
        for (scratch[0..initialized]) |column| allocator.free(column);
        allocator.free(scratch);
    }
    for (scratch) |*column| {
        column.* = try allocator.alloc(M31, capacity);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    try writer.writePhysical(key, descriptor.geometry, scratch);
    if (old.preprocessed_offset > old_tree.len or width > old_tree.len - old.preprocessed_offset)
        return error.V9CoreFriAnchorFixedSourceMismatch;
    for (scratch, old_tree[old.preprocessed_offset..][0..width]) |expected, actual| {
        if (actual.len != capacity) return error.V9CoreFriAnchorFixedSourceMismatch;
        for (expected, actual) |a, b| if (!a.eql(b)) return error.V9CoreFriAnchorFixedSourceMismatch;
    }
}

pub fn checkV9CoreFriInputFixedParity(
    allocator: std.mem.Allocator,
    key: *const recursion.air.segment_leaf_wrapper_template_v9.TemplateManifestV9,
    old_plan: *const recursion.segment_leaf_wrapper_roster_direct_v5.Plan,
    old_tree: [][]M31,
) !void {
    var writer = try recursion.segment_core_fri_row29_fixed_v9.Writer.initFromVerifierTemplate(allocator, key);
    defer writer.deinit();
    const descriptor = try writer.descriptor(key);
    const old = old_plan.placements[29].?;
    if (!std.meta.eql(old.geometry, descriptor.geometry)) return error.V9CoreFriInputFixedGeometryMismatch;
    const width = descriptor.geometry.preprocessed_columns;
    const capacity = @as(usize, 1) << @intCast(descriptor.geometry.log_size);
    const scratch = try allocator.alloc([]M31, width);
    var initialized: usize = 0;
    defer {
        for (scratch[0..initialized]) |column| allocator.free(column);
        allocator.free(scratch);
    }
    for (scratch) |*column| {
        column.* = try allocator.alloc(M31, capacity);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    try writer.writePhysical(key, descriptor.geometry, scratch);
    if (old.preprocessed_offset > old_tree.len or width > old_tree.len - old.preprocessed_offset)
        return error.V9CoreFriInputFixedSourceMismatch;
    for (scratch, old_tree[old.preprocessed_offset..][0..width], 0..) |expected, actual, column| {
        if (actual.len != capacity) return error.V9CoreFriInputFixedSourceMismatch;
        for (expected, actual, 0..) |a, b, physical| if (!a.eql(b)) {
            std.debug.print("V9_ROW29_FIXED_MISMATCH column={d} physical={d} expected={d} actual={d}\n", .{ column, physical, a.toU32(), b.toU32() });
            return error.V9CoreFriInputFixedSourceMismatch;
        };
    }
}

pub fn checkV11TraceMerkleFixedParity(
    allocator: std.mem.Allocator,
    key: *const recursion.air.segment_leaf_wrapper_template_v10.TemplateManifestV10,
    expected: recursion.segment_core_trace_row23_fixed_v11.ExpectedLayout,
    old_plan: *const recursion.segment_leaf_wrapper_roster_direct_v5.Plan,
    old_tree: [][]M31,
) !void {
    var writer = try recursion.segment_core_trace_row23_fixed_v11.Writer.initFromExpectedLayout(allocator, key, expected);
    defer writer.deinit();
    const descriptor = try writer.descriptor(key);
    const old = old_plan.placements[23].?;
    if (!std.meta.eql(old.geometry, descriptor.geometry)) return error.V11TraceMerkleFixedGeometryMismatch;
    const width = descriptor.geometry.preprocessed_columns;
    const capacity = @as(usize, 1) << @intCast(descriptor.geometry.log_size);
    const scratch = try allocator.alloc([]M31, width);
    var initialized: usize = 0;
    defer {
        for (scratch[0..initialized]) |column| allocator.free(column);
        allocator.free(scratch);
    }
    for (scratch) |*column| {
        column.* = try allocator.alloc(M31, capacity);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    try writer.writePhysical(key, descriptor.geometry, scratch);
    if (old.preprocessed_offset > old_tree.len or width > old_tree.len - old.preprocessed_offset)
        return error.V11TraceMerkleFixedSourceMismatch;
    for (scratch, old_tree[old.preprocessed_offset..][0..width]) |expected_column, actual| {
        if (actual.len != capacity) return error.V11TraceMerkleFixedSourceMismatch;
        for (expected_column, actual) |a, b| if (!a.eql(b)) return error.V11TraceMerkleFixedSourceMismatch;
    }
}

pub fn checkV11PcsInputFixedParity(
    allocator: std.mem.Allocator,
    key: *const recursion.air.segment_leaf_wrapper_template_v10.TemplateManifestV10,
    expected: recursion.segment_core_pcs_row24_fixed_v11.ExpectedProfile,
    captured_circuit_id: [32]u8,
    old_plan: *const recursion.segment_leaf_wrapper_roster_direct_v5.Plan,
    old_tree: [][]M31,
) ![32]u8 {
    var writer = try recursion.segment_core_pcs_row24_fixed_v11.Writer.initFromExpectedProfile(allocator, key, expected);
    defer writer.deinit();
    const descriptor = try writer.descriptor(key);
    if (!std.meta.eql(descriptor.circuit_identity, captured_circuit_id))
        return error.V11PcsInputCircuitMismatch;
    const old = old_plan.placements[24].?;
    if (!std.meta.eql(old.geometry, descriptor.geometry)) return error.V11PcsInputFixedGeometryMismatch;
    const width = descriptor.geometry.preprocessed_columns;
    const capacity = @as(usize, 1) << @intCast(descriptor.geometry.log_size);
    const scratch = try allocator.alloc([]M31, width);
    var initialized: usize = 0;
    defer {
        for (scratch[0..initialized]) |column| allocator.free(column);
        allocator.free(scratch);
    }
    for (scratch) |*column| {
        column.* = try allocator.alloc(M31, capacity);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    try writer.writePhysical(key, descriptor.geometry, scratch);
    if (old.preprocessed_offset > old_tree.len or width > old_tree.len - old.preprocessed_offset)
        return error.V11PcsInputFixedSourceMismatch;
    for (scratch, old_tree[old.preprocessed_offset..][0..width]) |expected_column, actual| {
        if (actual.len != capacity) return error.V11PcsInputFixedSourceMismatch;
        for (expected_column, actual) |a, b| if (!a.eql(b)) return error.V11PcsInputFixedSourceMismatch;
    }
    return descriptor.circuit_identity;
}

pub fn checkV11CandidateAdmission(
    allocator: std.mem.Allocator,
    prior: *const recursion.air.segment_leaf_wrapper_template_v10.TemplateManifestV10,
    key: *const recursion.air.segment_leaf_wrapper_template_v11.TemplateManifestV11,
    expected: recursion.segment_core_pcs_row24_fixed_v11.ExpectedProfile,
) !void {
    const layout = recursion.segment_core_trace_row23_fixed_v11.ExpectedLayout{
        .vm_trees = expected.ordered_tree_logs,
        .recursion_trees = expected.ordered_tree_logs,
    };
    var trace = try recursion.segment_core_trace_row23_fixed_v11.Writer.initFromExpectedLayout(allocator, prior, layout);
    defer trace.deinit();
    var pcs = try recursion.segment_core_pcs_row24_fixed_v11.Writer.initFromExpectedProfile(allocator, prior, expected);
    defer pcs.deinit();
    try key.admitBothWriters(allocator, expected, &trace, &pcs);
    if (key.requireCompletePreprocessing()) |_| return error.V11IncompleteTemplateWasAccepted else |err| {
        if (err != error.V11TemplatePreprocessingUnavailable) return err;
    }
}

pub fn checkV7CoreFriFixedParity(
    allocator: std.mem.Allocator,
    profile: *const recursion.air.segment_leaf_wrapper_template_v6.CoreProfileV6,
    v7_plan: *const recursion.segment_leaf_wrapper_roster_direct_v7.Plan,
    old_plan: *const recursion.segment_leaf_wrapper_roster_direct_v5.Plan,
    old_tree: [][]M31,
) !void {
    var writer = try recursion.segment_core_fri_rows25_26_fixed_v7.Writer.init(allocator, profile);
    defer writer.deinit();
    for ([_]u8{ 25, 26 }) |row| {
        const old = old_plan.placements[row].?;
        const current = v7_plan.placements[row];
        if (!std.meta.eql(old.geometry, current.geometry)) return error.V7CoreFriFixedGeometryMismatch;
        const width = current.geometry.preprocessed_columns;
        const capacity = @as(usize, 1) << @intCast(current.geometry.log_size);
        const scratch = try allocator.alloc([]M31, width);
        var initialized: usize = 0;
        defer {
            for (scratch[0..initialized]) |column| allocator.free(column);
            allocator.free(scratch);
        }
        for (scratch) |*column| {
            column.* = try allocator.alloc(M31, capacity);
            @memset(column.*, M31.zero());
            initialized += 1;
        }
        try writer.writeRow(row, current.geometry, scratch);
        if (old.preprocessed_offset > old_tree.len or width > old_tree.len - old.preprocessed_offset)
            return error.V7CoreFriFixedSourceMismatch;
        for (scratch, old_tree[old.preprocessed_offset..][0..width]) |expected, actual| {
            if (actual.len != capacity) return error.V7CoreFriFixedSourceMismatch;
            for (expected, actual) |a, b| if (!a.eql(b)) return error.V7CoreFriFixedSourceMismatch;
        }
    }
}

/// The real-leaf V7 diagnostic materializes only its four changed rows;
/// the remaining columns stay absent until the complete V7 cohort exists.
pub const V7ChangedTree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    allocations: [4][]M31,

    pub fn init(allocator: std.mem.Allocator, plan: *const recursion.segment_leaf_wrapper_roster_direct_v7.Plan, comptime kind: enum { preprocessed, main, interaction }) !V7ChangedTree {
        const count = switch (kind) {
            .preprocessed => plan.total_preprocessed_columns,
            .main => plan.total_main_columns,
            .interaction => plan.total_interaction_columns,
        };
        const columns = try allocator.alloc([]M31, count);
        errdefer allocator.free(columns);
        @memset(columns, &.{});
        var allocations: [4][]M31 = undefined;
        var written: usize = 0;
        errdefer for (allocations[0..written]) |allocation| allocator.free(allocation);
        inline for (.{ @as(usize, 5), @as(usize, 35), @as(usize, 39), @as(usize, 42) }, 0..) |row, slot| {
            const placement = plan.placements[row];
            const offset = switch (kind) {
                .preprocessed => placement.preprocessed_offset,
                .main => placement.main_offset,
                .interaction => placement.interaction_offset,
            };
            const n = switch (kind) {
                .preprocessed => placement.geometry.preprocessed_columns,
                .main => placement.geometry.main_columns,
                .interaction => placement.geometry.interaction_columns,
            };
            const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
            const backing = try allocator.alloc(M31, n * size);
            @memset(backing, M31.zero());
            allocations[slot] = backing;
            written += 1;
            for (columns[offset..][0..n], 0..) |*column, index|
                column.* = backing[index * size ..][0..size];
        }
        return .{ .allocator = allocator, .columns = columns, .allocations = allocations };
    }

    pub fn deinit(self: *V7ChangedTree) void {
        for (self.allocations) |allocation| self.allocator.free(allocation);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

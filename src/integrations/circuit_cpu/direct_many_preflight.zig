//! Witness-free V4 verifier-handle and PCS geometry inspection.
//!
//! This constructs the AIR handles a future native verifier must use. It
//! accepts no proof bytes and cannot authorize a V4 proof on its own.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");
const air = @import("air.zig");
const many = @import("private_many_boundary.zig");
const chip = @import("tagged_many_chip.zig");
const bridge = @import("tagged_many_bridge.zig");

const QM31 = core.fields.qm31.QM31;
const DirectCircuit = circuit.common.direct_arithmetic.Circuit;
const n_fixed = circuit.common.direct_arithmetic.N_COLUMNS;

pub const Fact = struct {
    kind: many.ComponentKind,
    call_id: ?u32,
    trace_log_size: u32,
    evaluation_log_size: u32,
    main_offset: usize,
    main_columns: usize,
    interaction_offset: usize,
    interaction_columns: usize,
    constraint_offset: usize,
    n_constraints: usize,
    preprocessed_indices: [n_fixed]u32 = [_]u32{0} ** n_fixed,
    preprocessed_count: usize = 0,
    relation_ids: [2]u32 = .{ 0, 0 },
    relation_count: usize = 0,
    air_source_sha256: [32]u8 = [_]u8{0} ** 32,
    chip_constant: ?u32 = null,
    bridge_boundary: ?many.Call = null,

    pub fn preprocessedSlice(self: *const Fact) []const u32 {
        return self.preprocessed_indices[0..self.preprocessed_count];
    }

    pub fn relationSlice(self: *const Fact) []const u32 {
        return self.relation_ids[0..self.relation_count];
    }
};

pub const Inspection = struct {
    pcs: core.pcs.config_v2.PcsConfigV2,
    facts: [many.max_components]Fact = undefined,
    count: usize,
    tree_columns: [4]u32,
    sample_width_limits: [4]u32,
    max_column_log_size: u32,
    composition_log_size: u32,
    composition_split: u32,

    pub fn factSlice(self: *const Inspection) []const Fact {
        return self.facts[0..self.count];
    }
};

fn sourceDigest(source: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &result, .{});
    return result;
}

pub fn chipSourceDigest() [32]u8 {
    return sourceDigest(@embedFile("tagged_many_chip.zig"));
}

pub fn bridgeSourceDigest() [32]u8 {
    return sourceDigest(@embedFile("tagged_many_bridge.zig"));
}

/// The only supported V4 PCS profile. The fixed tree is lifted to its own
/// circuit height; the remaining trees use the highest selected component.
pub fn fixedPcs(plan: many.Plan, circuit_log: u32) !core.pcs.config_v2.PcsConfigV2 {
    if (plan.count == 0 or plan.count > many.max_calls or circuit_log < 4 or circuit_log > 16)
        return error.UnsupportedManyPcsGeometry;
    var max_log = circuit_log;
    for (plan.callSlice(), 0..) |call, id| {
        if (call.call_id != id) return error.NonCanonicalManyCallId;
        max_log = @max(max_log, try chip.validateRounds(call.rounds));
    }
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 1);
    var pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, max_log);
    pcs.preprocessed_lifting_log_size = circuit_log + fri.log_blowup_factor;
    return pcs;
}

/// Reconstruct actual verifier handles and ask the same Components API used
/// by the verifier for logs, masks, composition split, and degree. Every
/// returned fact is checked against the source Plan and strict V4 profile.
pub fn inspect(
    allocator: std.mem.Allocator,
    pp: *const DirectCircuit,
    template: *const air.Bundle,
    plan: many.Plan,
) !Inspection {
    const boundary = pp.private_many_boundary orelse return error.MissingManyBoundary;
    if (!std.meta.eql(boundary, plan.boundary())) return error.ManyBoundaryMismatch;
    const circuit_log = pp.traceLogSize();
    const pcs = try fixedPcs(plan, circuit_log);
    const layout = pp.layout();
    var bound = try air.bindDirectArithmetic(allocator, template, circuit_log, &layout);
    defer bound.deinit();
    if (bound.components.len != 1) return error.InvalidManyRoster;
    const specs = try many.expectedRoster(plan, circuit_log, bound.total_constraints);
    var pp_logs = [_]u32{circuit_log} ** n_fixed;
    const lifting_bound = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured = cairo.proving.air.component.Component.init(
        allocator,
        &bound.components[0],
        &pp_logs,
        lifting_bound,
        QM31.one(),
        QM31.one(),
        QM31.zero(),
    );
    var chips: [many.max_calls]chip.Component = undefined;
    var bridges: [many.max_calls]bridge.Component = undefined;
    var handles: [many.max_components]core.air.components.Component = undefined;
    handles[0] = captured.asVerifierComponent();
    for (plan.callSlice(), 0..) |call, id| {
        const chip_spec = specs.entries[1 + id];
        const bridge_spec = specs.entries[1 + @as(usize, plan.count) + id];
        chips[id] = .{
            .log_size = chip_spec.log_size,
            .call_id = call.call_id,
            .constant = call.constant,
            .main_offset = chip_spec.main_offset,
            .interaction_offset = chip_spec.interaction_offset,
            .elements = .init(QM31.one(), QM31.one()),
            .claimed_sum = QM31.zero(),
        };
        handles[1 + id] = chips[id].asVerifierComponent();
        bridges[id] = .{
            .main_offset = bridge_spec.main_offset,
            .interaction_offset = bridge_spec.interaction_offset,
            .boundary = call,
            .elements = .init(QM31.one(), QM31.one()),
            .claimed_sum = QM31.zero(),
        };
        handles[1 + @as(usize, plan.count) + id] = bridges[id].asVerifierComponent();
        if (chips[id].call_id != call.call_id or !std.meta.eql(chips[id].constant, call.constant) or
            chips[id].log_size != try chip.validateRounds(call.rounds) or
            !std.meta.eql(bridges[id].boundary, call)) return error.ManyHandleBindingMismatch;
    }
    var result: Inspection = .{
        .pcs = pcs,
        .count = specs.count,
        .tree_columns = undefined,
        .sample_width_limits = @splat(0),
        .max_column_log_size = 0,
        .composition_log_size = 0,
        .composition_split = 0,
    };
    const chip_source_sha256 = chipSourceDigest();
    const bridge_source_sha256 = bridgeSourceDigest();
    for (handles[0..specs.count], specs.slice(), result.facts[0..specs.count]) |handle, spec, *fact| {
        const expected_eval: u32 = switch (spec.kind) {
            .circuit => bound.components[0].evaluation_log_size,
            .chip => spec.log_size + 1,
            .bridge => spec.log_size + 2,
        };
        if (handle.nConstraints() != spec.constraint_count or
            handle.maxConstraintLogDegreeBound() != expected_eval or
            handle.compositionLogSplit() != core.verifier_types.COMPOSITION_LOG_SPLIT)
            return error.UnsupportedManyHandleGeometry;
        fact.* = .{
            .kind = spec.kind,
            .call_id = spec.call_id,
            .trace_log_size = spec.log_size,
            .evaluation_log_size = expected_eval,
            .main_offset = spec.main_offset,
            .main_columns = spec.main_columns,
            .interaction_offset = spec.interaction_offset,
            .interaction_columns = spec.interaction_columns,
            .constraint_offset = spec.constraint_offset,
            .n_constraints = handle.nConstraints(),
        };
        const indices = try handle.preprocessedColumnIndices(allocator);
        defer allocator.free(indices);
        if (indices.len > n_fixed or (spec.kind != .circuit and indices.len != 0))
            return error.UnsupportedManyPreprocessedIndices;
        fact.preprocessed_count = indices.len;
        for (indices, 0..) |index, offset| {
            if (index >= n_fixed) return error.UnsupportedManyPreprocessedIndices;
            fact.preprocessed_indices[offset] = @intCast(index);
        }
        switch (spec.kind) {
            .circuit => {
                fact.relation_ids[0] = circuit.common.component_list.GATE_RELATION_ID;
                fact.relation_count = 1;
            },
            .chip => {
                const id: usize = @intCast(spec.call_id orelse return error.ManyHandleBindingMismatch);
                fact.chip_constant = chips[id].constant.toU32();
                fact.relation_ids[0] = many.relation_id;
                fact.relation_count = 1;
                fact.air_source_sha256 = chip_source_sha256;
            },
            .bridge => {
                const id: usize = @intCast(spec.call_id orelse return error.ManyHandleBindingMismatch);
                fact.bridge_boundary = bridges[id].boundary;
                fact.relation_ids = .{ circuit.common.component_list.GATE_RELATION_ID, many.relation_id };
                fact.relation_count = 2;
                fact.air_source_sha256 = bridge_source_sha256;
            },
        }
    }
    const components: core.air.components.Components = .{
        .components = handles[0..specs.count],
        .n_preprocessed_columns = n_fixed,
    };
    const split = try components.compositionLogSplit();
    const composition_log = core.verifier_types.compositionMaskLogSize(components.compositionLogDegreeBound(), split) orelse
        return error.UnsupportedManyCompositionGeometry;
    const composition_columns = core.verifier_types.compositionColumnCount(split, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse
        return error.UnsupportedManyCompositionGeometry;
    var logs = try components.columnLogSizes(allocator);
    defer logs.deinitDeep(allocator);
    const point = core.circle.secureFieldPointFromRandomSeed(QM31.one());
    var masks = try components.maskPoints(allocator, point, composition_log, true);
    defer masks.deinitDeep(allocator);
    if (logs.items.len != 3 or masks.items.len != 3) return error.UnsupportedManyTreeCount;
    const expected_widths = [_]usize{ n_fixed, specs.main_width, specs.interaction_width };
    for (logs.items, masks.items, expected_widths, 0..) |tree_logs, tree_masks, expected_width, tree| {
        if (tree_logs.len != expected_width or tree_masks.len != expected_width)
            return error.UnsupportedManyTreeWidth;
        result.tree_columns[tree] = @intCast(expected_width);
        for (tree_logs, tree_masks, 0..) |log, mask, column| {
            const expected_log: u32 = if (tree == 0) circuit_log else blk: {
                for (specs.slice()) |spec| {
                    const start = if (tree == 1) spec.main_offset else spec.interaction_offset;
                    const width = if (tree == 1) spec.main_columns else spec.interaction_columns;
                    if (column >= start and column < start + width) break :blk spec.log_size;
                }
                return error.UnsupportedManyTreeLog;
            };
            if (log != expected_log or mask.len == 0 or mask.len > 2)
                return error.UnsupportedManyMaskGeometry;
            result.max_column_log_size = @max(result.max_column_log_size, log);
            result.sample_width_limits[tree] = @max(result.sample_width_limits[tree], @as(u32, @intCast(mask.len)));
        }
    }
    result.tree_columns[3] = @intCast(composition_columns);
    result.sample_width_limits[3] = 1;
    result.max_column_log_size = @max(result.max_column_log_size, composition_log);
    result.composition_log_size = composition_log;
    result.composition_split = split;
    if (pcs.trace_lifting_log_size != @max(result.max_column_log_size, pcs.trace_lifting_log_size) or
        pcs.preprocessed_lifting_log_size != circuit_log + pcs.fri_config.log_blowup_factor)
        return error.UnsupportedManyPcsGeometry;
    return result;
}

test "V4 live preflight derives one-call verifier geometry and rejects plan mismatch" {
    const a = std.testing.allocator;
    var gates: [32]circuit.builder.circuit.BinaryGate = undefined;
    for (&gates, 0..) |*gate, id|
        gate.* = .{ .in0 = 0, .in1 = 1, .out = @intCast(3 + id) };
    const source = circuit.common.preprocessed.CircuitView{ .n_vars = 36, .add = &gates, .output = &.{35} };
    var plan: many.Plan = .{ .count = 1 };
    plan.calls[0] = .{
        .call_id = 0,
        .rounds = 16,
        .constant = core.fields.m31.M31.fromCanonical(7),
        .input = .{ 3, 4, 5, 6 },
        .output = .{ 7, 8, 9, 10 },
    };
    var pp = try plan.preprocessed(a, source);
    defer pp.deinit(a);
    const bytes = try std.fs.cwd().readFileAlloc(a, air.bundle_path, 1 << 20);
    defer a.free(bytes);
    var template = try air.parse(a, bytes);
    defer template.deinit();
    const result = try inspect(a, &pp, &template, plan);
    try std.testing.expectEqual(@as(usize, 3), result.count);
    try std.testing.expectEqual(@as(u32, 29), result.tree_columns[1]);
    try std.testing.expectEqual(@as(u32, 36), result.tree_columns[2]);
    try std.testing.expectEqual(@as(u32, 7), result.factSlice()[2].bridge_boundary.?.constant.toU32());
    var altered = plan;
    altered.calls[0].output[0] += 1;
    try std.testing.expectError(error.ManyBoundaryMismatch, inspect(a, &pp, &template, altered));
}

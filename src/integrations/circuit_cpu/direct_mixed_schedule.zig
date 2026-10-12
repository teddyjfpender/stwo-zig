//! Witness-free selected geometry for the experimental mixed AIR profile.
//!
//! Fixed N=3 and N=4 native proof adapters consume this geometry, but cannot
//! authenticate a caller's S31 source by themselves. The source-pinned wrapper
//! must rebuild it; a mutable returned value is not a verification key.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");
const air = @import("air.zig");
const many = @import("private_many_boundary.zig");
const v4 = @import("direct_many_preflight.zig");
const native = @import("direct_mixed_admission.zig");
const pair_chip = @import("tagged_pair_chip.zig");
const pair_bridge = @import("tagged_pair_bridge.zig");
const many_chip = @import("tagged_many_chip.zig");
const many_bridge = @import("tagged_many_bridge.zig");

const QM31 = core.fields.qm31.QM31;
const DirectCircuit = circuit.common.direct_arithmetic.Circuit;
const n_fixed = circuit.common.direct_arithmetic.N_COLUMNS;
pub const version: u32 = 1;
pub const max_slots = 1 + 2 * many.max_calls;
pub const max_tree_width = 8 + many.max_calls * (many_chip.main_width + many_bridge.interaction_width);
const registered_local_air_dependency_sha256 = parseDigest("df54f8cbec15616e4e7acb8ae88896c442b2fd85bc097bdc4a238847d0983fa0");

pub const Slot = struct {
    kind: ?native.SourceKind = null,
    call_id: ?u32 = null,
    trace_log_size: u32 = 0,
    evaluation_log_size: u32 = 0,
    main_offset: u32 = 0,
    main_columns: u32 = 0,
    interaction_offset: u32 = 0,
    interaction_columns: u32 = 0,
    constraint_offset: u32 = 0,
    n_constraints: u32 = 0,
    preprocessed_indices: [n_fixed]u32 = [_]u32{0} ** n_fixed,
    preprocessed_count: u8 = 0,
    relation_ids: [2]u32 = .{ 0, 0 },
    relation_count: u8 = 0,
    air_source_sha256: [32]u8 = [_]u8{0} ** 32,
};

pub const Column = struct {
    log_size: u32 = 0,
    mask_width: u8 = 0,
};

pub const Geometry = struct {
    version: u32 = version,
    pcs: core.pcs.config_v2.PcsConfigV2,
    slot_count: usize,
    slots: [max_slots]Slot = [_]Slot{.{}} ** max_slots,
    tree_columns: [4]u32 = @splat(0),
    tree_lifting_log_sizes: [4]u32 = @splat(0),
    columns: [3][max_tree_width]Column = @splat(@splat(.{})),
    mask_points_sha256: [32]u8 = [_]u8{0} ** 32,
    max_column_log_size: u32 = 0,
    composition_log_size: u32 = 0,
    composition_split: u32 = 0,
    local_air_dependency_sha256: [32]u8 = [_]u8{0} ** 32,

    pub fn slotSlice(self: *const Geometry) []const Slot {
        return self.slots[0..self.slot_count];
    }
};

/// The exact ordered local AIR dependency closure. Core/prover library code
/// belongs to the pinned engine revision, not this narrower local checksum.
pub fn localAirDependencyDigest() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("STWO-MIXED-LOCAL-AIR-CLOSURE-V1\x00");
    inline for (.{ "repeated_step_chip.zig", "private_pair_boundary.zig", "private_many_boundary.zig", "tagged_pair_chip.zig", "tagged_pair_bridge.zig", "tagged_many_chip.zig", "tagged_many_bridge.zig" }) |name| {
        const bytes = @embedFile(name);
        h.update(name);
        h.update("\x00");
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, @intCast(bytes.len), .little);
        h.update(&length);
        h.update(bytes);
    }
    var result: [32]u8 = undefined;
    h.final(&result);
    return result;
}

fn parseDigest(comptime hex: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, hex) catch unreachable;
    return result;
}

pub fn inspect(
    allocator: std.mem.Allocator,
    pp: *const DirectCircuit,
    template: *const air.Bundle,
    plan: many.Plan,
) !Geometry {
    if (plan.count == 0 or plan.count > many.max_calls or
        pp.private_many_boundary == null or
        !std.meta.eql(pp.private_many_boundary.?, plan.boundary()))
        return error.InvalidMixedSourcePlan;
    const pcs = try v4.fixedPcs(plan, pp.traceLogSize());
    const reference = try v4.inspect(allocator, pp, template, plan);
    const circuit_fact = reference.facts[0];
    const layout = pp.layout();
    var bound = try air.bindDirectArithmetic(allocator, template, pp.traceLogSize(), &layout);
    defer bound.deinit();
    if (bound.components.len != 1) return error.InvalidMixedCircuitAir;
    var pp_logs = [_]u32{pp.traceLogSize()} ** n_fixed;
    const lifting = pcs.trace_lifting_log_size - pcs.fri_config.log_blowup_factor + 1;
    var captured = cairo.proving.air.component.Component.init(
        allocator,
        &bound.components[0],
        &pp_logs,
        lifting,
        QM31.one(),
        QM31.one(),
        QM31.zero(),
    );
    var pc: [many.max_calls]pair_chip.Component = undefined;
    var pb: [many.max_calls]pair_bridge.Component = undefined;
    var mc: [many.max_calls]many_chip.Component = undefined;
    var mb: [many.max_calls]many_bridge.Component = undefined;
    var handles: [max_slots]core.air.components.Component = undefined;
    handles[0] = captured.asVerifierComponent();
    var result: Geometry = .{ .pcs = pcs, .slot_count = 1 + 2 * @as(usize, plan.count) };
    var main_at: u32 = 0;
    var interaction_at: u32 = 0;
    var constraint_at: u32 = 0;
    const circuit_handle = handles[0];
    const indices = try circuit_handle.preprocessedColumnIndices(allocator);
    defer allocator.free(indices);
    if (indices.len != n_fixed or circuit_handle.compositionLogSplit() != core.verifier_types.COMPOSITION_LOG_SPLIT or
        circuit_handle.nConstraints() != bound.components[0].n_constraints or
        circuit_handle.maxConstraintLogDegreeBound() != bound.components[0].evaluation_log_size)
        return error.UnsupportedMixedCircuitGeometry;
    var fixed_indices: [n_fixed]u32 = undefined;
    for (indices, 0..) |index, offset| {
        if (index >= n_fixed) return error.UnsupportedMixedCircuitGeometry;
        fixed_indices[offset] = @intCast(index);
    }
    result.slots[0] = .{
        .kind = null,
        .call_id = null,
        .trace_log_size = pp.traceLogSize(),
        .evaluation_log_size = bound.components[0].evaluation_log_size,
        .main_offset = 0,
        .main_columns = @intCast(circuit_fact.main_columns),
        .interaction_offset = 0,
        .interaction_columns = @intCast(circuit_fact.interaction_columns),
        .constraint_offset = 0,
        .n_constraints = @intCast(circuit_handle.nConstraints()),
        .preprocessed_indices = fixed_indices,
        .preprocessed_count = @intCast(n_fixed),
        .relation_ids = .{ circuit.common.component_list.GATE_RELATION_ID, 0 },
        .relation_count = 1,
    };
    try advance(&main_at, &interaction_at, &constraint_at, result.slots[0]);
    for (plan.callSlice(), 0..) |call, id| {
        if (call.call_id != id) return error.NonCanonicalManyCallId;
        inline for (.{ native.Role.chip, native.Role.bridge }) |role| {
            const index = 1 + 2 * id + @intFromBool(role == .bridge);
            const kind = try native.kindForCall(call.call_id, role);
            const fact = try native.inspectNative(allocator, kind, call);
            result.slots[index] = .{
                .kind = kind,
                .call_id = call.call_id,
                .trace_log_size = fact.trace_log_size,
                .evaluation_log_size = fact.evaluation_log_size,
                .main_offset = main_at,
                .main_columns = @intCast(fact.main_columns),
                .interaction_offset = interaction_at,
                .interaction_columns = @intCast(fact.interaction_columns),
                .constraint_offset = constraint_at,
                .n_constraints = @intCast(fact.n_constraints),
                .relation_ids = fact.relation_ids,
                .relation_count = @intCast(fact.relation_count),
                .air_source_sha256 = fact.source_sha256,
            };
            const slot = result.slots[index];
            const elements = many.Elements.init(QM31.one(), QM31.one());
            switch (kind) {
                .pair_chip => {
                    pc[id] = .{ .log_size = slot.trace_log_size, .call_id = call.call_id, .constant = call.constant, .main_offset = slot.main_offset, .interaction_offset = slot.interaction_offset, .elements = elements, .claimed_sum = QM31.zero() };
                    handles[index] = pc[id].asVerifierComponent();
                },
                .pair_bridge => {
                    pb[id] = .{ .main_offset = slot.main_offset, .interaction_offset = slot.interaction_offset, .boundary = call, .elements = elements, .claimed_sum = QM31.zero() };
                    handles[index] = pb[id].asVerifierComponent();
                },
                .many_chip => {
                    mc[id] = .{ .log_size = slot.trace_log_size, .call_id = call.call_id, .constant = call.constant, .main_offset = slot.main_offset, .interaction_offset = slot.interaction_offset, .elements = elements, .claimed_sum = QM31.zero() };
                    handles[index] = mc[id].asVerifierComponent();
                },
                .many_bridge => {
                    mb[id] = .{ .main_offset = slot.main_offset, .interaction_offset = slot.interaction_offset, .boundary = call, .elements = elements, .claimed_sum = QM31.zero() };
                    handles[index] = mb[id].asVerifierComponent();
                },
            }
            try advance(&main_at, &interaction_at, &constraint_at, slot);
        }
    }
    const components: core.air.components.Components = .{ .components = handles[0..result.slot_count], .n_preprocessed_columns = n_fixed };
    const split = try components.compositionLogSplit();
    const composition_log = core.verifier_types.compositionMaskLogSize(components.compositionLogDegreeBound(), split) orelse return error.UnsupportedMixedCompositionGeometry;
    const composition_columns = core.verifier_types.compositionColumnCount(split, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.UnsupportedMixedCompositionGeometry;
    var logs = try components.columnLogSizes(allocator);
    defer logs.deinitDeep(allocator);
    const point = core.circle.secureFieldPointFromRandomSeed(QM31.one());
    var masks = try components.maskPoints(allocator, point, composition_log, true);
    defer masks.deinitDeep(allocator);
    if (logs.items.len != 3 or masks.items.len != 3) return error.UnsupportedMixedTreeCount;
    const expected_widths = [_]u32{ n_fixed, main_at, interaction_at };
    var mask_hash = std.crypto.hash.sha2.Sha256.init(.{});
    mask_hash.update("STWO-MIXED-MASK-POINTS-V1\x00");
    for (logs.items, masks.items, expected_widths, 0..) |tree_logs, tree_masks, width, tree| {
        if (tree_logs.len != width or tree_masks.len != width or width > max_tree_width)
            return error.UnsupportedMixedTreeWidth;
        result.tree_columns[tree] = width;
        hashInt(&mask_hash, @as(u32, @intCast(tree)));
        hashInt(&mask_hash, width);
        for (tree_logs, tree_masks, 0..) |log, mask, column| {
            const expected_log: u32 = if (tree == 0) pp.traceLogSize() else blk: {
                for (result.slotSlice()) |slot| {
                    const start = if (tree == 1) slot.main_offset else slot.interaction_offset;
                    const count = if (tree == 1) slot.main_columns else slot.interaction_columns;
                    if (column >= start and column < @as(usize, start) + count) break :blk slot.trace_log_size;
                }
                return error.UnsupportedMixedTreeLog;
            };
            if (log != expected_log or mask.len == 0 or mask.len > 2)
                return error.UnsupportedMixedMaskGeometry;
            result.columns[tree][column] = .{ .log_size = log, .mask_width = @intCast(mask.len) };
            result.max_column_log_size = @max(result.max_column_log_size, log);
            hashInt(&mask_hash, log);
            hashInt(&mask_hash, @as(u32, @intCast(mask.len)));
            for (mask) |sample| hashPoint(&mask_hash, sample);
        }
    }
    mask_hash.final(&result.mask_points_sha256);
    result.tree_columns[3] = @intCast(composition_columns);
    result.max_column_log_size = @max(result.max_column_log_size, composition_log);
    result.composition_log_size = composition_log;
    result.composition_split = split;
    result.local_air_dependency_sha256 = localAirDependencyDigest();
    if (!std.meta.eql(result.local_air_dependency_sha256, registered_local_air_dependency_sha256))
        return error.UnregisteredMixedAirDependency;
    if (pcs.trace_lifting_log_size < result.max_column_log_size or
        pcs.preprocessed_lifting_log_size != pp.traceLogSize() + pcs.fri_config.log_blowup_factor)
        return error.UnsupportedMixedPcsGeometry;
    var extended_logs: [max_tree_width]u32 = undefined;
    for (result.tree_columns, 0..) |width, tree| {
        if (width > max_tree_width) return error.UnsupportedMixedPcsGeometry;
        for (extended_logs[0..width], 0..) |*log, column| {
            const base_log = if (tree == 3) composition_log else result.columns[tree][column].log_size;
            log.* = try std.math.add(u32, base_log, pcs.fri_config.log_blowup_factor);
        }
        result.tree_lifting_log_sizes[tree] = try pcs.treeHeight(tree, extended_logs[0..width]);
    }
    return result;
}

fn advance(main_at: *u32, interaction_at: *u32, constraint_at: *u32, slot: Slot) !void {
    main_at.* = try std.math.add(u32, main_at.*, slot.main_columns);
    interaction_at.* = try std.math.add(u32, interaction_at.*, slot.interaction_columns);
    constraint_at.* = try std.math.add(u32, constraint_at.*, slot.n_constraints);
}

fn hashPoint(h: *std.crypto.hash.sha2.Sha256, point: core.circle.CirclePointQM31) void {
    inline for (.{ point.x.c0.a, point.x.c0.b, point.x.c1.a, point.x.c1.b, point.y.c0.a, point.y.c0.b, point.y.c1.a, point.y.c1.b }) |field|
        hashInt(h, field.toU32());
}

fn hashInt(h: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    var bytes: [@sizeOf(@TypeOf(value))]u8 = undefined;
    std.mem.writeInt(@TypeOf(value), &bytes, value, .little);
    h.update(&bytes);
}

test "mixed selected schedule pins local AIR dependency closure" {
    try std.testing.expectEqual(registered_local_air_dependency_sha256, localAirDependencyDigest());
}

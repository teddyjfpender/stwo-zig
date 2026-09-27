//! Concrete composition evaluation from an independently verified detached
//! SegmentV2 child. This owns witness data and a symbolic OODS equation, not
//! a parent-proof receipt. A parent must authenticate every exported input
//! role, including deriving the public boundary from its expected statement.
const recursion = struct {
    const detached_parent_components_v1 = @import("detached_parent_components_v1.zig");
    const recursion_air_composition_circuit_v3 = @import("recursion_air_composition_circuit_v3.zig");
};
const air = struct {
    const composition_circuit = @import("air/composition_circuit.zig");
    const universal_adapter_manifest = @import("air/universal_adapter_manifest.zig");
};
const std = @import("std");
const core = @import("stwo_core");
const composition = air.composition_circuit;
const v3 = recursion.recursion_air_composition_circuit_v3;
const recorder = v3.segment_recorder_v3.graph_recorder;
const child_mod = @import("detached_child_capture_v1.zig");
const QM31 = core.fields.qm31.QM31;

pub const OwnedV1 = opaque {
    const Storage = struct {
        allocator: std.mem.Allocator,
        layout: v3.capture_layout_v3.CaptureLayoutV3,
        profile: v3.InputProfileV3,
        circuit: recorder.Circuit,
        bindings: []composition.RecursionInputBinding,
        inputs: []QM31,
        values: []QM31,
    };

    pub fn init(allocator: std.mem.Allocator, child: anytype) !*OwnedV1 {
        const family = @typeInfo(@TypeOf(child)).pointer.child.FAMILY;
        const kind: composition.ProofKind = if (family == .segment) .segment_leaf else .binary_node;
        const Factory = if (family == .segment) @import("detached_segment_recording_components_v1.zig") else recursion.detached_parent_components_v1;
        const key = child.key();
        try key.validate();
        var layout = try child.compositionLayout(allocator);
        errdefer layout.deinit();
        const profile = v3.InputProfileV3{ .sampled_value_count = layout.sampled_value_count };
        try profile.validate();
        const claims = child.claims();
        const components = try Factory.OwnedComponentsV1.init(allocator, &key.manifest, key.parameters, child.relations(), claims);
        defer components.deinit();
        var program = try recordDetached(kind, allocator, &key.manifest, &layout, profile, components);
        errdefer program.circuit.deinit();
        errdefer allocator.free(program.bindings);
        const inputs = try allocator.alloc(QM31, try composition.recursionInputCount(profile.graphProfile()));
        errdefer allocator.free(inputs);
        try child.writeCompositionInputs(profile, inputs);
        const values = try allocator.alloc(QM31, program.circuit.nodes.len);
        errdefer allocator.free(values);
        try program.circuit.evaluateInto(inputs, values);
        const owned = try allocator.create(Storage);
        owned.* = .{ .allocator = allocator, .layout = layout, .profile = profile, .circuit = program.circuit, .bindings = program.bindings, .inputs = inputs, .values = values };
        return @ptrCast(owned);
    }

    fn storage(self: *const OwnedV1) *const Storage {
        return @ptrCast(@alignCast(self));
    }

    pub fn deinit(self: *OwnedV1) void {
        const owned: *Storage = @ptrCast(@alignCast(self));
        const allocator = owned.allocator;
        allocator.free(owned.values);
        allocator.free(owned.inputs);
        allocator.free(owned.bindings);
        owned.circuit.deinit();
        owned.layout.deinit();
        allocator.destroy(owned);
    }

    pub fn graph(self: *const OwnedV1) composition.CircuitGraph {
        return self.storage().circuit.graph();
    }

    pub fn inputProfile(self: *const OwnedV1) v3.InputProfileV3 {
        return self.storage().profile;
    }

    pub fn inputBindings(self: *const OwnedV1) []const composition.RecursionInputBinding {
        return self.storage().bindings;
    }

    pub fn inputValues(self: *const OwnedV1) []const QM31 {
        return self.storage().inputs;
    }

    pub fn evaluatedValues(self: *const OwnedV1) []const QM31 {
        return self.storage().values;
    }
};

/// Shared symbolic OODS equation for the admitted detached leaf and parent
/// cohorts. Their concrete adapters own constraints; this layer routes inputs.
pub fn recordDetached(
    comptime kind: composition.ProofKind,
    allocator: std.mem.Allocator,
    manifest: anytype,
    layout: *const v3.capture_layout_v3.CaptureLayoutV3,
    profile: v3.InputProfileV3,
    components: anytype,
) !struct { circuit: recorder.Circuit, bindings: []composition.RecursionInputBinding } {
    if (comptime kind == .segment_leaf)
        try layout.validateAgainstSegment(manifest)
    else if (comptime kind == .binary_node)
        try layout.validateAgainstAuthenticatedBinary(.detached_segment_parent_v1, manifest)
    else
        @compileError("detached composition requires an actual child proof");
    const graph_profile = profile.graphProfile();
    const count = try composition.recursionInputCount(graph_profile);
    const bindings = try allocator.alloc(composition.RecursionInputBinding, count);
    errdefer allocator.free(bindings);
    const base = try allocator.alloc(recorder.Scalar, count);
    defer allocator.free(base);
    const samples = try allocator.alloc(recorder.Scalar, layout.sampled_value_count);
    defer allocator.free(samples);
    var builder = recorder.Builder.init(allocator);
    defer builder.deinit();
    try builder.reserve(count, @as(usize, manifest.total_constraints) + 768);
    for (base, bindings, 0..) |*value, *binding, index| {
        const input = try builder.input();
        value.* = input.value;
        binding.* = .{ .node_id = input.node_id, .source = composition.expectedRecursionSource(graph_profile, index) orelse return error.InvalidWitnessShape };
    }
    try builder.activate();
    var cursor: usize = 0;
    const parent_binary_selector = base[cursor];
    cursor += 1;
    const kinds: [v3.PROGRAM_KIND_COUNT]recorder.Scalar = base[cursor..][0..v3.PROGRAM_KIND_COUNT].*;
    cursor += v3.PROGRAM_KIND_COUNT;
    // Statement words retain the canonical typed ABI for parent binding.
    // Composition alone does not authenticate their relation to the boundary.
    cursor += v3.STATEMENT_WORD_COUNT;
    for (samples) |*value| value.* = v3.takeSecureRecorderInput(base, &cursor);
    var claims: [v3.COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar = undefined;
    for (&claims) |*value| value.* = v3.takeSecureRecorderInput(base, &cursor);
    const wire_boundary = v3.takeSecureRecorderInput(base, &cursor);
    var draws: [v3.RELATION_CHALLENGE_COUNT][2]recorder.Scalar = undefined;
    for (&draws) |*pair| for (pair) |*value| {
        value.* = v3.takeSecureRecorderInput(base, &cursor);
    };
    const alpha = v3.takeSecureRecorderInput(base, &cursor);
    const seed = v3.takeSecureRecorderInput(base, &cursor);
    if (cursor != count) return error.InvalidWitnessShape;
    const challenges = try recorder.ChallengeSet.init(draws);
    const point = recorder.pointFromSeed(seed);
    const expected_composition = try v3.reconstructSplitCompositionForLayout(layout, samples, point);
    const one = recorder.Scalar.one();
    try builder.constrainZero(parent_binary_selector.sub(one));
    for (kinds, 0..) |selector, index|
        try builder.constrainZero(selector.sub(if (index == v3.proofKindIndex(kind)) one else recorder.Scalar.zero()));
    _ = try v3.recordClaimPolicyConstraints(&builder, &kinds, &claims);
    if (comptime kind == .segment_leaf)
        try builder.constrainZero(claims[10]) // Existing inactive SegmentV2 row.
    else for (14..20) |row| {
        if (manifest.placements[row] == null) try builder.constrainZero(claims[row]);
    }
    var total = wire_boundary;
    for (claims[0..39]) |claim| total = total.add(claim);
    try builder.constrainZero(total);
    var denominators: recorder.DenominatorCache = .{null} ** core.circle.M31_CIRCLE_LOG_ORDER;
    const result = if (comptime kind == .segment_leaf) blk: {
        var program = try v3.segment_recorder_v3.SegmentProgramRecorderV3.init(&builder, manifest, layout, samples, &claims, &challenges, alpha, point, &denominators);
        break :blk try components.recordCompositionV3(&program);
    } else blk: {
        // Retained children have no opening-accumulator component. Keep each
        // admitted recorder's exact roster check rather than weakening it.
        const active_count = recursion.detached_parent_components_v1.LOGICAL_ROWS.len + 2;
        inline for (.{ active_count - 1, active_count }) |component_count| {
            if (manifest.roster_count == component_count) {
                const ParentRecorder = v3.segment_recorder_v3.ProgramRecorderForManifest(air.universal_adapter_manifest, .binary_node, component_count);
                var program = try ParentRecorder.initAuthenticatedBinary(&builder, manifest, .detached_segment_parent_v1, layout, samples, &claims, &challenges, alpha, point, &denominators);
                break :blk try components.recordCompositionV3(&program);
            }
        }
        return error.DetachedParentManifestMismatch;
    };
    try builder.constrainZero(expected_composition.sub(result.accumulation));
    builder.deactivate();
    return .{ .circuit = try builder.finish(), .bindings = bindings };
}

/// Genuine-child gate: graph evaluation, not recursive proof acceptance.
pub fn testFromVerifiedChild(allocator: std.mem.Allocator, child: *const child_mod.OwnedV1) !void {
    const owned = try OwnedV1.init(allocator, child);
    defer owned.deinit();
    const value = owned.storage();
    const inputs = try allocator.dupe(QM31, value.inputs);
    defer allocator.free(inputs);
    const scratch = try allocator.alloc(QM31, value.values.len);
    defer allocator.free(scratch);
    const first_composition_sample = value.layout.offsets[v3.capture_layout_v3.COMPOSITION_TREE_INDEX][0];
    var changed_claims: usize = 0;
    var changed_samples: usize = 0;
    for (value.bindings, 0..) |binding, index| {
        const mutate = switch (binding.source) {
            .claimed_sum => |coordinate| coordinate.word_index == 0,
            .sampled_value => |coordinate| coordinate.item_index == first_composition_sample,
            else => false,
        };
        if (!mutate) continue;
        inputs[index] = inputs[index].add(QM31.one());
        defer inputs[index] = value.inputs[index];
        try std.testing.expectError(error.UnsatisfiedCircuit, value.circuit.evaluateInto(inputs, scratch));
        switch (binding.source) {
            .claimed_sum => changed_claims += 1,
            .sampled_value => changed_samples += 1,
            else => unreachable,
        }
    }
    try std.testing.expectEqual(@as(usize, 41), changed_claims);
    try std.testing.expectEqual(@as(usize, 4), changed_samples);
    try value.circuit.evaluateInto(value.inputs, scratch);
    std.debug.print("detached composition: samples={d} inputs={d} nodes={d} outputs={d} rejected_claims={d} rejected_sample_words={d}\n", .{ value.profile.sampled_value_count, value.inputs.len, value.values.len, value.circuit.outputs.len, changed_claims, changed_samples });
}

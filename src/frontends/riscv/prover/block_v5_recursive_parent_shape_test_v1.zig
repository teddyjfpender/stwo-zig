//! Geometry/fixed-row fixtures. Metadata below is NOT cryptographic admission;
//! it has no expected key, root acceptance, successful proof or capture API.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Geometry = @import("../recursion/block_v5_recursive_parent_shape_v1.zig");
const Components = @import("../recursion/blake3_native_parent_components.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const Layouts = @import("../recursion/sample_point_layout.zig");
const Schema = @import("../recursion/block_v5_recursive_parent_operations_v1.zig");
const Transcript = @import("../recursion/air/block_v5_recursive_parent_fixed_transcript_v1.zig");
const Recorder = @import("../recursion/air/blake3_native_recorder.zig");
const t = @import("../recursion/air/blake3_transcript_witness.zig");
const Native = @import("../recursion/air/blake3_native_transcript.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Public = struct {
    pub fn replayPublic(_: *const Public, recorder: anytype) void {
        recorder.mixPublicWords(.{ .circuit = 4_300_281, .first_wire = 0 }, &.{ 0x42354d50, 5, 7 });
        recorder.mixPublicRoot(.{ .circuit = 4_300_281, .first_wire = 3 }, @splat(12));
    }
};
const Metadata = struct {
    key: struct { log_sizes: Geometry.Logs },
    settings: core.pcs.PcsConfig,
    source: *const Public,
    pub fn validate(self: *const Metadata) !void {
        if (self.settings.fri_config.n_queries != 1) return error.InvalidFixtureMetadata;
    }
    pub fn config(self: *const Metadata) !core.pcs.PcsConfig {
        return self.settings;
    }
};
fn metadata(public: *const Public) Metadata {
    var logs: Geometry.Logs = @splat(2);
    logs[0] = 7;
    return .{ .key = .{ .log_sizes = logs }, .settings = .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 1, .fold_step = 3 } }, .source = public };
}
fn shapeCase(a: std.mem.Allocator) !void {
    const public = Public{};
    const admitted = metadata(&public);
    const shape = try Geometry.Shape.initForAdmission(a, &admitted, .{});
    defer shape.deinit();
    try shape.validateAgainst(&admitted);
    const original = try Components.Owned.init(a, &admitted);
    defer original.deinit();
    // Real original challenge draws and arbitrary component claims are used
    // only to ask the shipped component for geometry. No proof is verified.
    var channel = core.channel.blake3.Channel{};
    const relations = try universal.UniversalRelations.draw(a, &channel);
    try original.bind(relations, @splat(Q.zero()));
    const all = original.admitted();
    const split = try all.compositionLogSplit();
    try std.testing.expectEqual(split, shape.composition_split);
    try std.testing.expectEqual(all.compositionLogDegreeBound(), shape.mask_log + split);
    const current = core.circle.SECURE_FIELD_CIRCLE_GEN;
    const step = core.poly.circle.canonic.CanonicCoset.new(shape.mask_log).step();
    const previous = current.sub(.{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) });
    var masks = try all.maskPoints(a, current, shape.mask_log, false);
    defer masks.deinitDeep(a);
    var cursor: usize = 0;
    for (original.columns[0..3], masks.items, shape.columns[0..3]) |logs, columns, extended| {
        try std.testing.expectEqual(logs.items.len, extended.len);
        for (logs.items, columns, extended) |log, mask, derived| {
            try std.testing.expectEqual(log + admitted.settings.fri_config.log_blowup_factor, derived);
            try std.testing.expectEqual(try Layouts.classifyColumn(mask, current, previous), shape.layouts[cursor]);
            cursor += 1;
        }
    }
    for (shape.layouts[cursor..]) |layout| try std.testing.expectEqual(Layouts.Layout.current, layout);
    try checkIndependentSeal(shape, &admitted);
}
fn checkIndependentSeal(shape: *Geometry.Shape, admitted: *const Metadata) !void {
    const saved = shape.layouts[0];
    shape.layouts[0] = .current_previous;
    shape.seal = shape.identity();
    if (shape.validateAgainst(admitted)) |_| return error.TestExpectedError else |failure| {
        if (failure == error.OutOfMemory) return failure;
        try std.testing.expectEqual(error.UntrustedRecursiveParentShape, failure);
    }
    shape.layouts[0] = saved;
    shape.seal = shape.identity();
    try shape.validateAgainst(admitted);
}
fn geometryAllocations(a: std.mem.Allocator) !void {
    const public = Public{};
    const admitted = metadata(&public);
    const shape = try Geometry.Shape.initForAdmission(a, &admitted, .{});
    defer shape.deinit();
    try shape.validateAgainst(&admitted);
    try checkIndependentSeal(shape, &admitted);
}
test "recursive shape: exact original component columns masks degrees and independently rebuilt seal" {
    try shapeCase(std.testing.allocator);
}
test "recursive shape: all metadata geometry construction allocations roll back" {
    // Failure injection covers new geometry construction, independently rebuilt
    // seals and teardown. Original component/mask parity is exercised above;
    // repeating its unrelated component factory for every new failure point
    // made this development check needlessly expensive.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, geometryAllocations, .{});
}
test "recursive shape: no verifier authority and exact resource admission" {
    const public = Public{};
    var admitted = metadata(&public);
    try std.testing.expect(!@hasDecl(Metadata, "admitRoot") and !@hasField(Metadata, "expected_id"));
    try std.testing.expectError(error.RecursiveParentShapeResourceLimit, Geometry.Shape.initForAdmission(std.testing.allocator, &admitted, .{ .max_columns = 1 }));
    admitted.key.log_sizes[0] = 25;
    try std.testing.expectError(error.InvalidRecursiveParentShape, Geometry.Shape.initForAdmission(std.testing.allocator, &admitted, .{}));
}
test "recursive shape: retained geometry owner survives original budget release" {
    const public = Public{};
    const admitted = metadata(&public);
    const budget = try Budget.create(std.testing.allocator, 1 << 20);
    const shape = Geometry.Shape.initForAdmission(budget.allocator(), &admitted, .{}) catch |failure| {
        budget.destroy();
        return failure;
    };
    budget.destroy();
    try shape.validate();
    shape.deinit();
}
fn secure(a: std.mem.Allocator, operations: *std.ArrayList(t.Operation), channel: *core.channel.blake3.Channel, role: t.OutputRole) !void {
    const value = channel.drawSecureFelt();
    var words: [8]core.fields.m31.M31 = @splat(core.fields.m31.M31.zero());
    words[0..4].* = value.toM31Array();
    try operations.append(a, .{ .secure = .{ .output = role, .attempts = 0, .consumption = .one, .values = words } });
}
fn transcriptCase(a: std.mem.Allocator) !void {
    const public = Public{};
    const admitted = metadata(&public);
    const shape = try Geometry.Shape.initForAdmission(a, &admitted, .{});
    defer shape.deinit();
    var fixed = try Transcript.Owned.init(a, &admitted, shape, 1_000_000, 2, .{});
    defer fixed.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var recorder = Recorder.Recorder{ .a = temp, .universal_relations = true };
    public.replayPublic(&recorder);
    recorder.mixRoot(@splat(1));
    recorder.mixRoot(@splat(2));
    _ = try universal.UniversalRelations.draw(temp, &recorder);
    recorder.private_felts = true;
    const count = @import("../recursion/blake3_native_parent_artifact.zig").CLAIM_COUNT;
    recorder.mixU32s(&.{ 0x42354d51, 5, count });
    const claims: [count]Q = @splat(Q.fromBase(core.fields.m31.M31.fromCanonical(7)));
    recorder.mixFelts(&claims);
    recorder.mixRoot(@splat(3));
    try recorder.check();
    try secure(temp, &recorder.operations, &recorder.native, .composition);
    const root_slots = try Native.suffixRootSlots(4);
    recorder.native.mixRoot(@splat(4));
    try recorder.operations.append(temp, .{ .routed_root = .{ .value = @splat(4), .source = root_slots.composition } });
    try secure(temp, &recorder.operations, &recorder.native, .oods);
    const samples = try temp.alloc(Q, try shape.deepProfile().sampleCount());
    @memset(samples, Q.fromBase(core.fields.m31.M31.fromCanonical(8)));
    recorder.native.mixFelts(samples);
    try recorder.operations.append(temp, .{ .routed_felts = .{ .values = samples, .source = Native.SAMPLE_SOURCE } });
    try secure(temp, &recorder.operations, &recorder.native, .deep);
    for (shape.widths, 0..) |_, layer| {
        recorder.native.mixRoot(@splat(9));
        try recorder.operations.append(temp, .{ .routed_root = .{ .value = @splat(9), .source = .{ .circuit = root_slots.fri.circuit, .first_wire = root_slots.fri.first_wire + @as(u32, @intCast(8 * layer)) } } });
        try secure(temp, &recorder.operations, &recorder.native, .{ .fri = layer });
    }
    const terminal = try temp.alloc(Q, try shape.friProfile().lastLayerCoefficientCount());
    @memset(terminal, Q.one());
    recorder.native.mixFelts(terminal);
    try recorder.operations.append(temp, .{ .routed_felts = .{ .values = terminal, .source = Native.TERMINAL_SOURCE } });
    const nonce_source = t.Caller{ .circuit = 4_100_001, .first_wire = 2 };
    // Exact native transcript operations; this does not claim a STARK receipt.
    try std.testing.expect(recorder.native.verifyPowNonce(0, 11));
    try recorder.operations.append(temp, .{ .pow = .{ .bits = 0, .nonce = 11, .nonce_source = nonce_source } });
    recorder.native.mixU64(11);
    try recorder.operations.append(temp, .{ .routed_integer = .{ .value = 11, .source = nonce_source } });
    const raw = try core.queries.drawQueries(&recorder.native, temp, shape.lifting_log, 1);
    const positions = try temp.alloc(u32, raw.len);
    for (raw, positions) |value, *position| position.* = @intCast(value);
    try recorder.operations.append(temp, .{ .queries = .{ .log_domain_size = shape.lifting_log, .values = positions, .export_outputs = true } });
    var original = try @import("../recursion/air/blake3_transcript_plan.zig").Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = 2 }, recorder.operations.items);
    defer original.deinit();
    try std.testing.expectEqual(original.id, fixed.fixed.id);
    try fixed.validateAgainst(shape);
    var operations: std.ArrayList(Schema.Operation) = .empty;
    defer operations.deinit(a);
    try Schema.appendClosedSuffix(a, &operations, shape);
    try std.testing.expectEqual(@as(usize, 0), operations.items[0].commitment.slot);
    try std.testing.expectEqual(@as(usize, 1), operations.items[1].commitment.slot);
    try std.testing.expectEqual(universal.RELATION_COUNT, 47);
}
test "recursive shape: bounded fixed transcript matches exact original native operation oracle" {
    try transcriptCase(std.testing.allocator);
}

//! Additional genuine Raw full-quotient parity, never a proof/capture receipt.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Frame = @import("block_v5_memory_source_page_capture_frame_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Components = @import("block_v5_memory_source_unified_page_components_v1.zig");
const C = Components.ForKind(.raw);
const Arith = @import("block_v5_memory_source_page_arithmetic_columns_v1.zig").ForKind(.raw);
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Schema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const Raw = @import("block_v5_memory_source_batch_raw_v1.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
const R = @import("../recursion/air/composition_graph_recorder.zig");
const Recorded = @import("../recursion/air/block_v5_memory_source_page_record_v1.zig");
const Layout = @import("../recursion/sample_point_layout.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
pub fn emptyAdmission() !Batch.Admission {
    const digest = Initial.sha256("");
    const root = @import("block_v5_memory_source_batch_defaults_v1.zig").get().defaults[0].bytes;
    const source = try Source.make(.{ .initial = .{
        .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 256, .stack_bottom = 128, .stack_top = 512, .io_base = 256, .io_end = 768, .input_base = 32, .input_end = 256, .output_len_addr = 768, .output_data_addr = 772, .output_base = 768, .output_end = 1024 },
        .initial_rw_root = root,
        .initial_registers = @splat(0),
        .public_input_sha256 = digest,
        .public_input_len = 0,
        .input_words = .{ .records = 0, .sha256 = digest },
        .rw_words = .{ .records = 0, .sha256 = digest },
        .first_touches = .{ .records = 0, .sha256 = digest },
    }, .memory_plan_digest = @splat(7), .expected_final_rw_root = root, .endpoints = .{ .records = 0, .sha256 = digest } }, @splat(8), .{});
    return Batch.Admission.init(source, .{});
}
fn sourceChallenges() Batch.Challenges {
    return .{ .source = .{ .word = .{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() }, .bytes = .dummy(), .input = .dummy(), .insertion = .dummy(), .before = .dummy(), .after = .dummy(), .route = .dummy(), .roots = .dummy(), .ordering = .dummy(), .sha_chain = .dummy() }, .route = .dummy(), .indexed = .dummy(), .hash = .dummy() };
}
pub const Fixture = struct {
    a: std.mem.Allocator,
    graph: *Semantic.Prepared,
    fixed: *Arith.Fixed,
    core_setup: *const C.CoreColumns.Setup,
    arithmetic_setup: *const Components.ArithmeticSetup,
    owner: *C.Owner,
    frame: Frame.ForKind(.raw),
    relations: Universal.UniversalRelations,
    pub fn init(a: std.mem.Allocator) !Fixture {
        const admitted = try emptyAdmission();
        const config = @import("../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
        const limits = Schema.Protocol.Limits{ .page_row_log = 1 };
        const plan = try Schema.Protocol.init(&admitted.source, config, limits);
        const pin = Schema.Protocol.Pin{ .plan_id = plan.identity, .page = try plan.page(0), .roots = .{ @splat(13), @splat(14) }, .config = config };
        const claims = Semantic.Claims.zero();
        const graph = try Semantic.prepareRaw(a, &admitted, plan, pin, sourceChallenges(), claims, 4_200_052, limits, .{});
        errdefer graph.deinit();
        const descriptors = try a.alloc(Raw.Descriptor, pin.page.chunks);
        defer a.free(descriptors);
        for (descriptors, 0..) |*d, i| d.* = try Raw.kindAt(&admitted.source, pin.page.first_chunk + i);
        const fixed = try a.create(Arith.Fixed);
        errdefer a.destroy(fixed);
        fixed.* = try Arith.Fixed.init(a, graph, descriptors, 1, 1, .{});
        errdefer fixed.deinit();
        const core_setup = try C.CoreColumns.Setup.create(a);
        errdefer core_setup.release();
        const arithmetic_setup = try Components.ArithmeticSetup.create(a);
        errdefer arithmetic_setup.release();
        const relations = Universal.UniversalRelations.dummy();
        const cores = try @import("block_v5_memory_source_packed_sha_columns_v1.zig").Geometry.fromPage(&admitted.source, pin.page, .{});
        var component_claims = std.mem.zeroes(C.Claims);
        component_claims.capture.wire_requests = @as(u64, cores.compressions) * 32;
        component_claims.source_inputs.requests = fixed.source_inputs.requests;
        component_claims.capture_inputs.requests = fixed.capture_inputs.requests;
        component_claims.arithmetic[0] = (try fixed.plan.publicBoundaryClaim(.segment_leaf, &relations)).neg();
        const geometry = C.Geometry{ .source_log = 1, .capture_log = 1, .core_logs = cores.logs, .arithmetic_logs = fixed.arithmetic.logs, .capture_requests = component_claims.capture.wire_requests };
        const owner = try C.Owner.init(a, graph, &fixed.plan, &fixed.arithmetic, &fixed.source_inputs, &fixed.capture_inputs, geometry, relations, component_claims, core_setup, arithmetic_setup, .{});
        errdefer owner.deinit();
        const semantic = @import("block_v5_memory_source_unified_page_protocol_v1.zig").SemanticPin{ .premix_identity = @splat(13), .source_epoch = @splat(14), .graph_identity = graph.identity, .circuit_id = graph.circuit_id, .input_requests = graph.input_requests, .claims = claims, .roots = .{ @splat(15), @splat(16) } };
        return .{ .a = a, .graph = graph, .fixed = fixed, .core_setup = core_setup, .arithmetic_setup = arithmetic_setup, .owner = owner, .frame = try Frame.ForKind(.raw).init(a, component_claims, semantic, geometry, owner), .relations = relations };
    }
    pub fn deinit(self: *Fixture) void {
        self.frame.deinit(self.a);
        self.owner.deinit();
        self.arithmetic_setup.release();
        self.core_setup.release();
        self.fixed.deinit();
        self.a.destroy(self.fixed);
        self.graph.deinit();
    }
};
fn symbolic(builder: *R.Builder, a: std.mem.Allocator, values: *std.ArrayList(Q), value: Q) !R.Scalar {
    const input = try builder.input();
    try values.append(a, value);
    return input.value;
}
fn parity(fixture: *const Fixture, changed_sample: ?usize) !void {
    const a = std.testing.allocator;
    const seed = Q.fromU32Unchecked(7, 11, 13, 17);
    const random = Q.fromU32Unchecked(19, 23, 29, 31);
    const point = core.circle.secureFieldPointFromRandomSeed(seed);
    const frame = &fixture.frame;
    const mask_log = core.verifier_types.compositionMaskLogSize(frame.constraint_log, frame.split).?;
    const step = core.poly.circle.canonic.CanonicCoset.new(mask_log).step();
    const previous = point.sub(.{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) });
    var masks = try fixture.owner.composition.?.maskPoints(a, point, mask_log);
    defer masks.deinitDeep(a);
    const trees = try a.alloc([][]Q, 9);
    for (trees) |*tree| tree.* = &.{};
    var concrete = core.air.components.MaskValues.initOwned(trees);
    defer concrete.deinitDeep(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    defer inputs.deinit(a);
    var symbols: std.ArrayList(R.Scalar) = .empty;
    defer symbols.deinit(a);
    var samples = Recorded.Samples{ .offsets = undefined, .layouts = undefined, .values = undefined };
    samples.offsets[9] = &.{};
    samples.layouts[9] = &.{};
    for (masks.items, trees, 0..) |columns, *tree, i| {
        tree.* = try a.alloc([]Q, columns.len);
        for (tree.*) |*column| column.* = &.{};
        samples.offsets[i] = try temp.alloc(usize, columns.len);
        samples.layouts[i] = try temp.alloc(Layout.Layout, columns.len);
        for (columns, tree.*, 0..) |points, *values, column| {
            values.* = try a.alloc(Q, points.len);
            samples.offsets[i][column] = symbols.items.len;
            samples.layouts[i][column] = try Layout.classifyColumn(points, point, previous);
            for (values.*) |*value| {
                value.* = Q.fromU32Unchecked(@intCast(37 + inputs.items.len), 41, 43, 47);
                try symbols.append(a, try symbolic(&builder, a, &inputs, value.*));
            }
        }
    }
    samples.values = symbols.items;
    var draws: [Universal.RELATION_COUNT][2]R.Scalar = undefined;
    for (&draws, fixture.relations.elements) |*pair, element| {
        pair[0] = try symbolic(&builder, a, &inputs, element.z);
        pair[1] = try symbolic(&builder, a, &inputs, element.alpha);
    }
    const randomness = try symbolic(&builder, a, &inputs, random);
    const oods = try symbolic(&builder, a, &inputs, seed);
    var claims: Recorded.ClaimSymbols(.raw) = undefined;
    const proposal = @import("../recursion/air/block_v5_memory_source_page_composition_v1.zig").claimValues(.raw, frame.claims);
    var position: usize = 0;
    inline for (std.meta.fields(@TypeOf(claims))) |field| {
        for (&@field(claims, field.name)) |*out| {
            out.* = try symbolic(&builder, a, &inputs, proposal[position]);
            position += 1;
        }
    }
    var original = core.air.accumulation.PointEvaluationAccumulator.init(random);
    try fixture.owner.composition.?.evaluateConstraintQuotientsAtPoint(point, &concrete, &original, mask_log);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const challenge = try R.ChallengeSet.init(draws);
    const quotient = try Recorded.record(.raw, &builder, fixture.owner, &fixture.fixed.plan, frame, samples, claims, &challenge, randomness, oods);
    try builder.constrainZero(quotient.sub(R.Scalar.fromSecure(original.finalize())));
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const evaluated = try a.alloc(Q, circuit.nodes.len);
    defer a.free(evaluated);
    if (changed_sample) |index| {
        if (index >= symbols.items.len) return error.InvalidFixtureSample;
        inputs.items[index] = inputs.items[index].add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs.items, evaluated));
    } else try circuit.evaluateInto(inputs.items, evaluated);
}
test "source PAGE forest: all original Raw quotient equations masks parameters and normalized claims match symbolic recorder" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try parity(&fixture, null);
}
test "source PAGE forest: genuine original Raw main mutation changes full symbolic quotient" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try parity(&fixture, fixture.frame.logs[0].len);
}

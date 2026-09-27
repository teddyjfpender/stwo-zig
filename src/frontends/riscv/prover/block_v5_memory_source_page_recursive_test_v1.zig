//! Original-source metadata and quotient tests only. No PCS commitments,
//! proof generation, guests, devices or successful-proof receipts occur here.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Frame = @import("block_v5_memory_source_page_capture_frame_v1.zig");
const Admission = @import("block_v5_memory_source_page_recursive_admission_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Components = @import("block_v5_memory_source_unified_page_components_v1.zig");
const C = Components.ForKind(.fold);
const Arith = @import("block_v5_memory_source_page_arithmetic_columns_v1.zig").ForKind(.fold);
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
const R = @import("../recursion/air/composition_graph_recorder.zig");
const Recorded = @import("../recursion/air/block_v5_memory_source_page_record_v1.zig");
const Layout = @import("../recursion/sample_point_layout.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
fn emptyAdmission() !Batch.Admission {
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
    frame: Frame.ForKind(.fold),
    relations: Universal.UniversalRelations,
    pub fn init(a: std.mem.Allocator) !Fixture {
        const admitted = try emptyAdmission();
        var claims = Semantic.Claims.zero();
        claims.fold.roots = Q.one();
        const rows = [_]Semantic.FoldRow{
            .{ .descriptor = .{ .kind = .empty, .height = 30 }, .recipes = &.{}, .first_compression = 0, .compressions = 0 },
            .{ .descriptor = .{ .kind = .root, .height = 30 }, .recipes = &.{}, .first_compression = 0, .compressions = 0 },
        };
        const graph = try Semantic.prepareFold(a, &admitted, &rows, @splat(13), sourceChallenges(), claims, 99, .{});
        errdefer graph.deinit();
        const fixed = try a.create(Arith.Fixed);
        errdefer a.destroy(fixed);
        const descriptors = [_]Eq.Descriptor{ .{ .kind = .empty, .height = 30 }, .{ .kind = .root, .height = 30 } };
        fixed.* = try Arith.Fixed.init(a, graph, &descriptors, 1, 1, .{});
        errdefer fixed.deinit();
        const core_setup = try C.CoreColumns.Setup.create(a);
        errdefer core_setup.release();
        const arithmetic_setup = try Components.ArithmeticSetup.create(a);
        errdefer arithmetic_setup.release();
        const relations = Universal.UniversalRelations.dummy();
        var component_claims = std.mem.zeroes(C.Claims);
        component_claims.source_inputs.requests = fixed.source_inputs.requests;
        component_claims.capture_inputs.requests = fixed.capture_inputs.requests;
        component_claims.arithmetic[0] = (try fixed.plan.publicBoundaryClaim(.segment_leaf, &relations)).neg();
        // These are algebra-only proposals at arbitrary OODS samples. They
        // never enter any proof verifier or successful receipt constructor.
        const geometry = C.Geometry{ .source_log = 1, .capture_log = 1, .core_logs = @splat(1), .arithmetic_logs = fixed.arithmetic.logs, .capture_requests = 0 };
        const owner = try C.Owner.init(a, graph, &fixed.plan, &fixed.arithmetic, &fixed.source_inputs, &fixed.capture_inputs, geometry, relations, component_claims, core_setup, arithmetic_setup, .{});
        errdefer owner.deinit();
        const semantic = @import("block_v5_memory_source_unified_page_protocol_v1.zig").SemanticPin{ .premix_identity = @splat(13), .source_epoch = @splat(14), .graph_identity = graph.identity, .circuit_id = graph.circuit_id, .input_requests = graph.input_requests, .claims = claims, .roots = .{ @splat(15), @splat(16) } };
        return .{ .a = a, .graph = graph, .fixed = fixed, .core_setup = core_setup, .arithmetic_setup = arithmetic_setup, .owner = owner, .frame = try Frame.ForKind(.fold).init(a, component_claims, semantic, geometry, owner), .relations = relations };
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
test "source PAGE recursion: exact suffix roots preserve original4/5/10 commitment slots" {
    const Transcript = @import("../recursion/air/blake3_native_transcript.zig");
    const Roots = @import("../recursion/air/blake3_root_sources.zig");
    for ([_]usize{ 4, 5, 10 }) |count| {
        const slots = try Transcript.suffixRootSlots(count);
        try std.testing.expect(std.meta.eql(slots.composition, try Roots.caller(count - 1)));
        try std.testing.expect(std.meta.eql(slots.fri, try Roots.caller(count)));
        try std.testing.expectEqual(@as(u32, @intCast(8 * (count - 1))), slots.composition.first_wire);
        try std.testing.expectEqual(@as(u32, @intCast(8 * count)), slots.fri.first_wire);
        // Exact digest order, including a distinct fifth-root composition.
        var roots: [10][32]u8 = undefined;
        for (&roots, 0..) |*root, i| root.* = @splat(@intCast(i + 1));
        try std.testing.expectEqual(@as(u8, @intCast(count)), roots[slots.composition.first_wire / 8][0]);
    }
    try std.testing.expectError(error.InvalidNativeBlake3Transcript, Transcript.suffixRootSlots(6));
}
test "source PAGE recursion: static prefix cannot widen legacy recorder admission" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var recorder = @import("../recursion/air/blake3_native_recorder.zig").Recorder{ .a = arena.allocator() };
    recorder.mixU32s(&.{1});
    try std.testing.expectError(error.InvalidNativeBlake3Transcript, recorder.skipCommittedRoots(8));
    try recorder.skipCommittedRootsFor(8);
    try std.testing.expectEqual(@as(usize, 8), recorder.root_count);
    try std.testing.expectError(error.InvalidNativeBlake3Transcript, recorder.skipCommittedRootsFor(8));
}
test "source PAGE recursion: resource policy rejects before undefined original source and proof authority" {
    inline for (.{ Semantic.Kind.raw, Semantic.Kind.fold }) |kind| {
        const A = Admission.ForKind(kind).Prepared;
        try std.testing.expectError(error.SourcePageRecursiveResourceLimit, A.init(std.testing.allocator, undefined, undefined, &.{}, undefined, undefined, .{ .max_capture_bytes = 0 }));
        try std.testing.expectError(error.SourcePageRecursiveResourceLimit, A.init(std.testing.allocator, undefined, undefined, &.{}, undefined, undefined, .{ .max_public_wires = 0 }));
    }
    try std.testing.expect(!@import("../recursion/block_v5_memory_source_page_recursive_leaf_v1.zig").ForKind(.raw).OpenEquation.complete_block_authority);
    try std.testing.expect(!@import("../recursion/block_v5_memory_source_page_recursive_leaf_v1.zig").ForKind(.fold).OpenEquation.complete_source_authority);
}
fn malformedProof(a: std.mem.Allocator) !core.proof_suites.Blake3.Proof {
    const suite = core.proof_suites.Blake3;
    const roots = try a.dupe(suite.Hasher.Hash, &.{@splat(77)});
    errdefer a.free(roots);
    const samples = try a.alloc([][]Q, 0);
    errdefer a.free(samples);
    const queries = try a.alloc([][]M, 0);
    errdefer a.free(queries);
    const paths = try a.alloc(core.vcs_lifted.verifier.MerkleDecommitmentLifted(suite.Hasher), 0);
    errdefer a.free(paths);
    const fri = try a.dupe(Q, &.{Q.one()});
    errdefer a.free(fri);
    const hashes = try a.dupe(suite.Hasher.Hash, &.{@splat(78)});
    errdefer a.free(hashes);
    const layers = try a.alloc(core.fri.FriLayerProof(suite.Hasher), 0);
    errdefer a.free(layers);
    const last = try a.dupe(Q, &.{Q.one()});
    return .{ .commitment_scheme_proof = .{ .config = @import("../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG, .commitments = core.pcs.TreeVec(suite.Hasher.Hash).initOwned(roots), .sampled_values = core.pcs.TreeVec([][]Q).initOwned(samples), .queried_values = core.pcs.TreeVec([][]M).initOwned(queries), .decommitments = core.pcs.TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLifted(suite.Hasher)).initOwned(paths), .proof_of_work = 0, .fri_proof = .{ .first_layer = .{ .fri_witness = fri, .decommitment = .{ .hash_witness = hashes }, .commitment = @splat(79) }, .inner_layers = layers, .last_layer_poly = core.poly.line.LinePoly.initOwned(last) } } };
}
test "source PAGE recursion: owned failures consume original vectors and borrowed failures preserve them" {
    inline for (.{ Semantic.Kind.raw, Semantic.Kind.fold }) |kind| {
        const Original = @import("block_v5_memory_source_unified_page_proof_v1.zig").ForKind(kind);
        const Capture = @import("block_v5_memory_source_page_recursive_capture_v1.zig").ForKind(kind);
        var admitted: Admission.ForKind(kind).Prepared = undefined;
        admitted.limits = .{ .max_capture_bytes = 0 };
        // Explicit malformed, allocated original proof vectors only. The
        // resource rejection cannot publish any verified capture or receipt.
        var owned: Original.Proof = undefined;
        owned.stark = try malformedProof(std.testing.allocator);
        try std.testing.expectError(error.SourcePageRecursiveResourceLimit, Capture.verifyOwned(std.testing.allocator, owned, &admitted));
        var borrowed: Original.Proof = undefined;
        borrowed.stark = try malformedProof(std.testing.allocator);
        defer borrowed.deinit(std.testing.allocator);
        const pointer = borrowed.stark.commitment_scheme_proof.commitments.items.ptr;
        try std.testing.expectError(error.SourcePageRecursiveResourceLimit, Capture.verifyBorrowed(std.testing.allocator, &borrowed, &admitted));
        try std.testing.expect(pointer == borrowed.stark.commitment_scheme_proof.commitments.items.ptr);
        try std.testing.expectEqual(@as(u8, 77), borrowed.stark.commitment_scheme_proof.commitments.items[0][0]);
    }
}
fn cloneCase(a: std.mem.Allocator, source: *const Frame.ForKind(.fold)) !void {
    var clone = try source.clone(a);
    defer clone.deinit(a);
    for (source.logs, clone.logs) |before, after| {
        try std.testing.expect(std.mem.eql(u32, before, after));
        if (before.len != 0) try std.testing.expect(before.ptr != after.ptr);
    }
}
test "source PAGE recursion: genuine original graph owner admits exact metadata and independent log clones" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.frame.require(fixture.frame.geometry, fixture.frame.semantic, fixture.owner);
    var clone = try fixture.frame.clone(std.testing.allocator);
    defer clone.deinit(std.testing.allocator);
    clone.logs[8][0] += 1;
    try std.testing.expectError(error.InvalidSourcePageCaptureFrame, clone.require(fixture.frame.geometry, fixture.frame.semantic, fixture.owner));
    clone.logs[8][0] -= 1;
    clone.constraint_count += 1;
    try std.testing.expectError(error.InvalidSourcePageCaptureFrame, clone.require(fixture.frame.geometry, fixture.frame.semantic, fixture.owner));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, cloneCase, .{&fixture.frame});
}
test "source PAGE recursion: original union masks reject shifted point count and extended log mutations" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const config = @import("../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
    const seed = Q.fromU32Unchecked(7, 11, 13, 17);
    const point = core.circle.secureFieldPointFromRandomSeed(seed);
    const frame = &fixture.frame;
    const mask_log = core.verifier_types.compositionMaskLogSize(frame.constraint_log, frame.split).?;
    const handle = fixture.owner.asVerifierComponent();
    const components = core.air.components.Components{ .components = &.{handle}, .n_preprocessed_columns = frame.logs[0].len };
    var masks = try components.maskPoints(a, point, mask_log, false);
    defer masks.deinitDeep(a);
    // Only verifier-geometry fields are initialized. This is a mask proposal,
    // not a capture from successful verification or a usable proof receipt.
    var proposal: core.verifier.ProofCapture(core.proof_suites.Blake3.Hasher) = undefined;
    proposal.oods_seed = seed;
    proposal.commitments = try a.alloc([32]u8, 10);
    proposal.column_log_sizes = try a.alloc([]u32, 10);
    proposal.sampled_points = try a.alloc([][]core.circle.CirclePointQM31, 10);
    var count: usize = 0;
    for (frame.logs, masks.items, 0..) |logs, points, tree| {
        proposal.column_log_sizes[tree] = try a.dupe(u32, logs);
        for (proposal.column_log_sizes[tree]) |*log| log.* += config.fri_config.log_blowup_factor;
        proposal.sampled_points[tree] = points;
        for (points) |column| count += column.len;
    }
    const composition_count = core.verifier_types.compositionColumnCount(frame.split, 4).?;
    proposal.column_log_sizes[9] = try a.alloc(u32, composition_count);
    @memset(proposal.column_log_sizes[9], mask_log + config.fri_config.log_blowup_factor);
    proposal.sampled_points[9] = try a.alloc([]core.circle.CirclePointQM31, composition_count);
    for (proposal.sampled_points[9]) |*column| {
        column.* = try a.alloc(core.circle.CirclePointQM31, 1);
        column.*[0] = point;
    }
    proposal.sampled_values = try a.alloc(Q, count + composition_count);
    try frame.requireCaptured(a, &proposal, config, fixture.owner);
    proposal.column_log_sizes[1][0] += 1;
    try std.testing.expectError(error.InvalidSourcePageCaptureGeometry, frame.requireCaptured(a, &proposal, config, fixture.owner));
    proposal.column_log_sizes[1][0] -= 1;
    const original = proposal.sampled_points[8][0][0];
    proposal.sampled_points[8][0][0] = core.circle.secureFieldPointFromRandomSeed(seed.add(Q.one()));
    try std.testing.expectError(error.InvalidSourcePageCaptureGeometry, frame.requireCaptured(a, &proposal, config, fixture.owner));
    proposal.sampled_points[8][0][0] = original;
    proposal.sampled_values = proposal.sampled_values[0 .. proposal.sampled_values.len - 1];
    try std.testing.expectError(error.InvalidSourcePageCaptureGeometry, frame.requireCaptured(a, &proposal, config, fixture.owner));
}
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
    var claims: Recorded.ClaimSymbols(.fold) = undefined;
    const proposal = @import("../recursion/air/block_v5_memory_source_page_composition_v1.zig").claimValues(.fold, frame.claims);
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
    const quotient = try Recorded.record(.fold, &builder, fixture.owner, &fixture.fixed.plan, frame, samples, claims, &challenge, randomness, oods);
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
test "source PAGE recursion: all original fold quotient equations masks parameters and normalized claims match symbolic recorder" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try parity(&fixture, null);
}
test "source PAGE recursion: genuine original main cell mutation changes authenticated symbolic quotient" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    // tree0 is independently opened though unused by fold arithmetic. Tree1
    // first source cell is constrained by the original canonical/source AIR.
    try parity(&fixture, fixture.frame.logs[0].len);
}

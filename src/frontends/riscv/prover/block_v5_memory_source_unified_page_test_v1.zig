//! Nonproving PAGE connector/custody fixtures. These do not invoke PCS,
//! STARK/FRI, guest execution, recursion proving or devices.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const Hash = @import("block_v5_memory_source_packed_hash_v1.zig");
const Blake = @import("block_v5_memory_source_blake_semantics_v1.zig");
const Air = @import("block_v5_memory_source_blake_capture_air_v1.zig");
const Component = @import("block_v5_memory_source_blake_capture_component_v1.zig");
const Canonical = @import("block_v5_memory_source_page_canonical_component_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Store = @import("block_v5_memory_source_fold_operand_store_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Crypto = @import("../recursion/air/block_v5_memory_source_crypto_v1.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
const G = @import("../recursion/air/blake3_g_call.zig");
const Xor = @import("../recursion/air/blake3_xor_call.zig");
const Plan = @import("../recursion/air/blake3_compression_plan.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig");
const Defaults = @import("block_v5_memory_source_batch_defaults_v1.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Input = @import("block_v5_memory_source_page_input_component_v1.zig").ForWidth(Eq.BIT_COUNT);
const Lower = @import("../recursion/air/verifier_arithmetic_lowering.zig");
const C = Crypto.Algebra(Q);
const Sink = struct {
    pub fn zero(_: *@This(), value: Q) !void {
        if (!value.isZero()) return error.UnsatisfiedPageCapture;
    }
};
const Capture = struct {
    values: [2][192]Q = undefined,
    count: usize = 0,
    pub fn g(_: *@This(), _: *const G.Row) !void {}
    pub fn xor(_: *@This(), _: *const Xor.Row) !void {}
    pub fn boundary(self: *@This(), captured: Hash.Boundary) !void {
        if (self.count == self.values.len) return error.TooManyPageCaptures;
        for (captured.initial ++ captured.output, 0..) |word, i| for (0..4) |j| {
            self.values[self.count][4 * i + j] = Q.fromBase(M.fromCanonical((word >> @as(u5, @intCast(8 * j))) & 255));
        };
        self.count += 1;
    }
};
fn pair() Blake.Algebra(Q).Pair {
    return .{ .z = Q.fromU32Unchecked(17, 19, 23, 29), .alpha = Q.fromU32Unchecked(31, 37, 41, 43) };
}
fn wireChallenge() Air.Algebra(Q).Challenge {
    const w = Universal.Elements.init(6, pair().z, pair().alpha);
    return .{ .z = w.z, .powers = w.alpha_powers[0..6].* };
}
fn frac(term: Air.Algebra(Q).Term) !Q {
    return if (term.numerator.isZero()) Q.zero() else term.numerator.mul(try term.denominator.inv());
}
test "source unified PAGE: original leaf/node byte framing equals independent bit hash97 and rejects input/output framing swaps" {
    const a = Blake.Algebra(Q);
    var sink = Sink{};
    const frames = [_]Hash.Frame{ .{ .leaf = 0x12345678 }, .{ .node = .{ .left = @splat(7), .right = @splat(11) } } };
    for (frames) |frame| {
        var captured = Capture{};
        const digest = try Hash.emit(frame, 1, &captured);
        try a.captured(&sink, a.frameFromNative(frame), a.digestFromNative(digest), captured.values[0..captured.count]);
        const recipe = Blake.Recipe{ .slot = 0, .multiplicity = 2, .default_height = null, .compression_count = @intCast(captured.count), .first_compression = 0 };
        const actual = try a.providers(&sink, if (std.meta.activeTag(frame) == .leaf) .leaf else .branch, if (std.meta.activeTag(frame) == .leaf) 0 else 1, @splat(a.frameFromNative(frame)), @splat(a.digestFromNative(digest)), &.{recipe}, captured.values[0..captured.count], 0, pair());
        const bit_frame: Hash.Algebra(Q).FrameBits = switch (frame) {
            .leaf => |word| .{ .leaf = C.word(word) },
            .node => |node| .{ .node = .{ .left = C.digest(node.left), .right = C.digest(node.right) } },
        };
        const expected = try Hash.hashSupply(Q, bit_frame, C.digest(digest), 2, .{ .z = pair().z, .alpha = pair().alpha });
        try std.testing.expect(actual.eql(expected));
        captured.values[0][56] = captured.values[0][56].add(Q.one());
        try std.testing.expectError(error.UnsatisfiedPageCapture, a.captured(&sink, a.frameFromNative(frame), a.digestFromNative(digest), captured.values[0..captured.count]));
        captured.values[0][56] = captured.values[0][56].sub(Q.one());
        var wrong = a.digestFromNative(digest);
        wrong[0] = wrong[0].add(Q.one());
        try std.testing.expectError(error.UnsatisfiedPageCapture, a.captured(&sink, a.frameFromNative(frame), wrong, captured.values[0..captured.count]));
    }
}
test "source unified PAGE: default and shared recipes cannot omit private before/after operands" {
    const a = Blake.Algebra(Q);
    var sink = Sink{};
    const frame = Hash.Frame{ .leaf = 0 };
    const digest = frame.nativeDigest();
    const recipe = Blake.Recipe{ .slot = 0, .multiplicity = 2, .default_height = 0, .compression_count = 0, .first_compression = 0 };
    const good_frames: [2]a.Frame = @splat(a.frameFromNative(frame));
    const good_digests: [2][32]Q = @splat(a.digestFromNative(digest));
    const actual = try a.providers(&sink, .leaf, 0, good_frames, good_digests, &.{recipe}, &.{}, 0, pair());
    try std.testing.expect(actual.eql(try Hash.defaultSupply(Q, 0, 2, .{ .z = pair().z, .alpha = pair().alpha })));
    var changed_frames = good_frames;
    changed_frames[1] = a.frameFromNative(.{ .leaf = 7 });
    try std.testing.expectError(error.UnsatisfiedPageCapture, a.providers(&sink, .leaf, 0, changed_frames, good_digests, &.{recipe}, &.{}, 0, pair()));
    changed_frames = @splat(a.frameFromNative(.{ .leaf = 7 }));
    try std.testing.expectError(error.UnsatisfiedPageCapture, a.providers(&sink, .leaf, 0, changed_frames, good_digests, &.{recipe}, &.{}, 0, pair()));
    var changed_digests = good_digests;
    changed_digests[1][0] = changed_digests[1][0].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedPageCapture, a.providers(&sink, .leaf, 0, good_frames, changed_digests, &.{recipe}, &.{}, 0, pair()));
    try std.testing.expectError(error.InvalidSourceBlakeRecipe, Blake.requireRecipes(.leaf, 0, &.{.{ .slot = 0, .multiplicity = 1, .default_height = 0, .compression_count = 0, .first_compression = 0 }}, 0, 0));
    try std.testing.expectError(error.InvalidSourceBlakeRecipe, Blake.requireRecipes(.root, 30, &.{recipe}, 0, 0));
}
test "source unified PAGE: all48 original BLAKE boundary wires include discarded outputs and weighted input uses" {
    var captures = Capture{};
    _ = try Hash.emit(.{ .leaf = 0x55667788 }, 9, &captures);
    var fixed: [Air.FIXED_COUNT]Q = @splat(Q.zero());
    fixed[0] = Q.one();
    fixed[1] = Q.fromBase(M.fromCanonical(9));
    const terms = Air.Algebra(Q).terms(fixed, captures.values[0], wireChallenge());
    var mass: u64 = 16;
    for (0..32) |i| {
        try std.testing.expect(terms[i].numerator.eql(Q.fromBase(M.fromCanonical(Plan.canonical().uses[i]))));
        mass += Plan.canonical().uses[i];
    }
    try std.testing.expectEqual(Air.requestMass(), mass);
    for (terms[32..]) |term| try std.testing.expect(term.numerator.eql(Q.one().neg()));
    var changed = captures.values[0];
    changed[191] = changed[191].add(Q.one()); // discarded last output word
    const altered = Air.Algebra(Q).terms(fixed, changed, wireChallenge());
    try std.testing.expect(!(try frac(terms[47])).eql(try frac(altered[47])));
    for (0..47) |i| try std.testing.expect(terms[i].denominator.eql(altered[i].denominator));
}
test "source unified PAGE: capture scalar packed off-domain equations preserve degree3 and exact normalized claims" {
    var fixed: [Air.FIXED_COUNT]Q = undefined;
    var main: [Air.MAIN_COUNT]Q = undefined;
    var current: [Air.INTERACTION_COUNT]Q = undefined;
    var previous: [Air.INTERACTION_COUNT]Q = undefined;
    for (&fixed, 0..) |*value, i| value.* = Q.fromU32Unchecked(@intCast(2 + i), 7, 11, 13);
    for (&main, 0..) |*value, i| value.* = Q.fromU32Unchecked(@intCast(17 + i), 19, 23, 29);
    for (&current, &previous, 0..) |*now, *before, i| {
        now.* = Q.fromU32Unchecked(@intCast(31 + i), 37, 41, 43);
        before.* = Q.fromU32Unchecked(@intCast(47 + i), 53, 59, 61);
    }
    const domain = try (Component.Spec{ .rows = 2, .expected_requests = Air.requestMass(), .claim = .{ .sums = @splat(Q.fromU32Unchecked(67, 71, 73, 79)), .wire_requests = Air.requestMass() }, .challenge = wireChallenge() }).prepareDomain(2);
    const scalar = try domain.evaluate(fixed, main, @splat(Q.zero()), current, previous, 2);
    var packed_fixed: [Air.FIXED_COUNT]P = undefined;
    var packed_main: [Air.MAIN_COUNT]P = undefined;
    var packed_current: [Air.INTERACTION_COUNT]P = undefined;
    var packed_previous: [Air.INTERACTION_COUNT]P = undefined;
    for (&packed_fixed, fixed) |*out, value| out.* = P.splat(value);
    for (&packed_main, main) |*out, value| out.* = P.splat(value);
    for (&packed_current, current) |*out, value| out.* = P.splat(value);
    for (&packed_previous, previous) |*out, value| out.* = P.splat(value);
    const vector = domain.evaluatePacked(packed_fixed, packed_main, @splat(P.zero()), packed_current, packed_previous);
    for (scalar, vector, 0..) |expected, actual, i| {
        for (0..core.fields.m31.PACK_WIDTH) |lane| try std.testing.expect(expected.eql(actual.lane(lane)));
        try std.testing.expectEqual(@as(u8, if (i < Air.MAIN_COUNT) 2 else 3), try Air.degree(i));
    }
}
test "source unified PAGE: omitted original source cells have explicit Boolean zero constraints and exact live masks" {
    const raws = [_]@import("block_v5_memory_source_batch_raw_v1.zig").Descriptor{
        .{ .sha = .{ .stream = .public_input, .block = 0 } },
        .{ .record = .{ .stream = .rw_words, .ordinal = 0 } },
        .{ .record = .{ .stream = .first_touches, .ordinal = 0 } },
        .{ .record = .{ .stream = .endpoints, .ordinal = 0 } },
    };
    const RawAir = Canonical.ForKind(.raw);
    for (raws) |descriptor| {
        var fixed: [5]Q = undefined;
        for (&fixed, Canonical.rawFixed(descriptor)) |*out, value| out.* = Q.fromBase(value);
        const main: [RawAir.MAIN_COUNT]Q = @splat(Q.one());
        const constraints = RawAir.Algebra(Q).constraints(fixed, main);
        for (0..RawAir.MAIN_COUNT) |column| {
            try std.testing.expect(constraints[2 * column].isZero());
            try std.testing.expectEqual(try Semantic.rawLive(descriptor, column), constraints[2 * column + 1].isZero());
        }
    }
    const FoldAir = Canonical.ForKind(.fold);
    for ([_]Fold.Kind{ .leaf, .branch, .empty, .root }) |kind| {
        const descriptor = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig").Descriptor{ .kind = kind, .height = if (kind == .root) 30 else if (kind == .branch) 1 else 0 };
        var fixed: [5]Q = undefined;
        for (&fixed, try Canonical.foldFixed(descriptor)) |*out, value| out.* = Q.fromBase(value);
        const main: [FoldAir.MAIN_COUNT]Q = @splat(Q.one());
        const constraints = FoldAir.Algebra(Q).constraints(fixed, main);
        for (0..FoldAir.MAIN_COUNT) |column| {
            try std.testing.expect(constraints[2 * column].isZero());
            try std.testing.expectEqual(try Semantic.foldLive(descriptor, column), constraints[2 * column + 1].isZero());
        }
    }
}
test "source unified PAGE: compact fold operand preserves full clocks routing and canonical enum bytes" {
    const before = (Hash.Frame{ .leaf = 7 }).nativeDigest();
    const after = (Hash.Frame{ .leaf = 9 }).nativeDigest();
    const operation = Fold.Operation{ .ordinal = 0x100000001, .kind = .leaf, .coordinate = .{ .height = 0, .index = 16 }, .value = .{ .before = before, .after = after }, .leaf = .{ .address = 64, .before = 7, .after = 9, .clock = 0xfedcba9876543210, .image = .rw, .image_ordinal = 0x123456789abcdef0, .touch_ordinal = 0x876543210fedcba9, .touched = true } };
    var bytes: [Store.RECORD_BYTES]u8 = undefined;
    try Store.encodeOperation(operation, &bytes);
    try std.testing.expect(std.meta.eql(operation, try Store.decodeOperation(&bytes)));
    bytes[105] = 2;
    try std.testing.expectError(error.InvalidSourceFoldOperandBoolean, Store.decodeOperation(&bytes));
    try Store.encodeOperation(operation, &bytes);
    bytes[104] = 3;
    try std.testing.expectError(error.InvalidSourceFoldOperandImage, Store.decodeOperation(&bytes));
    try Store.encodeOperation(operation, &bytes);
    bytes[8] = 4;
    try std.testing.expectError(error.InvalidSourceFoldOperandKind, Store.decodeOperation(&bytes));
}
fn emptyAdmission() !Batch.Admission {
    const digest = Initial.sha256("");
    const root = Defaults.get().defaults[0].bytes;
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
const EmptyCells = struct {
    bits: [2][Eq.BIT_COUNT]Q = undefined,
    fn init(self: *EmptyCells) !void {
        const digest = Defaults.get().defaults[0].bytes;
        try Eq.writeInputs(.{ .ordinal = 0, .kind = .empty, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = digest, .after = digest } }, &self.bits[0]);
        try Eq.writeInputs(.{ .ordinal = 1, .kind = .root, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = digest, .after = digest } }, &self.bits[1]);
    }
    fn read(context: *anyopaque, group: Semantic.Group, row: u32, column: u32) !M {
        const self: *EmptyCells = @ptrCast(@alignCast(context));
        if (group != .source or row >= 2 or column >= Eq.BIT_COUNT) return error.InvalidSourcePageCell;
        const coordinates = self.bits[row][column].toM31Array();
        for (coordinates[1..]) |value| if (!value.isZero()) return error.InvalidSourcePageBaseCell;
        return coordinates[0];
    }
};
fn emptyGraph(a: std.mem.Allocator) !*Semantic.Prepared {
    const admitted = try emptyAdmission();
    var claims = Semantic.Claims.zero();
    claims.fold.roots = Q.one();
    const rows = [_]Semantic.FoldRow{
        .{ .descriptor = .{ .kind = .empty, .height = 30 }, .recipes = &.{}, .first_compression = 0, .compressions = 0 },
        .{ .descriptor = .{ .kind = .root, .height = 30 }, .recipes = &.{}, .first_compression = 0, .compressions = 0 },
    };
    return Semantic.prepareFold(a, &admitted, &rows, @splat(13), sourceChallenges(), claims, 99, .{ .max_page_rows = 2, .max_inputs = 2048, .max_nodes = 100_000, .max_graph_bytes = 64 << 20, .max_arithmetic_rows = 100_000 });
}
test "source unified PAGE: genuine page graph direct arithmetic and all original input uses match authoritative lowering" {
    const a = std.testing.allocator;
    var cells = EmptyCells{};
    try cells.init();
    const graph = try emptyGraph(a);
    defer graph.deinit();
    try graph.readAndMaterialize(.{ .context = &cells, .read = EmptyCells.read }, .{});
    var routing = try Input.Plan.init(a, graph, .source, 1, .{});
    defer routing.deinit();
    try std.testing.expectEqual(graph.input_requests, routing.requests);
    var original_columns: [Eq.BIT_COUNT][2]M = undefined;
    var column_view: [Eq.BIT_COUNT][]const M = undefined;
    for (&original_columns, &column_view, 0..) |*column, *view, i| {
        column.* = .{ cells.bits[0][i].toM31Array()[0], cells.bits[1][i].toM31Array()[0] };
        // row_log1 logical/physical order coincides; no virtual domain.
        view.* = column;
    }
    const relations = Universal.UniversalRelations.dummy();
    const wire = relations.get(.recursion_wire);
    var interaction = try Input.generate(a, &routing, &column_view, .{ .z = wire.z, .powers = wire.alpha_powers[0..6].* }, .{});
    defer interaction.deinit();
    var supplied = Q.zero();
    for (interaction.claim.sums) |sum| supplied = supplied.add(sum);
    var lanes: [2]Lower.Lane = undefined;
    const reference = try graph.reference(&lanes);
    const evaluation = Lower.Evaluation{ .circuit_identity = graph.identity, .values = graph.values };
    const evaluations = [_]Lower.Evaluation{ evaluation, evaluation };
    const independently_derived = try graph.lowering.?.inputBoundaryClaim(a, reference, .{ .lanes = &evaluations }, .segment_leaf, &relations);
    try std.testing.expect(supplied.eql(independently_derived));
    const original_use = graph.cells[0].uses;
    graph.cells[0].uses += 1;
    try std.testing.expectError(error.InvalidSourcePageInputInventory, Input.Plan.init(a, graph, .source, 1, .{}));
    graph.cells[0].uses = original_use;
    const column = graph.cells[0].column;
    cells.bits[0][column] = cells.bits[0][column].add(Q.one());
    const changed = try emptyGraph(a);
    defer changed.deinit();
    try std.testing.expectError(error.UnsatisfiedCircuit, changed.readAndMaterialize(.{ .context = &cells, .read = EmptyCells.read }, .{}));
}
fn graphFault(a: std.mem.Allocator) !void {
    const graph = try emptyGraph(a);
    defer graph.deinit();
    var routing = try Input.Plan.init(a, graph, .source, 1, .{});
    defer routing.deinit();
}
test "source unified PAGE: semantic graph and complete original input-routing every allocation failure releases owners" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, graphFault, .{});
}
test "source unified PAGE: complete original core tables capture input and arithmetic claim closure with independent fixed projection" {
    const a = std.testing.allocator;
    const B = @import("block_v5_memory_source_packed_blake_columns_v1.zig");
    const Cmp = @import("block_v5_memory_source_unified_page_components_v1.zig");
    const CmpFold = Cmp.ForKind(.fold);
    const Arithmetic = @import("block_v5_memory_source_page_arithmetic_columns_v1.zig").ForKind(.fold);
    const Interaction = @import("block_v5_memory_source_page_interaction_v1.zig").ForKind(.fold);
    const Matrix = B.Matrix;
    const graph = try emptyGraph(a);
    defer graph.deinit();
    var cells = EmptyCells{};
    try cells.init();
    try graph.readAndMaterialize(.{ .context = &cells, .read = EmptyCells.read }, .{});
    const descriptors = [_]Eq.Descriptor{ .{ .kind = .empty, .height = 30 }, .{ .kind = .root, .height = 30 } };
    var fixed = try Arithmetic.Fixed.init(a, graph, &descriptors, 1, 1, .{});
    defer fixed.deinit();
    var main = try Arithmetic.Main.init(a, graph, &fixed, .{});
    defer main.deinit();
    const core_setup = try B.Setup.create(a);
    defer core_setup.release();
    const arithmetic_setup = try Cmp.ArithmeticSetup.create(a);
    defer arithmetic_setup.release();
    const digest = Defaults.get().defaults[0].bytes;
    const operations = [_]Fold.Operation{
        .{ .ordinal = 0, .kind = .empty, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = digest, .after = digest } },
        .{ .ordinal = 1, .kind = .root, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = digest, .after = digest } },
    };
    const cores = try B.Columns.regenerateWithSetup(a, &operations, 1, .{}, core_setup);
    defer cores.deinit();
    var original = try Matrix.init(a, Eq.BIT_COUNT, 1);
    defer original.deinit();
    for (operations, 0..) |operation, i| {
        var bits: [Eq.BIT_COUNT]Q = undefined;
        var native: [Eq.BIT_COUNT]M = undefined;
        try Eq.writeInputs(operation, &bits);
        for (&native, bits) |*value, bit| value.* = bit.toM31Array()[0];
        try original.put(i, &native);
    }
    const relations = Universal.UniversalRelations.dummy();
    var generated = try Interaction.generate(a, .{
        .cores = cores,
        .source_main = original.columns,
        .capture_fixed = cores.capture_fixed.?.columns,
        .capture_main = cores.capture_main.?.columns,
        .source_log = 1,
        .capture_log = 1,
        .logical_source_rows = 2,
        .compressions = 0,
        .first_circuit = 1,
    }, &fixed, &main, &relations, arithmetic_setup, .{});
    defer generated.deinit();
    const geometry = CmpFold.Geometry{ .source_log = 1, .capture_log = 1, .core_logs = cores.geometry.logs, .arithmetic_logs = fixed.arithmetic.logs, .capture_requests = 0 };
    const owner = try CmpFold.Owner.init(a, graph, &fixed.plan, &fixed.arithmetic, &fixed.source_inputs, &fixed.capture_inputs, geometry, relations, generated.claims, core_setup, arithmetic_setup, .{});
    defer owner.deinit();
    try std.testing.expectEqual(@as(usize, 9), owner.composition.?.logs.len);
    try std.testing.expectEqual(@as(usize, Eq.BIT_COUNT), owner.composition.?.logs[1].len);
    try std.testing.expectEqual(@as(usize, 192), owner.composition.?.logs[5].len);
    // Original requester and provider kernel closure cannot cancel freely
    // against semantic arithmetic or a different page's wire namespace.
    var bad = generated.claims;
    bad.core[0] = bad.core[0].add(Q.one());
    bad.arithmetic[0] = bad.arithmetic[0].sub(Q.one());
    try std.testing.expectError(error.UnclosedSourcePageHashKernel, CmpFold.Owner.init(a, graph, &fixed.plan, &fixed.arithmetic, &fixed.source_inputs, &fixed.capture_inputs, geometry, relations, bad, core_setup, arithmetic_setup, .{}));
    bad = generated.claims;
    bad.arithmetic[0] = bad.arithmetic[0].add(Q.one());
    try std.testing.expectError(error.UnclosedSourcePageSemanticWires, CmpFold.Owner.init(a, graph, &fixed.plan, &fixed.arithmetic, &fixed.source_inputs, &fixed.capture_inputs, geometry, relations, bad, core_setup, arithmetic_setup, .{}));
}

//! Pure metadata and original OODS-equation oracles. No literal capture is
//! accepted, no PCS proof/guest/device execution occurs in these fixtures.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const R = @import("../recursion/air/composition_graph_recorder.zig");
const S = R.Scalar;
const NativeAdmission = @import("block_v5_native_capacity_recursive_admission_v1.zig");
const Admission = @import("block_v5_native_capacity_fused_recursive_admission_v1.zig");
const Fused = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Capacity = @import("block_v5_native_capacity_protocol_v1.zig");
const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const MemoryBus = @import("block_memory_relation_v2.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Components = @import("../recursion/air/block_v5_native_capacity_fused_components_v1.zig");
const Composition = @import("../recursion/air/block_v5_native_capacity_fused_composition_v1.zig");
const Statement = @import("../recursion/air/block_v5_native_capacity_fused_statement_v1.zig");
const Bus = @import("../recursion/block_v5_native_capacity_fused_recursive_public_bus_v1.zig");
const Recorder = @import("../recursion/air/blake3_native_recorder.zig");
const Replay = @import("../recursion/air/block_v5_native_capacity_fused_transcript_v1.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    shape: @import("../air/statement.zig").Blake3ExecutionStatement,
    native: NativeAdmission.Prepared,
    admitted: Admission.Prepared,
    claims: []Fused.Claim,
    memory: []Memory.Claim,
    word: Word.Challenges,
    bus: MemoryBus.Challenges,
    /// This is an equation/metadata fixture only. Independent seal/catalog
    /// admission intentionally remains invalid; no capture/Leaf positive test
    /// can use this fixture as cryptographic authority.
    fn init(self: *Fixture, a: std.mem.Allocator, rw: bool, rows: u32) !void {
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        const temp = self.arena.allocator();
        self.shape = @import("block_v5_native_capacity_fused_transport_fixture_v1.zig").shape(rw);
        self.shape.component_descs[0].log_size = @max(1, std.math.log2_int_ceil(u32, rows));
        self.shape.component_descs[0].n_rows = rows;
        self.shape.total_steps = rows;
        self.shape.public_data.clock = rows;
        self.shape.n_infra = 1;
        self.shape.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 2, .n_columns = @import("../infra_trace.zig").CLOCK_UPDATE_COLS };
        try self.shape.validateBlake3ExecutionWithExternal(0);
        const config = @import("block_v5_native_capacity_transport_fixture_v1.zig").config;
        const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 0x100000001, .cycle_count = rows };
        // Every pointer refers to real fixture-owned storage. These zero job/
        // policy identities deliberately fail cryptographic admission; they
        // are never passed to a positive capture, public Leaf or Stage path.
        self.native = .{
            .allocator = temp,
            .shape = &self.shape,
            .external_retirements = 0,
            .pin = .{
                .context = .{
                    .job_id = @splat(0),
                    .source_image_digest = @splat(0),
                    .program_root = self.shape.public_data.program_root.?.bytes,
                    .program_plan_digest = @splat(0),
                    .memory_plan_digest = @splat(0),
                    .initial_source_plan_digest = @splat(0),
                    .rw_endpoint_plan_digest = @splat(0),
                    .register_custody_mode = 1,
                    .register_endpoint_plan_digest = @splat(0),
                    .execution_index = 0,
                    .first_cycle = frame.global_first_cycle,
                    .last_cycle = frame.global_first_cycle + rows - 1,
                },
                .public_digest = @splat(0),
                .expected_id = @splat(0),
            },
            .template = try Capacity.Template.fromShape(&self.shape, 0, config, .rv32im_zkvm_v1, @splat(3)),
            .template_id = @splat(7),
            .index = 0,
            .sealed = .{
                .digest = @splat(17),
                .native_roster_digest = @splat(0),
                .native_template_catalog_digest = @splat(0),
                .expected_final_rw_root = @splat(0),
                .rw_endpoint_plan_digest = @splat(0),
                .register_endpoint_plan_digest = @splat(0),
                .register_custody_mode = 1,
                .program_first_roots = @splat(@splat(0)),
                .program_plan_digest = @splat(0),
                .program_root = self.shape.public_data.program_root.?.bytes,
                .initial_source_plan_digest = @splat(0),
                .counts = @splat(0),
                .memory_instance_count = 0,
                .execution_instance_count = 0,
            },
            .pins = .{
                .job_id = @splat(0),
                .source_image_digest = @splat(0),
                .program_root = self.shape.public_data.program_root.?.bytes,
                .program_plan_digest = @splat(0),
                .memory_plan_digest = @splat(0),
                .initial_source_plan_digest = @splat(0),
                .register_custody_mode = 1,
                .config = config,
                .counts = @splat(0),
            },
            .entries = &.{},
            .catalog = null,
            .limits = .{},
            .config = config,
            .logs = .{
                try Capacity.columnLogs(temp, &self.shape, 0, .fixed),
                try Capacity.columnLogs(temp, &self.shape, 0, .main),
                try Capacity.columnLogs(temp, &self.shape, 0, .interaction),
            },
        };
        const projections = try Source.slotsFromShapeForMode(temp, &self.shape, 0, 1);
        const slots = try Source.memorySlots(temp, &self.shape, 0, frame, 1);
        const access: [32]u8 = if (slots.len == 0) try Source.emptyWitnessRoot(1) else @splat(13);
        self.admitted = .{ .allocator = temp, .native = &self.native, .binding = .{ .template_id = @splat(7), .instance_id = @splat(11), .first_roots = .{ @splat(3), @splat(5) }, .sealed_digest = @splat(17), .exact_geometry_digest = try @import("block_v5_native_template_protocol_v3.zig").geometryDigest(&self.shape, 0), .open_sum = Q.zero() }, .frame = frame, .witness_root = access, .empty_entry = null, .projections = projections, .slots = slots, .logs = undefined, .tree_count = if (slots.len == 0) 3 else 4, .template_id = undefined, .config = self.native.config, .limits = .{} };
        self.admitted.logs[0] = self.native.logs[0];
        self.admitted.logs[1] = self.native.logs[1];
        self.admitted.logs[2] = if (slots.len == 0) try Fused.interactionLogs(temp, projections, slots) else try Fused.witnessLogs(temp, slots);
        self.admitted.logs[3] = if (slots.len == 0) try temp.alloc(u32, 0) else try Fused.interactionLogs(temp, projections, slots);
        self.admitted.template_id = try self.admitted.templateId();
        self.claims = try temp.alloc(Fused.Claim, projections.len);
        for (self.claims, projections, 0..) |*claim, slot, i| claim.* = .{ .row_count = slot.n_rows, .sum = scalar(3 + i) };
        self.memory = try temp.alloc(Memory.Claim, slots.len);
        for (self.memory, 0..) |*claim, i| claim.* = .{ .active_count = 1, .transition_sum = scalar(19 + i), .universal_sum = scalar(23 + i), .range_claims = @splat(scalar(29 + i)) };
        self.word = try Word.Challenges.draw(temp, self.native.sealed);
        self.bus = try MemoryBus.Challenges.draw(temp, self.native.sealed);
    }
    fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
fn scalar(seed: usize) Q {
    return Q.fromU32Unchecked(@intCast(seed + 1), @intCast(seed + 2), @intCast(seed + 3), @intCast(seed + 4));
}
const Samples = struct {
    trees: [][][]S,
    pub fn at(self: Samples, tree: usize, column: usize, sample: usize) !S {
        if (tree >= self.trees.len or column >= self.trees[tree].len or sample >= self.trees[tree][column].len) return error.InvalidTestMask;
        return self.trees[tree][column][sample];
    }
};
fn input(b: *R.Builder, a: std.mem.Allocator, values: *std.ArrayList(Q), value: Q) !S {
    const result = try b.input();
    try values.append(a, value);
    return result.value;
}
const Oracle = struct {
    arena: std.heap.ArenaAllocator,
    circuit: R.Circuit,
    inputs: []Q,
    values: []Q,
    quotient: u32,
    expected: Q,
    selector_input: usize,
    count_input: ?usize,
    pub fn deinit(self: *Oracle) void {
        self.circuit.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    fn evaluate(self: *Oracle) !Q {
        try self.circuit.evaluateInto(self.inputs, self.values);
        return self.values[self.quotient];
    }
};
fn oracle(a: std.mem.Allocator, fixture: *const Fixture) !Oracle {
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var owner = try Components.Owner.initForClaims(temp, &fixture.admitted, fixture.claims, fixture.memory, &fixture.word, &fixture.bus);
    defer owner.deinit();
    const all = owner.all(fixture.admitted.logs[0].len);
    const mask_log = core.verifier_types.compositionMaskLogSize(all.compositionLogDegreeBound(), try all.compositionLogSplit()) orelse return error.InvalidTestMask;
    const seed = scalar(71);
    const point = try core.circle.secureFieldPointFromRandomSeedChecked(seed);
    var points = try all.maskPoints(temp, point, mask_log, false);
    defer points.deinitDeep(temp);
    const concrete = try temp.alloc([][]Q, points.items.len);
    const symbolic = try temp.alloc([][]S, points.items.len);
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    const plan = try Capacity.Plan.fromShape(&fixture.shape, 0);
    var selector_input: ?usize = null;
    for (points.items, concrete, symbolic, 0..) |tree, *out, *symbols, t| {
        out.* = try temp.alloc([]Q, tree.len);
        symbols.* = try temp.alloc([]S, tree.len);
        for (tree, out.*, symbols.*, 0..) |column, *values, *syms, i| {
            values.* = try temp.alloc(Q, column.len);
            syms.* = try temp.alloc(S, column.len);
            for (values.*, syms.*, 0..) |*value, *sym, j| {
                if (t == 1 and i == plan.shards[0].main_index and j == 0) selector_input = inputs.items.len;
                value.* = scalar(10 + t * 113 + i * 7 + j);
                sym.* = try input(&builder, temp, &inputs, value.*);
            }
        }
    }
    var draws: [Universal.RELATION_COUNT][2]S = undefined;
    for (&draws, fixture.word.universal_prefix.elements) |*pair, element| {
        pair[0] = try input(&builder, temp, &inputs, element.z);
        pair[1] = try input(&builder, temp, &inputs, element.alpha);
    }
    var word_draws: [10]S = undefined;
    inline for (.{ fixture.word.transition, fixture.word.link, fixture.word.initial, fixture.word.endpoint, fixture.word.range16 }, 0..) |element, i| {
        word_draws[2 * i] = try input(&builder, temp, &inputs, element.z);
        word_draws[2 * i + 1] = try input(&builder, temp, &inputs, element.alpha);
    }
    const public_values = try Composition.publicInputsFromClaims(temp, &fixture.admitted, fixture.claims, fixture.memory);
    const public = try temp.alloc(S, public_values.len);
    const public_start = inputs.items.len;
    for (public, public_values) |*sym, value| sym.* = try input(&builder, temp, &inputs, value);
    const random = scalar(17);
    const random_symbol = try input(&builder, temp, &inputs, random);
    const seed_symbol = try input(&builder, temp, &inputs, seed);
    var expected = core.air.accumulation.PointEvaluationAccumulator.init(random);
    const mask = core.air.components.MaskValues{ .items = concrete };
    var expected_count: usize = 0;
    for (owner.handles) |component| {
        try component.evaluateConstraintQuotientsAtPoint(point, &mask, &expected, mask_log);
        expected_count += component.nConstraints();
    }
    const expected_symbol = try input(&builder, temp, &inputs, expected.finalize());
    try builder.activate();
    var accumulated = S.zero();
    const count = Composition.recordConstraints(&fixture.admitted, Samples{ .trees = symbolic }, public, draws, word_draws, random_symbol, R.pointFromSeed(seed_symbol), mask_log, &accumulated) catch |err| return builder.failure orelse err;
    if (builder.failure) |failure| return failure;
    if (count != expected_count) return error.InvalidTestConstraintCount;
    const quotient = switch (accumulated.handle) {
        .node => |node| node,
        .constant => return error.InvalidTestConstraintCount,
    };
    builder.constrainZero(accumulated.sub(expected_symbol)) catch |err| return builder.failure orelse err;
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try temp.alloc(Q, circuit.nodes.len);
    var result = Oracle{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .values = values, .quotient = quotient, .expected = expected.finalize(), .selector_input = selector_input orelse return error.InvalidTestMask, .count_input = if (fixture.memory.len == 0) null else public_start + 8 + fixture.claims.len + 2 };
    try std.testing.expect((try result.evaluate()).eql(result.expected));
    return result;
}
test "capacity fused recursion: full original mixed-domain projections and optional access match symbolic OODS" {
    for ([_]bool{ false, true }) |rw| {
        var fixture: Fixture = undefined;
        try fixture.init(std.testing.allocator, rw, 3);
        defer fixture.deinit();
        try std.testing.expectError(error.MissingBlockV5RegisterEndpointPlan, fixture.native.validate(fixture.native.template_id));
        var graph = try oracle(std.testing.allocator, &fixture);
        defer graph.deinit();
        graph.inputs[graph.selector_input] = graph.inputs[graph.selector_input].add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, graph.evaluate());
        graph.inputs[graph.selector_input] = graph.inputs[graph.selector_input].sub(Q.one());
        if (graph.count_input) |index| {
            graph.inputs[index] = graph.inputs[index].add(Q.one());
            try std.testing.expectError(error.UnsatisfiedCircuit, graph.evaluate());
            graph.inputs[index] = graph.inputs[index].sub(Q.one());
        }
        try std.testing.expect((try graph.evaluate()).eql(graph.expected));
    }
}
fn allocationOracle(a: std.mem.Allocator, fixture: *const Fixture) !void {
    var graph = try oracle(a, fixture);
    defer graph.deinit();
}
test "capacity fused recursion: full equation construction propagates original OOM and unwinds" {
    var fixture: Fixture = undefined;
    try fixture.init(std.testing.allocator, true, 3);
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationOracle, .{&fixture});
}
test "capacity fused recursion: exact first and restarted Word52 claim framing preserve native channels" {
    for ([_]bool{ false, true }) |rw| {
        var fixture: Fixture = undefined;
        try fixture.init(std.testing.allocator, rw, 3);
        defer fixture.deinit();
        var statement = try Statement.Statement.initClaims(std.testing.allocator, &fixture.admitted, fixture.claims, fixture.memory);
        defer statement.deinit();
        var first = core.proof_suites.Blake3.Channel{};
        try statement.replay(&first, statement.first);
        var original = Fused.firstChannel(fixture.admitted.binding.template_id, fixture.admitted.binding.instance_id, 0, fixture.admitted.projections, fixture.admitted.slots);
        for (fixture.admitted.binding.first_roots) |root| original.mixRoot(root);
        if (rw) original.mixRoot(fixture.admitted.witness_root);
        try std.testing.expectEqualDeep(original, first);
        var replay = try Fused.proofChannel(std.testing.allocator, fixture.native.sealed);
        try statement.replay(&replay, statement.claims);
        var expected = try Fused.proofChannel(std.testing.allocator, fixture.native.sealed);
        try Fused.mixClaims(&expected, fixture.admitted.binding.template_id, fixture.admitted.binding.instance_id, 0, fixture.admitted.projections, fixture.admitted.slots, fixture.claims, fixture.memory);
        try std.testing.expectEqualDeep(expected, replay);
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var recorder = Recorder.Recorder{ .a = arena.allocator(), .universal_relations = true };
        const draws = try Replay.prefix(arena.allocator(), &recorder, &fixture.admitted, &statement);
        try std.testing.expectEqualDeep(fixture.word, draws);
        try std.testing.expectEqualDeep(expected, recorder.native);
        try std.testing.expectEqual(@as(usize, 52), recorder.relation_count);
        try std.testing.expectEqual(fixture.admitted.tree_count - 1, recorder.root_count);
        try std.testing.expectError(error.InvalidNativeBlake3Transcript, recorder.skipCommittedRoots(2));
    }
}
fn cloneOracle(a: std.mem.Allocator, fixture: *const Fixture) !void {
    var statement = try Statement.Statement.initClaims(a, &fixture.admitted, fixture.claims, fixture.memory);
    defer statement.deinit();
    const public = try Composition.publicInputsFromClaims(a, &fixture.admitted, fixture.claims, fixture.memory);
    defer a.free(public);
    const values = Bus.Values{ .allocator = a, .template = fixture.admitted.template_id, .statement = statement, .public = public, .roots_count = fixture.admitted.tree_count - 1 };
    var clone = try values.clone(a);
    defer clone.deinit();
    try clone.validate();
}
test "capacity fused recursion: public statement owning clones survive source release and allocation failures" {
    var fixture: Fixture = undefined;
    try fixture.init(std.testing.allocator, true, 3);
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, cloneOracle, .{&fixture});
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    var live = true;
    defer if (live) arena.deinit();
    const a = arena.allocator();
    const statement = try Statement.Statement.initClaims(a, &fixture.admitted, fixture.claims, fixture.memory);
    const values = Bus.Values{ .allocator = a, .template = fixture.admitted.template_id, .statement = statement, .public = try Composition.publicInputsFromClaims(a, &fixture.admitted, fixture.claims, fixture.memory), .roots_count = 3 };
    var owned = try values.clone(std.testing.allocator);
    defer owned.deinit();
    var before = core.proof_suites.Blake3.Channel{};
    owned.mix(&before);
    var original_mix = core.proof_suites.Blake3.Channel{};
    original_mix.mixU32s(&.{ 0x42355949, 1, @intCast(owned.roots_count), @intCast(owned.statement.words.len), @intCast(owned.statement.felts.len), @intCast(owned.public.len) });
    original_mix.mixRoot(owned.template);
    original_mix.mixU32s(owned.statement.words);
    original_mix.mixFelts(owned.statement.felts);
    original_mix.mixFelts(owned.public);
    try std.testing.expectEqualDeep(original_mix, before);
    arena.deinit();
    live = false;
    var after = core.proof_suites.Blake3.Channel{};
    owned.mix(&after);
    try std.testing.expectEqualDeep(before, after);
    owned.statement.words[0] ^= 1;
    var changed = core.proof_suites.Blake3.Channel{};
    owned.mix(&changed);
    try std.testing.expect(!std.meta.eql(before, changed));
}
test "capacity fused recursion: geometry key reuses changed logical counts but separates optional access" {
    var first: Fixture = undefined;
    try first.init(std.testing.allocator, true, 3);
    defer first.deinit();
    var second: Fixture = undefined;
    // Both admitted counts share physical log2; rows2 would independently
    // require log1 and therefore represent a different reusable template.
    try second.init(std.testing.allocator, true, 4);
    defer second.deinit();
    var empty: Fixture = undefined;
    try empty.init(std.testing.allocator, false, 3);
    defer empty.deinit();
    try std.testing.expectEqualDeep(first.admitted.template_id, second.admitted.template_id);
    try std.testing.expect(!std.meta.eql(first.admitted.template_id, empty.admitted.template_id));
    var a = try Statement.Statement.initClaims(std.testing.allocator, &first.admitted, first.claims, first.memory);
    defer a.deinit();
    var b = try Statement.Statement.initClaims(std.testing.allocator, &second.admitted, second.claims, second.memory);
    defer b.deinit();
    try std.testing.expect(!std.mem.eql(u32, a.words, b.words));
}
test "capacity fused recursion: wide public schedule stays strict and requires exact coordinates" {
    const wires = [_]Bus.Wire{ .{ .circuit = 1500, .wire = 70000, .uses = 1, .source = .public_input, .coordinate = 70000 }, .{ .circuit = 4_200_010, .wire = 90000, .uses = 2, .source = .word, .coordinate = 90000 } };
    const actual = try Bus.scheduleDigest(&wires);
    var original = core.proof_suites.Blake3.Channel{};
    original.mixU32s(&.{ 0x42355957, 1, wires.len });
    for (wires) |wire| original.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, @intFromEnum(wire.source), wire.coordinate });
    try std.testing.expectEqualDeep(original.digestBytes(), actual);
    try std.testing.expectError(error.InvalidFusedRecursivePublicSchedule, Bus.scheduleDigest(&.{ wires[1], wires[0] }));
    try std.testing.expectError(error.InvalidFusedRecursivePublicSchedule, Bus.scheduleDigest(&.{ wires[0], wires[0] }));
    var changed = wires;
    changed[1].uses = 0;
    try std.testing.expectError(error.InvalidFusedRecursivePublicSchedule, Bus.scheduleDigest(&changed));
}

test "capacity fused recursion: exact public extents reject caps before allocation in both root layouts" {
    for ([_]bool{ false, true }) |rw| {
        var fixture: Fixture = undefined;
        try fixture.init(std.testing.allocator, rw, 3);
        defer fixture.deinit();
        const extent = try Statement.extent(&fixture.admitted);
        var statement = try Statement.Statement.initClaims(std.testing.allocator, &fixture.admitted, fixture.claims, fixture.memory);
        defer statement.deinit();
        try std.testing.expectEqual(extent.words, statement.words.len);
        try std.testing.expectEqual(extent.felts, statement.felts.len);
        try std.testing.expectEqual(extent.first_steps, statement.first.len);
        try std.testing.expectEqual(extent.claim_steps, statement.claims.len);
        try std.testing.expectEqual(try Composition.publicCount(fixture.admitted.projections.len, fixture.admitted.slots.len), extent.public_inputs);
        fixture.admitted.limits.fused.max_metadata_bytes = extent.bytes;
        _ = try Statement.extent(&fixture.admitted);
        fixture.admitted.limits.fused.max_metadata_bytes -= 1;
        // A zero-capacity allocator would report OOM if any allocation occurs.
        var storage: [0]u8 = .{};
        var forbidden = std.heap.FixedBufferAllocator.init(&storage);
        try std.testing.expectError(error.CapacityFusedRecursiveResourceLimit, Statement.Statement.initClaims(forbidden.allocator(), &fixture.admitted, fixture.claims, fixture.memory));
    }
}

const Deep = @import("../recursion/air/pcs_deep_circuit.zig");
const Layout = @import("../recursion/sample_point_layout.zig");
const PhysicalDeep = struct {
    logs: [2]u32 = .{ 5, 7 },
    layouts: [2]Deep.SamplePointLayout = .{ .current_keccak_final, .current_previous },
    mask_logs: [2]u32 = .{ 4, 6 },
    fn profile(self: *const PhysicalDeep, trees: *[1]Deep.TreeProfile) Deep.Profile {
        trees.* = .{.{ .column_log_sizes = &self.logs }};
        return .{ .trees = trees, .sample_layouts = &self.layouts, .mask_log_sizes = &self.mask_logs, .lifting_log_size = 7, .log_blowup_factor = 1, .query_count = 2 };
    }
};
fn shiftedGraphAllocation(a: std.mem.Allocator) !void {
    var geometry: PhysicalDeep = .{};
    var trees: [1]Deep.TreeProfile = undefined;
    var graph = try Deep.build(a, geometry.profile(&trees));
    defer graph.deinit();
    try graph.validate();
}
test "capacity fused recursion: physical Keccak pair DEEP matches native periodicity and rejects mutations" {
    const legacy_trees = [_]Deep.TreeProfile{ .{ .column_log_sizes = &.{ 4, 3 } }, .{ .column_log_sizes = &.{4} } };
    const legacy = Deep.Profile{ .trees = &legacy_trees, .sample_layouts = &.{ .current_previous, .none, .current }, .lifting_log_size = 5, .log_blowup_factor = 1, .query_count = 2 };
    var legacy_digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&legacy_digest, "5f09c85ec7740797e2484932d802136d57d26e456a1338386cfe5aebb06076bb");
    try std.testing.expectEqualSlices(u8, &legacy_digest, &legacy.identityDigest());
    var geometry: PhysicalDeep = .{};
    var trees: [1]Deep.TreeProfile = undefined;
    const profile = geometry.profile(&trees);
    const seed = scalar(73);
    const current = try core.circle.secureFieldPointFromRandomSeedChecked(seed);
    const physical = core.poly.circle.CanonicCoset.new(4).step();
    const common = core.poly.circle.CanonicCoset.new(6).step();
    const physical_step = core.circle.CirclePointQM31{ .x = Q.fromBase(physical.x), .y = Q.fromBase(physical.y) };
    const common_step = core.circle.CirclePointQM31{ .x = Q.fromBase(common.x), .y = Q.fromBase(common.y) };
    var first_points = [_]core.circle.CirclePointQM31{ current, current.add(physical_step.mulSigned(27)) };
    var second_points = [_]core.circle.CirclePointQM31{ current, current.sub(common_step) };
    try std.testing.expectEqual(Deep.SamplePointLayout.current_keccak_final, try Layout.classifyKeccakPair(&first_points, current, current.sub(physical_step)));
    try std.testing.expectError(error.SamplePointLayoutMismatch, Layout.classifyColumn(&first_points, current, current.sub(common_step)));
    var point_columns = [_][]core.circle.CirclePointQM31{ &first_points, &second_points };
    var point_trees = [_][][]core.circle.CirclePointQM31{&point_columns};
    var log_trees = [_][]u32{&geometry.logs};
    var first_samples = [_]Q{ scalar(101), scalar(103) };
    var second_samples = [_]Q{ scalar(107), scalar(109) };
    var sample_columns = [_][]Q{ &first_samples, &second_samples };
    var sample_trees = [_][][]Q{&sample_columns};
    var first_queries = [_]M{ M.fromCanonical(11), M.fromCanonical(13) };
    var second_queries = [_]M{ M.fromCanonical(17), M.fromCanonical(19) };
    var query_columns = [_][]M{ &first_queries, &second_queries };
    var query_trees = [_][][]M{&query_columns};
    const positions = [_]usize{ 3, 97 };
    const raw = [_]M{ M.fromCanonical(3), M.fromCanonical(97) };
    const randomness = scalar(79);
    const answers = try core.pcs.quotients.friAnswers(std.testing.allocator, core.pcs.TreeVec([]u32).initOwned(&log_trees), core.pcs.TreeVec([][]core.circle.CirclePointQM31).initOwned(&point_trees), core.pcs.TreeVec([][]Q).initOwned(&sample_trees), randomness, &positions, core.pcs.TreeVec([][]M).initOwned(&query_trees), 7);
    defer std.testing.allocator.free(answers);
    var graph = try Deep.build(std.testing.allocator, profile);
    defer graph.deinit();
    var samples = first_samples ++ second_samples;
    const queries = first_queries ++ second_queries;
    const witness = Deep.Witness{ .active = true, .sampled_values = &samples, .queried_values = &queries, .oods_seed = seed, .deep_randomness = randomness, .raw_queries = &raw, .answers = answers };
    var evaluated = try graph.evaluate(std.testing.allocator, witness);
    defer evaluated.deinit();
    try evaluated.validateAgainst(&graph);
    samples[1] = samples[1].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.evaluate(std.testing.allocator, witness));
    samples[1] = first_samples[1];
    // This is the capture input-geometry adapter only, never a verifier seal
    // or a proof-acceptance fixture. It checks the same points as the graph.
    const arithmetic_capture = .{ .column_log_sizes = &log_trees, .sampled_points = &point_trees, .sampled_values = &samples, .queries = .{ .raw = &positions }, .deep_answers = answers, .queried_values = &queries, .oods_seed = seed, .deep_randomness = randomness };
    var captured = try @import("../recursion/pcs_arithmetic_capture.zig").Owned.init(std.testing.allocator, profile, arithmetic_capture);
    defer captured.deinit();
    const identity = profile.identityDigest();
    geometry.mask_logs[0] = 5;
    try std.testing.expectError(error.InvalidProfile, profile.validate());
    try std.testing.expect(!std.meta.eql(identity, profile.identityDigest()));
    geometry.mask_logs[0] = 4;
    first_points[1] = current.add(common_step.mulSigned(27));
    try std.testing.expectError(error.SamplePointLayoutMismatch, Layout.classifyKeccakPair(&first_points, current, current.sub(physical_step)));
    try std.testing.expectError(error.InvalidPcsArithmeticCapture, @import("../recursion/pcs_arithmetic_capture.zig").Owned.init(std.testing.allocator, profile, arithmetic_capture));
    std.mem.swap(core.circle.CirclePointQM31, &first_points[0], &first_points[1]);
    try std.testing.expectError(error.SamplePointLayoutMismatch, Layout.classifyKeccakPair(&first_points, current, current.sub(physical_step)));
    // The graph retained its own immutable physical-log vector.
    geometry.mask_logs[0] = 3;
    try graph.validate();
    try std.testing.expectEqual(@as(u32, 4), graph.profile().maskLogSize(0));
}
test "capacity fused recursion: shifted DEEP graph construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, shiftedGraphAllocation, .{});
}

test "capacity fused recursion: hash sizing admits exactly four or five consistently bound trees" {
    const CaptureType = core.verifier.ProofCapture(core.proof_suites.Blake3.Hasher);
    const Paths = @typeInfo(@FieldType(CaptureType, "trace_paths")).pointer.child;
    const Layers = @typeInfo(@FieldType(@FieldType(CaptureType, "fri"), "layers")).pointer.child;
    var log: [1]u32 = .{2};
    var logs: [5][]u32 = @splat(&log);
    var paths: [5]Paths = @splat(std.mem.zeroes(Paths));
    var roots: [5][32]u8 = @splat(@splat(3));
    var layers: [1]Layers = .{std.mem.zeroes(Layers)};
    layers[0].fold_step = 1;
    layers[0].fold_width = 1;
    // Sizing only. This deliberately is not a valid cryptographic capture,
    // cannot reach State.plan, and does not authenticate the proposed roots.
    var capture = std.mem.zeroes(CaptureType);
    capture.column_log_sizes = &logs;
    capture.trace_paths = &paths;
    capture.commitments = &roots;
    capture.fri.layers = &layers;
    const HashLayout = @import("../recursion/blake3_native_hash_layout.zig");
    _ = try HashLayout.Layout.init(std.testing.allocator, .{ .g = 0, .xor = 0 }, &capture);
    capture.trace_paths = paths[0..4];
    try std.testing.expectError(error.InvalidNativeHashLayout, HashLayout.Layout.init(std.testing.allocator, .{ .g = 0, .xor = 0 }, &capture));
    capture.column_log_sizes = logs[0..4];
    capture.commitments = roots[0..4];
    _ = try HashLayout.Layout.init(std.testing.allocator, .{ .g = 0, .xor = 0 }, &capture);
    capture.trace_paths = paths[0..3];
    capture.column_log_sizes = logs[0..3];
    capture.commitments = roots[0..3];
    try std.testing.expectError(error.InvalidNativeHashLayout, HashLayout.Layout.init(std.testing.allocator, .{ .g = 0, .xor = 0 }, &capture));
}

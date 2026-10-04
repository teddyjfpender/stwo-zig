//! Source construction/ownership fixtures, never verified child receipts. The
//! authenticated arithmetic graphs and exact typed input schedules exercise the
//! canonical source preparers without executing guests or proving a STARK.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Storage = @import("../blake3_parent_row_storage.zig");
const Source = @import("../blake3_direct_source_columns_v1.zig");
const Owned = @import("../blake3_upstream_source_columns_v1.zig");
const Deep = @import("../pcs_deep_circuit.zig");
const Fri = @import("../fri_verifier_circuit.zig");
const NativeDeep = @import("../blake3_native_deep.zig");
const NativeFri = @import("../blake3_native_fri.zig");
const Native = @import("../blake3_native_transcript.zig");
const Transcript = @import("../blake3_transcript_witness.zig");
const Plan = @import("../blake3_transcript_plan.zig").Plan;
const Graph = @import("../composition_circuit.zig");
const Vm = @import("../../vm_air_composition_circuit.zig");
const Recorder = @import("../composition_graph_recorder.zig");
const Execution = @import("../blake3_execution_composition.zig");
const Payload = @import("../blake3_native_payload_links.zig");
const Samples = @import("../blake3_native_sample_links.zig");
const Challenges = @import("../blake3_native_pcs_challenges.zig");
const Public = @import("../blake3_native_public_links.zig");
const Boundary = @import("../blake3_native_public_boundary.zig");
const Terminal = @import("../blake3_native_terminal_encoding.zig");
const ExecutionPayload = @import("../blake3_execution_payloads.zig");
const ExecutionChallenges = @import("../blake3_execution_challenges.zig");
const Authority = @import("../../segment_public_native_sum_authority_v2.zig");
const Arithmetic = @import("../../arithmetic_circuit.zig");
const zero_q = [_]Q{Q.zero()};
const zero_m = [_]M{M.zero()};
const pair_q = [_]Q{ Q.zero(), Q.zero() };
const layers_q = [_][]const Q{&pair_q};
const layers_m = [_][]const M{&zero_m};
const deep_logs = [_]u32{2};
const deep_trees = [_]Deep.TreeProfile{.{ .column_log_sizes = &deep_logs }};
const deep_layouts = [_]Deep.SamplePointLayout{.current};
const widths = [_]u32{2};
const deep_witness = Deep.Witness{ .active = false, .sampled_values = &zero_q, .queried_values = &zero_m, .oods_seed = Q.zero(), .deep_randomness = Q.zero(), .raw_queries = &zero_m, .answers = &zero_q };
const fri_witness = Fri.Witness{ .active = false, .deep_answers = &zero_q, .authenticated_values = &layers_q, .fri_alphas = &zero_q, .raw_queries = &zero_m, .fri_positions = &layers_m, .fri_offsets = &layers_m, .last_layer_positions = &zero_m, .last_layer_coefficients = &zero_q };

const Operations = struct {
    arena: std.heap.ArenaAllocator,
    operations: []Transcript.Operation,
    plan: Plan,
    fn deinit(self: *@This()) void {
        self.plan.deinit();
        self.arena.deinit();
    }
    fn init(a: std.mem.Allocator, native: bool) !@This() {
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const output = arena.allocator();
        var operations: std.ArrayList(Transcript.Operation) = .empty;
        const claim_count: usize = if (native) @import("../../../air/transcript/claims.zig").COMPONENT_COUNT else 1;
        // Reverse the receipts. Logical output order must remain claim/sample
        // index order rather than the receipt enumeration order.
        try operations.append(output, .{ .routed_felts = .{ .values = &zero_q, .source = Native.SAMPLE_SOURCE } });
        for (0..claim_count) |reverse| {
            const claim = claim_count - reverse - 1;
            try operations.append(output, .{ .routed_felts = .{ .values = &zero_q, .source = .{ .circuit = @import("../blake3_native_recorder.zig").CLAIM_CIRCUIT, .first_wire = @intCast(claim * 4) } } });
        }
        const relation_count: usize = if (native) @import("../../../air/relation_challenges.zig").RELATION_COUNT else 1;
        for (0..relation_count) |index| try operations.append(output, .{ .secure = .{ .output = if (native) .{ .riscv_relation = index } else .{ .universal = index }, .attempts = 0, .consumption = .two, .values = @splat(M.zero()) } });
        for ([_]Transcript.OutputRole{ .composition, .oods, .deep, .{ .fri = 0 } }) |role| try operations.append(output, .{ .secure = .{ .output = role, .attempts = 0, .values = @splat(M.zero()) } });
        try operations.append(output, .{ .routed_felts = .{ .values = &zero_q, .source = Native.TERMINAL_SOURCE } });
        const plan = try Plan.initCompact(a, .{ .namespace = 9_000_001, .attempt_capacity = 1 }, operations.items);
        return .{ .arena = arena, .operations = operations.items, .plan = plan };
    }
};
fn nativeTranscript(a: std.mem.Allocator) !Native.Prepared {
    var operations = try Operations.init(a, true);
    errdefer operations.deinit();
    // Source fixtures need exact independent fixed/live inventories. This is
    // schedule preprocessing, not authentication of the supplied draw values.
    const live = try Transcript.trustedBoundedCompact(a, 9_000_001, operations.operations, 1);
    return .{ .arena = operations.arena, .operations = operations.operations, .claim_payloads = &.{}, .plan = operations.plan, .live = live, .end = .{} };
}
fn executionTranscript(a: std.mem.Allocator) !Native.Planned {
    const operations = try Operations.init(a, false);
    return .{ .arena = operations.arena, .operations = operations.operations, .claim_payloads = &.{}, .plan = operations.plan, .end = .{} };
}
fn nativeGraph(a: std.mem.Allocator) !Vm.Prepared {
    const profile = Graph.InputProfile{ .sampled_value_count = 1, .claimed_sum_count = 0, .relation_challenge_count = @import("../../../air/relation_challenges.zig").RELATION_COUNT, .transcript_claimed_sum_count = @import("../../../air/transcript/claims.zig").COMPONENT_COUNT };
    const count = try Graph.vmInputCount(profile);
    const nodes = try a.alloc(Graph.Node, count);
    defer a.free(nodes);
    @memset(nodes, .{ .op = .input });
    const bindings = try a.alloc(Graph.VmInputBinding, count);
    defer a.free(bindings);
    for (bindings, 0..) |*binding, index| binding.* = .{ .node_id = @intCast(index), .source = Graph.expectedVmSource(profile, index) orelse return error.InvalidFixture };
    const inputs = try a.alloc(M, count);
    defer a.free(inputs);
    @memset(inputs, M.zero());
    const outputs = [_]u32{0};
    const graph = try Graph.CircuitGraph.authenticate(nodes, &outputs, Graph.computeGraphDigest(nodes, &outputs));
    return Vm.Prepared.initFromAuthenticatedLaneV2(a, .{ .circuit_id = Vm.CIRCUIT_ID, .graph = graph, .profile = profile, .bindings = bindings }, @splat(3), inputs);
}
fn executionGraph(a: std.mem.Allocator) !Execution.Prepared {
    var builder = Recorder.Builder.init(a);
    defer builder.deinit();
    var inputs: [10]Recorder.Input = undefined;
    for (&inputs) |*input| input.* = try builder.input();
    try builder.activate();
    for (inputs) |input| try builder.constrainZero(input.value);
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const output = arena.allocator();
    const concrete = try output.alloc(Q, inputs.len);
    @memset(concrete, Q.zero());
    const values = try output.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(concrete, values);
    const sources = try output.dupe(Execution.Source, &.{ .{ .sample = 0 }, .{ .claim = 0 }, .{ .challenge = 0 }, .{ .challenge = 1 }, .composition, .oods, .{ .packed_public_input = 0 }, .{ .packed_public_input = 1 }, .{ .packed_public_input = 2 }, .{ .packed_public_input = 3 } });
    var prepared = Execution.Prepared{ .arena = arena, .circuit = circuit, .inputs = concrete, .sources = sources, .values = values, .key_id = @splat(1), .capture_seal = @splat(2), .seal = undefined };
    prepared.seal = prepared.identity();
    return prepared;
}
fn publicBoundary(a: std.mem.Allocator) !Boundary.Prepared {
    var builder = Arithmetic.Builder.initDefault(a);
    defer builder.deinit();
    for (0..Authority.INPUT_SUFFIX_WORD_COUNT) |index| {
        const value = try builder.input(@intCast(index));
        if (index == 0) _ = try builder.markOutput(value);
    }
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    var graph = try Authority.NativeOwnedGraph.init(a, &circuit);
    errdefer graph.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const output = arena.allocator();
    const values = try output.alloc(Q, Authority.INPUT_SUFFIX_WORD_COUNT);
    @memset(values, Q.zero());
    const bindings = try output.alloc(Authority.InputSourceV2, values.len);
    for (bindings, 0..) |*binding, index| binding.* = try Authority.nativeInputSource(0, 0, index);
    const evaluation = try circuit.evaluate(a, values);
    return .{ .arena = arena, .circuit = circuit, .graph = graph, .evaluation = evaluation, .wire_count = 0, .memory_byte_count = 0, .inputs = values, .bindings = bindings };
}
const Fixture = struct {
    deep: NativeDeep.Prepared,
    fri: NativeFri.Prepared,
    native: Native.Prepared,
    execution: Native.Planned,
    vm: Vm.Prepared,
    composition: Execution.Prepared,
    boundary: Boundary.Prepared,
    fn deinit(self: *@This()) void {
        self.boundary.deinit();
        self.composition.deinit();
        self.vm.deinit();
        self.execution.deinit();
        self.native.deinit();
        self.fri.deinit();
        self.deep.deinit();
    }
    fn init(a: std.mem.Allocator) !@This() {
        var dg = try Deep.build(a, .{ .trees = &deep_trees, .sample_layouts = &deep_layouts, .lifting_log_size = 2, .log_blowup_factor = 1, .query_count = 1 });
        errdefer dg.deinit();
        var de = try dg.evaluate(a, deep_witness);
        errdefer de.deinit();
        var fg = try Fri.build(a, .{ .lifting_log_size = 2, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .fold_widths = &widths, .query_count = 1 });
        errdefer fg.deinit();
        var fe = try fg.evaluate(a, fri_witness);
        errdefer fe.deinit();
        var links = try @import("../blake3_terminal_links.zig").build(a, &dg, &fg, 1, 1);
        errdefer links.deinit();
        var native = try nativeTranscript(a);
        errdefer native.deinit();
        var execution = try executionTranscript(a);
        errdefer execution.deinit();
        var vm = try nativeGraph(a);
        errdefer vm.deinit();
        var composition = try executionGraph(a);
        errdefer composition.deinit();
        const boundary = try publicBoundary(a);
        return .{ .boundary = boundary, .composition = composition, .vm = vm, .native = native, .execution = execution, .deep = .{ .graph = dg, .evaluation = de, .inputs = .{ .arena = std.heap.ArenaAllocator.init(a), .inputs = deep_witness } }, .fri = .{ .arena = std.heap.ArenaAllocator.init(a), .graph = fg, .evaluation = fe, .inputs = .{ .arena = std.heap.ArenaAllocator.init(a), .inputs = fri_witness }, .links = links, .sources = &.{}, .fixed_sources = &.{}, .destinations = &.{}, .fixed_destinations = &.{} } };
    }
};
fn parity(comptime slot: usize, rows: []const Storage.Airs[slot].Row, fixed: []const Storage.Airs[slot].Row, columns: anytype) !void {
    const view = try columns.view(slot);
    try std.testing.expectEqual(rows.len, view.rowCount());
    for (rows, fixed, 0..) |row, trusted, index| {
        try std.testing.expectEqualDeep(row, view.rowAt(index));
        try std.testing.expectEqualDeep(Storage.compactFixed(Storage.Airs[slot], trusted), columns.owners[
            comptime switch (slot) {
                12 => 0,
                11 => 1,
                10 => 2,
                else => unreachable,
            }
        ].fixed[index]);
    }
}
fn checkSources(a: std.mem.Allocator, fixture: *const Fixture) !void {
    var payload_rows = try Payload.prepare(a, &fixture.vm, &fixture.native, 1500);
    defer payload_rows.deinit();
    var payload = try Payload.prepareColumns(a, &fixture.vm, &fixture.native, 1500);
    defer payload.deinit();
    try parity(12, payload_rows.scalars, payload_rows.fixed_scalars, &payload.columns.?);
    try parity(11, payload_rows.packing, payload_rows.fixed_packing, &payload.columns.?);
    try parity(10, payload_rows.encoded, payload_rows.fixed_encoded, &payload.columns.?);
    var sample_rows = try Samples.prepare(a, &fixture.vm, &payload_rows, &fixture.deep, 1500, 1502);
    defer sample_rows.deinit();
    var samples = try Samples.prepareColumns(a, &fixture.vm, &payload, &fixture.deep, 1500, 1502);
    defer samples.deinit();
    const sample_view = try samples.columns.?.view(12);
    for (sample_rows.sources, 0..) |row, index| try std.testing.expectEqualDeep(row, sample_view.rowAt(index));
    for (sample_rows.destinations, 0..) |row, index| try std.testing.expectEqualDeep(row, sample_view.rowAt(sample_rows.sources.len + index));
    var challenge_rows = try Challenges.prepare(a, &fixture.vm, &fixture.native, &fixture.deep, &fixture.fri, .{ 1500, 1502, 1504 });
    defer challenge_rows.deinit();
    var challenges = try Challenges.prepareColumns(a, &fixture.vm, &fixture.native, &fixture.deep, &fixture.fri, .{ 1500, 1502, 1504 });
    defer challenges.deinit();
    try parity(12, &challenge_rows.composition.?.rows, &challenge_rows.composition.?.fixed, &challenges.composition_columns.?);
    try parity(12, challenge_rows.rows, challenge_rows.fixed, &challenges.columns.?);
    var public_rows = try Public.prepareRows(a, &fixture.vm, &fixture.boundary, &challenge_rows, &payload_rows);
    defer public_rows.deinit();
    var public = try Public.prepare(a, &fixture.vm, &fixture.boundary, &challenges, &payload);
    defer public.deinit();
    var counts = Source.Counts{};
    inline for (.{ Public.Prepared.Part.composition, .challenges, .claims, .totals, .destinations }) |part| try public.appendPart(part, &counts);
    var legacy = Storage.Builder.init(a);
    defer legacy.deinit();
    try legacy.append(12, public_rows.composition_rows, public_rows.fixed_composition);
    try legacy.append(12, public_rows.challenge_rows, public_rows.fixed_challenges);
    try legacy.append(12, public_rows.claim_sources, public_rows.fixed_claims);
    try legacy.append(12, public_rows.total_sources, public_rows.fixed_total_sources);
    try legacy.append(12, public_rows.destinations, public_rows.fixed_destinations);
    try parity(12, legacy.rows[12].items, legacy.rows[12].items, &public.columns.?);
    // Inventory source ordering is unchanged despite per-part borrowed views.
    try std.testing.expectEqual(legacy.rows[12].items.len, counts.counts[12]);
    var unused_rows = Storage.Builder.init(a);
    defer unused_rows.deinit();
    var destination = try Source.Builder.init(a, &unused_rows, counts.counts);
    defer destination.deinit();
    inline for (.{ Public.Prepared.Part.composition, .challenges, .claims, .totals, .destinations }) |part| try public.appendPart(part, &destination);
    var prepared = Storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..Storage.Airs.len) |slot| prepared.fixed[slot] = &.{};
    defer prepared.deinit();
    try destination.takeInto(&prepared.main, &prepared.fixed);
    const scattered = try @import("../blake3_recursive_column_rows_v1.zig").ForAir(Storage.Airs[12]).init(prepared.main[12], prepared.fixed[12]);
    for (legacy.rows[12].items, 0..) |row, index| try std.testing.expectEqualDeep(row, scattered.rowAt(index));
    try std.testing.expectEqual(@as(usize, 0), unused_rows.rows[12].capacity);
    try std.testing.expectEqual(@as(usize, 0), unused_rows.fixed[12].capacity);
    var terminal_rows = try Terminal.prepare(a, &fixture.execution, &fixture.fri, 1504);
    defer terminal_rows.deinit();
    var terminal = try Terminal.prepareColumns(a, &fixture.execution, &fixture.fri, 1504);
    defer terminal.deinit();
    const ts = try terminal.columns.?.view(12);
    const tp = try terminal.columns.?.view(11);
    const te = try terminal.columns.?.view(10);
    for (terminal_rows.rows, 0..) |row, index| {
        for (row.scalars, 0..) |source, word| try std.testing.expectEqualDeep(source, ts.rowAt(4 * index + word));
        try std.testing.expectEqualDeep(row.packing, tp.rowAt(index));
        try std.testing.expectEqualDeep(row.encoded, te.rowAt(index));
    }
    var claims_rows = try ExecutionPayload.prepareRows(a, &fixture.composition, &fixture.execution, &fixture.deep, 1500, 1502, 5_000_012);
    defer claims_rows.deinit();
    var claims = try ExecutionPayload.prepare(a, &fixture.composition, &fixture.execution, &fixture.deep, 1500, 1502, 5_000_012);
    defer claims.deinit();
    try parity(12, claims_rows.claim_sources, claims_rows.fixed_claim_sources, &claims.columns.?);
    try parity(11, claims_rows.claim_packs, claims_rows.fixed_claim_packs, &claims.columns.?);
    try parity(10, claims_rows.encoded, claims_rows.fixed_encoded, &claims.columns.?);
    var execution_rows = try ExecutionChallenges.prepareRowsForRelations(1, a, &fixture.composition, &fixture.execution, &fixture.deep, &fixture.fri, .{ 1500, 1502, 1504 }, 5_000_003);
    defer execution_rows.deinit();
    var execution = try ExecutionChallenges.prepareForRelations(1, a, &fixture.composition, &fixture.execution, &fixture.deep, &fixture.fri, .{ 1500, 1502, 1504 }, 5_000_003);
    defer execution.deinit();
    try parity(12, execution_rows.rows, execution_rows.fixed, &execution.columns.?);
    try parity(11, execution_rows.packs, execution_rows.fixed_packs, &execution.columns.?);
    const nested = @import("../block_v5_open_parent_packed_sources_v2.zig");
    const terms = [_]@import("../../block_v5_open_child_frames_v2.zig").Term{.{ .circuit = 4_200_003, .wire = 0, .uses = 1, .coordinates = @splat(M.zero()) }};
    try nested.testing.attachTermsForParity(&claims_rows, &fixture.composition, &terms);
    try nested.testing.attachTermsForParity(&claims, &fixture.composition, &terms);
    const extra = try claims.nested_columns.?.view(12);
    const extra_packs = try claims.nested_columns.?.view(11);
    for (claims_rows.claim_sources[4..], 0..) |row, index| try std.testing.expectEqualDeep(row, extra.rowAt(index));
    try std.testing.expectEqualDeep(claims_rows.claim_packs[1], extra_packs.rowAt(0));
    try std.testing.expectError(error.InvalidV5NestedPackedSource, nested.testing.attachTermsForParity(&claims, &fixture.composition, &terms));
    try payload.releaseNodeMap();
    try std.testing.expectEqual(@as(usize, 0), payload.nodes.len);
}
test "upstream direct source columns preserve native execution claim challenge and terminal schedules" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try checkSources(std.testing.allocator, &fixture);
}
test "upstream direct source columns release every failed preparer allocation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkSources, .{&fixture});
}
test "upstream direct source columns reject duplicate missing out of bounds and late indexed emission" {
    const Columns = Owned.ForSlots(.{12});
    var columns = try Columns.init(std.testing.allocator, .{3});
    defer columns.deinit();
    const Scalar = Storage.Airs[12];
    const row = try Scalar.logicalRow(1500, 1, 2, M.fromCanonical(3));
    try columns.put(12, 2, row);
    try std.testing.expectError(error.InvalidUpstreamSourceColumns, columns.put(12, 2, row));
    try std.testing.expectError(error.InvalidUpstreamSourceColumns, columns.put(12, 3, row));
    try std.testing.expectError(error.DirectRecursiveRowCountMismatch, columns.finish());
    try std.testing.expectError(error.InvalidUpstreamSourceColumns, columns.view(12));
    try columns.put(12, 0, row);
    try columns.put(12, 1, row);
    try columns.finish();
    for (columns.seen) |mask| try std.testing.expectEqual(@as(usize, 0), mask.len);
    try std.testing.expectError(error.InvalidUpstreamSourceColumns, columns.put(12, 0, row));
    const view = try columns.view(12);
    try std.testing.expectEqualDeep(row, (try view.subview(1, 2)).rowAt(1));
    try std.testing.expectError(error.InvalidNativeParentRows, view.subview(2, 2));
    var forged = view;
    forged.first = std.math.maxInt(usize);
    var counts = Source.Counts{};
    try std.testing.expectError(error.InvalidNativeParentRows, counts.appendBorrowed(12, forged));
    try std.testing.expectEqual(@as(usize, 0), counts.counts[12]);
    forged = view;
    forged.log += 1;
    try std.testing.expectError(error.InvalidNativeParentRows, counts.appendBorrowed(12, forged));
    var legacy = Storage.Builder.init(std.testing.allocator);
    defer legacy.deinit();
    var builder = try Source.Builder.init(std.testing.allocator, &legacy, counts.counts);
    defer builder.deinit();
    try std.testing.expectError(error.InvalidNativeParentRows, builder.appendBorrowed(12, forged));
}
fn reject(expected: anyerror, result: anytype) !void {
    if (result) |value| {
        var owner = value;
        owner.deinit();
        return error.TestUnexpectedError;
    } else |err| {
        if (err == error.OutOfMemory) return err;
        try std.testing.expectEqual(expected, err);
    }
}
fn drawOperation(transcript: anytype, role: std.meta.Tag(Transcript.OutputRole)) !usize {
    for (transcript.operations, 0..) |operation, index| if (operation == .secure) {
        if (operation.secure.output) |output| if (std.meta.activeTag(output) == role) return index;
    };
    return error.InvalidFixture;
}
fn feltOperation(transcript: anytype, circuit: u32) !usize {
    for (transcript.operations, 0..) |operation, index| if (operation == .routed_felts and operation.routed_felts.source.circuit == circuit) return index;
    return error.InvalidFixture;
}
test "upstream direct source columns reject changed native claim sample and transcript exports" {
    const a = std.testing.allocator;
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    var payload = try Payload.prepareColumns(a, &fixture.vm, &fixture.native, 1500);
    defer payload.deinit();
    var challenges = try Challenges.prepareColumns(a, &fixture.vm, &fixture.native, &fixture.deep, &fixture.fri, .{ 1500, 1502, 1504 });
    defer challenges.deinit();
    const source_owner = &payload.columns.?.owners[0];
    const framework = @import("../framework_interaction.zig");
    const sample_index = @import("../../../air/transcript/claims.zig").COMPONENT_COUNT * 4;
    const sample_at = framework.committedRow(sample_index, source_owner.log);
    source_owner.mutable_main[0][sample_at] = M.one();
    try reject(error.InvalidNativeSampleLink, Samples.prepareColumns(a, &fixture.vm, &payload, &fixture.deep, 1500, 1502));
    source_owner.mutable_main[0][sample_at] = M.zero();
    const claim_at = framework.committedRow(0, source_owner.log);
    source_owner.mutable_main[0][claim_at] = M.one();
    try reject(error.InvalidNativePublicLink, Public.prepare(a, &fixture.vm, &fixture.boundary, &challenges, &payload));
    source_owner.mutable_main[0][claim_at] = M.zero();
    const receipt_index = try feltOperation(&fixture.native, @import("../blake3_native_recorder.zig").CLAIM_CIRCUIT);
    const receipt = fixture.native.operations[receipt_index];
    fixture.native.operations[receipt_index].routed_felts.source.first_wire += 1;
    try reject(error.InvalidNativePayloadLink, Payload.prepareColumns(a, &fixture.vm, &fixture.native, 1500));
    fixture.native.operations[receipt_index] = receipt;
    const deep_index = try drawOperation(&fixture.native, .deep);
    fixture.native.operations[deep_index].secure.values[0] = M.one();
    try reject(error.InvalidNativePcsChallenge, Challenges.prepareColumns(a, &fixture.vm, &fixture.native, &fixture.deep, &fixture.fri, .{ 1500, 1502, 1504 }));
    fixture.native.operations[deep_index].secure.values[0] = M.zero();
}
test "upstream direct source columns reject changed execution claim challenge terminal and mixed source mode" {
    const a = std.testing.allocator;
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    const one_q = [_]Q{Q.one()};
    const claim = try feltOperation(&fixture.execution, @import("../blake3_native_recorder.zig").CLAIM_CIRCUIT);
    const original_claim = fixture.execution.operations[claim];
    fixture.execution.operations[claim].routed_felts.values = &one_q;
    try reject(error.InvalidExecutionPayload, ExecutionPayload.prepare(a, &fixture.composition, &fixture.execution, &fixture.deep, 1500, 1502, 5_000_012));
    fixture.execution.operations[claim] = original_claim;
    const terminal_index = try feltOperation(&fixture.execution, Native.TERMINAL_SOURCE.circuit);
    const original_terminal = fixture.execution.operations[terminal_index];
    fixture.execution.operations[terminal_index].routed_felts.values = &one_q;
    try reject(error.InvalidNativeTerminalEncoding, Terminal.prepareColumns(a, &fixture.execution, &fixture.fri, 1504));
    fixture.execution.operations[terminal_index] = original_terminal;
    const deep_index = try drawOperation(&fixture.execution, .deep);
    fixture.execution.operations[deep_index].secure.values[0] = M.one();
    try reject(error.InvalidExecutionChallenge, ExecutionChallenges.prepareForRelations(1, a, &fixture.composition, &fixture.execution, &fixture.deep, &fixture.fri, .{ 1500, 1502, 1504 }, 5_000_003));
    fixture.execution.operations[deep_index].secure.values[0] = M.zero();
    var rows = try ExecutionPayload.prepareRows(a, &fixture.composition, &fixture.execution, &fixture.deep, 1500, 1502, 5_000_012);
    defer rows.deinit();
    var columns = try ExecutionPayload.prepare(a, &fixture.composition, &fixture.execution, &fixture.deep, 1500, 1502, 5_000_012);
    defer columns.deinit();
    var counts = Source.Counts{};
    columns.claim_sources = rows.claim_sources;
    try std.testing.expectError(error.InvalidExecutionPayload, columns.appendClaims(&counts));
    columns.claim_sources = &.{};
    try std.testing.expectEqual(@as(usize, 0), counts.counts[12]);
    const nested = @import("../block_v5_open_parent_packed_sources_v2.zig");
    const bad_terms = [_]@import("../../block_v5_open_child_frames_v2.zig").Term{.{ .circuit = 4_200_003, .wire = 0, .uses = 1, .coordinates = .{ M.one(), M.zero(), M.zero(), M.zero() } }};
    try std.testing.expectError(error.UntrustedV5NestedPackedSource, nested.testing.attachTermsForParity(&columns, &fixture.composition, &bad_terms));
    try std.testing.expect(columns.nested_columns == null);
}

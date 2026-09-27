//! Typed source construction only. Captured routing metadata below is not a
//! fresh proof receipt; independent parent-body fixtures exercise admission.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Fixture = @import("blake3_pcs_source_columns_test.zig").Fixture;
const Opening = @import("blake3_opening_inputs.zig");
const Queries = @import("blake3_native_queries.zig");
const Projection = @import("blake3_projection_links.zig");
const PCS = @import("blake3_pcs_source_columns_v1.zig");
const Source = @import("blake3_direct_source_columns_v1.zig");
const Storage = @import("blake3_parent_row_storage.zig");
const Upstream = @import("blake3_upstream_source_columns_v1.zig");
const roots = @import("blake3_execution_roots.zig");
const T = @import("blake3_transcript_witness.zig");
const Native = @import("blake3_native_transcript.zig");
const Plan = @import("blake3_transcript_plan.zig").Plan;
const RootSource = @import("blake3_root_sources.zig");
const capture_layers = [_]struct { path_depth: u32, fold_step: u32 }{.{ .path_depth = 1, .fold_step = 1 }};
const capture = .{ .column_log_sizes = &[_][]const u32{&.{2}}, .queries = .{ .raw = &[_]usize{0} }, .fri = .{ .layers = &capture_layers } };
fn compare(comptime slot: usize, owner: anytype, rows: []const Storage.Airs[slot].Row, fixed: []const Storage.Airs[slot].Row) !void {
    const view = try owner.view(slot);
    try std.testing.expectEqual(rows.len, view.rowCount());
    for (rows, fixed, 0..) |row, trusted, index| {
        try std.testing.expectEqualDeep(row, view.rowAt(index));
        try std.testing.expectEqualDeep(Storage.compactFixed(Storage.Airs[slot], trusted), view.fixed[index]);
    }
}
fn appendInput(input: *const Opening.Prepared, sink: anytype) !void {
    inline for (.{ 2, 10, 11, 16, 17 }) |slot| try input.appendCohort(slot, sink);
    try input.projection.appendRoutes(sink);
}
fn checkInputs(a: std.mem.Allocator, f: *const Fixture) !void {
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    var output = std.heap.ArenaAllocator.init(a);
    defer output.deinit();
    var oracle_arena = std.heap.ArenaAllocator.init(a);
    defer oracle_arena.deinit();
    var query = try Queries.prepare(a, &f.transcript, &f.deep, &f.fri);
    defer query.deinit();
    var builder = try Opening.Builder.initColumns(scratch.allocator(), output.allocator(), a, capture, &f.deep.graph, &f.fri.graph, &query.links);
    defer builder.deinit();
    var oracle = try Opening.Builder.init(oracle_arena.allocator(), capture, &f.deep.graph, &f.fri.graph, &query.links);
    defer oracle.deinit();
    try std.testing.expectError(error.InvalidOpeningInput, builder.trace(std.math.maxInt(usize), 0, 0, 0, M.zero(), 0, 1));
    try builder.trace(0, 0, 0, 0, M.zero(), 0, 1);
    try oracle.trace(0, 0, 0, 0, M.zero(), 0, 1);
    try std.testing.expectError(error.InvalidOpeningInput, builder.trace(0, 0, 0, 0, M.zero(), 0, 1));
    const pair: [2]Q = @splat(Q.zero());
    const uses: [8]u32 = @splat(1);
    try builder.friGroup(0, 0, &pair, 4, &uses);
    try oracle.friGroup(0, 0, &pair, 4, &uses);
    var actual = try builder.finish();
    defer actual.deinitColumns();
    var expected = try oracle.finish();
    defer expected.deinitColumns();
    try std.testing.expectEqualDeep(expected.sources, actual.sources);
    try std.testing.expectEqualDeep(expected.projection.bit_reads, actual.projection.bit_reads);
    try std.testing.expectEqualDeep(expected.projection.ports, actual.projection.ports);
    try compare(2, &actual.columns.?, expected.sentinels, expected.sentinels);
    try compare(10, &actual.columns.?, expected.encoded, expected.fixed_encoded);
    try compare(16, &actual.columns.?, expected.readonly_rows, expected.fixed_readonly_rows);
    try compare(17, &actual.columns.?, expected.adapter_rows, expected.fixed_adapter_rows);
    const pack_count = actual.columns.?.count(11);
    try compare(11, &actual.columns.?, expected.packing[0..pack_count], expected.fixed_packed[0..pack_count]);
    try compare(11, &actual.projection.columns.?, expected.packing[pack_count..], expected.fixed_packed[pack_count..]);
    try compare(7, &actual.projection.columns.?, expected.projection.routed, expected.projection.fixed_routed);
    var counts = Source.Counts{};
    var oracle_counts = Source.Counts{};
    try appendInput(&actual, &counts);
    try appendInput(&expected, &oracle_counts);
    try std.testing.expectEqualDeep(oracle_counts.counts, counts.counts);
    const before = counts.counts;
    actual.adapter_rows = expected.adapter_rows;
    try std.testing.expectError(error.InvalidOpeningInput, actual.appendCohort(17, &counts));
    try std.testing.expectEqualDeep(before, counts.counts);
    actual.adapter_rows = &.{};
    var legacy = Storage.Builder.init(a);
    defer legacy.deinit();
    var sink = try Source.Builder.init(a, &legacy, counts.counts);
    defer sink.deinit();
    try appendInput(&actual, &sink);
    inline for (.{ 2, 7, 10, 11, 16, 17 }) |slot| {
        try std.testing.expectEqual(@as(usize, 0), legacy.rows[slot].capacity);
        try std.testing.expectEqual(@as(usize, 0), legacy.fixed[slot].capacity);
    }
    var admitted_sources = try PCS.Openings.init(a, actual.sources, &f.deep, &f.fri);
    defer admitted_sources.deinit();
    actual.releaseSources();
    try std.testing.expectEqual(@as(usize, 0), actual.sources.len);
    try std.testing.expect(actual.source_allocator == null);
    // Released tuples do not invalidate committed byte/readonly/packing owners.
    try compare(16, &actual.columns.?, expected.readonly_rows, expected.fixed_readonly_rows);
}
test "direct path sources preserve packing byte readonly adapter sentinel schedule and release tuple roster" {
    var f = try Fixture.init(std.testing.allocator);
    defer f.deinit();
    try checkInputs(std.testing.allocator, &f);
}
test "direct path sources release every failed routing emission and owner transfer" {
    var f = try Fixture.init(std.testing.allocator);
    defer f.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkInputs, .{&f});
}
fn checkProjection(a: std.mem.Allocator, f: *const Fixture) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var oracle_arena = std.heap.ArenaAllocator.init(a);
    defer oracle_arena.deinit();
    var query = try Queries.prepare(a, &f.transcript, &f.deep, &f.fri);
    defer query.deinit();
    // Repeated logs share a projected producer but retain their exact use mass;
    // log5 exercises a partial final pack, log9 adds a third affine chunk.
    const logs = [_]u32{ 2, 5, 9, 5 };
    const raw = [_]usize{ 0, 39, 511 };
    const links = [_]@import("blake3_query_links.zig").Query{query.links.queries[0]} ** 3;
    var actual = try Projection.buildColumns(arena.allocator(), a, 9, &logs, &raw, &links);
    defer actual.deinitColumns();
    var expected = try Projection.build(oracle_arena.allocator(), 9, &logs, &raw, &links);
    defer expected.deinitColumns();
    try compare(11, &actual.columns.?, expected.packing, expected.fixed_packed);
    try compare(7, &actual.columns.?, expected.routed, expected.fixed_routed);
    try std.testing.expectEqualDeep(expected.bit_reads, actual.bit_reads);
    try std.testing.expectEqualDeep(expected.ports, actual.ports);
    const before = actual.columns.?.count(7);
    var counts = Source.Counts{};
    actual.routed = expected.routed;
    try std.testing.expectError(error.InvalidProjectionLink, actual.appendRoutes(&counts));
    try std.testing.expectEqual(@as(usize, 0), counts.counts[7]);
    actual.routed = &.{};
    try actual.appendRoutes(&counts);
    try std.testing.expectEqual(before, counts.counts[7]);
}
test "projected query packing shares repeated logs and preserves multi chunk affine links" {
    var f = try Fixture.init(std.testing.allocator);
    defer f.deinit();
    try checkProjection(std.testing.allocator, &f);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkProjection, .{&f});
}
test "upstream fixed recipe mismatch and missing indexed rows never publish" {
    var columns = try Upstream.ForSlots(.{2}).init(std.testing.allocator, .{2});
    defer columns.deinit();
    const Air = Storage.Airs[2];
    const row: Air.Row = @splat(M.zero());
    var fixed = row;
    fixed[Air.PHYSICAL_MAIN_COLUMN_COUNT] = M.one();
    try std.testing.expectError(error.InvalidNativeParentRows, columns.putFixed(2, 0, row, fixed));
    try std.testing.expectEqual(@as(usize, 0), columns.owners[0].next);
    try columns.putFixed(2, 1, row, row);
    try std.testing.expectError(error.InvalidUpstreamSourceColumns, columns.view(2));
    try std.testing.expectError(error.DirectRecursiveRowCountMismatch, columns.finish());
    try columns.putFixed(2, 0, row, row);
    try columns.finish();
    try std.testing.expectError(error.InvalidUpstreamSourceColumns, columns.putFixed(2, 0, row, row));
}
const commitments: [4][32]u8 = .{ @splat(7), @splat(11), @splat(19), @splat(23) };
const fri_root: [32]u8 = @splat(29);
const nonce_source = T.Caller{ .circuit = 4_100_001, .first_wire = 2 };
const root_layers = [_]struct { commitment: [32]u8 }{.{ .commitment = fri_root }};
const proof = .{ .commitments = &commitments, .fri = .{ .layers = &root_layers }, .queries = .{ .raw = &[_]usize{ 0, 1, 2 } }, .proof_of_work = @as(u64, 0x1_0000_0007) };
fn checkRoots(a: std.mem.Allocator) !void {
    for ([_]bool{ false, true }) |joint| {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        var operations: std.ArrayList(T.Operation) = .empty;
        const temp = arena.allocator();
        for ((if (joint) @as(usize, 2) else 0)..5) |index| try operations.append(temp, .{ .routed_root = .{ .source = try RootSource.caller(index), .value = if (index < 4) commitments[index] else fri_root } });
        try operations.append(temp, .{ .pow = .{ .bits = 0, .nonce = proof.proof_of_work, .nonce_source = nonce_source } });
        try operations.append(temp, .{ .routed_integer = .{ .value = proof.proof_of_work, .source = nonce_source } });
        var plan = try Plan.initCompact(a, .{ .namespace = 9_000_701, .attempt_capacity = 1 }, operations.items);
        defer plan.deinit();
        // Borrowed plan/operation aggregate used only by source constructors.
        // It is not a verifier-created transcript or STARK receipt.
        const transcript = Native.Planned{ .arena = arena, .operations = operations.items, .claim_payloads = &.{}, .plan = plan, .end = .{} };
        var actual = try roots.prepareCaptured(a, proof, commitments[0], .{ .pow_bits = 0, .fri_config = core.fri.FriConfig.default() }, &transcript, joint);
        defer actual.deinit();
        var expected = try roots.prepareCapturedRows(a, proof, commitments[0], .{ .pow_bits = 0, .fri_config = core.fri.FriConfig.default() }, &transcript, joint);
        defer expected.deinit();
        const key_view = try actual.columns.?.view(2);
        for (expected.key, 0..) |row, index| try std.testing.expectEqualDeep(row, key_view.rowAt(index));
        if (expected.joint_main) |main| for (main, 0..) |row, index| try std.testing.expectEqualDeep(row, key_view.rowAt(8 + index));
        try compare(9, &actual.columns.?, expected.words, expected.fixed_words);
        var counts = Source.Counts{};
        var expected_counts = Source.Counts{};
        try actual.appendKey(&counts);
        try actual.appendMain(&counts);
        try actual.appendWords(&counts);
        try expected.appendKey(&expected_counts);
        try expected.appendMain(&expected_counts);
        try expected.appendWords(&expected_counts);
        try std.testing.expectEqualDeep(expected_counts.counts, counts.counts);
        try actual.skipFirstWords(8);
        try expected.skipFirstWords(8);
        try std.testing.expectEqual(expected.wordCount(), actual.wordCount());
        try std.testing.expectError(error.InvalidExecutionRoots, actual.skipFirstWords(actual.wordCount() + 1));
        actual.word_skip = actual.columns.?.count(9) + 1;
        try std.testing.expectError(error.InvalidNativeRootNonce, actual.appendWords(&counts));
        actual.word_skip = 8;
        if (!joint) {
            const main: [8]Storage.Airs[2].Row = @splat(@splat(M.zero()));
            try actual.attachMain(a, main);
            try expected.attachMain(a, main);
            try std.testing.expectError(error.InvalidExecutionRoots, actual.attachMain(a, main));
        }
        actual.external_key = true;
        var skipped = Source.Counts{};
        try actual.appendKey(&skipped);
        try std.testing.expectEqual(@as(usize, 0), skipped.counts[2]);
        const changed = .{ .commitments = proof.commitments, .fri = proof.fri, .queries = proof.queries, .proof_of_work = proof.proof_of_work + 1 };
        if (roots.prepareCaptured(a, changed, commitments[0], .{ .pow_bits = 0, .fri_config = core.fri.FriConfig.default() }, &transcript, joint)) |owner| {
            var invalid = owner;
            invalid.deinit();
            return error.TestUnexpectedError;
        } else |err| {
            if (err == error.OutOfMemory) return err;
            try std.testing.expectEqual(error.InvalidExecutionRoots, err);
        }
    }
}
test "direct root nonce and joint main source schedule preserves tails rejects source swaps and releases failures" {
    try checkRoots(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkRoots, .{});
}

const PublicSources = @import("blake3_native_public_sources.zig");
const PublicBoundary = @import("blake3_native_public_boundary.zig");
const Authority = @import("../segment_public_native_sum_authority_v2.zig");
const Arithmetic = @import("../arithmetic_circuit.zig");
const Statement = @import("../../air/statement_v2.zig");
const Data = @import("../../air/public_data_v2.zig");
const ByteLayout = @import("../segment_register_byte_layout_v1.zig");
const PublicFixture = struct {
    a: std.mem.Allocator,
    words: []M,
    data: Data.PublicDataV2,
    boundary: PublicBoundary.Prepared,
    transcript: Native.Prepared,
    fn deinit(self: *@This()) void {
        self.transcript.deinit();
        self.boundary.deinit();
        self.a.free(self.words);
    }
    fn init(a: std.mem.Allocator) !@This() {
        var fixture = try @import("../../air/public_data_v2_test_support.zig").Fixture.initWithRegister7(0x11223344);
        const source = fixture.leftSource();
        const words = try @import("../../air/public_data_v2_test_support.zig").encode(a, &source);
        errdefer a.free(words);
        const data = try Data.PublicDataV2.authenticate(words);
        const view = try data.authenticatedView();
        const layout = try ByteLayout.MemoryLayout.init(&view);
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const temp = arena.allocator();
        const n = try std.math.add(usize, try std.math.add(usize, words.len, Authority.INPUT_SUFFIX_WORD_COUNT), try std.math.mul(usize, 2, layout.memoryByteCount()));
        const inputs = try temp.alloc(Q, n);
        const bindings = try temp.alloc(Authority.InputSourceV2, n);
        var builder = Arithmetic.Builder.initDefault(a);
        defer builder.deinit();
        for (inputs, bindings, 0..) |*input, *binding, index| {
            binding.* = try Authority.nativeInputSource(@intCast(words.len), @intCast(layout.memoryByteCount()), index);
            const value: M = switch (binding.*) {
                .wire_word => |word| words[word],
                .register_byte => |byte| ByteLayout.value(words, byte),
                .memory_byte => |byte| layout.value(words, ByteLayout.BYTE_COUNT + byte),
                .memory_selector => |byte| M.fromCanonical(@intFromBool(layout.value(words, ByteLayout.BYTE_COUNT + byte).v != 0)),
                .published_sum_word => |coordinate| M.fromCanonical(@intCast(17 + 4 * @intFromEnum(coordinate.domain) + coordinate.limb)),
                .published_total_word, .native_challenge_word => M.zero(),
            };
            input.* = Q.fromBase(value);
            _ = try builder.input(@intCast(index));
        }
        // Input-schedule source oracle, not an authenticated native arithmetic
        // statement: its zero output permits testing all producer coordinates.
        const zero = builder.constant(Q.zero());
        _ = try builder.markOutput(zero);
        var circuit = try builder.finish();
        errdefer circuit.deinit();
        var graph = try Authority.NativeOwnedGraph.init(a, &circuit);
        errdefer graph.deinit();
        var evaluation = try circuit.evaluate(a, inputs);
        errdefer evaluation.deinit();
        var operations_arena = std.heap.ArenaAllocator.init(a);
        errdefer operations_arena.deinit();
        var recorder = @import("blake3_native_recorder.zig").Recorder{ .a = operations_arena.allocator() };
        core.pcs.PcsConfig.default().mixInto(&recorder);
        try Statement.mixIntoNativeTranscript(&data, &recorder);
        try recorder.check();
        var plan = try Plan.initCompact(a, .{ .namespace = 9_000_703, .attempt_capacity = 1 }, recorder.operations.items);
        errdefer plan.deinit();
        const live = try T.trustedBoundedCompact(a, 9_000_703, recorder.operations.items, 1);
        return .{ .a = a, .words = words, .data = data, .boundary = .{ .arena = arena, .circuit = circuit, .graph = graph, .evaluation = evaluation, .wire_count = @intCast(words.len), .memory_byte_count = @intCast(layout.memoryByteCount()), .inputs = inputs, .bindings = bindings }, .transcript = .{ .arena = operations_arena, .operations = recorder.operations.items, .claim_payloads = &.{}, .plan = plan, .live = live, .end = .{} } };
    }
};
fn checkPublic(a: std.mem.Allocator, fixture: *const PublicFixture) !void {
    // Only public_data is read by this source constructor. The envelope's VM
    // geometry and authority are intentionally absent; it is never admitted.
    const statement = Statement.RiscVStatementV2{ .public_data = fixture.data, .core = undefined, .authority_id = undefined };
    var actual = try PublicSources.prepare(a, &statement, core.pcs.PcsConfig.default(), &fixture.transcript, &fixture.boundary);
    defer actual.deinit();
    var oracle = try PublicSources.prepareRows(a, &statement, core.pcs.PcsConfig.default(), &fixture.transcript, &fixture.boundary);
    defer oracle.deinit();
    try compare(2, &actual.columns.?, oracle.rows, oracle.fixed_rows);
    try compare(12, &actual.columns.?, oracle.sums, oracle.fixed_sums);
    try std.testing.expectEqual(oracle.statement_operation, actual.statement_operation);
    var counts = Source.Counts{};
    var expected = Source.Counts{};
    try actual.appendCoordinates(&counts);
    try actual.appendSums(&counts);
    try oracle.appendCoordinates(&expected);
    try oracle.appendSums(&expected);
    try std.testing.expectEqualDeep(expected.counts, counts.counts);
    const prior = counts.counts;
    actual.rows = oracle.rows;
    try std.testing.expectError(error.InvalidNativePublicSource, actual.appendCoordinates(&counts));
    try std.testing.expectEqualDeep(prior, counts.counts);
    actual.rows = &.{};
    // Exact public encoder words remain independently checked even when
    // source fields and the retained arithmetic graph are unchanged.
    const operations = try a.dupe(T.Operation, fixture.transcript.operations);
    defer a.free(operations);
    const changed_words = try a.dupe(u32, operations[actual.statement_operation].words);
    defer a.free(changed_words);
    changed_words[changed_words.len - 1] ^= 1;
    operations[actual.statement_operation].words = changed_words;
    var changed_transcript = fixture.transcript;
    changed_transcript.operations = operations;
    if (PublicSources.prepare(a, &statement, core.pcs.PcsConfig.default(), &changed_transcript, &fixture.boundary)) |value| {
        var owner = value;
        owner.deinit();
        return error.TestUnexpectedError;
    } else |err| {
        if (err == error.OutOfMemory) return err;
        try std.testing.expectEqual(error.InvalidNativePublicSource, err);
    }
}
test "direct public coordinates and sixteen sum limbs preserve canonical encodings and release every failed allocation" {
    var fixture = try PublicFixture.init(std.testing.allocator);
    defer fixture.deinit();
    try checkPublic(std.testing.allocator, &fixture);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkPublic, .{&fixture});
}

const Paths = @import("blake3_stark_paths.zig");
const Capture = core.verifier.ProofCapture(@import("../blake3_engine_protocol.zig").Hasher);
fn codegenPaths(a: std.mem.Allocator, captured: *const Capture, deep: *const @import("pcs_deep_circuit.zig").Circuit, fri: *const @import("fri_verifier_circuit.zig").Circuit, queries: *@import("blake3_query_links.zig").Prepared) anyerror!Paths.Prepared {
    return Paths.prepare(a, captured, deep, fri, queries);
}
fn codegenPathOracle(a: std.mem.Allocator, captured: *const Capture, deep: *const @import("pcs_deep_circuit.zig").Circuit, fri: *const @import("fri_verifier_circuit.zig").Circuit, queries: *@import("blake3_query_links.zig").Prepared) anyerror!Paths.Prepared {
    return Paths.prepareRows(a, captured, deep, fri, queries);
}
fn codegenPublic(a: std.mem.Allocator, statement: *const Statement.RiscVStatementV2, transcript: *const Native.Prepared, boundary: *const PublicBoundary.Prepared) anyerror!PublicSources.Prepared {
    return PublicSources.prepare(a, statement, core.pcs.PcsConfig.default(), transcript, boundary);
}
test "direct path and public source canonical captured bodies compile" {
    // Actual typed constructors are emitted without inventing a verified
    // capture or invoking a proof, guest, device, worker or segment.
    inline for (.{ &codegenPaths, &codegenPathOracle, &codegenPublic }) |function| std.mem.doNotOptimizeAway(function);
}

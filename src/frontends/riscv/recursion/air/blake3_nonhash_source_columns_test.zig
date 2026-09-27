//! Construction/parity checks only. Host Merkle snapshots in this file are not
//! fresh proof receipts; actual native/execution parent bodies are emitted by
//! the imported body root without dispatching STARK or guest execution.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Storage = @import("blake3_parent_row_storage.zig");
const Nonhash = @import("blake3_nonhash_emission_v1.zig");
const T = @import("blake3_transcript_witness.zig");
const Plan = @import("blake3_transcript_plan.zig").Plan;
const Source = @import("blake3_direct_source_columns_v1.zig");
const Main = @import("blake3_main_column_test_support.zig");
const Metadata = @import("blake3_hash_metadata.zig");
const Group = @import("blake3_merkle_group_witness.zig");
const Frontier = @import("blake3_two_level_frontier.zig");
const Paths = @import("blake3_stark_paths.zig");
const Deep = @import("pcs_deep_circuit.zig");
const Fri = @import("fri_verifier_circuit.zig");
const Links = @import("blake3_query_links.zig");
const Digest = [32]u8;
fn checkRows(comptime slot: usize, owner: *const Nonhash.Owner, fixed: *const Nonhash.FixedOwner, rows: []const Storage.Airs[slot].Row, trusted: []const Storage.Airs[slot].Row) !void {
    const view = try owner.columns.view(slot);
    const tails = try fixed.rows(slot);
    try std.testing.expectEqual(rows.len, view.rowCount());
    try std.testing.expectEqual(rows.len, tails.len);
    for (rows, trusted, tails, 0..) |row, expected, tail, index| {
        try std.testing.expectEqualDeep(row, view.rowAt(index));
        try std.testing.expectEqualDeep(Storage.compactFixed(Storage.Airs[slot], expected), tail);
        try std.testing.expectEqualDeep(tail, view.fixed[index]);
    }
}
fn counterOwner(a: std.mem.Allocator) !void {
    const Air = Storage.Airs[15];
    const schedule = Air.Schedule{ .source = .{ .circuit = 1, .first_wire = 0 }, .increment = .{ .circuit = 2, .wire = 0 }, .destination = .{ .circuit = 3, .first_wire = 0 }, .uses = .{ 0, 0 } };
    const row = try Air.logicalRow(schedule, 19, 1);
    const recipe = try Air.fixedRow(schedule);
    var counts = Nonhash.Counts{};
    try counts.sink().emit(15, &row, &recipe);
    try counts.sink().emit(15, &row, &recipe);
    // Child construction has already emitted a later producer. The parent
    // must patch the earlier producer, not accidentally update the new one.
    try counts.sink().addUses(15, 0, 31, 7);
    var owner = try Nonhash.Owner.init(a, counts);
    defer owner.deinit();
    var fixed = try Nonhash.FixedOwner.init(a, counts);
    defer fixed.deinit();
    for ([_]Nonhash.Sink{ owner.sink(), fixed.sink() }) |sink| {
        try sink.emit(15, &row, &recipe);
        try sink.emit(15, &row, &recipe);
        try sink.addUses(15, 0, 31, 7);
        try sink.addUses(15, 0, 32, 9);
        try std.testing.expectError(error.InvalidNonhashMultiplicityPatch, sink.addUses(15, 2, 31, 1));
        try std.testing.expectError(error.InvalidNonhashMultiplicityPatch, sink.addUses(15, 0, 30, 1));
        try std.testing.expectError(error.InvalidNonhashMultiplicityPatch, sink.addUses(15, 0, 31, core.fields.m31.Modulus));
    }
    try owner.finish();
    try fixed.finish();
    var expected = row;
    expected[31] = M.fromCanonical(7);
    expected[32] = M.fromCanonical(9);
    try checkRows(15, &owner, &fixed, &.{ expected, row }, &.{ expected, recipe });
    try std.testing.expectError(error.InvalidNonhashMultiplicityPatch, owner.sink().addUses(15, 0, 31, 1));
    try std.testing.expectError(error.InvalidNonhashMultiplicityPatch, fixed.sink().addUses(15, 0, 31, 1));
    var census = Source.Counts{};
    try owner.appendTrusted(15, &fixed, &census);
    try std.testing.expectEqual(@as(usize, 2), census.counts[15]);
    fixed.fixed[7][0][7] = M.zero();
    try std.testing.expectError(error.InvalidNativeParentRows, owner.appendTrusted(15, &fixed, &census));
    try std.testing.expectEqual(@as(usize, 2), census.counts[15]);
}
test "nonhash direct owners patch earlier counters exactly and reject stale recipe or multiplicity" {
    try counterOwner(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, counterOwner, .{});
    var counts = Nonhash.Counts{};
    counts.rows[0] = 1;
    var incomplete = try Nonhash.FixedOwner.init(std.testing.allocator, counts);
    defer incomplete.deinit();
    try std.testing.expectError(error.DirectRecursiveRowCountMismatch, incomplete.finish());
    const row: Storage.Airs[2].Row = @splat(M.zero());
    var wrong = row;
    wrong[Storage.Airs[2].PHYSICAL_MAIN_COLUMN_COUNT] = M.one();
    try std.testing.expectError(error.InvalidNativeParentRows, incomplete.sink().emit(2, &row, &wrong));
    try std.testing.expectEqual(@as(usize, 0), incomplete.next[0]);
    const cap = (1 << 24) + 1;
    counts.rows[0] = cap;
    try std.testing.expectError(error.InvalidTraceShape, Nonhash.FixedOwner.init(std.testing.allocator, counts));
    try std.testing.expectError(error.InvalidTraceShape, Nonhash.Owner.init(std.testing.allocator, counts));
}
const query_values = [_]u32{0} ** 9;
const words = [_]u32{ 0xffffffff, 19, 7, 0 };
const felts = [_]Q{Q.one()};
const operations = [_]T.Operation{
    .{ .routed_integer = .{ .value = 42, .source = .{ .circuit = 10, .first_wire = 0 } } },
    .{ .queries = .{ .log_domain_size = 0, .values = &query_values, .export_outputs = true } },
    .{ .secure = .{ .output = .oods, .attempts = 0, .values = @splat(M.zero()), .consumption = .one } },
    .{ .secure = .{ .output = .deep, .attempts = 0, .values = @splat(M.zero()), .consumption = .two } },
    .{ .queries = .{ .log_domain_size = 0, .values = &query_values } },
    .{ .pow = .{ .bits = 0, .nonce = 19, .nonce_source = .{ .circuit = 11, .first_wire = 0 } } },
    .{ .root = @splat(17) },
    .{ .routed_root = .{ .value = @splat(29), .source = .{ .circuit = 12, .first_wire = 0 } } },
    .{ .routed_words = .{ .values = &words, .source = .{ .circuit = 13, .first_wire = 0 } } },
    .{ .routed_felts = .{ .values = &felts, .source = .{ .circuit = 14, .first_wire = 0 } } },
    .{ .secure = .{ .output = .composition, .attempts = 0, .values = @splat(M.zero()) } },
};
fn transcriptCase(a: std.mem.Allocator, oracle: *const T.Prepared, trusted: *const T.Prepared, expected_id: Digest) !void {
    var plan = try Plan.initCompact(a, .{ .namespace = 100, .attempt_capacity = 3 }, &operations);
    defer plan.deinit();
    try std.testing.expectEqual(expected_id, plan.id);
    try std.testing.expect(plan.fixed.nonhash_fixed != null);
    inline for (Nonhash.slots) |slot| try std.testing.expectEqual(@as(usize, 0), plan.fixed.cohortRows(slot).len);
    const counts = plan.fixed.hashCounts();
    var output_arena = std.heap.ArenaAllocator.init(a);
    defer output_arena.deinit();
    const output = try Main.allocate(output_arena.allocator(), counts.g, counts.xor);
    var live = try plan.prepareMainColumns(a, &operations, output);
    defer live.deinit();
    try std.testing.expectEqualDeep(oracle.payload_reads, live.payload_reads);
    try std.testing.expectEqualDeep(oracle.draw_outputs, live.draw_outputs);
    try std.testing.expectEqualDeep(oracle.query_outputs, live.query_outputs);
    try std.testing.expectEqualDeep(oracle.root_reads, live.root_reads);
    try std.testing.expectEqualDeep(oracle.final_digest, live.final_digest);
    try std.testing.expectEqual(oracle.next_draw, live.next_draw);
    try Main.expectRows(output, oracle.*, trusted.*);
    inline for (Nonhash.slots) |slot| {
        try std.testing.expectEqual(@as(usize, 0), live.cohortRows(slot).len);
        try checkRows(slot, &live.nonhash.?, &plan.fixed.nonhash_fixed.?, oracle.cohortRows(slot), trusted.cohortRows(slot));
    }
    // The assembler consumes exact borrowed views and verifies fixed tails
    // before incrementing its count; mixed legacy storage is rejected.
    var census = Source.Counts{};
    inline for (.{ 2, 6, 7, 8, 14, 15 }) |slot| try live.appendCohort(slot, &plan.fixed, &census);
    const before = census.counts;
    live.boundary_rows = oracle.boundary_rows;
    try std.testing.expectError(error.InvalidNativeParentRows, live.appendCohort(2, &plan.fixed, &census));
    live.boundary_rows = &.{};
    try std.testing.expectEqualDeep(before, census.counts);
    const old = plan.fixed.nonhash_fixed.?.fixed[0][0][0];
    plan.fixed.nonhash_fixed.?.fixed[0][0][0] = old.add(M.one());
    try std.testing.expectError(error.CorruptBlake3TranscriptPlan, plan.validate());
    try std.testing.expectError(error.InvalidNativeParentRows, live.appendCohort(2, &plan.fixed, &census));
    plan.fixed.nonhash_fixed.?.fixed[0][0][0] = old;
    try plan.validate();
}
test "canonical direct transcript preserves chained draw query absorption PoW key rows and receipts" {
    var plan = try Plan.init(std.testing.allocator, .{ .namespace = 100, .attempt_capacity = 3 }, &operations);
    defer plan.deinit();
    var oracle = try plan.prepare(std.testing.allocator, &operations);
    defer oracle.deinit();
    try transcriptCase(std.testing.allocator, &oracle, &plan.fixed, plan.id);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, transcriptCase, .{ &oracle, &plan.fixed, plan.id });
}
fn groupRows(comptime slot: usize, p: *const Group.Prepared) []const Storage.Airs[slot].Row {
    return switch (slot) {
        2 => p.boundary_rows,
        7 => p.route_rows,
        9 => p.word_rows,
        13 => p.select_rows,
        else => @compileError("not a group source cohort"),
    };
}
fn groupCase(a: std.mem.Allocator, s: Group.Statement, values: []const M, siblings: []const Digest, oracle: *const Group.Prepared, trusted: *const Group.Prepared) !void {
    var cache = Group.PlanCache.init(a);
    defer cache.deinit();
    const counts = try Group.requiredHashRowsCached(a, s, &cache);
    var metadata = try Metadata.Rows.allocate(a, counts.g, counts.xor);
    defer metadata.free(a);
    var census = Nonhash.Counts{};
    var counted = try Group.prepareEmittingCached(a, s, null, null, .{ .fixed = metadata }, null, &cache, census.sink());
    counted.deinit();
    var fixed = try Nonhash.FixedOwner.init(a, census);
    defer fixed.deinit();
    var owner = try Nonhash.Owner.init(a, census);
    defer owner.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const output = try Main.allocate(arena.allocator(), counts.g, counts.xor);
    var live = try Group.prepareEmittingCached(a, s, values, siblings, null, output, &cache, owner.sink());
    defer live.deinit();
    var recipe = try Group.prepareEmittingCached(a, s, null, null, .{ .fixed = metadata }, null, &cache, fixed.sink());
    defer recipe.deinit();
    try owner.finish();
    try fixed.finish();
    try std.testing.expectEqualDeep(oracle.computed_root, live.computed_root);
    try std.testing.expectEqualDeep(oracle.payload_uses, live.payload_uses);
    try Main.expectRows(output, oracle.*, trusted.*);
    inline for (.{ 2, 7, 9, 13 }) |slot| {
        try std.testing.expectEqual(@as(usize, 0), groupRows(slot, &live).len);
        try checkRows(slot, &owner, &fixed, groupRows(slot, oracle), groupRows(slot, trusted));
    }
}
fn node(left: Digest, right: Digest) Digest {
    return (core.channel.blake3.Frame{ .node = .{ .left = left, .right = right } }).hash();
}
test "direct Merkle subtree preserves terminal roots selectors shared tail routes and hash masks" {
    const values = [_]M{ M.one(), M.fromCanonical(19) };
    const leaves = [_]Digest{ (core.channel.blake3.Frame{ .leaf = values[0..1] }).hash(), (core.channel.blake3.Frame{ .leaf = values[1..2] }).hash() };
    const subtree = node(leaves[0], leaves[1]);
    const siblings = [_]Digest{@splat(11)};
    const directions = [_]Group.select.Endpoint{.{ .circuit = 80, .wire = 0 }};
    for ([_]u32{ 0, 1, 2 }) |case| {
        const s = Group.Statement{ .namespace = 1000, .payload = .{ .circuit = 77, .first_wire = 0 }, .leaf_count = 2, .words_per_leaf = 1, .index = if (case == 0) 0 else 1, .depth = if (case == 0) 0 else 1, .root = if (case == 0) subtree else node(siblings[0], subtree), .root_source = if (case == 0) null else .{ .circuit = 78, .first_wire = 0 }, .directions = if (case == 0) null else &directions, .shared_root = if (case == 2) .{ .first_namespace = 994, .query_index = 1, .queries = 2 } else null };
        const path = if (case == 0) @as([]const Digest, &.{}) else &siblings;
        var oracle = try Group.prepare(std.testing.allocator, s, &values, path);
        defer oracle.deinit();
        var trusted = try Group.trusted(std.testing.allocator, s);
        defer trusted.deinit();
        try groupCase(std.testing.allocator, s, &values, path, &oracle, &trusted);
        if (case == 1) try std.testing.checkAllAllocationFailures(std.testing.allocator, groupCase, .{ s, &values, path, &oracle, &trusted });
    }
}
fn frameCase(a: std.mem.Allocator, values: []const M, retain: bool, oracle: *const @import("blake3_frame_witness.zig").Prepared, trusted: *const @import("blake3_frame_witness.zig").Prepared) !void {
    const Frame = @import("blake3_frame_witness.zig");
    const Direct = @import("blake3_frame_nonhash_v1.zig");
    const message = core.channel.blake3.Frame{ .leaf = values };
    const claim = message.hash();
    const payload = Frame.PayloadBinding{ .role = .leaf, .caller = .{ .circuit = 19, .first_wire = 13 }, .word_count = values.len };
    var graph = try @import("blake3_hash_plan.zig").build(a, try message.encodedSize());
    defer graph.deinit();
    var counts = Nonhash.Counts{};
    var counted = try Direct.prepare(a, 100, message, &.{}, payload, claim, false, null, null, &graph, .{ .sink = counts.sink(), .retain_output = retain });
    counted.deinit();
    var fixed = try Nonhash.FixedOwner.init(a, counts);
    defer fixed.deinit();
    var owner = try Nonhash.Owner.init(a, counts);
    defer owner.deinit();
    var metadata = try Metadata.Rows.allocate(a, graph.g.len, graph.xor.len);
    defer metadata.free(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const output = try Main.allocate(arena.allocator(), graph.g.len, graph.xor.len);
    var live = try Direct.prepare(a, 100, message, &.{}, payload, claim, true, null, output, &graph, .{ .sink = owner.sink(), .retain_output = retain });
    defer live.deinit();
    var recipe = try Direct.prepare(a, 100, message, &.{}, payload, claim, false, .{ .fixed = metadata }, null, &graph, .{ .sink = fixed.sink(), .retain_output = retain });
    defer recipe.deinit();
    try owner.finish();
    try fixed.finish();
    try std.testing.expectEqualDeep(oracle.digest, live.digest);
    try std.testing.expectEqualDeep(oracle.payload_uses, live.payload_uses);
    try std.testing.expectEqualDeep(oracle.source_uses, live.source_uses);
    try std.testing.expectEqual(@as(usize, 0), live.rows.boundary_rows.len + live.route_rows.len);
    const boundary_count = oracle.rows.boundary_rows.len - (if (retain) @as(usize, 0) else 8);
    try checkRows(2, &owner, &fixed, oracle.rows.boundary_rows[0..boundary_count], trusted.rows.boundary_rows[0..boundary_count]);
    try checkRows(7, &owner, &fixed, oracle.route_rows, trusted.route_rows);
    try Main.expectRows(output, oracle.*, trusted.*);
    var wrong = output;
    wrong.g_rows.metadata = wrong.g_rows.metadata[1..];
    Main.poison(output);
    try std.testing.expectError(error.InvalidBlake3WitnessDestination, Direct.prepare(a, 100, message, &.{}, payload, claim, true, null, wrong, &graph, .{ .sink = owner.sink(), .retain_output = retain }));
    try Main.expectPoison(output);
}
test "direct multi block frame emits canonical constants routes and optional terminal public coordinates" {
    const Frame = @import("blake3_frame_witness.zig");
    var values: [129]M = undefined;
    for (&values, 0..) |*value, index| value.* = M.fromU64(index * 107 + 19);
    const message = core.channel.blake3.Frame{ .leaf = &values };
    const payload = Frame.PayloadBinding{ .role = .leaf, .caller = .{ .circuit = 19, .first_wire = 13 }, .word_count = values.len };
    var oracle = try Frame.preparePayload(std.testing.allocator, 100, message, &.{}, payload, message.hash());
    defer oracle.deinit();
    var trusted = try Frame.trustedPayload(std.testing.allocator, 100, message, &.{}, payload, message.hash());
    defer trusted.deinit();
    try frameCase(std.testing.allocator, &values, false, &oracle, &trusted);
    try frameCase(std.testing.allocator, &values, true, &oracle, &trusted);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, frameCase, .{ &values, true, &oracle, &trusted });
}
fn frontierCase(a: std.mem.Allocator, context: Frontier.Context, oracle: *const Frontier.Prepared, trusted: *const Frontier.Prepared) !void {
    const zero: Digest = @splat(0);
    const message = core.channel.blake3.Frame{ .node = .{ .left = zero, .right = zero } };
    var graph = try @import("blake3_hash_plan.zig").build(a, try message.encodedSize());
    defer graph.deinit();
    const g_count = try std.math.mul(usize, 3, graph.g.len);
    const x_count = try std.math.mul(usize, 3, graph.xor.len);
    var metadata = try Metadata.Rows.allocate(a, g_count, x_count);
    defer metadata.free(a);
    var counts = Nonhash.Counts{};
    var counted = try Frontier.emitWithPlanEmitting(a, context, false, .{ .fixed = metadata }, null, &graph, counts.sink());
    counted.deinit();
    var owner = try Nonhash.Owner.init(a, counts);
    defer owner.deinit();
    var fixed = try Nonhash.FixedOwner.init(a, counts);
    defer fixed.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const output = try Main.allocate(arena.allocator(), g_count, x_count);
    var live = try Frontier.emitWithPlanEmitting(a, context, true, null, output, &graph, owner.sink());
    defer live.deinit();
    var recipe = try Frontier.emitWithPlanEmitting(a, context, false, .{ .fixed = metadata }, null, &graph, fixed.sink());
    defer recipe.deinit();
    try owner.finish();
    try fixed.finish();
    try std.testing.expectEqual(oracle.root, live.root);
    try Main.expectRows(output, oracle.*, trusted.*);
    inline for (.{ 2, 7, 9, 13 }) |slot| {
        const actual = switch (slot) {
            2 => oracle.boundary_rows,
            7 => oracle.route_rows,
            9 => oracle.word_rows,
            13 => oracle.select_rows,
            else => unreachable,
        };
        const expected = switch (slot) {
            2 => trusted.boundary_rows,
            7 => trusted.route_rows,
            9 => trusted.word_rows,
            13 => trusted.select_rows,
            else => unreachable,
        };
        try checkRows(slot, &owner, &fixed, actual, expected);
    }
}
test "direct shared frontier preserves active opaque branches public one and query root multiplicity" {
    const context = Frontier.Context{ .plan = .{ .namespace = 1000, .queries = 3, .root_source = .{ .circuit = 800, .first_wire = 0 } }, .witness = .{ .inputs = .{ .{ @splat(17), @splat(29) }, .{ @splat(37), @splat(43) } }, .opaque_digests = .{ @splat(53), @splat(61) }, .active = .{ 1, 0 } } };
    var oracle = try Frontier.prepare(std.testing.allocator, context.plan, context.witness);
    defer oracle.deinit();
    var trusted = try Frontier.emit(std.testing.allocator, context, false, null, null);
    defer trusted.deinit();
    try frontierCase(std.testing.allocator, context, &oracle, &trusted);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, frontierCase, .{ context, &oracle, &trusted });
}
const Capture = core.verifier.ProofCapture(@import("../blake3_engine_protocol.zig").Hasher);
fn pathCase(a: std.mem.Allocator, capture: *const Capture, dg: *const Deep.Circuit, fg: *const Fri.Circuit, oracle: *const Paths.Prepared, expected_reads: []const Links.Query) !void {
    const outputs = [_]T.QueryOutput{ .{ .operation = 0, .query = 0, .source = .{ .circuit = 700, .wire = 0 } }, .{ .operation = 0, .query = 1, .source = .{ .circuit = 700, .wire = 1 } } };
    var queries = try Links.build(a, &outputs, dg, fg, 2, 1);
    defer queries.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const output = try Main.allocate(arena.allocator(), oracle.live.g_rows.len, oracle.live.xor_rows.len);
    var direct = try Paths.prepareMainColumns(a, capture, dg, fg, &queries, output);
    defer direct.deinit();
    try std.testing.expect(direct.nonhash != null and direct.nonhash_fixed != null);
    try std.testing.expectEqual(@as(usize, 0), direct.live.g_rows.len + direct.live.xor_rows.len);
    // Row oracle includes opening sentinels/projection routes in its tail;
    // canonical path owners deliberately keep these in the input owners.
    try checkRows(2, &direct.nonhash.?, &direct.nonhash_fixed.?, oracle.live.boundary_rows[0 .. oracle.live.boundary_rows.len - oracle.inputs.sentinels.len], oracle.fixed.boundary_rows[0 .. oracle.fixed.boundary_rows.len - oracle.inputs.sentinels.len]);
    try checkRows(7, &direct.nonhash.?, &direct.nonhash_fixed.?, oracle.live.route_rows[0 .. oracle.live.route_rows.len - oracle.inputs.projection.routed.len], oracle.fixed.route_rows[0 .. oracle.fixed.route_rows.len - oracle.inputs.projection.fixed_routed.len]);
    try checkRows(9, &direct.nonhash.?, &direct.nonhash_fixed.?, oracle.live.word_rows, oracle.fixed.word_rows);
    try checkRows(13, &direct.nonhash.?, &direct.nonhash_fixed.?, oracle.live.select_rows, oracle.fixed.select_rows);
    try Main.expectRows(output, oracle.live, oracle.fixed);
    try std.testing.expectEqualDeep(expected_reads, queries.queries);
    try std.testing.expectEqualDeep(oracle.inputs.sources, direct.inputs.sources);
    var candidate = capture.*;
    var changed_roots: [4]Digest = undefined;
    @memcpy(&changed_roots, capture.commitments);
    changed_roots[0][0] ^= 1;
    candidate.commitments = &changed_roots;
    // A failed live root check must restore the pre-existing fanout counts,
    // even though the successful preceding plan has already populated them.
    if (Paths.prepare(a, &candidate, dg, fg, &queries)) |value| {
        var unexpected = value;
        unexpected.deinit();
        return error.TestExpectedError;
    } else |err| {
        if (err == error.OutOfMemory) return err;
        try std.testing.expect(err == error.InvalidFrontierCapture);
    }
    try std.testing.expectEqualDeep(expected_reads, queries.queries);
    var counts = Source.Counts{};
    direct.live.word_rows = oracle.live.word_rows;
    try std.testing.expectError(error.InvalidNativeParentRows, direct.appendCohort(7, &counts));
    direct.live.word_rows = &.{};
    try std.testing.expectEqual(@as(usize, 0), counts.counts[7]);
    inline for (.{ 2, 7, 9, 13 }) |slot| try direct.appendCohort(slot, &counts);
    try direct.inputs.appendCohort(2, &counts);
    try direct.inputs.projection.appendRoutes(&counts);
    inline for (.{ 2, 7, 9, 13 }) |slot| {
        const expected = switch (slot) {
            2 => oracle.live.boundary_rows.len,
            7 => oracle.live.route_rows.len,
            9 => oracle.live.word_rows.len,
            13 => oracle.live.select_rows.len,
            else => unreachable,
        };
        try std.testing.expectEqual(expected, counts.counts[slot]);
    }
}
test "canonical Merkle capture preparation has transactional query fanout and exact frontier source order" {
    const logs = [_]u32{2};
    const profiles = [_]Deep.TreeProfile{.{ .column_log_sizes = &logs }} ** 4;
    const layouts = [_]Deep.SamplePointLayout{.current} ** 4;
    const widths = [_]u32{2};
    var dg = try Deep.build(std.testing.allocator, .{ .trees = &profiles, .sample_layouts = &layouts, .lifting_log_size = 2, .log_blowup_factor = 1, .query_count = 2 });
    defer dg.deinit();
    var fg = try Fri.build(std.testing.allocator, .{ .lifting_log_size = 2, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .fold_widths = &widths, .query_count = 2 });
    defer fg.deinit();
    // This is a source-shape snapshot with native BLAKE3-consistent paths,
    // never a receipt from verifier verification. Production body codegen
    // below still accepts the actual independently captured type.
    var raw = [_]usize{ 0, 3 };
    const query = [_]T.QueryOutput{ .{ .operation = 0, .query = 0, .source = .{ .circuit = 700, .wire = 0 } }, .{ .operation = 0, .query = 1, .source = .{ .circuit = 700, .wire = 1 } } };
    var linked = try Links.build(std.testing.allocator, &query, &dg, &fg, 2, 1);
    defer linked.deinit();
    const zero_leaf = (core.channel.blake3.Frame{ .leaf = &[_]M{M.zero()} }).hash();
    const branch = node(zero_leaf, zero_leaf);
    const root = node(branch, branch);
    var tree_roots = [_]Digest{root} ** 4;
    var column_logs = [_][1]u32{.{2}} ** 4;
    var tree_logs = [_][]u32{ &column_logs[0], &column_logs[1], &column_logs[2], &column_logs[3] };
    var trace_siblings = [_]Digest{ zero_leaf, branch, zero_leaf, branch };
    const Trace = core.vcs_lifted.verifier.MerklePathCapture(@import("../blake3_engine_protocol.zig").Hasher);
    var trace_paths = [_]Trace{.{ .positions = &raw, .path_depth = 2, .siblings = &trace_siblings }} ** 4;
    var values = [_]M{M.zero()} ** 8;
    const fri_leaf = (core.channel.blake3.Frame{ .leaf = &[_]M{ M.zero(), M.zero(), M.zero(), M.zero() } }).hash();
    const fri_group = node(fri_leaf, fri_leaf);
    var fri_values = [_]Q{Q.zero()} ** 4;
    var fri_siblings = [_]Digest{fri_group} ** 2;
    var layers = [_]core.fri.FriLayerQueryCapture(@import("../blake3_engine_protocol.zig").Hasher){.{ .commitment = node(fri_group, fri_group), .folding_alpha = Q.zero(), .fold_step = 1, .fold_width = 2, .path_depth = 1, .query_count = 2, .positions = &raw, .values = &fri_values, .siblings = &fri_siblings }};
    const capture = Capture{ .queries = .{ .raw = &raw, .unique = &raw }, .commitments = &tree_roots, .column_log_sizes = &tree_logs, .sampled_points = &.{}, .sampled_values = &.{}, .queried_values = &values, .deep_answers = &.{}, .trace_paths = &trace_paths, .fri = .{ .layers = &layers }, .last_layer_coefficients = &.{}, .proof_of_work = 0, .composition_randomness = Q.zero(), .oods_seed = Q.zero(), .deep_randomness = Q.zero() };
    var oracle = try Paths.prepareRows(std.testing.allocator, &capture, &dg, &fg, &linked);
    defer oracle.deinit();
    try pathCase(std.testing.allocator, &capture, &dg, &fg, &oracle, linked.queries);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, pathCase, .{ &capture, &dg, &fg, &oracle, linked.queries });
}

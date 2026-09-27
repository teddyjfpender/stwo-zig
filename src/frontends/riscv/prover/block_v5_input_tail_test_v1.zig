//! Pure original byte/equation/routing/ownership fixtures. No proof accepted,
//! generated, decoded, or invoked; literal setup keys are metadata tests only.
const std = @import("std");
const core = @import("stwo_core");
const Tail = @import("../recursion/blake3_words_tail_v1.zig");
const Public = @import("../recursion/block_v5_input_tail_public_v1.zig");
const Rows = @import("../recursion/air/block_v5_input_tail_rows_v1.zig");
const Consumer = @import("../recursion/air/block_v5_input_tail_consumer_v1.zig");
const Digest = @import("../recursion/air/block_v5_input_tail_public_digest_v1.zig");
const Protocol = @import("../recursion/block_v5_input_tail_protocol_v1.zig");
const Source = @import("../recursion/block_v5_input_tail_source_v1.zig");
const Data = @import("../air/public_data.zig");
const Job = @import("../recursion/block_v5_global_expected_public_job_v1.zig");
const File = @import("block_v5_global_expected_public_file_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Windows = @import("block_v5_register_windows_v1.zig");
const G = @import("../recursion/air/blake3_g_call.zig");
const X = @import("../recursion/air/blake3_xor_call.zig");
const B = @import("../recursion/air/blake3_boundary.zig");
const R = @import("../recursion/air/blake3_byte_route.zig");
const Word = @import("../recursion/air/blake3_private_word.zig");
const M = core.fields.m31.M31;
fn dataFor(input: []const u32) Data.Blake3PublicData {
    return .{ .initial_pc = 0x1000, .final_pc = 0x1004, .clock = 2, .initial_regs = @splat(0), .final_regs = @splat(0), .reg_last_clock = @splat(0), .program_root = .{ .bytes = @splat(0xa5) }, .initial_rw_root = .{ .bytes = @splat(0x11) }, .final_rw_root = .{ .bytes = @splat(0x22) }, .completion = Data.Completion.canonicalSelfLoop(0x1004), .io_entries = .{ .input_start = 0x10000, .input_len = @intCast(input.len * 4), .input_words = input, .output_len = 0, .output_len_addr = 0x20000, .output_data_addr = 0x20004, .output_words = &.{} } };
}
fn jobFor(a: std.mem.Allocator, input: []const u32) !*File.Owned {
    const data = dataFor(input);
    const windows = [_]Job.Window{.{ .profile = .rv32im_zkvm_v1, .first_cycle = 1, .last_cycle = 2, .data = Job.Data.fromPublic(&data) }};
    const registers = [_]Windows.Window{Windows.Window.fromPublic(0, 1, &data)};
    const expected = Job.Expected{ .coverage_digest = @splat(0xa1), .seal_digest = @splat(0xb1), .recipe = 1, .input_words = input, .windows = &windows, .register_plan = .{ .version = Windows.LOCAL_ZERO_VERSION, .initial_registers = data.initial_regs, .final_registers = data.final_regs, .windows = &registers } };
    const raw = try File.encode(a, expected, .{});
    defer a.free(raw);
    return File.decode(a, raw, .{ .byte_len = raw.len, .sha256 = Files.hash(raw) }, expected, .{});
}
fn constraints(comptime Air: type, rows: []const Air.Row) !bool {
    const lang = @import("../air/lang/mod.zig");
    const support = @import("../recursion/air/test_support.zig");
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    for (rows) |row| {
        const evaluated = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
        defer std.testing.allocator.free(evaluated);
        for (definition.arena.constraintsView()) |constraint| if (!evaluated[lang.types.idIndex(constraint.root)].isZero()) return false;
    }
    return true;
}
fn wireClosure(prepared: *const Consumer.Prepared, statement: Consumer.Statement, prefix: []const u32, frontier: []const [8]u32) !bool {
    var external: std.ArrayList(B.Row) = .empty;
    defer external.deinit(std.testing.allocator);
    for (prepared.state_uses, 0..) |count, word| if (count != 0) try external.append(std.testing.allocator, try B.logicalRow(statement.sources.state.circuit, statement.sources.state.first_wire + @as(u32, @intCast(word)), M.fromCanonical(count), std.mem.readInt(u32, statement.state[4 * word ..][0..4], .little)));
    for (prepared.prefix_uses, prefix, 0..) |count, value, word| if (count != 0) try external.append(std.testing.allocator, try B.logicalRow(statement.sources.prefix.circuit, statement.sources.prefix.first_wire + @as(u32, @intCast(word)), M.fromCanonical(count), value));
    for (prepared.frontier_uses, statement.sources.frontier, frontier) |counts, caller, cv| for (counts, cv, 0..) |count, value, word| {
        if (count != 0) try external.append(std.testing.allocator, try B.logicalRow(caller.circuit, caller.first_wire + @as(u32, @intCast(word)), M.fromCanonical(count), value));
    };
    return tupleClosure(prepared.rows.g_rows, prepared.rows.xor_rows, prepared.rows.boundary_rows, prepared.route_rows, &.{}, external.items);
}
fn tupleClosure(gs: []const G.Row, xs: []const X.Row, bs: []const B.Row, routes: []const R.Row, words: []const Word.Row, external: []const B.Row) !bool {
    const binding = @import("../recursion/air/universal_relation_binding.zig");
    const lang = @import("../air/lang/mod.zig");
    var counts = std.AutoHashMap([6]u32, M).init(std.testing.allocator);
    defer counts.deinit();
    inline for (.{ G, X, B, R, Word, B }, .{ gs, xs, bs, routes, words, external }) |Air, rows| {
        var definition = try Air.build(std.testing.allocator);
        defer definition.deinit();
        const plan = try binding.Binding(Air).authenticate(&definition);
        for (rows) |row| for (plan.preparedEntries(row)) |entry| {
            if (entry.schema != lang.relation.id(.recursion_wire)) continue;
            var key: [6]u32 = undefined;
            for (&key, entry.values[0..6]) |*word, value| word.* = (try value.tryIntoM31()).toU32();
            const slot = try counts.getOrPut(key);
            if (!slot.found_existing) slot.value_ptr.* = M.zero();
            slot.value_ptr.* = slot.value_ptr.*.add(try entry.numerator.tryIntoM31());
        };
    }
    var iterator = counts.valueIterator();
    while (iterator.next()) |value| if (!value.isZero()) return false;
    return true;
}
fn callerSources(shape: *const Tail.Geometry, out: []Consumer.Caller) []const Consumer.Caller {
    for (out[0..shape.range_count], 0..) |*caller, i| caller.* = .{ .circuit = 902, .first_wire = @intCast(i * 8) };
    return out[0..shape.range_count];
}
test "input tail provider: exact original CV call selection covers unbalanced and partial final chunks" {
    const HashPlan = @import("../recursion/air/blake3_hash_plan.zig");
    for ([_]usize{ 239, 240, 495, 496, 753, 1009, 1265, 1521, 2033 }) |count| {
        const shape = try Tail.Geometry.init(count);
        var plan = try HashPlan.build(std.testing.allocator, shape.frame_bytes);
        defer plan.deinit();
        for (shape.frontier()) |range| {
            const call = try Public.outputCall(&shape, range);
            try std.testing.expect(call < plan.calls.len - 1);
            // Each message word is read in all7 original compression
            // rounds. Derive that count independently from the actual DAG
            // edges, then the provider adds ONE extra public export read.
            for (plan.calls[call].output[0..8]) |wire| {
                var original_reads: u32 = 0;
                for (plan.g) |g| for (g.input) |input| {
                    if (input == wire) original_reads += 1;
                };
                for (plan.xor) |x| for (x.input) |input| {
                    if (input == wire) original_reads += 1;
                };
                for (plan.output) |output| if (output == wire) {
                    original_reads += 1;
                };
                try std.testing.expectEqual(@as(u32, 7), original_reads);
                try std.testing.expectEqual(original_reads, plan.uses[wire]);
            }
        }
    }
}
test "input tail provider: bounded consumer original scalar parity exact fixed routes and byte multiset" {
    var input: [2033]u32 = undefined;
    for (&input, 0..) |*value, i| value.* = @truncate(i *% 0xa1f03043);
    var sources: [32]Consumer.Caller = undefined;
    for ([_]usize{ 0, 1, 239, 240, 753, 2033 }) |count| {
        var tail = try Tail.ScalarTail.init(std.testing.allocator, input[0..count]);
        defer tail.deinit();
        const state: [32]u8 = @splat(0xea);
        const expected = (core.channel.blake3.framing.Frame{ .words = .{ .state = state, .values = input[0..count] } }).hash();
        const statement = Consumer.Statement{ .circuit = 903, .word_count = count, .state = state, .claim = expected, .sources = .{ .state = .{ .circuit = 900, .first_wire = 0 }, .prefix = .{ .circuit = 901, .first_wire = 0 }, .frontier = callerSources(&tail.geometry, &sources) } };
        const prefix = input[0..@min(Public.PREFIX_WORDS, count)];
        var actual = try Consumer.prepare(std.testing.allocator, statement, prefix, tail.cvs);
        defer actual.deinit();
        var fixed = try Consumer.trusted(std.testing.allocator, statement);
        defer fixed.deinit();
        try std.testing.expectEqualSlices(u8, &expected, &actual.digest);
        try std.testing.expect(actual.compression_calls <= 16 + tail.geometry.range_count);
        inline for (.{ G, X, B, R }, .{ actual.rows.g_rows, actual.rows.xor_rows, actual.rows.boundary_rows, actual.route_rows }, .{ fixed.rows.g_rows, fixed.rows.xor_rows, fixed.rows.boundary_rows, fixed.route_rows }) |Air, live, trusted| {
            try std.testing.expect(try constraints(Air, live));
            try std.testing.expectEqual(live.len, trusted.len);
            for (live, trusted) |row, admitted| try std.testing.expectEqualSlices(M, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], admitted[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
        }
        try std.testing.expect(try wireClosure(&actual, statement, prefix, tail.cvs));
        if (count == 240) {
            var changed = tail.cvs[0];
            changed[0] ^= 1;
            try std.testing.expect(!try wireClosure(&actual, statement, prefix, &.{changed}));
            // Row0 routes constant header bytes and has no source. Its
            // unused source column is legitimately unconstrained. Mutate
            // the destination byte, which is an actual affine AIR output.
            actual.route_rows[0][8] = actual.route_rows[0][8].add(M.one());
            try std.testing.expect(!try constraints(R, actual.route_rows));
        }
    }
}
fn ownership(a: std.mem.Allocator) !void {
    const job = try jobFor(a, &.{ 0x80000000, 0xffffffff });
    defer job.deinit();
    const public = try Public.Owned.init(a, job, .{});
    defer public.deinit();
    try public.require(public.pin);
    const retained = public.retain();
    retained.deinit();
    try std.testing.expectEqual(@as(usize, 2), job.references.load(.acquire));
    const old = public.prefix_words[0];
    public.prefix_words[0] ^= 1;
    try std.testing.expectError(error.UntrustedInputTailPublic, public.require(public.pin));
    public.prefix_words[0] = old;
}
test "input tail provider: public owner mutation exact leases and exhaustive allocation rollback" {
    try ownership(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ownership, .{});
}
test "input tail provider: durable expected owner and alias survive original shared budget release" {
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const budget = try Budget.create(std.testing.allocator, 16 << 20);
    const job = jobFor(budget.allocator(), &.{ 0xf0011234, 0x80000000 }) catch |failure| {
        budget.destroy();
        return failure;
    };
    const public = Public.Owned.init(budget.allocator(), job, .{}) catch |failure| {
        job.deinit();
        budget.destroy();
        return failure;
    };
    job.deinit();
    budget.destroy();
    defer public.deinit();
    try public.require(public.pin);
    try std.testing.expectEqual(@as(usize, 1), public.job.references.load(.acquire));
}
test "input tail provider: actual original hash and private word AIR has exact public export sinks" {
    const job = try jobFor(std.testing.allocator, &.{ 0xf0011234, 0x80000000 });
    defer job.deinit();
    const public = try Public.Owned.init(std.testing.allocator, job, .{});
    defer public.deinit();
    var rows = try Rows.logical(std.testing.allocator, public, public.pin, true);
    defer rows.deinit();
    inline for (.{ G, X, B, R, Word }, .{ rows.framed.rows.g_rows, rows.framed.rows.xor_rows, rows.boundary_rows, rows.framed.route_rows, rows.word_rows }) |Air, values| try std.testing.expect(try constraints(Air, values));
    try std.testing.expectEqualSlices(u8, &public.pin.root, &rows.framed.digest.?);
    var pin = public.pin;
    pin.word_count += 1;
    try std.testing.expectError(error.UntrustedInputTailPublic, Rows.logical(std.testing.allocator, public, pin, true));
}
test "input tail provider: source normalization key identity and cap rejects are metadata only" {
    const job = try jobFor(std.testing.allocator, &.{0x80000001});
    defer job.deinit();
    const public = try Public.Owned.init(std.testing.allocator, job, .{});
    defer public.deinit();
    const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
    const key = Protocol.Key.fromGeometry(.{ .context = .{ .child_key_id = public.statement_id, .child_config = Base.PCS_CONFIG, .graph_ids = @splat(@splat(1)), .transcript_plan_id = @splat(2) }, .log_sizes = @splat(4), .preprocessed_root = @splat(3) });
    const admission = try Protocol.Admission.init(key, try key.identity(), public, public.pin);
    const normalized = try Source.Normalized.fromAdmission(&admission);
    const first = normalized.public_first.?;
    const expected_prefix: u32 = 0x80000001;
    const bytes = try normalized.cell(first + 21);
    try std.testing.expectEqual(@as(u32, expected_prefix >> 24), bytes[3].v);
    try std.testing.expect(normalized.count < Public.MAX_CELLS);
    var bad = key;
    bad.context.child_key_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedInputTailKey, Protocol.Admission.init(bad, try bad.identity(), public, public.pin));
    try std.testing.expectError(error.InputTailResourceLimit, Public.Owned.init(std.testing.allocator, job, .{ .max_words = 0 }));
    const Placement = @import("../recursion/block_v5_input_tail_attachment_v1.zig").Placement;
    try (Placement{ .first_window = 0, .window_count = 67, .job_window_count = 67, .provider_occurrences = 1 }).requireCommonAncestor(67);
    try std.testing.expectError(error.UntrustedInputTailPlacement, (Placement{ .first_window = 0, .window_count = 67, .job_window_count = 67, .provider_occurrences = 2 }).requireCommonAncestor(67));
    try std.testing.expectError(error.InputTailWindowSourceClosureUnavailable, (Placement{ .first_window = 0, .window_count = 67, .job_window_count = 67, .provider_occurrences = 1 }).requireComplete());
}
test "input tail provider: original B5PD chain uses bounded input hash calls and unchanged final digest" {
    var input: [753]u32 = undefined;
    for (&input, 0..) |*word, i| word.* = @truncate(i *% 0xffff7011);
    const job = try jobFor(std.testing.allocator, &input);
    defer job.deinit();
    const public = try Public.Owned.init(std.testing.allocator, job, .{});
    defer public.deinit();
    const data = job.expected().windows[0].data.publicData(job.expected().input_words);
    var fields = try @import("../recursion/block_v5_global_public_fields_v1.zig").init(std.testing.allocator, &data, .rv32im_zkvm_v1, 1, 2, .{});
    defer fields.deinit();
    var frontiers: [32]Consumer.Caller = undefined;
    const statement = Digest.Statement{ .namespace = 50000, .fields = &fields, .carrier = public, .expected_input = public.pin, .field_source = .{ .circuit = 900, .first_wire = 0 }, .prefix_source = .{ .circuit = 901, .first_wire = 0 }, .frontier_sources = callerSources(&public.geometry, &frontiers) };
    var actual = try Digest.prepare(std.testing.allocator, statement);
    defer actual.deinit();
    var trusted = try Digest.trusted(std.testing.allocator, statement);
    defer trusted.deinit();
    try std.testing.expectEqualSlices(u8, &@import("block_v5_native_public_admission_v1.zig").publicDigest(&data), &actual.digest);
    inline for (.{ G, X, B, R }, .{ actual.rows.g_rows, actual.rows.xor_rows, actual.rows.boundary_rows, actual.route_rows }, .{ trusted.rows.g_rows, trusted.rows.xor_rows, trusted.rows.boundary_rows, trusted.route_rows }) |Air, live, fixed| {
        try std.testing.expectEqual(live.len, fixed.len);
        for (live, fixed) |row, admitted| try std.testing.expectEqualSlices(M, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], admitted[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
    const input_span = fields.chunks[12];
    for (actual.field_uses) |field| try std.testing.expect(field.coordinate < input_span.first or field.coordinate >= input_span.first + input_span.words.len);
    try std.testing.expectEqual(Public.PREFIX_WORDS, actual.prefix_uses.len);
    try std.testing.expectEqual(public.frontier.len, actual.frontier_uses.len);
    try std.testing.expect(Digest.Prepared.native_digest_pairing_pending);
}

fn consumerRollback(a: std.mem.Allocator) !void {
    const input = [_]u32{0xffffffff};
    const state: [32]u8 = @splat(0x17);
    const expected = (core.channel.blake3.framing.Frame{ .words = .{ .state = state, .values = &input } }).hash();
    const statement = Consumer.Statement{ .circuit = 903, .word_count = 1, .state = state, .claim = expected, .sources = .{ .state = .{ .circuit = 900, .first_wire = 0 }, .prefix = .{ .circuit = 901, .first_wire = 0 }, .frontier = &.{} } };
    var actual = try Consumer.prepare(a, statement, &input, &.{});
    defer actual.deinit();
    var fixed = try Consumer.trusted(a, statement);
    defer fixed.deinit();
    try std.testing.expectEqualSlices(u8, &expected, &actual.digest);
    try std.testing.expectEqual(actual.route_rows.len, fixed.route_rows.len);
}
test "input tail provider: bounded consumer exhaustive failure cleanup and large mathematical extent" {
    try consumerRollback(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, consumerRollback, .{});
    const geometry = try Tail.Geometry.init(16 << 20);
    var sources: [32]Consumer.Caller = undefined;
    const statement = Consumer.Statement{ .circuit = 903, .word_count = geometry.words, .state = @splat(0), .claim = @splat(0), .sources = .{ .state = .{ .circuit = 900, .first_wire = 0 }, .prefix = .{ .circuit = 901, .first_wire = 0 }, .frontier = callerSources(&geometry, &sources) } };
    // Actual trusted preprocessing for a 64MiB input uses bounded prefix work;
    // no 64MiB buffer or original tail compression graph is allocated.
    var fixed = try Consumer.trusted(std.testing.allocator, statement);
    defer fixed.deinit();
    try std.testing.expectEqual(Public.PREFIX_WORDS, fixed.prefix_uses.len);
    try std.testing.expect(fixed.compression_calls <= 16 + geometry.range_count);
    var changed = statement;
    changed.sources.prefix = changed.sources.state;
    try std.testing.expectError(error.InvalidInputTailConsumer, changed.require());
    changed = statement;
    changed.sources.frontier = statement.sources.frontier[1..];
    try std.testing.expectError(error.InvalidInputTailConsumer, changed.require());
}

test "input tail provider: durable original and consumer columns retain backing budget after owner release" {
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const a = std.testing.allocator;
    const job = try jobFor(a, &.{ 0xf0011234, 0x80000000 });
    defer job.deinit();
    const public = try Public.Owned.init(a, job, .{});
    defer public.deinit();
    const config = @import("../recursion/blake3_execution_parent_protocol.zig").PCS_CONFIG;
    {
        const backing = try Budget.create(a, 256 << 20);
        var rows = Rows.prepare(backing.allocator(), public, public.pin, config, .{ .max_owned_bytes = 128 << 20 }) catch |failure| {
            backing.destroy();
            return failure;
        };
        backing.destroy();
        defer rows.deinit();
        try std.testing.expect(rows.backing_owner != null);
        try std.testing.expect(rows.budget.snapshot().live_bytes > 0);
    }
    const data = job.expected().windows[0].data.publicData(job.expected().input_words);
    var fields = try @import("../recursion/block_v5_global_public_fields_v1.zig").init(a, &data, .rv32im_zkvm_v1, 1, 2, .{});
    defer fields.deinit();
    const statement = Digest.Statement{ .namespace = 50000, .fields = &fields, .carrier = public, .expected_input = public.pin, .field_source = .{ .circuit = 900, .first_wire = 0 }, .prefix_source = .{ .circuit = 901, .first_wire = 0 }, .frontier_sources = &.{} };
    const backing = try Budget.create(a, 256 << 20);
    var columns = Digest.prepareColumns(backing.allocator(), statement, config, 128 << 20) catch |failure| {
        backing.destroy();
        return failure;
    };
    backing.destroy();
    defer columns.deinit();
    try std.testing.expect(columns.backing_owner != null);
    try std.testing.expect(columns.requests.len != 0);
    const input_span = fields.chunks[12];
    for (columns.requests) |request| switch (request.source) {
        .public_field => |coordinate| try std.testing.expect(coordinate < input_span.first or coordinate >= input_span.first + input_span.words.len),
        else => {},
    };
    fields.chunks[1].first += 1;
    try std.testing.expectError(error.UntrustedInputTailPublicDigest, statement.require());
}

test "input tail provider: frontier public export adds exactly one read to original seven-round CV use" {
    var input: [240]u32 = undefined;
    for (&input, 0..) |*value, i| value.* = @truncate(i *% 0xe11bb437);
    const job = try jobFor(std.testing.allocator, &input);
    defer job.deinit();
    const public = try Public.Owned.init(std.testing.allocator, job, .{});
    defer public.deinit();
    var rows = try Rows.logical(std.testing.allocator, public, public.pin, true);
    defer rows.deinit();
    try std.testing.expectEqual(@as(usize, 1), public.frontier.len);
    // This is an exact original wire-tuple conservation diagnostic; bitwise
    // and range providers remain the genuine Parent producer's job.
    try std.testing.expect(try tupleClosure(rows.framed.rows.g_rows, rows.framed.rows.xor_rows, rows.boundary_rows, rows.framed.route_rows, rows.word_rows, &.{}));
    const prefix_sink = rows.boundary_rows.len - public.prefix_count;
    const cv_sink = prefix_sink - 8 * public.frontier.len;
    const saved = rows.boundary_rows[cv_sink][7];
    rows.boundary_rows[cv_sink][7] = M.zero();
    try std.testing.expect(!try tupleClosure(rows.framed.rows.g_rows, rows.framed.rows.xor_rows, rows.boundary_rows, rows.framed.route_rows, rows.word_rows, &.{}));
    rows.boundary_rows[cv_sink][7] = saved;
    rows.boundary_rows[cv_sink][0] = rows.boundary_rows[cv_sink][0].add(M.one());
    try std.testing.expect(!try constraints(B, rows.boundary_rows));
}

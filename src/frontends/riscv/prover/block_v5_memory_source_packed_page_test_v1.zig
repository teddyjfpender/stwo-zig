//! Nonproving packed SOURCE SHA/raw-page contracts. Synthetic page roots are
//! proposal fixtures only. No PCS, FRI, STARK, guest or device is invoked.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Packed = @import("block_v5_memory_source_packed_sha_v1.zig");
const Raw = @import("block_v5_memory_source_batch_raw_v1.zig");
const Schema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const Legacy = @import("block_v5_memory_source_legacy_schema_v1.zig");
const Air = @import("block_v5_memory_source_sha_connector_air_v1.zig");
const Component = @import("block_v5_memory_source_sha_connector_component_v1.zig");
const Original = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
const Crypto = @import("../recursion/air/block_v5_memory_source_crypto_v1.zig");
const SHA = @import("../air/guest_precompile/sha256_compression.zig");
const Input = @import("../air/guest_precompile/sha256_packed_source.zig");
const Calls = @import("../air/guest_precompile/sha256_packed_call.zig");
const Rows = @import("../air/guest_precompile/sha256_compression_rows.zig");
const lang = @import("../air/lang/mod.zig");
const Support = @import("../recursion/air/test_support.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
fn admission(bytes: []const u8) !Source.Admitted {
    const empty = Initial.sha256("");
    return Source.make(.{ .initial = .{
        .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 256, .stack_bottom = 128, .stack_top = 512, .io_base = 256, .io_end = 768, .input_base = 32, .input_end = 256, .output_len_addr = 768, .output_data_addr = 772, .output_base = 768, .output_end = 1024 },
        .initial_rw_root = @splat(1),
        .initial_registers = @splat(0),
        .public_input_sha256 = Initial.sha256(bytes),
        .public_input_len = bytes.len,
        .input_words = .{ .records = 0, .sha256 = empty },
        .rw_words = .{ .records = 0, .sha256 = empty },
        .first_touches = .{ .records = 0, .sha256 = empty },
    }, .memory_plan_digest = @splat(7), .expected_final_rw_root = @splat(1), .endpoints = .{ .records = 0, .sha256 = empty } }, @splat(8), .{});
}
fn sourceChallenges() Source.Challenges {
    return .{ .word = .{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() }, .bytes = .dummy(), .input = .dummy(), .insertion = .dummy(), .before = .dummy(), .after = .dummy(), .route = .dummy(), .roots = .dummy(), .ordering = .dummy(), .sha_chain = .dummy() };
}
fn wireChallenge() Air.Algebra(Q).Challenge {
    const c = Universal.Elements.init(6, Q.fromU32Unchecked(17, 19, 23, 29), Q.fromU32Unchecked(31, 37, 41, 43));
    return .{ .z = c.z, .powers = c.alpha_powers[0..6].* };
}
const Capture = struct {
    values: [2]Packed.Boundary = undefined,
    count: usize = 0,
    source_rows: usize = 0,
    schedule_rows: usize = 0,
    round_rows: usize = 0,
    feed_rows: usize = 0,
    pub fn source(self: *@This(), _: *const Input.Row) !void {
        self.source_rows += 1;
    }
    pub fn schedule(self: *@This(), _: *const Rows.Schedule.Row) !void {
        self.schedule_rows += 1;
    }
    pub fn round(self: *@This(), _: *const Rows.Round.Row) !void {
        self.round_rows += 1;
    }
    pub fn feedForward(self: *@This(), _: *const Rows.FeedForward.Row) !void {
        self.feed_rows += 1;
    }
    pub fn boundary(self: *@This(), b: Packed.Boundary) !void {
        if (self.count == self.values.len) return error.TooManySourceShaBlocks;
        self.values[self.count] = b;
        self.count += 1;
    }
};
const ScalarSink = struct {
    total: Q = Q.zero(),
    pub fn zero(_: *@This(), value: Q) !void {
        if (!value.isZero()) return error.UnsatisfiedSourceShaConnector;
    }
    pub fn wire(self: *@This(), call: u32, node: u32, weight: u32, bytes: [4][8]Q, positive: bool) !void {
        var tuple: [6]Q = undefined;
        tuple[0] = Q.fromBase(M.fromCanonical(call));
        tuple[1] = Q.fromBase(M.fromCanonical(node));
        for (bytes, tuple[2..]) |bits, *value| {
            value.* = Q.zero();
            var power = Q.one();
            for (bits) |bit| {
                value.* = value.*.add(bit.mul(power));
                power = power.add(power);
            }
        }
        var denominator = wireChallenge().z.neg();
        for (tuple, wireChallenge().powers) |value, power| denominator = denominator.add(value.mul(power));
        const term = (try denominator.inv()).mulM31(M.fromCanonical(weight));
        self.total = if (positive) self.total.add(term) else self.total.sub(term);
    }
};
fn boundaryBits(b: Packed.Boundary) Packed.Algebra(Q).BoundaryBits {
    const C = Crypto.Algebra(Q);
    var out: Packed.Algebra(Q).BoundaryBits = undefined;
    for (&out.state, b.state) |*word, value| word.* = C.word(value);
    for (&out.block, b.block) |*byte, value| byte.* = C.byte(value);
    for (&out.output, b.output) |*word, value| word.* = C.word(value);
    return out;
}
test "source packed page SHA: original four-core emission exact padding edges and arbitrary chaining match independent SHA" {
    var bytes: [128]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @truncate(i * 37 + 11);
    for ([_]usize{ 0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128 }) |length| {
        const a = try admission(bytes[0..length]);
        var state = SHA.initial_state;
        var total: usize = 0;
        for (0..length / 64 + 1) |block| {
            var raw: [64]u8 = @splat(0);
            const used: usize = @min(@as(usize, 64), length - block * 64);
            @memcpy(raw[0..used], bytes[block * 64 ..][0..used]);
            var capture = Capture{};
            state = try Packed.emitChunk(&a, .public_input, block, raw, state, try Raw.firstCall(&a, .public_input, block), &capture);
            try std.testing.expectEqual(capture.count * 88, capture.source_rows);
            try std.testing.expectEqual(capture.count * 48, capture.schedule_rows);
            try std.testing.expectEqual(capture.count * 64, capture.round_rows);
            try std.testing.expectEqual(capture.count * 8, capture.feed_rows);
            total += capture.count;
        }
        try std.testing.expectEqual(try Packed.compressionCount(length), total);
        try std.testing.expectEqualSlices(u8, &a.digest(.public_input), &SHA.stateBytes(state));
    }
}
test "source packed page SHA semantics: exact Source9 byte input and chain sums match original bit-crypto oracle" {
    var bytes: [65]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @truncate(i * 13);
    const a = try admission(&bytes);
    const c = sourceChallenges();
    const C = Crypto.Algebra(Q);
    const A = Packed.Algebra(Q);
    var state = SHA.initial_state;
    for (0..2) |block| {
        var raw: [64]u8 = @splat(0);
        const used: usize = if (block == 0) 64 else 1;
        @memcpy(raw[0..used], bytes[block * 64 ..][0..used]);
        var capture = Capture{};
        const output = try Packed.emitChunk(&a, .public_input, block, raw, state, try Raw.firstCall(&a, .public_input, block), &capture);
        var raw_bits: [64]C.Byte = undefined;
        var state_bits: C.State = undefined;
        for (&raw_bits, raw) |*byte, value| byte.* = C.byte(value);
        for (&state_bits, state) |*word, value| word.* = C.word(value);
        var captured: [2]A.BoundaryBits = undefined;
        for (capture.values[0..capture.count], captured[0..capture.count]) |boundary, *bits| bits.* = boundaryBits(boundary);
        var sink = ScalarSink{};
        const out = try A.evaluate(&a, .public_input, block, raw_bits, state_bits, try Raw.firstCall(&a, .public_input, block), captured[0..capture.count], &sink);
        const sums = try A.semantic(&a, .public_input, block, raw_bits, state_bits, out, .{ .{ .z = c.bytes.z, .alpha = c.bytes.alpha }, .{ .z = c.input.z, .alpha = c.input.alpha }, .{ .z = c.sha_chain.z, .alpha = c.sha_chain.alpha } });
        var original: [Original.INPUT_COUNT]Q = undefined;
        try Original.writeInputs(.{ .raw = raw, .state = state }, c, .{}, &original);
        const oracle = try Original.Algebra(Q).compute(&a, .{ .sha = .{ .stream = .public_input, .block = block } }, &original, &sink);
        try std.testing.expectEqualDeep(oracle.bytes, sums.bytes);
        try std.testing.expectEqualDeep(oracle.input, sums.input);
        try std.testing.expectEqualDeep(oracle.sha_chain, sums.sha_chain);
        state = output;
    }
}
fn connectorRow(a: *const Source.Admitted, raw: [64]u8, capture: *const Capture) ![Air.MAIN_COUNT]Q {
    var result: [Air.MAIN_COUNT]Q = undefined;
    var original: [Original.INPUT_COUNT]Q = undefined;
    try Original.writeInputs(.{ .raw = raw, .state = SHA.initial_state }, sourceChallenges(), .{}, &original);
    @memcpy(result[0..Air.SOURCE_MAIN_COUNT], original[0..Air.SOURCE_MAIN_COUNT]);
    var bits: [Air.CAPTURE_MAIN_COUNT]M = undefined;
    try Air.captureInputs(capture.values[0..capture.count], &bits);
    for (result[Air.SOURCE_MAIN_COUNT..], bits) |*value, bit| value.* = Q.fromBase(bit);
    _ = a;
    return result;
}
test "source packed page SHA AIR: exact first and second captures padding digest and wire ID mutations fail" {
    const bytes: [56]u8 = @splat(0x65);
    const a = try admission(&bytes);
    var raw: [64]u8 = @splat(0);
    @memcpy(raw[0..bytes.len], &bytes);
    var capture = Capture{};
    _ = try Packed.emitChunk(&a, .public_input, 0, raw, SHA.initial_state, 1, &capture);
    const main = try connectorRow(&a, raw, &capture);
    var fixed: [Air.EXPANDED_FIXED_COUNT]Q = undefined;
    for (&fixed, try Air.expandedFixedRow(&a, .{ .sha = .{ .stream = .public_input, .block = 0 } })) |*value, cell| value.* = Q.fromBase(cell);
    const terms = Air.Algebra(Q).terms(fixed, main, wireChallenge());
    var current: [Air.INTERACTION_COUNT]Q = undefined;
    for (0..Air.PAIRS) |pair| {
        const change = terms[2 * pair].numerator.mul(try terms[2 * pair].denominator.inv()).add(terms[2 * pair + 1].numerator.mul(try terms[2 * pair + 1].denominator.inv()));
        for (current[4 * pair ..][0..4], change.toM31Array()) |*cell, coordinate| cell.* = Q.fromBase(coordinate);
    }
    const checks = Air.Algebra(Q).constraints(fixed, main, current, @splat(Q.zero()), @splat(Q.zero()), wireChallenge());
    for (checks) |value| try std.testing.expect(value.isZero());
    var changed = main;
    changed[Air.SOURCE_MAIN_COUNT + 128] = Q.fromBase(M.fromCanonical(256));
    var failed = false;
    for (Air.Algebra(Q).constraints(fixed, changed, current, @splat(Q.zero()), @splat(Q.zero()), wireChallenge())) |value| failed = failed or !value.isZero();
    try std.testing.expect(failed);
    fixed[4] = fixed[4].add(Q.one());
    failed = false;
    for (Air.Algebra(Q).constraints(fixed, main, current, @splat(Q.zero()), @splat(Q.zero()), wireChallenge())) |value| failed = failed or !value.isZero();
    try std.testing.expect(failed);
}
test "source packed page SHA SIMD: scalar and packed equations agree on nonzero off-domain masks" {
    const spec = Component.Spec{ .rows = 2, .expected_requests = 64, .claim = .{ .sums = @splat(Q.fromU32Unchecked(3, 5, 7, 11)), .wire_requests = 64 }, .challenge = wireChallenge() };
    const domain = try spec.prepareDomain(2);
    const fixed: [Air.EXPANDED_FIXED_COUNT]Q = @splat(Q.fromU32Unchecked(13, 17, 19, 23));
    const main: [Air.MAIN_COUNT]Q = @splat(Q.fromU32Unchecked(29, 31, 37, 41));
    const current: [Air.INTERACTION_COUNT]Q = @splat(Q.fromU32Unchecked(43, 47, 53, 59));
    const previous: [Air.INTERACTION_COUNT]Q = @splat(Q.fromU32Unchecked(61, 67, 71, 73));
    const scalar = try domain.evaluate(fixed, main, @splat(Q.zero()), current, previous, 2);
    var f: [Air.EXPANDED_FIXED_COUNT]P = undefined;
    var m: [Air.MAIN_COUNT]P = undefined;
    var c: [Air.INTERACTION_COUNT]P = undefined;
    var p: [Air.INTERACTION_COUNT]P = undefined;
    for (&f, fixed) |*out, value| out.* = P.splat(value);
    for (&m, main) |*out, value| out.* = P.splat(value);
    for (&c, current) |*out, value| out.* = P.splat(value);
    for (&p, previous) |*out, value| out.* = P.splat(value);
    const vector = domain.evaluatePacked(f, m, @splat(P.zero()), c, p);
    for (scalar, vector) |expected, actual| for (0..core.fields.m31.PACK_WIDTH) |lane| try std.testing.expectEqualDeep(expected, actual.lane(lane));
}
const Degree = struct {
    n: u8,
    pub fn zero() Degree {
        return .{ .n = 0 };
    }
    pub fn one() Degree {
        return zero();
    }
    pub fn fromBase(_: M) Degree {
        return zero();
    }
    pub fn add(x: Degree, y: Degree) Degree {
        return .{ .n = @max(x.n, y.n) };
    }
    pub fn sub(x: Degree, y: Degree) Degree {
        return add(x, y);
    }
    pub fn neg(x: Degree) Degree {
        return x;
    }
    pub fn mul(x: Degree, y: Degree) Degree {
        return .{ .n = x.n + y.n };
    }
    pub fn fromPartialEvals(values: [4]Degree) Degree {
        var out = zero();
        for (values) |v| out = add(out, v);
        return out;
    }
};
test "source packed page SHA degree: every direct equation and paired wire plane remains within exact degree3 recipe" {
    const variable = Degree{ .n = 1 };
    const equations = Air.Algebra(Degree).constraints(@splat(variable), @splat(variable), @splat(variable), @splat(variable), @splat(Degree.zero()), .{ .z = .zero(), .powers = @splat(Degree.one()) });
    var maximum: u8 = 0;
    for (equations, 0..) |equation, index| {
        try std.testing.expect(equation.n <= try Air.degree(index));
        maximum = @max(maximum, equation.n);
    }
    try std.testing.expectEqual(@as(u8, 3), maximum);
}
const CoreLedger = struct {
    input: *const Input.Definition,
    schedule_definition: *const Calls.ForKind(.schedule).Definition,
    round_definition: *const Calls.ForKind(.round).Definition,
    feed_definition: *const Calls.ForKind(.feed_forward).Definition,
    total: Q = Q.zero(),
    fn row(self: *@This(), arena: *const lang.ir.Arena, values: []const M) !void {
        const evaluated = try Support.evaluateArena(std.testing.allocator, arena, values);
        defer std.testing.allocator.free(evaluated);
        for (arena.constraintsView()) |constraint| try std.testing.expect(evaluated[lang.types.idIndex(constraint.root)].isZero());
        for (arena.effectsView(), 0..) |effect, ordinal| {
            const ids = arena.effectValues(@enumFromInt(ordinal)).?;
            var tuple: [6]M = undefined;
            for (ids, tuple[0..ids.len]) |id, *out| out.* = evaluated[lang.types.idIndex(id)];
            const binding = effect.binding.?;
            if (binding.schema == lang.relation.id(.recursion_wire)) {
                var denominator = wireChallenge().z.neg();
                for (tuple[0..ids.len], wireChallenge().powers[0..ids.len]) |value, power| denominator = denominator.add(Q.fromBase(value).mul(power));
                const term = (try denominator.inv()).mulM31(evaluated[lang.types.idIndex(effect.liveness.?)]);
                self.total = if (binding.role == .consume) self.total.sub(term) else self.total.add(term);
            } else if (binding.schema == lang.relation.id(.range_check_8_8)) {
                try std.testing.expect(tuple[0].toU32() < 256 and tuple[1].toU32() < 256);
            } else if (binding.schema == lang.relation.id(.bitwise)) {
                const x = tuple[0].toU32();
                const y = tuple[1].toU32();
                const z = tuple[2].toU32();
                const op = tuple[3].toU32();
                try std.testing.expect(x < 256 and y < 256 and z < 256 and (op == 0 or op == 2));
                try std.testing.expectEqual(if (op == 0) x & y else x ^ y, z);
            } else return error.UnexpectedSourceShaTable;
        }
    }
    pub fn source(self: *@This(), values: *const Input.Row) !void {
        try self.row(&self.input.arena, values);
    }
    pub fn schedule(self: *@This(), values: *const Rows.Schedule.Row) !void {
        try self.row(&self.schedule_definition.arena, values);
    }
    pub fn round(self: *@This(), values: *const Rows.Round.Row) !void {
        try self.row(&self.round_definition.arena, values);
    }
    pub fn feedForward(self: *@This(), values: *const Rows.FeedForward.Row) !void {
        try self.row(&self.feed_definition.arena, values);
    }
    pub fn boundary(_: *@This(), _: Packed.Boundary) !void {}
};
test "source packed page SHA core closure: actual four original AIRs exact byte and bitwise membership cancel every connector wire" {
    const allocator = std.testing.allocator;
    var input = try Input.build(allocator);
    defer input.deinit();
    var schedule_definition = try Calls.ForKind(.schedule).build(allocator);
    defer schedule_definition.deinit();
    var round_definition = try Calls.ForKind(.round).build(allocator);
    defer round_definition.deinit();
    var feed_definition = try Calls.ForKind(.feed_forward).build(allocator);
    defer feed_definition.deinit();
    const a = try admission("");
    const raw: [64]u8 = @splat(0);
    var ledger = CoreLedger{ .input = &input, .schedule_definition = &schedule_definition, .round_definition = &round_definition, .feed_definition = &feed_definition };
    _ = try Packed.emitChunk(&a, .public_input, 0, raw, SHA.initial_state, 1, &ledger);
    var capture = Capture{};
    _ = try Packed.emitChunk(&a, .public_input, 0, raw, SHA.initial_state, 1, &capture);
    const C = Crypto.Algebra(Q);
    var state: C.State = undefined;
    for (&state, SHA.initial_state) |*word, value| word.* = C.word(value);
    var blocks: [2]Packed.Algebra(Q).BoundaryBits = undefined;
    for (capture.values[0..capture.count], blocks[0..capture.count]) |b, *bits| bits.* = boundaryBits(b);
    var connector = ScalarSink{};
    _ = try Packed.Algebra(Q).evaluate(&a, .public_input, 0, @splat(C.byte(0)), state, 1, blocks[0..capture.count], &connector);
    try std.testing.expect(ledger.total.add(connector.total).isZero());
    var changed = ScalarSink{};
    _ = try Packed.Algebra(Q).evaluate(&a, .public_input, 0, @splat(C.byte(0)), state, 2, blocks[0..capture.count], &changed);
    try std.testing.expect(!ledger.total.add(changed.total).isZero());
}
test "source packed page raw: independent census fixed recipes ABI magic and bit owner retain zero tail" {
    const a = try admission("");
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 2, 8) };
    const plan = try Schema.Protocol.init(&a, config, .{ .page_row_log = 1 });
    const legacy = try Legacy.Protocol.init(&a, config, .{ .page_row_log = 1 });
    try std.testing.expect(!std.meta.eql(Schema.abiId(), Legacy.abiId()));
    try std.testing.expectEqual(@as(u64, 5), plan.total_chunks);
    try std.testing.expectEqual(@as(u64, 5), legacy.total_chunks); // zero edits, grammar still DISTINCT
    try std.testing.expect(!std.meta.eql(plan.identity, legacy.identity));
    try std.testing.expect(!std.mem.eql(u8, Schema.FILE_MAGIC, Legacy.FILE_MAGIC));
    var columns = try Schema.Columns.Columns.init(std.testing.allocator, &a, plan, try plan.page(plan.pages - 1), .{ .page_row_log = 1 });
    defer columns.deinit();
    try columns.append(&a, .{ .kind = try Schema.Stream.kindAt(&a, columns.page.first_chunk), .witness = .{ .state = SHA.initial_state } });
    try std.testing.expectEqualDeep(SHA.initial_state, (try columns.witness(0)).state);
    const tail = @import("../air/block/memory_component_trace.zig").committedRow(1, 1);
    for (0..Schema.MAIN_COUNT) |column| try std.testing.expect(columns.mainColumn(column)[tail].isZero());
    try std.testing.expectError(error.InvalidSourceBatchRawOrdinal, Raw.kindAt(&a, plan.total_chunks));
}
fn rawOwnerContract(allocator: std.mem.Allocator) !void {
    const a = try admission("");
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 2, 8) };
    const limits = Schema.Protocol.Limits{ .page_row_log = 1 };
    const plan = try Schema.Protocol.init(&a, config, limits);
    const page = try plan.page(plan.pages - 1);
    var columns = try Schema.Columns.Columns.init(allocator, &a, plan, page, limits);
    defer columns.deinit();
    try columns.append(&a, .{ .kind = try Schema.Stream.kindAt(&a, page.first_chunk), .witness = .{ .state = SHA.initial_state } });
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const pin = Schema.Protocol.Pin{ .plan_id = plan.identity, .page = page, .config = config, .roots = .{ @splat(21), @splat(31) } };
    // Durable bytes remain proposals; only actual replay recommit (retained
    // separately by body fixture) can turn them into proving input owners.
    const stored = try Schema.Store.write(dir.dir, "raw-page.bits", plan, pin, &columns, .{});
    try std.testing.expectEqual(@as(u64, 64 + 96), stored.bytes);
    var loaded = try Schema.Store.load(allocator, dir.dir, "raw-page.bits", &a, plan, pin, stored, limits, .{});
    defer loaded.deinit();
    try std.testing.expectEqualDeep(columns.snapshot(), loaded.snapshot());
    try std.testing.expectEqualDeep(SHA.initial_state, (try loaded.witness(0)).state);
    var wrong = stored;
    wrong.sha256[0] ^= 1;
    const result = Schema.Store.load(allocator, dir.dir, "raw-page.bits", &a, plan, pin, wrong, limits, .{});
    if (result) |success| {
        var owner = success;
        owner.deinit();
        return error.TestExpectedError;
    } else |err| switch (err) {
        error.UntrustedMemorySourcePageHash => {},
        else => return err, // OOM belongs to the exhaustive failure harness.
    }
}
test "source packed page raw replay: distinct bounded codec exact original cells and tampered SHA rejection" {
    try rawOwnerContract(std.testing.allocator);
}
test "source packed page raw faults: all page owner and loaded proposal allocations unwind" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, rawOwnerContract, .{});
}

const CoreColumns = @import("block_v5_memory_source_packed_sha_columns_v1.zig");
const Kernel = @import("block_v5_memory_source_packed_sha_proof_v1.zig");
const Operand = @import("block_v5_memory_source_packed_sha_replay_v1.zig");
const KernelCodec = @import("block_v5_memory_source_packed_sha_codec_v1.zig");
const ReadBytes = struct {
    bytes: []const u8,
    pub fn read(context: *anyopaque, stream: Source.Stream, offset: u64, out: []u8) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (stream != .public_input or offset > self.bytes.len or out.len > self.bytes.len - @as(usize, @intCast(offset))) return error.InvalidSourcePageTestRead;
        @memcpy(out, self.bytes[@intCast(offset)..][0..out.len]);
    }
};
fn coreColumnCase(allocator: std.mem.Allocator, length: usize, last_only: bool) !void {
    var bytes: [120]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @truncate(91 * i + 13);
    const admitted = try admission(bytes[0..length]);
    const limits = Schema.Protocol.Limits{ .page_row_log = 2 };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 2, 8) };
    const plan = try Schema.Protocol.init(&admitted, config, limits);
    const page = try plan.page(if (last_only) plan.pages - 1 else 0);
    var raw = try Schema.Columns.Columns.init(allocator, &admitted, plan, page, limits);
    defer raw.deinit();
    var reader = ReadBytes{ .bytes = bytes[0..length] };
    var cursor = try Schema.cursorInit(admitted, .{ .context = &reader, .read = ReadBytes.read });
    for (0..page.first_chunk) |_| _ = try cursor.next();
    for (0..page.chunks) |_| try raw.append(&admitted, (try cursor.next()).?);
    var direct = try CoreColumns.Columns.regenerate(allocator, &admitted, &raw, .{});
    defer direct.deinit();
    // Recover the small candidate call list solely as an independent legacy
    // row oracle. Production regeneration never builds this array/tape.
    var calls: std.ArrayList(Rows.Call) = .empty;
    defer calls.deinit(allocator);
    for (0..page.chunks) |i| switch (try Raw.kindAt(&admitted, page.first_chunk + i)) {
        .sha => |sha| {
            const witness = try raw.witness(@intCast(i));
            var capture = Capture{};
            _ = try Packed.emitChunk(&admitted, sha.stream, sha.block, witness.raw, witness.state, try Raw.firstCall(&admitted, sha.stream, sha.block), &capture);
            for (capture.values[0..capture.count]) |value| try calls.append(allocator, .{ .execution_clock = value.call, .state = value.state, .block = value.block });
        },
        .record => {},
    };
    try std.testing.expectEqual(calls.items.len, direct.geometry.compressions);
    var rows = try Rows.prepare(allocator, calls.items);
    defer rows.deinit();
    const row_tuple = rows.tuple();
    var reference_counters = [_]@import("../air/lookups/tables/counter.zig").Counter{
        try .init(allocator, .bitwise), undefined,
    };
    defer reference_counters[0].deinit(allocator);
    reference_counters[1] = try .init(allocator, .range_check_8_8);
    defer reference_counters[1].deinit(allocator);
    inline for (CoreColumns.Airs, 0..) |AirType, i| {
        var projected: std.ArrayList(@import("stwo_prover_engine").pcs.ColumnEvaluation) = .empty;
        defer {
            for (projected.items) |column| allocator.free(column.values);
            projected.deinit(allocator);
        }
        try @import("../recursion/air/blake3_row_columns.zig").project(AirType, allocator, row_tuple[i], rows.geometry.logs[i], 1, &projected);
        for (projected.items, direct.owners[i].main) |old, fresh| try std.testing.expectEqualSlices(M, old.values, fresh.values);
        // Register ALL padded legacy rows; this independently covers the
        // original unconditional zero-padding range/bitwise effects.
        try @import("../recursion/air/blake3_row_columns.zig").register(AirType, &direct.plans[i], row_tuple[i], &reference_counters);
    }
    for (&direct.counters, &reference_counters) |actual, wanted| try std.testing.expectEqualSlices(M, wanted.values, actual.values);
    const original = direct.snapshot();
    const at = @import("../air/block/memory_component_trace.zig").committedRow(0, page.row_log);
    direct.captures.values[at] = direct.captures.values[at].add(M.one());
    try std.testing.expect(!std.meta.eql(original, direct.snapshot()));
    // A cap rejection precedes any core graph/matrix allocation.
    try std.testing.expectError(error.SourcePackedPageResourceLimit, CoreColumns.Geometry.fromPage(&admitted, page, .{ .max_compressions = 0 }));
}
test "source packed page core replay: direct original matrices and ALL padding counters match full legacy rows" {
    try coreColumnCase(std.testing.allocator, 120, false);
    try coreColumnCase(std.testing.allocator, 0, true);
}
test "source packed page core faults: every graph direct column table and capture allocation unwinds" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, coreColumnCase, .{ @as(usize, 0), true });
}
test "source packed page kernel admission: exact six-root geometry calls wire closure mode and limits fail closed" {
    const admitted = try admission("");
    const limits = Operand.Limits{ .first = .{ .page_row_log = 1 } };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 2, 8) };
    const plan = try Schema.Protocol.init(&admitted, config, limits.first);
    const page = try plan.page(0);
    const pin = Operand.Pin{ .raw = .{ .plan_id = plan.identity, .page = page, .roots = .{ @splat(1), @splat(2) }, .config = config }, .geometry = try CoreColumns.Geometry.fromPage(&admitted, page, .{}), .roots = .{ @splat(1), @splat(2), @splat(3), @splat(4), @splat(5), @splat(6) } };
    try pin.require(&admitted, plan, limits);
    const identity = try pin.identity(&admitted, plan, limits);
    var changed = pin;
    changed.roots[5][0] ^= 1;
    try std.testing.expect(!std.meta.eql(identity, try changed.identity(&admitted, plan, limits)));
    changed = pin;
    changed.geometry.compressions += 1;
    try std.testing.expectError(error.UntrustedSourcePackedPagePin, changed.require(&admitted, plan, limits));
    changed = pin;
    changed.raw.config.pow_bits += 1;
    try std.testing.expectError(error.UntrustedSourceFirstPin, changed.require(&admitted, plan, limits));
    const claim = @import("block_v5_memory_source_sha_connector_interaction_v1.zig").Claim{ .sums = @splat(Q.zero()), .wire_requests = @as(u64, pin.geometry.compressions) * 32 };
    try Kernel.requireClaims(pin, @splat(Q.zero()), claim, .{ .operands = limits });
    var claims: [6]Q = @splat(Q.zero());
    claims[4] = Q.one();
    try std.testing.expectError(error.UnclosedSourceShaKernel, Kernel.requireClaims(pin, claims, claim, .{ .operands = limits }));
    try std.testing.expectError(error.SourcePackedPageResourceLimit, Kernel.requireClaims(pin, @splat(Q.zero()), claim, .{ .operands = limits, .max_interaction_cells = 1 }));
    var wrong = claim;
    wrong.wire_requests += 1;
    try std.testing.expectError(error.InvalidSourceShaConnectorClaim, Kernel.requireClaims(pin, @splat(Q.zero()), wrong, .{ .operands = limits }));
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.EndOfStream, KernelCodec.decode(failing.allocator(), "", &admitted, plan, pin, .{ .operands = limits }, .{}));
}

fn kernelInventoryCase(allocator: std.mem.Allocator) !void {
    const admitted = try admission("");
    const limits = Operand.Limits{ .first = .{ .page_row_log = 1 } };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 2, 8) };
    const plan = try Schema.Protocol.init(&admitted, config, limits.first);
    const page = try plan.page(0);
    const pin = Operand.Pin{ .raw = .{ .plan_id = plan.identity, .page = page, .roots = .{ @splat(1), @splat(2) }, .config = config }, .geometry = try CoreColumns.Geometry.fromPage(&admitted, page, .{}), .roots = .{ @splat(1), @splat(2), @splat(3), @splat(4), @splat(5), @splat(6) } };
    const claim = @import("block_v5_memory_source_sha_connector_interaction_v1.zig").Claim{ .sums = @splat(Q.zero()), .wire_requests = @as(u64, pin.geometry.compressions) * 32 };
    const owner = try Kernel.ComponentOwner.init(allocator, pin, .dummy(), @splat(Q.zero()), claim, .{ .operands = limits });
    defer owner.deinit();
    // These zero claims/roots are only construction proposals. No proof is
    // forged or verified, and no equation receipt is returned by this fixture.
    const handles = try owner.verifiers();
    const combined = core.air.components.Components{ .components = &handles, .n_preprocessed_columns = Schema.FIXED_COUNT };
    try std.testing.expectEqual(@as(u32, Kernel.COMPOSITION_SPLIT), try combined.compositionLogSplit());
    var logs = try combined.columnLogSizes(allocator);
    defer logs.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 7), logs.items.len);
    for (logs.items, 0..) |actual, i| {
        const expected = try Kernel.columnLogs(allocator, pin, i);
        defer allocator.free(expected);
        try std.testing.expectEqualSlices(u32, expected, actual);
    }
    const maximum_log = combined.compositionLogDegreeBound() - Kernel.COMPOSITION_SPLIT;
    var masks = try combined.maskPoints(allocator, .zero(), maximum_log, false);
    defer masks.deinitDeep(allocator);
    for (masks.items, logs.items) |columns, inventory| {
        try std.testing.expectEqual(inventory.len, columns.len);
    }
    // Every row/capture selector is opened once, even though all components
    // consume global absolute views. Only actual prefix planes have prev masks.
    for (masks.items[0..6]) |columns| for (columns) |samples| try std.testing.expectEqual(@as(usize, 1), samples.len);
    var previous_count: usize = 0;
    for (masks.items[6]) |samples| {
        try std.testing.expect(samples.len == 1 or samples.len == 2);
        if (samples.len == 2) previous_count += 1;
    }
    try std.testing.expect(previous_count >= 128);
}
test "source packed page kernel masks: exact seven-tree column inventory no duplicated fixed main or prefix columns" {
    try kernelInventoryCase(std.testing.allocator);
}
test "source packed page kernel owner faults: every typed component and remapped mask allocation unwinds" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, kernelInventoryCase, .{});
}

const Operands = @import("block_v5_memory_source_raw_operand_codec_v1.zig");
test "source packed page compact operands: exact record stream predecessor full clock and canonical dropped cells" {
    const kinds = [_]Original.Kind{
        .{ .sha = .{ .stream = .public_input, .block = 0 } },
        .{ .record = .{ .stream = .input_words, .ordinal = 1 } },
        .{ .record = .{ .stream = .rw_words, .ordinal = 1 } },
        .{ .record = .{ .stream = .first_touches, .ordinal = 1 } },
        .{ .record = .{ .stream = .endpoints, .ordinal = 1 } },
    };
    const lengths = [_]usize{ 96, 12, 12, 12, 20 };
    var buffer: [Operands.MAX_BYTES]u8 = undefined;
    for (kinds, lengths) |kind, length| {
        var w = Original.Witness{};
        switch (kind) {
            .sha => {
                for (&w.raw, 0..) |*v, i| v.* = @intCast(i);
                w.state = .{ 0xffffffff, 2, 3, 4, 5, 6, 7, 8 };
            },
            .record => |r| {
                w.address = 0xfffffffc;
                w.previous_address = 0x80000000;
                if (r.stream == .first_touches) w.before = 0xfedcba98 else w.after = 0xfedcba98;
                if (r.stream == .endpoints) w.clock = 0xfedcba9876543210;
            },
            else => unreachable,
        }
        try std.testing.expectEqual(length, try Operands.size(kind));
        try Operands.encode(kind, w, buffer[0..length]);
        try std.testing.expectEqualDeep(w, try Operands.decode(kind, buffer[0..length]));
        try std.testing.expectError(error.InvalidSourceRawOperandLength, Operands.decode(kind, buffer[0 .. length - 1]));
        var forged = w;
        forged.sibling[31] = 1;
        try std.testing.expectError(error.NonCanonicalSourceRawOperand, Operands.encode(kind, forged, buffer[0..length]));
        forged = w;
        if (kind == .sha) forged.clock = 1 else forged.raw[63] = 1;
        try std.testing.expectError(error.NonCanonicalSourceRawOperand, Operands.encode(kind, forged, buffer[0..length]));
    }
    const kind = kinds[4];
    const w = Original.Witness{ .address = 12, .previous_address = 4, .clock = 0xfedcba9876543210, .after = 19 };
    try Operands.encode(kind, w, buffer[0..20]);
    buffer[15] ^= 0x80;
    try std.testing.expect((try Operands.decode(kind, buffer[0..20])).clock != w.clock);
    try std.testing.expectError(error.InvalidSourceRawOperandKind, Operands.size(.{ .record = .{ .stream = .public_input, .ordinal = 0 } }));
    try std.testing.expectError(error.InvalidSourceRawOperandKind, Operands.size(.{ .root = .{ .edit = .update, .ordinal = 0 } }));
}
test "source packed page compact storage: exact cap unused private cells and omitted row tail fail before publication" {
    const a = try admission("");
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 2, 8) };
    const limits = Schema.Protocol.Limits{ .page_row_log = 1 };
    const plan = try Schema.Protocol.init(&a, config, limits);
    const page = try plan.page(plan.pages - 1);
    var columns = try Schema.Columns.Columns.init(std.testing.allocator, &a, plan, page, limits);
    defer columns.deinit();
    try columns.append(&a, .{ .kind = try Schema.Stream.kindAt(&a, page.first_chunk), .witness = .{ .state = SHA.initial_state } });
    const pin = Schema.Protocol.Pin{ .plan_id = plan.identity, .page = page, .config = config, .roots = .{ @splat(21), @splat(31) } };
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try std.testing.expectError(error.MemorySourcePageResourceLimit, Schema.Store.write(dir.dir, "cap", plan, pin, &columns, .{ .max_file_bytes = 159 }));
    const Placement = @import("../air/block/memory_component_trace.zig");
    const live = Placement.committedRow(0, page.row_log);
    // Address bits are unused in SHA kind and cannot disappear during encoding.
    const address_bit = 64 * 8 + 8 * 32;
    columns.main[address_bit * columns.rows() + live] = M.one();
    try std.testing.expectError(error.NonCanonicalSourceRawOperand, Schema.Store.write(dir.dir, "unused", plan, pin, &columns, .{}));
    columns.main[address_bit * columns.rows() + live] = M.zero();
    columns.main[Placement.committedRow(1, page.row_log)] = M.one();
    try std.testing.expectError(error.NonCanonicalMemorySourcePageTail, Schema.Store.write(dir.dir, "tail", plan, pin, &columns, .{}));
    columns.main[Placement.committedRow(1, page.row_log)] = M.zero();
    // The rejected writers cleaned temporary files and published no final name.
    try std.testing.expectError(error.FileNotFound, dir.dir.openFile("unused", .{}));
    try std.testing.expectError(error.FileNotFound, dir.dir.openFile("tail", .{}));
    const stored = try Schema.Store.write(dir.dir, "tail", plan, pin, &columns, .{ .max_file_bytes = 160 });
    try std.testing.expectEqual(@as(u64, 160), stored.bytes);
    try std.testing.expectError(error.ExistingMemorySourcePage, Schema.Store.write(dir.dir, "tail", plan, pin, &columns, .{}));
}

fn compactBufferedContract(allocator: std.mem.Allocator) !void {
    var bytes: [4096]u8 = undefined;
    for (&bytes, 0..) |*v, i| v.* = @truncate(i * 73 + 19);
    var pins = (try admission("")).pins;
    pins.initial.layout.data_end = 8192;
    pins.initial.layout.stack_bottom = 8192;
    pins.initial.layout.stack_top = 16384;
    pins.initial.layout.io_base = 16384;
    pins.initial.layout.io_end = 32768;
    pins.initial.layout.input_end = 8192;
    pins.initial.public_input_len = bytes.len;
    pins.initial.public_input_sha256 = Initial.sha256(&bytes);
    const a = try Source.make(pins, @splat(8), .{});
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 2, 8) };
    const limits = Schema.Protocol.Limits{ .page_row_log = 7 };
    const plan = try Schema.Protocol.init(&a, config, limits);
    try std.testing.expectEqual(@as(u32, 1), plan.pages);
    const page = try plan.page(0);
    var columns = try Schema.Columns.Columns.init(allocator, &a, plan, page, limits);
    defer columns.deinit();
    var reader = ReadBytes{ .bytes = &bytes };
    var cursor = try Schema.cursorInit(a, .{ .context = &reader, .read = ReadBytes.read });
    for (0..page.chunks) |_| try columns.append(&a, (try cursor.next()).?);
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const pin = Schema.Protocol.Pin{ .plan_id = plan.identity, .page = page, .config = config, .roots = .{ @splat(21), @splat(31) } };
    const stored = try Schema.Store.write(dir.dir, "multi-buffer", plan, pin, &columns, .{});
    try std.testing.expectEqual(@as(u64, 64 + 69 * 96), stored.bytes);
    try std.testing.expect(stored.bytes > 4096);
    var loaded = try Schema.Store.load(allocator, dir.dir, "multi-buffer", &a, plan, pin, stored, limits, .{});
    defer loaded.deinit();
    try std.testing.expectEqualDeep(columns.snapshot(), loaded.snapshot());
    for (0..page.chunks) |i| try std.testing.expectEqualDeep(try columns.witness(@intCast(i)), try loaded.witness(@intCast(i)));
}
test "source packed page compact buffers: multiple IO buffers split operands exactly and preserve all original private cells" {
    try compactBufferedContract(std.testing.allocator);
}
test "source packed page compact buffer faults: every multi-buffer source and replay owner allocation unwinds" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, compactBufferedContract, .{});
}

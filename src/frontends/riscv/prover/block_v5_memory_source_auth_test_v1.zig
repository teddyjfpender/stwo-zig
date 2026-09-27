//! Nonproving fixtures. No guest, PCS, STARK, FRI or device work occurs here.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const crypto = @import("../recursion/air/block_v5_memory_source_crypto_v1.zig");
const eq = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
const protocol = @import("block_v5_memory_source_auth_protocol_v1.zig");
const circuit = @import("block_v5_memory_source_circuit_v1.zig");
const stream = @import("block_v5_memory_source_stream_v1.zig");
const initial = @import("block_v5_initial_sources_v1.zig");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const sha = @import("../air/guest_precompile/sha256_compression.zig");
const A = crypto.Algebra(Q);
fn bytes(d: A.Digest) ![32]u8 {
    var out: [32]u8 = @splat(0);
    for (d, 0..) |b, j| for (b, 0..) |v, i| {
        const bit = (try v.tryIntoM31()).toU32();
        if (bit > 1) return error.NonBooleanHashBit;
        out[j] |= @as(u8, @intCast(bit)) << @intCast(i);
    };
    return out;
}
fn challenges() protocol.Challenges {
    return .{ .word = .{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() }, .bytes = .dummy(), .input = .dummy(), .insertion = .dummy(), .before = .dummy(), .after = .dummy(), .route = .dummy(), .roots = .dummy(), .ordering = .dummy(), .sha_chain = .dummy() };
}
fn pair(value: anytype) eq.Algebra(Q).Pair {
    return .{ .z = value.z, .alpha = value.alpha };
}
fn pairs(c: protocol.Challenges) [eq.PAIR_COUNT]eq.Algebra(Q).Pair {
    return .{ pair(c.bytes), pair(c.input), pair(c.insertion), pair(c.before), pair(c.after), pair(c.route), pair(c.roots), pair(c.ordering), pair(c.sha_chain), pair(c.word.initial), pair(c.word.endpoint) };
}
fn algebraSums(s: protocol.Sums) eq.Algebra(Q).Sums {
    var out: eq.Algebra(Q).Sums = undefined;
    inline for (std.meta.fields(protocol.Sums)) |f| @field(out, f.name) = @field(s, f.name);
    return out;
}
fn add(sum: *protocol.Sums, contribution: protocol.Sums) void {
    inline for (std.meta.fields(protocol.Sums)) |f| @field(sum.*, f.name) = @field(sum.*, f.name).add(@field(contribution, f.name));
}

const Fixture = struct {
    public_input: [3]u8 = .{ 0x34, 0x12, 0x80 },
    input: [8]u8 = undefined,
    rw: [8]u8 = undefined,
    touches: [9]u8 = undefined,
    endpoints: [16]u8 = undefined,
    leaves: [2]tree.Leaf = .{ .{ .index = 8, .value = 0x801234 }, .{ .index = 20, .value = 0xffffffff } },
    count: usize = 0,
    next_edit: u64 = 0,
    fn init() Fixture {
        var f: Fixture = .{};
        std.mem.writeInt(u32, f.input[0..4], 32, .little);
        std.mem.writeInt(u32, f.input[4..8], 0x801234, .little);
        std.mem.writeInt(u32, f.rw[0..4], 80, .little);
        std.mem.writeInt(u32, f.rw[4..8], 0xffffffff, .little);
        f.touches[0] = 1;
        std.mem.writeInt(u32, f.touches[1..5], 32, .little);
        std.mem.writeInt(u32, f.touches[5..9], 0x801234, .little);
        std.mem.writeInt(u32, f.endpoints[0..4], 32, .little);
        std.mem.writeInt(u64, f.endpoints[4..12], 0xfedcba9876543210, .little);
        std.mem.writeInt(u32, f.endpoints[12..16], 9, .little);
        return f;
    }
    fn admission(self: *Fixture) !protocol.Admitted {
        const hasher = tree.TreeHasher.init(.memory);
        const before = try hasher.root(&self.leaves);
        var final = self.leaves;
        final[0].value = 9;
        const after = try hasher.root(&final);
        return protocol.make(.{ .initial = .{ .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 256, .stack_bottom = 128, .stack_top = 512, .io_base = 256, .io_end = 768, .input_base = 32, .input_end = 64, .output_len_addr = 64, .output_data_addr = 68, .output_base = 64, .output_end = 256 }, .initial_rw_root = before.bytes, .initial_registers = @splat(0), .public_input_sha256 = initial.sha256(&self.public_input), .public_input_len = self.public_input.len, .input_words = .{ .sha256 = initial.sha256(&self.input), .records = 1 }, .rw_words = .{ .sha256 = initial.sha256(&self.rw), .records = 1 }, .first_touches = .{ .sha256 = initial.sha256(&self.touches), .records = 1 } }, .memory_plan_digest = @splat(7), .expected_final_rw_root = after.bytes, .endpoints = .{ .sha256 = initial.sha256(&self.endpoints), .records = 1 } }, @splat(8), .{});
    }
    fn read(context: *anyopaque, s: protocol.Stream, offset: u64, dst: []u8) !void {
        const self: *Fixture = @ptrCast(@alignCast(context));
        const raw: []const u8 = switch (s) {
            .public_input => &self.public_input,
            .input_words => &self.input,
            .rw_words => &self.rw,
            .first_touches => &self.touches,
            .endpoints => &self.endpoints,
        };
        if (offset > raw.len or dst.len > raw.len - offset) return error.InvalidFixtureRead;
        @memcpy(dst, raw[@intCast(offset)..][0..dst.len]);
    }
    fn opening(context: *anyopaque, index: u64, address: u32, before: u32, after: u32) !stream.Opening {
        const self: *Fixture = @ptrCast(@alignCast(context));
        if (index != self.next_edit) return error.InvalidFixtureOpeningOrder;
        const hasher = tree.TreeHasher.init(.memory);
        const old = try hasher.opening(self.leaves[0..self.count], address / 4);
        if (old.value != before) return error.InvalidFixtureBefore;
        if (index < 2) {
            self.leaves[self.count] = .{ .index = address / 4, .value = after };
            self.count += 1;
        } else self.leaves[0].value = after;
        self.next_edit += 1;
        var result: stream.Opening = undefined;
        for (&result.siblings, old.siblings) |*s, v| s.* = v.bytes;
        return result;
    }
    fn source(self: *Fixture) stream.Source {
        return .{ .context = self, .read = read, .opening = opening };
    }
};

test "source auth crypto: full SHA padding and BLAKE3 tree frames match independent kernels" {
    var raw: [129]u8 = undefined;
    for (&raw, 0..) |*b, i| b.* = @truncate(i * 19 + 7);
    for ([_]usize{ 0, 3, 55, 56, 63, 64, 65, 119, 120, 128, 129 }) |length| {
        var state = A.shaInitial();
        var offset: usize = 0;
        while (offset + 64 <= length) : (offset += 64) {
            var block: [64]A.Byte = undefined;
            for (&block, raw[offset..][0..64]) |*b, x| b.* = A.byte(x);
            state = try A.shaChunk(state, block, 64, length, false);
        }
        var tail: [64]A.Byte = @splat(A.byte(0));
        for (raw[offset..length], 0..) |x, i| tail[i] = A.byte(x);
        state = try A.shaChunk(state, tail, length - offset, length, true);
        try std.testing.expectEqualDeep(initial.sha256(raw[0..length]), try bytes(A.shaDigest(state)));
    }
    for ([_]u32{ 0, 1, 0x7fffffff, 0x80000000, 0xffffffff }) |value| try std.testing.expectEqualDeep((tree.Frame{ .leaf = .{ .kind = .memory, .value = value } }).hash().bytes, try bytes(A.leaf(A.word(value))));
    const left = initial.sha256("left");
    const right = initial.sha256("right");
    try std.testing.expectEqualDeep((tree.Frame{ .node = .{ .kind = .memory, .left = .{ .bytes = left }, .right = .{ .bytes = right } } }).hash().bytes, try bytes(A.node(A.digest(left), A.digest(right))));
    try std.testing.expectError(error.InvalidSourceShaChunk, A.shaChunk(A.shaInitial(), @splat(A.byte(0)), 64, 64, true));
}

test "source auth stream: complete image retains untouched word and authenticates full u64 endpoint" {
    var fixture = Fixture.init();
    const admitted = try fixture.admission();
    var cursor = try stream.Cursor.init(admitted, fixture.source());
    const c = challenges();
    var sum: protocol.Sums = .{};
    var chunks: u64 = 0;
    while (try cursor.next()) |chunk| {
        try std.testing.expectEqualDeep(try stream.kindAt(&admitted, chunks), chunk.kind);
        add(&sum, try circuit.propose(&admitted, chunk.kind, chunk.witness, c));
        chunks += 1;
    }
    try std.testing.expectEqual(@as(u64, 105), chunks); // SHA5 + records4 + 3*(leaf+30nodes+root)
    try std.testing.expectEqual(@as(u64, 3), cursor.expected.edits);
    var sink = circuit.ScalarSink{};
    try eq.Algebra(Q).closure(&admitted, pairs(c), algebraSums(sum), sum.initial, sum.endpoint, &sink);
    const word_protocol = @import("block_v5_word_memory_protocol_v1.zig");
    const transition = @import("../air/block/memory_transition.zig").Transition{ .space = 1, .address = 32, .clock = 0xfedcba9876543210, .before = 0x801234, .after = 9 };
    try std.testing.expect(sum.initial.eql(try c.word.initial.combineBase(word_protocol.initialTuple(transition)).inv()));
    try std.testing.expect(sum.endpoint.eql(try c.word.endpoint.combineBase(word_protocol.endpointTuple(transition)).inv()));
    const closure_owner = try circuit.prepareClosureWithChallenges(std.testing.allocator, &admitted, sum, sum.initial, sum.endpoint, c);
    defer closure_owner.deinit();
    try closure_owner.evaluate();
    closure_owner.inputs.?[2 * eq.PAIR_COUNT] = Q.one();
    try std.testing.expectError(error.UnsatisfiedCircuit, closure_owner.evaluate());
    var missing = sum;
    missing.before = missing.before.add(Q.one());
    try std.testing.expectError(error.UnsatisfiedMemorySourceEquation, eq.Algebra(Q).closure(&admitted, pairs(c), algebraSums(missing), sum.initial, sum.endpoint, &sink));
    var wrong = admitted;
    wrong.pins.expected_final_rw_root[0] ^= 1;
    wrong = try protocol.make(wrong.pins, wrong.sealed_digest, wrong.limits);
    try std.testing.expectError(error.UnsatisfiedMemorySourceEquation, eq.Algebra(Q).closure(&wrong, pairs(c), algebraSums(sum), sum.initial, sum.endpoint, &sink));
}

test "source auth metadata: canonical census identity caps and RAM-only classification fail closed" {
    var f = Fixture.init();
    const admitted = try f.admission();
    const count = try stream.census(&admitted);
    try std.testing.expectEqual(@as(u64, 105), count.total);
    var pins = admitted.pins;
    pins.endpoints.records += 1;
    try std.testing.expectError(error.InvalidMemorySourceAdmission, protocol.make(pins, admitted.sealed_digest, .{}));
    var limits = admitted.limits;
    limits.max_stream_bytes = 2;
    try std.testing.expectError(error.MemorySourceResourceLimit, protocol.make(admitted.pins, admitted.sealed_digest, limits));
    try std.testing.expectError(error.InvalidMemorySourceChunk, eq.validateKind(&admitted, .{ .record = .{ .stream = .endpoints, .ordinal = 1 } }));
    const id = try circuit.chunkIdentity(&admitted, .{ .record = .{ .stream = .first_touches, .ordinal = 0 } });
    try std.testing.expect(!std.mem.eql(u8, &id, &(try circuit.chunkIdentity(&admitted, .{ .record = .{ .stream = .endpoints, .ordinal = 0 } }))));
    var w = eq.Witness{ .address = 16, .after = 1 };
    try std.testing.expectError(error.UnsatisfiedMemorySourceEquation, circuit.propose(&admitted, .{ .record = .{ .stream = .rw_words, .ordinal = 0 } }, w, challenges()));
    w.address = 33;
    try std.testing.expectError(error.UnsatisfiedMemorySourceEquation, circuit.propose(&admitted, .{ .record = .{ .stream = .rw_words, .ordinal = 0 } }, w, challenges()));
    f.touches[0] = 0;
    var cursor = try stream.Cursor.init(admitted, f.source());
    // Source callback cannot turn a register record into an authenticated RAM
    // record. The streaming constructor rejects it before witness publication.
    for (0..7) |_| {
        _ = try cursor.next();
    }
    try std.testing.expectError(error.InvalidMemorySourceRamSpace, cursor.next());
}

test "source auth symbolic: endpoint byte clock bit claims and chunk admission are constrained" {
    var f = Fixture.init();
    const admitted = try f.admission();
    const c = challenges();
    const kind: eq.Kind = .{ .record = .{ .stream = .endpoints, .ordinal = 0 } };
    const w = eq.Witness{ .address = 32, .after = 9, .clock = 0xfedcba9876543210 };
    const claim = try circuit.propose(&admitted, kind, w, c);
    const owner = try circuit.prepareWithChallenges(std.testing.allocator, &admitted, kind, w, claim, c);
    defer owner.deinit();
    try owner.evaluate();
    const clock_start: usize = 64 * 8 + 8 * 32 + 4 * 32;
    const old = owner.inputs.?[clock_start + 57];
    owner.inputs.?[clock_start + 57] = Q.one().sub(old);
    try std.testing.expectError(error.UnsatisfiedCircuit, owner.evaluate());
    owner.inputs.?[clock_start + 57] = old;
    owner.inputs.?[0] = Q.fromBase(M.fromCanonical(2));
    try std.testing.expectError(error.UnsatisfiedCircuit, owner.evaluate());
    owner.inputs.?[0] = Q.zero();
    owner.inputs.?[eq.INPUT_COUNT] = owner.inputs.?[eq.INPUT_COUNT].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, owner.evaluate());
}

test "source auth symbolic SHA: full pinned digest and canonical raw tail use actual compression equations" {
    var f = Fixture.init();
    const admitted = try f.admission();
    const c = challenges();
    var w = eq.Witness{ .state = sha.initial_state };
    @memcpy(w.raw[0..3], &f.public_input);
    const kind: eq.Kind = .{ .sha = .{ .stream = .public_input, .block = 0 } };
    const claim = try circuit.propose(&admitted, kind, w, c);
    const owner = try circuit.prepareWithChallenges(std.testing.allocator, &admitted, kind, w, claim, c);
    defer owner.deinit();
    try owner.evaluate();
    owner.inputs.?[0] = Q.one().sub(owner.inputs.?[0]);
    try std.testing.expectError(error.UnsatisfiedCircuit, owner.evaluate());
}

fn allocationFixture(a: std.mem.Allocator) !void {
    var f = Fixture.init();
    const admitted = try f.admission();
    const c = challenges();
    const kind: eq.Kind = .{ .record = .{ .stream = .endpoints, .ordinal = 0 } };
    const w = eq.Witness{ .address = 32, .after = 9, .clock = 0xfedcba9876543210 };
    const claim = try circuit.propose(&admitted, kind, w, c);
    const owner = try circuit.prepareWithChallenges(a, &admitted, kind, w, claim, c);
    defer owner.deinit();
    try owner.evaluate();
}
test "source auth fault: every record graph allocation failure releases partial owner" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFixture, .{});
    var f = Fixture.init();
    var admitted = try f.admission();
    admitted.limits.max_chunk_heap_bytes = 32;
    try std.testing.expectError(error.OutOfMemory, circuit.prepareWithChallenges(std.testing.allocator, &admitted, .{ .record = .{ .stream = .endpoints, .ordinal = 0 } }, .{ .address = 32, .after = 9 }, .{}, challenges()));
}

test "source auth zero: empty files still hash and both image roots close without fake tree chunks" {
    var f = Fixture.init();
    const original = try f.admission();
    var pins = original.pins;
    const empty = tree.TreeHasher.init(.memory).defaults[0].bytes;
    pins.initial.initial_rw_root = empty;
    pins.expected_final_rw_root = empty;
    pins.initial.public_input_len = 0;
    pins.initial.public_input_sha256 = initial.sha256("");
    pins.initial.input_words = .{ .records = 0, .sha256 = initial.sha256("") };
    pins.initial.rw_words = .{ .records = 0, .sha256 = initial.sha256("") };
    pins.initial.first_touches = .{ .records = 0, .sha256 = initial.sha256("") };
    pins.endpoints = .{ .records = 0, .sha256 = initial.sha256("") };
    const admitted = try protocol.make(pins, original.sealed_digest, original.limits);
    var cursor = try stream.Cursor.init(admitted, f.source());
    var sums: protocol.Sums = .{};
    const c = challenges();
    while (try cursor.next()) |chunk| add(&sums, try circuit.propose(&admitted, chunk.kind, chunk.witness, c));
    try std.testing.expectEqual(@as(u64, 5), cursor.emitted);
    try std.testing.expectEqual(@as(u64, 0), f.next_edit);
    var sink = circuit.ScalarSink{};
    try eq.Algebra(Q).closure(&admitted, pairs(c), algebraSums(sums), Q.zero(), Q.zero(), &sink);
    pins.initial.initial_rw_root[0] ^= 1;
    const changed = try protocol.make(pins, original.sealed_digest, original.limits);
    try std.testing.expectError(error.UnsatisfiedMemorySourceEquation, eq.Algebra(Q).closure(&changed, pairs(c), algebraSums(sums), Q.zero(), Q.zero(), &sink));
}

test "source auth mutations: pinned SHA and strict predecessor are equation authority" {
    var f = Fixture.init();
    const admitted = try f.admission();
    const c = challenges();
    var w = eq.Witness{ .state = sha.initial_state };
    @memcpy(w.raw[0..3], &f.public_input);
    var wrong_pins = admitted.pins;
    wrong_pins.initial.public_input_sha256[0] ^= 1;
    const wrong = try protocol.make(wrong_pins, admitted.sealed_digest, admitted.limits);
    try std.testing.expectError(error.UnsatisfiedMemorySourceEquation, circuit.propose(&wrong, .{ .sha = .{ .stream = .public_input, .block = 0 } }, w, c));
    w.raw[3] = 1;
    try std.testing.expectError(error.UnsatisfiedMemorySourceEquation, circuit.propose(&admitted, .{ .sha = .{ .stream = .public_input, .block = 0 } }, w, c));
    var pins = admitted.pins;
    pins.initial.rw_words.records = 2;
    const two = try protocol.make(pins, admitted.sealed_digest, admitted.limits);
    const repeated = eq.Witness{ .address = 80, .previous_address = 80, .after = 1 };
    try std.testing.expectError(error.UnsatisfiedMemorySourceEquation, circuit.propose(&two, .{ .record = .{ .stream = .rw_words, .ordinal = 1 } }, repeated, c));
    const reversed = eq.Witness{ .address = 80, .previous_address = 84, .after = 1 };
    try std.testing.expectError(error.UnsatisfiedMemorySourceEquation, circuit.propose(&two, .{ .record = .{ .stream = .rw_words, .ordinal = 1 } }, reversed, c));
    // Shared sibling equation consumes one sibling list; a changed list changes
    // both authenticated parent digests/routing claims, and cannot silently
    // replace only the final path while keeping the original public sums.
    const hasher = tree.TreeHasher.init(.memory);
    const path = try hasher.opening(&f.leaves, 8);
    var node = eq.Witness{ .address = 32, .before_hash = hasher.leaf(0x801234).bytes, .after_hash = hasher.leaf(9).bytes, .sibling = path.siblings[0].bytes };
    const kind: eq.Kind = .{ .node = .{ .edit = .update, .ordinal = 0, .height = 0 } };
    const before = try circuit.propose(&admitted, kind, node, c);
    node.sibling[0] ^= 1;
    const after = try circuit.propose(&admitted, kind, node, c);
    try std.testing.expect(!before.route.eql(after.route));
    node.sibling = @splat(0);
    try std.testing.expectError(error.UnsatisfiedMemorySourceEquation, circuit.propose(&admitted, .{ .node = .{ .edit = .update, .ordinal = 0, .height = 29 } }, node, c));
}

fn wordValue(w: A.Word) !u32 {
    var result: u32 = 0;
    for (w, 0..) |v, i| {
        const bit = (try v.tryIntoM31()).toU32();
        if (bit > 1) return error.NonBooleanWordBit;
        result |= @as(u32, @intCast(bit)) << @intCast(i);
    }
    return result;
}
test "source auth crypto operations: carry rotate arbitrary SHA chaining and compression match exact kernel" {
    const values = [_]u32{ 0, 1, 2, 0x7fffffff, 0x80000000, 0xffffffff, 0x12345678 };
    for (values) |a| for (values) |b| {
        try std.testing.expectEqual(a +% b, try wordValue(A.add(A.word(a), A.word(b))));
    };
    for (values) |a| {
        inline for (.{ @as(u5, 2), @as(u5, 6), @as(u5, 7), @as(u5, 13), @as(u5, 18), @as(u5, 25) }) |n| try std.testing.expectEqual(std.math.rotr(u32, a, n), try wordValue(A.rotate(A.word(a), n)));
    }
    var block: [64]u8 = @splat(0);
    block[0] = 0x80;
    var bits: [64]A.Byte = undefined;
    for (&bits, block) |*v, b| v.* = A.byte(b);
    for ([_]sha.State{ sha.initial_state, .{ 0xffffffff, 0, 1, 0x80000000, 3, 5, 7, 0x12345678 } }) |native| {
        var state: A.State = undefined;
        for (&state, native) |*v, n| v.* = A.word(n);
        const computed = A.shaCompress(state, bits);
        const expected = sha.compress(native, block);
        for (computed, expected) |v, n| try std.testing.expectEqual(n, try wordValue(v));
    }
}

test "source auth crypto frames: independent full-width tree leaf and node digests" {
    for ([_]u32{ 0, 1, 0x7fffffff, 0x80000000, 0xffffffff }) |value| try std.testing.expectEqualDeep((tree.Frame{ .leaf = .{ .kind = .memory, .value = value } }).hash().bytes, try bytes(A.leaf(A.word(value))));
    const left = initial.sha256("independent-left");
    const right = initial.sha256("independent-right");
    try std.testing.expectEqualDeep((tree.Frame{ .node = .{ .kind = .memory, .left = .{ .bytes = left }, .right = .{ .bytes = right } } }).hash().bytes, try bytes(A.node(A.digest(left), A.digest(right))));
}

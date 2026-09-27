//! Bounded nonproving source-fold/hash equations. No PCS, STARK, guest,
//! device, recursive proof or source receipt is constructed by these tests.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Protocol = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig");
const Circuit = @import("block_v5_memory_source_batch_circuit_v1.zig");
const Hash = @import("block_v5_memory_source_packed_hash_v1.zig");
const Crypto = @import("../recursion/air/block_v5_memory_source_crypto_v1.zig");
const Records = @import("block_v5_memory_source_batch_records_v1.zig");
const Original = @import("block_v5_memory_source_circuit_v1.zig");
const G = @import("../recursion/air/blake3_g_call.zig");
const Xor = @import("../recursion/air/blake3_xor_call.zig");
const lang = @import("../air/lang/mod.zig");
const Support = @import("../recursion/air/test_support.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
fn challenges() Protocol.Challenges {
    return .{ .source = .{ .word = .{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() }, .bytes = .dummy(), .input = .dummy(), .insertion = .dummy(), .before = .dummy(), .after = .dummy(), .route = .dummy(), .roots = .dummy(), .ordering = .dummy(), .sha_chain = .dummy() }, .route = .dummy(), .hash = .dummy(), .indexed = .dummy() };
}
const Fixture = struct {
    public_input: [12]u8 = .{ 7, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0 },
    input: [16]u8 = undefined,
    rw: [257 * 8]u8 = undefined,
    touch: [4 * 9]u8 = undefined,
    endpoint: [4 * 16]u8 = undefined,
    admitted: Source.Admitted = undefined,
    fn init(self: *Fixture, words: usize) !void {
        if (words < 3 or words > 257) return error.InvalidFixture;
        putWord(self.input[0..8], 32, 7);
        putWord(self.input[8..16], 40, 9);
        var before: [259]Tree.Leaf = undefined;
        var after: [260]Tree.Leaf = undefined;
        before[0] = .{ .index = 8, .value = 7 };
        before[1] = .{ .index = 10, .value = 9 };
        after[0..2].* = before[0..2].*;
        var final_count: usize = 2;
        for (0..words) |i| {
            const address: u32 = 128 + 4 * @as(u32, @intCast(i));
            const value: u32 = 17 + @as(u32, @intCast(i));
            putWord(self.rw[i * 8 ..][0..8], address, value);
            before[2 + i] = .{ .index = address / 4, .value = value };
            if (i != 0) {
                after[final_count] = .{ .index = address / 4, .value = if (i == 2) 0x12345678 else value };
                final_count += 1;
            }
        }
        after[final_count] = .{ .index = 8192 / 4, .value = 0xff00ff00 };
        final_count += 1;
        self.putTouch(0, 36, 0, 0, 0x123456789abcdef0);
        self.putTouch(1, 128, 17, 0, 0xfedcba9876543210);
        self.putTouch(2, 136, 19, 0x12345678, 0x8000000000000000);
        self.putTouch(3, 8192, 0, 0xff00ff00, 123);
        const hasher = Tree.TreeHasher.init(.memory);
        self.admitted = try Source.make(.{ .initial = .{
            .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 16384, .stack_bottom = 8192, .stack_top = 16384, .io_base = 32, .io_end = 64, .input_base = 32, .input_end = 64, .output_len_addr = 64, .output_data_addr = 68, .output_base = 64, .output_end = 128 },
            .initial_rw_root = (try hasher.root(before[0 .. words + 2])).bytes,
            .initial_registers = @splat(0),
            .public_input_len = self.public_input.len,
            .public_input_sha256 = Initial.sha256(&self.public_input),
            .input_words = .{ .records = 2, .sha256 = Initial.sha256(&self.input) },
            .rw_words = .{ .records = words, .sha256 = Initial.sha256(self.rw[0 .. words * 8]) },
            .first_touches = .{ .records = 4, .sha256 = Initial.sha256(&self.touch) },
        }, .memory_plan_digest = @splat(7), .expected_final_rw_root = (try hasher.root(after[0..final_count])).bytes, .endpoints = .{ .records = 4, .sha256 = Initial.sha256(&self.endpoint) } }, @splat(8), .{});
    }
    fn putTouch(self: *Fixture, ordinal: usize, address: u32, before: u32, after: u32, clock: u64) void {
        const first = self.touch[ordinal * 9 ..][0..9];
        first[0] = 1;
        std.mem.writeInt(u32, first[1..5], address, .little);
        std.mem.writeInt(u32, first[5..9], before, .little);
        const last = self.endpoint[ordinal * 16 ..][0..16];
        std.mem.writeInt(u32, last[0..4], address, .little);
        std.mem.writeInt(u64, last[4..12], clock, .little);
        std.mem.writeInt(u32, last[12..16], after, .little);
    }
    fn read(context: *anyopaque, stream: Source.Stream, offset: u64, output: []u8) !void {
        const self: *Fixture = @ptrCast(@alignCast(context));
        const bytes: []const u8 = switch (stream) {
            .public_input => &self.public_input,
            .input_words => &self.input,
            .rw_words => self.rw[0 .. @as(usize, @intCast(self.admitted.records(.rw_words))) * 8],
            .first_touches => &self.touch,
            .endpoints => &self.endpoint,
        };
        if (offset > bytes.len or output.len > bytes.len - @as(usize, @intCast(offset))) return error.InvalidFixtureOffset;
        @memcpy(output, bytes[@intCast(offset)..][0..output.len]);
    }
    fn opening(_: *anyopaque, _: u64, _: u32, _: u32, _: u32) !@import("block_v5_memory_source_stream_v1.zig").Opening {
        return error.UnexpectedPerEditOpening;
    }
    fn reader(self: *Fixture) Fold.Reader {
        return .{ .context = self, .read = read };
    }
};
fn putWord(bytes: *[8]u8, address: u32, value: u32) void {
    std.mem.writeInt(u32, bytes[0..4], address, .little);
    std.mem.writeInt(u32, bytes[4..8], value, .little);
}

test "source batch fold: streaming dense union retains untouched leaves and exact original roots with linear unique work" {
    var fixture = Fixture{};
    try fixture.init(257);
    var cursor = try Fold.Cursor.init(fixture.admitted, fixture.reader(), .{});
    var seen: [3000]Fold.Coordinate = undefined;
    var count: usize = 0;
    var full_clock = false;
    var compression_count: u64 = 0;
    while (try cursor.next()) |operation| {
        if (operation.kind != .root) {
            for (seen[0..count]) |coordinate| try std.testing.expect(!std.meta.eql(coordinate, operation.coordinate));
            seen[count] = operation.coordinate;
            count += 1;
        }
        const recipes = try Hash.recipes(operation);
        compression_count += recipes.compressionCount();
        if (operation.kind == .leaf and operation.leaf.address == 128) full_clock = operation.leaf.clock == 0xfedcba9876543210;
    }
    try std.testing.expect(full_clock);
    try std.testing.expectEqual(@as(u64, 261), cursor.census.leaves);
    try std.testing.expectEqual(cursor.census.compressions, compression_count);
    try std.testing.expect(cursor.census.compressions < 4 * @as(u64, 259) + 300);
    // Work counts only, no benchmark/speedup claim. Old oracle=122E.
    try std.testing.expect(cursor.census.compressions * 16 < 122 * @as(u64, 263));
    try std.testing.expectEqualSlices(u8, &fixture.admitted.pins.initial.initial_rw_root, &cursor.result.?.before);
    try std.testing.expectEqualSlices(u8, &fixture.admitted.pins.expected_final_rw_root, &cursor.result.?.after);
}
test "source batch merge: before image input mutation clocks order missing duplicate space and resource mutations fail closed" {
    var fixture = Fixture{};
    try fixture.init(3);
    std.mem.writeInt(u32, fixture.touch[14..18], 18, .little); // wrong before for address128
    var merge = try Fold.Merge.init(fixture.admitted, fixture.reader());
    _ = try merge.next();
    _ = try merge.next();
    _ = try merge.next();
    try std.testing.expectError(error.InvalidSourceFoldBeforeValue, merge.next());
    try fixture.init(3);
    fixture.endpoint[12] = 1;
    var writable_input = try Fold.Merge.init(fixture.admitted, fixture.reader());
    _ = try writable_input.next();
    const modified_input = (try writable_input.next()).?;
    try std.testing.expectEqual(@as(u32, 1), modified_input.after);
    try fixture.init(3);
    fixture.touch[0] = 0;
    try std.testing.expectError(error.InvalidSourceFoldTouch, Fold.Cursor.init(fixture.admitted, fixture.reader(), .{}));
    try fixture.init(3);
    putWord(fixture.rw[8..16], 128, 18);
    var duplicate = try Fold.Merge.init(fixture.admitted, fixture.reader());
    _ = try duplicate.next();
    _ = try duplicate.next();
    _ = try duplicate.next();
    try std.testing.expectError(error.InvalidSourceFoldImage, duplicate.next());
    try fixture.init(3);
    fixture.admitted.pins.expected_final_rw_root[0] ^= 1;
    fixture.admitted = try Source.make(fixture.admitted.pins, fixture.admitted.sealed_digest, fixture.admitted.limits);
    var wrong_root = try Fold.Cursor.init(fixture.admitted, fixture.reader(), .{});
    var root_error = false;
    while (true) {
        const next = wrong_root.next() catch |err| {
            try std.testing.expectEqual(error.InvalidSourceFoldRoot, err);
            root_error = true;
            break;
        };
        if (next == null) break;
    }
    try std.testing.expect(root_error);
    try fixture.init(3);
    var bounded = try Fold.Cursor.init(fixture.admitted, fixture.reader(), .{ .max_operations = 1 });
    _ = try bounded.next();
    try std.testing.expectError(error.SourceFoldResourceLimit, bounded.next());
}
fn add(a: *Eq.Algebra(Q).Sums, b: Eq.Algebra(Q).Sums) void {
    inline for (std.meta.fields(Eq.Algebra(Q).Sums)) |field| @field(a, field.name) = @field(a, field.name).add(@field(b, field.name));
}
fn provider(operation: Fold.Operation, c: Protocol.Challenges) !Q {
    const C = Crypto.Algebra(Q);
    const recipes = try Hash.recipes(operation);
    var sum = Q.zero();
    for (recipes.values[0..recipes.count]) |recipe| {
        if (recipe.default_height) |height| {
            sum = sum.add(try Hash.defaultSupply(Q, height, recipe.multiplicity, Eq.Algebra(Q).challenges(c).hash));
        } else {
            const frame: Hash.Algebra(Q).FrameBits = switch (recipe.frame) {
                .leaf => |word| .{ .leaf = C.word(word) },
                .node => |node| .{ .node = .{ .left = C.digest(node.left), .right = C.digest(node.right) } },
            };
            sum = sum.add(try Hash.hashSupply(Q, frame, C.digest(recipe.frame.nativeDigest()), recipe.multiplicity, Eq.Algebra(Q).challenges(c).hash));
        }
    }
    return sum;
}
fn sourceRecords(fixture: *Fixture, c: Protocol.Challenges) !Eq.Algebra(Q).Sums {
    var sum = Eq.Algebra(Q).Sums{};
    inline for (.{ Source.Stream.input_words, .rw_words, .first_touches, .endpoints }) |stream| {
        var previous: u32 = 0;
        for (0..@intCast(fixture.admitted.records(stream))) |ordinal| {
            var raw: [16]u8 = @splat(0);
            const size: usize = switch (stream) {
                .input_words, .rw_words => 8,
                .first_touches => 9,
                .endpoints => 16,
                else => unreachable,
            };
            try Fixture.read(fixture, stream, ordinal * size, raw[0..size]);
            var witness = @import("../recursion/air/block_v5_memory_source_equations_v1.zig").Witness{ .previous_address = previous };
            witness.address = std.mem.readInt(u32, raw[if (stream == .first_touches) 1 else 0..][0..4], .little);
            switch (stream) {
                .input_words, .rw_words => witness.after = std.mem.readInt(u32, raw[4..8], .little),
                .first_touches => witness.before = std.mem.readInt(u32, raw[5..9], .little),
                .endpoints => {
                    witness.clock = std.mem.readInt(u64, raw[4..12], .little);
                    witness.after = std.mem.readInt(u32, raw[12..16], .little);
                },
                else => unreachable,
            }
            const original = try Original.propose(&fixture.admitted, .{ .record = .{ .stream = stream, .ordinal = ordinal } }, witness, c.source);
            const OldEq = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
            var original_inputs: [OldEq.INPUT_COUNT]Q = undefined;
            try OldEq.writeInputs(witness, c.source, .{}, &original_inputs);
            sum.indexed = sum.indexed.add(try Eq.Algebra(Q).indexedRecord(stream, ordinal, &original_inputs, Eq.Algebra(Q).challenges(c).indexed));
            sum.insertion = sum.insertion.add(original.insertion);
            sum.before = sum.before.add(original.before);
            sum.after = sum.after.add(original.after);
            previous = witness.address;
        }
    }
    return sum;
}
test "source batch equations: exact old source record joins default/shared hash supplies and unique tree closure detect omissions" {
    var fixture = Fixture{};
    try fixture.init(3);
    const admitted = try Protocol.Admission.init(fixture.admitted, .{});
    const c = challenges();
    var cursor = try Fold.Cursor.init(fixture.admitted, fixture.reader(), .{});
    var totals = Eq.Algebra(Q).Sums{};
    var hashes = Q.zero();
    var omitted: ?Eq.Algebra(Q).Sums = null;
    while (try cursor.next()) |operation| {
        const claims = try Circuit.propose(false, &admitted, operation, c);
        add(&totals, claims);
        hashes = hashes.add(try provider(operation, c));
        if (operation.kind == .leaf and operation.leaf.image == .rw) omitted = claims;
    }
    var sink = Circuit.ScalarSink{};
    const records = try sourceRecords(&fixture, c);
    try Eq.Algebra(Q).closure(&admitted, totals, hashes, records, &sink);
    try std.testing.expect(omitted != null);
    var bad = totals;
    inline for (std.meta.fields(Eq.Algebra(Q).Sums)) |field| @field(bad, field.name) = @field(bad, field.name).sub(@field(omitted.?, field.name));
    try std.testing.expectError(error.UnsatisfiedSourceFoldEquation, Eq.Algebra(Q).closure(&admitted, bad, hashes, records, &sink));
    bad = totals;
    bad.touches = bad.touches.add(Q.one());
    try std.testing.expectError(error.UnsatisfiedSourceFoldEquation, Eq.Algebra(Q).closure(&admitted, bad, hashes, records, &sink));
    try std.testing.expectError(error.UnsatisfiedSourceFoldEquation, Eq.Algebra(Q).closure(&admitted, totals, hashes.add(Q.one()), records, &sink));
}
fn firstLeaf(fixture: *Fixture) !Fold.Operation {
    var cursor = try Fold.Cursor.init(fixture.admitted, fixture.reader(), .{});
    while (try cursor.next()) |operation| if (operation.kind == .leaf) return operation;
    return error.InvalidFixture;
}
fn expectMutatedGraphRejection(prepared: anytype) !void {
    // Evaluation owns scratch too: let allocation fault injection observe OOM.
    prepared.evaluate() catch |err| switch (err) {
        error.UnsatisfiedCircuit => return,
        else => return err,
    };
    return error.TestExpectedError;
}
fn circuitContract(a: std.mem.Allocator) !void {
    var fixture = Fixture{};
    try fixture.init(3);
    const admitted = try Protocol.Admission.init(fixture.admitted, .{});
    const operation = try firstLeaf(&fixture);
    const c = challenges();
    const claims = try Circuit.propose(false, &admitted, operation, c);
    const prepared = try Circuit.prepare(false, a, &admitted, operation, claims, c, .{});
    defer prepared.deinit();
    try prepared.circuit.?.validate();
    try prepared.evaluate();
    prepared.inputs.?[0] = prepared.inputs.?[0].add(Q.one());
    try expectMutatedGraphRejection(prepared);
}
test "source batch symbolic: actual packed-mode source graph independent construction and private coordinate mutation" {
    try circuitContract(std.testing.allocator);
}
test "source batch faults: every operation graph owner allocation unwinds" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, circuitContract, .{});
}

test "source batch oracle: original BLAKE3 leaf and node equations constrain private digests and level coordinates" {
    var fixture = Fixture{};
    try fixture.init(3);
    const admitted = try Protocol.Admission.init(fixture.admitted, .{});
    const c = challenges();
    var leaf = try firstLeaf(&fixture);
    _ = try Circuit.propose(true, &admitted, leaf, c);
    leaf.value.before[0] ^= 1;
    try std.testing.expectError(error.UnsatisfiedSourceFoldEquation, Circuit.propose(true, &admitted, leaf, c));
    var cursor = try Fold.Cursor.init(fixture.admitted, fixture.reader(), .{});
    var found = false;
    while (try cursor.next()) |operation| if (operation.kind == .branch) {
        _ = try Circuit.propose(true, &admitted, operation, c);
        var bad = operation;
        bad.right.before[0] ^= 1;
        try std.testing.expectError(error.UnsatisfiedSourceFoldEquation, Circuit.propose(true, &admitted, bad, c));
        found = true;
        break;
    };
    try std.testing.expect(found);
}
const Capture = struct {
    blocks: [2]Hash.Boundary = undefined,
    count: usize = 0,
    g_count: usize = 0,
    xor_count: usize = 0,
    pub fn g(self: *@This(), _: *const G.Row) !void {
        self.g_count += 1;
    }
    pub fn xor(self: *@This(), _: *const Xor.Row) !void {
        self.xor_count += 1;
    }
    pub fn boundary(self: *@This(), value: Hash.Boundary) !void {
        if (self.count == self.blocks.len) return error.InvalidFixture;
        self.blocks[self.count] = value;
        self.count += 1;
    }
};
const ConnectorSink = struct {
    total: Q = Q.zero(),
    pub fn zero(_: *@This(), value: Q) !void {
        if (!value.isZero()) return error.UnsatisfiedSourceHashConnector;
    }
    pub fn wire(self: *@This(), circuit: u32, id: u32, weight: u32, bytes: [4]Crypto.Algebra(Q).Byte, positive: bool) !void {
        const C = Crypto.Algebra(Q);
        var tuple: [6]Q = .{ C.scalar(circuit), C.scalar(id), Q.zero(), Q.zero(), Q.zero(), Q.zero() };
        for (bytes, 0..) |byte, i| {
            var factor = Q.one();
            for (byte) |bit| {
                tuple[i + 2] = tuple[i + 2].add(factor.mul(bit));
                factor = factor.add(factor);
            }
        }
        const elements = Universal.Elements.init(6, Q.fromU32Unchecked(17, 19, 23, 29), Q.fromU32Unchecked(31, 37, 41, 43));
        const term = (try (try elements.combineSecure(&tuple)).inv()).mulM31(M.fromCanonical(weight));
        self.total = if (positive) self.total.add(term) else self.total.sub(term);
    }
};
fn bits(boundary: Hash.Boundary) Hash.Algebra(Q).BoundaryBits {
    const C = Crypto.Algebra(Q);
    var out: Hash.Algebra(Q).BoundaryBits = undefined;
    for (&out.initial, boundary.initial) |*word, value| word.* = C.word(value);
    for (&out.output, boundary.output) |*word, value| word.* = C.word(value);
    return out;
}
test "source batch hash connector: actual packed frame cores match independent BLAKE3 and reject header chain digest and nonboolean mutations" {
    const C = Crypto.Algebra(Q);
    const frames = [_]Hash.Frame{ .{ .leaf = 0xdeadbeef }, .{ .node = .{ .left = @splat(0x91), .right = @splat(0x62) } } };
    for (frames) |frame| {
        var capture = Capture{};
        const digest = try Hash.emit(frame, 100, &capture);
        try std.testing.expectEqualSlices(u8, &frame.nativeDigest(), &digest);
        try std.testing.expectEqual(capture.count * 56, capture.g_count);
        try std.testing.expectEqual(capture.count * 16, capture.xor_count);
        var blocks: [2]Hash.Algebra(Q).BoundaryBits = undefined;
        for (capture.blocks[0..capture.count], blocks[0..capture.count]) |boundary, *block| block.* = bits(boundary);
        const frame_bits: Hash.Algebra(Q).FrameBits = switch (frame) {
            .leaf => |value| .{ .leaf = C.word(value) },
            .node => |value| .{ .node = .{ .left = C.digest(value.left), .right = C.digest(value.right) } },
        };
        var sink = ConnectorSink{};
        try Hash.Algebra(Q).evaluate(frame_bits, C.digest(digest), 100, blocks[0..capture.count], &sink);
        const original = blocks[0].initial[15][0];
        blocks[0].initial[15][0] = original.add(Q.one());
        try std.testing.expectError(error.UnsatisfiedSourceHashConnector, Hash.Algebra(Q).evaluate(frame_bits, C.digest(digest), 100, blocks[0..capture.count], &sink));
        blocks[0].initial[15][0] = original;
        var changed_digest = C.digest(digest);
        changed_digest[0][0] = changed_digest[0][0].add(Q.one());
        try std.testing.expectError(error.UnsatisfiedSourceHashConnector, Hash.Algebra(Q).evaluate(frame_bits, changed_digest, 100, blocks[0..capture.count], &sink));
        if (capture.count == 2) {
            blocks[1].initial[0][0] = Q.fromBase(M.fromCanonical(2));
            try std.testing.expectError(error.UnsatisfiedSourceHashConnector, Hash.Algebra(Q).evaluate(frame_bits, C.digest(digest), 100, blocks[0..capture.count], &sink));
        }
    }
}

const CoreLedger = struct {
    g_definition: *const G.Definition,
    xor_definition: *const Xor.Definition,
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
                const elements = Universal.Elements.init(6, Q.fromU32Unchecked(17, 19, 23, 29), Q.fromU32Unchecked(31, 37, 41, 43));
                const term = (try (try elements.combineBase(tuple[0..ids.len])).inv()).mulM31(evaluated[lang.types.idIndex(effect.liveness.?)]);
                self.total = if (binding.role == .consume) self.total.sub(term) else self.total.add(term);
            } else if (binding.schema == lang.relation.id(.range_check_8_8)) {
                try std.testing.expect(tuple[0].toU32() < 256 and tuple[1].toU32() < 256);
            } else if (binding.schema == lang.relation.id(.bitwise)) {
                const a = tuple[0].toU32();
                const b = tuple[1].toU32();
                const c = tuple[2].toU32();
                try std.testing.expect(a < 256 and b < 256 and c < 256 and tuple[3].toU32() == 2 and (a ^ b) == c);
            } else return error.UnexpectedSourceHashSchema;
        }
    }
    pub fn g(self: *@This(), value: *const G.Row) !void {
        try self.row(&self.g_definition.arena, value);
    }
    pub fn xor(self: *@This(), value: *const Xor.Row) !void {
        try self.row(&self.xor_definition.arena, value);
    }
    pub fn boundary(_: *@This(), _: Hash.Boundary) !void {}
};
test "source batch hash wire closure: every original G XOR constraint table request and connector schedule cancel exactly" {
    var g_definition = try G.build(std.testing.allocator);
    defer g_definition.deinit();
    var xor_definition = try Xor.build(std.testing.allocator);
    defer xor_definition.deinit();
    const frame = Hash.Frame{ .node = .{ .left = @splat(0x9a), .right = @splat(0x75) } };
    var ledger = CoreLedger{ .g_definition = &g_definition, .xor_definition = &xor_definition };
    _ = try Hash.emit(frame, 500, &ledger);
    var capture = Capture{};
    const digest = try Hash.emit(frame, 500, &capture);
    var blocks: [2]Hash.Algebra(Q).BoundaryBits = undefined;
    for (capture.blocks[0..capture.count], blocks[0..capture.count]) |boundary, *block| block.* = bits(boundary);
    const C = Crypto.Algebra(Q);
    var connector = ConnectorSink{};
    try Hash.Algebra(Q).evaluate(.{ .node = .{ .left = C.digest(@splat(0x9a)), .right = C.digest(@splat(0x75)) } }, C.digest(digest), 500, blocks[0..capture.count], &connector);
    try std.testing.expect(ledger.total.add(connector.total).isZero());
    var wrong = ConnectorSink{};
    try Hash.Algebra(Q).evaluate(.{ .node = .{ .left = C.digest(@splat(0x9a)), .right = C.digest(@splat(0x75)) } }, C.digest(digest), 501, blocks[0..capture.count], &wrong);
    try std.testing.expect(!ledger.total.add(wrong.total).isZero());
}
test "source batch records: exact SHA canonical records count excludes every old per-edit path and never reads an opening" {
    var fixture = Fixture{};
    try fixture.init(3);
    var cursor = try Records.Cursor.init(fixture.admitted, .{ .context = &fixture, .read = Fixture.read, .opening = Fixture.opening });
    var count: u64 = 0;
    while (try cursor.next()) |chunk| {
        switch (chunk.kind) {
            .sha, .record => {},
            else => return error.UnexpectedPerEditChunk,
        }
        count += 1;
    }
    try std.testing.expectEqual(try Records.count(&fixture.admitted), count);
    const old = try @import("block_v5_memory_source_stream_v1.zig").census(&fixture.admitted);
    try std.testing.expectEqual(@as(u64, 9 * (Tree.DEPTH + 2)), old.total - count);
    try std.testing.expectError(error.InvalidSourceBatchRecordOrdinal, Records.kindAt(&fixture.admitted, count));
}
test "source batch defaults and shared requests: all canonical default heights exact supply and duplicate multiplicity require real joins" {
    var fixture = Fixture{};
    try fixture.init(3);
    const admitted = try Protocol.Admission.init(fixture.admitted, .{});
    const c = challenges();
    const hasher = Tree.TreeHasher.init(.memory);
    for (0..Tree.DEPTH + 1) |height| {
        const operation = Fold.Operation{ .ordinal = 0, .kind = .empty, .coordinate = .{ .height = @intCast(height), .index = 0 }, .value = .{ .before = hasher.defaults[Tree.DEPTH - height].bytes, .after = hasher.defaults[Tree.DEPTH - height].bytes } };
        _ = try Circuit.propose(false, &admitted, operation, c);
        var mutated = operation;
        mutated.value.after[0] ^= 1;
        try std.testing.expectError(error.UnsatisfiedSourceFoldEquation, Circuit.propose(false, &admitted, mutated, c));
    }
    var leaf = try firstLeaf(&fixture);
    const recipes = try Hash.recipes(leaf);
    try std.testing.expectEqual(@as(usize, 1), recipes.count);
    try std.testing.expectEqual(@as(u32, 2), recipes.values[0].multiplicity);
    const request = try Circuit.propose(false, &admitted, leaf, c);
    const supply = try provider(leaf, c);
    try std.testing.expect(request.hash.add(supply).isZero());
    const C = Crypto.Algebra(Q);
    const once = try Hash.hashSupply(Q, .{ .leaf = C.word(leaf.leaf.before) }, C.digest(leaf.value.before), 1, Eq.Algebra(Q).challenges(c).hash);
    try std.testing.expect(!request.hash.add(once).isZero());
    try std.testing.expectError(error.InvalidSourceHashMultiplicity, Hash.hashSupply(Q, .{ .leaf = C.word(leaf.leaf.before) }, C.digest(leaf.value.before), 3, Eq.Algebra(Q).challenges(c).hash));
    leaf.coordinate.index = 1 << 30;
    try std.testing.expectError(error.UnsatisfiedSourceFoldEquation, Circuit.propose(false, &admitted, leaf, c));
}

test "source batch touched input: original initial public input authentication permits a different final RAM word" {
    var fixture = Fixture{};
    try fixture.init(3);
    fixture.putTouch(0, 36, 0, 0x87654321, 0xfedcba9876543210);
    const after = [_]Tree.Leaf{ .{ .index = 8, .value = 7 }, .{ .index = 9, .value = 0x87654321 }, .{ .index = 10, .value = 9 }, .{ .index = 33, .value = 18 }, .{ .index = 34, .value = 0x12345678 }, .{ .index = 2048, .value = 0xff00ff00 } };
    const hasher = Tree.TreeHasher.init(.memory);
    fixture.admitted.pins.expected_final_rw_root = (try hasher.root(&after)).bytes;
    fixture.admitted.pins.initial.first_touches.sha256 = Initial.sha256(&fixture.touch);
    fixture.admitted.pins.endpoints.sha256 = Initial.sha256(&fixture.endpoint);
    fixture.admitted = try Source.make(fixture.admitted.pins, fixture.admitted.sealed_digest, fixture.admitted.limits);
    const admitted = try Protocol.Admission.init(fixture.admitted, .{});
    const c = challenges();
    var cursor = try Fold.Cursor.init(fixture.admitted, fixture.reader(), .{});
    var totals = Eq.Algebra(Q).Sums{};
    var hashes = Q.zero();
    var changed = false;
    while (try cursor.next()) |operation| {
        add(&totals, try Circuit.propose(false, &admitted, operation, c));
        hashes = hashes.add(try provider(operation, c));
        if (operation.kind == .leaf and operation.leaf.address == 36) changed = operation.leaf.before == 0 and operation.leaf.after == 0x87654321;
    }
    try std.testing.expect(changed);
    var sink = Circuit.ScalarSink{};
    try Eq.Algebra(Q).closure(&admitted, totals, hashes, try sourceRecords(&fixture, c), &sink);
}
test "source batch indexed record joins: exact image and touch ordinal swaps fail despite unchanged counts and values" {
    var fixture = Fixture{};
    try fixture.init(3);
    const admitted = try Protocol.Admission.init(fixture.admitted, .{});
    const c = challenges();
    const leaf = try firstLeaf(&fixture);
    const good = try Circuit.propose(false, &admitted, leaf, c);
    var changed = leaf;
    changed.leaf.image_ordinal = 1;
    const bad = try Circuit.propose(false, &admitted, changed, c);
    try std.testing.expect(good.insertion.eql(bad.insertion));
    try std.testing.expect(!good.indexed.eql(bad.indexed));
    changed.leaf.image_ordinal = fixture.admitted.records(.input_words);
    try std.testing.expectError(error.UnsatisfiedSourceFoldEquation, Circuit.propose(false, &admitted, changed, c));
    var cursor = try Fold.Cursor.init(fixture.admitted, fixture.reader(), .{});
    var found = false;
    while (try cursor.next()) |operation| if (operation.kind == .leaf and operation.leaf.touched) {
        const before = try Circuit.propose(false, &admitted, operation, c);
        changed = operation;
        changed.leaf.touch_ordinal = (operation.leaf.touch_ordinal + 1) % fixture.admitted.records(.endpoints);
        const after_claim = try Circuit.propose(false, &admitted, changed, c);
        try std.testing.expect(before.before.eql(after_claim.before) and before.after.eql(after_claim.after));
        try std.testing.expect(!before.indexed.eql(after_claim.indexed));
        found = true;
        break;
    };
    try std.testing.expect(found);
}

fn hashGraphContract(a: std.mem.Allocator) !void {
    const HashCircuit = @import("block_v5_memory_source_batch_hash_circuit_v1.zig");
    const frame = Hash.Frame{ .leaf = 0xfedcba98 };
    var captured = HashCircuit.Capture{};
    _ = try Hash.emit(frame, 800, &captured);
    const wire = Universal.Elements.init(6, Q.fromU32Unchecked(17, 19, 23, 29), Q.fromU32Unchecked(31, 37, 41, 43));
    const hash = Eq.Algebra(Q).challenges(challenges()).hash;
    const claims = try HashCircuit.propose(frame, 1, 800, &captured, wire, hash);
    const prepared = try HashCircuit.prepare(a, frame, 1, 800, &captured, wire, hash, claims, .{});
    defer prepared.deinit();
    try prepared.circuit.?.validate();
    try prepared.evaluate();
    prepared.inputs.?[32] = prepared.inputs.?[32].add(Q.one());
    try expectMutatedGraphRejection(prepared);
}
test "source batch hash symbolic: actual packed frame request graph pins framing public sums and private core output cells" {
    try hashGraphContract(std.testing.allocator);
}
test "source batch hash faults: every packed connector graph allocation unwinds" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, hashGraphContract, .{});
}
test "source batch zero image: canonical root default closes two operations and no hash or fake edit witness" {
    var fixture = Fixture{};
    try fixture.init(3);
    const hasher = Tree.TreeHasher.init(.memory);
    const empty_sha = Initial.sha256("");
    var pins = fixture.admitted.pins;
    pins.initial.public_input_len = 0;
    pins.initial.public_input_sha256 = empty_sha;
    pins.initial.input_words = .{ .records = 0, .sha256 = empty_sha };
    pins.initial.rw_words = .{ .records = 0, .sha256 = empty_sha };
    pins.initial.first_touches = .{ .records = 0, .sha256 = empty_sha };
    pins.endpoints = .{ .records = 0, .sha256 = empty_sha };
    pins.initial.initial_rw_root = hasher.defaults[0].bytes;
    pins.expected_final_rw_root = hasher.defaults[0].bytes;
    fixture.admitted = try Source.make(pins, fixture.admitted.sealed_digest, fixture.admitted.limits);
    const admitted = try Protocol.Admission.init(fixture.admitted, .{});
    const c = challenges();
    var cursor = try Fold.Cursor.init(fixture.admitted, fixture.reader(), .{});
    var sums = Eq.Algebra(Q).Sums{};
    var count: usize = 0;
    while (try cursor.next()) |operation| {
        add(&sums, try Circuit.propose(false, &admitted, operation, c));
        const recipe = try Hash.recipes(operation);
        try std.testing.expectEqual(@as(usize, 0), recipe.count);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqual(@as(u64, 0), cursor.census.compressions);
    var sink = Circuit.ScalarSink{};
    try Eq.Algebra(Q).closure(&admitted, sums, Q.zero(), .{}, &sink);
}

//! Fixed three-call boundary for an 80-byte Bitcoin header SHA256d chip.
//!
//! This prepares the witness and checks the public/circuit-to-chip boundary.
//! It does not verify compression: the SHA AIR must prove each Call's
//! (state, block) -> output relation in the same bound proof.
const std = @import("std");
const provider = @import("s31_sha_provider");
const sha = provider.compression;
const modulus = @import("stwo_core").fields.m31.Modulus;

pub const Call = struct {
    state: sha.State,
    block: [64]u8,
    output: sha.State,
};

pub const Plan = struct {
    calls: [3]Call,
    digest: [32]u8,
};

/// One signed SHA graph boundary word. The byte coordinates are little-endian
/// within the SHA word, as required by the recursion_wire relation. For the
/// first 16 message words this reverses each four-byte span of the serialized
/// header: SHA reads those spans as big-endian u32 words.
pub const BoundaryWord = struct {
    call_id: u32,
    wire_id: u32,
    bytes: [4]u8,
    direction: enum { emit_input, consume_output },
};

pub const boundary_words_per_call: usize = 32;
pub const boundary_words_per_header: usize = 3 * boundary_words_per_call;

fn wordBytes(value: u32) [4]u8 {
    return .{ @truncate(value), @truncate(value >> 8), @truncate(value >> 16), @truncate(value >> 24) };
}

/// Produce exactly the 24 input and eight output recursion_wire tuples per
/// compression call. This is a witness/caller plan, not proof authentication:
/// a joined circuit and SHA proof must constrain these bytes to circuit wires
/// and close the signed lookup multiset before accepting a private header.
pub fn boundaryWords(header: [80]u8, plan: Plan, first_call_id: u32) ![boundary_words_per_header]BoundaryWord {
    const records = try providerCalls(header, plan, first_call_id);
    var words: [boundary_words_per_header]BoundaryWord = undefined;
    for (records, plan.calls, 0..) |record, call, call_index| {
        const source_words = provider.graph.sources(record.state, record.block);
        for (source_words[0..24], 0..) |value, index| {
            words[call_index * boundary_words_per_call + index] = .{
                .call_id = record.execution_clock,
                .wire_id = provider.graph.input_boundary_offset + @as(u32, @intCast(index)),
                .bytes = wordBytes(value),
                .direction = .emit_input,
            };
        }
        for (call.output, 0..) |value, index| {
            words[call_index * boundary_words_per_call + 24 + index] = .{
                .call_id = record.execution_clock,
                .wire_id = provider.topology.output[index],
                .bytes = wordBytes(value),
                .direction = .consume_output,
            };
        }
    }
    return words;
}

/// RISC-V SHA proof roster rows for the private tuple witness. These rows close
/// the SHA graph's boundary lookups but do not connect to an S31 circuit by
/// themselves. The joined profile must add circuit-side events for the same
/// tuples, otherwise the private header/digest could float independently.
pub fn privateBoundaryRows(header: [80]u8, plan: Plan, first_call_id: u32) ![boundary_words_per_header]provider.Boundary.Row {
    const words = try boundaryWords(header, plan, first_call_id);
    const M31 = @import("stwo_core").fields.m31.M31;
    var rows: [boundary_words_per_header]provider.Boundary.Row = undefined;
    for (words, &rows) |word, *row| {
        var coordinates: [4]M31 = undefined;
        for (word.bytes, &coordinates) |byte, *coordinate| coordinate.* = M31.fromCanonical(byte);
        const weight = if (word.direction == .emit_input) M31.one() else M31.one().neg();
        row.* = try provider.Boundary.privateCoordinates(word.call_id, word.wire_id, weight, coordinates);
    }
    return rows;
}

pub fn prepare(header: [80]u8) Plan {
    var first_block: [64]u8 = undefined;
    @memcpy(&first_block, header[0..64]);
    const first_state = sha.compress(sha.initial_state, first_block);

    var second_block: [64]u8 = @splat(0);
    @memcpy(second_block[0..16], header[64..80]);
    second_block[16] = 0x80;
    std.mem.writeInt(u64, second_block[56..64], 640, .big);
    const first_digest_state = sha.compress(first_state, second_block);

    var third_block: [64]u8 = @splat(0);
    @memcpy(third_block[0..32], &sha.stateBytes(first_digest_state));
    third_block[32] = 0x80;
    std.mem.writeInt(u64, third_block[56..64], 256, .big);
    const final_state = sha.compress(sha.initial_state, third_block);
    const plan = Plan{
        .calls = .{
            .{ .state = sha.initial_state, .block = first_block, .output = first_state },
            .{ .state = first_state, .block = second_block, .output = first_digest_state },
            .{ .state = sha.initial_state, .block = third_block, .output = final_state },
        },
        .digest = sha.stateBytes(final_state),
    };
    return plan;
}

/// Checks every byte crossing between the three SHA calls and the enclosing
/// statement. A prover cannot choose padding, block order, chaining states,
/// or a digest independently of the chip outputs. This check is useful for
/// native testing; the eventual verifier must impose equivalent *proof-bound*
/// constraints and also verify each compression call's AIR.
pub fn validateBoundary(header: [80]u8, plan: Plan) !void {
    const calls = plan.calls;
    if (!std.meta.eql(calls[0].state, sha.initial_state) or
        !std.mem.eql(u8, &calls[0].block, header[0..64])) return error.InvalidShaBoundary;
    if (!std.meta.eql(calls[1].state, calls[0].output) or
        !std.mem.eql(u8, calls[1].block[0..16], header[64..80]) or
        calls[1].block[16] != 0x80 or
        !allZero(calls[1].block[17..56]) or
        std.mem.readInt(u64, calls[1].block[56..64], .big) != 640) return error.InvalidShaBoundary;
    const first_digest = sha.stateBytes(calls[1].output);
    if (!std.meta.eql(calls[2].state, sha.initial_state) or
        !std.mem.eql(u8, calls[2].block[0..32], &first_digest) or
        calls[2].block[32] != 0x80 or
        !allZero(calls[2].block[33..56]) or
        std.mem.readInt(u64, calls[2].block[56..64], .big) != 256 or
        !std.mem.eql(u8, &plan.digest, &sha.stateBytes(calls[2].output))) return error.InvalidShaBoundary;
}

/// Adapter to the existing packed SHA AIR row provider. Call IDs are explicit
/// and must be unique across a proof; a two-header batch can use 1..3, 4..6.
/// This prepares rows only. The S31 proof still needs an authenticated lookup
/// bridge and a verifier roster before these rows may replace circuit gates.
pub fn providerCalls(header: [80]u8, plan: Plan, first_call_id: u32) ![3]provider.Call {
    try validateBoundary(header, plan);
    if (first_call_id == 0 or first_call_id > modulus - 3) return error.InvalidShaCallId;
    var records: [3]provider.Call = undefined;
    for (plan.calls, &records, 0..) |call, *record, i| {
        if (!std.meta.eql(call.output, sha.compress(call.state, call.block)))
            return error.InvalidShaCompressionWitness;
        record.* = .{
            .execution_clock = first_call_id + @as(u32, @intCast(i)),
            .state = call.state,
            .block = call.block,
        };
    }
    return records;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

test "three calls match independent SHA256d and reject every bridge substitution" {
    var random = std.Random.DefaultPrng.init(0x5348_4132_3536);
    for (0..16) |_| {
        var header: [80]u8 = undefined;
        random.random().bytes(&header);
        const plan = prepare(header);
        try validateBoundary(header, plan);
        var first_digest: [32]u8 = undefined;
        var expected: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&header, &first_digest, .{});
        std.crypto.hash.sha2.Sha256.hash(&first_digest, &expected, .{});
        try std.testing.expectEqualDeep(expected, plan.digest);

        var changed = plan;
        changed.calls[0].block[0] ^= 1;
        try std.testing.expectError(error.InvalidShaBoundary, validateBoundary(header, changed));
        changed = plan;
        changed.calls[1].state[0] ^= 1;
        try std.testing.expectError(error.InvalidShaBoundary, validateBoundary(header, changed));
        changed = plan;
        changed.calls[1].block[16] = 0;
        try std.testing.expectError(error.InvalidShaBoundary, validateBoundary(header, changed));
        changed = plan;
        changed.calls[2].block[0] ^= 1;
        try std.testing.expectError(error.InvalidShaBoundary, validateBoundary(header, changed));
        changed = plan;
        changed.digest[0] ^= 1;
        try std.testing.expectError(error.InvalidShaBoundary, validateBoundary(header, changed));
    }
}

test "two header plans feed six exact packed SHA provider calls" {
    var parent: [80]u8 = undefined;
    var child: [80]u8 = undefined;
    for (&parent, &child, 0..) |*a, *b, i| {
        a.* = @truncate(i * 37 + 11);
        b.* = @truncate(i * 71 + 9);
    }
    const a = prepare(parent);
    const b = prepare(child);
    const a_records = try providerCalls(parent, a, 1);
    const b_records = try providerCalls(child, b, 4);
    const records = a_records ++ b_records;
    var rows = try provider.prepare(std.testing.allocator, &records);
    defer rows.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 10, 9, 9, 6 }, &rows.geometry.logs);
    try std.testing.expectEqual(@as(u32, 1), rows.sources[0][4].toU32());
    try std.testing.expectEqual(@as(u32, 6), rows.sources[5 * 88][4].toU32());
    try std.testing.expectError(error.InvalidShaCallId, providerCalls(parent, a, 0));
    var corrupt = a;
    corrupt.calls[0].output[0] ^= 1;
    corrupt.calls[1].state = corrupt.calls[0].output;
    try std.testing.expectError(error.InvalidShaCompressionWitness, providerCalls(parent, corrupt, 1));
}

test "SHA private caller tape has exact word IDs, byte order and directions" {
    var header: [80]u8 = undefined;
    for (&header, 0..) |*byte, i| byte.* = @truncate(i * 37 + 11);
    const plan = prepare(header);
    const words = try boundaryWords(header, plan, 7);
    const graph = provider.graph;
    const sources = graph.sources(plan.calls[0].state, plan.calls[0].block);
    for (0..3) |call_index| {
        for (0..boundary_words_per_call) |index| {
            const word = words[call_index * boundary_words_per_call + index];
            try std.testing.expectEqual(@as(u32, @intCast(7 + call_index)), word.call_id);
            if (index < 24) {
                try std.testing.expectEqual(@as(u32, @intCast(graph.input_boundary_offset + index)), word.wire_id);
                try std.testing.expectEqual(.emit_input, word.direction);
            } else {
                try std.testing.expectEqual(provider.topology.output[index - 24], word.wire_id);
                try std.testing.expectEqual(.consume_output, word.direction);
            }
        }
    }
    try std.testing.expectEqualDeep(wordBytes(sources[0]), words[0].bytes);
    try std.testing.expectEqualDeep([4]u8{ header[3], header[2], header[1], header[0] }, words[8].bytes);
    try std.testing.expectEqualDeep([4]u8{ 0, 0, 0, 0x80 }, words[boundary_words_per_call + 12].bytes);
    try std.testing.expectEqualDeep([4]u8{ 0, 0, 0, 0x80 }, words[2 * boundary_words_per_call + 16].bytes);
    for (0..8) |index| {
        const offset = index * 4;
        try std.testing.expectEqualDeep(
            [4]u8{ plan.digest[offset + 3], plan.digest[offset + 2], plan.digest[offset + 1], plan.digest[offset] },
            words[2 * boundary_words_per_call + 24 + index].bytes,
        );
    }
    try std.testing.expectError(error.InvalidShaCallId, boundaryWords(header, plan, 0));
    var corrupted = plan;
    corrupted.calls[1].block[16] ^= 1;
    try std.testing.expectError(error.InvalidShaBoundary, boundaryWords(header, corrupted, 7));
    corrupted = plan;
    corrupted.calls[2].output[0] ^= 1;
    corrupted.digest = sha.stateBytes(corrupted.calls[2].output);
    try std.testing.expectError(error.InvalidShaCompressionWitness, boundaryWords(header, corrupted, 7));
}

/// Audit helper over authenticated SHA AIR definitions. It is not a proof
/// verifier: it checks the current row multiset before a STARK is produced.
pub fn wireImbalanceCount(
    allocator: std.mem.Allocator,
    prepared: *const provider.Rows,
    boundary_rows: []const provider.Boundary.Row,
) !usize {
    const M31 = @import("stwo_core").fields.m31.M31;
    const Sums = std.AutoHashMap([6]u32, M31);
    var sums = Sums.init(allocator);
    defer sums.deinit();
    const Visitor = struct {
        sums: *Sums,
        pub fn accepts(_: *@This(), id: anytype) bool {
            return id == provider.wire_relation_id;
        }
        pub fn visit(self: *@This(), _: anytype, numerator: M31, tuple: []const M31) !void {
            if (tuple.len != 6) return error.InvalidShaWireTuple;
            var key: [6]u32 = undefined;
            for (tuple, &key) |value, *coordinate| coordinate.* = value.toU32();
            const entry = try self.sums.getOrPut(key);
            if (!entry.found_existing) entry.value_ptr.* = M31.zero();
            entry.value_ptr.* = entry.value_ptr.add(numerator);
        }
    };
    var visitor = Visitor{ .sums = &sums };
    const rows = prepared.tuple() ++ .{boundary_rows};
    inline for (.{ provider.Source, provider.Schedule, provider.Round, provider.FeedForward, provider.Boundary }, 0..) |Air, index| {
        var definition = try Air.build(allocator);
        defer definition.deinit();
        const binding = try provider.Binding.Binding(Air).authenticate(&definition);
        for (rows[index]) |row| try binding.visitPreparedBaseEntries(row, &visitor);
    }
    var failures: usize = 0;
    var it = sums.iterator();
    while (it.next()) |entry| if (!entry.value_ptr.isZero()) {
        failures += 1;
    };
    return failures;
}

test "three SHA calls close graph wires only with the exact private caller tape" {
    const allocator = std.testing.allocator;
    var header: [80]u8 = undefined;
    for (&header, 0..) |*byte, i| byte.* = @truncate(i * 13 + 41);
    const plan = prepare(header);
    const records = try providerCalls(header, plan, 1);
    var prepared = try provider.prepare(allocator, &records);
    defer prepared.deinit();
    const rows = try privateBoundaryRows(header, plan, 1);
    try std.testing.expectEqual(@as(usize, 0), try wireImbalanceCount(allocator, &prepared, &rows));

    var changed = rows;
    changed[0][0] = changed[0][0].add(@import("stwo_core").fields.m31.M31.one());
    try std.testing.expect((try wireImbalanceCount(allocator, &prepared, &changed)) != 0);
    changed = rows;
    changed[boundary_words_per_header - 1][3] = changed[boundary_words_per_header - 1][3].add(@import("stwo_core").fields.m31.M31.one());
    try std.testing.expect((try wireImbalanceCount(allocator, &prepared, &changed)) != 0);
    changed = rows;
    changed[1] = changed[0]; // omit one input, duplicate another
    try std.testing.expect((try wireImbalanceCount(allocator, &prepared, &changed)) != 0);
}

test "six SHA calls keep two private headers in distinct call namespaces" {
    const allocator = std.testing.allocator;
    var first: [80]u8 = undefined;
    var second: [80]u8 = undefined;
    for (&first, &second, 0..) |*a, *b, i| {
        a.* = @truncate(i * 17 + 3);
        b.* = @truncate(i * 29 + 7);
    }
    const first_plan = prepare(first);
    const second_plan = prepare(second);
    const records = (try providerCalls(first, first_plan, 1)) ++ (try providerCalls(second, second_plan, 4));
    var prepared = try provider.prepare(allocator, &records);
    defer prepared.deinit();
    const rows = (try privateBoundaryRows(first, first_plan, 1)) ++ (try privateBoundaryRows(second, second_plan, 4));
    try std.testing.expectEqual(@as(usize, 0), try wireImbalanceCount(allocator, &prepared, &rows));
    try std.testing.expectEqualSlices(u32, &.{ 10, 9, 9, 6 }, &prepared.geometry.logs);
    var changed = rows;
    // Copying a second-header call ID into the first header cannot cross-link
    // two otherwise byte-identical words: every tuple includes its namespace.
    changed[boundary_words_per_header][5] = changed[0][5];
    try std.testing.expect((try wireImbalanceCount(allocator, &prepared, &changed)) != 0);
}

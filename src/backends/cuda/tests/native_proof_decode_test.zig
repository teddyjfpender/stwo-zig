const std = @import("std");
const stwo = @import("stwo");
const core = stwo.core;
const core_fri = core.fri;
const core_pcs = core.pcs;
const m31 = core.fields.m31;
const proof_wire = stwo.interop.proof_wire;
const decommit = stwo.backends.cuda.runtime.proof_assembly.decommit_bundle;
const stark = stwo.backends.cuda.runtime.proof_assembly.stark_bundle;
const wide_fibonacci = stwo.examples.wide_fibonacci;
const subject = stwo.integrations.native_cuda.wide_fibonacci.proof_decode;

const queries = [_]u32{ 0, 16, 32 };

test "single SWPC read reconstructs the exact CPU log5x8 proof bytes" {
    const allocator = std.testing.allocator;
    const config = core_pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try core_fri.FriConfig.init(0, 1, queries.len),
    };
    var cpu = try wide_fibonacci.prove(
        allocator,
        config,
        .{ .log_n_rows = 5, .sequence_len = 8 },
    );
    defer cpu.proof.deinit(allocator);

    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const wire = try proof_wire.proofToWire(scratch.allocator(), cpu.proof);
    var bundle = try stark.Bundle.decodeOwned(
        allocator,
        try Fixture.make(allocator, wire),
    );
    defer bundle.deinit(allocator);

    var decoded = try subject.decodeProof(allocator, bundle);
    defer decoded.deinit(allocator);
    const expected = try proof_wire.encodeProofBytes(allocator, cpu.proof);
    defer allocator.free(expected);
    const actual = try proof_wire.encodeProofBytes(allocator, decoded);
    defer allocator.free(actual);
    try std.testing.expectEqual(@as(usize, 8912), actual.len);
    try std.testing.expectEqualSlices(u8, expected, actual);

    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(actual, &digest, .{});
    try std.testing.expectEqualSlices(u8, &.{
        0x2c, 0x90, 0x68, 0x4b, 0x49, 0x38, 0x78, 0x04,
        0xfd, 0x51, 0xbe, 0xf3, 0xe2, 0x86, 0x20, 0x1e,
        0x4b, 0x0b, 0x43, 0xa9, 0x6b, 0x42, 0x20, 0x0a,
        0x7b, 0x68, 0x12, 0xa5, 0xa1, 0x1e, 0x31, 0x7d,
    }, &digest);
}

test "SWPC proof decoder rejects noncanonical fields and opening metadata" {
    const allocator = std.testing.allocator;
    const config = core_pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try core_fri.FriConfig.init(0, 1, queries.len),
    };
    var cpu = try wide_fibonacci.prove(
        allocator,
        config,
        .{ .log_n_rows = 5, .sequence_len = 8 },
    );
    defer cpu.proof.deinit(allocator);
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const wire = try proof_wire.proofToWire(scratch.allocator(), cpu.proof);

    {
        var bundle = try stark.Bundle.decodeOwned(
            allocator,
            try Fixture.make(allocator, wire),
        );
        defer bundle.deinit(allocator);
        const sample = bundle.sections[
            @intFromEnum(stark.SectionKind.sampled_values) - 1
        ];
        bundle.storage[sample.offset_words] = m31.Modulus;
        try std.testing.expectError(
            error.InvalidFieldElement,
            subject.decodeProof(allocator, bundle),
        );
    }
    {
        var bundle = try stark.Bundle.decodeOwned(
            allocator,
            try Fixture.make(allocator, wire),
        );
        defer bundle.deinit(allocator);
        const fri_tree = bundle.decommitment.trees[2];
        bundle.decommitment.storage[fri_tree.all_values_offset] += 1;
        try std.testing.expectError(
            error.InvalidFriOpening,
            subject.decodeProof(allocator, bundle),
        );
    }
    {
        var bundle = try stark.Bundle.decodeOwned(
            allocator,
            try Fixture.make(allocator, wire),
        );
        defer bundle.deinit(allocator);
        const trace_tree = bundle.decommitment.trees[0];
        bundle.decommitment.storage[trace_tree.aux_offset] = 0;
        try std.testing.expectError(
            error.InvalidMerkleArtifacts,
            subject.decodeProof(allocator, bundle),
        );
    }
}

test "duplicate raw queries decode to unique canonical trace columns" {
    const allocator = std.testing.allocator;
    const config = core_pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try core_fri.FriConfig.init(0, 1, queries.len),
    };
    var cpu = try wide_fibonacci.prove(
        allocator,
        config,
        .{ .log_n_rows = 5, .sequence_len = 8 },
    );
    defer cpu.proof.deinit(allocator);
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const source = try proof_wire.proofToWire(scratch.allocator(), cpu.proof);
    const raw = [_]u32{ 0, 16, 16, 32 };
    var bundle = try stark.Bundle.decodeOwned(
        allocator,
        try Fixture.makeWithRaw(allocator, source, &raw),
    );
    defer bundle.deinit(allocator);

    var decoded = try subject.OwnedProofWire.init(allocator, bundle);
    defer decoded.deinit();
    try std.testing.expectEqual(
        @as(u64, raw.len),
        decoded.value.config.fri_config.n_queries,
    );
    for (decoded.value.queried_values[1..], source.queried_values[1..]) |
        decoded_tree,
        source_tree,
    | {
        for (decoded_tree, source_tree) |decoded_column, source_column| {
            try std.testing.expectEqual(queries.len, decoded_column.len);
            try std.testing.expectEqualSlices(
                u32,
                source_column,
                decoded_column,
            );
        }
    }
}

const Fixture = struct {
    fn make(
        allocator: std.mem.Allocator,
        wire: proof_wire.ProofWire,
    ) ![]u32 {
        return makeWithRaw(allocator, wire, &queries);
    }

    fn makeWithRaw(
        allocator: std.mem.Allocator,
        wire: proof_wire.ProofWire,
        raw_queries: []const u32,
    ) ![]u32 {
        const nested = try nestedBundle(allocator, wire, raw_queries);
        defer allocator.free(nested);

        var sections: [stark.section_count][]u32 = undefined;
        sections[0] = try hashWords(allocator, wire.commitments);
        defer allocator.free(sections[0]);
        sections[1] = try sampleWords(allocator, wire.sampled_values);
        defer allocator.free(sections[1]);
        sections[2] = try friRootWords(allocator, wire.fri_proof);
        defer allocator.free(sections[2]);
        sections[3] = try secureWords(
            allocator,
            wire.fri_proof.last_layer_poly,
        );
        defer allocator.free(sections[3]);
        sections[4] = try allocator.dupe(u32, &.{
            @truncate(wire.proof_of_work),
            @truncate(wire.proof_of_work >> 32),
        });
        defer allocator.free(sections[4]);
        sections[5] = nested;

        var total = stark.header_words;
        for (sections) |section| total += section.len;
        const output = try allocator.alloc(u32, total);
        @memset(output, 0);
        output[0..stark.fixed_header_words].* = .{
            stark.magic,
            stark.version,
            @intCast(total),
            stark.section_count,
            5,
            8,
            wire.config.pow_bits,
            wire.config.fri_config.log_blowup_factor,
            wire.config.fri_config.log_last_layer_degree_bound,
            @intCast(raw_queries.len),
            wire.config.fri_config.fold_step,
            std.math.maxInt(u32),
            @intCast(wire.commitments.len),
            @intCast(1 + wire.fri_proof.inner_layers.len),
            @intCast(decommitTreeCount(wire)),
            0,
        };
        var cursor = stark.header_words;
        inline for (std.meta.fields(stark.SectionKind), 0..) |field, index| {
            const record = stark.fixed_header_words +
                index * stark.section_record_words;
            output[record] = field.value;
            output[record + 1] = @intCast(cursor);
            output[record + 2] = @intCast(sections[index].len);
            @memcpy(output[cursor .. cursor + sections[index].len], sections[index]);
            cursor += sections[index].len;
        }
        return output;
    }

    fn nestedBundle(
        allocator: std.mem.Allocator,
        wire: proof_wire.ProofWire,
        raw_queries: []const u32,
    ) ![]u32 {
        const tree_count = decommitTreeCount(wire);
        const prefix_words = decommit.header_words +
            tree_count * decommit.tree_meta_words +
            raw_queries.len + queries.len;
        var output = std.ArrayList(u32).empty;
        errdefer output.deinit(allocator);
        try output.resize(allocator, prefix_words);
        @memset(output.items, 0);
        output.items[0..decommit.header_words].* = .{
            decommit.magic,
            decommit.version,
            @intCast(tree_count),
            @intCast(raw_queries.len),
            queries.len,
            @intCast(decommit.header_words + tree_count * decommit.tree_meta_words),
            @intCast(decommit.header_words + tree_count * decommit.tree_meta_words + raw_queries.len),
            0,
        };
        const raw_offset: usize = output.items[5];
        @memcpy(
            output.items[raw_offset .. raw_offset + raw_queries.len],
            raw_queries,
        );
        @memcpy(
            output.items[raw_offset + raw_queries.len .. prefix_words],
            &queries,
        );

        try appendTraceTree(allocator, &output, wire, 0, 1);
        try appendTraceTree(allocator, &output, wire, 1, 2);
        try appendFriTrees(allocator, &output, wire);
        output.items[7] = @intCast(output.items.len);
        return output.toOwnedSlice(allocator);
    }

    fn appendTraceTree(
        allocator: std.mem.Allocator,
        output: *std.ArrayList(u32),
        wire: proof_wire.ProofWire,
        tree_index: usize,
        wire_index: usize,
    ) !void {
        const start = output.items.len;
        const query_offset = try appendSlice(allocator, output, &queries);
        const values_offset = output.items.len;
        for (wire.queried_values[wire_index]) |column| {
            if (column.len != queries.len) return error.InvalidFixture;
            try output.appendSlice(allocator, column);
        }
        const hashes = wire.decommitments[wire_index].hash_witness;
        const hash_offset = try appendHashes(allocator, output, hashes);
        const aux_offset = output.items.len;
        const aux_count = try appendAux(allocator, output, &queries, 6);
        setMeta(output.items, tree_index, .{
            @intFromEnum(decommit.TreeKind.trace),
            @intCast(wire_index),
            @intCast(query_offset),
            queries.len,
            @intCast(values_offset),
            @intCast(wire.queried_values[wire_index].len * queries.len),
            0,
            0,
            @intCast(hash_offset),
            @intCast(hashes.len),
            @intCast(aux_offset),
            @intCast(aux_count),
            0,
            0,
            6,
            @intCast(output.items.len - start),
        });
        try requireHashCount(hashes.len, &queries, 6);
    }

    fn appendFriTrees(
        allocator: std.mem.Allocator,
        output: *std.ArrayList(u32),
        wire: proof_wire.ProofWire,
    ) !void {
        const layer_count = 1 + wire.fri_proof.inner_layers.len;
        for (0..layer_count) |layer_index| {
            const layer = if (layer_index == 0)
                wire.fri_proof.first_layer
            else
                wire.fri_proof.inner_layers[layer_index - 1];
            const folded = foldedQueries(layer_index);
            const expanded = expandedQueries(folded.slice());
            const tree_index = 2 + layer_index;
            const start = output.items.len;
            const query_offset = try appendSlice(
                allocator,
                output,
                folded.slice(),
            );
            const witness_offset = try appendSecure(
                allocator,
                output,
                layer.fri_witness,
            );
            const hash_offset = try appendHashes(
                allocator,
                output,
                layer.decommitment.hash_witness,
            );
            const aux_offset = output.items.len;
            const leaf_log: u32 = @intCast(6 - layer_index);
            const aux_count = try appendAux(
                allocator,
                output,
                expanded.slice(),
                leaf_log,
            );
            const all_offset = output.items.len;
            var witness_index: usize = 0;
            for (expanded.slice()) |position| {
                try output.append(allocator, position);
                if (contains(folded.slice(), position)) {
                    try output.appendSlice(allocator, &.{ 0, 0, 0, 0 });
                } else {
                    try appendSecureValue(
                        allocator,
                        output,
                        layer.fri_witness[witness_index],
                    );
                    witness_index += 1;
                }
            }
            if (witness_index != layer.fri_witness.len)
                return error.InvalidFixture;
            setMeta(output.items, tree_index, .{
                @intFromEnum(decommit.TreeKind.fri),
                @intCast(tree_index),
                @intCast(query_offset),
                @intCast(folded.len),
                0,
                0,
                if (layer.fri_witness.len == 0)
                    0
                else
                    @intCast(witness_offset),
                @intCast(layer.fri_witness.len),
                if (layer.decommitment.hash_witness.len == 0)
                    0
                else
                    @intCast(hash_offset),
                @intCast(layer.decommitment.hash_witness.len),
                @intCast(aux_offset),
                @intCast(aux_count),
                @intCast(all_offset),
                @intCast(expanded.len),
                leaf_log,
                @intCast(output.items.len - start),
            });
            try requireHashCount(
                layer.decommitment.hash_witness.len,
                expanded.slice(),
                leaf_log,
            );
        }
    }
};

const SmallQueries = struct {
    values: [queries.len * 2]u32 = undefined,
    len: usize,

    fn slice(self: *const SmallQueries) []const u32 {
        return self.values[0..self.len];
    }
};

fn foldedQueries(folds: usize) SmallQueries {
    var output = SmallQueries{ .len = 0 };
    for (queries) |query| {
        const value = query >> @intCast(folds);
        if (output.len == 0 or output.values[output.len - 1] != value) {
            output.values[output.len] = value;
            output.len += 1;
        }
    }
    return output;
}

fn expandedQueries(input: []const u32) SmallQueries {
    var output = SmallQueries{ .len = 0 };
    var previous: ?u32 = null;
    for (input) |query| {
        const coset = query >> 1;
        if (previous != null and previous.? == coset) continue;
        output.values[output.len] = 2 * coset;
        output.values[output.len + 1] = 2 * coset + 1;
        output.len += 2;
        previous = coset;
    }
    return output;
}

fn appendAux(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u32),
    input: []const u32,
    leaf_log: u32,
) !usize {
    var current: [queries.len * 2]u32 = undefined;
    @memcpy(current[0..input.len], input);
    var current_len = input.len;
    var count: usize = 0;
    var level = leaf_log;
    while (level != 0) : (level -= 1) {
        var read: usize = 0;
        var write: usize = 0;
        while (read < current_len) {
            const position = current[read];
            const paired = read + 1 < current_len and
                current[read + 1] == (position ^ 1);
            const parent = position >> 1;
            current[write] = parent;
            write += 1;
            for (0..2) |child| {
                try output.append(allocator, level);
                try output.append(allocator, @intCast(2 * parent + child));
                try output.appendNTimes(allocator, 0, stark.hash_words);
                count += 1;
            }
            read += if (paired) 2 else 1;
        }
        current_len = write;
    }
    return count;
}

fn requireHashCount(expected: usize, input: []const u32, leaf_log: u32) !void {
    var current: [queries.len * 2]u32 = undefined;
    @memcpy(current[0..input.len], input);
    var current_len = input.len;
    var count: usize = 0;
    var level = leaf_log;
    while (level != 0) : (level -= 1) {
        var read: usize = 0;
        var write: usize = 0;
        while (read < current_len) {
            const position = current[read];
            const paired = read + 1 < current_len and
                current[read + 1] == (position ^ 1);
            if (!paired) count += 1;
            current[write] = position >> 1;
            write += 1;
            read += if (paired) 2 else 1;
        }
        current_len = write;
    }
    if (count != expected) return error.InvalidFixture;
}

fn setMeta(words: []u32, tree_index: usize, value: [16]u32) void {
    const base = decommit.header_words + tree_index * decommit.tree_meta_words;
    @memcpy(words[base .. base + value.len], &value);
}

fn appendSlice(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u32),
    values: []const u32,
) !usize {
    const offset = output.items.len;
    try output.appendSlice(allocator, values);
    return offset;
}

fn appendHashes(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u32),
    hashes: []const proof_wire.HashWire,
) !usize {
    const offset = output.items.len;
    for (hashes) |hash| {
        for (0..stark.hash_words) |word_index| {
            const base = word_index * 4;
            try output.append(allocator, std.mem.readInt(
                u32,
                hash[base..][0..4],
                .little,
            ));
        }
    }
    return offset;
}

fn appendSecure(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u32),
    values: []const proof_wire.Qm31Wire,
) !usize {
    const offset = output.items.len;
    for (values) |value| try appendSecureValue(allocator, output, value);
    return offset;
}

fn appendSecureValue(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u32),
    value: proof_wire.Qm31Wire,
) !void {
    try output.appendSlice(allocator, &value);
}

fn hashWords(
    allocator: std.mem.Allocator,
    values: []const proof_wire.HashWire,
) ![]u32 {
    var output = std.ArrayList(u32).empty;
    errdefer output.deinit(allocator);
    _ = try appendHashes(allocator, &output, values);
    return output.toOwnedSlice(allocator);
}

fn secureWords(
    allocator: std.mem.Allocator,
    values: []const proof_wire.Qm31Wire,
) ![]u32 {
    var output = std.ArrayList(u32).empty;
    errdefer output.deinit(allocator);
    _ = try appendSecure(allocator, &output, values);
    return output.toOwnedSlice(allocator);
}

fn sampleWords(
    allocator: std.mem.Allocator,
    trees: []const [][]proof_wire.Qm31Wire,
) ![]u32 {
    var output = std.ArrayList(u32).empty;
    errdefer output.deinit(allocator);
    for (trees) |tree| {
        for (tree) |column| {
            if (column.len != 1) return error.InvalidFixture;
            try appendSecureValue(allocator, &output, column[0]);
        }
    }
    return output.toOwnedSlice(allocator);
}

fn friRootWords(
    allocator: std.mem.Allocator,
    proof: proof_wire.FriProofWire,
) ![]u32 {
    var output = std.ArrayList(u32).empty;
    errdefer output.deinit(allocator);
    _ = try appendHashes(allocator, &output, &.{proof.first_layer.commitment});
    for (proof.inner_layers) |layer| {
        _ = try appendHashes(allocator, &output, &.{layer.commitment});
    }
    return output.toOwnedSlice(allocator);
}

fn contains(values: []const u32, needle: u32) bool {
    for (values) |value| if (value == needle) return true;
    return false;
}

fn decommitTreeCount(wire: proof_wire.ProofWire) usize {
    return 2 + 1 + wire.fri_proof.inner_layers.len;
}

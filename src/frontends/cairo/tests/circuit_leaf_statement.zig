//! Rung R6 (leaf statement): the Cairo lane's host inputs of the circuit
//! recursion leaf against `vectors/circuit/r6/cairo_statement.json`, which the
//! pinned oracle derives from `starkware-libs/proving@5a7c5ed`.
//!
//! Covers the 83-slot order, the leaf `enabled_bits`, the ordered
//! preprocessed ids of every variant, the statement constants, the leaf test
//! program's limbs and hash, and, on a synthetic claim with every segment
//! present, `serialize_aux_data` and `FlatClaim::mix_into` under both
//! Blake2s Merkle channels through the lane's own transcript code.

const std = @import("std");
const core = @import("stwo_core");
const cairo = @import("cairo_frontend");

const M31 = core.fields.m31.M31;
const blake2_merkle = core.vcs_lifted.blake2_merkle;
const layout = cairo.air_layout;
const leaf = cairo.statement.circuit_leaf;
const registry = cairo.claim_registry;

const checkpoint_path = "vectors/circuit/r6/cairo_statement.json";
const components_path = "vectors/circuit/r3/components.json";
const program_path = "vectors/circuit/official/programs/use_all_opcodes_and_builtins_compiled.json";

const Checkpoint = struct {
    arena: std.heap.ArenaAllocator,
    body: std.json.ObjectMap,

    fn load(allocator: std.mem.Allocator, path: []const u8) !Checkpoint {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const bytes = try std.fs.cwd().readFileAlloc(arena.allocator(), path, 4 * 1024 * 1024);
        const value = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), bytes, .{});
        const root = value.object;
        try std.testing.expectEqualStrings("stwo-circuit-oracle-checkpoint-v1", root.get("schema").?.string);
        try std.testing.expectEqualStrings(
            "5a7c5ede4299c91a61df19a07cba4f7502c14230",
            root.get("authority").?.object.get("revision").?.string,
        );
        return .{ .arena = arena, .body = root.get("body").?.object };
    }

    fn deinit(self: *Checkpoint) void {
        self.arena.deinit();
    }

    fn variant(self: *const Checkpoint, name: []const u8) std.json.ObjectMap {
        for (self.body.get("variants").?.array.items) |item| {
            if (std.mem.eql(u8, item.object.get("variant").?.string, name)) return item.object;
        }
        unreachable;
    }
};

fn int(value: std.json.Value) u32 {
    return @intCast(value.integer);
}

fn expectWords(expected: std.json.Value, actual: []const u32) !void {
    try std.testing.expectEqual(expected.array.items.len, actual.len);
    for (expected.array.items, actual) |want, got| try std.testing.expectEqual(int(want), got);
}

fn wordsFromJson(allocator: std.mem.Allocator, value: std.json.Value) ![]u32 {
    const words = try allocator.alloc(u32, value.array.items.len);
    for (value.array.items, words) |item, *word| word.* = int(item);
    return words;
}

test "R6 leaf: the 83 Cairo slots match upstream all_components in order" {
    var checkpoint = try Checkpoint.load(std.testing.allocator, checkpoint_path);
    defer checkpoint.deinit();
    var components = try Checkpoint.load(std.testing.allocator, components_path);
    defer components.deinit();
    const upstream = checkpoint.body.get("all_components").?.array.items;
    const r3_slots = components.body.get("cairo_slots").?.array.items;
    try std.testing.expectEqual(registry.enable_slot_count, upstream.len);
    try std.testing.expectEqual(upstream.len, r3_slots.len);
    for (upstream, r3_slots, 0..) |name, r3_name, slot| {
        var buffer: [64]u8 = undefined;
        try std.testing.expectEqualStrings(name.string, leaf.slotName(slot, &buffer));
        try std.testing.expectEqualStrings(name.string, r3_name.string);
    }
}

test "R6 leaf: enabled bits and disabled components per variant" {
    var checkpoint = try Checkpoint.load(std.testing.allocator, checkpoint_path);
    defer checkpoint.deinit();
    inline for (.{ layout.Variant.canonical, layout.Variant.canonical_small }) |variant| {
        const record = checkpoint.variant(@tagName(variant));
        const disabled = try layout.leafDisabledComponents(variant);
        const upstream_disabled = record.get("disabled_components").?.array.items;
        try std.testing.expectEqual(disabled.len, upstream_disabled.len);
        for (disabled, upstream_disabled) |name, upstream| try std.testing.expectEqualStrings(upstream.string, name);

        var bits: [registry.enable_slot_count]bool = undefined;
        const enabled = try leaf.leafEnabledBits(variant, &bits);
        try std.testing.expectEqual(int(record.get("n_enabled_components").?), enabled);
        for (record.get("enabled_bits").?.array.items, bits) |want, got| try std.testing.expectEqual(want.bool, got);
    }
    const without = checkpoint.variant("canonical_without_pedersen");
    try std.testing.expect(without.get("enabled_bits").? == .null);
    var bits: [registry.enable_slot_count]bool = undefined;
    try std.testing.expectError(layout.Error.UnsupportedLeafVariant, leaf.leafEnabledBits(.canonical_without_pedersen, &bits));
}

test "R6 leaf: ordered preprocessed column ids of every variant" {
    var checkpoint = try Checkpoint.load(std.testing.allocator, checkpoint_path);
    defer checkpoint.deinit();
    inline for (comptime std.enums.values(layout.Variant)) |variant| {
        const record = checkpoint.variant(@tagName(variant));
        const upstream = record.get("preprocessed_column_ids").?.array.items;
        try std.testing.expectEqual(int(record.get("n_preprocessed_columns").?), upstream.len);
        var spec = try cairo.preprocessed.trace.Spec.init(std.testing.allocator, variant);
        defer spec.deinit();
        try std.testing.expectEqual(upstream.len, spec.columns.len);
        for (upstream, spec.columns) |id, column| try std.testing.expectEqualStrings(id.string, column.identity);
    }
}

test "R6 leaf: statement constants" {
    var checkpoint = try Checkpoint.load(std.testing.allocator, checkpoint_path);
    defer checkpoint.deinit();
    const constants = checkpoint.body.get("constants").?.object;
    try std.testing.expectEqual(int(constants.get("aux_data_fixed_len").?), leaf.aux_data_fixed_len);
    try std.testing.expectEqual(int(constants.get("n_outputs").?), leaf.n_outputs);
    try std.testing.expectEqual(int(constants.get("n_words_per_output_cell").?), leaf.n_words_per_output_cell);
    try std.testing.expectEqual(int(constants.get("memory_values_limbs").?), leaf.memory_values_limbs);
    try std.testing.expectEqual(int(constants.get("memory_address_to_id_split").?), cairo.claim_generator.memory_address_to_id_split);
    try std.testing.expectEqual(int(constants.get("max_sequence_log_size").?), cairo.claim_generator.max_sequence_log_size);
    try std.testing.expectEqual(int(constants.get("max_sequence_log_size").?), layout.Variant.canonical.maxSequenceLogSize());
    const ids = cairo.air.claims.relation_ids;
    try std.testing.expectEqual(int(constants.get("opcodes_relation_id").?), ids.OPCODES.v);
    try std.testing.expectEqual(int(constants.get("memory_address_to_id_relation_id").?), ids.MEMORY_ADDRESS_TO_ID.v);
    try std.testing.expectEqual(int(constants.get("memory_id_to_big_relation_id").?), ids.MEMORY_ID_TO_BIG.v);
    const cells = constants.get("builtin_memory_cells").?.array.items;
    try std.testing.expectEqual(layout.verify_builtins_order.len, cells.len);
    for (layout.verify_builtins_order, cells, 0..) |builtin, entry, index| {
        const pair = entry.array.items;
        try std.testing.expectEqual(int(pair[1]), builtin.memoryCells());
        // Entry 0 names the Pedersen segment; the others name their component.
        if (index > 0) try std.testing.expectEqualStrings(pair[0].string, builtin.componentName(.canonical));
    }
}

test "R6 leaf: program limbs and program hash of the leaf test program" {
    const allocator = std.testing.allocator;
    var checkpoint = try Checkpoint.load(allocator, checkpoint_path);
    defer checkpoint.deinit();
    const record = checkpoint.body.get("program").?.object;
    const json_bytes = try std.fs.cwd().readFileAlloc(allocator, program_path, 4 * 1024 * 1024);
    defer allocator.free(json_bytes);
    const program = try leaf.programFeltsFromCompiledJson(allocator, json_bytes);
    defer allocator.free(program);
    try std.testing.expectEqual(int(record.get("n_felts").?), program.len);

    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    for (program) |felt| for (felt) |limb| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, limb.v, .little);
        sha.update(&bytes);
    };
    const digest = std.fmt.bytesToHex(sha.finalResult(), .lower);
    try std.testing.expectEqualStrings(record.get("limbs_sha256").?.string, &digest);
    var first: [leaf.memory_values_limbs]u32 = undefined;
    var last: [leaf.memory_values_limbs]u32 = undefined;
    for (program[0], program[program.len - 1], &first, &last) |a, b, *x, *y| {
        x.* = a.v;
        y.* = b.v;
    }
    try expectWords(record.get("first_felt_limbs").?, &first);
    try expectWords(record.get("last_felt_limbs").?, &last);
    const hash = leaf.programHash(program);
    try expectWords(record.get("program_hash").?, &hash);
}

fn paddedCopy(allocator: std.mem.Allocator, words: []const u32) ![]u32 {
    const padded = try allocator.alloc(u32, std.mem.alignForward(usize, words.len, 4));
    @memset(padded, 0);
    @memcpy(padded[0..words.len], words);
    return padded;
}

/// The public-data leaf root exactly as `public_data.derive` streams it: one
/// `updateLeaf` per 28-limb value under the plain Blake2s Merkle hasher.
fn claimRoot(words: []const u32) [8]u32 {
    var hasher = blake2_merkle.Blake2sPlainMerkleHasher.defaultWithInitialState();
    var offset: usize = 0;
    while (offset < words.len) : (offset += leaf.memory_values_limbs) {
        var limbs: [leaf.memory_values_limbs]M31 = undefined;
        for (&limbs, words[offset..][0..leaf.memory_values_limbs]) |*limb, word| limb.* = M31.fromCanonical(word);
        hasher.updateLeaf(&limbs);
    }
    const digest = hasher.finalize();
    var root: [8]u32 = undefined;
    for (&root, 0..) |*word, index| word.* = std.mem.readInt(u32, digest[index * 4 ..][0..4], .little);
    return root;
}

test "R6 leaf: synthetic claim aux data and FlatClaim mix on both Blake2s channels" {
    var checkpoint = try Checkpoint.load(std.testing.allocator, checkpoint_path);
    defer checkpoint.deinit();
    const arena = checkpoint.arena.allocator();
    const claim = checkpoint.body.get("synthetic_claim").?.object;
    const public_claim = try wordsFromJson(arena, claim.get("public_claim").?);
    const log_sizes = try wordsFromJson(arena, claim.get("component_log_sizes").?);
    const program_len = claim.get("program").?.array.items.len;
    const output_len = claim.get("output").?.array.items.len;

    const aux = try leaf.serializeAuxDataFromPublicClaim(
        std.testing.allocator,
        public_claim,
        [_]bool{true} ** leaf.n_segments,
        output_len,
        program_len,
        log_sizes,
    );
    defer std.testing.allocator.free(aux);
    try expectWords(claim.get("serialized_aux_data").?, aux);

    const bits = claim.get("component_enable_bits").?.array.items;
    const enable_words = try arena.alloc(u32, std.mem.alignForward(usize, bits.len, 4));
    @memset(enable_words, 0);
    for (bits, enable_words[0..bits.len]) |bit, *word| word.* = @intFromBool(bit.bool);
    var statement = cairo.statement_bootstrap.OwnedStatementBootstrap{
        .allocator = arena,
        .ordinal_1 = &.{},
        .ordinal_2 = &.{},
        .ordinal_10 = try arena.dupe(u32, &.{ @intCast(bits.len), 0, 0, 0 }),
        .ordinal_11 = enable_words,
        .ordinal_12 = try paddedCopy(arena, log_sizes),
        .ordinal_13 = try arena.dupe(u32, &.{ @intCast(program_len), 0, 0, 0 }),
        .ordinal_14 = try paddedCopy(arena, public_claim),
        .ordinal_15 = try arena.dupe(u32, &claimRoot(try wordsFromJson(arena, claim.get("output_claim").?))),
        .ordinal_16 = try arena.dupe(u32, &claimRoot(try wordsFromJson(arena, claim.get("program_claim").?))),
    };
    const transcript = cairo.proving.transcript;

    var m31_channel = core.channel.blake2s.Blake2sM31Channel{};
    try transcript.mixClaimWith(blake2_merkle.Blake2sM31MerkleChannel, std.testing.allocator, &m31_channel, &statement);
    const m31_hex = std.fmt.bytesToHex(m31_channel.digestBytes(), .lower);
    try std.testing.expectEqualStrings(claim.get("mix_digest_blake2s_m31").?.string, &m31_hex);

    var plain_channel = core.channel.blake2s.Blake2sChannel{};
    try transcript.mixClaim(std.testing.allocator, &plain_channel, &statement);
    const plain_hex = std.fmt.bytesToHex(plain_channel.digestBytes(), .lower);
    try std.testing.expectEqualStrings(claim.get("mix_digest_blake2s").?.string, &plain_hex);
}

test "R6 leaf: output hash packs the synthetic output cells" {
    var checkpoint = try Checkpoint.load(std.testing.allocator, checkpoint_path);
    defer checkpoint.deinit();
    const output = checkpoint.body.get("synthetic_claim").?.object.get("output").?.array.items;
    var cells: [leaf.n_outputs][8]u32 = undefined;
    for (output, &cells) |cell, *words| {
        for (cell.object.get("value").?.array.items, words) |word, *slot| slot.* = int(word);
    }
    const digest = try leaf.outputHashFromOutputCells(&cells);
    for (0..leaf.n_outputs) |index|
        try std.testing.expectEqualSlices(u32, cells[index][0..4], digest[index * 4 ..][0..4]);
}

test "R6 leaf: serializeAuxData on an official execution follows the output-count rule" {
    const allocator = std.testing.allocator;
    var input = try cairo.adapter.input.readFile(allocator, "vectors/cairo/official/all_builtins.prover_input.json");
    defer input.deinit(allocator);
    const public = try cairo.statement.public_data.derive(allocator, &input);
    defer allocator.free(public.public_claim);
    const log_sizes = [_]u32{7} ** 79;
    if (public.output_len != leaf.n_outputs) {
        try std.testing.expectError(error.OutputCellCount, leaf.serializeAuxData(allocator, &input, &log_sizes));
        return;
    }
    const aux = try leaf.serializeAuxData(allocator, &input, &log_sizes);
    defer allocator.free(aux);
    try std.testing.expectEqual(leaf.aux_data_fixed_len + public.program_len + log_sizes.len, aux.len);
    try std.testing.expectEqualSlices(u32, public.public_claim[0..public.public_claim_word_count], aux[0..public.public_claim_word_count]);
}

const std = @import("std");
const cairo = @import("cairo_frontend");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const Blake2sMerkleChannel =
    @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sPlainMerkleChannel;

const claim_summary_path = "vectors/cairo/official/all_opcodes.claim_summary.json";
const input_path = "vectors/cairo/official/all_opcodes.prover_input.json";

test "official Cairo claim: live input matches canonical flat geometry and mix" {
    const encoded = try std.fs.cwd().readFileAlloc(
        std.testing.allocator,
        claim_summary_path,
        64 * 1024,
    );
    defer std.testing.allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings(
        "stwo_cairo_official_claim_summary_v1",
        root.get("schema").?.string,
    );
    try std.testing.expectEqualStrings(
        "canonical",
        root.get("preprocessed_trace_variant").?.string,
    );

    var input = try cairo.adapter.official_input.readFile(std.testing.allocator, input_path);
    defer input.deinit(std.testing.allocator);
    var geometry = try cairo.claim_generator.deriveFromProverInput(
        std.testing.allocator,
        &input,
        .{ .preprocessed_variant = .canonical },
    );
    defer geometry.deinit();

    const flat_json = root.get("flat_claim").?.object;
    const expected_bits = flat_json.get("component_enable_bits").?.array.items;
    const expected_logs = flat_json.get("component_log_sizes").?.array.items;
    try std.testing.expectEqual(cairo.claim_registry.enable_slot_count, expected_bits.len);

    var slot_logs = [_]?u32{null} ** cairo.claim_registry.enable_slot_count;
    var expected_log_index: usize = 0;
    for (expected_bits, 0..) |enabled, slot| {
        if (!enabled.bool) continue;
        if (expected_log_index >= expected_logs.len) return error.InvalidOracleVector;
        slot_logs[slot] = try jsonU32(expected_logs[expected_log_index]);
        expected_log_index += 1;
    }
    try std.testing.expectEqual(expected_logs.len, expected_log_index);

    const feeds = try std.testing.allocator.alloc(
        cairo.claim_generator.FeedGeometry,
        geometry.deferredCount(),
    );
    defer std.testing.allocator.free(feeds);
    var feed_index: usize = 0;
    var derived_bits = [_]bool{false} ** cairo.claim_registry.enable_slot_count;
    for (geometry.components) |component| {
        const field = findField(component.name) orelse return error.UnknownClaimComponent;
        const slot = @as(usize, field.first_enable_slot) + component.instance;
        if (slot >= derived_bits.len or derived_bits[slot]) return error.InvalidClaimGeometry;
        derived_bits[slot] = true;
        try std.testing.expect(expected_bits[slot].bool);
        const expected_log = slot_logs[slot] orelse return error.InvalidOracleVector;
        switch (component.log_size) {
            .known => |actual| try std.testing.expectEqual(expected_log, actual),
            .deferred => {
                feeds[feed_index] = .{
                    .name = component.name,
                    .instance = component.instance,
                    .log_size = expected_log,
                };
                feed_index += 1;
            },
        }
    }
    try std.testing.expectEqual(feeds.len, feed_index);
    for (expected_bits, derived_bits) |expected, actual| {
        try std.testing.expectEqual(expected.bool, actual);
    }

    try geometry.resolveFeedGeometry(std.testing.allocator, feeds);
    var flat = try geometry.flatten();
    defer flat.deinit();
    for (expected_bits, flat.component_enable_bits) |expected, actual| {
        try std.testing.expectEqual(expected.bool, actual);
    }
    for (expected_logs, flat.component_log_sizes) |expected, actual| {
        try std.testing.expectEqual(try jsonU32(expected), actual);
    }

    var statement = try cairo.statement_bootstrap.init(std.testing.allocator, .{
        .channel_salt = 0,
        .pcs = .{
            .pow_bits = 26,
            .log_blowup_factor = 1,
            .n_queries = 70,
            .log_last_layer_degree_bound = 0,
            .fold_step = 1,
        },
        .component_enable_bits = flat.component_enable_bits,
        .component_log_sizes = flat.component_log_sizes,
        .prover_input = &input,
    });
    defer statement.deinit();
    const actual_mix = try mixClaim(std.testing.allocator, &statement);
    const actual_mix_hex = std.fmt.bytesToHex(actual_mix, .lower);
    try std.testing.expectEqualStrings(
        flat_json.get("blake2s_mix_digest").?.string,
        &actual_mix_hex,
    );
}

fn findField(name: []const u8) ?cairo.claim_registry.ClaimField {
    for (cairo.claim_registry.claim_fields) |field| {
        if (std.mem.eql(u8, name, field.name)) return field;
    }
    return null;
}

fn jsonU32(value: std.json.Value) !u32 {
    return switch (value) {
        .integer => |number| std.math.cast(u32, number) orelse error.InvalidOracleVector,
        .number_string => |number| std.fmt.parseInt(u32, number, 10),
        else => error.InvalidOracleVector,
    };
}

fn mixClaim(
    allocator: std.mem.Allocator,
    statement: *const cairo.statement_bootstrap.OwnedStatementBootstrap,
) ![32]u8 {
    var channel = Blake2sChannel{};
    for ([_]u32{ 10, 11, 12, 13, 14 }) |ordinal| {
        try mixPackedWords(allocator, &channel, statement.words(ordinal).?);
    }
    Blake2sMerkleChannel.mixRoot(&channel, rootBytes(statement.words(15).?));
    Blake2sMerkleChannel.mixRoot(&channel, rootBytes(statement.words(16).?));
    return channel.digestBytes();
}

fn mixPackedWords(
    allocator: std.mem.Allocator,
    channel: *Blake2sChannel,
    words: []const u32,
) !void {
    std.debug.assert(words.len % 4 == 0);
    const felts = try allocator.alloc(QM31, words.len / 4);
    defer allocator.free(felts);
    var offset: usize = 0;
    for (felts) |*felt| {
        felt.* = QM31.fromM31(
            M31.fromCanonical(words[offset]),
            M31.fromCanonical(words[offset + 1]),
            M31.fromCanonical(words[offset + 2]),
            M31.fromCanonical(words[offset + 3]),
        );
        offset += 4;
    }
    channel.mixFelts(felts);
}

fn rootBytes(words: []const u32) [32]u8 {
    std.debug.assert(words.len == 8);
    var bytes: [32]u8 = undefined;
    for (words, 0..) |word, index| {
        std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
    }
    return bytes;
}

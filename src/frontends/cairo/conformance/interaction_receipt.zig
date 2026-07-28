//! Strict JSON interchange for pinned Rust Cairo interaction-trace receipts.

const std = @import("std");
const checkpoint = @import("interaction_checkpoint.zig");
const claim_registry = @import("../air/official_claim_registry.zig");

pub const schema = "stwo-cairo-interaction-trace-checkpoint-v1";
pub const stwo_cairo_revision = "dcd5834565b7a26a27a614e353c9c60109ebc1d9";
pub const stwo_revision = "3fe684648ff31e55b71525ad689fab7dfbd88880";
pub const challenge_purpose = "deterministic_cross_backend_interaction_trace_diagnostics";
pub const challenge_warning = "fixed diagnostic lookup elements; not Fiat-Shamir proof-transcript challenges";
pub const challenge_derivation = "sha256(domain) -> eight little-endian u32 -> Blake2sChannel::default().mix_u32s -> CommonLookupElements::draw";
pub const official_challenge_derivation = challenge_derivation ++ "; independent channel replay exposes z and alpha";
pub const challenge_domain_hex = "5354574f5f434149524f5f494e544552414354494f4e5f444941474e4f535449435f4348414c4c454e47455f563100";
pub const lookup_elements_sha256 = "c74885eaf1a19905938559496c6fa73ff21776abc2c5bc578307c1c7f4d7e319";

pub const max_receipt_bytes = 8 * 1024 * 1024;
pub const max_components = 256;
pub const max_columns = 16 * 1024;
pub const max_label_bytes = 128;
pub const max_string_bytes = 512;
pub const max_row_count: u64 = @as(u64, 1) << 32;

const WireAuthority = struct {
    stwo_cairo_revision: []const u8,
    stwo_revision: []const u8,
};

const WireChallenge = struct {
    purpose: []const u8,
    is_proof_transcript: bool,
    warning: []const u8,
    derivation: []const u8,
    domain_hex: []const u8,
    seed_sha256: []const u8,
    z_m31: checkpoint.SecureLimbs,
    alpha_m31: checkpoint.SecureLimbs,
    alpha_powers_m31: []const checkpoint.SecureLimbs,
    lookup_elements_sha256: []const u8,
};

const WireColumn = struct {
    ordinal: u32,
    row_count: u64,
    sha256: []const u8,
};

const WireComponent = struct {
    ordinal: u32,
    label: []const u8,
    claimed_sum_m31: checkpoint.SecureLimbs,
    columns: []const WireColumn,
    accumulator_sha256: []const u8,
};

const WireReceipt = struct {
    schema: []const u8,
    input_sha256: []const u8,
    authority: WireAuthority,
    challenge: WireChallenge,
    components: []const WireComponent,
    final_accumulator_sha256: []const u8,
};

pub const Expected = struct {
    input_sha256: checkpoint.Digest,
    authority: Authority = legacy_authority,
    challenge_derivation: []const u8 = challenge_derivation,
};

pub const Authority = struct {
    stwo_cairo_revision: []const u8,
    stwo_revision: []const u8,
};

pub const legacy_authority = Authority{
    .stwo_cairo_revision = stwo_cairo_revision,
    .stwo_revision = stwo_revision,
};

pub const official_authority = Authority{
    .stwo_cairo_revision = claim_registry.source_revision.stwo_cairo,
    .stwo_revision = claim_registry.source_revision.stwo,
};

pub const Challenge = struct {
    seed_sha256: checkpoint.Digest,
    z_m31: checkpoint.SecureLimbs,
    alpha_m31: checkpoint.SecureLimbs,
    alpha_powers_m31: []const checkpoint.SecureLimbs,
    lookup_elements_sha256: checkpoint.Digest,
};

pub const Loaded = struct {
    allocator: std.mem.Allocator,
    parsed: std.json.Parsed(WireReceipt),
    challenge: Challenge,
    components: []checkpoint.Component,
    columns: []checkpoint.Column,
    final_accumulator: checkpoint.Digest,

    pub fn deinit(self: *Loaded) void {
        self.allocator.free(self.columns);
        self.allocator.free(self.components);
        self.parsed.deinit();
        self.* = undefined;
    }
};

pub const Error = error{
    ReceiptTooLarge,
    InvalidSchema,
    AuthorityMismatch,
    InputMismatch,
    InvalidChallenge,
    InvalidComponentCount,
    InvalidComponentOrdinal,
    InvalidComponentLabel,
    UnknownComponentLabel,
    NonCanonicalComponentOrder,
    NonCanonicalInstancePrefix,
    DuplicateComponent,
    InvalidClaimedSum,
    InvalidColumnCount,
    InvalidColumnOrdinal,
    InvalidRowCount,
    InconsistentRowCount,
    InvalidDigest,
    AccumulatorMismatch,
    ColumnCountOverflow,
};

pub fn readFile(allocator: std.mem.Allocator, path: []const u8, expected: Expected) !Loaded {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const size = (try file.stat()).size;
    if (size == 0 or size > max_receipt_bytes) return Error.ReceiptTooLarge;
    const encoded = try allocator.alloc(u8, @intCast(size));
    defer allocator.free(encoded);
    if (try file.readAll(encoded) != encoded.len) return error.TruncatedReceipt;
    return parse(allocator, encoded, expected);
}

pub fn parse(allocator: std.mem.Allocator, encoded: []const u8, expected: Expected) !Loaded {
    if (encoded.len == 0 or encoded.len > max_receipt_bytes) return Error.ReceiptTooLarge;
    var parsed = try std.json.parseFromSlice(WireReceipt, allocator, encoded, .{
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .max_value_len = max_string_bytes,
    });
    errdefer parsed.deinit();
    const wire = parsed.value;
    if (!std.mem.eql(u8, wire.schema, schema)) return Error.InvalidSchema;
    if (!std.mem.eql(
        u8,
        wire.authority.stwo_cairo_revision,
        expected.authority.stwo_cairo_revision,
    ) or
        !std.mem.eql(u8, wire.authority.stwo_revision, expected.authority.stwo_revision))
        return Error.AuthorityMismatch;
    if (!std.mem.eql(u8, &(try decodeDigest(wire.input_sha256)), &expected.input_sha256))
        return Error.InputMismatch;
    const challenge = try validateChallenge(wire.challenge, expected.challenge_derivation);
    if (wire.components.len == 0 or wire.components.len > max_components)
        return Error.InvalidComponentCount;

    var total_columns: usize = 0;
    for (wire.components) |component| {
        if (component.columns.len == 0 or component.columns.len > max_columns)
            return Error.InvalidColumnCount;
        total_columns = std.math.add(usize, total_columns, component.columns.len) catch
            return Error.ColumnCountOverflow;
        if (total_columns > max_columns) return Error.InvalidColumnCount;
    }
    const components = try allocator.alloc(checkpoint.Component, wire.components.len);
    errdefer allocator.free(components);
    const columns = try allocator.alloc(checkpoint.Column, total_columns);
    errdefer allocator.free(columns);

    var cursor: usize = 0;
    var accumulator = checkpoint.initial_accumulator;
    var previous_enable_slot: ?u8 = null;
    var next_memory_instance: u8 = 0;
    for (wire.components, components, 0..) |wire_component, *component, component_index| {
        if (wire_component.ordinal != component_index) return Error.InvalidComponentOrdinal;
        if (!isCanonicalLabel(wire_component.label)) return Error.InvalidComponentLabel;
        const enable_slot = findEnableSlot(wire_component.label) orelse
            return Error.UnknownComponentLabel;
        if (previous_enable_slot) |previous| {
            if (enable_slot.enable_slot <= previous) return Error.NonCanonicalComponentOrder;
        }
        previous_enable_slot = enable_slot.enable_slot;
        const claim_field = claim_registry.claim_fields[enable_slot.claim_field_index];
        if (std.mem.eql(u8, claim_field.name, "memory_id_to_big")) {
            if (enable_slot.field_slot_index != next_memory_instance)
                return Error.NonCanonicalInstancePrefix;
            next_memory_instance += 1;
        }
        for (wire.components[0..component_index]) |previous| {
            if (std.mem.eql(u8, previous.label, wire_component.label)) return Error.DuplicateComponent;
        }
        checkpoint.validateLimbs(wire_component.claimed_sum_m31) catch return Error.InvalidClaimedSum;
        const component_columns = columns[cursor .. cursor + wire_component.columns.len];
        cursor += wire_component.columns.len;
        var row_count: ?u64 = null;
        for (wire_component.columns, component_columns, 0..) |wire_column, *column, column_index| {
            if (wire_column.ordinal != column_index) return Error.InvalidColumnOrdinal;
            if (wire_column.row_count == 0 or wire_column.row_count > max_row_count or
                !std.math.isPowerOfTwo(wire_column.row_count))
                return Error.InvalidRowCount;
            if (row_count) |expected_rows| {
                if (wire_column.row_count != expected_rows) return Error.InconsistentRowCount;
            } else {
                row_count = wire_column.row_count;
            }
            column.* = .{
                .ordinal = wire_column.ordinal,
                .row_count = wire_column.row_count,
                .sha256 = try decodeDigest(wire_column.sha256),
            };
        }
        accumulator = try checkpoint.extendAccumulator(
            accumulator,
            challenge.lookup_elements_sha256,
            wire_component.ordinal,
            wire_component.label,
            wire_component.claimed_sum_m31,
            component_columns,
        );
        const stated_accumulator = try decodeDigest(wire_component.accumulator_sha256);
        if (!std.mem.eql(u8, &accumulator, &stated_accumulator)) return Error.AccumulatorMismatch;
        component.* = .{
            .ordinal = wire_component.ordinal,
            .label = wire_component.label,
            .claimed_sum_m31 = wire_component.claimed_sum_m31,
            .columns = component_columns,
            .accumulator = accumulator,
        };
    }
    const final_accumulator = try decodeDigest(wire.final_accumulator_sha256);
    if (!std.mem.eql(u8, &accumulator, &final_accumulator)) return Error.AccumulatorMismatch;
    return .{
        .allocator = allocator,
        .parsed = parsed,
        .challenge = challenge,
        .components = components,
        .columns = columns,
        .final_accumulator = final_accumulator,
    };
}

fn validateChallenge(wire: WireChallenge, expected_derivation: []const u8) Error!Challenge {
    if (!std.mem.eql(u8, wire.purpose, challenge_purpose) or wire.is_proof_transcript or
        !std.mem.eql(u8, wire.warning, challenge_warning) or
        !std.mem.eql(u8, wire.derivation, expected_derivation) or
        !std.mem.eql(u8, wire.domain_hex, challenge_domain_hex))
        return Error.InvalidChallenge;

    var expected_seed: checkpoint.Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(checkpoint.challenge_domain, &expected_seed, .{});
    const seed = decodeDigest(wire.seed_sha256) catch return Error.InvalidChallenge;
    if (!std.mem.eql(u8, &seed, &expected_seed)) return Error.InvalidChallenge;
    checkpoint.validateLimbs(wire.z_m31) catch return Error.InvalidChallenge;
    checkpoint.validateLimbs(wire.alpha_m31) catch return Error.InvalidChallenge;
    if (!std.mem.eql(u32, &wire.z_m31, &checkpoint.diagnostic_z) or
        !std.mem.eql(u32, &wire.alpha_m31, &checkpoint.diagnostic_alpha) or
        wire.alpha_powers_m31.len != checkpoint.alpha_power_count)
        return Error.InvalidChallenge;
    const expected_powers = checkpoint.deriveAlphaPowers();
    for (wire.alpha_powers_m31, &expected_powers) |actual, expected| {
        checkpoint.validateLimbs(actual) catch return Error.InvalidChallenge;
        if (!std.mem.eql(u32, &actual, &expected)) return Error.InvalidChallenge;
    }
    if (!std.mem.eql(u8, wire.lookup_elements_sha256, lookup_elements_sha256))
        return Error.InvalidChallenge;
    const stated_lookup_digest = decodeDigest(wire.lookup_elements_sha256) catch
        return Error.InvalidChallenge;
    const computed_lookup_digest = checkpoint.digestLookupElements(
        wire.z_m31,
        wire.alpha_powers_m31,
    ) catch return Error.InvalidChallenge;
    if (!std.mem.eql(u8, &stated_lookup_digest, &computed_lookup_digest))
        return Error.InvalidChallenge;
    return .{
        .seed_sha256 = seed,
        .z_m31 = wire.z_m31,
        .alpha_m31 = wire.alpha_m31,
        .alpha_powers_m31 = wire.alpha_powers_m31,
        .lookup_elements_sha256 = stated_lookup_digest,
    };
}

fn isCanonicalLabel(label: []const u8) bool {
    if (label.len == 0 or label.len > max_label_bytes) return false;
    for (label) |byte| switch (byte) {
        'a'...'z', '0'...'9', '_', '[', ']' => {},
        else => return false,
    };
    return true;
}

fn findEnableSlot(label: []const u8) ?claim_registry.EnableSlot {
    for (claim_registry.enable_slots) |slot| {
        if (std.mem.eql(u8, slot.name, label)) return slot;
    }
    return null;
}

fn decodeDigest(encoded: []const u8) Error!checkpoint.Digest {
    if (encoded.len != 64) return Error.InvalidDigest;
    for (encoded) |byte| switch (byte) {
        '0'...'9', 'a'...'f' => {},
        else => return Error.InvalidDigest,
    };
    var digest: checkpoint.Digest = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded) catch return Error.InvalidDigest;
    return digest;
}

fn testValidReceipt(allocator: std.mem.Allocator) ![]u8 {
    const powers = checkpoint.deriveAlphaPowers();
    const lookup_digest = try checkpoint.digestLookupElements(checkpoint.diagnostic_z, &powers);
    const column_digest = [_]u8{0x33} ** 32;
    const columns = [_]checkpoint.Column{.{
        .ordinal = 0,
        .row_count = 8,
        .sha256 = column_digest,
    }};
    const claimed_sum = checkpoint.SecureLimbs{ 1, 2, 3, 4 };
    const accumulator = try checkpoint.extendAccumulator(
        checkpoint.initial_accumulator,
        lookup_digest,
        0,
        "ret_opcode",
        claimed_sum,
        &columns,
    );
    const input_digest = [_]u8{0x11} ** 32;
    const input_hex = std.fmt.bytesToHex(input_digest, .lower);
    const seed_hex = std.fmt.bytesToHex([_]u8{
        0x61, 0x09, 0x12, 0xca, 0x90, 0x08, 0xcd, 0x5b,
        0x27, 0xa3, 0xf1, 0x01, 0x34, 0x19, 0x22, 0xc7,
        0x4f, 0xf8, 0x79, 0x3f, 0x85, 0xd6, 0x1f, 0xae,
        0x23, 0x8f, 0xb7, 0x3d, 0xf0, 0xfe, 0xa4, 0xc0,
    }, .lower);
    const column_hex = std.fmt.bytesToHex(column_digest, .lower);
    const accumulator_hex = std.fmt.bytesToHex(accumulator, .lower);
    const wire_columns = [_]WireColumn{.{
        .ordinal = 0,
        .row_count = 8,
        .sha256 = &column_hex,
    }};
    const wire_components = [_]WireComponent{.{
        .ordinal = 0,
        .label = "ret_opcode",
        .claimed_sum_m31 = claimed_sum,
        .columns = &wire_columns,
        .accumulator_sha256 = &accumulator_hex,
    }};
    return std.json.Stringify.valueAlloc(allocator, WireReceipt{
        .schema = schema,
        .input_sha256 = &input_hex,
        .authority = .{
            .stwo_cairo_revision = stwo_cairo_revision,
            .stwo_revision = stwo_revision,
        },
        .challenge = .{
            .purpose = challenge_purpose,
            .is_proof_transcript = false,
            .warning = challenge_warning,
            .derivation = challenge_derivation,
            .domain_hex = challenge_domain_hex,
            .seed_sha256 = &seed_hex,
            .z_m31 = checkpoint.diagnostic_z,
            .alpha_m31 = checkpoint.diagnostic_alpha,
            .alpha_powers_m31 = &powers,
            .lookup_elements_sha256 = lookup_elements_sha256,
        },
        .components = &wire_components,
        .final_accumulator_sha256 = &accumulator_hex,
    }, .{});
}

test "interaction receipt authenticates challenge claims and accumulator chain" {
    const encoded = try testValidReceipt(std.testing.allocator);
    defer std.testing.allocator.free(encoded);
    var loaded = try parse(std.testing.allocator, encoded, .{ .input_sha256 = [_]u8{0x11} ** 32 });
    defer loaded.deinit();
    @memset(encoded, 'x');
    try std.testing.expectEqual(@as(usize, 1), loaded.components.len);
    try std.testing.expectEqualStrings("ret_opcode", loaded.components[0].label);
    try std.testing.expectEqual(checkpoint.diagnostic_alpha, loaded.challenge.alpha_m31);
}

test "interaction receipt rejects a forged final accumulator" {
    const encoded = try testValidReceipt(std.testing.allocator);
    defer std.testing.allocator.free(encoded);
    encoded[encoded.len - 3] = if (encoded[encoded.len - 3] == '0') '1' else '0';
    try std.testing.expectError(Error.AccumulatorMismatch, parse(
        std.testing.allocator,
        encoded,
        .{ .input_sha256 = [_]u8{0x11} ** 32 },
    ));
}

test "interaction receipt rejects semantic and structural mutations" {
    var powers = checkpoint.deriveAlphaPowers();
    powers[7][0] +%= 1;
    const malformed_challenge = WireChallenge{
        .purpose = challenge_purpose,
        .is_proof_transcript = false,
        .warning = challenge_warning,
        .derivation = challenge_derivation,
        .domain_hex = challenge_domain_hex,
        .seed_sha256 = "610912ca9008cd5b27a3f101341922c74ff8793f85d61fae238fb73df0fea4c0",
        .z_m31 = checkpoint.diagnostic_z,
        .alpha_m31 = checkpoint.diagnostic_alpha,
        .alpha_powers_m31 = &powers,
        .lookup_elements_sha256 = lookup_elements_sha256,
    };
    try std.testing.expectError(
        Error.InvalidChallenge,
        validateChallenge(malformed_challenge, challenge_derivation),
    );
    try std.testing.expectError(error.DuplicateField, parse(
        std.testing.allocator,
        "{\"schema\":\"x\",\"schema\":\"y\"}",
        .{ .input_sha256 = [_]u8{0} ** 32 },
    ));
    try std.testing.expectError(error.UnknownField, parse(
        std.testing.allocator,
        "{\"unknown\":1}",
        .{ .input_sha256 = [_]u8{0} ** 32 },
    ));
}

test "committed Fib25k interaction receipt authenticates the Rust checkpoint" {
    var input_digest: checkpoint.Digest = undefined;
    _ = try std.fmt.hexToBytes(
        &input_digest,
        "3e5f076f30efbf9f295803ac7198750879267ba78d1e98c820742de08255e366",
    );
    var expected_accumulator: checkpoint.Digest = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_accumulator,
        "536c927621cfc55712d7650ad774d2bb8a7c23d4d0c64f2989c6350366190d5a",
    );
    var loaded = try readFile(
        std.testing.allocator,
        "vectors/cairo/checkpoints/fib_25000_interaction_trace.json",
        .{ .input_sha256 = input_digest },
    );
    defer loaded.deinit();

    var column_count: usize = 0;
    for (loaded.components) |component| column_count += component.columns.len;
    try std.testing.expectEqual(@as(usize, 30), loaded.components.len);
    try std.testing.expectEqual(@as(usize, 324), column_count);
    try std.testing.expectEqualStrings("add_opcode", loaded.components[0].label);
    try std.testing.expectEqualStrings("verify_bitwise_xor_9", loaded.components[29].label);
    try std.testing.expectEqual(expected_accumulator, loaded.final_accumulator);
}

test "official all-opcodes interaction receipt authenticates every component" {
    var input_digest: checkpoint.Digest = undefined;
    _ = try std.fmt.hexToBytes(
        &input_digest,
        "7f94bd5dcf32e7dd69a8a47f42d41830b4fdd3b75846ef9f7694f3164117fcd6",
    );
    var expected_accumulator: checkpoint.Digest = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_accumulator,
        "74386dacef4d5c36da2b02a570e894ed2a8f050f6d32d7e1228c378b3c7d0a60",
    );
    var loaded = try readFile(
        std.testing.allocator,
        "vectors/cairo/official/all_opcodes.interaction_trace_checkpoint.json",
        .{
            .input_sha256 = input_digest,
            .authority = official_authority,
            .challenge_derivation = official_challenge_derivation,
        },
    );
    defer loaded.deinit();

    var column_count: usize = 0;
    for (loaded.components) |component| column_count += component.columns.len;
    try std.testing.expectEqual(@as(usize, 46), loaded.components.len);
    try std.testing.expectEqual(@as(usize, 1032), column_count);
    try std.testing.expectEqualStrings("add_opcode", loaded.components[0].label);
    try std.testing.expectEqualStrings("verify_bitwise_xor_9", loaded.components[45].label);
    try std.testing.expectEqual(expected_accumulator, loaded.final_accumulator);
}

test "official all-builtins interaction receipt authenticates every component" {
    var input_digest: checkpoint.Digest = undefined;
    _ = try std.fmt.hexToBytes(
        &input_digest,
        "d7e902c3b8584a79b466ef0c384208ad95ea75340f0b0590ea0ba765c54acac1",
    );
    var expected_accumulator: checkpoint.Digest = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_accumulator,
        "c62b56454feb25f110bb16dcebe583aa0adfa42e042cfefcea0827192fc1f37e",
    );
    var loaded = try readFile(
        std.testing.allocator,
        "vectors/cairo/official/all_builtins.interaction_trace_checkpoint.json",
        .{
            .input_sha256 = input_digest,
            .authority = official_authority,
            .challenge_derivation = official_challenge_derivation,
        },
    );
    defer loaded.deinit();

    var column_count: usize = 0;
    for (loaded.components) |component| column_count += component.columns.len;
    try std.testing.expectEqual(@as(usize, 48), loaded.components.len);
    try std.testing.expectEqual(@as(usize, 2220), column_count);
    try std.testing.expectEqualStrings("add_opcode_small", loaded.components[0].label);
    try std.testing.expectEqualStrings("verify_bitwise_xor_9", loaded.components[47].label);
    try std.testing.expectEqual(expected_accumulator, loaded.final_accumulator);
}

//! Private value-comparison and transport-identity helpers for the schema-3
//! role-aware I/O witness. No helper here validates or mints an authority.

const std = @import("std");

pub fn claimsEql(left: anytype, right: @TypeOf(left)) bool {
    return left.memory_access.eql(right.memory_access) and
        left.program_access.eql(right.program_access);
}

pub fn publicSumRowEql(left: anytype, right: @TypeOf(left)) bool {
    const left_values = left.values();
    const right_values = right.values();
    for (left_values, right_values) |actual, expected|
        if (!actual.eql(expected)) return false;
    return true;
}

pub fn callsEql(left: anytype, right: @TypeOf(left)) bool {
    if (left.len != right.len) return false;
    for (left, right) |actual, expected|
        if (!std.meta.eql(actual, expected)) return false;
    return true;
}

pub fn splitU32(value: u32) [2]u32 {
    return .{ value & 0xffff, value >> 16 };
}

pub fn joinU32(value: [2]u32) u32 {
    return value[0] | (value[1] << 16);
}

pub fn programIdentity(
    domain: []const u8,
    format_version: u16,
    schema_version: u16,
    parameters: []const u32,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    hashInt(&hash, u16, format_version);
    hashInt(&hash, u16, schema_version);
    for (parameters) |value| hashInt(&hash, u32, value);
    return hash.finalResult();
}

pub fn liveCapacity(count: u32) !u32 {
    return std.math.ceilPowerOfTwo(u32, @max(count, 1)) catch
        error.ArithmeticOverflow;
}

pub fn validateCapacity(
    active: u32,
    capacity: u32,
    modulus: u32,
    header_words: usize,
    tuple_words: usize,
) !void {
    if (capacity == 0 or capacity >= modulus or active > capacity or
        !std.math.isPowerOfTwo(capacity))
    {
        return error.RoleAwareIoWitnessMismatchV4;
    }
    _ = try canonicalWordCount(capacity, header_words, tuple_words);
}

pub fn canonicalWordCount(
    capacity: u32,
    header_words: usize,
    tuple_words: usize,
) !usize {
    const tuples = std.math.mul(
        usize,
        capacity,
        tuple_words,
    ) catch return error.ArithmeticOverflow;
    return std.math.add(usize, header_words, tuples) catch
        error.ArithmeticOverflow;
}

pub fn witnessIdentity(
    value: anytype,
    domain: []const u8,
    format_version: u16,
    schema_version: u16,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    hashInt(&hash, u16, format_version);
    hashInt(&hash, u16, schema_version);
    hashInt(&hash, u32, value.active_tuple_count);
    hashInt(&hash, u32, value.padded_tuple_capacity);
    hashInt(&hash, u64, value.canonical_words.len);
    for (value.canonical_words) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u64, value.poseidon_calls.len);
    for (value.poseidon_calls) |call| {
        for (call.input) |word| hashInt(&hash, u32, word);
        hashInt(&hash, u8, @intFromBool(call.wide));
        hashInt(&hash, u8, @intFromBool(call.io));
        hashInt(&hash, u8, @intFromBool(call.narrow_output != null));
        if (call.narrow_output) |word| hashInt(&hash, u32, word);
    }
    for (value.commitment) |word| hashInt(&hash, u32, word);
    hashQm31(&hash, value.claims.memory_access);
    hashQm31(&hash, value.claims.program_access);
    for (value.public_sum_row.values()) |sum| hashQm31(&hash, sum);
    return hash.finalResult();
}

fn hashQm31(hash: anytype, value: anytype) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

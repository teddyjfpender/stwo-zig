//! Read-only parity validation for resident Cairo Metal quotient inputs.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const composition_bundle = @import("stwo_cairo_frontend").witness.composition_bundle;
const geometry = @import("stwo_cairo_frontend").witness.quotient_geometry;

const fixture_magic = "STWZQI01";
const fixture_version: u32 = 1;

pub const ReferenceValidation = struct {
    quotient_digest: [32]u8,
    payload_bytes: u64,
};
/// Validates the immutable quotient-input fixture against already-populated
/// resident inputs. This function never writes to the arena. The fixture is a
/// parity oracle only; malformed, non-canonical, truncated, or trailing data
/// fails closed before the quotient bottom executes.
pub fn validateReferenceFixture(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    bundle: composition_bundle.Bundle,
    partials: []const arena_plan.Binding,
    sample_points: arena_plan.Binding,
    first_linear_terms: arena_plan.Binding,
    subdomain_values: arena_plan.Binding,
    quotient_values: arena_plan.Binding,
    path: []const u8,
) !ReferenceValidation {
    if (partials.len == 0 or partials.len % 4 != 0) return error.InvalidQuotientReference;
    const lifting_log_size = geometry.validatedLiftingLogSize(bundle.max_evaluation_log_size) catch
        return error.InvalidQuotientReference;
    const expected_subdomain_log = lifting_log_size - 1;
    const sample_count = partials.len / 4;
    if (sample_points.size_bytes != @as(u64, sample_count) * 8 * 4 or
        first_linear_terms.size_bytes != @as(u64, sample_count) * 4 * 4 or
        subdomain_values.size_bytes == 0 or subdomain_values.size_bytes % 16 != 0 or
        quotient_values.size_bytes == 0 or quotient_values.size_bytes % 16 != 0)
        return error.InvalidQuotientReference;

    const partial_bytes = try allocator.alloc([]const u8, partials.len);
    defer allocator.free(partial_bytes);
    for (partials, partial_bytes) |partial, *bytes| {
        if (partial.size_bytes == 0 or partial.size_bytes % 4 != 0 or
            !std.math.isPowerOfTwo(partial.size_bytes / 4))
            return error.InvalidQuotientReference;
        bytes.* = try resident_arena.bytes(partial);
    }
    const sample_bytes = try resident_arena.bytes(sample_points);
    const linear_bytes = try resident_arena.bytes(first_linear_terms);
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var buffer: [1 << 20]u8 = undefined;
    var file_reader = file.reader(&buffer);
    const reader = &file_reader.interface;
    const actual_subdomain_log = std.math.log2_int(u64, subdomain_values.size_bytes / 16);
    const actual_quotient_log = std.math.log2_int(u64, quotient_values.size_bytes / 16);
    try validateReferenceLogs(
        expected_subdomain_log,
        lifting_log_size,
        actual_subdomain_log,
        actual_quotient_log,
    );
    return validateReferenceReader(
        allocator,
        reader,
        partial_bytes,
        sample_bytes,
        linear_bytes,
        expected_subdomain_log,
        lifting_log_size,
    );
}

fn validateReferenceLogs(
    expected_subdomain_log: u32,
    expected_quotient_log: u32,
    actual_subdomain_log: u32,
    actual_quotient_log: u32,
) !void {
    if (actual_subdomain_log != expected_subdomain_log or
        actual_quotient_log != expected_quotient_log or
        expected_quotient_log != expected_subdomain_log + 1)
        return error.InvalidQuotientReference;
}

fn validateReferenceReader(
    allocator: std.mem.Allocator,
    reader: anytype,
    partials: []const []const u8,
    sample_points: []const u8,
    first_linear_terms: []const u8,
    expected_subdomain_log: u32,
    expected_quotient_log: u32,
) !ReferenceValidation {
    if (partials.len == 0 or partials.len % 4 != 0) return error.InvalidQuotientReference;
    const sample_count = partials.len / 4;
    const expected_sample_bytes = std.math.mul(usize, sample_count, 8 * 4) catch
        return error.InvalidQuotientReference;
    const expected_linear_bytes = std.math.mul(usize, sample_count, 4 * 4) catch
        return error.InvalidQuotientReference;
    if (sample_count > std.math.maxInt(u32) or
        sample_points.len != expected_sample_bytes or
        first_linear_terms.len != expected_linear_bytes or
        expected_subdomain_log >= 63 or expected_quotient_log >= 63 or
        expected_quotient_log <= expected_subdomain_log)
        return error.InvalidQuotientReference;
    if (!std.mem.eql(u8, try reader.takeArray(8), fixture_magic) or
        try reader.takeInt(u32, .little) != fixture_version or
        try reader.takeInt(u32, .little) != sample_count or
        try reader.takeInt(u32, .little) != expected_subdomain_log or
        try reader.takeInt(u32, .little) != expected_quotient_log)
        return error.InvalidQuotientReference;
    var digest: [32]u8 = undefined;
    try reader.readSliceAll(&digest);

    const populated = try allocator.alloc(bool, sample_count);
    defer allocator.free(populated);
    @memset(populated, false);
    var payload_bytes: u64 = 0;
    for (0..sample_count) |fixture_index| {
        const partial_log = try reader.takeInt(u32, .little);
        if (partial_log > expected_subdomain_log) return error.InvalidQuotientReference;
        const partial_byte_len = try checkedPartialByteLength(partial_log);
        var target: ?usize = null;
        for (0..sample_count) |candidate| {
            if (!populated[candidate] and partials[candidate * 4].len == partial_byte_len) {
                target = candidate;
                break;
            }
        }
        const sample = target orelse return error.InvalidQuotientReference;
        populated[sample] = true;
        compareCanonical(
            reader,
            sample_points[sample * 8 * 4 ..][0 .. 8 * 4],
            &payload_bytes,
        ) catch |err| {
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("quotient_reference mismatch=sample_point fixture_index={} target={} log={}\n", .{ fixture_index, sample, partial_log });
            return err;
        };
        compareCanonical(
            reader,
            first_linear_terms[sample * 4 * 4 ..][0 .. 4 * 4],
            &payload_bytes,
        ) catch |err| {
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                std.debug.print("quotient_reference mismatch=linear_term fixture_index={} target={} log={}\n", .{ fixture_index, sample, partial_log });
            return err;
        };
        for (0..4) |coordinate| {
            const partial = partials[sample * 4 + coordinate];
            if (partial.len != partial_byte_len) return error.InvalidQuotientReference;
            compareCanonical(reader, partial, &payload_bytes) catch |err| {
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
                    std.debug.print(
                        "quotient_reference mismatch=partial fixture_index={} target={} log={} coordinate={}\n",
                        .{ fixture_index, sample, partial_log, coordinate },
                    );
                return err;
            };
        }
    }
    for (populated) |value| if (!value) return error.InvalidQuotientReference;
    var trailing: [1]u8 = undefined;
    if (try reader.readSliceShort(&trailing) != 0) return error.InvalidQuotientReference;
    return .{ .quotient_digest = digest, .payload_bytes = payload_bytes };
}

fn compareCanonical(reader: anytype, actual: []const u8, total: *u64) !void {
    if (actual.len % 4 != 0) return error.InvalidQuotientReference;
    var scratch: [64 * 1024]u8 align(4) = undefined;
    var cursor: usize = 0;
    while (cursor < actual.len) {
        const len = @min(scratch.len, actual.len - cursor);
        const expected = scratch[0..len];
        try reader.readSliceAll(expected);
        try geometry.canonicalWords(std.mem.bytesAsSlice(u32, expected));
        if (!std.mem.eql(u8, expected, actual[cursor .. cursor + len])) {
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) {
                const expected_words = std.mem.bytesAsSlice(u32, expected);
                const actual_bytes: []align(4) const u8 = @alignCast(actual[cursor .. cursor + len]);
                const actual_words = std.mem.bytesAsSlice(u32, actual_bytes);
                var mismatch: usize = 0;
                while (mismatch < expected_words.len and expected_words[mismatch] == actual_words[mismatch]) : (mismatch += 1) {}
                std.debug.print(
                    "quotient_reference first_word={} expected={} actual={} chunk_word_count={}\n",
                    .{ cursor / 4 + mismatch, expected_words[mismatch], actual_words[mismatch], expected_words.len },
                );
            }
            return error.QuotientReferenceMismatch;
        }
        cursor += len;
        total.* = std.math.add(u64, total.*, len) catch return error.InvalidQuotientReference;
    }
}

fn checkedPartialByteLength(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize) - 2) return error.InvalidQuotientReference;
    return @as(usize, 1) << @intCast(log_size + 2);
}

const SliceReader = struct {
    bytes: []const u8,
    cursor: usize = 0,

    fn takeArray(self: *SliceReader, count: usize) ![]const u8 {
        const end = std.math.add(usize, self.cursor, count) catch return error.EndOfStream;
        if (end > self.bytes.len) return error.EndOfStream;
        defer self.cursor = end;
        return self.bytes[self.cursor..end];
    }

    fn takeInt(self: *SliceReader, comptime T: type, endian: std.builtin.Endian) !T {
        const bytes = try self.takeArray(@sizeOf(T));
        return std.mem.readInt(T, bytes[0..@sizeOf(T)], endian);
    }

    fn readSliceAll(self: *SliceReader, destination: []u8) !void {
        @memcpy(destination, try self.takeArray(destination.len));
    }

    fn readSliceShort(self: *SliceReader, destination: []u8) !usize {
        const count = @min(destination.len, self.bytes.len - self.cursor);
        @memcpy(destination[0..count], self.bytes[self.cursor .. self.cursor + count]);
        self.cursor += count;
        return count;
    }
};
test "Cairo Metal quotient reference supports lifting logs 24 and 25" {
    try std.testing.expectEqual(@as(u32, 24), try geometry.validatedLiftingLogSize(24));
    try std.testing.expectEqual(@as(u32, 25), try geometry.validatedLiftingLogSize(25));
    try validateReferenceLogs(23, 24, 23, 24);
    try validateReferenceLogs(24, 25, 24, 25);
    try std.testing.expectError(
        error.InvalidQuotientReference,
        validateReferenceLogs(24, 25, 23, 24),
    );
    try std.testing.expectError(error.InvalidQuotientInputShape, geometry.validatedLiftingLogSize(3));
}

test "Cairo Metal quotient reference validates without restoring resident inputs" {
    const allocator = std.testing.allocator;
    const sample_words = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const linear_words = [_]u32{ 21, 22, 23, 24, 25, 26, 27, 28 };
    const p00 = [_]u32{ 31, 32, 33, 34 };
    const p01 = [_]u32{ 35, 36, 37, 38 };
    const p02 = [_]u32{ 39, 40, 41, 42 };
    const p03 = [_]u32{ 43, 44, 45, 46 };
    const p10 = [_]u32{ 51, 52 };
    const p11 = [_]u32{ 53, 54 };
    const p12 = [_]u32{ 55, 56 };
    const p13 = [_]u32{ 57, 58 };
    const partials = [_][]const u8{
        std.mem.sliceAsBytes(p00[0..]),
        std.mem.sliceAsBytes(p01[0..]),
        std.mem.sliceAsBytes(p02[0..]),
        std.mem.sliceAsBytes(p03[0..]),
        std.mem.sliceAsBytes(p10[0..]),
        std.mem.sliceAsBytes(p11[0..]),
        std.mem.sliceAsBytes(p12[0..]),
        std.mem.sliceAsBytes(p13[0..]),
    };

    var encoded = std.ArrayList(u8).empty;
    defer encoded.deinit(allocator);
    const writer = encoded.writer(allocator);
    try writer.writeAll(fixture_magic);
    try writer.writeInt(u32, fixture_version, .little);
    try writer.writeInt(u32, 2, .little);
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u32, 4, .little);
    try writer.writeAll(&[_]u8{0xa5} ** 32);
    try writer.writeInt(u32, 2, .little);
    try writer.writeAll(std.mem.sliceAsBytes(sample_words[0..8]));
    try writer.writeAll(std.mem.sliceAsBytes(linear_words[0..4]));
    for (partials[0..4]) |partial| try writer.writeAll(partial);
    try writer.writeInt(u32, 1, .little);
    try writer.writeAll(std.mem.sliceAsBytes(sample_words[8..16]));
    try writer.writeAll(std.mem.sliceAsBytes(linear_words[4..8]));
    for (partials[4..8]) |partial| try writer.writeAll(partial);

    var reader = SliceReader{ .bytes = encoded.items };
    const validation = try validateReferenceReader(
        allocator,
        &reader,
        &partials,
        std.mem.sliceAsBytes(sample_words[0..]),
        std.mem.sliceAsBytes(linear_words[0..]),
        3,
        4,
    );
    try std.testing.expectEqual(@as(u64, 192), validation.payload_bytes);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xa5} ** 32, &validation.quotient_digest);

    const mutated = try allocator.dupe(u8, encoded.items);
    defer allocator.free(mutated);
    std.mem.writeInt(u32, mutated[60..64], 99, .little);
    reader = .{ .bytes = mutated };
    try std.testing.expectError(
        error.QuotientReferenceMismatch,
        validateReferenceReader(
            allocator,
            &reader,
            &partials,
            std.mem.sliceAsBytes(sample_words[0..]),
            std.mem.sliceAsBytes(linear_words[0..]),
            3,
            4,
        ),
    );
    std.mem.writeInt(u32, mutated[60..64], geometry.m31_prime, .little);
    reader = .{ .bytes = mutated };
    try std.testing.expectError(
        error.NonCanonicalQuotientReference,
        validateReferenceReader(
            allocator,
            &reader,
            &partials,
            std.mem.sliceAsBytes(sample_words[0..]),
            std.mem.sliceAsBytes(linear_words[0..]),
            3,
            4,
        ),
    );
    std.mem.writeInt(u32, mutated[56..60], 63, .little);
    reader = .{ .bytes = mutated };
    try std.testing.expectError(
        error.InvalidQuotientReference,
        validateReferenceReader(
            allocator,
            &reader,
            &partials,
            std.mem.sliceAsBytes(sample_words[0..]),
            std.mem.sliceAsBytes(linear_words[0..]),
            3,
            4,
        ),
    );
}

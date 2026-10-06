//! Versioned row35 counter for the 24 authenticated byte requests introduced
//! by the eight canonical ProgramV2 wire-word rows. Native V2 and V4 remain
//! unchanged. The actual counter batch is regenerated from all requests.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const legacy = @import("segment_leaf_wrapper_range_provider_direct_v4.zig");
const arithmetic = @import("air/ethereum_leaf_link_arithmetic_v1.zig");
const program = @import("air/transcript_program_v2_field_bridge_v6.zig");
const bridge = @import("air/range_check_8_8_bridge.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const WIRE_ROW_COUNT: usize = 8;
pub const REQUESTS_PER_WIRE: usize = 3;
pub const WIRE_REQUEST_COUNT: u32 = WIRE_ROW_COUNT * REQUESTS_PER_WIRE;

pub const Provider = struct {
    legacy_provider: legacy.Provider,
    wire_requests: u32,

    pub fn init(
        allocator: std.mem.Allocator,
        native: *const bridge.PreparedBatch,
        arithmetic_rows: *const [16]arithmetic.Row,
        wire_rows: *const [WIRE_ROW_COUNT]program.Row,
        expected_words: []const M31,
    ) !Provider {
        if (expected_words.len != WIRE_ROW_COUNT) return error.InvalidV7WireRangeSource;
        var prior = try legacy.Provider.init(allocator, native, arithmetic_rows);
        errdefer prior.deinit();
        var definition = try program.build(allocator);
        defer definition.deinit();
        const authenticated = try program.authenticate(&definition);
        const values = try allocator.dupe(M31, prior.batch.counter.values);
        defer allocator.free(values);
        var request_count: u32 = 0;
        for (wire_rows, expected_words, 0..) |row, expected, index| {
            if (!std.meta.eql(row, program.logicalRow(expected, 1, @intCast(10 + index))))
                return error.InvalidV7WireRangeSource;
            var next_ordinal: u8 = 4;
            for (authenticated.preparedEntries(row)) |entry| {
                if (entry.domain != .range_check_8_8) continue;
                if (entry.ordinal != next_ordinal or entry.role != .request or
                    entry.arity != 2 or !entry.numerator.eql(QM31.one().neg()))
                    return error.InvalidV7WireRangeSource;
                const low = try canonicalByte(entry.values[0]);
                const high = try canonicalByte(entry.values[1]);
                values[@as(usize, low) | (@as(usize, high) << 8)] =
                    values[@as(usize, low) | (@as(usize, high) << 8)].sub(M31.one());
                next_ordinal += 1;
                request_count += 1;
            }
            if (next_ordinal != 7) return error.IncompleteV7WireRangeSource;
        }
        if (request_count != WIRE_REQUEST_COUNT) return error.IncompleteV7WireRangeSource;
        const counter = counter_mod.Counter{ .kind = bridge.TABLE_KIND, .values = values };
        const replacement = try bridge.PreparedBatch.init(allocator, &counter);
        prior.batch.deinit();
        prior.batch = replacement;
        prior.appended_requests = try std.math.add(u32, prior.appended_requests, request_count);
        return .{ .legacy_provider = prior, .wire_requests = request_count };
    }

    pub fn deinit(self: *Provider) void {
        self.legacy_provider.deinit();
        self.* = undefined;
    }
};

fn canonicalByte(value: QM31) !u8 {
    const limbs = value.toM31Array();
    if (!limbs[1].isZero() or !limbs[2].isZero() or !limbs[3].isZero() or limbs[0].toU32() > 255)
        return error.InvalidV7WireRangeSource;
    return @intCast(limbs[0].toU32());
}

test "V7 row35 adds exactly 24 authenticated wire byte requests" {
    const allocator = std.testing.allocator;
    var counter = try counter_mod.Counter.init(allocator, bridge.TABLE_KIND);
    defer counter.deinit(allocator);
    var native = try bridge.PreparedBatch.init(allocator, &counter);
    defer native.deinit();
    const arithmetic_witness = @import("air/ethereum_leaf_link_arithmetic_witness_v1.zig");
    var arithmetic_rows = [_]arithmetic.Row{[_]M31{M31.zero()} ** arithmetic.LOGICAL_INPUT_COUNT} ** 16;
    arithmetic_rows[0] = try arithmetic_witness.logicalRow(.entry_root, 7, false, 0, 0);
    arithmetic_rows[1] = try arithmetic_witness.logicalRow(.exit_root, 9, false, 0, 0);
    arithmetic_rows[2] = try arithmetic_witness.logicalRow(.completion, 0, true, 0, 0);
    arithmetic_rows[3] = try arithmetic_witness.logicalRow(.position, 0, false, 100, 11);
    var wire_words: [WIRE_ROW_COUNT]M31 = undefined;
    var wire_rows: [WIRE_ROW_COUNT]program.Row = undefined;
    for (&wire_words, &wire_rows, 0..) |*word, *row, index| {
        word.* = M31.fromCanonical(@intCast(0x1234_0000 + index * 101));
        row.* = program.logicalRow(word.*, 1, @intCast(10 + index));
    }
    var baseline = try legacy.Provider.init(allocator, &native, &arithmetic_rows);
    defer baseline.deinit();
    var provider = try Provider.init(allocator, &native, &arithmetic_rows, &wire_rows, &wire_words);
    defer provider.deinit();
    try std.testing.expectEqual(WIRE_REQUEST_COUNT, provider.wire_requests);
    try std.testing.expectEqual(baseline.appended_requests + WIRE_REQUEST_COUNT, provider.legacy_provider.appended_requests);
    const low_byte = wire_rows[0][3].toU32();
    const high_byte = wire_rows[0][4].toU32();
    const at = @as(usize, low_byte) | (@as(usize, high_byte) << 8);
    try std.testing.expect(!provider.legacy_provider.batch.counter.values[at].isZero());
    wire_rows[0][11] = M31.fromCanonical(19);
    try std.testing.expectError(error.InvalidV7WireRangeSource, Provider.init(allocator, &native, &arithmetic_rows, &wire_rows, &wire_words));
    wire_rows[0] = program.logicalRow(wire_words[0], 1, 10);
    wire_rows[0][8] = M31.fromCanonical(256);
    try std.testing.expectError(error.InvalidV7WireRangeSource, Provider.init(allocator, &native, &arithmetic_rows, &wire_rows, &wire_words));
}

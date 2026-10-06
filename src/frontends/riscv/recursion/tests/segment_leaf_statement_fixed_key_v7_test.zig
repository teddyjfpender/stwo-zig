//! Regression: padded row-36 geometry does not determine its fixed columns.
//!
//! SegmentV2 has a 652-word fixed header followed by variable retained
//! sections. V7 therefore must not install the V6 Statement source's four
//! preprocessed columns from log geometry alone. A replacement AIR needs
//! proof-visible active/scope/index and fan-out multiplicity, constraints for
//! the canonical wire-then-context prefix, and exact links to verifier-owned
//! local/link consumers and the native authenticated statement values.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const air = @import("../air/segment_leaf_statement_source_direct_v6.zig");
const native = @import("../segment_leaf_outer_air_v2.zig").Statement;
const boundary = @import("../segment_leaf_statement_contract_v2.zig");
const link = @import("../ethereum_leaf_link_program_v3.zig");
const child = @import("../ethereum_leaf_child_field_program_v1.zig");
const layout = @import("../segment_statement_v2_transcript_layout.zig");

test "row36 exact fixed columns differ for wire lengths with identical padded geometry" {
    const allocator = std.testing.allocator;
    const fixture = @import("../tests/ethereum_leaf_child_field_test.zig");
    const empty = try layout.Layout.init(.{ 0, 0, 0, 0 });
    const retained = try layout.Layout.init(.{ 1, 0, 0, 0 });
    try std.testing.expectEqual(@as(usize, 664), empty.wordCount());
    try std.testing.expectEqual(@as(usize, 668), retained.wordCount());
    var program = try link.ProgramV3.init(allocator);
    defer program.deinit();
    var local = try child.ProgramV1.initWithNativeProgramBridge(allocator, &fixture.components, &fixture.infra);
    defer local.deinit();
    var first = try schedule(allocator, &program, &local, empty.wordCount(), 17);
    defer first.deinit();
    var same_shape_new_value = try schedule(allocator, &program, &local, empty.wordCount(), 23);
    defer same_shape_new_value.deinit();
    var longer = try schedule(allocator, &program, &local, retained.wordCount(), 17);
    defer longer.deinit();

    const first_capacity = try std.math.ceilPowerOfTwo(usize, first.rows.len);
    const longer_capacity = try std.math.ceilPowerOfTwo(usize, longer.rows.len);
    try std.testing.expectEqual(@as(usize, 1024), first_capacity);
    try std.testing.expectEqual(first_capacity, longer_capacity);
    try std.testing.expectEqualDeep(first.id, same_shape_new_value.id);
    try std.testing.expect(!first.rows[0][0].eql(same_shape_new_value.rows[0][0]));
    try std.testing.expect(!std.mem.eql(u8, &first.id, &longer.id));
    // At logical row 664, the first schedule starts the context; the second
    // still has a wire word. Their committed row is identical at log 10.
    try std.testing.expectEqual(boundary.CONTEXT_SCOPE, first.rows[empty.wordCount()][3].toU32());
    try std.testing.expectEqual(boundary.WIRE_SCOPE, longer.rows[empty.wordCount()][3].toU32());
}

fn schedule(
    allocator: std.mem.Allocator,
    program: *const link.ProgramV3,
    local: *const child.ProgramV1,
    wire_words: usize,
    value: u32,
) !air.Schedule {
    const old = try allocator.alloc(native.Row, wire_words + boundary.CONTEXT_WORD_COUNT);
    defer allocator.free(old);
    for (old, 0..) |*row, index| {
        const wire = index < wire_words;
        row.* = native.logicalRow(
            M31.fromCanonical(value),
            M31.one(),
            M31.fromCanonical(if (wire) boundary.WIRE_SCOPE else boundary.CONTEXT_SCOPE),
            M31.fromCanonical(@intCast(if (wire) index else index - wire_words)),
        );
    }
    return air.Schedule.init(allocator, program, local, old);
}

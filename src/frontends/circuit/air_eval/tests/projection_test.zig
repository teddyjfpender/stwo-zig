//! The committed compiled-AIR projection decodes, carries the pinned header,
//! and is rejected when corrupted.

const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const fixture = @import("../../testing/fixture_json.zig");

const projection = circuit.air_eval.projection;
const projection_path = "vectors/circuit/official/compiled_air_constraints_v1.bin";

fn readProjection(allocator: std.mem.Allocator) ![]u8 {
    return std.fs.cwd().readFileAlloc(allocator, projection_path, 4 << 20);
}

test "projection header pins the revision, constants and both slot orders" {
    const gpa = std.testing.allocator;
    const bytes = try readProjection(gpa);
    defer gpa.free(bytes);
    var parsed = try projection.parse(gpa, bytes);
    defer parsed.deinit();

    try std.testing.expectEqualStrings(fixture.proving_revision, parsed.str(parsed.revision));
    try std.testing.expectEqual(@as(?u32, 1 << 30), parsed.constant("LARGE_MEMORY_VALUE_ID_BASE"));
    try std.testing.expectEqual(@as(?u32, 25), parsed.constant("MAX_SEQUENCE_LOG_SIZE"));
    try std.testing.expectEqual(@as(?u32, 16), parsed.constant("MEMORY_ADDRESS_TO_ID_SPLIT"));

    const cairo = parsed.source("cairo").?;
    try std.testing.expectEqual(@as(usize, 83), cairo.slots.len);
    try std.testing.expectEqual(@as(usize, 164), cairo.functions.len);
    try std.testing.expectEqual(@as(usize, 3), cairo.hand_written.len);
    const circuit_source = parsed.source("circuit").?;
    const expected_circuit_slots = [_][]const u8{
        "eq",                   "qm31_ops",             "triple_xor",            "m_31_to_u_32",
        "blake_g_gate",         "verify_bitwise_xor_8", "verify_bitwise_xor_12", "verify_bitwise_xor_4",
        "verify_bitwise_xor_7", "verify_bitwise_xor_9", "range_check_16",
    };
    const slots = parsed.nameList(circuit_source.slots);
    try std.testing.expectEqual(expected_circuit_slots.len, slots.len);
    for (expected_circuit_slots, slots) |name, slot| try std.testing.expectEqualStrings(name, parsed.str(slot));
    try std.testing.expectEqual(@as(usize, 22), circuit_source.functions.len);
}

test "projection rejects a corrupted record, bad magic and truncation" {
    const gpa = std.testing.allocator;
    const bytes = try readProjection(gpa);
    defer gpa.free(bytes);

    const corrupted = try gpa.dupe(u8, bytes);
    defer gpa.free(corrupted);
    // A string-table entry that a function record names: the record bytes
    // are unchanged, but its canonical form (strings inline) is not.
    const name = std.mem.indexOf(u8, corrupted, "add_opcode").?;
    corrupted[name] = 'b';
    try std.testing.expectError(error.RecordDigestMismatch, projection.parse(gpa, corrupted));
    corrupted[name] = 'a';

    // The last byte belongs to the final function record.
    corrupted[corrupted.len - 1] ^= 1;
    try std.testing.expect(std.meta.isError(projection.parse(gpa, corrupted)));
    corrupted[corrupted.len - 1] ^= 1;

    corrupted[0] = 'X';
    try std.testing.expectError(error.BadMagic, projection.parse(gpa, corrupted));

    try std.testing.expectError(error.Truncated, projection.parse(gpa, bytes[0 .. bytes.len - 1]));

    const extended = try gpa.alloc(u8, bytes.len + 1);
    defer gpa.free(extended);
    @memcpy(extended[0..bytes.len], bytes);
    extended[bytes.len] = 0;
    try std.testing.expectError(error.TrailingBytes, projection.parse(gpa, extended));
}

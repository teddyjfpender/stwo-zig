//! Witness-free ABI sizes used by the retained-source lifetime inventory.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const Core = @import("../word16_execution/sources.zig").Source;
const Native = @import("../word16_execution/prepared.zig").Prepared;
fn elem(comptime T: type, comptime field: []const u8) usize {
    return @sizeOf(@typeInfo(@FieldType(T, field)).pointer.child);
}
test "OP retained source layout manifest uses compiled owner ABI sizes only" {
    const path = std.posix.getenv("STWO_OP_SOURCE_LAYOUT_OUTPUT") orelse return error.SkipZigTest;
    const V = A.memory.load_store_v2.source.Source;
    const D = A.memory.load_store_dword.source.Source;
    const Bulk = A.crypto.bulk_memory.source.Source;
    const Secp = A.crypto.secp256k1.word16_bridge.source;
    const Sponge = A.crypto.keccak_sponge.source;
    const sizes = .{
        .cpu_metadata = elem(@FieldType(Core, "cpu"), "metadata"),
        .alu_metadata = elem(@FieldType(Core, "alu"), "metadata"),
        .binary_metadata = elem(@FieldType(Core, "binary"), "metadata"),
        .shift_metadata = elem(@FieldType(Core, "shift"), "metadata"),
        .division_metadata = elem(@FieldType(Core, "division"), "metadata"),
        .multiplication_metadata = elem(@FieldType(Core, "multiplication"), "request_metadata"),
        .ls32_metadata = elem(V, "metadata"),
        .ls64_metadata = elem(D, "metadata"),
        .boundary_metadata = elem(@FieldType(@FieldType(Core, "memory"), "initial"), "metadata"),
        .alu_native_fact = elem(@FieldType(Native, "alu"), "facts"),
        .binary_native_fact = elem(@FieldType(Native, "binary"), "facts"),
        .shift_native_fact = elem(Native, "shift"),
        .division_native_fact = elem(Native, "division"),
        .multiplication_native_fact = elem(Native, "multiplication"),
        .jalr_fact = elem(@FieldType(Core, "jalr"), "facts"),
        .bridge_call = elem(Secp.Source, "calls"),
        .tower_call = elem(Secp.TowerSource, "calls"),
        .bulk_call = elem(Bulk, "calls"),
        .bulk_word = elem(Bulk, "words"),
        .sponge_call = elem(Sponge.Plan, "calls"),
        .sponge_word = elem(Sponge.Plan, "words"),
        .sponge_permutation = elem(Sponge.Plan, "perms"),
        .ordinary_event = @sizeOf(A.memory.load_store_v2.native.Event),
        .cell = @sizeOf(@import("../word16_execution/memory/statement.zig").Cell),
        .m31 = @sizeOf(@import("stwo_core").fields.m31.M31),
    };
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, sizes, .{ .whitespace = .indent_2 });
    defer std.testing.allocator.free(bytes);
    try file.writeAll(bytes);
}

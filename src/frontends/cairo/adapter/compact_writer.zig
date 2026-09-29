//! Lossless official ProverInput transport; contains no witness computation.
const std = @import("std");
const adapter = @import("mod.zig");

pub fn encode(allocator: std.mem.Allocator, input: *const adapter.ProverInput) ![]align(64) u8 {
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();
    const writer = &out.writer;
    try writer.writeAll(&adapter.adapted_input.MAGIC);
    try writer.writeInt(u32, adapter.adapted_input.VERSION, .little);
    try writer.writeInt(u32, 0, .little);
    try state(writer, input.state_transitions.initial_state);
    try state(writer, input.state_transitions.final_state);
    try writer.writeInt(u64, input.pc_count, .little);
    var mask: u16 = 0;
    for (input.public_segment_context, 0..) |present, bit| mask |= @as(u16, @intFromBool(present)) << @intCast(bit);
    try writer.writeInt(u16, mask, .little);
    try writer.writeInt(u16, 0, .little);
    try writer.writeInt(u32, 0, .little);
    try writer.writeInt(u32, adapter.opcodes.N_OPCODES, .little);
    try writer.writeInt(u32, 0, .little);
    for (input.state_transitions.casm_states_by_opcode.states) |group| {
        try writer.writeInt(u64, group.items.len, .little);
        for (group.items) |entry| try state(writer, entry);
    }
    const memory = input.memory;
    try writer.writeInt(u128, memory.config.small_max, .little);
    try writer.writeInt(u32, memory.config.log_small_value_capacity, .little);
    try writer.writeInt(u32, 0, .little);
    try writer.writeInt(u64, memory.address_to_id.len, .little);
    try writer.writeInt(u64, memory.f252_values.len, .little);
    try writer.writeInt(u64, memory.small_values.len, .little);
    for (memory.address_to_id) |id| try writer.writeInt(u32, id.raw, .little);
    for (memory.f252_values) |value| for (value) |limb| try writer.writeInt(u32, limb, .little);
    for (memory.small_values) |value| try writer.writeInt(u128, value, .little);
    try writer.writeInt(u64, input.public_memory_addresses.len, .little);
    for (input.public_memory_addresses) |address| try writer.writeInt(u32, address, .little);
    inline for (std.meta.fields(adapter.BuiltinSegments)) |field| {
        const segment = @field(input.builtin_segments, field.name);
        try writer.writeByte(@intFromBool(segment != null));
        try writer.splatByteAll(0, 7);
        try writer.writeInt(u64, if (segment) |s| s.begin_addr else 0, .little);
        try writer.writeInt(u64, if (segment) |s| s.stop_ptr else 0, .little);
    }
    const result = try allocator.alignedAlloc(u8, .@"64", out.written().len);
    @memcpy(result, out.written());
    return result;
}

fn state(writer: *std.Io.Writer, value: anytype) !void {
    try writer.writeInt(u32, value.pc.v, .little);
    try writer.writeInt(u32, value.ap.v, .little);
    try writer.writeInt(u32, value.fp.v, .little);
}

test "compact Cairo writer matches independent Rust transport bytes" {
    var input = try adapter.input.readFile(std.testing.allocator, "vectors/cairo/official/all_opcodes.prover_input.json");
    defer input.deinit(std.testing.allocator);
    const actual = try encode(std.testing.allocator, &input);
    defer std.testing.allocator.free(actual);
    const expected = try std.fs.cwd().readFileAlloc(std.testing.allocator, "vectors/cairo/official/all_opcodes.prover_input.cpi", 2 * 1024 * 1024);
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualSlices(u8, expected, actual);
}

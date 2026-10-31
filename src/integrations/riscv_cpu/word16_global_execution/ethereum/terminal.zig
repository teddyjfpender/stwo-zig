//! Terminal conditions over an ALREADY VERIFIED global execution's RAM list.
//! This helper grants no proof authority; an accepting receiver verifies every
//! physical proof and global closure before checking these conditions.
const std = @import("std");
const Image = @import("../../word16_execution/expected_image.zig");
const Cell = @import("../../word16_execution/memory/statement.zig").Cell;
const Cpu = @import("stwo_riscv_frontend").rv64_air.word16_execution.types.Boundary;
pub fn require(image: *const Image.Owner, final: Cpu, terminal: []const Cell) ![43]u8 {
    // Owner.init already requires this independently pinned ROM word to be
    // absorbing JAL x0,0. A producer-selected final PC is insufficient.
    if (final.final_pc != image.terminal_pc) return error.EthereumTerminalPcMismatch;
    if (try u32At(terminal, image.symbols.halt_flag) != 1) return error.EthereumHaltNotSet;
    if (try u32At(terminal, image.symbols.output_len) != 43) return error.EthereumOutputLengthMismatch;
    var output: [43]u8 = undefined;
    for (&output, 0..) |*v, i| v.* = try byteAt(terminal, image.symbols.output_data + @as(u64, @intCast(i)));
    if (!std.mem.eql(u8, &output, &image.expected_output)) return error.EthereumOutputMismatch;
    return output;
}
fn u32At(cells: []const Cell, address: u64) !u32 {
    var bytes: [4]u8 = undefined;
    for (&bytes, 0..) |*v, i| v.* = try byteAt(cells, address + @as(u64, @intCast(i)));
    return std.mem.readInt(u32, &bytes, .little);
}
fn byteAt(cells: []const Cell, address: u64) !u8 {
    const word = address & ~@as(u64, 7);
    var low: usize = 0;
    var high = cells.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (cells[middle].address < word) low = middle + 1 else high = middle;
    }
    if (low == cells.len or cells[low].address != word) return error.MissingEthereumTerminalWord;
    return @truncate(cells[low].state.value >> @as(u6, @intCast(8 * (address & 7))));
}

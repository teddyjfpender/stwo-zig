//! Host-native identity manifest for every frozen C-013 call-count corpus.
//!
//! This tool does not execute or prove either guest. It derives the exact
//! deterministic input bytes and the pinned scalar Poseidon2 outputs so a
//! capture plan can bind every child request before measured execution.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const corpus = @import("corpus.zig");
const schedule = @import("capture_schedule.zig");

const M31 = core.fields.m31.M31;
const poseidon2 = frontend.air.memory_commitment.poseidon2;

const Record = struct {
    calls: usize,
    input_bytes: usize,
    output_bytes: usize,
    input_sha256: []const u8,
    output_sha256: []const u8,
};

const Manifest = struct {
    schema: []const u8,
    generator: []const u8,
    seed: []const u8,
    call_counts: []const usize,
    records: []const Record,
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temporary = arena.allocator();
    var records: [schedule.call_counts.len]Record = undefined;
    var input_hex: [schedule.call_counts.len][64]u8 = undefined;
    var output_hex: [schedule.call_counts.len][64]u8 = undefined;
    for (schedule.call_counts, 0..) |calls, index| {
        const input = try corpus.makeInput(temporary, calls);
        const output = try expectedOutput(temporary, input, calls);
        input_hex[index] = std.fmt.bytesToHex(digest(input), .lower);
        output_hex[index] = std.fmt.bytesToHex(digest(output), .lower);
        records[index] = .{
            .calls = calls,
            .input_bytes = input.len,
            .output_bytes = output.len,
            .input_sha256 = &input_hex[index],
            .output_sha256 = &output_hex[index],
        };
    }
    var buffer: [16 * 1024]u8 = undefined;
    var output = std.fs.File.stdout().writer(&buffer);
    try std.json.Stringify.value(Manifest{
        .schema = "stwo.c013.poseidon2-corpus-manifest.v1",
        .generator = "poseidon2-software-precompile-equivalence-v1",
        .seed = "stwo-typed-air-m6-poseidon2-v1",
        .call_counts = &schedule.call_counts,
        .records = &records,
    }, .{}, &output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

fn expectedOutput(
    allocator: std.mem.Allocator,
    input: []const u8,
    calls: usize,
) ![]u8 {
    const output = try allocator.alloc(
        u8,
        try std.math.mul(usize, calls, corpus.lanes * @sizeOf(u32)),
    );
    for (0..calls) |call| {
        var state: poseidon2.State = undefined;
        for (0..corpus.lanes) |lane| {
            const input_word = 1 + call * corpus.lanes + lane;
            state[lane] = M31.fromU64(std.mem.readInt(
                u32,
                input[4 * input_word ..][0..4],
                .little,
            ));
        }
        poseidon2.permute(&state);
        for (state, 0..) |value, lane| {
            const output_word = call * corpus.lanes + lane;
            std.mem.writeInt(
                u32,
                output[4 * output_word ..][0..4],
                value.v,
                .little,
            );
        }
    }
    return output;
}

fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

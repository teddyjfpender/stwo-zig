//! Writes the fixed compression graph into the two canonical logical row types.
//! This is witness data, not a proof admission token. The verifier must bind the
//! fixed schedules and the initial/output boundaries in its key and statement.
const core = @import("stwo_core");
const compression = core.crypto.blake3_compression;
const topology = @import("blake3_compression_plan.zig");
const g = @import("blake3_g_call.zig");
const xor = @import("blake3_xor_call.zig");
pub const Prepared = struct {
    g_rows: [56]g.Row,
    xor_rows: [16]xor.Row,
    initial: [32]u32,
    output: [16]u32,
};
pub fn prepare(circuit: u32, cv: [8]u32, block: [16]u32, counter: u64, block_len: u32, flags: u32) !Prepared {
    const trace = try compression.trace(cv, block, counter, block_len, flags);
    const plan = topology.canonical();
    var result: Prepared = undefined;
    result.initial = cv ++ compression.IV[0..4].* ++ [4]u32{ @truncate(counter), @truncate(counter >> 32), block_len, flags } ++ block;
    var wires: [topology.WIRE_COUNT]u32 = undefined;
    wires[0..32].* = result.initial;
    for (plan.g, trace.calls, &result.g_rows) |call, native, *row| {
        var uses: [4]u32 = undefined;
        for (call.input, native.input) |id, word| if (wires[id] != word) return error.InvalidBlake3CallSchedule;
        for (call.output, native.output, &uses) |id, word, *count| {
            wires[id] = word;
            count.* = plan.uses[id];
        }
        row.* = try g.logicalRow(.{ .circuit = circuit, .input = call.input, .output = call.output, .uses = uses }, native.input);
    }
    for (plan.xor, &result.xor_rows, &result.output, trace.output) |call, *row, *out, expected| {
        const input: [2]u32 = .{ wires[call.input[0]], wires[call.input[1]] };
        out.* = input[0] ^ input[1];
        if (out.* != expected) return error.InvalidBlake3CallSchedule;
        row.* = try xor.logicalRow(.{ .circuit = circuit, .input = call.input, .output = call.output, .uses = plan.uses[call.output] }, input);
    }
    return result;
}

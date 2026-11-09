//! Fixed SSA topology. Commitment to these schedules is a verifier/key duty;
//! a proof-supplied schedule is not an authority for a compression statement.
const compression = @import("stwo_core").crypto.blake3_compression;
pub const GCall = struct { input: [6]u32, output: [4]u32 };
pub const XorCall = struct { input: [2]u32, output: u32 };
pub const WIRE_COUNT = 272;
pub const Plan = struct {
    g: [56]GCall,
    xor: [16]XorCall,
    uses: [WIRE_COUNT]u32,
    output: [16]u32,
};
pub fn canonical() Plan {
    var result: Plan = undefined;
    result.uses = @splat(0);
    var state: [16]u32 = undefined;
    var message: [16]u32 = undefined;
    for (&state, &message, 0..) |*s, *m, i| {
        s.* = @intCast(i);
        m.* = @intCast(16 + i);
    }
    var next: u32 = 32;
    for (0..7) |round| {
        for (compression.G_INDICES, 0..) |indices, slot| {
            const call = &result.g[round * 8 + slot];
            call.input = .{ state[indices[0]], state[indices[1]], state[indices[2]], state[indices[3]], message[slot * 2], message[slot * 2 + 1] };
            for (call.input) |id| result.uses[id] += 1;
            for (&call.output, indices) |*id, index| {
                id.* = next;
                state[index] = next;
                next += 1;
            }
        }
        const old = message;
        for (&message, compression.PERMUTATION) |*id, index| id.* = old[index];
    }
    for (&result.xor, 0..) |*call, i| {
        call.* = .{ .input = if (i < 8) .{ state[i], state[i + 8] } else .{ state[i], @intCast(i - 8) }, .output = next };
        for (call.input) |id| result.uses[id] += 1;
        result.output[i] = next;
        result.uses[next] = 1; // final digest boundary
        next += 1;
    }
    return result;
}

//! Shared canonical-word hash row construction. Callers own authentication of
//! preimages, fixed routing coordinates, and the expected provider schedule.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const air = frontend.recursion.air.vm_public_claim_hash;
const witness = frontend.recursion.air.vm_public_claim_hash_witness;
const poseidon = frontend.air.memory_commitment.poseidon2;
const M31 = core.fields.m31.M31;
pub const Row = [air.LOGICAL_INPUT_COUNT]M31;
pub const Call = frontend.air.memory_commitment.poseidon2_air.Call;
pub const Digest = frontend.recursion.poseidon2_channel.Digest;
pub const Route = struct { domain: u32, scope: u32, verifier: u32, input_kind: u32 };

pub fn rowCount(word_count: usize) !usize {
    return std.math.divCeil(usize, try std.math.add(usize, word_count, 1), air.RATE);
}

pub fn write(preimage: []const u32, route: Route, first_step: u32, rows: []Row, calls: []Call) !Digest {
    const count = try rowCount(preimage.len);
    if (rows.len != count or calls.len != count or
        @as(u64, first_step) + count >= core.fields.m31.Modulus)
        return error.InvalidPublicHashGeometry;
    for ([_]u32{ route.domain, route.scope, route.verifier, route.input_kind }) |word|
        if (word >= core.fields.m31.Modulus) return error.InvalidPublicHashWord;
    for (preimage) |word| if (word >= core.fields.m31.Modulus)
        return error.InvalidPublicHashWord;
    var state = [_]M31{M31.zero()} ** air.STATE_WIDTH;
    state[state.len - 1] = M31.fromCanonical(route.domain);
    for (rows, calls, 0..) |*row, *call, step| {
        var metadata = witness.PreprocessedRow{
            .row_mask = 1,
            .step = first_step + @as(u32, @intCast(step)),
            .first = @intFromBool(step == 0),
            .last = @intFromBool(step + 1 == count),
            .chunks = undefined,
        };
        var chunks: [air.RATE]M31 = undefined;
        for (&metadata.chunks, &chunks, 0..) |*chunk, *value, offset| {
            const index = step * air.RATE + offset;
            const from_word = index < preimage.len;
            const constant: u32 = @intFromBool(index == preimage.len);
            chunk.* = .{ .source_mask = @intFromBool(from_word), .word_index = @intCast(index), .constant = constant };
            value.* = M31.fromCanonical(if (from_word) preimage[index] else constant);
        }
        const previous = state;
        for (state[0..air.RATE], chunks) |*value, chunk| value.* = value.add(chunk);
        var input: [air.STATE_WIDTH]u32 = undefined;
        for (&input, state) |*value, field| value.* = field.toU32();
        call.* = .{ .input = input, .wide = false, .io = true, .narrow_output = null };
        poseidon.permute(&state);
        const main = witness.MainRow{ .enabler = 1, .previous = previous, .chunks = chunks, .output = state };
        row.* = main.values() ++ metadata.values() ++ [_]M31{
            M31.one(),                         M31.fromCanonical(route.domain),     M31.fromCanonical(route.scope),
            M31.fromCanonical(route.verifier), M31.fromCanonical(route.input_kind),
        };
    }
    var output: Digest = undefined;
    for (&output, state[0..air.RATE]) |*word, field| word.* = field.toU32();
    return output;
}

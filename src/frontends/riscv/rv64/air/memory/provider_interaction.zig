//! Bounded streaming of retained full-I/O records into the QUALIFIED provider
//! prefix convention. No duplicate Call/output arrays and no permutation replay.
const std = @import("std");
const core = @import("stwo_core");
const legacy = @import("../../../air/memory_commitment/poseidon2_air.zig");
const Relations = @import("../../../air/relation_challenges.zig").Relations;
const Pair = @import("../../../air/logup.zig").RowPair;
const values = @import("values.zig");
const physical = @import("../witness.zig").physical;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const BATCH = 256;
const Scratch = struct { pairs: [BATCH][2]Pair, denominators: [BATCH * 2]Q, inverses: [BATCH * 2]Q };
pub const Interaction = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    columns: []M,
    claims: [2]Q,
    pub fn deinit(self: *Interaction) void {
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};
pub fn generate(a: std.mem.Allocator, records: []const values.PermutationIO, log_size: u32, relations: *const Relations) !Interaction {
    if (log_size < 4 or log_size > 24 or records.len > @as(usize, 1) << @intCast(log_size)) return error.InvalidRamProviderInteractionShape;
    const size = @as(usize, 1) << @intCast(log_size);
    const data = try a.alloc(M, 8 * size);
    errdefer a.free(data);
    const scratch = try a.create(Scratch);
    defer a.destroy(scratch);
    var claims: [2]Q = @splat(Q.zero());
    var start: usize = 0;
    while (start < records.len) {
        const used: usize = @min(BATCH, records.len - start);
        for (records[start..][0..used], 0..) |record, i| {
            var call = legacy.Call{ .input = undefined, .io = true };
            var output: [16]u32 = undefined;
            for (&call.input, record.input, &output, record.output) |*input, in, *out, value| {
                if (in.toU32() >= core.fields.m31.Modulus or value.toU32() >= core.fields.m31.Modulus) return error.NonCanonicalRamProviderIO;
                input.* = in.toU32();
                out.* = value.toU32();
            }
            scratch.pairs[i] = legacy.ioRowPairsFromOutput(call, output, relations);
            for (scratch.pairs[i], 0..) |pair, group| scratch.denominators[2 * i + group] = pair.d1.mul(pair.d2);
        }
        core.fields.batchInverseInPlace(Q, scratch.denominators[0 .. 2 * used], scratch.inverses[0 .. 2 * used]) catch return error.ZeroDenominator;
        for (0..used) |i| {
            for (scratch.pairs[i], 0..) |pair, group| {
                claims[group] = claims[group].add(pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1)).mul(scratch.inverses[2 * i + group]));
                for (claims[group].toM31Array(), 0..) |coordinate, j| data[(4 * group + j) * size + physical(start + i, log_size)] = coordinate;
            }
        }
        start += used;
    }
    // Inactive permutation rows contribute nothing to either relation.
    for (records.len..size) |i| for (claims, 0..) |claim, group| for (claim.toM31Array(), 0..) |coordinate, j| {
        data[(4 * group + j) * size + physical(i, log_size)] = coordinate;
    };
    return .{ .allocator = a, .log_size = log_size, .columns = data, .claims = claims };
}

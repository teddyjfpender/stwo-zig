//! Fixed Word16 bidirectional microshift table: 2^16 inputs *16 amounts.
//! This identity is distinct from the byte table despite the same tuple arity.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const Bus = @import("function_bus.zig");
const Tables = @import("../providers/tables.zig");
const physical = @import("../witness.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
pub const LOG: u32 = 20;
pub const SIZE: usize = 1 << LOG;
pub const DOMAIN_TAG: u32 = 0x53573136;
pub const Challenges = Tables.Challenges;
pub const evaluateFor = Tables.evaluateFor;
pub fn tupleAt(row: usize) Tables.Tuple {
    std.debug.assert(row < SIZE);
    const x: u32 = @intCast(row >> 4);
    const shift: u5 = @intCast(row & 15);
    const left = x << shift; // At most 2^31-32768, strictly below M31 modulus.
    return .{ x, shift, left & 65535, left >> 16, x >> shift, if (shift == 0) 0 else (x << @as(u5, @intCast(16 - @as(u32, shift)))) & 65535 };
}
pub fn rowIndex(tuple: Tables.Tuple) !usize {
    if (tuple[0] > 65535 or tuple[1] > 15) return error.InvalidWordShiftTuple;
    const row = @as(usize, tuple[0]) * 16 + tuple[1];
    if (!std.mem.eql(u32, &tuple, &tupleAt(row))) return error.InvalidWordShiftTuple;
    return row;
}
pub const Setup = struct {
    allocator: std.mem.Allocator,
    fixed: []M,
    pub fn init(a: std.mem.Allocator) !Setup {
        const fixed = try a.alloc(M, 8 * SIZE);
        @memset(fixed, M.zero());
        for (0..SIZE) |i| {
            const p = physical(i, LOG);
            for (tupleAt(i)[0..6], 0..) |value, c| fixed[c * SIZE + p] = M.fromCanonical(value);
        }
        fixed[6 * SIZE + physical(0, LOG)] = M.one();
        fixed[7 * SIZE + physical(SIZE - 1, LOG)] = M.one();
        return .{ .allocator = a, .fixed = fixed };
    }
    pub fn deinit(self: *Setup) void {
        self.allocator.free(self.fixed);
        self.* = undefined;
    }
};
pub const Request = struct {
    allocator: std.mem.Allocator,
    main: []M,
    interaction: []M = &.{},
    dictionary: []Q = &.{},
    pub fn init(a: std.mem.Allocator, counts: []const u64) !Request {
        if (counts.len != SIZE) return error.InvalidWordShiftCounts;
        _ = try Bus.admitPositiveMass(counts);
        const main = try a.alloc(M, SIZE);
        for (counts, 0..) |count, i| main[physical(i, LOG)] = M.fromCanonical(@intCast(count));
        return .{ .allocator = a, .main = main };
    }
    pub fn deinit(self: *Request) void {
        self.allocator.free(self.main);
        self.allocator.free(self.interaction);
        self.allocator.free(self.dictionary);
        self.* = undefined;
    }
    pub fn generateInteraction(self: *Request, ch: Challenges) !Q {
        if (self.interaction.len != 0) return error.InvalidWordShiftPhase;
        const a = self.allocator;
        const output = try a.alloc(M, 8 * SIZE);
        errdefer a.free(output);
        const dictionary = try a.alloc(Q, SIZE);
        errdefer a.free(dictionary);
        const scratch = try a.alloc(Q, 4096);
        defer a.free(scratch);
        var sum = Q.zero();
        var start: usize = 0;
        while (start < SIZE) : (start += 4096) {
            for (0..4096 / E.LANES) |batch| {
                const begin = start + batch * E.LANES;
                var tuple: [6]E.PackedBase = undefined;
                for (&tuple, 0..) |*v, c| {
                    var lanes: [E.LANES]M = undefined;
                    for (&lanes, 0..) |*lane, i| lane.* = M.fromCanonical(tupleAt(begin + i)[c]);
                    v.* = E.PackedBase.fromLanes(lanes);
                }
                const denominator = E.denominatorFor(E.PackedBase, ch.offset, &ch.coefficients, &tuple, true);
                for (0..E.LANES) |i| scratch[batch * E.LANES + i] = denominator.lane(i);
            }
            try core.fields.batchInverseInPlace(Q, scratch, dictionary[start..][0..4096]);
            for (0..4096) |i| {
                const row = physical(start + i, LOG);
                const inverse = dictionary[start + i];
                sum = sum.sub(inverse.mulM31(self.main[row]));
                for (inverse.toM31Array(), 0..) |v, c| output[c * SIZE + row] = v;
                for (sum.toM31Array(), 0..) |v, c| output[(4 + c) * SIZE + row] = v;
            }
        }
        self.interaction = output;
        self.dictionary = dictionary;
        return sum;
    }
};

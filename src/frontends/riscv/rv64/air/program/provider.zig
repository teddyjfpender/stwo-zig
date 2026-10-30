//! Per-request ROM multiplicities and LogUp witness. Setup is borrowed and never
//! mutated. Commit multiplicities together with execution main BEFORE drawing
//! Challenges; claims enter the transcript BEFORE composition randomness.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const E = @import("../evaluation.zig");
const rom = @import("setup.zig");
pub const INTERACTION = 8;
pub const CONSTRAINTS = 4;
pub const MAX_REQUESTS = 1 << 28; // exact integer multiplicity, below M31 prime

pub const Challenges = struct {
    offset: Q,
    coefficients: [rom.field.COUNT]Q,
    pub fn draw(channel: *@import("../protocol.zig").Channel) Challenges {
        channel.mixU32s(&.{ 0x52563634, 0x524f4d31, 1, rom.field.COUNT });
        var result: Challenges = undefined;
        result.offset = channel.drawSecureFelt();
        for (&result.coefficients) |*value| value.* = channel.drawSecureFelt();
        return result;
    }
    pub fn denominator(self: Challenges, entry: *const rom.Tuple) Q {
        var result = self.offset;
        for (entry, self.coefficients) |value, coefficient| {
            // Compact41 has structurally zero coefficients for omitted fields.
            if (!coefficient.isZero()) result = result.add(value.mul(coefficient));
        }
        return result;
    }
};

pub const Request = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    /// Column-major bit-reversed circle order, one main column.
    multiplicities: []M,
    interaction: []M = &.{},
    count: usize = 0,

    pub fn init(a: std.mem.Allocator, setup: *const rom.Setup, pcs: []const u64) !Request {
        if (pcs.len > MAX_REQUESTS) return error.InvalidRv64RomRequestCount;
        const multiplicities = try a.alloc(M, setup.domainSize());
        errdefer a.free(multiplicities);
        @memset(multiplicities, M.zero());
        for (pcs) |pc| {
            const index = physical(try setup.lookup(pc), setup.log_size);
            multiplicities[index] = multiplicities[index].add(M.one());
        }
        return .{ .allocator = a, .log_size = setup.log_size, .multiplicities = multiplicities, .count = pcs.len };
    }
    pub fn deinit(self: *Request) void {
        self.allocator.free(self.multiplicities);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
    /// Transactional: publish only after every inverse succeeds. Must be called
    /// after the joint main commitment and relation challenge draw.
    pub fn generateInteraction(self: *Request, setup: *const rom.Setup, challenges: Challenges) !Q {
        if (self.log_size != setup.log_size or self.multiplicities.len != setup.domainSize()) return error.InvalidRv64RomGeometry;
        const size = setup.domainSize();
        const values = try self.allocator.alloc(M, INTERACTION * size);
        errdefer self.allocator.free(values);
        var sum = Q.zero();
        for (0..size) |i| {
            const index = physical(i, self.log_size);
            const row = setup.row(i);
            const entry = rom.tuple(&row);
            const inverse = try challenges.denominator(&entry).inv();
            sum = sum.sub(inverse.mulM31(self.multiplicities[index]));
            putSecure(values, size, index, 0, inverse);
            putSecure(values, size, index, 4, sum);
        }
        self.allocator.free(self.interaction);
        self.interaction = values;
        return sum;
    }
};

/// Execution uses positive contributions; provider uses negative contributions.
/// The combined receiver requires execution_claim + provider_claim == zero.
/// Fixed first/last are receiver-derived for this provider's own domain.
pub fn evaluate(first: Q, last: Q, entry: *const rom.Tuple, multiplicity: Q, current: *const [INTERACTION]Q, previous: *const [INTERACTION]Q, challenges: Challenges, claim: Q, sink: *E.Sink) void {
    const inverse = secure(current, 0);
    const sum = secure(current, 4);
    const prior = secure(previous, 4);
    const contribution = multiplicity.mul(inverse);
    sink.emit(challenges.denominator(entry).mul(inverse).sub(Q.one()));
    sink.emit(sum.sub(Q.one().sub(first).mul(prior)).add(contribution));
    sink.emit(first.mul(sum.add(contribution)));
    sink.emit(last.mul(sum.sub(claim)));
}

pub fn physical(logical: usize, log_size: u32) usize {
    return core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, log_size), log_size);
}
pub fn secure(values: *const [INTERACTION]Q, start: usize) Q {
    return values[start].add(values[start + 1].mul(Q.fromU32Unchecked(0, 1, 0, 0)))
        .add(values[start + 2].mul(Q.fromU32Unchecked(0, 0, 1, 0)))
        .add(values[start + 3].mul(Q.fromU32Unchecked(0, 0, 0, 1)));
}
fn putSecure(values: []M, size: usize, index: usize, start: usize, value: Q) void {
    const parts = value.toM31Array();
    for (parts, 0..) |part, i| values[(start + i) * size + index] = part;
}

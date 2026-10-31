//! Receiver-derived immutable mapping-grant ROM and sealed LogUp counts.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const authority = @import("policy_air.zig");
const policy = @import("policy.zig");
const physical = @import("../witness.zig").physical;
pub const Q = E.Q;
pub const M = core.fields.m31.M31;
pub const MAIN = 1;
pub const FIXED = 21;
pub const FIRST = 18;
pub const LAST = 19;
pub const VALID = 20;
pub const SUMS = 1;
pub const INTERACTION = 8;
pub const CONSTRAINTS = 5;
pub const Row = [MAIN]M;
pub const SecureRow = [MAIN]Q;
pub const Fixed = [FIXED]Q;
pub const Claims = [SUMS]Q;
pub const Challenges = struct { policy: authority.PolicyChallenge };
pub const Shape = struct {
    grants: []const policy.Grant,
    log_size: u32,
    pub fn size(self: Shape) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn validate(self: Shape) !void {
        if (self.log_size < 4 or self.log_size > 12 or self.grants.len > self.size()) return error.InvalidRamPolicyProviderShape;
    }
    pub fn fixedAt(self: Shape, i: usize) [FIXED]M {
        var result: [FIXED]M = @splat(M.zero());
        result[FIRST] = M.fromCanonical(@intFromBool(i == 0));
        result[LAST] = M.fromCanonical(@intFromBool(i + 1 == self.size()));
        if (i < self.grants.len) {
            const grant = self.grants[i];
            for (0..8) |j| {
                result[j] = M.fromCanonical(@intCast((grant.first >> @intCast(8 * j)) & 255));
                result[8 + j] = M.fromCanonical(@intCast((grant.last >> @intCast(8 * j)) & 255));
            }
            result[16] = M.fromCanonical(grant.mask & 1);
            result[17] = M.fromCanonical((grant.mask >> 1) & 1);
            result[VALID] = M.one();
        }
        return result;
    }
};
pub fn evaluate(_: Shape, fixed: *const Fixed, main: *const SecureRow, _: *const SecureRow, interaction: []const Q, previous_interaction: []const Q, claims: Claims, challenges: *const Challenges, out: *E.Sink) void {
    const inverse = authority.secure(interaction, 0);
    const sum = authority.secure(interaction, 1);
    const previous = authority.secure(previous_interaction, 1);
    const term = main[0].mul(inverse);
    out.emit(inverse.mul(challenges.policy.denominator(fixed[0..18].*)).sub(Q.one()));
    out.emit(sum.sub(previous).add(fixed[FIRST].mul(previous)).add(term));
    out.emit(fixed[FIRST].mul(sum.add(term)));
    out.emit(fixed[LAST].mul(sum.sub(claims[0])));
    out.emit(Q.one().sub(fixed[VALID]).mul(main[0]));
}
pub const Trace = struct {
    allocator: std.mem.Allocator,
    shape: Shape,
    fixed: []M,
    main: []M,
    interaction: []M = &.{},
    claim: Q = Q.zero(),
    pub fn init(a: std.mem.Allocator, mappings: *const policy.Policy, counts: []const u64) !Trace {
        try mappings.validate();
        if (counts.len != mappings.grants.len) return error.InvalidRamPolicyMultiplicity;
        var total: u64 = 0;
        for (counts) |count| {
            total = try std.math.add(u64, total, count);
            if (total >= core.fields.m31.Modulus) return error.InvalidRamPolicyMultiplicity;
        }
        const shape = Shape{ .grants = mappings.grants, .log_size = @intCast(@max(4, std.math.log2_int_ceil(usize, @max(1, mappings.grants.len)))) };
        try shape.validate();
        const fixed = try a.alloc(M, FIXED * shape.size());
        errdefer a.free(fixed);
        const main = try a.alloc(M, shape.size());
        errdefer a.free(main);
        @memset(main, M.zero());
        for (0..shape.size()) |i| {
            const at = physical(i, shape.log_size);
            for (shape.fixedAt(i), 0..) |value, col| fixed[col * shape.size() + at] = value;
            if (i < counts.len) main[at] = M.fromCanonical(@intCast(counts[i]));
        }
        return .{ .allocator = a, .shape = shape, .fixed = fixed, .main = main };
    }
    pub fn generateInteraction(self: *Trace, challenges: Challenges) !Q {
        if (self.interaction.len != 0) return error.InvalidRamPolicyProviderPhase;
        const data = try self.allocator.alloc(M, INTERACTION * self.shape.size());
        errdefer self.allocator.free(data);
        var sum = Q.zero();
        for (0..self.shape.size()) |i| {
            const at = physical(i, self.shape.log_size);
            const f = self.shape.fixedAt(i);
            var tuple: authority.PolicyTuple = undefined;
            for (&tuple, f[0..18]) |*value, base| value.* = Q.fromBase(base);
            const inverse = try challenges.policy.denominator(tuple).inv();
            sum = sum.sub(inverse.mulM31(self.main[at]));
            for (inverse.toM31Array(), sum.toM31Array(), 0..) |inv, prefix, j| {
                data[j * self.shape.size() + at] = inv;
                data[(4 + j) * self.shape.size() + at] = prefix;
            }
        }
        self.interaction = data;
        self.claim = sum;
        return sum;
    }
    pub fn deinit(self: *Trace) void {
        self.allocator.free(self.fixed);
        self.allocator.free(self.main);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
};

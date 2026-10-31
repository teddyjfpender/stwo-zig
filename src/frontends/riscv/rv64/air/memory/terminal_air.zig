//! One terminal root-observation certificate. Existing CellTable authenticates
//! private canonical words; public constraints bind only halt/len/43 output
//! bytes. The final word's upper five bytes remain private and unconstrained.
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const Cell = @import("cell_air.zig");
const values = @import("values.zig");
pub const Q = E.Q;
pub const M = core.fields.m31.M31;
pub const OUTPUT_BYTES = 43;
pub const SELECTORS = 7;
pub const FIXED = Cell.FIXED + SELECTORS;
pub const MAIN = Cell.MAIN;
pub const INTERACTION = Cell.INTERACTION;
pub const SUMS = Cell.SUMS;
pub const CONSTRAINTS = Cell.CONSTRAINTS + 17;
pub const ACTIVE = Cell.ACTIVE;
pub const BASE = Cell.BASE;
pub const WRITE = Cell.WRITE;
pub const SecureRow = Cell.SecureRow;
pub const Row = Cell.Row;
pub const Fixed = [FIXED]Q;
pub const Claims = Cell.Claims;
pub const Challenges = Cell.Challenges;
pub const Spec = struct {
    geometry: values.Geometry,
    halt_flag: u64,
    output: [OUTPUT_BYTES]u8,
    pub fn validate(self: Spec) !void {
        if (self.halt_flag & 7 != 0 or (self.halt_flag & (self.geometry.bytes() - 1)) + 8 + OUTPUT_BYTES > self.geometry.bytes()) return error.InvalidRv64TerminalLayout;
    }
    pub fn base(self: Spec) u64 {
        return self.halt_flag & ~@as(u64, self.geometry.bytes() - 1);
    }
    pub fn firstCell(self: Spec) usize {
        return @intCast((self.halt_flag & (self.geometry.bytes() - 1)) >> 3);
    }
    pub fn byte(self: Spec, word: usize, lane: usize) ?u8 {
        if (word == 0) return if (lane == 0) 1 else if (lane == 4) OUTPUT_BYTES else 0;
        const index = 8 * (word - 1) + lane;
        return if (index < OUTPUT_BYTES) self.output[index] else null;
    }
};
pub const Shape = struct {
    spec: Spec,
    log_size: u32,
    pub fn size(self: Shape) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn cellShape(self: Shape) Cell.Shape {
        return .{ .geometry = self.spec.geometry, .chunks = 1, .log_size = self.log_size, .policy_mode = .chunk };
    }
    pub fn validate(self: Shape) !void {
        try self.spec.validate();
        if (self.log_size != self.spec.geometry.logBytes() - 3) return error.InvalidRv64TerminalLayout;
    }
    pub fn fixedAt(self: Shape, logical: usize) [FIXED]M {
        var row: [FIXED]M = undefined;
        @memcpy(row[0..Cell.FIXED], &self.cellShape().fixedAt(logical));
        for (0..SELECTORS) |i| row[Cell.FIXED + i] = M.fromCanonical(@intFromBool(logical % self.spec.geometry.cells() == self.spec.firstCell() + i));
        return row;
    }
};
pub fn evaluate(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow, interaction: []const Q, previous_interaction: []const Q, claims: Claims, challenges: *const Challenges, out: *E.Sink) void {
    Cell.evaluate(shape.cellShape(), fixed[0..Cell.FIXED], main, previous, interaction, previous_interaction, claims, challenges, out);
    evaluateBinding(shape.spec, fixed[Cell.FIXED..][0..SELECTORS], main, out);
}
pub fn evaluateBinding(spec: Spec, selectors: *const [SELECTORS]Q, main: *const SecureRow, out: *E.Sink) void {
    // An observation creates no synthetic timestamped memory event. Root
    // equality and canonical before/after values are checked by the outer mode.
    out.emit(main[Cell.TOUCHED]);
    const base = spec.base();
    for (0..8) |i| out.emit(main[Cell.BASE + i].sub(E.q(@intCast((base >> @intCast(8 * i)) & 255))));
    for (0..8) |lane| {
        var mask = Q.zero();
        var expected = Q.zero();
        for (0..SELECTORS) |word| if (spec.byte(word, lane)) |byte| {
            const selector = selectors[word];
            mask = mask.add(selector);
            expected = expected.add(selector.mul(E.q(byte)));
        };
        out.emit(mask.mul(main[Cell.AFTER + lane]).sub(expected));
    }
}

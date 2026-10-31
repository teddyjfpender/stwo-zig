//! Canonical bitwise lookup providers with independent immutable domains.
//! Setup is receiver-owned; only multiplicities and prefixes vary per request.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const E = @import("../evaluation.zig");
const Column = engine.pcs.ColumnEvaluation;
const physical = @import("../witness.zig").physical;
pub const MAX_ARITY = 6;
pub const N_INTERACTION = 8;
pub const N_CONSTRAINTS = 4;
pub const Tuple = [MAX_ARITY]u32;
pub const Kind = enum {
    byte_and,
    byte_shift,
    pub fn arity(self: Kind) usize {
        return switch (self) {
            .byte_and => 3,
            .byte_shift => 6,
        };
    }
    pub fn logSize(self: Kind) u32 {
        return switch (self) {
            .byte_and => 16,
            .byte_shift => 11,
        };
    }
    pub fn size(self: Kind) usize {
        return @as(usize, 1) << @intCast(self.logSize());
    }
    pub fn tupleAt(self: Kind, row: usize) Tuple {
        std.debug.assert(row < self.size());
        return switch (self) {
            .byte_and => blk: {
                const x: u32 = @intCast(row >> 8);
                const y: u32 = @intCast(row & 255);
                break :blk .{ x, y, x & y, 0, 0, 0 };
            },
            .byte_shift => blk: {
                const x: u32 = @intCast(row >> 3);
                const shift: u5 = @intCast(row & 7);
                const left = x << shift;
                break :blk .{ x, shift, left & 255, left >> 8, x >> shift, if (shift == 0) 0 else (x << @as(u5, @intCast(8 - @as(u32, shift)))) & 255 };
            },
        };
    }
    /// Validates the whole relation tuple, including canonical unused lanes.
    pub fn rowIndex(self: Kind, tuple: Tuple) !usize {
        const row: usize = switch (self) {
            .byte_and => blk: {
                if (tuple[0] > 255 or tuple[1] > 255) return error.InvalidLookupTuple;
                break :blk @as(usize, tuple[0]) * 256 + tuple[1];
            },
            .byte_shift => blk: {
                if (tuple[0] > 255 or tuple[1] > 7) return error.InvalidLookupTuple;
                break :blk @as(usize, tuple[0]) * 8 + tuple[1];
            },
        };
        if (!std.mem.eql(u32, &tuple, &self.tupleAt(row))) return error.InvalidLookupTuple;
        return row;
    }
};

pub const Challenges = struct {
    offset: Q,
    coefficients: [MAX_ARITY]Q,
    pub fn draw(channel: anytype) Challenges {
        var result: Challenges = undefined;
        result.offset = channel.drawSecureFelt();
        for (&result.coefficients) |*coefficient| coefficient.* = channel.drawSecureFelt();
        return result;
    }
    pub fn denominator(self: Challenges, tuple: []const Q) Q {
        std.debug.assert(tuple.len <= MAX_ARITY);
        var result = self.offset;
        for (tuple, self.coefficients[0..tuple.len]) |value, coefficient| result = result.sub(value.mul(coefficient));
        return result;
    }
};

pub fn evaluate(tuple: []const Q, first: Q, last: Q, multiplicity: Q, inverse: Q, sum: Q, previous: Q, claim: Q, challenges: Challenges) [N_CONSTRAINTS]Q {
    return evaluateFor(Q, tuple, first, last, multiplicity, inverse, sum, previous, claim, challenges);
}
pub fn evaluateFor(comptime F: type, tuple: []const F, first: F, last: F, multiplicity: F, inverse: E.SecureFor(F), sum: E.SecureFor(F), previous: E.SecureFor(F), claim: Q, challenges: Challenges) [N_CONSTRAINTS]E.SecureFor(F) {
    const S = E.SecureFor(F);
    const term = E.mulBaseFor(F, inverse, multiplicity);
    const d = E.denominatorFor(F, challenges.offset, challenges.coefficients[0..tuple.len], tuple, true);
    return .{ inverse.mul(d).sub(S.one()), sum.sub(previous).add(E.mulBaseFor(F, previous, first)).add(term), E.mulBaseFor(F, sum.add(term), first), E.mulBaseFor(F, sum.sub(E.splatFor(F, claim)), last) };
}

pub const Setup = struct {
    allocator: std.mem.Allocator,
    kind: Kind,
    fixed: []M,
    pub fn init(a: std.mem.Allocator, kind: Kind) !Setup {
        const size = kind.size();
        const arity = kind.arity();
        const fixed = try a.alloc(M, (arity + 2) * size);
        errdefer a.free(fixed);
        @memset(fixed, M.zero());
        for (0..size) |i| {
            const row = physical(i, kind.logSize());
            const tuple = kind.tupleAt(i);
            for (tuple[0..arity], 0..) |value, c| fixed[c * size + row] = M.fromCanonical(value);
            fixed[arity * size + row] = M.fromCanonical(@intFromBool(i == 0));
            fixed[(arity + 1) * size + row] = M.fromCanonical(@intFromBool(i + 1 == size));
        }
        return .{ .allocator = a, .kind = kind, .fixed = fixed };
    }
    pub fn deinit(self: *Setup) void {
        self.allocator.free(self.fixed);
        self.* = undefined;
    }
    pub fn fixedColumns(self: *const Setup, a: std.mem.Allocator) ![]Column {
        return columns(a, self.fixed, self.kind.logSize());
    }
};

pub const Request = struct {
    allocator: std.mem.Allocator,
    kind: Kind,
    main: []M,
    interaction: []M = &.{},
    claim: Q = Q.zero(),
    pub fn init(a: std.mem.Allocator, setup: *const Setup, counts: []const u64) !Request {
        if (counts.len != setup.kind.size()) return error.InvalidLookupMultiplicity;
        var total: u64 = 0;
        for (counts) |count| {
            total = std.math.add(u64, total, count) catch return error.InvalidLookupMultiplicity;
            if (total >= core.fields.m31.Modulus) return error.InvalidLookupMultiplicity;
        }
        const main = try a.alloc(M, counts.len);
        for (counts, 0..) |count, i| main[physical(i, setup.kind.logSize())] = M.fromCanonical(@intCast(count));
        return .{ .allocator = a, .kind = setup.kind, .main = main };
    }
    pub fn deinit(self: *Request) void {
        self.allocator.free(self.main);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
    pub fn mainColumns(self: *const Request, a: std.mem.Allocator) ![]Column {
        return columns(a, self.main, self.kind.logSize());
    }
    pub fn interactionColumns(self: *const Request, a: std.mem.Allocator) ![]Column {
        return columns(a, self.interaction, self.kind.logSize());
    }
    pub fn generateInteraction(self: *Request, challenges: Challenges) !Q {
        if (self.interaction.len != 0) return error.InvalidLookupProviderPhase;
        const size = self.kind.size();
        const data = try self.allocator.alloc(M, N_INTERACTION * size);
        errdefer self.allocator.free(data);
        var sum = Q.zero();
        for (0..size) |i| {
            const row = physical(i, self.kind.logSize());
            const tuple = self.kind.tupleAt(i);
            var secure_tuple: [MAX_ARITY]Q = undefined;
            for (&secure_tuple, tuple) |*dst, value| dst.* = Q.fromBase(M.fromCanonical(value));
            const inverse = try challenges.denominator(secure_tuple[0..self.kind.arity()]).inv();
            sum = sum.sub(inverse.mulM31(self.main[row]));
            for (inverse.toM31Array(), 0..) |coordinate, c| data[c * size + row] = coordinate;
            for (sum.toM31Array(), 0..) |coordinate, c| data[(4 + c) * size + row] = coordinate;
        }
        self.interaction = data;
        self.claim = sum;
        return sum;
    }
};
fn columns(a: std.mem.Allocator, storage: []const M, log: u32) ![]Column {
    const size = @as(usize, 1) << @intCast(log);
    const result = try a.alloc(Column, storage.len / size);
    for (result, 0..) |*column, c| column.* = .{ .log_size = log, .values = storage[c * size ..][0..size] };
    return result;
}

test "canonical AND and shift tables enumerate exact byte semantics" {
    for ([_]Kind{ .byte_and, .byte_shift }) |kind| {
        for (0..kind.size()) |i| {
            const tuple = kind.tupleAt(i);
            try std.testing.expectEqual(i, try kind.rowIndex(tuple));
            if (kind == .byte_shift) {
                const x = tuple[0];
                const shift: u5 = @intCast(tuple[1]);
                try std.testing.expectEqual(x << shift, tuple[2] + 256 * tuple[3]);
                try std.testing.expectEqual(x, (tuple[4] << shift) + (if (shift == 0) @as(u32, 0) else tuple[5] >> @as(u5, @intCast(8 - @as(u32, shift)))));
            }
            var wrong = tuple;
            wrong[2] ^= 1;
            try std.testing.expectError(error.InvalidLookupTuple, kind.rowIndex(wrong));
        }
    }
}

test "typed providers constrain every inverse and reset and terminal prefix" {
    const a = std.testing.allocator;
    const challenges = Challenges{ .offset = Q.fromU32Unchecked(1021, 3, 7, 11), .coefficients = .{Q.fromU32Unchecked(17, 2, 1, 3)} ** MAX_ARITY };
    for ([_]Kind{ .byte_and, .byte_shift }) |kind| {
        var setup = try Setup.init(a, kind);
        defer setup.deinit();
        const counts = try a.alloc(u64, kind.size());
        defer a.free(counts);
        @memset(counts, 0);
        counts[0] = 3;
        counts[17] = 91;
        counts[kind.size() - 1] = 2;
        var request = try Request.init(a, &setup, counts);
        defer request.deinit();
        const claim = try request.generateInteraction(challenges);
        const size = kind.size();
        for (0..size) |i| {
            const row = physical(i, kind.logSize());
            const prior = physical((i + size - 1) % size, kind.logSize());
            var tuple: [MAX_ARITY]Q = undefined;
            for (tuple[0..kind.arity()], 0..) |*value, c| value.* = Q.fromBase(setup.fixed[c * size + row]);
            const inverse = secure(request.interaction, size, row, 0);
            const sum = secure(request.interaction, size, row, 4);
            const previous = secure(request.interaction, size, prior, 4);
            const first = Q.fromBase(setup.fixed[kind.arity() * size + row]);
            const last = Q.fromBase(setup.fixed[(kind.arity() + 1) * size + row]);
            const m = Q.fromBase(request.main[row]);
            for (evaluate(tuple[0..kind.arity()], first, last, m, inverse, sum, previous, claim, challenges)) |residual| try std.testing.expect(residual.isZero());
            const forged = evaluate(tuple[0..kind.arity()], first, last, m.add(Q.one()), inverse, sum, previous, claim, challenges);
            try std.testing.expect(!forged[1].isZero());
        }
        try std.testing.expectError(error.InvalidLookupProviderPhase, request.generateInteraction(challenges));
    }
}
fn secure(data: []const M, size: usize, row: usize, column: usize) Q {
    return Q.fromM31(data[column * size + row], data[(column + 1) * size + row], data[(column + 2) * size + row], data[(column + 3) * size + row]);
}

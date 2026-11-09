//! Column-major narrow reference witness. Components retain only their input
//! advice after MAIN release; source-owned ROM and lookup counts are immutable.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../memory/closed_ram/mod.zig");
const S = @import("narrow_source.zig");
const NE = @import("narrow_equations.zig");
const D = @import("dag.zig");
const Micro = @import("micro.zig");
const M = core.fields.m31.M31;
const E = @import("../../evaluation.zig");
pub const Input = [D.INPUTS]u256;
pub fn fixed(a: std.mem.Allocator, role: S.Role, log: u32) ![]M {
    const n = @as(usize, 1) << @intCast(log);
    const out = try a.alloc(M, S.FIXED * n);
    for (0..n) |index| {
        const row = S.fixedRow(role, index, log);
        const physical = R.trace.physical(index, log);
        for (row, 0..) |value, column| out[column * n + physical] = M.fromCanonical(value);
    }
    return out;
}
pub fn Source(comptime role: S.Role) type {
    return SourceForField(role, core.fields.qm31.QM31);
}
pub fn SourceForField(comptime role: S.Role, comptime Q: type) type {
    return struct {
        const Self = @This();
        pub const L = NE.LayoutForField(role, Q);
        pub const Eq = NE.EquationsForField(role, Q);
        allocator: std.mem.Allocator,
        log_size: u32,
        first_id: u32,
        inputs: []Input,
        fixed: []M,
        main: []M,
        interaction: []M = &.{},
        pub fn init(a: std.mem.Allocator, inputs: []const Input, first: u32, log: u32) !Self {
            try L.validateGeometry(@intCast(inputs.len), first, log);
            const n = @as(usize, 1) << @intCast(log);
            const copy = try a.dupe(Input, inputs);
            errdefer a.free(copy);
            const preprocessing = try fixed(a, role, log);
            errdefer a.free(preprocessing);
            const main = try a.alloc(M, L.MAIN * n);
            errdefer a.free(main);
            @memset(main, M.zero());
            const byte_counts = try a.alloc(u32, 256);
            defer a.free(byte_counts);
            @memset(byte_counts, 0);
            const carry_counts = try a.alloc(u32, Micro.CARRY_LIMIT);
            defer a.free(carry_counts);
            @memset(carry_counts, 0);
            for (inputs, 0..) |*input, call| {
                if (role == .frontier) {
                    for (0..D.INPUTS) |step| {
                        const row = S.frontierRow(input, step);
                        const physical = R.trace.physical(call * D.INPUTS + step, log);
                        for (row, 0..) |value, column| main[column * n + physical] = M.fromCanonical(value);
                    }
                } else {
                    const values = D.evaluate(input);
                    for (0..D.STEPS) |step| {
                        const row = Micro.fill(step, &values);
                        const physical = R.trace.physical(call * D.STEPS + step, log);
                        for (row, 0..) |value, column| main[column * n + physical] = M.fromCanonical(value);
                        for (0..Micro.BYTE_QUERIES) |query| byte_counts[Micro.rangeQuery(&row, query)] += 1;
                        for (0..Micro.CARRY_QUERIES) |query| carry_counts[Micro.rangeQuery(&row, Micro.BYTE_QUERIES + query)] += 1;
                    }
                }
            }
            if (role == .arithmetic) {
                for (byte_counts, 0..) |count, value| main[L.BYTE_MULT * n + R.trace.physical(value, log)] = M.fromCanonical(count);
                for (carry_counts, 0..) |count, value| main[L.CARRY_MULT * n + R.trace.physical(value, log)] = M.fromCanonical(count);
            }
            return .{ .allocator = a, .log_size = log, .first_id = first, .inputs = copy, .fixed = preprocessing, .main = main };
        }
        pub fn deinit(self: *Self) void {
            const a = self.allocator;
            a.free(self.inputs);
            a.free(self.fixed);
            a.free(self.main);
            a.free(self.interaction);
            self.* = undefined;
        }
        pub fn size(self: *const Self) usize {
            return @as(usize, 1) << @intCast(self.log_size);
        }
        pub fn public(self: *const Self) @import("../../evaluation.zig").CallSpanFor(Q) {
            return .{ .calls = @intCast(self.inputs.len), .first_id = self.first_id };
        }
        pub const View = struct {
            source: *const Self,
            physical: usize,
            pub fn fixed(self: *const @This(), c: usize) Q {
                return Q.fromBase(self.source.fixed[c * self.source.size() + self.physical]);
            }
            pub fn main(self: *const @This(), c: usize) Q {
                return Q.fromBase(self.source.main[c * self.source.size() + self.physical]);
            }
        };
        pub fn generateInteraction(self: *Self, ch: NE.ChallengesFor(Q)) !NE.ClaimsFor(Q) {
            return self.generateInteractionImpl(ch, true);
        }
        pub fn generateInteractionScalarForTesting(self: *Self, ch: NE.ChallengesFor(Q)) !NE.ClaimsFor(Q) {
            if (!@import("builtin").is_test) @compileError("scalar reference is test-only");
            return self.generateInteractionImpl(ch, false);
        }
        // Bounded independent fraction inversions; prefix order and all bytes
        // remain the scalar reference's exact order. No full tuple plane.
        const CHUNK_ROWS = 128;
        const FRACTIONS = L.SSA_FRACTIONS + 1;
        fn generateInteractionImpl(self: *Self, ch: NE.ChallengesFor(Q), comptime batched: bool) !NE.ClaimsFor(Q) {
            if (self.interaction.len != 0) return error.TowerInteractionAlreadyGenerated;
            const n = self.size();
            const out = try self.allocator.alloc(M, L.INTERACTION * n);
            errdefer self.allocator.free(out);
            var bytes: [256]Q = undefined;
            const carries = try self.allocator.alloc(Q, if (role == .arithmetic) Micro.CARRY_LIMIT else 0);
            defer self.allocator.free(carries);
            if (role == .arithmetic) {
                if (batched) {
                    const denominators = try self.allocator.alloc(Q, Micro.CARRY_LIMIT);
                    defer self.allocator.free(denominators);
                    for (denominators[0..256], 0..) |*value, index| value.* = ch.bytes.sub(Q.fromBase(M.fromCanonical(@intCast(index))));
                    try core.fields.batchInverseInPlace(Q, denominators[0..256], &bytes);
                    for (denominators, 0..) |*value, index| value.* = ch.carries.sub(Q.fromBase(M.fromCanonical(@intCast(index))));
                    try core.fields.batchInverseInPlace(Q, denominators, carries);
                } else {
                    for (&bytes, 0..) |*value, index| value.* = try ch.bytes.sub(Q.fromBase(M.fromCanonical(@intCast(index)))).inv();
                    for (carries, 0..) |*value, index| value.* = try ch.carries.sub(Q.fromBase(M.fromCanonical(@intCast(index)))).inv();
                }
            }
            var range_total = Q.zero();
            var ssa_total = Q.zero();
            var wire_total = Q.zero();
            const scratch = try self.allocator.alloc(Q, if (batched) 3 * CHUNK_ROWS * FRACTIONS else 0);
            defer self.allocator.free(scratch);
            var chunk_start: usize = 0;
            while (chunk_start < n) : (chunk_start += CHUNK_ROWS) {
                const chunk_end = @min(n, chunk_start + CHUNK_ROWS);
                const count = (chunk_end - chunk_start) * FRACTIONS;
                const denominators = if (batched) scratch[0..count] else scratch;
                const inverses = if (batched) scratch[count .. 2 * count] else scratch;
                const numerators = if (batched) scratch[2 * count .. 3 * count] else scratch;
                if (batched) {
                    for (chunk_start..chunk_end) |index| {
                        const view = View{ .source = self, .physical = R.trace.physical(index, self.log_size) };
                        for (0..FRACTIONS) |slot| {
                            const fraction = if (slot < L.SSA_FRACTIONS) Eq.fraction(Q, &view, self.public(), ch, .ssa, slot) else Eq.fraction(Q, &view, self.public(), ch, .wire, 0);
                            const at = (index - chunk_start) * FRACTIONS + slot;
                            numerators[at] = fraction[0];
                            // A zero-weight term has no inversion obligation in
                            // the scalar producer. Preserve its pole behavior.
                            denominators[at] = if (fraction[0].isZero()) Q.one() else fraction[1];
                        }
                    }
                    try core.fields.batchInverseInPlace(Q, denominators, inverses);
                }
                for (chunk_start..chunk_end) |index| {
                    const physical = R.trace.physical(index, self.log_size);
                    const view = View{ .source = self, .physical = physical };
                    if (role == .arithmetic) {
                        for (0..L.RANGE_BATCHES) |batch| {
                            for (0..2) |lane| {
                                const query = 2 * batch + lane;
                                if (query < Micro.BYTE_QUERIES) {
                                    if (index < self.inputs.len * D.STEPS) {
                                        const column = if (query < 32) Micro.RESULT + query else if (query < 32 + Micro.G.q_bytes) Micro.QUOTIENT + query - 32 else Micro.DISTANCE + query - 32 - Micro.G.q_bytes;
                                        range_total = range_total.add(bytes[self.main[column * n + physical].v]);
                                    }
                                } else if (query == Micro.BYTE_QUERIES) {
                                    range_total = range_total.sub(bytes[index % 256].mul(Q.fromBase(self.main[L.BYTE_MULT * n + physical])));
                                } else {
                                    const carry = query - Micro.BYTE_QUERIES - 1;
                                    if (carry < Micro.G.carries) {
                                        if (index < self.inputs.len * D.STEPS) range_total = range_total.add(carries[self.main[(Micro.CARRY + carry) * n + physical].v]);
                                    } else if (carry == Micro.G.carries) range_total = range_total.sub(carries[index % Micro.CARRY_LIMIT].mul(Q.fromBase(self.main[L.CARRY_MULT * n + physical])));
                                }
                            }
                            store(out, n, physical, L.COORDINATES * batch, range_total);
                        }
                    }
                    for (0..L.SSA_BATCHES) |batch| {
                        for (0..2) |lane| {
                            const slot = 2 * batch + lane;
                            if (batched) {
                                if (slot < L.SSA_FRACTIONS) {
                                    const at = (index - chunk_start) * FRACTIONS + slot;
                                    ssa_total = ssa_total.add(numerators[at].mul(inverses[at]));
                                }
                            } else {
                                const f = Eq.fraction(Q, &view, self.public(), ch, .ssa, 2 * batch + lane);
                                if (!f[0].isZero()) ssa_total = ssa_total.add(f[0].mul(try f[1].inv()));
                            }
                        }
                        store(out, n, physical, L.SSA_FIRST + L.COORDINATES * batch, ssa_total);
                    }
                    if (batched) {
                        const at = (index - chunk_start) * FRACTIONS + L.SSA_FRACTIONS;
                        wire_total = wire_total.add(numerators[at].mul(inverses[at]));
                    } else {
                        const wire = Eq.fraction(Q, &view, self.public(), ch, .wire, 0);
                        if (!wire[0].isZero()) wire_total = wire_total.add(wire[0].mul(try wire[1].inv()));
                    }
                    store(out, n, physical, L.WIRE_FIRST, wire_total);
                }
            }
            if (!range_total.isZero()) return error.TowerRangeClaimNotClosed;
            for (0..L.SSA_BATCHES) |batch| center(out, n, L.SSA_FIRST + L.COORDINATES * batch, ssa_total);
            center(out, n, L.WIRE_FIRST, wire_total);
            self.interaction = out;
            return .{ .ssa = ssa_total, .wire = wire_total };
        }
    };
}

fn store(data: []M, n: usize, row: usize, start: usize, value: anytype) void {
    for (value.toM31Array(), 0..) |v, c| data[(start + c) * n + row] = v;
}
fn center(data: []M, n: usize, start: usize, sum: anytype) void {
    for (sum.toM31Array(), 0..) |v, c| {
        for (0..n) |r| data[(start + c) * n + r] = data[(start + c) * n + r].sub(v);
    }
}

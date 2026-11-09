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
        const Retained = if (role == .frontier) Input else Micro.Advice;
        allocator: std.mem.Allocator,
        log_size: u32,
        first_id: u32,
        call_count: u32,
        interaction_generated: bool = false,
        advice_retired: bool = false,
        inputs: []Retained,
        byte_counts: [256]u32,
        carry_counts: []u32,
        fixed: []M,
        main: []M,
        interaction: []M = &.{},
        pub fn init(a: std.mem.Allocator, inputs: []const Input, first: u32, log: u32) !Self {
            return initImpl(a, inputs, first, log, true);
        }
        /// Reuse independently committed immutable FIXED setup. Native fixed
        /// rows are cheap source-owned expressions, never mutable input advice.
        pub fn initWithoutFixed(a: std.mem.Allocator, inputs: []const Input, first: u32, log: u32) !Self {
            return initImpl(a, inputs, first, log, false);
        }
        fn initImpl(a: std.mem.Allocator, inputs: []const Input, first: u32, log: u32, comptime keep_fixed: bool) !Self {
            const call_count = std.math.cast(u32, inputs.len) orelse return error.TowerGeometry;
            try L.validateGeometry(call_count, first, log);
            const n = @as(usize, 1) << @intCast(log);
            const copy = try a.alloc(Retained, inputs.len);
            errdefer a.free(copy);
            const preprocessing = if (keep_fixed) try fixed(a, role, log) else try a.alloc(M, 0);
            errdefer a.free(preprocessing);
            const main = try a.alloc(M, L.MAIN * n);
            errdefer a.free(main);
            @memset(main, M.zero());
            var byte_counts: [256]u32 = @splat(0);
            const carry_counts = try a.alloc(u32, if (role == .arithmetic) Micro.CARRY_LIMIT else 0);
            errdefer a.free(carry_counts);
            @memset(carry_counts, 0);
            for (inputs, 0..) |*input, call| {
                if (role == .frontier) {
                    copy[call] = input.*;
                    for (0..D.INPUTS) |step| {
                        const row = S.frontierRow(input, step);
                        const physical = R.trace.physical(call * D.INPUTS + step, log);
                        for (row, 0..) |value, column| main[column * n + physical] = M.fromCanonical(value);
                    }
                } else {
                    copy[call] = .{ .values = D.evaluate(input), .quotients = undefined, .carries = undefined };
                    const values = &copy[call].values;
                    for (0..D.STEPS) |step| {
                        const row = Micro.fill(step, values);
                        copy[call].record(step, &row);
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
            return .{ .allocator = a, .log_size = log, .first_id = first, .call_count = call_count, .inputs = copy, .fixed = preprocessing, .main = main, .byte_counts = byte_counts, .carry_counts = carry_counts };
        }
        pub fn deinit(self: *Self) void {
            const a = self.allocator;
            a.free(self.inputs);
            a.free(self.carry_counts);
            a.free(self.fixed);
            a.free(self.main);
            a.free(self.interaction);
            self.* = undefined;
        }
        pub fn size(self: *const Self) usize {
            return @as(usize, 1) << @intCast(self.log_size);
        }
        pub fn public(self: *const Self) @import("../../evaluation.zig").CallSpanFor(Q) {
            return .{ .calls = self.call_count, .first_id = self.first_id };
        }
        /// Ownership transfers only after the caller has allocated all commit
        /// headers/backings. Advice and range counts remain owned by Source.
        pub fn takeMain(self: *Self) ![]M {
            if (self.main.len == 0) return error.TowerMainAlreadyReleased;
            const data = self.main;
            self.main = &.{};
            return data;
        }
        pub fn releaseFixed(self: *Self) void {
            self.allocator.free(self.fixed);
            self.fixed = &.{};
        }
        /// After INTER is committed, authenticated claims/PCS retain the
        /// obligations. No source operation is allowed to regenerate it.
        pub fn releaseAdvice(self: *Self) !void {
            if (self.advice_retired) return error.TowerAdviceRetired;
            if (!self.interaction_generated) return error.TowerInteractionNotGenerated;
            self.allocator.free(self.inputs);
            self.inputs = &.{};
            self.allocator.free(self.carry_counts);
            self.carry_counts = &.{};
            self.byte_counts = @splat(0);
            self.advice_retired = true;
        }
        pub fn retainedAdviceBytes(self: *const Self) usize {
            return self.inputs.len * @sizeOf(Retained) + @sizeOf(@TypeOf(self.byte_counts)) + self.carry_counts.len * @sizeOf(u32);
        }
        fn replayMain(self: *const Self, index: usize) [L.MAIN]u32 {
            var out: [L.MAIN]u32 = @splat(0);
            const active_rows = self.inputs.len * S.period(role);
            if (index < active_rows) {
                const call = index / S.period(role);
                const step = index % S.period(role);
                if (role == .frontier) out = S.frontierRow(&self.inputs[call], step) else out[0..Micro.MAIN].* = self.inputs[call].replay(step);
            }
            if (role == .arithmetic) {
                if (index < self.byte_counts.len) out[L.BYTE_MULT] = self.byte_counts[index];
                if (index < self.carry_counts.len) out[L.CARRY_MULT] = self.carry_counts[index];
            }
            return out;
        }
        fn viewAt(self: *const Self, index: usize, row: *[L.MAIN]u32, preprocessing: *[S.FIXED]u32) View {
            if (self.main.len == 0) row.* = self.replayMain(index);
            if (self.fixed.len == 0) preprocessing.* = S.fixedRow(role, index, self.log_size);
            return .{ .source = self, .physical = R.trace.physical(index, self.log_size), .row = if (self.main.len == 0) row else null, .preprocessing = if (self.fixed.len == 0) preprocessing else null };
        }
        pub const View = struct {
            source: *const Self,
            physical: usize,
            row: ?*const [L.MAIN]u32 = null,
            preprocessing: ?*const [S.FIXED]u32 = null,
            pub fn fixed(self: *const @This(), c: usize) Q {
                return Q.fromBase(if (self.preprocessing) |values| M.fromCanonical(values[c]) else self.source.fixed[c * self.source.size() + self.physical]);
            }
            pub fn main(self: *const @This(), c: usize) Q {
                return Q.fromBase(self.mainBase(c));
            }
            pub fn mainBase(self: *const @This(), c: usize) M {
                return if (self.row) |values| M.fromCanonical(values[c]) else self.source.main[c * self.source.size() + self.physical];
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
            if (self.advice_retired) return error.TowerAdviceRetired;
            if (self.interaction_generated or self.interaction.len != 0) return error.TowerInteractionAlreadyGenerated;
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
                        var replay: [L.MAIN]u32 = undefined;
                        var preprocessing: [S.FIXED]u32 = undefined;
                        const view = self.viewAt(index, &replay, &preprocessing);
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
                    var replay: [L.MAIN]u32 = undefined;
                    var preprocessing: [S.FIXED]u32 = undefined;
                    const view = self.viewAt(index, &replay, &preprocessing);
                    if (role == .arithmetic) {
                        for (0..L.RANGE_BATCHES) |batch| {
                            for (0..2) |lane| {
                                const query = 2 * batch + lane;
                                if (query < Micro.BYTE_QUERIES) {
                                    if (index < self.inputs.len * D.STEPS) {
                                        const column = if (query < 32) Micro.RESULT + query else if (query < 32 + Micro.G.q_bytes) Micro.QUOTIENT + query - 32 else Micro.DISTANCE + query - 32 - Micro.G.q_bytes;
                                        range_total = range_total.add(bytes[view.mainBase(column).v]);
                                    }
                                } else if (query == Micro.BYTE_QUERIES) {
                                    range_total = range_total.sub(bytes[index % 256].mul(Q.fromBase(view.mainBase(L.BYTE_MULT))));
                                } else {
                                    const carry = query - Micro.BYTE_QUERIES - 1;
                                    if (carry < Micro.G.carries) {
                                        if (index < self.inputs.len * D.STEPS) range_total = range_total.add(carries[view.mainBase(Micro.CARRY + carry).v]);
                                    } else if (carry == Micro.G.carries) range_total = range_total.sub(carries[index % Micro.CARRY_LIMIT].mul(Q.fromBase(view.mainBase(L.CARRY_MULT))));
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
            self.interaction_generated = true;
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

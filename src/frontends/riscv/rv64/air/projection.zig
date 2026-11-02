//! Verifier-derived linear substitution. No witness values select the layout.
//! Zero-only words/carries are omitted; bytes and bounded integers are linear
//! combinations of committed bits. Fixed columns are constant-folded/deduplicated.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const E = @import("evaluation.zig");
const L = E.L;
const R = @import("rows.zig");
const S = @import("statement.zig");
const zero = std.math.maxInt(u16);
const derived = zero - 1;
pub const Projection = struct {
    support: L.Support,
    fixed_map: [L.fixed.COUNT]u16,
    fixed_constants: [L.fixed.COUNT]M,
    fixed_sources: [L.fixed.COUNT]u16,
    main_map: [L.MAIN]u16,
    main_sources: [L.MAIN]u16,
    fixed_count: usize = 0,
    main_count: usize = 0,

    pub fn init(a: std.mem.Allocator, public: S.Statement, metadata: S.Metadata, size: usize) !Projection {
        try metadata.validate(public);
        if (size < 32 or size > S.MAX_STEPS or !std.math.isPowerOfTwo(size) or size < public.steps) return error.InvalidRv64ProjectionGeometry;
        var result: Projection = undefined;
        result.support = .{ .words = @splat(false), .carries = @splat(false), .slots = @splat(false), .shifts = false, .product = false };
        result.fixed_count = 0;
        result.main_count = 0;
        result.main_map = @splat(zero);
        const rows = try a.alloc(R.Fixed, size);
        defer a.free(rows);
        for (rows, 0..) |*row, i| row.* = try R.fixedRow(public, metadata, i, size);
        for (0..L.fixed.COUNT) |c| {
            const first = rows[0][c];
            var constant = true;
            for (rows) |row| if (!row[c].eql(first)) {
                constant = false;
                break;
            };
            result.fixed_constants[c] = first;
            if (constant) {
                result.fixed_map[c] = zero;
                continue;
            }
            var duplicate: ?u16 = null;
            for (0..result.fixed_count) |j| {
                var same = true;
                for (rows) |row| if (!row[c].eql(row[result.fixed_sources[j]])) {
                    same = false;
                    break;
                };
                if (same) {
                    duplicate = @intCast(j);
                    break;
                }
            }
            if (duplicate) |j| {
                result.fixed_map[c] = j;
            } else {
                result.fixed_map[c] = @intCast(result.fixed_count);
                result.fixed_sources[result.fixed_count] = @intCast(c);
                result.fixed_count += 1;
            }
        }
        // Keep a word only when its public enable is nonzero somewhere.
        for (0..L.WORDS) |w| {
            var active = false;
            for (rows) |row| active = active or !row[L.fixed.word_start + w].isZero();
            result.support.words[w] = active;
            if (!active) continue;
            const word: L.Word = @enumFromInt(w);
            for (0..8) |i| result.main_map[L.byte(word, i)] = derived;
            for (0..64) |i| result.keep(L.bit(word, i));
        }
        for (0..L.CARRIES) |i| {
            var active = false;
            for (rows) |row| active = active or !row[L.fixed.carry_start + i].isZero();
            result.support.carries[i] = active;
            if (active) result.keep(L.carry_start + i);
        }
        // Auxiliary scalar fields stay explicit here. Derive bounded values from
        // their bits without changing the polynomial degree or range argument.
        for (L.product_carry_start..L.MAIN) |c| result.keep(c);
        for (0..16) |i| result.main_map[L.productCarry(i)] = derived;
        for (0..4) |slot| {
            result.main_map[L.previousClock(slot)] = derived;
            result.main_map[L.gap(slot)] = derived;
        }
        var product = false;
        var shift64 = false;
        var shift32 = false;
        for (metadata.path) |pc| {
            const instruction = try public.instruction(pc);
            const op = instruction.opcode;
            const ops = @import("operations.zig");
            product = product or ops.mul(op) or ops.div(op);
            shift64 = shift64 or (ops.shift(op) and !ops.word(op));
            shift32 = shift32 or (ops.shift(op) and ops.word(op));
        }
        result.support.product = product;
        result.support.shifts = shift64 or shift32;
        if (!product) for (L.product_carry_start..L.shift_start) |c| {
            result.main_map[c] = zero;
        };
        for (0..6) |stage| for (0..64) |i| {
            if (!shift64 and !(shift32 and stage < 5 and i < 32)) result.main_map[L.shift(stage, i)] = zero;
        };
        for (0..4) |slot| {
            var active = false;
            for (rows) |row| active = active or !row[L.fixed.slot_start + slot].isZero();
            result.support.slots[slot] = active;
            if (!active) for (L.previousClock(slot)..L.gap(slot) + 1 + L.CLOCK_BITS) |c| {
                result.main_map[c] = zero;
            };
        }
        // Compact again after replacing bounded scalar columns with aliases.
        result.main_count = 0;
        for (&result.main_map, 0..) |*entry, c| if (entry.* != zero and entry.* != derived) {
            entry.* = @intCast(result.main_count);
            result.main_sources[result.main_count] = @intCast(c);
            result.main_count += 1;
        };
        return result;
    }
    fn keep(self: *Projection, c: usize) void {
        self.main_map[c] = 0;
    }
    pub fn fixedValue(self: *const Projection, logical: usize, physical: []const Q) Q {
        const entry = self.fixed_map[logical];
        return if (entry == zero) Q.fromBase(self.fixed_constants[logical]) else physical[entry];
    }
    pub fn inflateMain(self: *const Projection, physical: []const Q) E.Main {
        std.debug.assert(physical.len == self.main_count);
        var result: E.Main = @splat(Q.zero());
        for (&result, self.main_map) |*value, entry| if (entry != zero and entry != derived) {
            value.* = physical[entry];
        };
        for (0..L.WORDS) |w| {
            const word: L.Word = @enumFromInt(w);
            for (0..8) |i| result[L.byte(word, i)] = reconstruct(&result, L.bit(word, 8 * i), 8);
        }
        for (0..16) |i| result[L.productCarry(i)] = reconstruct(&result, L.productCarry(i) + 1, 11);
        for (0..4) |slot| {
            result[L.previousClock(slot)] = reconstruct(&result, L.previousClock(slot) + 1, L.CLOCK_BITS);
            result[L.gap(slot)] = reconstruct(&result, L.gap(slot) + 1, L.CLOCK_BITS);
        }
        return result;
    }
    pub fn inflateFixed(self: *const Projection, physical: []const Q) E.Fixed {
        std.debug.assert(physical.len == self.fixed_count);
        var result: E.Fixed = undefined;
        for (&result, 0..) |*value, i| value.* = self.fixedValue(i, physical);
        return result;
    }
};
fn reconstruct(values: *const E.Main, start: usize, count: usize) Q {
    var result = Q.zero();
    for (0..count) |i| result = result.add(values[start + i].mul(E.q(@as(u32, 1) << @as(u5, @intCast(i)))));
    return result;
}

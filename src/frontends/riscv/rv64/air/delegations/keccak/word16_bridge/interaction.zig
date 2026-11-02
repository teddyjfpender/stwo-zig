//! Bounded active RAM/IO inversion waves; per-call OWNER and used padding facts
//! are inverted once. Tuple/event/prefix order is identical to the scalar oracle.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../../memory/closed_ram/mod.zig");
const LS = @import("../../../memory/load_store_v2/mod.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const Source = @import("source.zig").Source;
const Lookup = @import("lookup.zig").Row;
const M = core.fields.m31.M31;
const Q = T.Q;
const CHUNK: usize = 4096;
fn promote(comptime n: usize, tuple: [n]M) [n]Q {
    var out: [n]Q = undefined;
    for (tuple, &out) |v, *q| q.* = Q.fromBase(v);
    return out;
}
fn ram(ch: T.Challenges, row: Lookup, after: bool) Q {
    return ch.ram.denominatorFor(Q, promote(14, row.ramTuple(after)));
}
fn io(ch: T.Challenges, row: Lookup, lane: usize, after: bool) Q {
    return ch.io.denominator(&promote(11, row.ioTuple(lane, after)));
}
fn meta(s: *const Source, logical: usize) Lookup {
    const index = logical / 25;
    return Lookup.fromCall(if (index < s.calls.len) &s.calls[index] else null, logical % 25, if (index < s.calls.len) s.first_id + @as(u32, @intCast(index)) else 0);
}
pub fn generate(s: *Source, ch: T.Challenges, dict16: []const Q, dict8: []const Q) !T.Claims {
    if (s.interaction.len != 0) return error.InvalidWord16KeccakPhase;
    const n = try T.validateGeometry(s.calls.len, s.first_id, s.log_size);
    for (s.calls) |c| try @import("source.zig").validate(c);
    try LS.interaction.validateDictionary(ch.range16, dict16, 65536);
    try LS.interaction.validateDictionary(ch.range8, dict8, 256);
    const a = s.allocator;
    const out = try a.alloc(M, L.INTERACTION * n);
    errdefer a.free(out);
    var claims = T.Claims.zero();
    claims.range16 = try LS.interaction.countDot(s.counts16, dict16);
    claims.range8 = try LS.interaction.countDot(s.counts8, dict8);
    const owner_input = try a.alloc(Q, s.calls.len + 1);
    defer a.free(owner_input);
    const owners = try a.alloc(Q, s.calls.len + 1);
    defer a.free(owners);
    ownerDenominators(s, ch, owner_input);
    try core.fields.batchInverseInPlace(Q, owner_input, owners);
    const dummy = ram(ch, .{}, false);
    const padding_ram = try dummy.mul(dummy).inv();
    var padding_io: [25]Q = undefined;
    for (0..@min(@as(usize, 25), n - 25 * s.calls.len)) |lane| padding_io[lane] = try io(ch, .{}, lane, false).mul(io(ch, .{}, lane, true)).inv();
    const scratch = try a.alloc(Q, 6 * CHUNK);
    defer a.free(scratch);
    const ram_input = scratch[0..CHUNK];
    const io_input = scratch[CHUNK .. 2 * CHUNK];
    const ram_delta = scratch[2 * CHUNK .. 3 * CHUNK];
    const io_sum = scratch[3 * CHUNK .. 4 * CHUNK];
    const ram_inv = scratch[4 * CHUNK .. 5 * CHUNK];
    const io_inv = scratch[5 * CHUNK .. 6 * CHUNK];
    var range_prefix = [_]Q{ claims.range16.neg(), claims.range8.neg() };
    var begin: usize = 0;
    while (begin < n) : (begin += CHUNK) {
        const count: usize = @min(CHUNK, n - begin);
        const active: usize = if (begin < 25 * s.calls.len) @min(count, 25 * s.calls.len - begin) else 0;
        activeDenominators(s, ch, begin, active, ram_input, io_input, ram_delta, io_sum);
        if (active != 0) {
            try core.fields.batchInverseInPlace(Q, ram_input[0..active], ram_inv[0..active]);
            try core.fields.batchInverseInPlace(Q, io_input[0..active], io_inv[0..active]);
        }
        for (0..count) |i| {
            const logical = begin + i;
            const p = R.trace.physical(logical, s.log_size);
            const row = meta(s, logical);
            const ri = if (i < active) ram_inv[i] else padding_ram;
            const ii = if (i < active) io_inv[i] else padding_io[logical % 25];
            const oi = owners[if (i < active) logical / 25 else s.calls.len];
            R.trace.store(out, n, p, L.RAM, ri);
            R.trace.store(out, n, p, L.OWNER, oi);
            R.trace.store(out, n, p, L.IO, ii);
            if (i < active) {
                claims.ram = claims.ram.add(ram_delta[i].mul(ri));
                claims.io = claims.io.sub(io_sum[i].mul(ii));
                if (logical % 25 == 0) claims.owner = claims.owner.sub(oi);
            }
            R.trace.store(out, n, p, L.RAM + 4, claims.ram);
            R.trace.store(out, n, p, L.OWNER + 4, claims.owner);
            R.trace.store(out, n, p, L.IO + 4, claims.io);
            inline for (.{ row.range16, row.range8 }, 0..) |values, k| {
                const dict = if (k == 0) dict16 else dict8;
                const start = if (k == 0) L.RANGE16 else L.RANGE8;
                for (0..(values.len + 1) / 2) |batch| {
                    const x = dict[values[2 * batch]];
                    var inverse = x;
                    range_prefix[k] = range_prefix[k].add(x);
                    if (2 * batch + 1 < values.len) {
                        const y = dict[values[2 * batch + 1]];
                        inverse = inverse.mul(y);
                        range_prefix[k] = range_prefix[k].add(y);
                    }
                    R.trace.store(out, n, p, start + 4 * batch, inverse);
                }
                R.trace.store(out, n, p, start + 4 * ((values.len + 1) / 2), range_prefix[k]);
            }
        }
    }
    if (!range_prefix[0].isZero() or !range_prefix[1].isZero()) return error.InvalidWord16KeccakCounts;
    R.trace.center(out, n, L.RAM + 4, claims.ram);
    R.trace.center(out, n, L.OWNER + 4, claims.owner);
    R.trace.center(out, n, L.IO + 4, claims.io);
    s.interaction = out;
    a.free(s.calls);
    s.calls = &.{};
    return claims;
}

const E = @import("../../../evaluation.zig");
const F = E.PackedBase;
fn transpose(comptime width: usize, rows: *const [E.LANES][width]M) [width]F {
    var columns: [width]F = undefined;
    for (&columns, 0..) |*column, c| {
        var lanes: [E.LANES]M = undefined;
        for (&lanes, 0..) |*v, lane| v.* = rows[lane][c];
        column.* = F.fromLanes(lanes);
    }
    return columns;
}
fn ownerDenominators(s: *const Source, ch: T.Challenges, output: []Q) void {
    var begin: usize = 0;
    while (begin < output.len) : (begin += E.LANES) {
        const count: usize = @min(E.LANES, output.len - begin);
        var tuples: [E.LANES][19]M = undefined;
        for (&tuples, 0..) |*tuple, lane| {
            const index = begin + lane;
            tuple.* = Lookup.fromCall(if (index < s.calls.len) &s.calls[index] else null, 0, if (index < s.calls.len) s.first_id + @as(u32, @intCast(index)) else 0).ownerTuple();
        }
        const values = ch.owner.denominatorFor(F, transpose(19, &tuples));
        for (output[begin..][0..count], 0..) |*v, lane| v.* = values.lane(lane);
    }
}
fn activeDenominators(s: *const Source, ch: T.Challenges, begin: usize, count: usize, products: []Q, io_products: []Q, deltas: []Q, io_sums: []Q) void {
    var first: usize = 0;
    while (first < count) : (first += E.LANES) {
        const lanes: usize = @min(E.LANES, count - first);
        var before: [E.LANES][14]M = undefined;
        var after: [E.LANES][14]M = undefined;
        var io_before: [E.LANES][11]M = undefined;
        var io_after: [E.LANES][11]M = undefined;
        for (0..E.LANES) |lane| {
            const logical = begin + first + lane;
            const row = meta(s, logical);
            before[lane] = row.ramTuple(false);
            after[lane] = row.ramTuple(true);
            io_before[lane] = row.ioTuple(logical % 25, false);
            io_after[lane] = row.ioTuple(logical % 25, true);
        }
        const b = ch.ram.denominatorFor(F, transpose(14, &before));
        const a = ch.ram.denominatorFor(F, transpose(14, &after));
        const x = E.denominatorFor(F, ch.io.offset, &ch.io.coefficients, &transpose(11, &io_before), true);
        const y = E.denominatorFor(F, ch.io.offset, &ch.io.coefficients, &transpose(11, &io_after), true);
        const product = b.mul(a);
        const difference = a.sub(b);
        const io_product = x.mul(y);
        const io_sum = x.add(y);
        for (0..lanes) |lane| {
            products[first + lane] = product.lane(lane);
            deltas[first + lane] = difference.lane(lane);
            io_products[first + lane] = io_product.lane(lane);
            io_sums[first + lane] = io_sum.lane(lane);
        }
    }
}

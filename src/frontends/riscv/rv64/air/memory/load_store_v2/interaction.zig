//! Packed challenge algebra over retained lookup metadata; no wide row replay.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const R = @import("../closed_ram/mod.zig");
const V1 = @import("../load_store_v1/mod.zig");
const S = @import("source.zig");
const T = @import("types.zig");
const M = T.M;
const Q = T.Q;
const F = E.PackedBase;
const PS = E.PackedSecure;
const CHUNK = 4096;
pub fn validateDictionary(ch: @import("../../providers/scalar_range.zig").Challenges, dict: []const Q, size: usize) !void {
    if (dict.len != size) return error.InvalidLsDictionary;
    for (dict) |v| for (v.toM31Array()) |c| if (c.v >= core.fields.m31.Modulus) return error.InvalidLsDictionary;
    for (0..size / E.LANES) |batch| {
        var lanes: [E.LANES]M = undefined;
        for (&lanes, 0..) |*v, i| v.* = M.fromCanonical(@intCast(batch * E.LANES + i));
        const d = ch.denominatorFor(F, F.fromLanes(lanes));
        const product = d.mul(PS.fromLanes(dict[batch * E.LANES ..][0..E.LANES].*));
        for (0..E.LANES) |i| {
            if (d.lane(i).isZero()) return error.DivisionByZero;
            if (!product.lane(i).eql(Q.one())) return error.InvalidLsDictionary;
        }
    }
}
pub fn countDot(counts: []const u64, dict: []const Q) !Q {
    if (counts.len != dict.len) return error.InvalidLsCounts;
    var sum = Q.zero();
    for (counts, dict) |count, inverse| {
        if (count >= core.fields.m31.Modulus) return error.InvalidLsCounts;
        sum = sum.add(inverse.mulM31(M.fromCanonical(@intCast(count))));
    }
    return sum;
}
fn selectionDictionary(a: std.mem.Allocator, ch: V1.types.SelectionChallenges) ![]Q {
    const input = try a.alloc(Q, 131072);
    defer a.free(input);
    const output = try a.alloc(Q, 131072);
    errdefer a.free(output);
    for (0..131072 / E.LANES) |batch| {
        var facts: [E.LANES][5]M = undefined;
        for (&facts, 0..) |*fact, i| {
            for (V1.selection.fact(batch * E.LANES + i), fact) |v, *x| x.* = M.fromCanonical(v);
        }
        var tuple: [5]F = undefined;
        for (&tuple, 0..) |*v, c| {
            var lanes: [E.LANES]M = undefined;
            for (&lanes, 0..) |*x, i| x.* = facts[i][c];
            v.* = F.fromLanes(lanes);
        }
        const d = ch.denominatorFor(F, tuple);
        for (0..E.LANES) |i| input[batch * E.LANES + i] = d.lane(i);
    }
    try core.fields.batchInverseInPlace(Q, input, output);
    return output;
}
fn transpose(comptime width: usize, rows: *const [E.LANES][width]M) [width]F {
    var columns: [width]F = undefined;
    for (&columns, 0..) |*column, c| {
        var lanes: [E.LANES]M = undefined;
        for (&lanes, 0..) |*v, i| v.* = rows[i][c];
        column.* = F.fromLanes(lanes);
    }
    return columns;
}
fn denominators(meta: []const S.Metadata, ch: T.Challenges, products: []Q, differences: []Q, owners: []Q) void {
    for (0..meta.len / E.LANES) |batch| {
        var before: [E.LANES][14]M = undefined;
        var after: [E.LANES][14]M = undefined;
        var own: [E.LANES][19]M = undefined;
        for (0..E.LANES) |i| {
            const m = meta[batch * E.LANES + i];
            before[i] = m.ramTuple(false);
            after[i] = m.ramTuple(true);
            own[i] = m.ownerTuple();
        }
        const bd = ch.ram.denominatorFor(F, transpose(14, &before));
        const ad = ch.ram.denominatorFor(F, transpose(14, &after));
        const product = bd.mul(ad);
        const delta = ad.sub(bd);
        const owner = ch.owner.denominatorFor(F, transpose(19, &own)).neg();
        for (0..E.LANES) |i| {
            const at = batch * E.LANES + i;
            products[at] = product.lane(i);
            differences[at] = delta.lane(i);
            owners[at] = owner.lane(i);
        }
    }
}
pub fn generate(source: *S.Source, ch: T.Challenges, dict16: []const Q, dict8: []const Q) !T.Claims {
    const n = source.size();
    const a = source.allocator;
    if (source.interaction.len != 0 or source.metadata.len != n) return error.InvalidLsPhase;
    for (source.metadata, 0..) |meta, i| if (meta.flags & ~@as(u8, 7) != 0 or (meta.flags & 1) != @intFromBool(i < source.rows) or meta.selectionIndex() >= 131072) return error.InvalidLsMetadata;
    try validateDictionary(ch.range16, dict16, 65536);
    try validateDictionary(ch.range8, dict8, 256);
    const selection = try selectionDictionary(a, ch.selection);
    defer a.free(selection);
    var claims = T.Claims.zero();
    claims.range16 = try countDot(source.counts16, dict16);
    claims.range8 = try countDot(source.counts8, dict8);
    claims.selection = try countDot(source.selection_counts, selection);
    const output = try a.alloc(M, 116 * n);
    errdefer a.free(output);
    const scratch = try a.alloc(Q, 5 * CHUNK);
    defer a.free(scratch);
    var p16 = claims.range16.neg();
    var p8 = claims.range8.neg();
    var ps = claims.selection.neg();
    var start: usize = 0;
    while (start < n) : (start += CHUNK) {
        const count: usize = @min(CHUNK, n - start);
        const product = scratch[0..count];
        const delta = scratch[CHUNK..][0..count];
        const owner = scratch[2 * CHUNK ..][0..count];
        const inv = scratch[3 * CHUNK ..][0..count];
        const invOwner = scratch[4 * CHUNK ..][0..count];
        denominators(source.metadata[start..][0..count], ch, product, delta, owner);
        try core.fields.batchInverseInPlace(Q, product, inv);
        try core.fields.batchInverseInPlace(Q, owner, invOwner);
        for (0..count) |i| {
            const logical = start + i;
            const pos = R.trace.physical(logical, source.log_size);
            const meta = source.metadata[logical];
            R.trace.store(output, n, pos, 0, inv[i]);
            claims.ram = claims.ram.add(delta[i].mul(inv[i]).mulM31(meta.active()));
            R.trace.store(output, n, pos, 4, claims.ram);
            R.trace.store(output, n, pos, 8, invOwner[i]);
            claims.owner = claims.owner.add(invOwner[i].mulM31(meta.active()));
            R.trace.store(output, n, pos, 12, claims.owner);
            for (0..18) |batch| {
                const x = dict16[meta.range16[2 * batch]];
                var inverse = x;
                p16 = p16.add(x);
                if (2 * batch + 1 < 35) {
                    const y = dict16[meta.range16[2 * batch + 1]];
                    inverse = inverse.mul(y);
                    p16 = p16.add(y);
                }
                R.trace.store(output, n, pos, 16 + 4 * batch, inverse);
            }
            R.trace.store(output, n, pos, 88, p16);
            for (0..3) |batch| {
                const x = dict8[meta.range8[2 * batch]];
                var inverse = x;
                p8 = p8.add(x);
                if (2 * batch + 1 < 5) {
                    const y = dict8[meta.range8[2 * batch + 1]];
                    inverse = inverse.mul(y);
                    p8 = p8.add(y);
                }
                R.trace.store(output, n, pos, 92 + 4 * batch, inverse);
            }
            R.trace.store(output, n, pos, 104, p8);
            const selected = selection[meta.selectionIndex()];
            ps = ps.add(selected);
            R.trace.store(output, n, pos, 108, selected);
            R.trace.store(output, n, pos, 112, ps);
        }
    }
    if (!p16.isZero() or !p8.isZero() or !ps.isZero()) return error.InvalidLsCounts;
    R.trace.center(output, n, 4, claims.ram);
    R.trace.center(output, n, 12, claims.owner);
    source.interaction = output;
    a.free(source.metadata);
    source.metadata = &.{};
    return claims;
}

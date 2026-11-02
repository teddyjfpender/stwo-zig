//! Strict enabled pair inverses and one circular prefix; private until complete.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const K = @import("../layout.zig");
const L = @import("layout.zig");
const E = @import("../equations.zig");
const T = @import("trace.zig");
const I = @import("../interaction.zig");
const tables = @import("../../../../../air/guest_precompile/keccakf_tables.zig");
const tuples = @import("../../../../../air/guest_precompile/keccakf_lookup_tuples.zig");
const physical = @import("../../../witness.zig").physical;
pub fn generate(trace: *T.Trace, ch: E.Challenges) !Q {
    if (trace.interaction.len != 0) return error.KeccakInteractionAlreadyGenerated;
    try trace.base.validateMetadata();
    const a = trace.allocator;
    const n = trace.base.size();
    const dictionary = try a.alloc(Q, 2 * (8192 + 1024));
    defer a.free(dictionary);
    const denominators = dictionary[0 .. 8192 + 1024];
    const inverses = dictionary[8192 + 1024 ..];
    for ([_]tables.Kind{ .chi, .xor5 }) |kind| {
        const offset: usize = if (kind == .chi) 0 else 8192;
        const lookup = if (kind == .chi) ch.chi else ch.xor5;
        for (denominators[offset..][0..tables.size(kind)], 0..) |*v, index| {
            const tuple = try tables.tupleAt(kind, index);
            var d = lookup.offset;
            for (tuple, lookup.coefficients) |x, c| d = d.sub(c.mulM31(x));
            v.* = d;
        }
    }
    try core.fields.batchInverseInPlace(Q, denominators, inverses);
    const data = try a.alloc(M, L.INTERACTION * n);
    errdefer a.free(data);
    @memset(data, M.zero());
    var sum = Q.zero();
    for (0..n) |logical| {
        const r = physical(logical, trace.base.log_size);
        const main = try trace.base.metadataRow(logical);
        var fixed: [K.FIXED]M = undefined;
        for (&fixed, 0..) |*v, c| v.* = trace.base.fixed[c * n + r];
        const state = main[0..K.STATE];
        const row = E.RowFor(M){ .main = &main, .fixed = &fixed, .state_minus_two = state, .state_minus_one = state, .state_plus_one = state, .state_plus_two = state };
        if (E.roundActiveFor(M, row).isOne()) {
            const next = try trace.base.metadataRow((logical + 1) % n);
            for (0..L.ROUND_PAIRS) |pair| {
                var inv: [2]Q = undefined;
                for (&inv, 0..) |*value, side| {
                    const event = 2 * pair + side;
                    const kind: tables.Kind = if (event < K.STATE) .chi else .xor5;
                    const tuple = if (kind == .chi) tuples.chi(M, state, main[K.STATE..K.ACTIVE_A], next[0..K.STATE], fixed[2..26], event) else tuples.xor5(M, state, main[K.STATE..K.ACTIVE_A], event - K.STATE);
                    value.* = inverses[(if (kind == .chi) @as(usize, 0) else 8192) + try tables.index(kind, &tuple)];
                }
                I.store(data, n, r, pair, inv[0].mul(inv[1]));
                sum = sum.sub(inv[0]).sub(inv[1]);
            }
        }
        if (E.ioActiveFor(M, row).isOne()) {
            var io_d: [K.IO_LANES]Q = undefined;
            var io_i: [K.IO_LANES]Q = undefined;
            for (&io_d, 0..) |*v, lane| {
                const tuple = E.ioTupleFor(M, row, lane);
                var d = ch.io.offset;
                for (tuple, ch.io.coefficients) |x, c| d = d.sub(c.mulM31(x));
                v.* = d;
            }
            try core.fields.batchInverseInPlace(Q, &io_d, &io_i);
            for (0..L.IO_PAIRS) |pair| {
                const i = 2 * pair;
                const other = if (i + 1 < K.IO_LANES) io_i[i + 1] else Q.one();
                I.store(data, n, r, L.ROUND_PAIRS + pair, io_i[i].mul(other));
                sum = sum.add(io_i[i]);
                if (i + 1 < K.IO_LANES) sum = sum.add(io_i[i + 1]);
            }
        }
        I.store(data, n, r, L.PAIRS, sum);
    }
    trace.interaction = data;
    return sum;
}

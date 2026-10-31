//! Column-stitching witness: all row/batch deltas close one circular sum.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const waves = @import("interaction_parallel.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const L = @import("layout.zig");
const E = @import("equations.zig");
const T = @import("trace.zig");
const physical = @import("../../witness.zig").physical;
const tables = @import("../../../../air/guest_precompile/keccakf_tables.zig");
const tuple_algebra = @import("../../../../air/guest_precompile/keccakf_lookup_tuples.zig");
pub const Counts = struct {
    chi: [8192]u64 = @splat(0),
    xor5: [1024]u64 = @splat(0),
    pub fn fromTrace(trace: *const T.Trace) !Counts {
        try trace.validateMetadata();
        var counts = Counts{};
        const n = trace.size();
        for (0..trace.metadata.len) |logical| {
            const r = physical(logical, trace.log_size);
            var selectors: [24]M = undefined;
            var active = false;
            for (&selectors, 0..) |*s, i| {
                s.* = trace.fixed[(2 + i) * n + r];
                active = active or !s.isZero();
            }
            active = active and (trace.metadata[logical].flags & 1 != 0);
            if (!active) continue;
            const main = try trace.metadataRow(logical);
            const next = try trace.metadataRow((logical + 1) % n);
            for (0..L.STATE) |event| {
                const tuple = tuple_algebra.chi(M, main[0..L.STATE], main[L.STATE..L.ACTIVE_A], next[0..L.STATE], &selectors, event);
                const index = try tables.index(.chi, &tuple);
                counts.chi[index] += 1;
            }
            for (0..L.PARITY) |event| {
                const tuple = tuple_algebra.xor5(M, main[0..L.STATE], main[L.STATE..L.ACTIVE_A], event);
                const index = try tables.index(.xor5, &tuple);
                counts.xor5[index] += 1;
            }
        }
        return counts;
    }
};
pub const Options = struct {
    pool: ?*engine.work_pool.WorkPool = null,
    recorder: ?*engine.stage_profile.Recorder = null,
};
pub fn generate(trace: *T.Trace, ch: E.Challenges) !Q {
    return generateWithOptions(trace, ch, .{ .pool = engine.work_pool.currentScopedPool() });
}
pub fn generateWithOptions(trace: *T.Trace, ch: E.Challenges, options: Options) !Q {
    return generateImpl(trace, ch, options, .{}, .triple_v2);
}
/// Explicit experimental profile entry. Existing source/coordinator APIs always
/// call generateWithOptions and retain triple-v2 geometry and transcript.
pub fn generateForPolicy(trace: *T.Trace, ch: E.Challenges, policy: E.BatchPolicy, options: Options) !Q {
    return generateImpl(trace, ch, options, .{}, policy);
}
fn generateImpl(trace: *T.Trace, ch: E.Challenges, options: Options, faults: waves.Faults, policy: E.BatchPolicy) !Q {
    if (trace.interaction.len != 0) return error.KeccakInteractionAlreadyGenerated;
    try trace.validateMetadata();
    const n = trace.size();
    const workers = try waves.workerCount(n, options.pool);
    // Tables and consumer share this exact qualified tuple encoding. Only the
    // native witness recipe uses the dictionary; AIR/OODS equations are unchanged.
    const dictionary_size = tables.size(.chi) + tables.size(.xor5);
    const dictionary = try trace.allocator.alloc(Q, 2 * dictionary_size);
    defer trace.allocator.free(dictionary);
    const denominators = dictionary[0..dictionary_size];
    const inverses = dictionary[dictionary_size..];
    {
        var dictionary_stage = try engine.stage_profile.StageScope.begin(options.recorder, "keccak_interaction_dictionary", "Keccak inverse dictionary");
        defer dictionary_stage.end();
        for ([_]tables.Kind{ .chi, .xor5 }) |kind| {
            const offset: usize = if (kind == .chi) 0 else tables.size(.chi);
            const challenges = if (kind == .chi) ch.chi else ch.xor5;
            for (denominators[offset..][0..tables.size(kind)], 0..) |*value, i| {
                const base = try tables.tupleAt(kind, i);
                var tuple: [6]Q = undefined;
                for (&tuple, base) |*v, b| v.* = Q.fromBase(b);
                value.* = challenges.denominator(&tuple);
            }
        }
        try core.fields.batchInverseInPlace(Q, denominators, inverses);
    }
    const data = try trace.allocator.alloc(M, policy.interactionCount() * n);
    errdefer trace.allocator.free(data);
    if (workers > 1) @import("../../native_output_pages.zig").prepare(data);
    const prepared = Prepared{ .trace = trace, .ch = ch, .inverses = inverses, .data = data, .batch_policy = policy };
    const sum = if (workers == 1) blk: {
        var stage = try engine.stage_profile.StageScope.begin(options.recorder, "keccak_interaction_prefix", "Keccak serial lookup prefix");
        defer stage.end();
        break :blk try prepared.fillRange(0, n);
    } else try waves.generate(&prepared, options.pool.?, workers, options.recorder, faults);
    trace.interaction = data;
    return sum;
}
pub const Prepared = struct {
    batch_policy: E.BatchPolicy = .triple_v2,
    trace: *const T.Trace,
    ch: E.Challenges,
    inverses: []const Q,
    data: []M,
    pub fn fillRange(self: *const Prepared, start: usize, end: usize) !Q {
        var sum = Q.zero();
        switch (self.batch_policy) {
            .triple_v2 => for (start..end) |logical| try self.fillRowBatch(3, logical, &sum),
            .quartet_v3 => for (start..end) |logical| try self.fillRowBatch(4, logical, &sum),
        }
        return sum;
    }
    fn fillRowBatch(self: *const Prepared, comptime width: usize, logical: usize, sum: *Q) !void {
        const n = self.trace.size();
        const r = physical(logical, self.trace.log_size);
        var fixed: [L.FIXED]M = undefined;
        for (&fixed, 0..) |*v, c| v.* = self.trace.fixed[c * n + r];
        const main = try self.trace.metadataRow(logical);
        var round = M.zero();
        for (fixed[2..26]) |selector| round = round.add(selector);
        round = round.mul(main[L.ACTIVE_A]);
        if (!round.isZero()) {
            const next = try self.trace.metadataRow((logical + 1) % n);
            for (0..L.LOOKUPS / width) |batch| {
                for (0..width) |i| {
                    const event = width * batch + i;
                    const kind: tables.Kind = if (event < L.STATE) .chi else .xor5;
                    const tuple = if (kind == .chi)
                        tuple_algebra.chi(M, main[0..L.STATE], main[L.STATE..L.ACTIVE_A], next[0..L.STATE], fixed[2..26], event)
                    else
                        tuple_algebra.xor5(M, main[0..L.STATE], main[L.STATE..L.ACTIVE_A], event - L.STATE);
                    const offset: usize = if (kind == .chi) 0 else tables.size(.chi);
                    const inverse = self.inverses[offset + try tables.index(kind, &tuple)];
                    sum.* = sum.*.sub(if (round.isOne()) inverse else inverse.mulM31(round));
                }
                store(self.data, n, r, batch, sum.*);
            }
        } else for (0..L.LOOKUPS / width) |batch| store(self.data, n, r, batch, sum.*);
        const io = main[L.ACTIVE_A].mul(fixed[0].add(fixed[27])).add(main[L.ACTIVE_B].mul(fixed[1].add(fixed[28])));
        var io_inverses: [L.IO_LANES]Q = undefined;
        if (!io.isZero()) {
            var io_denominators: [L.IO_LANES]Q = undefined;
            ioDenominators(&main, &fixed, self.ch.io, &io_denominators);
            try core.fields.batchInverseInPlace(Q, &io_denominators, &io_inverses);
        }
        for (0..(L.IO_LANES + width - 1) / width) |local| {
            if (!io.isZero()) for (0..width) |i| if (width * local + i < L.IO_LANES) {
                const inverse = io_inverses[width * local + i];
                sum.* = sum.*.add(if (io.isOne()) inverse else inverse.mulM31(io));
            };
            store(self.data, n, r, L.LOOKUPS / width + local, sum.*);
        }
    }
};
fn ioDenominators(main: *const [L.MAIN]M, fixed: *const [L.FIXED]M, ch: E.Io, out: *[L.IO_LANES]Q) void {
    var qm: [L.MAIN]Q = undefined;
    var qf: [L.FIXED]Q = undefined;
    for (&qm, main) |*v, b| v.* = Q.fromBase(b);
    for (&qf, fixed) |*v, b| v.* = Q.fromBase(b);
    const state = qm[0..L.STATE];
    const row = E.Row{ .main = &qm, .fixed = &qf, .state_minus_two = state, .state_minus_one = state, .state_plus_one = state, .state_plus_two = state };
    for (out, 0..) |*denominator, lane| denominator.* = ch.denominator(&E.ioTuple(row, lane));
}
pub fn store(data: []M, n: usize, row: usize, secure_column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(4 * secure_column + c) * n + row] = v;
}

pub const testing = if (@import("builtin").is_test) struct {
    pub const Faults = waves.Faults;
    pub fn generateWithFaults(trace: *T.Trace, ch: E.Challenges, options: Options, faults: Faults) !Q {
        return generateImpl(trace, ch, options, faults, .triple_v2);
    }
    pub fn generatePolicyWithFaults(trace: *T.Trace, ch: E.Challenges, policy: E.BatchPolicy, options: Options, faults: Faults) !Q {
        return generateImpl(trace, ch, options, faults, policy);
    }
} else struct {};

//! Disjoint quotient row tiles on the admitted shared CPU pool. Inputs are
//! immutable; each tile owns its accumulator cursor and error slot.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const m31 = core.fields.m31;
const pool_mod = engine.work_pool;
const accumulation = engine.air.accumulation;

pub fn For(comptime Spec: type) type {
    return struct {
        const F = Spec.FIXED_COUNT;
        const W = Spec.MAIN_COUNT;
        const I = Spec.INTERACTION_COUNT;
        pub const Values = [F + W + I][]const M;
        pub const Inverses = [1 << Spec.EXPANSION_BITS]M;
        const Tile = struct {
            prepared: Spec.Domain,
            values: *const Values,
            inverses: *const Inverses,
            trace_log: u32,
            eval_log: u32,
            begin: usize,
            end: usize,
            result: accumulation.ColumnAccumulator,
            packed_powers: *const [Spec.CONSTRAINT_COUNT]P,
            failure: ?anyerror = null,

            fn run(self: *Tile) !void {
                // Wide typed AIRs share this row kernel. Their inline masks
                // need compiler evaluation proportional to the main width;
                // this changes no runtime work or admitted degree bound.
                @setEvalBranchQuota(1000 + 128 * W);
                const shift: std.math.Log2Int(usize) = @intCast(self.trace_log);
                var row = self.begin;
                while (row + m31.PACK_WIDTH <= self.end) : (row += m31.PACK_WIDTH) {
                    var prior: [m31.PACK_WIDTH]usize = undefined;
                    var inverse: m31.PackedM31 = undefined;
                    for (&prior, 0..) |*before, lane| {
                        before.* = core.utils.previousBitReversedCircleDomainIndex(row + lane, self.trace_log, self.eval_log);
                        inverse[lane] = self.inverses[(row + lane) >> shift].v;
                    }
                    var fixed: [F]P = undefined;
                    var main: [W]P = undefined;
                    var prior_main: [W]P = @splat(P.zero());
                    var current: [I]P = undefined;
                    var previous: [I]P = undefined;
                    for (&fixed, 0..) |*value, i| value.* = P.fromBase(m31.loadPacked(self.values[i].ptr + row));
                    inline for (0..W) |i| {
                        main[i] = P.fromBase(m31.loadPacked(self.values[F + i].ptr + row));
                        if (Spec.PREVIOUS_MAIN_MASK[i]) prior_main[i] = gather(self.values[F + i], prior);
                    }
                    for (&current, &previous, 0..) |*value, *before, i| {
                        value.* = P.fromBase(m31.loadPacked(self.values[F + W + i].ptr + row));
                        before.* = gather(self.values[F + W + i], prior);
                    }
                    const equations = self.prepared.evaluatePacked(fixed, main, prior_main, current, previous);
                    var folded = P.zero();
                    for (equations, self.packed_powers.*) |equation, power| folded = folded.add(power.mul(equation));
                    const scaled = folded.mulBase(inverse);
                    for (0..m31.PACK_WIDTH) |lane| self.result.accumulate(row + lane, scaled.lane(lane));
                }
                while (row < self.end) : (row += 1) {
                    const prior = core.utils.previousBitReversedCircleDomainIndex(row, self.trace_log, self.eval_log);
                    var fixed: [F]Q = undefined;
                    var main: [W]Q = undefined;
                    var prior_main: [W]Q = @splat(Q.zero());
                    var current: [I]Q = undefined;
                    var previous: [I]Q = undefined;
                    for (&fixed, 0..) |*value, i| value.* = Q.fromBase(self.values[i][row]);
                    inline for (0..W) |i| {
                        main[i] = Q.fromBase(self.values[F + i][row]);
                        if (Spec.PREVIOUS_MAIN_MASK[i]) prior_main[i] = Q.fromBase(self.values[F + i][prior]);
                    }
                    for (&current, &previous, 0..) |*value, *before, i| {
                        value.* = Q.fromBase(self.values[F + W + i][row]);
                        before.* = Q.fromBase(self.values[F + W + i][prior]);
                    }
                    const equations = try self.prepared.evaluate(fixed, main, prior_main, current, previous, @as(u32, 1) << @intCast(self.trace_log));
                    var folded = Q.zero();
                    const powers = self.result.random_coeff_powers;
                    for (equations, 0..) |equation, i| folded = folded.add(powers[powers.len - 1 - i].mul(equation));
                    self.result.accumulate(row, folded.mulM31(self.inverses[row >> shift]));
                }
            }
            fn gather(values: []const M, indices: [m31.PACK_WIDTH]usize) P {
                var lanes: m31.PackedM31 = undefined;
                for (indices, 0..) |index, lane| lanes[lane] = values[index].v;
                return P.fromBase(lanes);
            }
            fn worker(self: *Tile) void {
                self.run() catch |err| {
                    self.failure = err;
                };
            }
        };

        pub fn evaluate(prepared: Spec.Domain, values: *const Values, inverses: *const Inverses, trace_log: u32, eval_log: u32, result: *accumulation.ColumnAccumulator) !void {
            return evaluateWithPool(prepared, values, inverses, trace_log, eval_log, result, pool_mod.getGlobalPool());
        }
        pub fn evaluateWithPool(prepared: Spec.Domain, values: *const Values, inverses: *const Inverses, trace_log: u32, eval_log: u32, result: *accumulation.ColumnAccumulator, requested_pool: ?*pool_mod.WorkPool) !void {
            const size = @as(usize, 1) << @intCast(eval_log);
            var packed_powers: [Spec.CONSTRAINT_COUNT]P = undefined;
            for (&packed_powers, 0..) |*value, index| value.* = P.splat(result.random_coeff_powers[result.random_coeff_powers.len - 1 - index]);
            var first = Tile{ .prepared = prepared, .values = values, .inverses = inverses, .trace_log = trace_log, .eval_log = eval_log, .begin = 0, .end = size, .result = result.*, .packed_powers = &packed_powers };
            const minimum_rows = 1 << 13;
            const active = if (size >= 2 * minimum_rows) requested_pool else null;
            if (active) |pool| {
                const count = @min(pool.availableWorkers(), size / minimum_rows);
                if (count > 1) {
                    var lease = pool.acquire(try pool_mod.WorkerBudget.init(count)) catch |err| switch (err) {
                        error.WorkerBudgetUnavailable => {
                            try first.run();
                            result.next_fresh_index = first.result.next_fresh_index;
                            return;
                        },
                        else => return err,
                    };
                    var group = std.Thread.WaitGroup{};
                    defer {
                        group.wait();
                        lease.completeWave();
                        lease.deinit();
                    }
                    var tiles: [pool_mod.MAX_WORKERS]Tile = undefined;
                    for (tiles[0..count], 0..) |*tile, index| {
                        tile.* = first;
                        tile.begin = size * index / count;
                        tile.end = size * (index + 1) / count;
                        // A fresh zero bucket admits direct stores in every
                        // disjoint tile. Existing buckets remain additive.
                        tile.result.next_fresh_index = if (result.next_fresh_index == 0) tile.begin else null;
                    }
                    for (tiles[1..count]) |*tile| try lease.spawnWg(&group, Tile.worker, .{tile});
                    tiles[0].worker();
                    group.wait();
                    for (tiles[0..count]) |tile| if (tile.failure) |err| return err;
                    result.next_fresh_index = if (result.next_fresh_index == 0) size else null;
                    return;
                }
            }
            try first.run();
            result.next_fresh_index = first.result.next_fresh_index;
        }
    };
}

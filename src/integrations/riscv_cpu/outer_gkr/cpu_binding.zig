//! Joined CPU construction of the existing cyclic Eq/prefix binding.
//! The reference binding_v2 authority and transcript are unchanged. Work is
//! partitioned in logical order for the scan and physical order for writes;
//! this avoids false sharing from bit-reversed scatter between worker chunks.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const B = @import("binding_v2.zig");
const Legacy = @import("binding.zig");
const MP = @import("../logup_gkr/mle_point.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31;
const Pack = core.fields.packed_om31;
const chunk_rows = 4096;

const EqFill = struct {
    high: []const O,
    low: []const O,
    out: []O,
    pub fn runRange(self: *@This(), _: usize, first: usize, end: usize) void {
        const packs = self.low.len / M.PACK_WIDTH;
        for (first..end) |tile| {
            const hi = tile / packs;
            const lo = (tile % packs) * M.PACK_WIDTH;
            Pack.storeNative(self.out[hi * self.low.len + lo ..], Pack.mul(Pack.splat(self.high[hi]), Pack.loadNative(self.low[lo..])));
        }
    }
};

const Scan = struct {
    eq: []const O,
    projection: []const O,
    logical: []O,
    totals: []O,
    log: u32,
    uniform: O,
    pub fn runRange(self: *@This(), _: usize, first: usize, end: usize) void {
        for (first..end) |chunk| {
            var sum = O.zero();
            const begin = chunk * chunk_rows;
            const finish = @min(begin + chunk_rows, self.eq.len);
            var k = begin;
            while (k < finish) : (k += M.PACK_WIDTH) {
                var eq: [M.PACK_WIDTH]O = undefined;
                var projection: [M.PACK_WIDTH]O = undefined;
                inline for (0..M.PACK_WIDTH) |lane| {
                    const p = MP.storageIndex(k + lane, self.log);
                    eq[lane] = self.eq[p];
                    projection[lane] = self.projection[p];
                }
                const product = Pack.mul(Pack.loadNative(&eq), Pack.loadNative(&projection));
                inline for (0..M.PACK_WIDTH) |lane| {
                    sum = sum.add(Pack.lane(product, lane)).sub(self.uniform);
                    self.logical[k + lane] = sum;
                }
            }
            self.totals[chunk] = sum;
        }
    }
};

const Finish = struct {
    logical: []const O,
    carries: []const O,
    out: []O,
    log: u32,
    pub fn runRange(self: *@This(), _: usize, first: usize, end: usize) void {
        for (first..end) |tile| {
            const p = tile * M.PACK_WIDTH;
            var local: [M.PACK_WIDTH]O = undefined;
            var carries: [M.PACK_WIDTH]O = undefined;
            inline for (0..M.PACK_WIDTH) |lane| {
                const k = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p + lane, self.log), self.log);
                local[lane] = self.logical[k];
                carries[lane] = self.carries[k / chunk_rows];
            }
            Pack.storeNative(self.out[p..], Pack.loadNative(&local).add(Pack.loadNative(&carries)));
        }
    }
};

pub fn columns(a: std.mem.Allocator, point: []const O, projection: []const O, target: O) !B.Columns {
    _ = try MP.MleEvalPointFor(O).init(point);
    const log: u32 = @intCast(point.len);
    const rows = @as(usize, 1) << @intCast(log);
    if (projection.len != rows) return error.OuterGkrBindingShape;
    // Small fixtures keep the independent reference construction; large
    // components amortize three joined waves and the additional logical plane.
    if (rows < chunk_rows) return B.columns(a, point, projection, target);
    const high = try Legacy.eqTable(a, point[0..4]);
    defer a.free(high);
    const low = try Legacy.eqTable(a, point[4..]);
    defer a.free(low);
    const eq = try a.alloc(O, rows);
    errdefer a.free(eq);
    var eq_work = EqFill{ .high = high, .low = low, .out = eq };
    _ = engine.lookups.row_work.forEachRange(rows / M.PACK_WIDTH, &eq_work, .{ .min_rows_per_shard = 256 });
    const prefix = try a.alloc(O, rows);
    errdefer a.free(prefix);
    const logical = try a.alloc(O, rows);
    defer a.free(logical);
    const carries = try a.alloc(O, rows / chunk_rows);
    defer a.free(carries);
    var scan = Scan{ .eq = eq, .projection = projection, .logical = logical, .totals = carries, .log = log, .uniform = target.mulM31(try M.M31.fromU64(rows).inv()) };
    _ = engine.lookups.row_work.forEachRange(carries.len, &scan, .{ .min_rows_per_shard = 1 });
    var total = O.zero();
    for (carries) |*carry| {
        const part = carry.*;
        carry.* = total;
        total = total.add(part);
    }
    if (!total.isZero()) return error.OuterGkrTerminalMismatch;
    var finish = Finish{ .logical = logical, .carries = carries, .out = prefix, .log = log };
    _ = engine.lookups.row_work.forEachRange(rows / M.PACK_WIDTH, &finish, .{ .min_rows_per_shard = 256 });
    return .{ .eq = eq, .prefix = prefix };
}

//! Derived public Eq auxiliaries: one physical fill, one shared twiddle tower,
//! then the existing pooled in-place M31 interpolation authority. No PCS work,
//! global caches, witness replay or independent constraint implementation.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const MP = @import("../../../logup_gkr/mle_point.zig");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const Point = MP.MleEvalPointFor(O);
const Poly = engine.poly.circle.CircleCoefficients;
const Pool = engine.work_pool;
pub const COLUMNS = 10;
pub const BLOCK_ROWS = 32;
pub const Plan = struct {
    rows: usize,
    coefficient_bytes: usize,
    twiddle_bytes: usize,
    /// Requested heap only. Fixed stack scheduler/coordinate arrays and the
    /// already-owned pool's worker stacks are separate, bounded overhead.
    peak_requested_heap_bytes: usize,
};
pub fn plan(log: u32) !Plan {
    if (log == 0 or log > 22) return error.InvalidPublicAuxGeometry;
    const rows = @as(usize, 1) << @intCast(log);
    const one = try std.math.mul(usize, rows, @sizeOf(M));
    const coefficients = try std.math.mul(usize, COLUMNS, one);
    // precomputeM31 owns forward and inverse arrays of rows/2 elements.
    return .{ .rows = rows, .coefficient_bytes = coefficients, .twiddle_bytes = one, .peak_requested_heap_bytes = try std.math.add(usize, coefficients, one) };
}
/// p is an index in bit-reversed circle order. Its low bit selects the
/// half-coset; reversal turns trailing carries in the logical coset index
/// into leading equal bits of p. Neither division nor bit reversal is needed.
fn carryIndex(physical: usize, log: u32, rows: usize) usize {
    const bits = if (physical & 1 == 0) (rows - 1) ^ physical else physical;
    return @as(usize, @clz(bits)) - (@bitSizeOf(usize) - log);
}
const Fill = struct {
    columns: *const [COLUMNS][]M,
    coordinates: *const [2][MP.MAX_VARIABLES][8]M,
    rows: usize,
    log: u32,
    pub fn runRange(self: *@This(), _: usize, first: usize, end: usize) void {
        for (first * BLOCK_ROWS..@min(end * BLOCK_ROWS, self.rows)) |physical| {
            const half = physical & 1;
            const values = self.coordinates[half][carryIndex(physical, self.log, self.rows)];
            for (0..8) |c| self.columns[c][physical] = values[c];
            self.columns[8][physical] = if (physical == 0) M.one() else M.zero();
            self.columns[9][physical] = if (physical + 1 == self.rows) M.one() else M.zero();
        }
    }
};
/// `point` is the checked row suffix of the GKR point. Its initial construction
/// rejects coordinates0/1; no new inverse or exception masking is introduced.
/// Returned polynomials independently own their coefficient allocations.
pub fn init(a: std.mem.Allocator, point: *const Point, log: u32, pool: ?*Pool.WorkPool) ![COLUMNS]Poly {
    const geometry = try plan(log);
    if (point.n != log) return error.InvalidPublicAuxGeometry;
    const active_pool = pool orelse Pool.currentScopedPool();
    var binding: ?Pool.ScopedPoolBinding = null;
    if (active_pool) |active| binding = try Pool.ScopedPoolBinding.initIfNeeded(active);
    defer if (binding) |*owner| owner.deinit();
    var coordinates: [2][MP.MAX_VARIABLES][8]M = undefined;
    for (0..log) |i| {
        coordinates[0][i] = point.hc0[i].toM31Array();
        coordinates[1][i] = point.hc1[i].toM31Array();
    }
    var values: [COLUMNS][]M = undefined;
    var allocated: usize = 0;
    errdefer for (values[0..allocated]) |column| a.free(column);
    for (&values) |*column| {
        column.* = try a.alloc(M, geometry.rows);
        allocated += 1;
    }
    var fill = Fill{ .columns = &values, .coordinates = &coordinates, .rows = geometry.rows, .log = log };
    _ = engine.lookups.row_work.forEachRange((geometry.rows + BLOCK_ROWS - 1) / BLOCK_ROWS, &fill, .{ .min_rows_per_shard = 4096 / BLOCK_ROWS });
    const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
    // Use explicit pool FFTs. The separate precomputeM31Parallel API discovers
    // a global pool, so it is deliberately not used by this ownership route.
    var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
    defer engine.poly.twiddles.deinitM31(a, &twiddles);
    try engine.poly.circle.poly.interpolateBuffersWithTwiddlesWithPool(&values, domain, .{ .root_coset = twiddles.root_coset, .twiddles = twiddles.twiddles, .itwiddles = twiddles.itwiddles }, active_pool);
    var out: [COLUMNS]Poly = undefined;
    for (values, &out) |column, *polynomial| polynomial.* = try Poly.initOwned(column);
    return out;
}

//! Evaluate the honest coefficient-backed quotient on its degree-bound
//! canonic domain and extend once for the ordinary FRI commitment.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const SecureColumn = @import("../secure_column.zig").SecureColumnByCoordsFor(O);
const Column = @import("quotient_column_geometry.zig").ColumnEvaluation;
const Poly = @import("../poly/circle/poly.zig");
const Twiddles = @import("../poly/twiddles.zig");
const Pools = @import("../work_pool.zig");
const Canonic = core.poly.circle.canonic.CanonicCoset;

pub fn produce(
    comptime B: type,
    a: std.mem.Allocator,
    trees: anytype,
    points: core.pcs.TreeVec([][]core.circle.CirclePoint(O)),
    samples: core.pcs.TreeVec([][]O),
    alpha: O,
    lifting_log: u32,
    blowup: u32,
    limit: ?usize,
) !?SecureColumn {
    if (blowup != 2 or lifting_log <= blowup + 1) return null;
    const degree_log = lifting_log - blowup;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const meta = arena.allocator();
    const headers = try meta.alloc([]const Column, trees.len);
    for (trees, headers) |tree, *header| {
        const coefficients = tree.coefficients orelse return null;
        if (tree.columns.len != coefficients.len) return error.ShapeMismatch;
        const view = try meta.alloc(Column, coefficients.len);
        for (view, tree.columns, coefficients) |*out, original, poly| {
            if (original.log_size <= blowup or poly.logSize() != original.log_size - blowup) return null;
            out.* = .{ .log_size = original.log_size - blowup, .values = &.{}, .coefficient_values = poly.coefficients() };
        }
        header.* = view;
    }
    const small_domain = Canonic.new(degree_log).circleDomain();
    const full_domain = Canonic.new(lifting_log).circleDomain();
    var small = try SecureColumn.uninitialized(a, small_domain.size());
    defer small.deinit(a);

    {
        const P = @import("quotient_field.zig").ForField(O).LazyQuotientProvider;
        var provider = try P.initForBackendWithWorkRecorderAndByteLimit(
            B,
            a,
            core.pcs.TreeVec([]const Column).initOwned(headers),
            points,
            samples,
            alpha,
            degree_log,
            null,
            limit,
        );
        defer provider.deinit(a);
        // The AIR points stay on the original lifting domain. Lowering the
        // lifting and column logs together preserves the periodic mask shift.
        provider.computeAll(a, &small) catch |err| switch (err) {
            error.DivisionByZero => return null,
            else => return err,
        };
    }
    var twiddles = try Twiddles.precomputeM31(a, full_domain.half_coset);
    defer Twiddles.deinitM31(a, &twiddles);
    const view: Twiddles.TwiddleTree([]const core.fields.m31.M31) = .{ .root_coset = twiddles.root_coset, .twiddles = twiddles.twiddles, .itwiddles = twiddles.itwiddles };
    const pool = Pools.currentScopedPool();
    try Poly.interpolateBuffersWithTwiddlesWithPool(&small.columns, small_domain, view, pool);

    var full = try SecureColumn.uninitialized(a, full_domain.size());
    errdefer full.deinit(a);
    for (full.columns, small.columns) |out, coefficient| @memcpy(out[0..coefficient.len], coefficient);
    try Poly.evaluateDyadicExtensionBuffersWithTwiddlesWithPool(&full.columns, degree_log, full_domain, view, pool);
    return full;
}

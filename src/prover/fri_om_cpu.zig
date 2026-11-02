//! Concrete OM31 CPU FRI execution. Core circle/line laws and coordinate walk
//! are unchanged; row jobs use the existing scoped pool and bounded scratch.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const F = core.fri.ForField(O);
const Rows = @import("lookups/row_work.zig");
const Packed = @import("lookups/packed_rows.zig").ForField(O);
const po = core.fields.packed_om31;
pub const MAX_LINE_SCRATCH_BYTES: usize = 128 << 20;
/// This hook overwrites a freshly allocated first-line destination. It is NOT
/// the core accumulation API and never assumes arbitrary dst values are zero.
pub fn foldCircleFreshIntoLine(a: std.mem.Allocator, dst: []O, src: [8][]const M, domain: core.poly.circle.domain.CircleDomain, alpha: O, workspace: *F.FoldCircleWorkspace) !void {
    if (src[0].len / 2 != dst.len or src[0].len % 2 != 0 or dst.len == 0 or !std.math.isPowerOfTwo(dst.len) or domain.size() != src[0].len) return error.ShapeMismatch;
    for (src) |c| if (c.len != src[0].len) return error.ShapeMismatch;
    try workspace.ensureCapacity(a, dst.len);
    const ys = workspace.py_values[0..dst.len];
    const inverses = workspace.inv_py_values[0..dst.len];
    F.fillBitReversedCosetCoordinate(ys, domain.half_coset, .y);
    try core.fields.batchInverseInPlace(M, ys, inverses);
    const Context = struct {
        dst: []O,
        src: [8][]const M,
        inverses: []const M,
        alpha: O,
        pub fn runRange(self: *@This(), _: usize, first: usize, end: usize) void {
            const a_pack = Packed.splat(self.alpha);
            var i = first;
            while (i + core.fields.m31.PACK_WIDTH <= end) : (i += core.fields.m31.PACK_WIDTH) {
                var l: [8]core.fields.m31.PackedM31 = undefined;
                var r: [8]core.fields.m31.PackedM31 = undefined;
                inline for (0..8) |c| {
                    l[c] = Packed.base(self.src[c], 2 * i, 2);
                    r[c] = Packed.base(self.src[c], 2 * i + 1, 2);
                }
                const left = po.fromCoordinates(l);
                const right = po.fromCoordinates(r);
                const odd = left.sub(right).mulBase(Packed.base(self.inverses, i, 1));
                Packed.store(self.dst, i, left.add(right).add(Packed.mul(a_pack, odd)));
            }
            while (i < end) : (i += 1) {
                var l: [8]M = undefined;
                var r: [8]M = undefined;
                inline for (0..8) |c| {
                    l[c] = self.src[c][2 * i];
                    r[c] = self.src[c][2 * i + 1];
                }
                var even = O.fromM31Array(l);
                var odd = O.fromM31Array(r);
                core.fft.ibutterfly(O, &even, &odd, self.inverses[i]);
                self.dst[i] = even.add(self.alpha.mul(odd));
            }
        }
    };
    var context = Context{ .dst = dst, .src = src, .inverses = inverses, .alpha = alpha };
    _ = Rows.forEachRange(dst.len, &context, .{});
}
/// Original in-place ownership contract: failure retains the original owner and
/// original length (values may have been folded). Disjoint pingpong prevents
/// higher output ranges overwriting unread lower input ranges in helper jobs.
pub fn foldLineN(a: std.mem.Allocator, values: []O, domain: core.poly.line.LineDomain, alpha: O, workspace: *F.FoldLineWorkspace, n: u32) !F.FoldLineResult {
    return foldLineNWithLimit(a, values, domain, alpha, workspace, n, MAX_LINE_SCRATCH_BYTES);
}
pub fn foldLineNWithLimit(a: std.mem.Allocator, values: []O, domain: core.poly.line.LineDomain, alpha: O, workspace: *F.FoldLineWorkspace, n: u32, limit: usize) !F.FoldLineResult {
    if (n == 0) return .{ .domain = domain, .values = values };
    if (values.len < 2 or !std.math.isPowerOfTwo(values.len) or domain.size() != values.len or n > std.math.log2_int(usize, values.len)) return error.InvalidEvaluationLength;
    const scratch_bytes = try std.math.mul(usize, values.len / 2, @sizeOf(O));
    if (std.process.hasEnvVarConstant("STWO_ZIG_PROFILE_OM_FRI")) std.debug.print("OM_FRI_LINE rows={d} folds={d} scratch_bytes={d} cap_bytes={d} packed={any}\n", .{ values.len, n, scratch_bytes, limit, scratch_bytes <= limit });
    if (scratch_bytes > limit) return F.foldLineInPlaceNWithWorkspace(a, values, domain, alpha, workspace, n);
    // All growth before writes. Actual allocator OOM is propagated; only an
    // explicit geometry/cap refusal takes the original scalar path.
    try workspace.ensureCapacity(a, values.len / 2);
    const scratch = try a.alloc(O, values.len / 2);
    var owns_scratch = true;
    defer if (owns_scratch) a.free(scratch);
    const Context = struct {
        src: []const O,
        dst: []O,
        inverses: []const M,
        alpha: O,
        pub fn runRange(self: *@This(), _: usize, first: usize, end: usize) void {
            const a_pack = Packed.splat(self.alpha);
            var i = first;
            while (i + core.fields.m31.PACK_WIDTH <= end) : (i += core.fields.m31.PACK_WIDTH) {
                const left = Packed.load(self.src, 2 * i, 2);
                const right = Packed.load(self.src, 2 * i + 1, 2);
                const odd = left.sub(right).mulBase(Packed.base(self.inverses, i, 1));
                Packed.store(self.dst, i, left.add(right).add(Packed.mul(a_pack, odd)));
            }
            while (i < end) : (i += 1) {
                var even = self.src[2 * i];
                var odd = self.src[2 * i + 1];
                core.fft.ibutterfly(O, &even, &odd, self.inverses[i]);
                self.dst[i] = even.add(self.alpha.mul(odd));
            }
        }
    };
    var current: []O = values;
    var in_original = true;
    var current_domain = domain;
    var current_alpha = alpha;
    for (0..n) |_| {
        const count = current.len / 2;
        const xs = workspace.x_values[0..count];
        const inverses = workspace.inv_x_values[0..count];
        F.fillBitReversedCosetCoordinate(xs, current_domain.coset(), .x);
        try core.fields.batchInverseInPlace(M, xs, inverses);
        const dst = if (in_original) scratch[0..count] else values[0..count];
        var context = Context{ .src = current, .dst = dst, .inverses = inverses, .alpha = current_alpha };
        _ = Rows.forEachRange(count, &context, .{});
        current = dst;
        in_original = !in_original;
        current_domain = current_domain.double();
        current_alpha = current_alpha.square();
    }
    if (!in_original) @memcpy(values[0..current.len], current);
    // Retire scratch before final realloc, so its fallback copy never overlaps
    // the pingpong owner. Original backing capacity remains charged until free.
    a.free(scratch);
    owns_scratch = false;
    return .{ .domain = current_domain, .values = try a.realloc(values, current.len) };
}

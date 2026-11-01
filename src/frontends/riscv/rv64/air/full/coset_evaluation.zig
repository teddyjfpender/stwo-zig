//! Bounded CPU quotient scratch: n values per column and n extra values only
//! for columns sampled at the preceding trace row. Four disjoint n-point
//! conjugate cosets cover the canonical 4n quotient domain exactly.
//!
//! A trace predecessor crosses to the paired coset: it does not stay in one
//! n-point circle domain. Its exact position is obtained from the core index
//! authority. Source coefficients are borrowed; evaluation scratch is reusable.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Poly = engine.air.component_prover.Poly;
const CircleDomain = core.poly.circle.domain.CircleDomain;
const partition = engine.poly.circle.coset_partition;
const work = engine.work_pool;
pub const PARTS = 4;

pub const Evaluation = struct {
    allocator: std.mem.Allocator,
    sources: []const Poly,
    previous_columns: []const bool,
    trace_log: u32,
    log_expansion: u32 = 2,
    size: usize,
    current_values: [][]const M,
    previous_values: [][]const M,
    buffers: [][]M,
    /// Indices requiring coefficient FFTs. Matching retained domains borrow views.
    owned_sources: []usize,
    unshifted_buffers: [][]M,
    scratch: []M,
    cached_part: ?usize = null,
    test_transformed_columns: if (@import("builtin").is_test) usize else void = if (@import("builtin").is_test) 0 else {},

    /// Allocates n*(columns + previous columns) M31 values once. Metadata and
    /// coefficient sources remain borrowed and immutable until deinit. Missing coefficients
    /// fail closed; this operation never interpolates or silently allocates 4n.
    pub fn init(a: std.mem.Allocator, polys: []const Poly, trace_log: u32, previous_columns: []const bool) !Evaluation {
        return initWithExpansion(a, polys, trace_log, previous_columns, 2);
    }
    /// Two conjugate n-point parts cover the native degree-three 2n domain.
    /// The legacy constructor remains four-way and keeps its exact geometry.
    pub fn initDegreeThree(a: std.mem.Allocator, polys: []const Poly, trace_log: u32, previous_columns: []const bool) !Evaluation {
        return initWithExpansion(a, polys, trace_log, previous_columns, 1);
    }
    fn initWithExpansion(a: std.mem.Allocator, polys: []const Poly, trace_log: u32, previous_columns: []const bool, log_expansion: u32) !Evaluation {
        if ((log_expansion != 1 and log_expansion != 2) or trace_log < 2 or trace_log > 28 - log_expansion or polys.len == 0 or previous_columns.len != polys.len) return error.InvalidRv64CosetGeometry;
        const size = @as(usize, 1) << @intCast(trace_log);
        var previous_count: usize = 0;
        var owned_count: usize = 0;
        for (polys, previous_columns) |poly, previous| {
            try poly.validate();
            if (poly.coefficients) |coefficients| {
                if (coefficients.logSize() > trace_log or coefficients.coefficients().len > size) return error.InvalidRv64CosetGeometry;
            } else if (!retainedDomain(poly, trace_log, log_expansion)) return error.MissingRv64CosetCoefficients;
            if (!retainedDomain(poly, trace_log, log_expansion)) {
                owned_count += 1;
                previous_count += @intFromBool(previous);
            }
        }
        const count = std.math.add(usize, owned_count, previous_count) catch return error.InvalidRv64CosetGeometry;
        const cells = std.math.mul(usize, count, size) catch return error.InvalidRv64CosetGeometry;
        const current = try a.alloc([]const M, polys.len);
        errdefer a.free(current);
        const previous = try a.alloc([]const M, polys.len);
        errdefer a.free(previous);
        const buffers = try a.alloc([]M, count);
        errdefer a.free(buffers);
        const owned_sources = try a.alloc(usize, owned_count);
        errdefer a.free(owned_sources);
        const unshifted = try a.alloc([]M, if (previous_count == 0) 0 else owned_count - previous_count);
        errdefer a.free(unshifted);
        const scratch = try a.alloc(M, cells);
        errdefer a.free(scratch);
        for (buffers, 0..) |*buffer, i| buffer.* = scratch[i * size ..][0..size];
        var cursor = owned_count;
        var owned_at: usize = 0;
        var unshifted_at: usize = 0;
        for (polys, current, previous, previous_columns, 0..) |poly, *cur, *prior, needs_previous, i| {
            if (retainedDomain(poly, trace_log, log_expansion)) {
                cur.* = poly.values[0..size];
                prior.* = if (needs_previous) poly.values[size..][0..size] else &.{};
                continue;
            }
            owned_sources[owned_at] = i;
            cur.* = buffers[owned_at];
            prior.* = if (needs_previous) buffers[cursor] else &.{};
            cursor += @intFromBool(needs_previous);
            if (previous_count != 0 and !needs_previous) {
                unshifted[unshifted_at] = buffers[owned_at];
                unshifted_at += 1;
            }
            owned_at += 1;
        }
        return .{ .allocator = a, .sources = polys, .previous_columns = previous_columns, .trace_log = trace_log, .log_expansion = log_expansion, .size = size, .current_values = current, .previous_values = previous, .buffers = buffers, .owned_sources = owned_sources, .unshifted_buffers = unshifted, .scratch = scratch };
    }
    pub fn deinit(self: *Evaluation) void {
        self.allocator.free(self.current_values);
        self.allocator.free(self.previous_values);
        self.allocator.free(self.buffers);
        self.allocator.free(self.owned_sources);
        self.allocator.free(self.unshifted_buffers);
        self.allocator.free(self.scratch);
        self.* = undefined;
    }
    pub fn domain(self: *const Evaluation, part: usize) !CircleDomain {
        return partition.domain(core.poly.circle.canonic.CanonicCoset.new(self.trace_log + self.log_expansion).circleDomain(), self.log_expansion, part);
    }
    /// Replaces all current/previous views. No field-value allocation occurs;
    /// each FFT owns only its n-point twiddle tree during that batch.
    pub fn evaluatePart(self: *Evaluation, part: usize) !void {
        return self.evaluatePartWithPool(part, null);
    }
    pub fn evaluatePartWithPool(self: *Evaluation, part: usize, pool: ?*work.WorkPool) !void {
        const current_domain = try self.domain(part);
        // Canonical bit-reversed partitions are contiguous. The core partition
        // authority also fixes the predecessor partner to part xor1. Borrow
        // exactly those immutable committed slices; no FFT or n-row copy.
        for (self.sources, self.previous_columns, 0..) |poly, previous, i| {
            if (!retainedDomain(poly, self.trace_log, self.log_expansion)) continue;
            self.current_values[i] = poly.values[part * self.size ..][0..self.size];
            self.previous_values[i] = if (previous) poly.values[(part ^ 1) * self.size ..][0..self.size] else &.{};
        }
        const reuse_partner = if (self.cached_part) |prior| prior ^ 1 == part else false;
        // Any failed FFT invalidates the cache, including after swapping views.
        // A subsequent call reinitializes every current/partner buffer.
        self.cached_part = null;
        if (reuse_partner) {
            var cursor = self.owned_sources.len;
            for (self.owned_sources, 0..) |i, k| {
                if (!self.previous_columns[i]) continue;
                const old_current = self.buffers[k];
                self.buffers[k] = self.buffers[cursor];
                self.buffers[cursor] = old_current;
                self.current_values[i] = self.buffers[k];
                self.previous_values[i] = self.buffers[cursor];
                cursor += 1;
            }
            // Unmarked buffer addresses never swap, so these borrowed headers
            // stay valid across every pair and arbitrary requested part order.
            for (self.owned_sources, 0..) |i, k| {
                if (!self.previous_columns[i]) copyCoefficients(self.sources[i], self.buffers[k]);
            }
            try self.transform(self.unshifted_buffers, current_domain, pool);
            self.cached_part = part;
            return;
        }
        for (self.owned_sources, 0..) |i, k| copyCoefficients(self.sources[i], self.buffers[k]);
        try self.transform(self.buffers[0..self.owned_sources.len], current_domain, pool);
        if (self.buffers.len == self.owned_sources.len) return;
        var cursor = self.owned_sources.len;
        for (self.owned_sources) |i| {
            if (!self.previous_columns[i]) continue;
            copyCoefficients(self.sources[i], self.buffers[cursor]);
            cursor += 1;
        }
        try self.transform(self.buffers[self.owned_sources.len..], try self.domain(part ^ 1), pool);
        self.cached_part = part;
    }
    pub fn globalRow(self: *const Evaluation, part: usize, row: usize) usize {
        std.debug.assert(part < (@as(usize, 1) << @intCast(self.log_expansion)) and row < self.size);
        return part * self.size + row;
    }
    pub fn previousRow(self: *const Evaluation, part: usize, row: usize) usize {
        const previous = core.utils.previousBitReversedCircleDomainIndex(self.globalRow(part, row), self.trace_log, self.trace_log + self.log_expansion);
        // The quotient domain's natural half-coset predecessor shifts by two.
        // In four-way bit-reversed partition order this changes part xor 1.
        std.debug.assert(previous / self.size == part ^ 1);
        return previous % self.size;
    }
    pub fn denominatorInverse(self: *const Evaluation, part: usize) !M {
        return (try core.constraints.cosetVanishing(M, core.poly.circle.canonic.CanonicCoset.new(self.trace_log).coset(), (try self.domain(part)).at(0)).inv());
    }
    fn transform(self: *Evaluation, buffers: [][]M, target: CircleDomain, pool: ?*work.WorkPool) !void {
        if (buffers.len == 0) return;
        var twiddles = try engine.poly.twiddles.precomputeM31(self.allocator, target.half_coset);
        defer engine.poly.twiddles.deinitM31(self.allocator, &twiddles);
        const tree = engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
        try @import("../providers/domain_transform.zig").evaluate(buffers, target, tree, pool);
        if (comptime @import("builtin").is_test) self.test_transformed_columns += buffers.len;
    }
};
fn copyCoefficients(poly: Poly, buffer: []M) void {
    const source = poly.coefficients.?.coefficients();
    @memcpy(buffer[0..source.len], source);
    @memset(buffer[source.len..], M.zero());
}

/// Domain equality includes the canonical log and exact value count. A 2n
/// commitment never substitutes for a disjoint 4n quotient domain.
fn retainedDomain(poly: Poly, trace_log: u32, expansion: u32) bool {
    return poly.log_size == trace_log + expansion and poly.values.len == (@as(usize, 1) << @intCast(trace_log + expansion));
}

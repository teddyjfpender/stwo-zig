//! No-copy PCS coefficient ingress. GPU blits gather/pad; the existing
//! resident FFT expands the exact polynomial. No host scatter or recovery.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const external = prover.shared_external_memory;
const runtime = @import("../runtime.zig");
const M = core.fields.m31.M31;
const Trace = prover.air.component_prover.Trace;
pub const Descriptor = extern struct {
    coefficients: [*]const M,
    evaluations: [*]const M,
    coefficient_words: usize,
    evaluation_words: usize,
    tree_index: u32,
    column_index: u32,
    trace_log: u32,
    evaluation_log: u32,
};
extern fn stwo_zig_secure_coefficient_gather_v1(*anyopaque, [*]const ?*anyopaque, u32, [*]const Descriptor, u32, *anyopaque, u32, usize, *f64) u32;
pub const Geometry = struct { rows: usize, source_bytes: usize, output_bytes: usize, charged_bytes: usize };
pub fn geometry(columns: usize, trace_log: u32, eval_log: u32, cap: usize) !Geometry {
    if (columns == 0 or columns > 512 or trace_log < 1 or trace_log > 24 or eval_log <= trace_log or eval_log > 27 or eval_log - trace_log > 3) return error.InvalidSecureCoefficientGeometry;
    const rows = @as(usize, 1) << @intCast(eval_log);
    const source_bytes = try std.math.mul(usize, columns, (@as(usize, 1) << @intCast(trace_log)) * 4);
    const output_bytes = try std.math.mul(usize, columns, rows * 4);
    const charged_bytes = try std.math.add(usize, source_bytes, output_bytes);
    if (charged_bytes > cap) return error.SecureCoefficientResidentCap;
    return .{ .rows = rows, .source_bytes = source_bytes, .output_bytes = output_bytes, .charged_bytes = charged_bytes };
}
pub fn requireNoCopySpan(address: usize, bytes: usize, page: usize) !void {
    if (address == 0 or bytes == 0 or page == 0 or !std.math.isPowerOfTwo(page) or address % page != 0 or bytes % page != 0 or bytes > std.math.maxInt(usize) - address) return error.SecureCoefficientNoCopyUnavailable;
}
pub const Owned = struct {
    a: std.mem.Allocator,
    source: *const Trace,
    descriptors: []Descriptor,
    columns: [][]M,
    offsets: [3][]u64,
    resident: runtime.ResidentBuffer,
    gpu_milliseconds: f64,
    ingress_bytes: usize,
    pub fn init(a: std.mem.Allocator, metal: *runtime.Runtime, source: *const Trace, residents: []const ?*anyopaque, trace_log: u32, eval_log: u32, twiddles: prover.poly.twiddles.TwiddleTree([]const M), cap: usize) !Owned {
        if (source.polys.items.len != 3 or residents.len != 3) return error.InvalidSecureCoefficientOwner;
        var count: usize = 0;
        for (source.polys.items, residents) |tree, handle| {
            if (tree.len == 0 or handle == null) return error.InvalidSecureCoefficientOwner;
            count = try std.math.add(usize, count, tree.len);
        }
        const g = try geometry(count, trace_log, eval_log, cap);
        const descriptors = try a.alloc(Descriptor, count);
        errdefer a.free(descriptors);
        const columns = try a.alloc([]M, count);
        errdefer a.free(columns);
        var offsets: [3][]u64 = undefined;
        var initialized: usize = 0;
        errdefer for (offsets[0..initialized]) |values| a.free(values);
        var cursor: usize = 0;
        for (source.polys.items, 0..) |tree, t| {
            offsets[t] = try a.alloc(u64, tree.len);
            initialized += 1;
            for (tree, 0..) |poly, c| {
                try poly.validate();
                const coefficient = poly.coefficients orelse return error.MissingSecureCommittedCoefficients;
                const values = coefficient.coefficients();
                if (coefficient.logSize() != trace_log or values.len != @as(usize, 1) << @intCast(trace_log) or poly.values.len == 0) return error.InvalidSecureCoefficientOwner;
                try requireNoCopySpan(@intFromPtr(values.ptr), values.len * 4, std.heap.pageSize());
                descriptors[cursor] = .{ .coefficients = values.ptr, .evaluations = poly.values.ptr, .coefficient_words = values.len, .evaluation_words = poly.values.len, .tree_index = @intCast(t), .column_index = @intCast(c), .trace_log = trace_log, .evaluation_log = poly.log_size };
                offsets[t][c] = @intCast(cursor * g.rows);
                cursor += 1;
            }
        }
        // PCS-owned coefficient inputs are immutable no-copy host aliases and
        // already heap charged. Only the gathered device output is new bytes.
        var reservation = try external.reserve(a, g.output_bytes, .require_shared_budget);
        defer reservation.deinit();
        var resident = try metal.allocateResidentBuffer(g.output_bytes);
        resident.external_reservation = reservation.take();
        errdefer resident.deinit();
        if (resident.byte_length != g.output_bytes or @intFromPtr(resident.contents) % @alignOf(M) != 0) return error.InvalidSecureCoefficientOutput;
        const all: [*]M = @ptrCast(@alignCast(resident.contents));
        for (columns, 0..) |*column, i| column.* = all[i * g.rows ..][0..g.rows];
        var gpu_ms: f64 = 0;
        if (stwo_zig_secure_coefficient_gather_v1(metal.handle, residents.ptr, 3, descriptors.ptr, @intCast(count), resident.handle, @intCast(g.rows), g.charged_bytes, &gpu_ms) != 0) return error.SecureCoefficientIngressFailed;
        const transformed = try metal.transformCircleResidentBatch(a, &resident, columns, twiddles.twiddles, eval_log, false);
        if (!transformed.exact_resident_source or !transformed.direct_host_alias) return error.SecureCoefficientTransformNotResident;
        const result = Owned{ .a = a, .source = source, .descriptors = descriptors, .columns = columns, .offsets = offsets, .resident = resident, .gpu_milliseconds = gpu_ms + transformed.gpu_milliseconds, .ingress_bytes = g.source_bytes };
        try result.requireSource(source);
        return result;
    }
    pub fn requireSource(self: *const Owned, source: *const Trace) !void {
        if (self.source != source or source.polys.items.len != 3) return error.InvalidSecureCoefficientOwner;
        for (self.descriptors) |d| {
            if (d.tree_index >= source.polys.items.len or d.column_index >= source.polys.items[d.tree_index].len) return error.InvalidSecureCoefficientOwner;
            const poly = source.polys.items[d.tree_index][d.column_index];
            const coeff = poly.coefficients orelse return error.MissingSecureCommittedCoefficients;
            if (coeff.coefficients().ptr != d.coefficients or coeff.coefficients().len != d.coefficient_words or coeff.logSize() != d.trace_log or poly.values.ptr != d.evaluations or poly.values.len != d.evaluation_words or poly.log_size != d.evaluation_log) return error.InvalidSecureCoefficientOwner;
        }
    }
    pub fn deinit(self: *Owned) void {
        var resident = self.resident;
        for (self.offsets) |values| self.a.free(values);
        self.a.free(self.columns);
        self.a.free(self.descriptors);
        resident.deinit();
        self.* = undefined;
    }
};

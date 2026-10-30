//! Exact host-derived DEEP topology for the existing CUDA numeric kernels.
//! This is execution metadata, not proof or admission authority. Every original
//! sample term appears once, in its original batch and random-power order.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const abi = @import("../../backends/cuda/abi/stages/quotient.zig");
const field = @import("../../backends/cuda/abi/field.zig");
const Provider = engine.pcs.quotient_ops.LazyQuotientProvider;
const Column = engine.pcs.ColumnEvaluation;
const Q = core.fields.qm31.QM31;

pub const Limits = struct {
    max_device_bytes: usize = 16 * 1024 * 1024 * 1024,
    max_metadata_bytes: usize = 64 * 1024 * 1024,
    max_columns: usize = 1_000_000,
    max_terms: usize = 4_000_000,
    max_groups: usize = 65535,
    max_log: u32 = 28,
};
pub const Source = struct { column: Column, offset: usize, log: u32 };
/// Existing CUDA LDE requires a proper coefficient extension and log >= 3.
/// Other shapes remain explicitly accounted CPU materialization, never a
/// substitute for the selected CUDA quotient kernels.
pub fn gpuExpandable(source: Source) bool {
    const coefficients = source.column.coefficient_values orelse return false;
    return source.log >= 3 and coefficients.len <= (@as(usize, 1) << @intCast(source.log - 1));
}
pub const Owned = struct {
    allocator: std.mem.Allocator,
    sources: []Source,
    terms: []abi.BatchTermDescriptor,
    lines: []field.SecureField,
    points: []field.SecureCirclePoint,
    first: []field.SecureField,
    group_offsets: []u32,
    group_logs: []u32,
    output_offsets: []u64,
    source_words: usize,
    partial_words: usize,
    output_words: usize,
    device_bytes: usize,
    metadata_bytes: usize,

    pub fn init(a: std.mem.Allocator, p: *const Provider, limits: Limits) !Owned {
        if (p.input_mode != .raw_backend or !p.domain.isCanonic() or p.lifting_log_size < 1 or p.lifting_log_size > limits.max_log or limits.max_log > 30)
            return error.UnsupportedCudaQuotientGeometry;
        const batches = p.prepared.sample_batches;
        const active = p.prepared.contribution_plan.active_column_indices;
        const n = p.prepared.contribution_plan.contributions.len;
        if (active.len == 0 or active.len > limits.max_columns or n == 0 or n > limits.max_terms or batches.len == 0 or batches.len > limits.max_groups or batches.len > 65535 or
            active.len > std.math.maxInt(u32) or n > std.math.maxInt(u32) or p.raw_columns.len > limits.max_columns)
            return error.CudaQuotientResourceLimit;
        const metadata = try sum(&.{ try mul(active.len, @sizeOf(Source) + @sizeOf(abi.AddressedSourceDescriptor)), try mul(n, @sizeOf(abi.BatchTermDescriptor) + 3 * @sizeOf(field.SecureField)), try mul(batches.len, @sizeOf(field.SecureCirclePoint) + @sizeOf(field.SecureField) + 8 + 8), 12, try mul(p.raw_columns.len, @sizeOf(u32)) });
        if (metadata > limits.max_metadata_bytes) return error.CudaQuotientResourceLimit;
        var source_words: usize = 0;
        for (active) |index| {
            if (index >= p.raw_columns.len) return error.InvalidCudaQuotientPlan;
            const c = p.raw_columns[index];
            try c.validateRetained();
            if (c.log_size == 0 or c.log_size > p.lifting_log_size) return error.InvalidCudaQuotientPlan;
            source_words = try add(source_words, @as(usize, 1) << @intCast(@max(c.log_size, 1)));
        }
        var partial_words: usize = 0;
        var counted: usize = 0;
        for (batches, p.prepared.quotient_constants.line_coeffs) |batch, lines| {
            if (batch.cols_vals_randpows.len == 0 or batch.cols_vals_randpows.len != lines.len) return error.InvalidCudaQuotientPlan;
            var log: u32 = 1;
            for (batch.cols_vals_randpows) |term| {
                if (term.column_index >= p.raw_columns.len) return error.InvalidCudaQuotientPlan;
                log = @max(log, p.raw_columns[term.column_index].log_size);
            }
            partial_words = try add(partial_words, @as(usize, 1) << @intCast(log));
            counted = try add(counted, batch.cols_vals_randpows.len);
        }
        if (counted != n) return error.InvalidCudaQuotientPlan;
        // Includes descriptors, exact line coefficients, group metadata and
        // both four-plane numerical outputs, not merely the source arena.
        const device_bytes = try sum(&.{ try mul(source_words, 4), try mul(partial_words, 16), try mul(p.domain_size, 16), try mul(active.len, @sizeOf(abi.AddressedSourceDescriptor)), try mul(n, @sizeOf(abi.BatchTermDescriptor) + 3 * @sizeOf(field.SecureField)), try mul(batches.len, @sizeOf(field.SecureCirclePoint) + @sizeOf(field.SecureField) + 8 + 8), 12 });
        if (device_bytes > limits.max_device_bytes) return error.CudaQuotientResourceLimit;
        const map = try a.alloc(u32, p.raw_columns.len);
        defer a.free(map);
        @memset(map, std.math.maxInt(u32));
        const sources = try a.alloc(Source, active.len);
        errdefer a.free(sources);
        var cursor: usize = 0;
        for (active, sources, 0..) |index, *target, ordinal| {
            if (map[index] != std.math.maxInt(u32)) return error.InvalidCudaQuotientPlan;
            map[index] = @intCast(ordinal);
            target.* = .{ .column = p.raw_columns[index], .offset = cursor, .log = @max(p.raw_columns[index].log_size, 1) };
            cursor += @as(usize, 1) << @intCast(target.log);
        }
        // Source indices and original term order stay unchanged. Only device
        // arena offsets change: compact same-height columns become contiguous
        // destinations for the existing batched circle LDE kernel.
        cursor = 0;
        for (3..limits.max_log + 1) |log| for (sources) |*source| {
            if (source.log == log and gpuExpandable(source.*)) {
                source.offset = cursor;
                cursor += @as(usize, 1) << @intCast(source.log);
            }
        };
        for (sources) |*source| if (!gpuExpandable(source.*)) {
            source.offset = cursor;
            cursor += @as(usize, 1) << @intCast(source.log);
        };
        if (cursor != source_words) return error.InvalidCudaQuotientPlan;
        const terms = try a.alloc(abi.BatchTermDescriptor, n);
        errdefer a.free(terms);
        const lines = try a.alloc(field.SecureField, try mul(n, 3));
        errdefer a.free(lines);
        const points = try a.alloc(field.SecureCirclePoint, batches.len);
        errdefer a.free(points);
        const first = try a.alloc(field.SecureField, batches.len);
        errdefer a.free(first);
        const offsets = try a.alloc(u32, batches.len + 1);
        errdefer a.free(offsets);
        const logs = try a.alloc(u32, batches.len);
        errdefer a.free(logs);
        const outputs = try a.alloc(u64, batches.len + 1);
        errdefer a.free(outputs);
        cursor = 0;
        var output: usize = 0;
        for (batches, p.prepared.quotient_constants.line_coeffs, 0..) |batch, coefficients, group| {
            offsets[group] = @intCast(cursor);
            outputs[group] = output;
            logs[group] = 1;
            points[group] = .{ .x = pack(batch.point.x), .y = pack(batch.point.y) };
            var a_sum = Q.zero();
            for (batch.cols_vals_randpows, coefficients) |term, line| {
                const source_index = map[term.column_index];
                if (source_index == std.math.maxInt(u32)) return error.InvalidCudaQuotientPlan;
                const log = sources[source_index].log;
                terms[cursor] = .{ .source_index = source_index, .term_index = @intCast(cursor), .source_log_size = log };
                lines[cursor * 3] = pack(line.a);
                lines[cursor * 3 + 1] = pack(line.b);
                lines[cursor * 3 + 2] = pack(line.c);
                a_sum = a_sum.add(line.a);
                logs[group] = @max(logs[group], log);
                cursor += 1;
            }
            first[group] = pack(a_sum);
            output += @as(usize, 1) << @intCast(logs[group]);
        }
        offsets[batches.len] = @intCast(cursor);
        outputs[batches.len] = output;
        return .{ .allocator = a, .sources = sources, .terms = terms, .lines = lines, .points = points, .first = first, .group_offsets = offsets, .group_logs = logs, .output_offsets = outputs, .source_words = source_words, .partial_words = partial_words, .output_words = p.domain_size, .device_bytes = device_bytes, .metadata_bytes = metadata };
    }
    pub fn deinit(self: *Owned) void {
        inline for (.{ "sources", "terms", "lines", "points", "first", "group_offsets", "group_logs", "output_offsets" }) |name| self.allocator.free(@field(self, name));
        self.* = undefined;
    }
};
pub fn pack(q: Q) field.SecureField {
    const words = q.toM31Array();
    return .{ .a = words[0].v, .b = words[1].v, .c = words[2].v, .d = words[3].v };
}
fn add(a: usize, b: usize) !usize {
    return std.math.add(usize, a, b) catch error.CudaQuotientResourceLimit;
}
fn mul(a: usize, b: usize) !usize {
    return std.math.mul(usize, a, b) catch error.CudaQuotientResourceLimit;
}
fn sum(xs: []const usize) !usize {
    var out: usize = 0;
    for (xs) |x| out = try add(out, x);
    return out;
}

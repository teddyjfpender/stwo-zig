//! Per-component expansion of coefficient-backed trace columns.
//! The source trace remains immutable. Duplicate mask reads share one buffer;
//! the caller retains this lease until all native, SIMD or device work joins.
//!
//! A captured component reads each column on the canonic coset of log size
//! `t + (evaluation_log_size - trace_log_size)`, `t` being the column's own
//! trace log size (smaller columns are then lifted by the mask resolver).
//! Under blowup 1 that coset is the committed evaluation itself. A column
//! with no retained evaluation (compact storage) or committed on a larger
//! coset (blowup above the constraint degree, as the circuit lane's blowup-3
//! proofs are) is evaluated from its coefficients on that coset instead.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const composition = @import("../../witness/composition_bundle.zig");
const geometry = @import("../../witness/resident_geometry.zig");
const M31 = core.fields.m31.M31;
const Trace = prover.air.component_prover.Trace;
const Poly = prover.air.component_prover.Poly;
const circle = prover.poly.circle;
const twiddles = prover.poly.twiddles;

pub const ExpansionRequest = struct { coefficients: []const M31, values: []M31, log_size: u32 };
pub const ExpansionExecutor = struct {
    context: *anyopaque,
    run: *const fn (*anyopaque, std.mem.Allocator, []const ExpansionRequest) anyerror!void,
};

pub const Address = struct { tree: usize, column: usize };

pub fn address(trace: *const Trace, captured: *const composition.Component, interaction: u8, local: u32) !Address {
    if (trace.polys.items.len < 3) return error.InvalidTraceShape;
    const index: usize = switch (interaction) {
        0 => blk: {
            if (local >= captured.preprocessed_indices.len) return error.InvalidTraceShape;
            break :blk captured.preprocessed_indices[local];
        },
        1, 2 => blk: {
            const span = try geometry.componentSpan(captured.*, interaction);
            const global = std.math.add(usize, span.start, local) catch return error.InvalidTraceShape;
            if (global >= span.end) return error.InvalidTraceShape;
            break :blk global;
        },
        else => return error.InvalidTraceShape,
    };
    if (index >= trace.polys.items[interaction].len) return error.InvalidTraceShape;
    return .{ .tree = interaction, .column = index };
}

const BufferOwner = union(enum) {
    host: []M31,
    native: []align(std.heap.page_size_max) M31,

    fn values(self: BufferOwner) []M31 {
        return switch (self) {
            .host => |owner| owner,
            .native => |owner| owner,
        };
    }

    fn deinit(self: BufferOwner, a: std.mem.Allocator) void {
        switch (self) {
            .host => |owner| a.free(owner),
            .native => |owner| a.free(owner),
        }
    }
};

/// The log size of the coset `captured` reads `column` on: the column's
/// trace log size (its coefficient count, or its committed log size under
/// blowup 1 when no coefficients are retained) plus the component's
/// evaluation blowup.
fn evaluationLogSize(column: Poly, captured: *const composition.Component) !u32 {
    const blowup = std.math.sub(u32, captured.evaluation_log_size, captured.trace_log_size) catch
        return error.InvalidTraceShape;
    const target = if (column.coefficients) |coefficients| blk: {
        const count = coefficients.coefficients().len;
        if (count == 0 or !std.math.isPowerOfTwo(count)) return error.InvalidTraceShape;
        break :blk @as(u32, @intCast(std.math.log2_int(usize, count))) + blowup;
    } else column.log_size;
    if (target > captured.evaluation_log_size) return error.InvalidTraceShape;
    if (column.values.len == 0 and column.coefficients == null) return error.InvalidTraceShape;
    if (column.log_size < target) return error.InvalidTraceShape;
    if (column.log_size != target and column.coefficients == null) return error.InvalidTraceShape;
    return target;
}

pub const Lease = struct {
    allocator: std.mem.Allocator,
    source: *const Trace,
    expanded: ?Trace = null,
    buffers: std.ArrayList(BufferOwner) = .empty,

    pub fn trace(self: *const Lease) *const Trace {
        return if (self.expanded) |*view| view else self.source;
    }

    pub fn deinit(self: *Lease) void {
        for (self.buffers.items) |buffer| buffer.deinit(self.allocator);
        self.buffers.deinit(self.allocator);
        if (self.expanded) |view| {
            for (view.polys.items) |columns| self.allocator.free(columns);
            self.allocator.free(view.polys.items);
        }
        self.* = undefined;
    }

    pub fn init(a: std.mem.Allocator, source: *const Trace, captured: *const composition.Component) !Lease {
        return initWithExecutor(a, source, captured, null);
    }

    pub fn initWithExecutor(a: std.mem.Allocator, source: *const Trace, captured: *const composition.Component, executor: ?ExpansionExecutor) !Lease {
        var result = Lease{ .allocator = a, .source = source };
        errdefer result.deinit();
        var keys = std.ArrayList(Address).empty;
        defer keys.deinit(a);
        var max_log: u32 = 0;
        for (captured.parts) |part| for (part.program.base_insts) |instruction| {
            if (instruction.op != .trace_col and instruction.op != .preprocessed_col) continue;
            const key = try address(source, captured, instruction.interaction, instruction.a);
            const column = source.polys.items[key.tree][key.column];
            try column.validate();
            const target_log = try evaluationLogSize(column, captured);
            if (column.values.len != 0 and column.log_size == target_log) continue;
            var exists = false;
            for (keys.items) |prior| if (prior.tree == key.tree and prior.column == key.column) {
                exists = true;
                break;
            };
            if (exists) continue;
            try keys.append(a, key);
            max_log = @max(max_log, target_log);
        };
        // Ordinary evaluation-backed proofs incur no allocation or FFT.
        if (keys.items.len == 0) return result;
        const trees = try a.alloc([]const Poly, source.polys.items.len);
        var copied: usize = 0;
        errdefer {
            for (trees[0..copied]) |columns| a.free(columns);
            a.free(trees);
        }
        for (source.polys.items, trees) |columns, *owned| {
            owned.* = try a.dupe(Poly, columns);
            copied += 1;
        }
        var transform: ?twiddles.TwiddleTree([]M31) = if (executor == null)
            try twiddles.precomputeM31(a, circle.CanonicCoset.new(max_log).circleDomain().half_coset)
        else
            null;
        defer if (transform) |*owned| twiddles.deinitM31(a, owned);
        if (executor != null) {
            const Sort = struct {
                trace: *const Trace,
                fn less(self: @This(), left: Address, right: Address) bool {
                    return self.log(left) < self.log(right);
                }
                fn log(self: @This(), key: Address) u32 {
                    return @intCast(std.math.log2_int(usize, self.trace.polys.items[key.tree][key.column].coefficients.?.coefficients().len));
                }
            };
            std.sort.heap(Address, keys.items, Sort{ .trace = source }, Sort.less);
        }
        const Job = struct {
            coefficients: []const M31,
            values: []M31,
            log_size: u32,
            transform: ?twiddles.TwiddleTree([]const M31),
            failure: ?anyerror = null,
            fn run(self: *@This()) void {
                @memcpy(self.values[0..self.coefficients.len], self.coefficients);
                @memset(self.values[self.coefficients.len..], M31.zero());
                circle.poly.evaluateBuffersWithTwiddles(&.{self.values}, circle.CanonicCoset.new(self.log_size).circleDomain(), self.transform.?) catch |err| {
                    self.failure = err;
                };
            }
        };
        const jobs = try a.alloc(Job, keys.items.len);
        defer a.free(jobs);
        try result.buffers.ensureTotalCapacity(a, keys.items.len);
        var next: usize = 0;
        while (next < keys.items.len) {
            const first = keys.items[next];
            const log = try evaluationLogSize(source.polys.items[first.tree][first.column], captured);
            var end = next + 1;
            if (executor != null) while (end < keys.items.len and try evaluationLogSize(source.polys.items[keys.items[end].tree][keys.items[end].column], captured) == log) : (end += 1) {};
            const rows = @as(usize, 1) << @intCast(log);
            const cells = try std.math.mul(usize, rows, end - next);
            const owned: BufferOwner = if (executor != null)
                .{ .native = try a.alignedAlloc(M31, comptime std.mem.Alignment.fromByteUnits(std.heap.page_size_max), cells) }
            else
                .{ .host = try a.alloc(M31, cells) };
            result.buffers.appendAssumeCapacity(owned);
            const owner = owned.values();
            for (keys.items[next..end], jobs[next..end], 0..) |key, *job, i| {
                const column = source.polys.items[key.tree][key.column];
                const values = owner[i * rows ..][0..rows];
                @constCast(trees[key.tree])[key.column].values = values;
                @constCast(trees[key.tree])[key.column].log_size = log;
                job.* = .{ .coefficients = column.coefficients.?.coefficients(), .values = values, .log_size = log, .transform = if (transform) |t| .{ .root_coset = t.root_coset, .twiddles = t.twiddles, .itwiddles = t.itwiddles } else null };
            }
            next = end;
        }
        if (executor) |native| {
            const requests = try a.alloc(ExpansionRequest, jobs.len);
            defer a.free(requests);
            for (jobs, requests) |job, *request| request.* = .{ .coefficients = job.coefficients, .values = job.values, .log_size = job.log_size };
            try native.run(native.context, a, requests);
        } else if (prover.work_pool.getGlobalPool()) |pool| {
            var group: std.Thread.WaitGroup = .{};
            for (jobs[1..]) |*job| pool.spawnWg(&group, Job.run, .{job});
            jobs[0].run();
            group.wait();
        } else for (jobs) |*job| job.run();
        for (jobs) |job| if (job.failure) |err| return err;
        result.expanded = source.*;
        result.expanded.?.polys = core.pcs.TreeVec([]const Poly).initOwned(trees);
        return result;
    }
};

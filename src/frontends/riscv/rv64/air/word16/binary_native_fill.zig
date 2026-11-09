//! Concrete joined native BINARY projection. Facts and weights are prevalidated;
//! the same row authority formats scalar and parallel ranges. No worker owns
//! caller buffers or recorder state. All failures before the start gate leave
//! borrowed MAIN untouched; every submitted helper drains before returning.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const work = @import("stwo_prover_engine").work_pool;
const Shared = @import("../providers/native_fill.zig");
const S = @import("binary_source.zig");
const M = core.fields.m31.M31;
const HISTOGRAM = 65536;
pub const HISTOGRAM_BYTES_PER_WORKER = HISTOGRAM * @sizeOf(u64);
pub const MIN_STACK_BYTES = if (builtin.mode == .Debug) 1024 * 1024 else 256 * 1024;

pub const Fill = struct {
    facts: []const S.Fact,
    weights: ?[]const u32,
    log: u32,
    main: []M,
    metadata: []S.Metadata,
    pub fn run(self: Fill, a: std.mem.Allocator, counts: []u64, pool: ?*work.WorkPool) !void {
        return self.runInternal(a, counts, pool, null);
    }
    fn runInternal(self: Fill, a: std.mem.Allocator, counts: []u64, pool: ?*work.WorkPool, fail_after: ?usize) !void {
        const n: usize = @intCast((try S.massForLog(self.log)).fact_capacity);
        if (self.main.len != S.MAIN * n or self.metadata.len != n or counts.len != HISTOGRAM) return error.InvalidBinaryNativeFillShape;
        if (comptime @import("builtin").is_test) {
            if (fail_after) |after| {
                return Shared.testing.failSubmission(Adapter, a, self, n, .{counts}, .{8 * n}, pool.?, after) catch |err| return mapError(err);
            }
        }
        return Shared.fill(Adapter, a, self, n, .{counts}, .{8 * n}, pool) catch |err| return mapError(err);
    }
    fn rows(self: Fill, start: usize, end: usize, counts: []u64) void {
        const n = @as(usize, 1) << @intCast(self.log);
        for (start..end) |position| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(position, self.log), self.log);
            S.NativeSupport.write(self.facts, self.weights, self.main, self.metadata, counts, n, logical, position);
        }
    }
};
const Adapter = struct {
    pub const Context = Fill;
    pub const BINS = [_]usize{HISTOGRAM};
    pub fn rows(context: Fill, start: usize, end: usize, counts: []u64) void {
        context.rows(start, end, counts);
    }
    pub fn prepare(context: Fill) void {
        prepareMetadataPages(std.mem.sliceAsBytes(context.metadata));
    }
};
fn mapError(err: anyerror) anyerror {
    return switch (err) {
        error.InvalidNativeFillShape => error.InvalidBinaryNativeFillShape,
        error.InvalidNativeFillPhase => error.InvalidBinaryNativeFillPhase,
        error.InvalidNativeFillStack => error.InvalidBinaryNativeFillStack,
        error.InvalidNativeFillMass => error.InvalidBinaryNativeFillMass,
        error.InjectedNativeFillSubmissionFailure => error.InjectedBinaryNativeFillSubmissionFailure,
        else => err,
    };
}
fn prepareMetadataPages(bytes: []u8) void {
    // This is page establishment, NOT byte/field initialization. Every used
    // metadata field is subsequently assigned by rows; padding is never read.
    const page = std.heap.pageSize();
    if (bytes.len < page) return;
    const first: *volatile u8 = &bytes[0];
    first.* = 0;
    var at = page - @intFromPtr(bytes.ptr) % page;
    while (at < bytes.len) : (at += page) {
        const p: *volatile u8 = &bytes[at];
        p.* = 0;
    }
}
pub const testing = if (builtin.is_test) struct {
    pub fn failSubmission(fill: Fill, a: std.mem.Allocator, counts: []u64, pool: *work.WorkPool, after: usize) !void {
        return fill.runInternal(a, counts, pool, after);
    }
} else struct {};

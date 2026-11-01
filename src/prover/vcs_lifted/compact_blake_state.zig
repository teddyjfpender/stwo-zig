//! Native BLAKE2s streaming leaves: 96 row-specific bytes plus one captured
//! metadata record per uniform height/update wave. The complete pending block
//! is retained, including a full final64-byte block. No dummy compressions.
const std = @import("std");
const core = @import("stwo_core");
const Work = @import("../lookups/row_work.zig");
const Stream = @import("blake2_stream4.zig");
const Column = @import("columns.zig").ColumnRef;
const Backend = core.crypto.blake2s_backend.Blake2sHasher;
pub const State = struct { h: [8]u32, buf: [64]u8 };
comptime {
    std.debug.assert(@sizeOf(State) == 96);
}
const Metadata = struct {
    t0: u32,
    t1: u32,
    buf_len: usize,
    finalized: bool,
    selection: core.crypto.blake2s_backend.BackendSelection,
    fn from(context: Backend) Metadata {
        return .{ .t0 = context.t0, .t1 = context.t1, .buf_len = context.buf_len, .finalized = context.finalized, .selection = context.selection };
    }
    fn restore(self: Metadata, state: State) Backend {
        return .{ .h = state.h, .buf = state.buf, .t0 = self.t0, .t1 = self.t1, .buf_len = self.buf_len, .finalized = self.finalized, .selection = self.selection };
    }
};
pub fn supports(comptime H: type) bool {
    return Stream.supports(H);
}
pub fn Array(comptime H: type) type {
    if (!supports(H)) @compileError("compact native state requires supported raw BLAKE2s protocol");
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        states: []State,
        metadata: Metadata,
        pub fn init(a: std.mem.Allocator, count: usize, seed: H) !Self {
            if (count < 2 or !std.math.isPowerOfTwo(count) or seed.inner.ctx.finalized or seed.inner.ctx.buf_len > 64) return error.InvalidCompactBlakeState;
            const states = try a.alloc(State, count);
            const value = State{ .h = seed.inner.ctx.h, .buf = seed.inner.ctx.buf };
            const Fill = struct {
                states: []State,
                value: State,
                pub fn runRange(self: *@This(), _: usize, begin: usize, end: usize) void {
                    @memset(self.states[begin..end], self.value);
                }
            };
            var fill = Fill{ .states = states, .value = value };
            _ = Work.forEachRange(count, &fill, .{});
            return .{ .allocator = a, .states = states, .metadata = Metadata.from(seed.inner.ctx) };
        }
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.states);
            self.* = undefined;
        }
        pub fn get(self: *const Self, index: usize) H {
            return .{ .inner = .{ .ctx = self.metadata.restore(self.states[index]) } };
        }
        /// Allocate and fill the replacement before changing any old owner.
        pub fn expand(self: *Self, count: usize, shift: std.math.Log2Int(usize)) !void {
            if (shift < 1 or self.states.len > @as(usize, std.math.maxInt(usize)) >> (shift - 1) or count != self.states.len << (shift - 1)) return error.InvalidCompactBlakeState;
            const next = try self.allocator.alloc(State, count);
            const Expand = struct {
                old: []const State,
                next: []State,
                shift: std.math.Log2Int(usize),
                pub fn runRange(job: *@This(), _: usize, begin: usize, end: usize) void {
                    var i = begin;
                    while (i < end) {
                        const run = i >> job.shift;
                        const even = job.old[2 * run];
                        const odd = job.old[2 * run + 1];
                        const stop = @min(end, (run + 1) << job.shift);
                        while (i < stop) : (i += 1) job.next[i] = if ((i & 1) == 0) even else odd;
                    }
                }
            };
            var expansion = Expand{ .old = self.states, .next = next, .shift = shift };
            _ = Work.forEachRange(count, &expansion, .{});
            self.allocator.free(self.states);
            self.states = next;
        }
        pub fn update(self: *Self, columns: []const Column) !void {
            if (columns.len == 0) return;
            const log = std.math.log2_int(usize, self.states.len);
            for (columns) |column| if (column.values.len != self.states.len or column.log_size != log) return error.InvalidColumnSize;
            const Update = struct {
                states: []State,
                before: Metadata,
                after: Metadata = undefined,
                columns: []const Column,
                fn save(job: *@This(), index: usize, value: H) void {
                    job.states[index] = .{ .h = value.inner.ctx.h, .buf = value.inner.ctx.buf };
                    // One writer. Every helper reads the immutable BEFORE snapshot
                    // until the entire wave joins. No global/default-mode redraw.
                    if (index == 0) job.after = Metadata.from(value.inner.ctx);
                }
                pub fn runRange(job: *@This(), _: usize, begin: usize, end: usize) void {
                    var index = begin;
                    while (index + 4 <= end) : (index += 4) {
                        var batch: [4]H = undefined;
                        inline for (0..4) |lane| batch[lane] = .{ .inner = .{ .ctx = job.before.restore(job.states[index + lane]) } };
                        Stream.updateM31Columns4(&batch, job.columns, index);
                        inline for (0..4) |lane| job.save(index + lane, batch[lane]);
                    }
                    while (index < end) : (index += 1) {
                        var value = H{ .inner = .{ .ctx = job.before.restore(job.states[index]) } };
                        for (job.columns) |column| value.updateLeaf(column.values[index..][0..1]);
                        job.save(index, value);
                    }
                }
            };
            var update_job = Update{ .states = self.states, .before = self.metadata, .columns = columns };
            _ = Work.forEachRange(self.states.len, &update_job, .{});
            self.metadata = update_job.after;
        }
        pub fn finalizeInto(self: *const Self, output: []H.Hash) !void {
            if (output.len != self.states.len) return error.InvalidColumnSize;
            const Final = struct {
                source: *const Self,
                output: []H.Hash,
                pub fn runRange(job: *@This(), _: usize, begin: usize, end: usize) void {
                    var index = begin;
                    while (index + 4 <= end) : (index += 4) {
                        var batch: [4]H = undefined;
                        inline for (0..4) |lane| batch[lane] = job.source.get(index + lane);
                        const hashes = Stream.finalize4(&batch);
                        @memcpy(job.output[index..][0..4], &hashes);
                    }
                    while (index < end) : (index += 1) {
                        var value = job.source.get(index);
                        job.output[index] = value.finalize();
                    }
                }
            };
            var final = Final{ .source = self, .output = output };
            _ = Work.forEachRange(output.len, &final, .{});
        }
    };
}

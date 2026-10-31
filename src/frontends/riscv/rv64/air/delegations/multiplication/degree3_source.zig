//! Reuses the legacy87-column main recipe and ownership. Only the200-column
//! interaction constructor changes; all metadata is retired on success only.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const Old = @import("trace.zig");
const L = @import("degree3_layout.zig");
const P = @import("provider.zig");
const M = core.fields.m31.M31;
const Q = E.Q;
const physical = @import("../../witness.zig").physical;
pub const Source = struct {
    base: Old.Trace,
    pub fn init(a: std.mem.Allocator, requests: []const Old.Request) !Source {
        return .{ .base = try Old.Trace.init(a, requests) };
    }
    pub fn initWithLog(a: std.mem.Allocator, requests: []const Old.Request, log: u32) !Source {
        return .{ .base = try Old.Trace.initWithLog(a, requests, log) };
    }
    pub fn initWithBorrowedMain(a: std.mem.Allocator, requests: []const Old.Request, log: u32, main: []M) !Source {
        return .{ .base = try Old.Trace.initWithBorrowedMain(a, requests, log, main) };
    }
    pub fn releaseMain(self: *Source) !void {
        return self.base.releaseMain();
    }
    pub fn deinit(self: *Source) void {
        self.base.deinit();
        self.* = undefined;
    }
    pub fn generate(self: *Source, ch: P.Challenges, alpha: Q) !Q {
        const b = &self.base;
        if (b.log_size < 5 or b.log_size > 22) return error.InvalidRv64MultiplicationShape;
        if (b.interaction.len != 0 or b.request_metadata.len != b.count) return error.InvalidRv64MultiplicationPhase;
        const n = b.domainSize();
        if (b.count > n) return error.InvalidRv64MultiplicationShape;
        const data = try b.allocator.alloc(M, L.INTERACTION * n);
        errdefer b.allocator.free(data);
        var bytes: [256]Q = undefined;
        for (&bytes, 0..) |*v, i| v.* = try alpha.sub(E.q(@intCast(i))).inv();
        const padding_inverse = if (b.count < n) try ch.offset.inv() else Q.zero();
        var denominators: [512]Q = undefined;
        var inverses: [512]Q = undefined;
        var sum = Q.zero();
        var first: usize = 0;
        while (first < n) : (first += @min(512, n - first)) {
            const count: usize = @min(512, n - first);
            const active = @min(count, @as(usize, b.count) -| first);
            for (0..active) |j| denominators[j] = ch.denominator(&try Old.requestTuple(b.request_metadata[first + j]));
            if (active != 0) try core.fields.batchInverseInPlace(Q, denominators[0..active], inverses[0..active]);
            for (0..count) |j| {
                const logical = first + j;
                const row = physical(logical, b.log_size);
                const main = if (j < active) try Old.row(b.request_metadata[logical]) else [_]M{M.zero()} ** L.MAIN;
                const values = try Old.byteValuesNative(&main);
                for (0..L.BYTE_PAIRS) |pair| {
                    const x = bytes[values[2 * pair]];
                    const y = bytes[values[2 * pair + 1]];
                    store(data, n, row, 4 * pair, x.mul(y));
                    sum = sum.add(x).add(y);
                }
                const inverse = if (j < active) inverses[j] else padding_inverse;
                store(data, n, row, L.FUNCTION_INVERSE, inverse);
                if (j < active) sum = sum.sub(inverse);
                store(data, n, row, L.PREFIX, sum);
            }
        }
        const correction = sum.toM31Array();
        for (correction, 0..) |v, c| for (0..n) |r| {
            data[(L.PREFIX + c) * n + r] = data[(L.PREFIX + c) * n + r].sub(v);
        };
        b.interaction = data;
        b.allocator.free(b.request_metadata);
        b.request_metadata = &.{};
        return sum;
    }
};
fn store(data: []M, n: usize, row: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(column + c) * n + row] = v;
}

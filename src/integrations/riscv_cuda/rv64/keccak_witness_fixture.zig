//! Independent original native paired trace and throughput-table oracle.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const IO = @import("fixture_io.zig");
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, id: u32, log: u32, calls: u32) !void {
    return writePolicy(a, dir, id, log, calls, .throughput_r27_v1);
}
pub fn writePolicy(a: std.mem.Allocator, dir: std.fs.Dir, id: u32, log: u32, calls: u32, policy: K.equations.BatchPolicy) !void {
    const inputs = try a.alloc(K.trace.State, calls);
    defer a.free(inputs);
    var rng = std.Random.DefaultPrng.init(0xd336780 + id);
    for (inputs) |*state| for (state) |*word| {
        word.* = rng.random().int(u64);
    };
    const first: u32 = 17 + id;
    var trace = try K.trace.Trace.initWithLogGeometry(a, inputs, first, log, policy.geometry());
    defer trace.deinit();
    var throughput: ?K.throughput_counts.Counts = if (policy.throughputTables()) try K.throughput_counts.Counts.fromTrace(a, &trace) else null;
    defer if (throughput) |*counts| counts.deinit();
    var compact: ?K.interaction.Counts = if (!policy.throughputTables()) try K.interaction.Counts.fromTrace(&trace) else null;
    const chi_counts: []const u64 = if (throughput) |counts| counts.chi else &compact.?.chi;
    const xor_counts: []const u64 = if (throughput) |counts| counts.xor5 else &compact.?.xor5;
    var chi = try K.tables.Trace.initPolicy(a, .chi, policy, chi_counts);
    defer chi.deinit();
    var xor5 = try K.tables.Trace.initPolicy(a, .xor5, policy, xor_counts);
    defer xor5.deinit();
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(a);
    const w = output.writer(a);
    try IO.words(w, &.{ 0x52564b57, 1, id, log, calls, first, K.layout.MAIN, @intCast(policy.geometry().rowsPerPair()) });
    try w.writeAll(std.mem.sliceAsBytes(inputs));
    try w.writeAll(std.mem.sliceAsBytes(trace.main));
    try w.writeAll(std.mem.sliceAsBytes(chi.main));
    try w.writeAll(std.mem.sliceAsBytes(xor5.main));
    const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(name);
    try dir.writeFile(.{ .sub_path = name, .data = output.items });
}

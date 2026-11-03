//! Independent original native paired trace and throughput-table oracle.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const IO = @import("fixture_io.zig");
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, id: u32, log: u32, calls: u32) !void {
    const inputs = try a.alloc(K.trace.State, calls);
    defer a.free(inputs);
    var rng = std.Random.DefaultPrng.init(0xd336780 + id);
    for (inputs) |*state| for (state) |*word| {
        word.* = rng.random().int(u64);
    };
    const first: u32 = 17 + id;
    var trace = try K.trace.Trace.initWithLogGeometry(a, inputs, first, log, .pair27);
    defer trace.deinit();
    var counts = try K.throughput_counts.Counts.fromTrace(a, &trace);
    defer counts.deinit();
    var chi = try K.tables.Trace.initPolicy(a, .chi, .throughput_r27_v1, counts.chi);
    defer chi.deinit();
    var xor5 = try K.tables.Trace.initPolicy(a, .xor5, .throughput_r27_v1, counts.xor5);
    defer xor5.deinit();
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(a);
    const w = output.writer(a);
    try IO.words(w, &.{ 0x52564b57, 1, id, log, calls, first, K.layout.MAIN, 27 });
    try w.writeAll(std.mem.sliceAsBytes(inputs));
    try w.writeAll(std.mem.sliceAsBytes(trace.main));
    try w.writeAll(std.mem.sliceAsBytes(chi.main));
    try w.writeAll(std.mem.sliceAsBytes(xor5.main));
    const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(name);
    try dir.writeFile(.{ .sub_path = name, .data = output.items });
}

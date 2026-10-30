//! Offline differential vectors only. CPU witnesses here are test oracles;
//! they are not inputs to the resident device witness API.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("resident_parent_hash_plan_v1.zig");
const Code = @import("resident_parent_hash_codegen_v1.zig");
const Hash = @import("../../frontends/riscv/recursion/air/blake3_hash_witness.zig");
pub fn exportVectors(a: std.mem.Allocator, path: []const u8) !void {
    var dir = try std.fs.cwd().makeOpenPath(path, .{});
    defer dir.close();
    const source = try Code.generate(a);
    defer a.free(source);
    try dir.writeFile(.{ .sub_path = "resident_hash.cu", .data = source });
    try dir.writeFile(.{ .sub_path = "numeric_runner.cu", .data = @embedFile("resident_parent_hash_numeric_runner_v1.cpp") });
    var binary: std.Io.Writer.Allocating = .init(a);
    defer binary.deinit();
    try word(&binary.writer, 4);
    const lengths = [_]usize{ 0, 1, 3, 4, 63, 64, 65, 1023, 1024, 1025, 4096 };
    for (0..3) |variant| try one(a, &binary.writer, &lengths, @intCast(variant));
    const many = [_]usize{65} ** 128;
    try one(a, &binary.writer, &many, 3);
    try dir.writeFile(.{ .sub_path = "numeric.bin", .data = binary.written() });
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &sha, .{});
    const receipt = .{ .schema = "stwo-resident-parent-hash-witness-v1", .scope = "device hash witness primitive only; not a complete resident prover", .source_sha256 = std.fmt.bytesToHex(sha, .lower), .cases = 4, .cpu_numeric_input = false, .cpu_witness_oracle = true, .device_readback = "test oracle only", .full_parent_qualified = false };
    const json = try std.json.Stringify.valueAlloc(a, receipt, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try dir.writeFile(.{ .sub_path = "source_manifest.json", .data = json });
    std.debug.print("RESIDENT_PARENT_HASH_EXPORT source_bytes={d} vector_bytes={d} source_sha256={s}\n", .{ source.len, binary.written().len, std.fmt.bytesToHex(sha, .lower) });
}
fn word(w: anytype, x: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, x, .little);
    try w.writeAll(&b);
}
fn words(w: anytype, x: []align(1) const u32) !void {
    try word(w, @intCast(x.len));
    for (x) |v| try word(w, v);
}
fn one(backing: std.mem.Allocator, w: anytype, lengths: []const usize, variant: u32) !void {
    var arena = std.heap.ArenaAllocator.init(backing);
    defer arena.deinit();
    const a = arena.allocator();
    const plan = try P.Owned.derive(a, lengths, .{});
    defer plan.deinit();
    const p = plan.view();
    const g_rows = @as(usize, 1) << @intCast(p.g_log);
    const x_rows = @as(usize, 1) << @intCast(p.xor_log);
    const input = try a.alloc(u8, (p.input_bytes + 3) / 4 * 4);
    @memset(input, 0);
    for (input[0..p.input_bytes], 0..) |*b, i| b.* = switch (variant) {
        0 => 0,
        1 => 255,
        else => @truncate(i *% 131 + 17 + variant),
    };
    const gs = try a.alloc(u32, 82 * g_rows);
    @memset(gs, 0);
    const xs = try a.alloc(u32, 12 * x_rows);
    @memset(xs, 0);
    const outputs = try a.alloc(u32, p.frames.len * 8);
    const digests = try a.alloc(u32, p.frames.len * 8);
    for (p.frames, 0..) |frame, f| {
        const bytes = input[frame.input_first..][0..frame.input_bytes];
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(bytes, &digest, .{});
        var expected = try Hash.prepare(a, @intCast(f + 1), bytes, digest);
        defer expected.rows.deinit();
        try std.testing.expectEqualSlices(u8, &digest, &expected.digest);
        for (expected.rows.g_rows, 0..) |row, i| {
            const dst = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(frame.first_call * 56 + i, p.g_log), p.g_log);
            for (row[0..82], 0..) |v, j| gs[j * g_rows + dst] = v.toU32();
        }
        for (expected.rows.xor_rows, 0..) |row, i| {
            const dst = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(frame.first_call * 16 + i, p.xor_log), p.xor_log);
            for (row[0..12], 0..) |v, j| xs[j * x_rows + dst] = v.toU32();
        }
        for (frame.digest, 0..) |wire, j| {
            outputs[f * 8 + j] = wire;
            digests[f * 8 + j] = std.mem.readInt(u32, digest[j * 4 ..][0..4], .little);
        }
    }
    try word(w, p.wire_count);
    try word(w, p.g_log);
    try word(w, p.xor_log);
    try word(w, @intCast(p.input_bytes));
    try words(w, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(p.sources)));
    try words(w, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(p.calls)));
    try words(w, p.level_calls);
    try words(w, p.level_offsets);
    try words(w, outputs);
    try words(w, std.mem.bytesAsSlice(u32, input));
    try words(w, gs);
    try words(w, xs);
    try words(w, digests);
    try words(w, p.phase_calls);
    try word(w, @intCast(p.frames.len));
    for (p.frames) |frame| {
        try word(w, @intCast(frame.first_source));
        try word(w, @intCast(frame.source_count));
        try words(w, frame.level_offsets);
    }
}

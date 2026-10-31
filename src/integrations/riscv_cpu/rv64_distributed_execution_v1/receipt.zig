//! Bounded diagnostic receipt for three actual proofs. u64 PCs/registers/step
//! spans use explicit LE64, never JSON numbers. A receipt is untrusted advice;
//! readAndVerify reconstructs expected keys and performs aggregate verification.
const std = @import("std");
const air = @import("stwo_riscv_frontend").rv64_air;
const Q = @import("stwo_core").fields.qm31.QM31;
const CPU = @import("../word16/cpu.zig");
const Claims = @import("../word16/cpu_sources.zig").Claims;
const A = @import("aggregate.zig");
const P = @import("public.zig");
const D = @import("../rv64_distributed_v1/manifest.zig");
const W = @import("../rv64_distributed_v1/wire.zig");
const IO = @import("../rv64_work_packet_io.zig");
const JSON = struct { cpu: [2]Claims, binary: air.word16_v1.binary_lookup.Claims, and_table: Q };
const names = [_][]const u8{ "cpu-0.bin", "cpu-1.bin", "binary.bin" };
const SHARD_BYTES = 672;
pub fn write(dir: std.fs.Dir, encoded: *const A.Encoded) !void {
    const boundary = try dir.createFile("boundaries.bin", .{});
    defer boundary.close();
    var out = IO.Writer{ .file = boundary };
    try out.bytes("RV64BE01");
    try out.int(u32, 1);
    try out.int(u32, 2);
    for (encoded.shards) |shard| {
        try out.int(u64, shard.first_step);
        try out.int(u32, shard.cpu_log);
        try out.int(u32, shard.public.steps);
        try out.int(u64, shard.public.initial_pc);
        try out.int(u64, shard.public.final_pc);
        for (shard.public.initial_registers) |value| try out.int(u64, value);
        for (shard.public.final_registers) |value| try out.int(u64, value);
        for (shard.public.register_clocks) |value| try out.int(u32, value);
    }
    try out.flush();
    const manifest = try dir.createFile("manifest.bin", .{});
    defer manifest.close();
    try W.write(manifest, &encoded.manifest);
    for ([_][]const u8{ encoded.cpu[0].bytes, encoded.cpu[1].bytes, encoded.binary.bytes }, names) |bytes, name| try dir.writeFile(.{ .sub_path = name, .data = bytes });
    const json = try std.json.Stringify.valueAlloc(encoded.manifest.allocator, JSON{ .cpu = .{ encoded.cpu[0].claims, encoded.cpu[1].claims }, .binary = encoded.binary.claims, .and_table = encoded.binary.and_table_claim }, .{});
    defer encoded.manifest.allocator.free(json);
    try dir.writeFile(.{ .sub_path = "claims.json", .data = json });
}
pub fn readBoundaries(dir: std.fs.Dir) !P.Boundaries {
    const file = try dir.openFile("boundaries.bin", .{});
    defer file.close();
    var header: [16]u8 = undefined;
    try IO.exact(file, &header);
    if (!std.mem.eql(u8, header[0..8], "RV64BE01") or std.mem.readInt(u32, header[8..12], .little) != 1 or std.mem.readInt(u32, header[12..16], .little) != 2) return error.InvalidDistributedExecutionReceipt;
    var reader = IO.Reader{ .file = file, .remaining = 2 * SHARD_BYTES };
    var shards: P.Boundaries = undefined;
    for (&shards) |*shard| {
        shard.first_step = try reader.int(u64);
        shard.cpu_log = try reader.int(u32);
        shard.public.steps = try reader.int(u32);
        shard.public.initial_pc = try reader.int(u64);
        shard.public.final_pc = try reader.int(u64);
        for (&shard.public.initial_registers) |*value| value.* = try reader.int(u64);
        for (&shard.public.final_registers) |*value| value.* = try reader.int(u64);
        for (&shard.public.register_clocks) |*value| value.* = try reader.int(u32);
        try shard.public.validate(shard.cpu_log);
    }
    try reader.finish();
    var extra: [1]u8 = undefined;
    if (try file.read(&extra) != 0) return error.TrailingDistributedExecutionReceipt;
    return shards;
}
pub fn readAndVerify(a: std.mem.Allocator, dir: std.fs.Dir, expected: A.Expected, program: *const air.word16_cpu.rom.Setup) !void {
    const shards = try readBoundaries(dir);
    var prepared = try A.Prepared.init(a, expected, program, shards);
    defer prepared.deinit();
    var encoded = try readBody(a, dir, expected, &prepared, shards);
    defer encoded.deinit(a);
    try A.verifyPrepared(a, &prepared, expected, program, &encoded);
}
/// Decode-only owner; NOT an acceptance result. Caller must run verifyPrepared.
/// This seam qualifies exhaustive allocation cleanup without redoing key FFTs.
pub fn readPrepared(a: std.mem.Allocator, dir: std.fs.Dir, expected: A.Expected, program: *const air.word16_cpu.rom.Setup, prepared: *const A.Prepared) !A.Encoded {
    const shards = try readBoundaries(dir);
    try expected.validate(program, shards);
    return readBody(a, dir, expected, prepared, shards);
}
fn readBody(a: std.mem.Allocator, dir: std.fs.Dir, expected: A.Expected, prepared: *const A.Prepared, shards: P.Boundaries) !A.Encoded {
    const specs = try prepared.descriptors(expected, shards);
    const manifest_file = try dir.openFile("manifest.bin", .{});
    defer manifest_file.close();
    var manifest = try W.read(a, manifest_file, .{ .context = expected.context(), .specs = &specs });
    var owns_manifest = true;
    defer if (owns_manifest) manifest.deinit();
    var bytes: [3][]u8 = undefined;
    var n: usize = 0;
    errdefer for (bytes[0..n]) |data| a.free(data);
    for (&bytes, names) |*data, name| {
        data.* = try dir.readFileAlloc(a, name, 32 * 1024 * 1024);
        n += 1;
    }
    const raw = try dir.readFileAlloc(a, "claims.json", 32 * 1024);
    defer a.free(raw);
    const claims = try std.json.parseFromSlice(JSON, a, raw, .{});
    defer claims.deinit();
    const encoded = A.Encoded{ .shards = shards, .manifest = manifest, .cpu = .{
        CPU.Encoded{ .bytes = bytes[0], .claims = claims.value.cpu[0] },
        CPU.Encoded{ .bytes = bytes[1], .claims = claims.value.cpu[1] },
    }, .binary = .{ .bytes = bytes[2], .claims = claims.value.binary, .and_table_claim = claims.value.and_table } };
    owns_manifest = false;
    n = 0;
    return encoded;
}

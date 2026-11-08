//! Native physical child suffix: PCS image, leaf statement seed tape and
//! hash of the public frame. Programs contain class/public metadata only;
//! GKR coefficients, claims, MAIN and manifest digests come from the device.
const std = @import("std");
pub const magic: u32 = 0x3157464c; // LFW1
pub const header_words = 16;
pub const modulus = 0x7fff_ffff;
pub const Source = enum(u32) { pool, section, manifest, receipt, claims, pcs };
pub const Kind = enum(u32) { word, felts, polynomial };
pub const Op = extern struct { kind: Kind, source: Source, offset: u32, count: u32 };
pub const Run = extern struct {
    program: [*]const u32,
    program_words: u64,
    sources: [6]?[*]const u32,
    source_words: [6]u64,
    region: [*]u32,
    region_words: u64,
    verdict: [*]u32,
    reject_code: u32,
    reserved: u32 = 0,
};
comptime {
    if (@sizeOf(Run) != 144) @compileError("native leaf suffix ABI changed");
}
pub const EncodeFn = *const fn (*anyopaque, u32, *const Run) callconv(.c) c_int;
pub fn load(addon: *std.DynLib) !EncodeFn {
    return addon.lookup(EncodeFn, "stwo_rv64_native_leaf_suffix_v1_on") orelse error.MissingNativeLeafEncoder;
}
pub const Buffer = struct { ptr: [*]u32, words: usize };
pub const Copy = *const fn (*anyopaque, *anyopaque, *const anyopaque, usize) callconv(.c) c_int;
pub fn enqueue(sym: EncodeFn, copy: Copy, ctx: *anyopaque, program: *const Program, device: Buffer, sources: [6]?Buffer, region: Buffer, verdict: [*]u32, reject_code: u32) !void {
    if (region.words != program.regionWords() or device.words != program.words.len) return error.NativeLeafRegionBounds;
    const pcs = sources[5] orelse return error.NativeLeafSourceBounds;
    if (pcs.words != program.words[11]) return error.NativeLeafSourceBounds;
    if (copy(ctx, region.ptr + program.words[10], pcs.ptr, pcs.words * 4) != 0) return error.CudaEnqueueFailed;
    var args = Run{ .program = device.ptr, .program_words = device.words, .sources = @splat(null), .source_words = @splat(0), .region = region.ptr, .region_words = region.words, .verdict = verdict, .reject_code = reject_code };
    for (sources, 0..) |source, i| if (source) |b| {
        args.sources[i] = b.ptr;
        args.source_words[i] = b.words;
    };
    if (sym(ctx, 0, &args) != 0) return error.CudaEnqueueFailed;
}
pub const Geometry = struct { wire_words: u32, image_words: u32, tail_seeds: u32, output_words: u32 = 32 };
pub const Program = struct {
    a: std.mem.Allocator,
    words: []u32,
    pub fn deinit(self: *Program) void {
        self.a.free(self.words);
    }
    pub fn key(self: *const Program) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("rv64/m8/native-leaf-suffix/v1");
        hash.update(std.mem.sliceAsBytes(self.words));
        return hash.finalResult();
    }
    pub fn regionWords(self: *const Program) usize {
        return @as(usize, self.words[10]) + self.words[11] + 4 * @as(usize, self.words[8]) + self.words[12];
    }
    pub fn build(a: std.mem.Allocator, geometry: Geometry, pool: []const u32, tail: []const Op, frame: []const Op) !Program {
        if (geometry.wire_words < 2 or geometry.image_words < 1 or geometry.output_words != 32 or geometry.tail_seeds > 1 << 20 or tail.len + frame.len > 1 << 16) return error.NativeLeafProgramShape;
        var seeds: u64 = 0;
        var frame_words: u64 = 0;
        for (tail) |op| {
            try checkOp(op, pool.len);
            seeds += 2 * @as(u64, op.count);
        }
        for (frame) |op| {
            try checkOp(op, pool.len);
            if (op.kind == .polynomial) return error.NativeLeafProgramShape;
            frame_words += @as(u64, op.count) * (if (op.kind == .felts) @as(u64, 8) else 1);
        }
        if (seeds != geometry.tail_seeds or frame_words == 0 or frame_words > 1 << 20) return error.NativeLeafProgramShape;
        const n = header_words + 4 * (tail.len + frame.len) + pool.len;
        if (n > 1 << 20) return error.NativeLeafProgramShape;
        const words = try a.alloc(u32, n);
        @memcpy(words[0..header_words], &[_]u32{ magic, 1, @intCast(n), @intCast(tail.len), @intCast(frame.len), header_words, @intCast(header_words + 4 * (tail.len + frame.len)), @intCast(pool.len), geometry.tail_seeds, @intCast(frame_words), geometry.wire_words, geometry.image_words, geometry.output_words, 0, 0, 0 });
        var at: usize = header_words;
        for ([_][]const Op{ tail, frame }) |ops| for (ops) |op| {
            @memcpy(words[at..][0..4], &[_]u32{ @intFromEnum(op.kind), @intFromEnum(op.source), op.offset, op.count });
            at += 4;
        };
        @memcpy(words[at..], pool);
        return .{ .a = a, .words = words };
    }
};
fn checkOp(op: Op, pool_words: usize) !void {
    if (op.kind == .polynomial and (op.source != .section or op.count > 4)) return error.NativeLeafProgramShape;
    const count = @as(u64, op.count) * (if (op.kind == .word) @as(u64, 1) else 8);
    if (op.source == .pool and @as(u64, op.offset) + count > pool_words) return error.NativeLeafProgramShape;
}
pub const Sources = [6][]const u32;
/// Claims were written as raw canonical OM31 coordinates in the tail. This
/// is publication slicing after the single readback, not proof assembly.
pub fn claimWords(program: *const Program, region: []const u32) ![]const u32 {
    const p = program.words;
    if (region.len != program.regionWords()) return error.NativeLeafRegionBounds;
    var at: usize = @as(usize, p[10]) + p[11];
    for (0..p[3]) |i| {
        const op = p[header_words + 4 * i ..][0..4];
        const words = @as(usize, op[3]) * 8;
        if (op[1] == @intFromEnum(Source.claims)) {
            if (op[0] != @intFromEnum(Kind.felts) or op[2] != 0 or at + words > region.len) return error.NativeLeafProgramShape;
            return region[at..][0..words];
        }
        at += words;
    }
    return error.NativeLeafProgramShape;
}
pub fn frameWords(a: std.mem.Allocator, program: *const Program, sources: Sources) ![]u32 {
    const p = program.words;
    const out = try a.alloc(u32, p[9]);
    errdefer a.free(out);
    var at: usize = 0;
    for (0..p[4]) |i| {
        const op = p[header_words + 4 * (p[3] + i) ..][0..4];
        if (op[0] == @intFromEnum(Kind.polynomial)) return error.NativeLeafProgramShape;
        const values = try read(p, op, sources);
        if (values.len > out.len - at) return error.NativeLeafProgramShape;
        @memcpy(out[at..][0..values.len], values);
        at += values.len;
    }
    if (at != out.len) return error.NativeLeafProgramShape;
    return out;
}
fn read(p: []const u32, op: []const u32, sources: Sources) ![]const u32 {
    if (op[0] > 2 or op[1] > 5) return error.NativeLeafProgramShape;
    const src = if (op[1] == 0) p[p[6]..][0..p[7]] else sources[op[1]];
    const n = @as(u64, op[3]) * (if (op[0] == 0) @as(u64, 1) else 8);
    if (@as(u64, op[2]) + n > src.len) return error.NativeLeafSourceBounds;
    if (op[0] == 2) {
        if (op[1] != 1 or op[3] > 4 or @as(u64, op[2]) + 44 > src.len or src[op[2] + 40] != op[3]) return error.NativeLeafPolynomialShape;
    }
    const words = src[op[2]..][0..@intCast(n)];
    if (op[0] != 0) for (words) |word| if (word >= modulus) return error.NativeLeafNoncanonical;
    return words;
}

/// Independent host interpreter for codec parity, not used by the service.
pub fn reference(program: *const Program, sources: Sources, region: []u32) !void {
    const p = program.words;
    if (region.len < program.regionWords() or sources[5].len != p[11]) return error.NativeLeafRegionBounds;
    if (region[0] == 0 or region[0] > @as(u64, p[10] - 1) * 4) return error.NativeLeafRegionBounds;
    @memcpy(region[p[10]..][0..p[11]], sources[5]);
    var dst: usize = @as(usize, p[10]) + p[11];
    for (0..p[3]) |i| {
        const op = p[header_words + 4 * i ..][0..4];
        const values = try read(p, op, sources);
        if (op[0] == 0) {
            for (values) |word| {
                @memcpy(region[dst..][0..8], &[_]u32{ word & 0xffff, 0, 0, 0, word >> 16, 0, 0, 0 });
                dst += 8;
            }
        } else {
            @memcpy(region[dst..][0..values.len], values);
            dst += values.len;
        }
    }
    if (dst != @as(usize, p[10]) + p[11] + 4 * @as(usize, p[8])) return error.NativeLeafProgramShape;
    var hash = std.crypto.hash.blake2.Blake2s256.init(.{});
    var bytes: [4]u8 = undefined;
    var count: usize = 0;
    for (0..p[4]) |i| {
        const op = p[header_words + 4 * (p[3] + i) ..][0..4];
        for (try read(p, op, sources)) |word| {
            std.mem.writeInt(u32, &bytes, word, .little);
            hash.update(&bytes);
            count += 1;
        }
    }
    if (count != p[9]) return error.NativeLeafProgramShape;
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    for (0..8) |i| {
        const word = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
        @memcpy(region[dst + 4 * i ..][0..4], &[_]u32{ word & 0xffff, word >> 16, 0, 0 });
    }
}

test "leaf suffix: distinct word/OM encodings and public hash; shape and canonical guards" {
    const a = std.testing.allocator;
    const t = std.testing;
    const tail = [_]Op{ .{ .kind = .word, .source = .pool, .offset = 0, .count = 1 }, .{ .kind = .polynomial, .source = .section, .offset = 0, .count = 2 }, .{ .kind = .felts, .source = .claims, .offset = 0, .count = 1 } };
    const frame = [_]Op{ .{ .kind = .word, .source = .pool, .offset = 0, .count = 1 }, .{ .kind = .felts, .source = .claims, .offset = 0, .count = 1 } };
    var p = try Program.build(a, .{ .wire_words = 10, .image_words = 9, .tail_seeds = 8 }, &.{0xfedc_ba98}, &tail, &frame);
    defer p.deinit();
    var section: [44]u32 = @splat(1);
    section[40] = 2;
    const claims = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const pcs = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    const sources: Sources = .{ &.{}, &section, &.{}, &.{}, &claims, &pcs };
    const out = try a.alloc(u32, p.regionWords());
    defer a.free(out);
    @memset(out, 0);
    out[0] = 3;
    try reference(&p, sources, out);
    try t.expectEqualSlices(u32, &.{ 0xba98, 0, 0, 0, 0xfedc, 0, 0, 0 }, out[19..27]);
    try t.expectEqualSlices(u32, &claims, out[43..51]);
    try t.expectEqualSlices(u32, &claims, try claimWords(&p, out));
    const public_frame = try frameWords(a, &p, sources);
    defer a.free(public_frame);
    try t.expectEqual(@as(u32, 0xfedc_ba98), public_frame[0]);
    try t.expectEqualSlices(u32, &claims, public_frame[1..]);
    var frame_bytes: [36]u8 = undefined;
    std.mem.writeInt(u32, frame_bytes[0..4], 0xfedc_ba98, .little);
    for (claims, 0..) |word, i| std.mem.writeInt(u32, frame_bytes[4 + 4 * i ..][0..4], word, .little);
    var expected: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&frame_bytes, &expected, .{});
    for (0..8) |i| try t.expectEqual(std.mem.readInt(u32, expected[4 * i ..][0..4], .little), out[51 + 4 * i] | out[52 + 4 * i] << 16);
    section[40] = 1;
    try t.expectError(error.NativeLeafPolynomialShape, reference(&p, sources, out));
    section[40] = 2;
    section[0] = modulus;
    try t.expectError(error.NativeLeafNoncanonical, reference(&p, sources, out));
    try t.expectError(error.NativeLeafRegionBounds, reference(&p, sources, out[0 .. out.len - 1]));
    try t.expectError(error.NativeLeafProgramShape, Program.build(a, .{ .wire_words = 10, .image_words = 9, .tail_seeds = 6 }, &.{1}, &tail, &frame));
}

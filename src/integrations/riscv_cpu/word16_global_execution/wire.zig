//! Two-shard transport only. Sidecar hashes detect corruption; actual PCS roots,
//! physical claims and independent Expected authority remain the receiver's job.
const std = @import("std");
const E = @import("execution.zig");
const P = @import("protocol.zig");
const G = @import("../word16_execution/geometry.zig");
const Cells = @import("../word16_execution/cells_wire.zig");
const Receipt = @import("../rv64_ethereum_batch_receipt.zig");
const Cell = @import("../word16_execution/memory/statement.zig").Cell;
const MAX_META = 1 << 20;
const MAX_LEGACY = 512 << 20;
pub const Request = struct {
    cpu: @FieldType(P.Old.Request, "cpu"),
    epoch: u16,
    division_requests: u32,
    multiplication_requests: u32,
    memory_epoch: u16,
    ls_count: u32,
    fn from(r: P.Old.Request) Request {
        return .{ .cpu = r.cpu, .epoch = r.epoch, .division_requests = r.division_requests, .multiplication_requests = r.multiplication_requests, .memory_epoch = r.memory.epoch, .ls_count = r.memory.ls_count };
    }
    fn expand(self: Request, initial: []const Cell, terminal: []const Cell) P.Old.Request {
        return .{ .cpu = self.cpu, .epoch = self.epoch, .division_requests = self.division_requests, .multiplication_requests = self.multiplication_requests, .memory = .{ .initial = initial, .terminal = terminal, .epoch = self.memory_epoch, .ls_count = self.ls_count } };
    }
};
pub const Metadata = struct {
    schema: u32 = 2,
    geometries: [2]G.Geometry,
    requests: [2]Request,
    claims: [2]P.Old.Claims,
    specs: [2][32]u8,
    roots: [2]P.Receipt,
    seal: [32]u8,
    memory_words: u32,
    cells_sha256: [32]u8,
};
const Legacy = struct { schema: u32 = 1, geometries: [2]G.Geometry, requests: [2]P.Old.Request, claims: [2]P.Old.Claims, specs: [2][32]u8, roots: [2]P.Receipt, seal: [32]u8 };
pub const Loaded = struct {
    geometries: [2]G.Geometry,
    bundle: E.Bundle,
    pub fn deinit(self: *Loaded, a: std.mem.Allocator) void {
        self.bundle.deinit(a);
    }
};
fn hashCells(dir: std.fs.Dir, words: u32) ![32]u8 {
    if (words > 1 << 22) return error.InvalidMemorySidecarCount;
    var file = try dir.openFile("cells.bin", .{});
    defer file.close();
    if (try file.getEndPos() != 16 + 46 * @as(u64, words)) return error.InvalidMemorySidecarSize;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [65536]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hash.update(buffer[0..count]);
    }
    return hash.finalResult();
}
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, geometries: [2]G.Geometry, bundle: *const E.Bundle) !void {
    if (bundle.proofs.len != 2 or bundle.manifest.specs.len != 2 or bundle.manifest.roots.len != 2) return error.InvalidGlobalWireRoster;
    const first = bundle.proofs[0].request.memory;
    const last = bundle.proofs[1].request.memory;
    if (first.terminal.len != 0 or last.initial.len != 0 or first.initial.len != last.terminal.len or first.initial.len > 1 << 22) return error.InvalidGlobalWireBoundary;
    try Cells.write(dir, first.initial, last.terminal);
    const meta = Metadata{ .geometries = geometries, .requests = .{ Request.from(bundle.proofs[0].request), Request.from(bundle.proofs[1].request) }, .claims = .{ bundle.proofs[0].claims, bundle.proofs[1].claims }, .specs = bundle.manifest.specs[0..2].*, .roots = bundle.manifest.roots[0..2].*, .seal = bundle.manifest.digest, .memory_words = @intCast(first.initial.len), .cells_sha256 = try hashCells(dir, @intCast(first.initial.len)) };
    const json = try std.json.Stringify.valueAlloc(a, meta, .{ .whitespace = .indent_2 });
    defer a.free(json);
    if (json.len > MAX_META) return error.GlobalMetadataLimit;
    try Receipt.writeExclusive(dir, "proof0.bin", bundle.proofs[0].bytes);
    try Receipt.writeExclusive(dir, "proof1.bin", bundle.proofs[1].bytes);
    // Metadata is the ready marker: publish only after every sidecar has synced.
    try Receipt.writeExclusive(dir, "bundle.json", json);
    try std.posix.fsync(dir.fd);
}
fn legacyPrefix(bytes: []const u8) bool {
    var i: usize = 0;
    const tokens = [_][]const u8{ "{", "\"schema\"", ":", "1" };
    for (tokens) |token| {
        while (i < bytes.len and std.ascii.isWhitespace(bytes[i])) : (i += 1) {}
        if (!std.mem.startsWith(u8, bytes[i..], token)) return false;
        i += token.len;
    }
    return i < bytes.len and (std.ascii.isWhitespace(bytes[i]) or bytes[i] == ',');
}
pub fn read(a: std.mem.Allocator, dir: std.fs.Dir) !Loaded {
    var file = try dir.openFile("bundle.json", .{});
    defer file.close();
    const len = try file.getEndPos();
    if (len > MAX_LEGACY) return error.GlobalMetadataLimit;
    if (len > MAX_META) {
        var prefix: [128]u8 = undefined;
        const count = try file.readAll(&prefix);
        if (!legacyPrefix(prefix[0..count])) return error.GlobalMetadataLimit;
        try file.seekTo(0);
    }
    const bytes = try file.readToEndAlloc(a, MAX_LEGACY);
    defer a.free(bytes);
    const header = try std.json.parseFromSlice(struct { schema: u32 }, a, bytes, .{ .ignore_unknown_fields = true });
    defer header.deinit();
    if (header.value.schema == 1) return readLegacy(a, dir, bytes);
    if (header.value.schema != 2 or bytes.len > MAX_META) return error.UnsupportedGlobalExecutionBundle;
    const parsed = try std.json.parseFromSlice(Metadata, a, bytes, .{});
    defer parsed.deinit();
    const m = parsed.value;
    for (m.geometries) |g| try g.validate();
    if (!std.mem.eql(u8, &m.cells_sha256, &try hashCells(dir, m.memory_words))) return error.GlobalMemorySidecarChanged;
    const cells = try Cells.read(a, dir, m.memory_words);
    errdefer cells.deinit(a);
    const requests = [2]P.Old.Request{ m.requests[0].expand(cells.initial, &.{}), m.requests[1].expand(&.{}, cells.terminal) };
    return finish(a, dir, m.geometries, requests, m.claims, m.specs, m.roots, m.seal);
}
fn readLegacy(a: std.mem.Allocator, dir: std.fs.Dir, bytes: []const u8) !Loaded {
    const parsed = try std.json.parseFromSlice(Legacy, a, bytes, .{});
    defer parsed.deinit();
    const m = parsed.value;
    for (m.geometries) |g| try g.validate();
    if (m.requests[0].memory.terminal.len != 0 or m.requests[1].memory.initial.len != 0 or m.requests[0].memory.initial.len != m.requests[1].memory.terminal.len or m.requests[0].memory.initial.len > 1 << 22) return error.InvalidGlobalWireBoundary;
    const initial = try a.dupe(Cell, m.requests[0].memory.initial);
    errdefer a.free(initial);
    const terminal = try a.dupe(Cell, m.requests[1].memory.terminal);
    errdefer a.free(terminal);
    var requests = m.requests;
    requests[0].memory.initial = initial;
    requests[0].memory.terminal = &.{};
    requests[1].memory.initial = &.{};
    requests[1].memory.terminal = terminal;
    return finish(a, dir, m.geometries, requests, m.claims, m.specs, m.roots, m.seal);
}
fn finish(a: std.mem.Allocator, dir: std.fs.Dir, geometries: [2]G.Geometry, requests: [2]P.Old.Request, claims: [2]P.Old.Claims, specs: [2][32]u8, roots: [2]P.Receipt, seal: [32]u8) !Loaded {
    var manifest = try P.Manifest.init(a, &specs, &roots);
    errdefer manifest.deinit();
    if (!std.mem.eql(u8, &manifest.digest, &seal)) return error.GlobalExecutionManifestChanged;
    const first = try dir.readFileAlloc(a, "proof0.bin", 64 << 20);
    errdefer a.free(first);
    const second = try dir.readFileAlloc(a, "proof1.bin", 64 << 20);
    errdefer a.free(second);
    const proofs = try a.alloc(E.Encoded, 2);
    proofs[0] = .{ .bytes = first, .request = requests[0], .claims = claims[0] };
    proofs[1] = .{ .bytes = second, .request = requests[1], .claims = claims[1] };
    return .{ .geometries = geometries, .bundle = .{ .manifest = manifest, .proofs = proofs } };
}

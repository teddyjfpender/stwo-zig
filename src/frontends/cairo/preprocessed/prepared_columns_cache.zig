//! Reuses only public preprocessing coefficients and extended evaluations.
//! Source content participates in the key before any in-place interpolation.
//! Mapped artifacts are fully authenticated before either destination is
//! modified, so every miss can safely run the ordinary preparation path.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cache = @import("product_cache.zig");
const integrity = @import("tree_digest_cache.zig");
const M31 = core.fields.m31.M31;
const Request = prover.pcs.column_preparation_cache.Request;
const header_bytes = 128;
const magic = "STWOZPC1";
const maximum_payload: u64 = 8 * 1024 * 1024 * 1024;

const Session = struct {
    allocator: std.mem.Allocator,
    binding: cache.Binding,
    recorder: ?*prover.stage_profile.Recorder,
    remaining: u64,
};
threadlocal var session: Session = undefined;

pub fn arm(allocator: std.mem.Allocator, binding: cache.Binding, recorder: ?*prover.stage_profile.Recorder) void {
    if (!cache.isEnabled() or builtin.cpu.arch.endian() != .little) return;
    const enabled = if (std.posix.getenv("STWO_CAIRO_PREPROCESSED_COLUMNS")) |value| std.mem.eql(u8, value, "1") else false;
    if (!enabled or std.process.hasEnvVarConstant("STWO_ZIG_METAL_RETAINED_LDE_PARITY")) return;
    const budget = cache.currentConfig().budget_bytes;
    // Reserve space for the source table and compact Merkle layers. A smaller
    // budget admits fewer prepared groups instead of exceeding the bound.
    const available = if (budget == 0) maximum_payload else budget -| (1024 * 1024 * 1024);
    session = .{ .allocator = allocator, .binding = binding, .recorder = recorder, .remaining = @min(maximum_payload, available) };
    prover.pcs.column_preparation_cache.arm(.{ .ctx = &session, .identify = identifyThunk, .load = loadThunk, .store = storeThunk });
}

pub fn disarm() void {
    prover.pcs.column_preparation_cache.disarm();
}

fn payloadBytes(request: Request) !u64 {
    if (request.column_count == 0 or request.base_log_size == 0 or request.extended_log_size <= request.base_log_size or request.extended_log_size > 30)
        return error.PreparedCacheUnusable;
    const rows = (@as(u64, 1) << @intCast(request.base_log_size)) + (@as(u64, 1) << @intCast(request.extended_log_size));
    const bytes = try std.math.mul(u64, try std.math.mul(u64, rows, request.column_count), @sizeOf(M31));
    if (bytes > maximum_payload) return error.PreparedCacheUnusable;
    return bytes;
}

fn header(key: [32]u8, request: Request) ![header_bytes]u8 {
    var out: [header_bytes]u8 = @splat(0);
    @memcpy(out[0..8], magic);
    std.mem.writeInt(u32, out[8..12], 1, .little);
    std.mem.writeInt(u32, out[12..16], 3, .little);
    @memcpy(out[16..48], &key);
    std.mem.writeInt(u32, out[48..52], request.base_log_size, .little);
    std.mem.writeInt(u32, out[52..56], request.extended_log_size, .little);
    std.mem.writeInt(u64, out[56..64], request.column_count, .little);
    std.mem.writeInt(u64, out[64..72], try payloadBytes(request), .little);
    std.mem.writeInt(u32, out[72..76], 4 * 1024 * 1024, .little);
    return out;
}

fn keyFor(state: *Session, request: Request, sources: []const []const M31) ![32]u8 {
    if (sources.len != request.column_count) return error.PreparedCacheUnusable;
    const views = try state.allocator.alloc([]const u8, sources.len);
    defer state.allocator.free(views);
    for (sources, views) |source, *view| {
        if (source.len != @as(usize, 1) << @intCast(request.base_log_size)) return error.PreparedCacheUnusable;
        view.* = std.mem.sliceAsBytes(source);
    }
    const source_header = try header(@splat(0), request);
    const source_digest = try integrity.integrityDigest(state.allocator, &source_header, views);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("stwo-zig/cairo-prepared-public-columns/v1\x00");
    hasher.update(&cache.currentConfig().product_digest);
    hasher.update(@tagName(state.binding.variant));
    hasher.update("\x00");
    hasher.update(&state.binding.spec_digest);
    hasher.update(&state.binding.pcs_digest);
    hasher.update(&source_digest);
    return hasher.finalResult();
}

fn identifyThunk(raw: *anyopaque, request: Request, sources: []const []const M31) ?[32]u8 {
    const state: *Session = @ptrCast(@alignCast(raw));
    const payload = payloadBytes(request) catch return null;
    const total = payload + header_bytes + 32;
    if (payload < 8 * 1024 * 1024 or total > state.remaining) return null;
    var stage = prover.stage_profile.StageScope.begin(state.recorder, "preprocessed_columns_identity", "Public column source identity") catch return null;
    defer stage.end();
    const key = keyFor(state, request, sources) catch return null;
    state.remaining -= total;
    cache.protectKey(key);
    return key;
}

fn pathFor(buffer: []u8, key: [32]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}/{s}.preprocessed-columns", .{ cache.currentConfig().directory, std.fmt.bytesToHex(key, .lower) });
}

fn viewsFor(allocator: std.mem.Allocator, request: Request, coefficients: []const []M31, evaluations: []const []M31) ![][]const u8 {
    if (coefficients.len != request.column_count or evaluations.len != request.column_count) return error.PreparedCacheUnusable;
    _ = try payloadBytes(request);
    const views = try allocator.alloc([]const u8, try std.math.mul(usize, 2, request.column_count));
    errdefer allocator.free(views);
    for (coefficients, evaluations, 0..) |coefficient, evaluation, index| {
        if (coefficient.len != @as(usize, 1) << @intCast(request.base_log_size) or evaluation.len != @as(usize, 1) << @intCast(request.extended_log_size)) return error.PreparedCacheUnusable;
        views[index] = std.mem.sliceAsBytes(coefficient);
        views[request.column_count + index] = std.mem.sliceAsBytes(evaluation);
    }
    return views;
}

fn canonical(bytes: []const u8) bool {
    if (bytes.len % @sizeOf(u32) != 0) return false;
    const words = std.mem.bytesAsSlice(u32, @as([]align(4) const u8, @alignCast(bytes)));
    const width = core.fields.m31.PACK_WIDTH;
    var at: usize = 0;
    while (at + width <= words.len) : (at += width) {
        const values: @Vector(width, u32) = words[at..][0..width].*;
        if (@reduce(.Or, values >= @as(@Vector(width, u32), @splat(core.fields.m31.Modulus)))) return false;
    }
    for (words[at..]) |word| if (word >= core.fields.m31.Modulus) return false;
    return true;
}

fn load(state: *Session, key: [32]u8, request: Request, coefficients: []const []M31, evaluations: []const []M31) !void {
    var stage = try prover.stage_profile.StageScope.begin(state.recorder, "preprocessed_columns_cache_load", "Prepared public column cache load");
    defer stage.end();
    const views = try viewsFor(state.allocator, request, coefficients, evaluations);
    defer state.allocator.free(views);
    const expected_header = try header(key, request);
    const payload = try payloadBytes(request);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const file = try std.fs.openFileAbsolute(try pathFor(&path_buffer, key), .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size != payload + header_bytes + 32) return error.PreparedCacheUnusable;
    const mapping = try std.posix.mmap(null, @intCast(stat.size), std.posix.PROT.READ, .{ .TYPE = .PRIVATE }, file.handle, 0);
    defer std.posix.munmap(mapping);
    if (!std.mem.eql(u8, &expected_header, mapping[0..header_bytes])) return error.PreparedCacheUnusable;
    const mapped_views = try state.allocator.alloc([]const u8, views.len);
    defer state.allocator.free(mapped_views);
    var at: usize = header_bytes;
    for (views, mapped_views) |view, *mapped| {
        mapped.* = mapping[at..][0..view.len];
        if (!canonical(mapped.*)) return error.PreparedCacheUnusable;
        at += view.len;
    }
    const digest = try integrity.integrityDigest(state.allocator, &expected_header, mapped_views);
    if (!std.crypto.timing_safe.eql([32]u8, digest, mapping[at..][0..32].*)) return error.PreparedCacheUnusable;
    // All checks and allocations precede these infallible publications. In
    // particular, coefficients may alias the original source values.
    for (coefficients, mapped_views[0..coefficients.len]) |destination, source| @memcpy(std.mem.sliceAsBytes(destination), source);
    for (evaluations, mapped_views[coefficients.len..]) |destination, source| @memcpy(std.mem.sliceAsBytes(destination), source);
    cache.touchArtifact(file);
}

fn loadThunk(raw: *anyopaque, key: [32]u8, request: Request, coefficients: []const []M31, evaluations: []const []M31) bool {
    const state: *Session = @ptrCast(@alignCast(raw));
    load(state, key, request, coefficients, evaluations) catch {
        cache.recordMiss();
        return false;
    };
    cache.recordHit((payloadBytes(request) catch unreachable) + header_bytes + 32);
    return true;
}

fn store(state: *Session, key: [32]u8, request: Request, coefficients: []const []M31, evaluations: []const []M31) !void {
    var stage = try prover.stage_profile.StageScope.begin(state.recorder, "preprocessed_columns_cache_store", "Prepared public column cache store");
    defer stage.end();
    const views = try viewsFor(state.allocator, request, coefficients, evaluations);
    defer state.allocator.free(views);
    for (views) |view| if (!canonical(view)) return error.PreparedCacheUnusable;
    const artifact_header = try header(key, request);
    const digest = try integrity.integrityDigest(state.allocator, &artifact_header, views);
    try std.fs.cwd().makePath(cache.currentConfig().directory);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try pathFor(&path_buffer, key);
    var salt: [16]u8 = undefined;
    std.crypto.random.bytes(&salt);
    var temporary_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const temporary = try std.fmt.bufPrint(&temporary_buffer, "{s}.{s}.tmp", .{ path, std.fmt.bytesToHex(salt, .lower) });
    const file = try std.fs.createFileAbsolute(temporary, .{ .exclusive = true, .mode = 0o600 });
    defer file.close();
    errdefer std.fs.deleteFileAbsolute(temporary) catch {};
    try file.writeAll(&artifact_header);
    for (views) |view| try file.writeAll(view);
    try file.writeAll(&digest);
    try file.sync();
    try std.fs.renameAbsolute(temporary, path);
}

fn storeThunk(raw: *anyopaque, key: [32]u8, request: Request, coefficients: []const []M31, evaluations: []const []M31) void {
    const state: *Session = @ptrCast(@alignCast(raw));
    store(state, key, request, coefficients, evaluations) catch return;
    cache.recordStore((payloadBytes(request) catch unreachable) + header_bytes + 32);
    cache.enforceBudget(state.allocator);
}

// Test-only visibility keeps artifact readers private in production.
pub const testing = if (builtin.is_test) struct {
    const implementation = @import("prepared_columns_cache.zig");
    pub const Session = implementation.Session;
    pub const payloadBytes = implementation.payloadBytes;
    pub const keyFor = implementation.keyFor;
    pub const load = implementation.load;
    pub const store = implementation.store;
    pub const viewsFor = implementation.viewsFor;
    pub const header = implementation.header;
    pub const pathFor = implementation.pathFor;
    pub const header_bytes = implementation.header_bytes;
    pub const maximum_payload = implementation.maximum_payload;
} else void;

//! V2 shared-provider transport. Files/pins never grant proof authority. The
//! loader retains the exact independent roster and consumes original proofs.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Artifact = @import("block_v5_readonly_provider_artifact_v2.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Wire = @import("guest_precompile/proof_artifact_wire.zig");
const Provider = @import("block_v5_readonly_input_provider_proof_v2.zig");
const Range = @import("block_v5_range16_proof_v1.zig");
const Table = @import("block_v5_readonly_input_provider_v2.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const Expected = Artifact.Expected;
pub const Kind = enum { provider, range, ordinals };
pub const ArtifactPin = struct { kind: Kind, index: u32, group_id: u32, scope_digest: [32]u8, byte_len: u64, sha256: [32]u8 };
pub const FileSet = struct { provider: ArtifactPin, range: ArtifactPin, ordinals: ArtifactPin };
pub const ORDINAL_MAGIC = "B5PV2O01";
pub const ORDINAL_HEADER = ORDINAL_MAGIC.len + 32 + 4 + 4 + 4;
pub const Limits = struct {
    artifact: Artifact.Limits = .{},
    max_ordinal_bytes: usize = 256 << 10,
    max_metadata_bytes: usize = 1 << 20,
    pub fn require(self: Limits, expected: Expected) !usize {
        try expected.validate();
        try self.artifact.validate();
        const words = try std.math.mul(usize, expected.provider.shape.fragment_count, @sizeOf(u32));
        const bytes = try std.math.add(usize, ORDINAL_HEADER, words);
        // The encoded ordinal buffer and decoded vector may coexist only here.
        const resident = try std.math.add(usize, try std.math.add(usize, bytes, words), @sizeOf(Loaded));
        if (bytes > self.max_ordinal_bytes or resident > self.max_metadata_bytes) return error.ReadonlyProviderMetadataLimit;
        return bytes;
    }
};
pub fn fileName(buffer: []u8, kind: Kind, index: u32) ![]const u8 {
    return std.fmt.bufPrint(buffer, "readonly-provider-{d}.{s}", .{ index, switch (kind) {
        .provider => "proof",
        .range => "range",
        .ordinals => "ordinals",
    } });
}
fn indexFor(expected: Expected, kind: Kind) u32 {
    return if (kind == .range) expected.range.index else expected.provider.shape.index;
}
pub fn requirePin(pin: ArtifactPin, expected: Expected, kind: Kind, limits: Limits) !void {
    const ordinal_bytes = try limits.require(expected);
    const cap = if (kind == .ordinals) limits.max_ordinal_bytes else limits.artifact.max_artifact_bytes;
    if (pin.kind != kind or pin.index != indexFor(expected, kind) or pin.group_id != expected.provider.shape.group_id or
        !std.meta.eql(pin.scope_digest, try expected.scopeDigest()) or pin.byte_len == 0 or pin.byte_len > cap or
        (kind == .ordinals and pin.byte_len != ordinal_bytes) or std.mem.allEqual(u8, &pin.sha256, 0)) return error.UntrustedReadonlyProviderFilePin;
}
fn requireOrdinals(expected: Expected, ordinals: []const u32, interval_count: usize) !void {
    if (ordinals.len != expected.provider.shape.fragment_count) return error.InvalidReadonlyProviderFragments;
    for (ordinals, 0..) |ordinal, i| if (ordinal >= interval_count or (i != 0 and ordinal < ordinals[i - 1])) return error.InvalidReadonlyProviderFragments;
    if (!std.meta.eql(try Table.ordinalDigest(expected.provider.shape, expected.provider.plan_digest, ordinals), expected.provider.ordinal_digest)) return error.UntrustedReadonlyProviderOrdinals;
}
fn writeOrdinalHeader(writer: *std.Io.Writer, expected: Expected) !void {
    const scope = try expected.scopeDigest();
    try writer.writeAll(ORDINAL_MAGIC);
    try writer.writeAll(&scope);
    try Wire.writeInt(writer, u32, expected.provider.shape.index);
    try Wire.writeInt(writer, u32, expected.provider.shape.group_id);
    try Wire.writeInt(writer, u32, expected.provider.shape.fragment_count);
}
pub fn writeOrdinals(writer: *std.Io.Writer, expected: Expected, ordinals: []const u32, interval_count: usize, limits: Limits) !void {
    _ = try limits.require(expected);
    try requireOrdinals(expected, ordinals, interval_count);
    try writeOrdinalHeader(writer, expected);
    for (ordinals) |ordinal| try Wire.writeInt(writer, u32, ordinal);
}
pub fn decodeOrdinals(a: std.mem.Allocator, raw: []const u8, expected: Expected, interval_count: usize, limits: Limits) ![]u32 {
    const required = try limits.require(expected);
    if (raw.len != required) return error.ReadonlyProviderOrdinalLength;
    const scope = try expected.scopeDigest();
    var cursor = Wire.Cursor.init(raw);
    if (!std.mem.eql(u8, try cursor.take(ORDINAL_MAGIC.len), ORDINAL_MAGIC) or !std.mem.eql(u8, try cursor.take(32), &scope) or
        try cursor.readInt(u32) != expected.provider.shape.index or try cursor.readInt(u32) != expected.provider.shape.group_id or
        try cursor.readInt(u32) != expected.provider.shape.fragment_count) return error.UntrustedReadonlyProviderOrdinalScope;
    // Bounds/order preflight before any vector allocation. Original digest is
    // rederived from the vector after allocation, never trusted from this file.
    const words = cursor;
    var prior: u32 = 0;
    for (0..expected.provider.shape.fragment_count) |i| {
        const ordinal = try cursor.readInt(u32);
        if (ordinal >= interval_count or (i != 0 and ordinal < prior)) return error.InvalidReadonlyProviderFragments;
        prior = ordinal;
    }
    try cursor.requireDone();
    const result = try a.alloc(u32, expected.provider.shape.fragment_count);
    errdefer a.free(result);
    cursor = words;
    for (result) |*ordinal| ordinal.* = try cursor.readInt(u32);
    try requireOrdinals(expected, result, interval_count);
    return result;
}
pub const Loaded = struct {
    a: std.mem.Allocator,
    allocation_owner: ?*Budget = null,
    expected: Expected,
    authority: *const Roster.Authority,
    sealed: Seal.Sealed,
    provider: Provider.Proof,
    range: Range.Proof,
    ordinals: []u32,
    proofs_live: bool = true,
    pub fn deinit(self: *Loaded) void {
        if (self.proofs_live) {
            self.provider.deinit(self.a);
            self.range.deinit(self.a);
        }
        self.a.free(self.ordinals);
        const owner = self.allocation_owner;
        self.* = undefined;
        if (owner) |budget| budget.destroy();
    }
    pub fn verifyPair(self: *Loaded, comptime Backend: type, pins: Seal.Pins, entries: []const Seal.Entry, limits: Table.Limits) !Provider.OpenSource {
        if (!self.proofs_live) return error.ReadonlyProviderProofsConsumed;
        try self.expected.requireAuthority(self.authority, self.sealed);
        // The original paired verifier consumes BOTH proofs on every path.
        self.proofs_live = false;
        return Provider.ForBackend(Backend).verifyPairOwned(self.a, self.provider, self.range, self.expected.provider, self.ordinals, self.authority, self.sealed, pins, entries, limits);
    }
};
fn read(a: std.mem.Allocator, dir: std.fs.Dir, pin: ArtifactPin, expected: Expected, kind: Kind, limits: Limits) ![]u8 {
    try requirePin(pin, expected, kind, limits);
    var buffer: [96]u8 = undefined;
    return Files.readPinned(a, dir, try fileName(&buffer, kind, pin.index), pin.byte_len, pin.sha256, if (kind == .ordinals) limits.max_ordinal_bytes else limits.artifact.max_artifact_bytes);
}
pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, expected: Expected, authority: *const Roster.Authority, sealed: Seal.Sealed, files: FileSet, limits: Limits) !Loaded {
    try expected.requireAuthority(authority, sealed);
    inline for (.{ "provider", "range", "ordinals" }) |field| try requirePin(@field(files, field), expected, @field(Kind, field), limits);
    const allocation_owner = if (Budget.fromAllocator(a)) |budget| budget.retain() else null;
    errdefer if (allocation_owner) |budget| budget.destroy();
    const ordinals = blk: {
        const raw = try read(a, dir, files.ordinals, expected, .ordinals, limits);
        defer a.free(raw);
        break :blk try decodeOrdinals(a, raw, expected, authority.intervals().len, limits);
    };
    errdefer a.free(ordinals);
    var provider = blk: {
        const raw = try read(a, dir, files.provider, expected, .provider, limits);
        defer a.free(raw);
        break :blk try Artifact.decode(a, raw, expected, limits.artifact);
    };
    errdefer provider.deinit(a);
    var range = blk: {
        const raw = try read(a, dir, files.range, expected, .range, limits);
        defer a.free(raw);
        break :blk try Artifact.decodeRange(a, raw, expected, limits.artifact);
    };
    errdefer range.deinit(a);
    try expected.requireAuthority(authority, sealed);
    return .{ .a = a, .allocation_owner = allocation_owner, .expected = expected, .authority = authority, .sealed = sealed, .provider = provider, .range = range, .ordinals = ordinals };
}
/// Owns only this publication's exclusive inodes and an independently opened
/// directory. A failed delete retains custody for a later retry; an unrelated
/// existing inode is never removed, including equal-content artifacts.
pub const CleanupOwner = struct {
    dir: std.fs.Dir,
    records: [3]Record = @splat(.{}),
    pub const Record = struct { inode: ?std.fs.File.INode = null, retained_file: ?std.fs.File = null, unretained_ctime: ?i128 = null, kind: Kind = .provider, index: u32 = 0, published: bool = false, pin: ?ArtifactPin = null };
    pub fn init(dir: std.fs.Dir) !CleanupOwner {
        return .{ .dir = try dir.openDir(".", .{}) };
    }
    fn remove(self: *CleanupOwner, path: []const u8, record: Record, require_owned: bool) !void {
        const native = std.posix.fstatat(self.dir.fd, path, std.posix.AT.SYMLINK_NOFOLLOW) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        const stat = std.fs.File.Stat.fromPosix(native);
        if (stat.kind != .file or stat.inode != record.inode.? or
            (record.retained_file == null and stat.ctime != record.unretained_ctime.?))
        {
            if (require_owned) return error.ReplacedReadonlyProviderPublication;
            return;
        }
        try self.dir.deleteFile(path);
    }
    pub fn retry(self: *CleanupOwner) !void {
        // Retain every nonterminal record even if an earlier removal fails.
        var failure: ?anyerror = null;
        for (&self.records) |*record| {
            if (record.retained_file == null and record.inode == null) continue;
            if (record.inode == null) record.inode = (record.retained_file.?.stat() catch |err| {
                failure = failure orelse err;
                continue;
            }).inode;
            var buffer: [96]u8 = undefined;
            const path = try fileName(&buffer, record.kind, record.index);
            var temporary_buffer: [104]u8 = undefined;
            const temporary = try std.fmt.bufPrint(&temporary_buffer, "{s}.part", .{path});
            self.remove(path, record.*, record.published) catch |err| {
                failure = failure orelse err;
                continue;
            };
            self.remove(temporary, record.*, false) catch |err| {
                failure = failure orelse err;
                continue;
            };
            if (record.retained_file) |file| file.close();
            record.* = .{};
        }
        if (failure) |err| return err;
        self.dir.close();
        self.* = undefined;
    }
};
pub const Publication = union(enum) {
    published: FileSet,
    failed: struct { cause: anyerror, cleanup: ?CleanupOwner },
    released: void,
    /// Published files persist. Failed publication cleanup can itself fail and
    /// leaves this outcome retryable; callers must retain it until terminal.
    pub fn deinit(self: *Publication) !void {
        switch (self.*) {
            .failed => |*failure| if (failure.cleanup) |*cleanup| try cleanup.retry(),
            .published, .released => {},
        }
        self.* = .{ .released = {} };
    }
};
const BytesEmitter = struct {
    raw: []const u8,
    record: *CleanupOwner.Record,
    pub fn write(self: @This(), file: std.fs.File) !void {
        const stat = try file.stat();
        self.record.inode = stat.inode;
        self.record.unretained_ctime = stat.ctime;
        self.record.retained_file = .{ .handle = try std.posix.dup(file.handle) };
        try file.writeAll(self.raw);
    }
};
const OrdinalEmitter = struct {
    expected: Expected,
    ordinals: []const u32,
    interval_count: usize,
    limits: Limits,
    record: *CleanupOwner.Record,
    hash: *[32]u8,
    pub fn write(self: @This(), file: std.fs.File) !void {
        const stat = try file.stat();
        self.record.inode = stat.inode;
        self.record.unretained_ctime = stat.ctime;
        self.record.retained_file = .{ .handle = try std.posix.dup(file.handle) };
        var header: [ORDINAL_HEADER]u8 = undefined;
        var fixed = std.Io.Writer.fixed(&header);
        _ = try self.limits.require(self.expected);
        try requireOrdinals(self.expected, self.ordinals, self.interval_count);
        try writeOrdinalHeader(&fixed, self.expected);
        try file.writeAll(&header);
        var state = std.crypto.hash.sha2.Sha256.init(.{});
        state.update(&header);
        var buffer: [64 * 4]u8 = undefined;
        var offset: usize = 0;
        while (offset < self.ordinals.len) {
            const count = @min(64, self.ordinals.len - offset);
            for (self.ordinals[offset..][0..count], 0..) |ordinal, i| std.mem.writeInt(u32, buffer[i * 4 ..][0..4], ordinal, .little);
            const raw = buffer[0 .. count * 4];
            state.update(raw);
            try file.writeAll(raw);
            offset += count;
        }
        self.hash.* = state.finalResult();
    }
};
fn publishBytes(cleanup: *CleanupOwner, slot: usize, expected: Expected, kind: Kind, raw: []const u8) !ArtifactPin {
    const record = &cleanup.records[slot];
    record.* = .{ .kind = kind, .index = indexFor(expected, kind) };
    var buffer: [96]u8 = undefined;
    const pin = ArtifactPin{ .kind = kind, .index = record.index, .group_id = expected.provider.shape.group_id, .scope_digest = try expected.scopeDigest(), .byte_len = raw.len, .sha256 = Files.hash(raw) };
    try Files.publishStream(cleanup.dir, try fileName(&buffer, kind, record.index), BytesEmitter{ .raw = raw, .record = record });
    record.published = true;
    record.pin = pin;
    return pin;
}
fn publishAll(a: std.mem.Allocator, cleanup: *CleanupOwner, expected: Expected, authority: *const Roster.Authority, sealed: Seal.Sealed, provider: *const Provider.Proof, range: *const Range.Proof, ordinals: []const u32, limits: Limits) !FileSet {
    try expected.requireAuthority(authority, sealed);
    const ordinal_bytes = try limits.require(expected);
    try requireOrdinals(expected, ordinals, authority.intervals().len);
    const provider_pin = blk: {
        const raw = try Artifact.encode(a, provider, expected, limits.artifact);
        defer a.free(raw);
        break :blk try publishBytes(cleanup, 0, expected, .provider, raw);
    };
    const range_pin = blk: {
        const raw = try Artifact.encodeRange(a, range, expected, limits.artifact);
        defer a.free(raw);
        break :blk try publishBytes(cleanup, 1, expected, .range, raw);
    };
    var hash: [32]u8 = undefined;
    const record = &cleanup.records[2];
    record.* = .{ .kind = .ordinals, .index = expected.provider.shape.index };
    var buffer: [96]u8 = undefined;
    const scope = try expected.scopeDigest();
    try Files.publishStream(cleanup.dir, try fileName(&buffer, .ordinals, record.index), OrdinalEmitter{ .expected = expected, .ordinals = ordinals, .interval_count = authority.intervals().len, .limits = limits, .record = record, .hash = &hash });
    const ordinal_pin = ArtifactPin{ .kind = .ordinals, .index = record.index, .group_id = expected.provider.shape.group_id, .scope_digest = scope, .byte_len = ordinal_bytes, .sha256 = hash };
    record.published = true;
    record.pin = ordinal_pin;
    try expected.requireAuthority(authority, sealed);
    return .{ .provider = provider_pin, .range = range_pin, .ordinals = ordinal_pin };
}
/// Success consumes both producer proofs; failure leaves both with their
/// producer and transfers any failed-delete custody into the typed outcome.
pub fn publishPair(a: std.mem.Allocator, dir: std.fs.Dir, expected: Expected, authority: *const Roster.Authority, sealed: Seal.Sealed, provider: *Provider.Proof, range: *Range.Proof, ordinals: []const u32, limits: Limits) Publication {
    var cleanup = CleanupOwner.init(dir) catch |err| return .{ .failed = .{ .cause = err, .cleanup = null } };
    const files = publishAll(a, &cleanup, expected, authority, sealed, provider, range, ordinals, limits) catch |err| {
        cleanup.retry() catch return .{ .failed = .{ .cause = err, .cleanup = cleanup } };
        return .{ .failed = .{ .cause = err, .cleanup = null } };
    };
    for (&cleanup.records) |*record| if (record.retained_file) |file| file.close();
    cleanup.dir.close();
    provider.deinit(a);
    range.deinit(a);
    return .{ .published = files };
}

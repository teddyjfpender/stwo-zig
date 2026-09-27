//! Versioned transport roster for staged block-v4 CPU proof files.
//! Hashes and claims here are never admission authority: the receiver still
//! requires an out-of-band trusted manifest and fresh STARK/recursive checks.
const std = @import("std");
const batch = @import("block_memory_batch_verify_v2.zig");
const first = @import("block_v4_cpu_streaming_first_round.zig");
const roster = @import("block_memory_source_roster_v2.zig");
const fallback = @import("block_memory_public_rw_fallback_v2.zig");
const capture = @import("block_v4_cpu_staged_capture.zig");
const execution = @import("block_v4_cpu_staged_execution.zig");
const parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const Q = @import("stwo_core").fields.qm31.QM31;

pub const VERSION: u32 = 1;
pub const FILE = "block-v4-bundle-v1.json";
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
pub const Digest = [32]u8;
pub const FilePin = struct { len: u64, sha256: Digest };
pub const TablePin = struct { file: FilePin, claim: Q };
pub const LeafPin = struct { file: FilePin, admission: parent.Admission, descriptor: linked.Descriptor };
pub const ParentPin = struct { file: FilePin, statement: span.SpanStatement, admission: parent.Admission, left: span.SlotSpan, right: span.SlotSpan };
pub const RootPin = struct { statement: span.SpanStatement, admission: parent.Admission, parent_file: bool, file_index: u32 };
pub const OuterPin = struct { file: FilePin, statement: span.RootStatement, admission: parent.Admission, forest_digest: Digest };
pub const Locator = union(enum) {
    public_image,
    public_touches,
    memory: u32,
    memory_table: u32,
    execution_native: u32,
    execution_opcode: u32,
    execution_extension: u32,
    opcode_table: u32,
    external_table: u32,
    leaf: u32,
    parent: span.SlotSpan,
    outer,
};

pub const Wire = struct {
    version: u32,
    candidate_manifest_sha256: Digest,
    final_manifest_sha256: Digest,
    statement: batch.PinnedStatement,
    first_entries: []const first.Entry,
    event_count: u64,
    opcode_events: u64,
    external_events: u64,
    public_pin: fallback.Pin,
    public_registers: [32]u32,
    public_entries: []const roster.Entry,
    public_image: FilePin,
    public_touches: FilePin,
    memories: []const capture.MemoryMeta,
    memory_tables: []const capture.TableMeta,
    executions: []const execution.Entry,
    opcode_tables: []const TablePin,
    external_tables: []const TablePin,
    leaves: []const LeafPin,
    parents: []const ParentPin,
    roots: []const RootPin,
    outer: OuterPin,

    pub fn validate(self: Wire, a: std.mem.Allocator) !void {
        if (self.version != VERSION) return error.UnsupportedBlockV4BundleVersion;
        try self.statement.requireExecutionSidecars(a);
        var memory_plan = try self.statement.validate(a);
        defer memory_plan.deinit(a);
        const count = @as(usize, self.statement.seal.execution_instance_count);
        if (count == 0 or count > 1024 or self.first_entries.len != count or
            self.executions.len != count or self.leaves.len != count or
            self.memories.len != self.statement.memory_instances.len or
            self.memory_tables.len != self.statement.range_table_roots.len or
            self.opcode_tables.len != self.statement.execution_range_table_roots.len or
            self.external_tables.len != self.statement.execution_extension_range_table_roots.len or
            self.parents.len != count - @as(usize, @popCount(self.statement.seal.execution_instance_count)) or
            self.roots.len != @as(usize, @popCount(self.statement.seal.execution_instance_count)) or
            self.event_count != self.statement.expected_events or
            !std.meta.eql(self.outer.forest_digest, (self.statement.complete_pins orelse return error.MissingCompleteBlockPublicPins).forest_roster_digest))
            return error.InvalidBlockV4BundleCensus;
        if (self.public_entries.len != count + 2 or
            !std.meta.eql(try roster.digest(self.public_entries), self.statement.seal.roster_digest))
            return error.InvalidBlockV4BundleSourceRoster;
        try self.public_pin.validate();
        if (self.public_image.len != try std.math.mul(u64, self.public_pin.image_count, fallback.IMAGE_RECORD_BYTES) or
            self.public_touches.len != try std.math.mul(u64, self.public_pin.first_touch_count, fallback.TOUCH_RECORD_BYTES))
            return error.InvalidBlockV4BundlePublicFiles;
        var opcode_total: u64 = 0;
        var external_total: u64 = 0;
        for (self.first_entries, self.statement.execution_roots, self.statement.execution_sidecar_roots, 0..) |entry, native, sidecar, index| {
            if (!std.meta.eql(entry.native_roots, native) or
                !std.meta.eql(entry.opcode_witness_root, sidecar[0]) or
                entry.opcode_events != self.statement.execution_active_counts[index] or
                entry.external_events != (if (self.statement.execution_extension_active_counts.len == 0) @as(u64, 0) else self.statement.execution_extension_active_counts[index]))
                return error.ChangedBlockV4BundleFirstRound;
            opcode_total = try std.math.add(u64, opcode_total, entry.opcode_events);
            external_total = try std.math.add(u64, external_total, entry.external_events);
        }
        if (opcode_total != self.opcode_events or external_total != self.external_events or
            self.event_count != try std.math.add(u64, opcode_total, external_total))
            return error.InvalidBlockV4BundleEventCensus;
        try filePin(self.public_image, true);
        try filePin(self.public_touches, true);
        for (self.memories) |item| try filePin(.{ .len = item.file.len, .sha256 = item.file.sha256 }, false);
        for (self.memory_tables) |item| try filePin(.{ .len = item.file.len, .sha256 = item.file.sha256 }, false);
        for (self.executions, self.statement.execution_active_counts, 0..) |item, active, index| {
            const external = if (self.statement.execution_extension_active_counts.len == 0) @as(u64, 0) else self.statement.execution_extension_active_counts[index];
            try filePin(.{ .len = item.native.len, .sha256 = item.native.sha256 }, false);
            try filePin(.{ .len = item.opcode.len, .sha256 = item.opcode.sha256 }, active == 0);
            if ((item.extension != null) != (external != 0)) return error.InvalidBlockV4BundleExtensionCensus;
            if (item.extension) |pin| try filePin(.{ .len = pin.len, .sha256 = pin.sha256 }, false);
        }
        for (self.opcode_tables) |item| try filePin(item.file, false);
        for (self.external_tables) |item| try filePin(item.file, false);
        for (self.leaves) |item| try filePin(item.file, false);
        for (self.parents) |item| try filePin(item.file, false);
        try filePin(self.outer.file, false);
        for (self.roots) |root| {
            const index = @as(usize, root.file_index);
            if (root.parent_file) {
                if (index >= self.parents.len or !std.meta.eql(root.statement, self.parents[index].statement) or
                    !std.meta.eql(root.admission, self.parents[index].admission))
                    return error.InvalidBlockV4BundleForestFile;
            } else if (index >= self.leaves.len or !std.meta.eql(root.statement, self.leaves[index].descriptor.statement) or
                !std.meta.eql(root.admission, self.leaves[index].admission))
                return error.InvalidBlockV4BundleForestFile;
        }
        const descriptors = try a.alloc(linked.Descriptor, self.roots.len);
        defer a.free(descriptors);
        for (self.roots, descriptors) |root, *descriptor|
            descriptor.* = .{ .statement = root.statement, .admission = root.admission };
        const complete = self.statement.complete_pins.?;
        if (!std.meta.eql(self.outer.statement.statement.job, complete.expected_job) or
            !std.meta.eql(self.outer.admission.expected_id, complete.outer_recursive_key_id) or
            self.outer.admission.key.profile != .csp_q70_pow26)
            return error.InvalidBlockV4BundleOuterPin;
        if (!std.meta.eql(try linked.verifiedForestDigest(complete.expected_job, descriptors), self.outer.forest_digest))
            return error.InvalidBlockV4BundleForestDigest;
    }
};

pub const Owned = struct {
    parsed: std.json.Parsed(Wire),
    sha256: Digest,
    pub fn deinit(self: *Owned) void {
        self.parsed.deinit();
        self.* = undefined;
    }
    pub fn view(self: *const Owned) Wire {
        return self.parsed.value;
    }
};

/// The bundle hash is a transport-integrity pin, not a trusted block input.
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, wire: Wire) !Digest {
    try wire.validate(a);
    const bytes = try std.json.Stringify.valueAlloc(a, wire, .{});
    defer a.free(bytes);
    if (bytes.len == 0 or bytes.len > MAX_MANIFEST_BYTES) return error.BlockV4BundleManifestTooLarge;
    var file = try dir.createFile(FILE, .{ .exclusive = true });
    defer file.close();
    errdefer dir.deleteFile(FILE) catch {};
    try file.writeAll(bytes);
    try file.sync();
    return sha(bytes);
}

pub fn read(a: std.mem.Allocator, dir: std.fs.Dir, expected_sha256: Digest) !Owned {
    var parsed = try readJsonPinned(Wire, a, dir, FILE, expected_sha256, MAX_MANIFEST_BYTES);
    errdefer parsed.deinit();
    try parsed.value.validate(a);
    return .{ .parsed = parsed, .sha256 = expected_sha256 };
}

fn readJsonPinned(comptime T: type, a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, expected_sha256: Digest, limit: usize) !std.json.Parsed(T) {
    var file = try dir.openFile(name, .{});
    defer file.close();
    const size = (try file.stat()).size;
    if (size == 0 or size > limit) return error.BlockV4BundleManifestTooLarge;
    const bytes = try file.readToEndAlloc(a, limit);
    defer a.free(bytes);
    const digest = sha(bytes);
    if (!std.meta.eql(digest, expected_sha256)) return error.ChangedBlockV4BundleManifest;
    return std.json.parseFromSlice(T, a, bytes, .{ .allocate = .alloc_always, .ignore_unknown_fields = false });
}

pub fn sha(bytes: []const u8) Digest {
    var digest: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

/// Bounded transport reopen. Callers must still decode and freshly verify the
/// returned proof under independently pinned statements and keys.
pub fn openPinned(a: std.mem.Allocator, dir: std.fs.Dir, locator: Locator, pin: FilePin) ![]u8 {
    try filePin(pin, true);
    var name_buffer: [96]u8 = undefined;
    const name = try fileName(locator, &name_buffer);
    var file = try dir.openFile(name, .{});
    defer file.close();
    if ((try file.stat()).size != pin.len) return error.ChangedBlockV4BundleFile;
    const bytes = try file.readToEndAlloc(a, @intCast(pin.len));
    errdefer a.free(bytes);
    if (bytes.len != pin.len or !std.meta.eql(sha(bytes), pin.sha256))
        return error.ChangedBlockV4BundleFile;
    return bytes;
}

/// Hash a large public image without retaining it alongside proof buffers.
pub fn checkPinnedFile(dir: std.fs.Dir, locator: Locator, pin: FilePin) !void {
    try filePin(pin, true);
    var name_buffer: [96]u8 = undefined;
    var file = try dir.openFile(try fileName(locator, &name_buffer), .{});
    defer file.close();
    if ((try file.stat()).size != pin.len) return error.ChangedBlockV4BundleFile;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < pin.len) {
        const take: usize = @intCast(@min(buffer.len, pin.len - offset));
        if (try file.preadAll(buffer[0..take], offset) != take)
            return error.ChangedBlockV4BundleFile;
        hasher.update(buffer[0..take]);
        offset += take;
    }
    if (!std.meta.eql(hasher.finalResult(), pin.sha256))
        return error.ChangedBlockV4BundleFile;
}

pub fn fileName(locator: Locator, buffer: *[96]u8) ![]const u8 {
    return switch (locator) {
        .public_image => "initial-nonzero.bin",
        .public_touches => "first-touch.bin",
        .memory => |index| std.fmt.bufPrint(buffer, "block-v4-memory-{d}.stark", .{index}),
        .memory_table => |index| std.fmt.bufPrint(buffer, "block-v4-table-{d}.stark", .{index}),
        .execution_native => |index| std.fmt.bufPrint(buffer, "block-v4-exec-{d}-native.bin", .{index}),
        .execution_opcode => |index| std.fmt.bufPrint(buffer, "block-v4-exec-{d}-opcode.bin", .{index}),
        .execution_extension => |index| std.fmt.bufPrint(buffer, "block-v4-exec-{d}-extension.bin", .{index}),
        .opcode_table => |index| std.fmt.bufPrint(buffer, "block-v4-opcode-table-{d}.stark", .{index}),
        .external_table => |index| std.fmt.bufPrint(buffer, "block-v4-external-table-{d}.stark", .{index}),
        .leaf => |index| std.fmt.bufPrint(buffer, "block-v4-leaf-{d}.proof", .{index}),
        .parent => |slots| std.fmt.bufPrint(buffer, "block-v4-parent-{d}-{d}.proof", .{ slots.first, slots.height }),
        .outer => "block-v4-outer.proof",
    };
}

fn filePin(pin: FilePin, allow_empty: bool) !void {
    if (pin.len > MAX_FILE_BYTES or (!allow_empty and pin.len == 0))
        return error.InvalidBlockV4BundleFilePin;
}

test "bundle JSON and staged files round trip under independent hashes" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const Sample = struct { version: u32, pin: FilePin };
    const payload = "serialized proof bytes";
    var staged = try tmp.dir.createFile("block-v4-exec-0-native.bin", .{ .exclusive = true });
    try staged.writeAll(payload);
    staged.close();
    const sample = Sample{ .version = VERSION, .pin = .{ .len = payload.len, .sha256 = sha(payload) } };
    const json = try std.json.Stringify.valueAlloc(a, sample, .{});
    defer a.free(json);
    var manifest = try tmp.dir.createFile("sample.json", .{ .exclusive = true });
    try manifest.writeAll(json);
    manifest.close();
    var parsed = try readJsonPinned(Sample, a, tmp.dir, "sample.json", sha(json), 4096);
    defer parsed.deinit();
    try std.testing.expectEqualDeep(sample, parsed.value);
    const bytes = try openPinned(a, tmp.dir, .{ .execution_native = 0 }, parsed.value.pin);
    defer a.free(bytes);
    try std.testing.expectEqualSlices(u8, payload, bytes);
    try checkPinnedFile(tmp.dir, .{ .execution_native = 0 }, parsed.value.pin);
    staged = try tmp.dir.createFile("block-v4-exec-0-native.bin", .{ .truncate = true });
    try staged.writeAll("changed proof bytes");
    staged.close();
    try std.testing.expectError(error.ChangedBlockV4BundleFile, openPinned(a, tmp.dir, .{ .execution_native = 0 }, parsed.value.pin));
    try std.testing.expectError(error.ChangedBlockV4BundleFile, checkPinnedFile(tmp.dir, .{ .execution_native = 0 }, parsed.value.pin));
    manifest = try tmp.dir.createFile("sample.json", .{ .truncate = true });
    try manifest.writeAll("{\"version\":2}");
    manifest.close();
    try std.testing.expectError(error.ChangedBlockV4BundleManifest, readJsonPinned(Sample, a, tmp.dir, "sample.json", sha(json), 4096));
    var invalid: Wire = undefined;
    invalid.version = 0;
    try std.testing.expectError(error.UnsupportedBlockV4BundleVersion, write(a, tmp.dir, invalid));
    try std.testing.expectError(error.FileNotFound, read(a, tmp.dir, @splat(0)));
}

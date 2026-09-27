//! Versioned, detached mixed-forest transport. The JSON and its SHA-256 pin
//! locate proof files; only independent leaf verification and the receiver's
//! fresh parent checks establish a recursive forest.
const std = @import("std");
const spans = @import("../recursion/span_statement_blake3.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const plan = @import("block_v4_cpu_mixed_forest_plan.zig");
const stage = @import("block_v4_cpu_mixed_forest_stage.zig");
const receiver = @import("block_v5_mixed_forest_receiver_v1.zig");

pub const VERSION: u32 = 1;
pub const FILE = "block-v5-mixed-forest-v1.json";
pub const MAX_BYTES: usize = 8 * 1024 * 1024;
pub const Digest = [32]u8;

pub const Wire = struct {
    version: u32,
    segment_count: u32,
    parents: []const stage.ParentPin,
    roots: []const stage.RootPin,
    forest_digest: Digest,

    pub fn validate(self: Wire, a: std.mem.Allocator) !void {
        if (self.version != VERSION) return error.UnsupportedMixedForestManifest;
        var expected = try plan.plan(a, self.segment_count);
        defer expected.deinit();
        if (self.parents.len != expected.tasks.len or self.roots.len != expected.roots.len)
            return error.InvalidMixedForestManifestCensus;
        for (expected.tasks, self.parents) |task, pin| {
            if (pin.kind != task.kind or !std.meta.eql(pin.statement.slots, task.slots) or
                pin.byte_len == 0 or pin.byte_len > receiver.MAX_PARENT_BYTES)
                return error.InvalidMixedForestManifestParent;
            for (task.children[0..task.childCount()], pin.children[0..task.childCount()]) |child, actual| {
                if (!std.meta.eql(child.slots, actual)) return error.InvalidMixedForestManifestEdge;
            }
            // Unused edges have one canonical serialization, including for
            // binary parents. They cannot carry hidden data into a hash pin.
            for (pin.children[task.childCount()..]) |unused| {
                if (unused.first != 0 or unused.height != 0)
                    return error.NoncanonicalMixedForestParentTail;
            }
            try pin.admission.validate();
        }
        for (expected.roots, self.roots) |root, pin| {
            if (!std.meta.eql(pin.statement.slots, root.slots))
                return error.InvalidMixedForestManifestRoot;
        }
    }
};

pub const Owned = struct {
    parsed: std.json.Parsed(Wire),
    pub fn deinit(self: *Owned) void {
        self.parsed.deinit();
        self.* = undefined;
    }
    pub fn view(self: *const Owned) Wire {
        return self.parsed.value;
    }
};

pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, staged: *const stage.Stage, segment_count: u32) !Digest {
    const wire = Wire{ .version = VERSION, .segment_count = segment_count, .parents = staged.parents, .roots = staged.roots, .forest_digest = staged.digest };
    try wire.validate(a);
    const bytes = try std.json.Stringify.valueAlloc(a, wire, .{});
    defer a.free(bytes);
    if (bytes.len == 0 or bytes.len > MAX_BYTES) return error.MixedForestManifestTooLarge;
    var file = try dir.createFile(FILE, .{ .exclusive = true });
    errdefer dir.deleteFile(FILE) catch {};
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
    return sha(bytes);
}

pub fn read(a: std.mem.Allocator, dir: std.fs.Dir, expected_sha256: Digest) !Owned {
    var file = try dir.openFile(FILE, .{});
    defer file.close();
    const size = (try file.stat()).size;
    if (size == 0 or size > MAX_BYTES) return error.MixedForestManifestTooLarge;
    const bytes = try file.readToEndAlloc(a, MAX_BYTES);
    defer a.free(bytes);
    if (bytes.len != size or !std.meta.eql(sha(bytes), expected_sha256))
        return error.ChangedMixedForestManifest;
    var parsed = try std.json.parseFromSlice(Wire, a, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    try parsed.value.validate(a);
    return .{ .parsed = parsed };
}

/// `expected_sha256`, `expected_forest_digest`, `job` and `fresh_leaves`
/// must be independently supplied by the complete-block receiver.
pub fn verifyCanonical(
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    expected_sha256: Digest,
    expected_forest_digest: Digest,
    job: spans.JobContext,
    profile: parent.Profile,
    fresh_leaves: []const linked.Descriptor,
) ![]linked.Descriptor {
    var manifest = try read(a, dir, expected_sha256);
    defer manifest.deinit();
    const wire = manifest.view();
    if (wire.segment_count != job.segment_count or
        !std.meta.eql(wire.forest_digest, expected_forest_digest))
        return error.UntrustedMixedForestManifest;
    return receiver.verify(a, dir, job, profile, fresh_leaves, wire.parents, wire.roots, expected_forest_digest);
}

fn sha(bytes: []const u8) Digest {
    var digest: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

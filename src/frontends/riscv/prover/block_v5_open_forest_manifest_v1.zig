//! Detached OpenV2 transport with independent recursive policy. Received keys,
//! schedules and public endpoints are proposals only: the caller supplies all
//! authority from the complete receiver's immutable scheduler/native policy.
const std = @import("std");
const core = @import("stwo_core");
const stage = @import("block_v5_open_forest_stage_v1.zig");
const dag_mod = @import("block_v5_open_exact_forest_plan_v1.zig");
const exact = @import("../recursion/block_v5_open_exact_forest_receiver_v1.zig");
const bus = @import("../recursion/block_v5_open_parent_public_bus_v2.zig");
const parent = @import("../recursion/blake3_execution_parent_protocol.zig");
pub const VERSION: u32 = 1;
pub const FILE = "block-v5-open-forest-v1.json";
pub const Limits = struct { max_execution_count: u32, max_manifest_bytes: usize, max_proof_bytes: usize };
pub const Wire = struct {
    version: u32,
    profile: parent.Profile,
    execution_count: u32,
    leaf_files: []const exact.FilePin,
    parents: []const stage.ParentPin,
    outer: stage.OuterPin,
    public_pins: exact.OuterPins,
    combined_native_open_sum: core.fields.qm31.QM31,
    pub fn validate(self: Wire, a: std.mem.Allocator, limits: Limits) !void {
        if (self.version != VERSION) return error.UnsupportedV5OpenForestManifest;
        if (self.execution_count != self.public_pins.segment_count or self.leaf_files.len != self.execution_count) return error.InvalidV5OpenManifestCensus;
        var dag = try dag_mod.plan(a, self.execution_count, limits.max_execution_count);
        defer dag.deinit();
        if (self.parents.len != dag.tasks.len) return error.InvalidV5OpenManifestCensus;
        for (self.leaf_files) |file| try validateFile(file, limits.max_proof_bytes);
        for (dag.tasks, self.parents) |task, pin| {
            if (pin.kind != task.kind or !std.meta.eql(pin.slots, task.slots)) return error.InvalidV5OpenManifestTopology;
            for (task.children[0..task.childCount()], pin.child_slots[0..task.childCount()]) |edge, slots| {
                if (!std.meta.eql(edge.slots, slots)) return error.InvalidV5OpenManifestTopology;
            }
            for (pin.child_slots[task.childCount()..]) |unused| {
                if (unused.first != 0 or unused.height != 0) return error.NoncanonicalV5OpenManifestTail;
            }
            try validateNode(pin.node, self.profile);
            try validateFile(pin.file, limits.max_proof_bytes);
        }
        try validateNode(self.outer.node, self.profile);
        try validateFile(self.outer.file, limits.max_proof_bytes);
        for (self.combined_native_open_sum.toM31Array()) |part| if (part.v >= core.fields.m31.Modulus) return error.InvalidV5OpenManifestClaim;
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
fn validateFile(file: exact.FilePin, max_bytes: usize) !void {
    if (file.byte_len == 0 or file.byte_len > max_bytes or std.mem.allEqual(u8, &file.sha256, 0)) return error.InvalidV5OpenProofFilePin;
}
fn validateNode(node: exact.NodePin, profile: parent.Profile) !void {
    if (node.key.profile != profile or !std.meta.eql(node.key.config, profile.config()) or
        !std.meta.eql(node.key.context.child_config, profile.config()) or
        !std.meta.eql(try node.key.identity(), node.expected_id) or
        !std.meta.eql(try bus.scheduleDigest(node.schedule), node.key.public_schedule_digest)) return error.UntrustedV5OpenManifestNode;
}
fn hash(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, staged: *const stage.Stage, leaves: []const stage.LeafFile, profile: parent.Profile, limits: Limits) ![32]u8 {
    return writeForStage(a, dir, staged, leaves, profile, limits);
}
/// Capacity/default stages retain the same outer transport and canonical JSON;
/// their typed leaf policies are supplied independently during reception.
pub fn writeForStage(a: std.mem.Allocator, dir: std.fs.Dir, staged: *const stage.Stage, leaves: anytype, profile: parent.Profile, limits: Limits) ![32]u8 {
    const files = try a.alloc(exact.FilePin, leaves.len);
    defer a.free(files);
    for (leaves, files) |leaf, *file| file.* = leaf.file;
    const wire = Wire{ .version = VERSION, .profile = profile, .execution_count = staged.execution_count, .leaf_files = files, .parents = staged.parents, .outer = staged.outer, .public_pins = staged.public_pins, .combined_native_open_sum = staged.combined_native_open_sum };
    return writeWire(a, dir, wire, limits);
}
/// One canonical validated serializer for producer stages and independently
/// assembled small fixtures. It provides transport, never setup authority.
pub fn writeWire(a: std.mem.Allocator, dir: std.fs.Dir, wire: Wire, limits: Limits) ![32]u8 {
    try wire.validate(a, limits);
    const bytes = try std.json.Stringify.valueAlloc(a, wire, .{});
    defer a.free(bytes);
    if (bytes.len == 0 or bytes.len > limits.max_manifest_bytes) return error.V5OpenForestManifestTooLarge;
    var file = try dir.createFile(FILE, .{ .exclusive = true });
    errdefer dir.deleteFile(FILE) catch {};
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
    return hash(bytes);
}
pub fn read(a: std.mem.Allocator, dir: std.fs.Dir, expected_sha: [32]u8, limits: Limits) !Owned {
    if (limits.max_manifest_bytes == 0 or std.mem.allEqual(u8, &expected_sha, 0)) return error.InvalidV5OpenManifestPin;
    var file = try dir.openFile(FILE, .{});
    defer file.close();
    const length = (try file.stat()).size;
    if (length == 0 or length > limits.max_manifest_bytes) return error.V5OpenForestManifestTooLarge;
    const bytes = try file.readToEndAlloc(a, @intCast(length));
    defer a.free(bytes);
    if (bytes.len != length or !std.meta.eql(hash(bytes), expected_sha)) return error.TamperedV5OpenManifest;
    var parsed = try std.json.parseFromSlice(Wire, a, bytes, .{ .allocate = .alloc_always, .ignore_unknown_fields = false });
    errdefer parsed.deinit();
    try parsed.value.validate(a, limits);
    return .{ .parsed = parsed };
}

/// Shared detached checker chooses leaf authority from a typed receiver only.
/// Received JSON cannot choose that type or independently admitted pins.
pub const ForExactReceiver = @import("block_v5_open_forest_manifest_leaf_impl_v1.zig").ForExactReceiver;
const DefaultReceive = ForExactReceiver(exact);
pub const verifyDetached = DefaultReceive.verifyDetached;
pub const verifyDetachedPinned = DefaultReceive.verifyDetachedPinned;

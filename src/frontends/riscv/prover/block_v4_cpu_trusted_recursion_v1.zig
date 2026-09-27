//! Proposed recursive proof policy, selected by an independent SHA-256 pin.
//! The producer may write this file, but its bytes have no authority until a
//! caller supplies its digest to a detached receiver.
const std = @import("std");
const pins_mod = @import("block_memory_complete_receiver_v3.zig");
const leaf_stage = @import("block_v4_cpu_incremental_leaf_stage.zig");
const forest_stage = @import("block_v4_cpu_incremental_forest_stage.zig");
const outer_stage = @import("block_v4_cpu_incremental_outer_stage.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const parent = @import("../recursion/blake3_execution_parent_protocol.zig");

pub const FILE = "block-v4-recursion-policy-v1.json";
pub const VERSION: u32 = 1;
const MAX_BYTES: usize = 16 * 1024 * 1024;

pub const Wire = struct {
    version: u32,
    job: span.JobContext,
    forest_digest: [32]u8,
    leaf: []const pins_mod.ProofPin,
    dyadic: []const pins_mod.DyadicPin,
    root_indices: []const u32,
    outer: pins_mod.ProofPin,

    pub fn pins(self: Wire) pins_mod.RecursionPins {
        return .{ .leaf = self.leaf, .dyadic = self.dyadic, .root_indices = self.root_indices, .outer = self.outer };
    }

    pub fn validate(self: Wire) !void {
        if (self.version != VERSION) return error.UnsupportedBlockV4RecursionPolicy;
        try self.job.validate();
        const count: usize = self.job.segment_count;
        const roots: usize = @popCount(self.job.segment_count);
        if (count == 0 or count > 1024 or self.leaf.len != count or
            self.dyadic.len != count - roots or self.root_indices.len != roots)
            return error.InvalidBlockV4RecursionPolicyCensus;
        for (self.leaf) |pin| try checkPin(pin);
        for (self.dyadic, 0..) |item, index| {
            try checkPin(item.proof);
            if (item.left_index >= count + index or item.right_index >= count + index or
                item.left_index == item.right_index)
                return error.InvalidBlockV4RecursionPolicyTopology;
        }
        for (self.root_indices) |index| if (index >= count + self.dyadic.len)
            return error.InvalidBlockV4RecursionPolicyTopology;
        try checkPin(self.outer);
        if (self.outer.admission.key.profile != .csp_q70_pow26)
            return error.ExpectedCanonicalBlockSecurity;
        const exact = self.outer.admission.key.context.exact_aggregation orelse
            return error.InvalidBlockV4RecursionPolicyOuter;
        if (!std.meta.eql(exact.roster_digest, self.forest_digest) or
            exact.child_count != roots)
            return error.InvalidBlockV4RecursionPolicyOuter;
    }
};

pub const Owned = struct {
    parsed: std.json.Parsed(Wire),
    sha256: [32]u8,
    pub fn deinit(self: *Owned) void {
        self.parsed.deinit();
        self.* = undefined;
    }
    pub fn view(self: *const Owned) Wire {
        return self.parsed.value;
    }
};

/// This is only a proposal. The emitted digest must be conveyed out of band
/// to the independent verifier before it may select the policy file.
pub fn writeProposed(a: std.mem.Allocator, dir: std.fs.Dir, job: span.JobContext, leaves: *const leaf_stage.Capture, forest: *const forest_stage.Stage, outer: *const outer_stage.Stage) ![32]u8 {
    const count: usize = job.segment_count;
    if (leaves.next != count or leaves.entries.len != count or
        forest.parents.len != count - @as(usize, @popCount(job.segment_count)) or
        forest.roots.len != @popCount(job.segment_count) or
        !std.meta.eql(forest.digest, outer.forest_digest))
        return error.IncompleteBlockV4RecursionPolicy;
    const leaf = try a.alloc(pins_mod.ProofPin, count);
    defer a.free(leaf);
    for (leaves.entries, leaf) |entry, *pin|
        pin.* = .{ .admission = entry.admission, .expected_key_id = entry.admission.expected_id };
    const dyadic = try a.alloc(pins_mod.DyadicPin, forest.parents.len);
    defer a.free(dyadic);
    for (forest.parents, dyadic, 0..) |item, *pin, index| pin.* = .{
        .left_index = try locateSpan(leaves, forest.parents[0..index], item.left),
        .right_index = try locateSpan(leaves, forest.parents[0..index], item.right),
        .proof = .{ .admission = item.admission, .expected_key_id = item.admission.expected_id },
    };
    const roots = try a.alloc(u32, forest.roots.len);
    defer a.free(roots);
    for (forest.roots, roots) |item, *index| index.* = switch (item.file) {
        .leaf => |leaf_index| leaf_index,
        .parent => |parent_index| @intCast(count + parent_index),
    };
    const wire = Wire{
        .version = VERSION,
        .job = job,
        .forest_digest = forest.digest,
        .leaf = leaf,
        .dyadic = dyadic,
        .root_indices = roots,
        .outer = .{ .admission = outer.admission, .expected_key_id = outer.admission.expected_id },
    };
    try wire.validate();
    const bytes = try std.json.Stringify.valueAlloc(a, wire, .{});
    defer a.free(bytes);
    if (bytes.len == 0 or bytes.len > MAX_BYTES) return error.BlockV4RecursionPolicyTooLarge;
    var file = try dir.createFile(FILE, .{ .exclusive = true });
    defer file.close();
    errdefer dir.deleteFile(FILE) catch {};
    try file.writeAll(bytes);
    try file.sync();
    return sha(bytes);
}

pub fn read(a: std.mem.Allocator, dir: std.fs.Dir, expected_sha256: [32]u8) !Owned {
    var file = try dir.openFile(FILE, .{});
    defer file.close();
    if ((try file.stat()).size > MAX_BYTES) return error.BlockV4RecursionPolicyTooLarge;
    const bytes = try file.readToEndAlloc(a, MAX_BYTES);
    defer a.free(bytes);
    if (!std.meta.eql(sha(bytes), expected_sha256)) return error.UntrustedBlockV4RecursionPolicyHash;
    var parsed = try std.json.parseFromSlice(Wire, a, bytes, .{ .allocate = .alloc_always, .ignore_unknown_fields = false });
    errdefer parsed.deinit();
    try parsed.value.validate();
    return .{ .parsed = parsed, .sha256 = expected_sha256 };
}

fn locateSpan(leaves: *const leaf_stage.Capture, parents: []const forest_stage.ParentPin, sought: span.SlotSpan) !u32 {
    if (sought.height == 0) {
        if (sought.first >= leaves.next or
            !std.meta.eql(leaves.entries[@intCast(sought.first)].descriptor.statement.slots, sought))
            return error.InvalidBlockV4RecursionPolicyTopology;
        return @intCast(sought.first);
    }
    for (parents, 0..) |item, index| if (std.meta.eql(item.statement.slots, sought))
        return @intCast(leaves.next + index);
    return error.InvalidBlockV4RecursionPolicyTopology;
}

fn checkPin(pin: pins_mod.ProofPin) !void {
    try pin.admission.validate();
    if (pin.admission.key.profile != .csp_q70_pow26 or
        !std.meta.eql(pin.expected_key_id, pin.admission.expected_id))
        return error.InvalidBlockV4RecursionPolicyKey;
}

fn sha(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

test "recursion policy rejects an unpinned file before parsing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = FILE, .data = "{}" });
    try std.testing.expectError(error.UntrustedBlockV4RecursionPolicyHash, read(std.testing.allocator, tmp.dir, @splat(0)));
}

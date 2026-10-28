//! Independent, proof-free key admission for a detached parent tree. The
//! registry locates keys; each parent key authenticates its exact two children.
//! No node visits a claims file, proof, captured witness, or candidate receipt.
const std = @import("std");
const recursion = @import("stwo_riscv_frontend").recursion;
const fixed_root = @import("recursive_segment_v2_detached_parent_fixed_root.zig");
const leaf_proof = @import("recursive_segment_v2_detached_proof.zig");
const Engine = recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
const SegmentKey = recursion.detached_segment_command_v1.OwnedKeyV1;
const ParentKey = recursion.detached_parent_command_v1.OwnedKeyV1;

pub const MAX_REGISTRY_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_NODES: usize = 65535;
pub const NodeV1 = struct {
    family: enum { segment, parent },
    key_path: []const u8,
    key_sha256: [32]u8,
    children: ?[2]usize = null,
};
pub const RegistryV1 = struct {
    version: u32 = 1,
    root_index: usize,
    nodes: []const NodeV1,
};
const Admitted = union(enum) {
    segment: *SegmentKey,
    parent: *ParentKey,

    fn deinit(self: Admitted) void {
        switch (self) {
            .segment => |key| key.deinit(),
            .parent => |key| key.deinit(),
        }
    }
};

pub fn admit(allocator: std.mem.Allocator, registry_directory: []const u8, registry: *const RegistryV1, independent_root_sha256: [32]u8) !void {
    if (registry.version != 1 or registry.nodes.len == 0 or registry.nodes.len > MAX_NODES or
        registry.root_index >= registry.nodes.len)
        return error.DetachedParentKeyRegistryMismatch;
    const root = registry.nodes[registry.root_index];
    if (root.family != .parent or !std.meta.eql(root.key_sha256, independent_root_sha256))
        return error.DetachedParentKeyRegistryMismatch;
    const states = try allocator.alloc(u8, registry.nodes.len);
    defer allocator.free(states);
    @memset(states, 0);
    const admitted = try visit(allocator, registry_directory, registry, registry.root_index, states, 0);
    defer admitted.deinit();
    for (states) |state| if (state != 2) return error.DetachedParentKeyRegistryMismatch;
}

fn visit(allocator: std.mem.Allocator, registry_directory: []const u8, registry: *const RegistryV1, index: usize, states: []u8, depth: usize) anyerror!Admitted {
    if (index >= registry.nodes.len or depth > 32 or states[index] != 0)
        return error.DetachedParentKeyRegistryMismatch;
    states[index] = 1;
    const node = registry.nodes[index];
    if (node.key_path.len == 0) return error.DetachedParentKeyRegistryMismatch;
    const resolved_path = if (std.fs.path.isAbsolute(node.key_path))
        try allocator.dupe(u8, node.key_path)
    else
        try std.fs.path.join(allocator, &.{ registry_directory, node.key_path });
    defer allocator.free(resolved_path);
    if (node.family == .segment) {
        if (node.children != null) return error.DetachedParentKeyRegistryMismatch;
        const bytes = try std.fs.cwd().readFileAlloc(allocator, resolved_path, recursion.detached_segment_command_v1.MAX_KEY_BYTES);
        defer allocator.free(bytes);
        const key = try SegmentKey.admitWithNativeRoot(Engine, allocator, bytes, node.key_sha256);
        errdefer key.deinit();
        const root = try leaf_proof.rebuildFixedRootFromKey(allocator, key.key());
        if (!std.meta.eql(root, key.key().preprocessed_root)) return error.DetachedParentChildRootMismatch;
        states[index] = 2;
        return .{ .segment = key };
    }

    const children = node.children orelse return error.DetachedParentKeyRegistryMismatch;
    if (children[0] == children[1] or children[0] >= index or children[1] >= index)
        return error.DetachedParentKeyRegistryMismatch;
    const bytes = try std.fs.cwd().readFileAlloc(allocator, resolved_path, recursion.detached_parent_command_v1.MAX_KEY_BYTES);
    defer allocator.free(bytes);
    const key = try ParentKey.admit(allocator, bytes, node.key_sha256);
    errdefer key.deinit();
    for (children, key.key().child_key_sha256) |child_index, committed_pin| {
        if (!std.meta.eql(registry.nodes[child_index].key_sha256, committed_pin))
            return error.DetachedParentChildKeyPinMismatch;
    }
    const left = try visit(allocator, registry_directory, registry, children[0], states, depth + 1);
    defer left.deinit();
    const right = try visit(allocator, registry_directory, registry, children[1], states, depth + 1);
    defer right.deinit();
    const family: recursion.detached_parent_fixed_recipe_v1.ChildFamily = switch (left) {
        .segment => if (right == .segment) .segment else return error.DetachedParentChildFamilyMismatch,
        .parent => if (right == .parent) .parent else return error.DetachedParentChildFamilyMismatch,
    };
    if (key.key().profile == .recursive_q193_v1) {
        const child_profile_ok = switch (left) {
            .segment => |child| child.key().profile == .recursive_q193_v1 and right.segment.key().profile == .recursive_q193_v1,
            .parent => |child| child.key().profile == .recursive_q193_v1 and right.parent.key().profile == .recursive_q193_v1,
        };
        if (!child_profile_ok) return error.DetachedParentChildSecurityMismatch;
    }
    switch (family) {
        .segment => {
            const child_keys = .{ left.segment.key(), right.segment.key() };
            try key.key().fixed_recipe.validateAgainstChildKeys(.segment, allocator, child_keys);
            const root = try fixed_root.rootFromKeysAgainstManifest(Engine, .segment, allocator, child_keys, key.key().publication_mode, &key.key().manifest, &key.key().parameters, key.key().profile);
            if (!std.meta.eql(root, key.key().preprocessed_root)) return error.DetachedParentPreprocessedCommitmentMismatch;
        },
        .parent => {
            const child_keys = .{ left.parent.key(), right.parent.key() };
            try key.key().fixed_recipe.validateAgainstChildKeys(.parent, allocator, child_keys);
            const root = try fixed_root.rootFromKeysAgainstManifest(Engine, .parent, allocator, child_keys, key.key().publication_mode, &key.key().manifest, &key.key().parameters, key.key().profile);
            if (!std.meta.eql(root, key.key().preprocessed_root)) return error.DetachedParentPreprocessedCommitmentMismatch;
        },
    }
    states[index] = 2;
    return .{ .parent = key };
}

//! Opt-in, process-local admission memoization. NOT proof verification, a VK
//! transport, or publication authority. Baseline execution does not use it;
//! the full-block driver has an explicit, default-false experimental option.
//! Frozen inputs are owned and never exposed; profiles come only from the
//! existing independent mathematical factories. Final receiving stays fresh.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Upper = @import("block_v8_window_root_receiver_v1.zig");
const Profile = @import("block_v8_window_root_profile_v1.zig");
const Wire = @import("block_v8_window_root_wire_v1.zig");
const Mixed = @import("block_v8_endpoint_mixed_join_receiver_v1.zig");
const Full = @import("../prover/block_v8_full_boundary_policy_v1.zig");
const Capture = @import("../prover/block_v7_real_window_capture_v1.zig");
const Digest = [32]u8;
const Sha = std.crypto.hash.sha2.Sha256;
pub const production_active = false;
pub const receiving_authority = false;
pub const VERSION: u32 = 1;
pub const InputContext = struct {
    elf: []const u8,
    private_input: []const u8,
    trusted: Full.Trusted,
};
pub const Limits = struct {
    max_nodes: usize = 4096,
    max_depth: usize = 16,
    max_tree_visits: usize = 16_384,
    max_snapshots: usize = 4096,
    max_snapshot_words: usize = 8_000_000,
    max_frozen_snapshot_bytes: usize = 8 << 30,
    max_metadata_bytes: usize = 128 << 20,
    max_metadata_items: usize = 16 << 20,
    /// Temporary fixed-row compilation can be large, but must be released by
    /// the existing factory before retained-profile accounting is checked.
    max_key_derivation_live_bytes: usize = 64 << 30,
    max_retained_profile_bytes: usize = 256 << 20,
};
pub const Node = struct { index: u32, context_id: Digest, descriptor_id: Digest };
pub const Stats = struct {
    unique_nodes: usize,
    independent_derivations: usize,
    temporary_fold_derivations: usize,
    hits: usize,
    profile_live_bytes: usize,
    /// High-water live bytes sampled only after factory temporaries are freed.
    retained_profile_peak_bytes: usize,
    /// Includes temporary fixed rows and commitments during key derivation.
    key_derivation_peak_bytes: usize,
    frozen_snapshot_bytes: usize,
    frozen_snapshot_count: usize,
    frozen_metadata_wire_bytes: usize,
    /// ELF/input and the independently derived initial snapshot are additional
    /// owned context, separate from the small retained profiles.
    frozen_elf_bytes: usize,
    frozen_input_bytes: usize,
    frozen_initial_snapshot_bytes: usize,
};

pub const Frozen = opaque {
    /// The caller must not mutate inputs concurrently with this call. After
    /// return, all caller buffers may be mutated/freed: the context owns copies.
    /// A forest permits freezing all leaf statements before parent proofs exist.
    pub fn clone(a: std.mem.Allocator, input: InputContext, forest: []const Upper.Tree, limits: Limits) !*Frozen {
        return @ptrCast(try FrozenImpl.create(a, input, forest, limits));
    }
    pub fn deinit(self: *Frozen) void {
        frozen(self).release();
    }
    pub fn identity(self: *const Frozen) Digest {
        return frozenConst(self).identity;
    }
    pub fn nodeCount(self: *const Frozen) usize {
        return frozenConst(self).descriptors.items.len;
    }
};

pub const Cache = opaque {
    /// No callback, supplied key, serialized profile or successful receipt is
    /// accepted. Each unique descriptor is derived bottom-up exactly once.
    pub fn create(a: std.mem.Allocator, inputs: *const Frozen) !*Cache {
        return @ptrCast(try CacheImpl.create(a, frozenConst(inputs)));
    }
    pub fn deinit(self: *Cache) void {
        cache(self).destroy();
    }
    pub fn root(self: *const Cache, forest_index: usize) !Node {
        const impl = cacheConst(self);
        if (forest_index >= impl.inputs.roots.items.len) return error.InvalidAdmissionCacheNode;
        return impl.handle(impl.inputs.roots.items[forest_index]);
    }
    pub fn node(self: *const Cache, index: usize) !Node {
        const impl = cacheConst(self);
        if (index >= impl.entries.items.len) return error.InvalidAdmissionCacheNode;
        return impl.handle(@intCast(index));
    }
    /// Borrowed const data, not a verification receipt. Do not mutate any
    /// reachable slice/pointer. Every checkout rechecks the immutable seal.
    pub fn profile(self: *const Cache, handle: Node) !*const Profile.Owned {
        return try cacheConst(self).checked(handle);
    }
    /// Parents can be added after their actual MAIN root is known. Descendant
    /// profiles are reused, never recursively reconstructed from leaf metadata.
    /// Calls require external synchronization: checkout validates shape using
    /// the supplied allocator, whose thread-safety is not assumed.
    pub fn appendFold(self: *Cache, children: []const Node, main_root: Digest) !Node {
        return try cache(self).appendFold(children, main_root);
    }
    /// Independently compile an expected fold admission before a saved proof's
    /// own MAIN root is known. The placeholder is NOT a verified statement.
    /// Caller must fresh-verify proof bytes, destroy this temporary profile,
    /// append the authenticated MAIN root, compare admissions and requireCapture.
    /// This factory accepts only checked child handles, never a supplied VK.
    pub fn deriveUnboundFoldForVerification(self: *Cache, children: []const Node) !*Profile.Owned {
        const impl = cache(self);
        if (children.len < 2 or children.len > 4) return error.InvalidAdmissionCacheRoot;
        var profiles: [4]*const Profile.Owned = undefined;
        var depth: usize = 0;
        for (children, 0..) |child, i| {
            profiles[i] = try impl.checked(child);
            depth = @max(depth, impl.entries.items[child.index].depth + 1);
        }
        if (depth > impl.inputs.limits.max_depth) return error.AdmissionCacheResourceLimit;
        const p = try Profile.Owned.deriveFold(impl.key_budget.allocator(), profiles[0..children.len], @splat(0));
        impl.temporary_fold_derivations += 1;
        return p;
    }
    pub fn validateAll(self: *const Cache) !void {
        const impl = cacheConst(self);
        for (impl.entries.items, 0..) |_, i| _ = try impl.checked(impl.handle(@intCast(i)));
    }
    pub fn stats(self: *const Cache) Stats {
        const impl = cacheConst(self);
        const snapshot = impl.key_budget.snapshot();
        return .{ .unique_nodes = impl.entries.items.len, .independent_derivations = impl.derivations, .temporary_fold_derivations = impl.temporary_fold_derivations, .hits = impl.hits, .profile_live_bytes = snapshot.live_bytes, .retained_profile_peak_bytes = impl.retained_profile_peak_bytes, .key_derivation_peak_bytes = snapshot.peak_live_bytes, .frozen_snapshot_bytes = impl.inputs.snapshot_bytes, .frozen_snapshot_count = impl.inputs.snapshots.items.len, .frozen_metadata_wire_bytes = impl.inputs.metadata_bytes, .frozen_elf_bytes = impl.inputs.elf.len, .frozen_input_bytes = impl.inputs.private_input.len, .frozen_initial_snapshot_bytes = impl.inputs.boundary.initial_snapshot.words.len * @sizeOf(Capture.Word) };
    }
};

fn frozen(value: *Frozen) *FrozenImpl {
    return @ptrCast(@alignCast(value));
}
fn frozenConst(value: *const Frozen) *const FrozenImpl {
    return @ptrCast(@alignCast(value));
}
fn cache(value: *Cache) *CacheImpl {
    return @ptrCast(@alignCast(value));
}
fn cacheConst(value: *const Cache) *const CacheImpl {
    return @ptrCast(@alignCast(value));
}
const Branch = struct { children: [4]u32 = @splat(0), count: u8, main_root: Digest };
const Descriptor = struct {
    id: Digest,
    data: union(enum) {
        native: struct { external: Upper.External, input: Upper.Leaf, wire: []const u8 },
        mixed: struct { external: Upper.External, input: Wire.MixedLeaf, wire: []const u8 },
        branch: Branch,
    },
};
const Snapshot = struct {
    id: Digest,
    value: Capture.Snapshot,
    // Only used to avoid rehashing the SAME borrowed immutable buffer while
    // cloning adjacent leaves. Never dereferenced after freeze returns.
    original_pointer: usize,
    original_length: usize,
};
const FrozenImpl = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    backing_budget: ?*Budget,
    refs: std.atomic.Value(usize) = .init(1),
    limits: Limits,
    elf: []const u8,
    private_input: []const u8,
    boundary: Full.Owned,
    context_id: Digest,
    identity: Digest,
    snapshots: std.ArrayList(Snapshot) = .empty,
    descriptors: std.ArrayList(Descriptor) = .empty,
    roots: std.ArrayList(u32) = .empty,
    snapshot_bytes: usize = 0,
    metadata_bytes: usize = 0,
    tree_visits: usize = 0,
    fn create(a: std.mem.Allocator, input: InputContext, forest: []const Upper.Tree, limits: Limits) !*FrozenImpl {
        if (forest.len == 0 or forest.len > limits.max_nodes or limits.max_nodes == 0 or limits.max_nodes > 4096 or limits.max_depth > 16 or limits.max_tree_visits == 0 or limits.max_metadata_bytes == 0 or limits.max_snapshots == 0 or limits.max_retained_profile_bytes == 0 or limits.max_key_derivation_live_bytes == 0) return error.InvalidAdmissionCacheLimits;
        const raw_limits = Capture.Limits{};
        if (input.elf.len > raw_limits.max_elf_bytes or input.private_input.len > raw_limits.max_input_bytes) return error.AdmissionCacheResourceLimit;
        const backing_budget = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (backing_budget) |owner| owner.destroy();
        const self = try a.create(FrozenImpl);
        errdefer a.destroy(self);
        var arena = std.heap.ArenaAllocator.init(a);
        var arena_transferred = false;
        errdefer if (!arena_transferred) arena.deinit();
        const t = arena.allocator();
        const elf = try t.dupe(u8, input.elf);
        const private_input = try t.dupe(u8, input.private_input);
        var boundary = try Full.Owned.derive(a, elf, private_input, input.trusted, .{});
        var boundary_transferred = false;
        errdefer if (!boundary_transferred) boundary.deinit();
        var h = Hasher.init("B8/admission-cache/context/v1");
        try h.value(input.trusted);
        try h.value(boundary.digest);
        try h.value(boundary.program_root);
        try h.value(boundary.initial_policy);
        try h.value(boundary.terminal_policy);
        self.* = .{ .a = a, .arena = arena, .backing_budget = backing_budget, .limits = limits, .elf = elf, .private_input = private_input, .boundary = boundary, .context_id = h.finish(), .identity = undefined };
        arena_transferred = true;
        boundary_transferred = true;
        errdefer {
            self.boundary.deinit();
            self.arena.deinit();
            self.snapshots.deinit(a);
            self.descriptors.deinit(a);
            self.roots.deinit(a);
        }
        for (forest) |tree| try self.roots.append(a, try self.freezeTree(tree, input.elf, 0));
        h = Hasher.init("B8/admission-cache/frozen-forest/v1");
        try h.value(self.context_id);
        try h.value(self.roots.items.len);
        for (self.roots.items) |index| try h.value(self.descriptors.items[index].id);
        self.identity = h.finish();
        return self;
    }
    fn retain(self: *const FrozenImpl) void {
        _ = @constCast(self).refs.fetchAdd(1, .monotonic);
    }
    fn release(self: *FrozenImpl) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        const a = self.a;
        const backing_budget = self.backing_budget;
        self.boundary.deinit();
        self.arena.deinit();
        self.snapshots.deinit(a);
        self.descriptors.deinit(a);
        self.roots.deinit(a);
        a.destroy(self);
        if (backing_budget) |owner| owner.destroy();
    }
    fn internSnapshot(self: *FrozenImpl, source: Capture.Snapshot, expected: Digest) !Capture.Snapshot {
        if (source.words.len > self.limits.max_snapshot_words or source.cpu.regs[0] != 0) return error.InvalidFrozenSnapshot;
        const pointer = @intFromPtr(source.words.ptr);
        for (self.snapshots.items) |item| if (item.original_pointer == pointer and item.original_length == source.words.len and std.meta.eql(item.value.cpu, source.cpu)) {
            if (!std.meta.eql(item.id, expected)) return error.MutatedFrozenSnapshotReference;
            return item.value;
        };
        // A second buffer claiming the same identity must have the same actual
        // canonical state, not merely the same producer-supplied digest label.
        for (self.snapshots.items) |item| if (std.meta.eql(item.id, expected)) {
            if (!std.meta.eql(item.value.cpu, source.cpu) or item.value.words.len != source.words.len) return error.UntrustedFrozenSnapshot;
            for (item.value.words, source.words) |x, y| if (!std.meta.eql(x, y)) return error.UntrustedFrozenSnapshot;
            return item.value;
        };
        if (self.snapshots.items.len >= self.limits.max_snapshots) return error.AdmissionCacheResourceLimit;
        for (source.words, 0..) |word, i| if (word.address & 3 != 0 or (i != 0 and source.words[i - 1].address >= word.address)) return error.InvalidFrozenSnapshot;
        const bytes = try std.math.mul(usize, source.words.len, @sizeOf(Capture.Word));
        const total = try std.math.add(usize, self.snapshot_bytes, bytes);
        if (total > self.limits.max_frozen_snapshot_bytes) return error.AdmissionCacheResourceLimit;
        var owned = source;
        owned.words = try self.arena.allocator().dupe(Capture.Word, source.words);
        const id = owned.identity();
        if (!std.meta.eql(id, expected)) return error.UntrustedFrozenSnapshot;
        try self.snapshots.append(self.a, .{ .id = id, .value = owned, .original_pointer = pointer, .original_length = source.words.len });
        self.snapshot_bytes = total;
        return owned;
    }
    fn freezeExternal(self: *FrozenImpl, source: Upper.External, original_elf: []const u8) !Upper.External {
        if (!std.meta.eql(source.config, self.boundary.config) or !std.meta.eql(source.trusted.elf_sha256, self.boundary.elf_sha256)) return error.UntrustedFrozenExternal;
        if (source.elf.ptr != original_elf.ptr or source.elf.len != original_elf.len) {
            if (!std.mem.eql(u8, source.elf, self.elf)) return error.UntrustedFrozenExternal;
        }
        const selected = try self.boundary.windowOptions(source.trusted.window.skip_cycles, source.trusted.window.cycles);
        if (!std.meta.eql(selected, source.boundary)) return error.UntrustedFrozenBoundary;
        return .{ .elf = self.elf, .incoming = try self.internSnapshot(source.incoming, source.trusted.incoming_sha256), .outgoing = try self.internSnapshot(source.outgoing, source.trusted.outgoing_sha256), .trusted = source.trusted, .config = source.config, .boundary = selected };
    }
    fn keepWire(self: *FrozenImpl, bytes: []const u8) ![]const u8 {
        const total = try std.math.add(usize, self.metadata_bytes, bytes.len);
        if (total > self.limits.max_metadata_bytes) return error.AdmissionCacheResourceLimit;
        const owned = try self.arena.allocator().dupe(u8, bytes);
        self.metadata_bytes = total;
        return owned;
    }
    fn freezeTree(self: *FrozenImpl, tree: Upper.Tree, original_elf: []const u8, depth: usize) anyerror!u32 {
        if (depth > self.limits.max_depth or self.tree_visits >= self.limits.max_tree_visits) return error.AdmissionCacheResourceLimit;
        self.tree_visits += 1;
        var descriptor: Descriptor = undefined;
        var h = Hasher.init("B8/admission-cache/descriptor/v1");
        try h.value(self.context_id);
        switch (tree) {
            .leaf => |leaf| {
                if (std.mem.allEqual(u8, &leaf.input.main_root, 0)) return error.InvalidAdmissionCacheRoot;
                const ext = try self.freezeExternal(leaf.external, original_elf);
                const encoded = try Wire.encodeNativeLeafWithLimits(self.a, leaf.input, .{ .max_bytes = self.limits.max_metadata_bytes, .max_items = self.limits.max_metadata_items });
                defer self.a.free(encoded);
                try h.value(@as(u8, 0));
                try hashExternal(&h, ext);
                try h.value(encoded);
                const id = h.finish();
                for (self.descriptors.items, 0..) |previous, i| if (std.meta.eql(previous.id, id)) return @intCast(i);
                const bytes = try self.keepWire(encoded);
                descriptor = .{ .id = id, .data = .{ .native = .{ .external = ext, .input = try Wire.decodeNativeLeafLeaky(self.arena.allocator(), bytes, .{ .max_bytes = self.limits.max_metadata_bytes, .max_items = self.limits.max_metadata_items }), .wire = bytes } } };
            },
            .mixed_leaf => |leaf| {
                if (leaf.input.root.len != 0 or leaf.global_g_repartition != leaf.input.global_g_repartition or std.mem.allEqual(u8, &leaf.main_root, 0)) return error.InvalidAdmissionCacheRoot;
                const ext = try self.freezeExternal(leaf.external, original_elf);
                const encoded = try Wire.encodeMixedLeafWithLimits(self.a, .{ .main_root = leaf.main_root, .global_g_repartition = leaf.global_g_repartition, .input = leaf.input }, .{ .max_bytes = self.limits.max_metadata_bytes, .max_items = self.limits.max_metadata_items });
                defer self.a.free(encoded);
                try h.value(@as(u8, 1));
                try hashExternal(&h, ext);
                try h.value(encoded);
                const id = h.finish();
                for (self.descriptors.items, 0..) |previous, i| if (std.meta.eql(previous.id, id)) return @intCast(i);
                const bytes = try self.keepWire(encoded);
                descriptor = .{ .id = id, .data = .{ .mixed = .{ .external = ext, .input = try Wire.decodeMixedLeafLeaky(self.arena.allocator(), bytes, .{ .max_bytes = self.limits.max_metadata_bytes, .max_items = self.limits.max_metadata_items }), .wire = bytes } } };
            },
            .branch => |branch| {
                if (branch.children.len < 2 or branch.children.len > 4 or std.mem.allEqual(u8, &branch.main_root, 0)) return error.InvalidAdmissionCacheRoot;
                var out = Branch{ .count = @intCast(branch.children.len), .main_root = branch.main_root };
                for (branch.children, 0..) |child, i| out.children[i] = try self.freezeTree(child, original_elf, depth + 1);
                descriptor = .{ .id = try branchIdentity(self.context_id, out, self.descriptors.items), .data = .{ .branch = out } };
            },
        }
        // Memoize identical canonical subtrees within a forest too.
        for (self.descriptors.items, 0..) |previous, i| if (std.meta.eql(previous.id, descriptor.id)) return @intCast(i);
        if (self.descriptors.items.len >= self.limits.max_nodes) return error.AdmissionCacheResourceLimit;
        const index: u32 = @intCast(self.descriptors.items.len);
        try self.descriptors.append(self.a, descriptor);
        return index;
    }
};
fn hashExternal(h: *Hasher, ext: Upper.External) !void {
    // The actual frozen snapshots were checked against these exact identities.
    try h.value(ext.trusted);
    try h.value(ext.incoming.cpu);
    try h.value(ext.outgoing.cpu);
    try h.value(ext.config);
    try h.value(ext.boundary);
}
fn branchIdentity(context_id: Digest, branch: Branch, nodes: []const Descriptor) !Digest {
    var h = Hasher.init("B8/admission-cache/branch/v1");
    try h.value(context_id);
    try h.value(branch.count);
    try h.value(branch.main_root);
    for (branch.children[0..branch.count]) |index| {
        if (index >= nodes.len) return error.InvalidAdmissionCacheNode;
        try h.value(nodes[index].id);
    }
    return h.finish();
}

const Entry = struct { profile: *Profile.Owned, descriptor_id: Digest, fingerprint: Digest, depth: usize };
const CacheImpl = struct {
    a: std.mem.Allocator,
    inputs: *const FrozenImpl,
    key_budget: *Budget,
    entries: std.ArrayList(Entry) = .empty,
    derivations: usize = 0,
    temporary_fold_derivations: usize = 0,
    hits: usize = 0,
    retained_profile_peak_bytes: usize = 0,
    fn create(a: std.mem.Allocator, inputs: *const FrozenImpl) !*CacheImpl {
        const self = try a.create(CacheImpl);
        errdefer a.destroy(self);
        const key_budget = try Budget.createRetainingParent(a, inputs.limits.max_key_derivation_live_bytes);
        self.* = .{ .a = a, .inputs = inputs, .key_budget = key_budget };
        inputs.retain();
        errdefer {
            for (self.entries.items) |entry| entry.profile.deinit();
            self.entries.deinit(a);
            key_budget.destroy();
            @constCast(inputs).release();
        }
        for (inputs.descriptors.items) |descriptor| {
            var depth: usize = 0;
            if (descriptor.data == .branch) {
                const branch = descriptor.data.branch;
                for (branch.children[0..branch.count]) |index| depth = @max(depth, self.entries.items[index].depth + 1);
                if (depth > inputs.limits.max_depth) return error.AdmissionCacheResourceLimit;
            }
            const p = switch (descriptor.data) {
                .native => |leaf| try Upper.deriveLeaf(key_budget.allocator(), leaf.external, leaf.input),
                .mixed => |leaf| blk: {
                    var metadata = try Mixed.admitMetadata(key_budget.allocator(), leaf.external, leaf.input.input);
                    defer metadata.deinit();
                    break :blk try Profile.Owned.deriveJoin(key_budget.allocator(), &metadata.admissions, &metadata.extra, leaf.input.main_root, .{ .global_g_repartition = leaf.input.global_g_repartition });
                },
                .branch => |branch| blk: {
                    var children: [4]*const Profile.Owned = undefined;
                    for (branch.children[0..branch.count], 0..) |index, i| children[i] = try self.checked(self.handle(index));
                    break :blk try Profile.Owned.deriveFold(key_budget.allocator(), children[0..branch.count], branch.main_root);
                },
            };
            try self.add(p, descriptor.id, depth);
        }
        return self;
    }
    fn destroy(self: *CacheImpl) void {
        const a = self.a;
        for (self.entries.items) |entry| entry.profile.deinit();
        self.entries.deinit(a);
        const key_budget = self.key_budget;
        const inputs = self.inputs;
        // The key budget retains a backing budget allocator, so release that
        // lease only after the cache control allocation has been freed too.
        a.destroy(self);
        key_budget.destroy();
        @constCast(inputs).release();
    }
    fn add(self: *CacheImpl, p: *Profile.Owned, descriptor_id: Digest, depth: usize) !void {
        errdefer p.deinit();
        const fingerprint = try profileFingerprint(p);
        // Existing factories have returned and released wide temporary rows.
        // Fingerprint validation also releases its temporary shape before here.
        const retained_bytes = self.key_budget.snapshot().live_bytes;
        if (retained_bytes > self.inputs.limits.max_retained_profile_bytes) return error.AdmissionCacheRetainedLimit;
        try self.entries.append(self.a, .{ .profile = p, .descriptor_id = descriptor_id, .fingerprint = fingerprint, .depth = depth });
        self.derivations += 1;
        self.retained_profile_peak_bytes = @max(self.retained_profile_peak_bytes, retained_bytes);
    }
    fn handle(self: *const CacheImpl, index: u32) Node {
        return .{ .index = index, .context_id = self.inputs.identity, .descriptor_id = self.entries.items[index].descriptor_id };
    }
    fn checked(self: *const CacheImpl, handle_value: Node) !*const Profile.Owned {
        if (!std.meta.eql(handle_value.context_id, self.inputs.identity) or handle_value.index >= self.entries.items.len) return error.InvalidAdmissionCacheNode;
        const entry = self.entries.items[handle_value.index];
        if (!std.meta.eql(handle_value.descriptor_id, entry.descriptor_id) or !std.meta.eql(entry.fingerprint, try profileFingerprint(entry.profile))) return error.MutatedAdmissionCacheEntry;
        return entry.profile;
    }
    fn appendFold(self: *CacheImpl, children: []const Node, main_root: Digest) !Node {
        if (children.len < 2 or children.len > 4 or std.mem.allEqual(u8, &main_root, 0)) return error.InvalidAdmissionCacheRoot;
        var profiles: [4]*const Profile.Owned = undefined;
        var depth: usize = 0;
        var h = Hasher.init("B8/admission-cache/branch/v1");
        try h.value(self.inputs.context_id);
        try h.value(@as(u8, @intCast(children.len)));
        try h.value(main_root);
        for (children, 0..) |child, i| {
            profiles[i] = try self.checked(child);
            depth = @max(depth, self.entries.items[child.index].depth + 1);
            try h.value(child.descriptor_id);
        }
        if (depth > self.inputs.limits.max_depth) return error.AdmissionCacheResourceLimit;
        const id = h.finish();
        for (self.entries.items, 0..) |entry, i| if (std.meta.eql(entry.descriptor_id, id)) {
            const existing = self.handle(@intCast(i));
            _ = try self.checked(existing);
            self.hits += 1;
            return existing;
        };
        if (self.entries.items.len >= self.inputs.limits.max_nodes) return error.AdmissionCacheResourceLimit;
        const p = try Profile.Owned.deriveFold(self.key_budget.allocator(), profiles[0..children.len], main_root);
        const index: u32 = @intCast(self.entries.items.len);
        try self.add(p, id, depth);
        return self.handle(index);
    }
};

/// Seal ALL semantic/readable profile data, including redundant wrapper fields
/// not covered by Profile.identity(). No allocator or address enters the hash.
fn profileFingerprint(p: *const Profile.Owned) !Digest {
    try p.validate();
    try p.shape.original.validateAgainst(&p.admission);
    const shape = p.shape.original;
    if (!std.meta.eql(p.fixed_root, p.admission.key.preprocessed_root) or !std.meta.eql(p.shape.config, shape.config) or p.shape.lifting_log != shape.lifting_log or p.shape.columns.len != 4 or p.shape.widths.ptr != shape.widths.ptr or p.shape.widths.len != shape.widths.len) return error.MutatedAdmissionCacheEntry;
    for (p.shape.columns, shape.columns) |x, y| if (x.ptr != y.ptr or x.len != y.len) return error.MutatedAdmissionCacheEntry;
    var h = Hasher.init("B8/admission-cache/profile/v1");
    try h.value(p.admission.key);
    try h.value(p.admission.expected_id);
    try h.value(p.admission.public_id);
    try h.value(p.admission.seal);
    const prefix = p.admission.prefix;
    try h.value(prefix.words);
    try h.value(prefix.felts);
    try h.value(prefix.first);
    try h.value(prefix.claims);
    try h.value(prefix.sealed_offset);
    try h.value(prefix.roots_offset);
    try h.value(p.admission.claim_tag);
    try h.value(p.admission.source.terms);
    try h.value(p.admission.pc_clock_children);
    try h.value(shape.limits);
    try h.value(shape.logs);
    try h.value(shape.config);
    try h.value(shape.columns);
    try h.value(shape.trees);
    try h.value(shape.layouts);
    try h.value(shape.widths);
    try h.value(shape.mask_log);
    try h.value(shape.lifting_log);
    try h.value(shape.composition_split);
    try h.value(shape.seal);
    try h.value(p.span);
    try h.value(p.main_root);
    try h.value(p.fixed_root);
    try h.value(p.seal);
    return h.finish();
}

/// Canonical structural hash for finite scalar/slice/enum/union metadata.
/// Unlike @asBytes this excludes padding, pointer addresses and allocators.
const Hasher = struct {
    hash: Sha,
    remaining: usize = 32 << 20,
    fn init(domain: []const u8) Hasher {
        var out = Hasher{ .hash = Sha.init(.{}) };
        out.hash.update(domain);
        return out;
    }
    fn number(self: *Hasher, scalar: u64) void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, scalar, .little);
        self.hash.update(&bytes);
    }
    fn value(self: *Hasher, input: anytype) anyerror!void {
        try self.typed(@TypeOf(input), input);
    }
    fn typed(self: *Hasher, comptime T: type, input: T) anyerror!void {
        if (T == core.fields.m31.M31) {
            if (input.v >= core.fields.m31.Modulus) return error.NonCanonicalAdmissionCacheField;
            self.number(input.v);
            return;
        }
        if (T == core.fields.qm31.QM31) {
            for (input.toM31Array()) |limb| try self.typed(core.fields.m31.M31, limb);
            return;
        }
        switch (@typeInfo(T)) {
            .void => {},
            .bool => self.number(@intFromBool(input)),
            .int => |info| {
                if (info.bits > 64) @compileError("wide integer in admission cache identity");
                self.number(if (info.signedness == .signed) @bitCast(@as(i64, input)) else @intCast(input));
            },
            .@"enum" => self.number(@intFromEnum(input)),
            .optional => |info| {
                self.number(@intFromBool(input != null));
                if (input) |v| try self.typed(info.child, v);
            },
            .array => |info| {
                self.number(info.len);
                for (input) |v| try self.typed(info.child, v);
            },
            .pointer => |info| {
                if (info.size != .slice) @compileError("only metadata slices belong in admission cache identities");
                if (input.len > self.remaining) return error.AdmissionCacheResourceLimit;
                self.remaining -= input.len;
                self.number(input.len);
                if (info.child == u8) self.hash.update(input) else for (input) |v| try self.typed(info.child, v);
            },
            .@"struct" => |info| {
                self.number(info.fields.len);
                inline for (info.fields) |field| {
                    self.number(field.name.len);
                    self.hash.update(field.name);
                    try self.typed(field.type, @field(input, field.name));
                }
            },
            .@"union" => |info| {
                if (info.tag_type == null) @compileError("untagged cache metadata union");
                self.number(@intFromEnum(std.meta.activeTag(input)));
                switch (input) {
                    inline else => |v| try self.value(v),
                }
            },
            else => @compileError("unsupported admission cache metadata type " ++ @typeName(T)),
        }
    }
    fn finish(self: *Hasher) Digest {
        return self.hash.finalResult();
    }
};

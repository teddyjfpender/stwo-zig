//! Actual durable PAGE leaf/closed-forest setup construction. Expected keys
//! derive from independently admitted PAGE metadata and pinned semantic
//! proposals before native decode. Original freshness remains mandatory.
//! Interior node setup uses the independently derived VERSION16 catalogue.
//! File pins and this host owner are proposals, not recursive authority.
//! Fold descriptors are loaded only for <=4 current direct leaf children.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Catalogue = @import("block_v5_memory_source_page_leaf_catalogue_v1.zig");
const PolicyFile = @import("block_v5_memory_source_page_policy_file_v1.zig");
const ExpectedSetup = @import("block_v5_page_recursive_expected_setup_v1.zig");
const Global = @import("block_v5_capacity_global_receiver_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Leaves = @import("../recursion/block_v5_memory_source_page_forest_leaf_v1.zig");
const Plan = @import("../recursion/block_v5_memory_source_page_forest_plan_v1.zig");
const Bus = @import("../recursion/block_v5_memory_source_page_forest_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_memory_source_page_forest_protocol_v1.zig");
const Receiver = @import("../recursion/block_v5_memory_source_page_forest_summary_receiver_v1.zig");
const Source = @import("../recursion/block_v5_memory_source_page_forest_summary_source_v1.zig");
const Rows = @import("../recursion/block_v5_memory_source_page_forest_preparation_v1.zig").ForNode(Receiver, Source);
const RowTypes = @import("../recursion/block_v5_memory_source_page_forest_preparation_v1.zig");
const ForestFixed = @import("../recursion/block_v5_memory_source_page_forest_fixed_assembly_v1.zig");
const FixedKey = @import("../recursion/blake3_parent_fixed_key_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const LiveBudget = @import("block_v5_memory_source_page_forest_live_budget_v1.zig");
pub const FilePin = struct { byte_len: u64, sha256: [32]u8 };
pub const Existing = struct { leaves: []const FilePin, nodes: []const FilePin };
pub const Action = union(enum) { publish, reconstruct: Existing };
pub const Limits = struct {
    catalogue: Catalogue.Limits = .{},
    plan: Plan.Limits = .{},
    public: Bus.Limits = .{},
    rows: RowTypes.Limits = .{},
    fixed: ExpectedSetup.Limits = .{},
    node_fixed: ForestFixed.Limits = .{},
    max_metadata_bytes: usize = 1 << 30,
    max_live_bytes: usize = 8 << 30,
    max_proof_bytes: usize = 512 << 20,
    max_total_proof_bytes: u64 = 512 << 30,
    max_schedule_terms: usize = 1 << 20,
    transcript_capacity: u32 = 1 << 24,
    pub fn validate(self: Limits) !void {
        try self.catalogue.validate();
        try self.node_fixed.validate(self.transcript_capacity);
        if (self.fixed.max_bytes == 0 or self.max_metadata_bytes == 0 or self.max_live_bytes == 0 or self.max_proof_bytes == 0 or
            self.max_total_proof_bytes == 0 or self.max_schedule_terms == 0 or self.transcript_capacity == 0 or
            !std.meta.eql(self.catalogue.recursive.page, self.plan.pages)) return error.InvalidPageForestPolicyLimits;
    }
};
pub fn requireExisting(action: Action, leaves: usize, nodes: usize) !void {
    if (action == .reconstruct and (action.reconstruct.leaves.len != leaves or action.reconstruct.nodes.len != nodes)) return error.IncompletePageForestPolicyFiles;
}
pub fn leafFilename(buffer: []u8, index: u32) ![]const u8 {
    return std.fmt.bufPrint(buffer, "source-page-recursive-leaf-{d}.b5pgp", .{index});
}
pub fn nodeFilename(buffer: []u8, index: u32) ![]const u8 {
    return std.fmt.bufPrint(buffer, "source-page-recursive-node-{d}.b5pgf", .{index});
}
pub const Owner = struct {
    budget: *Budget,
    catalogue: *Catalogue.Catalogue,
    raw: []Leaves.ForKind(.raw).Policy,
    fold: []Leaves.ForKind(.fold).Policy,
    specs: []Bus.Spec,
    leaf_files: []FilePin,
    node_files: []FilePin,
    forest: Plan.Owned,
    fixed_catalogue: ?ForestFixed.Catalogue = null,
    independently_expected_catalogue: [32]u8 = @splat(0),
    limits: Limits,
    profile: Base.Profile,
    expected_policy: PolicyFile.Pin,
    identity: [32]u8,
    independently_derived_plan: [32]u8,
    pub const complete_source_authority = false;
    pub const complete_block_authority = false;
    pub fn nodePolicy(self: *const Owner, index: u32) Receiver.Policy {
        return .{ .public = .{ .forest = &self.forest, .expected_plan = self.independently_derived_plan, .specs = self.specs, .index = index }, .public_limits = self.limits.public, .max_proof_bytes = self.limits.max_proof_bytes };
    }
    pub fn require(self: *const Owner, independently_expected: PolicyFile.Pin) !void {
        if (!std.meta.eql(self.expected_policy, independently_expected) or !std.meta.eql(self.catalogue.policy.pin, independently_expected) or !std.meta.eql(self.identity, self.computeIdentity())) return error.UntrustedPageForestPolicyOwner;
        try self.forest.require(self.independently_derived_plan);
        if (self.fixed_catalogue) |*fixed| {
            try fixed.require(self.independently_expected_catalogue);
            if (fixed.forest != &self.forest or fixed.leaf_catalogue != self.catalogue or fixed.specs.len != self.specs.len) return error.UntrustedPageForestPolicyOwner;
            for (fixed.specs, self.specs) |expected, actual| if (!std.meta.eql(expected.geometry, actual.geometry) or !std.meta.eql(expected.expected_id, actual.expected_id) or expected.schedule.len != actual.schedule.len) return error.UntrustedPageForestPolicyOwner;
        } else return error.UntrustedPageForestPolicyOwner;
        if (self.specs.len != self.forest.geometry.nodes.len or self.leaf_files.len != self.forest.geometry.leaves or self.node_files.len != self.specs.len) return error.UntrustedPageForestPolicyOwner;
    }
    fn computeIdentity(self: *const Owner) [32]u8 {
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x5047464f, 1, @intFromEnum(self.profile), @intCast(self.raw.len), @intCast(self.fold.len), @intCast(self.specs.len) });
        channel.mixU64(self.expected_policy.byte_len);
        channel.mixRoot(self.expected_policy.sha256);
        channel.mixRoot(self.independently_derived_plan);
        channel.mixRoot(self.independently_expected_catalogue);
        for (self.raw) |leaf| channel.mixRoot(leaf.expected_id);
        for (self.fold) |leaf| channel.mixRoot(leaf.expected_id);
        for (self.specs) |spec| channel.mixRoot(spec.expected_id);
        return channel.digestBytes();
    }
    pub fn deinit(self: *Owner) void {
        const budget = self.budget;
        const a = budget.allocator();
        if (self.fixed_catalogue) |*fixed| fixed.deinit();
        self.forest.deinit();
        for (self.raw) |policy| a.free(policy.schedule);
        for (self.fold) |policy| a.free(policy.schedule);
        for (self.specs) |spec| a.free(spec.schedule);
        a.free(self.raw);
        a.free(self.fold);
        a.free(self.specs);
        a.free(self.leaf_files);
        a.free(self.node_files);
        self.catalogue.deinit();
        a.destroy(self);
        budget.destroy();
    }
};
pub const Built = struct {
    owner: *Owner,
    root: ?*Receiver.Fresh,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Built) void {
        if (self.root) |fresh| fresh.deinit();
        self.owner.deinit();
        self.* = undefined;
    }
};
fn initialGeometry(profile: Base.Profile) Base.Key {
    // Storage-only self/future slot; validateSources never admits it. Replaced
    // by actual child verifier rows before any positive node receiver use.
    return .{ .profile = profile, .config = profile.config(), .context = .{ .child_key_id = @splat(0), .child_config = profile.config(), .graph_ids = @splat(@splat(0)), .transcript_plan_id = @splat(0) }, .log_sizes = @splat(1), .preprocessed_root = @splat(1) };
}
fn chooseBytes(comptime Backend: type, comptime P: type, a: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, pin: ?FilePin, rows: anytype, admission: anytype, maximum: usize) ![]u8 {
    if (pin) |received| return Files.readPinned(a, dir, path, received.byte_len, received.sha256, maximum);
    const Producer = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, P);
    const producer = try Producer.init(a, &rows.rows, admission);
    defer producer.deinit();
    var proof = try producer.prove(a, &rows.rows);
    defer proof.deinit();
    const encoded = try Parent.codec.encode(a, &proof, &admission);
    errdefer a.free(encoded);
    if (encoded.len == 0 or encoded.len > maximum) return error.PageForestPolicyResourceLimit;
    return encoded;
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        /// Reconstruct mode repeats independent original verification and key
        /// derivation once per job. Stored files provide bytes, never keys.
        pub fn build(backing: std.mem.Allocator, dir: std.fs.Dir, policy_pin: PolicyFile.Pin, globals: Global.Pins, profile: Base.Profile, limits: Limits, action: Action) !Built {
            try limits.validate();
            const budget = try Budget.createRetainingParent(backing, limits.max_metadata_bytes);
            errdefer budget.destroy();
            const a = budget.allocator();
            const self = try a.create(Owner);
            errdefer a.destroy(self);
            const catalogue = try Catalogue.Catalogue.create(a, dir, policy_pin, globals, limits.catalogue);
            errdefer catalogue.deinit();
            if (!std.meta.eql(profile.config(), catalogue.context().fold_plan.config)) return error.UntrustedPageForestPolicySecurity;
            const raw = try a.alloc(Leaves.ForKind(.raw).Policy, catalogue.raw.len);
            errdefer a.free(raw);
            var raw_made: usize = 0;
            errdefer for (raw[0..raw_made]) |policy| a.free(policy.schedule);
            const fold = try a.alloc(Leaves.ForKind(.fold).Policy, catalogue.fold.len);
            errdefer a.free(fold);
            var fold_made: usize = 0;
            errdefer for (fold[0..fold_made]) |policy| a.free(policy.schedule);
            const count = try std.math.add(usize, raw.len, fold.len);
            var geometry = try Plan.derive(a, count, limits.plan);
            defer geometry.deinit();
            try requireExisting(action, count, geometry.nodes.len);
            const specs = try a.alloc(Bus.Spec, geometry.nodes.len);
            errdefer a.free(specs);
            for (specs) |*spec| spec.* = .{ .geometry = initialGeometry(profile), .schedule = &.{}, .expected_id = @splat(0) };
            var specs_made: usize = 0;
            errdefer for (specs[0..specs_made]) |spec| a.free(spec.schedule);
            const leaf_files = try a.alloc(FilePin, count);
            errdefer a.free(leaf_files);
            const node_files = try a.alloc(FilePin, geometry.nodes.len);
            errdefer a.free(node_files);
            var leaf_published: usize = 0;
            var node_published: usize = 0;
            errdefer if (action == .publish) {
                for (0..leaf_published) |index| {
                    var path: [96]u8 = undefined;
                    dir.deleteFile(leafFilename(&path, @intCast(index)) catch continue) catch {};
                }
                for (0..node_published) |index| {
                    var path: [96]u8 = undefined;
                    dir.deleteFile(nodeFilename(&path, @intCast(index)) catch continue) catch {};
                }
            };
            var total: u64 = 0;
            inline for ([_]Semantic.Kind{ .raw, .fold }) |kind| {
                const Capture = @import("block_v5_memory_source_page_recursive_capture_v1.zig").ForKind(kind);
                const LeafBus = @import("../recursion/block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(kind);
                const LeafProtocol = @import("../recursion/block_v5_reusable_memory_source_page_parent_protocol_v1.zig").ForKind(kind);
                const destination = if (kind == .raw) raw else fold;
                for (destination, 0..) |*policy, index| {
                    const live = try LiveBudget.create(backing, budget, limits.max_live_bytes);
                    defer live.destroy();
                    const scratch = live.allocator();
                    var scope = try catalogue.acquire(kind, @intCast(index));
                    defer scope.deinit();
                    const admitted = try scope.prepared();
                    const claims = try scope.expectedClaims();
                    var expected = try ExpectedSetup.ForKind(kind).ForBackend(Backend).derive(scratch, admitted, claims, limits.transcript_capacity, profile, limits.fixed);
                    defer expected.deinit();
                    // Only compact independently derived key/routing survive
                    // into native decode. Setup never reads this proof.
                    var original = try scope.decodeOriginal(scratch);
                    defer original.deinit(scratch);
                    var capture = try Capture.verifyBorrowed(scratch, &original, admitted);
                    defer capture.deinit();
                    try ExpectedSetup.requireClaims(kind, claims, capture.original.frame.semantic.claims);
                    const key = expected.key;
                    const id = try key.identity();
                    if (expected.wires.len > limits.max_schedule_terms) return error.PageForestPolicyResourceLimit;
                    const schedule = try a.dupe(LeafBus.Wire, expected.wires);
                    errdefer a.free(schedule);
                    const proposed = Leaves.ForKind(kind).Policy{ .admitted = admitted, .claims = .{ .semantic = capture.original.frame.semantic, .components = capture.original.frame.claims }, .key = key, .expected_id = id, .schedule = schedule, .normalization = limits.public.normalization, .max_proof_bytes = limits.max_proof_bytes };
                    const physical = if (kind == .raw) index else raw.len + index;
                    var path: [96]u8 = undefined;
                    const bytes = if (action == .reconstruct)
                        try Files.readPinned(scratch, dir, try leafFilename(&path, @intCast(physical)), action.reconstruct.leaves[physical].byte_len, action.reconstruct.leaves[physical].sha256, limits.max_proof_bytes)
                    else produced: {
                        var rows = try LeafBus.prepare(scratch, admitted, &capture, limits.transcript_capacity);
                        defer rows.deinit();
                        try ExpectedSetup.ForKind(kind).requirePrepared(key, expected.wires, &rows);
                        const admission = try LeafProtocol.Admission.init(key, id, expected.wires, rows.values);
                        break :produced try chooseBytes(Backend, LeafProtocol, scratch, dir, try leafFilename(&path, @intCast(physical)), null, &rows.recursive, admission, limits.max_proof_bytes);
                    };
                    defer scratch.free(bytes);
                    const fresh = try Leaves.ForKind(kind).verify(scratch, proposed, bytes);
                    defer fresh.deinit();
                    total = try std.math.add(u64, total, bytes.len);
                    if (total > limits.max_total_proof_bytes) return error.PageForestPolicyResourceLimit;
                    if (action == .publish) {
                        try Files.publish(dir, try leafFilename(&path, @intCast(physical)), bytes);
                        leaf_published += 1;
                    }
                    policy.* = proposed;
                    leaf_files[physical] = .{ .byte_len = bytes.len, .sha256 = Files.hash(bytes) };
                    if (kind == .raw) raw_made += 1 else fold_made += 1;
                }
            }
            var forest = try Plan.Owned.initWithCatalogue(a, catalogue, raw, fold, limits.plan);
            errdefer forest.deinit();
            self.* = .{ .budget = budget, .catalogue = catalogue, .raw = raw, .fold = fold, .specs = specs, .leaf_files = leaf_files, .node_files = node_files, .forest = forest, .limits = limits, .profile = profile, .expected_policy = policy_pin, .identity = undefined, .independently_derived_plan = forest.identity };
            // Independent live/setup lanes are siblings of metadata under
            // aggregate backing, never nested beneath the 1GiB metadata cap.
            self.fixed_catalogue = try ForestFixed.ForBackend(Backend).deriveWithCatalogue(backing, &self.forest, self.independently_derived_plan, limits.transcript_capacity, profile, limits.node_fixed, catalogue);
            errdefer if (self.fixed_catalogue) |*fixed| fixed.deinit();
            self.independently_expected_catalogue = self.fixed_catalogue.?.independently_expected;
            for (specs, self.fixed_catalogue.?.specs) |*spec, expected| {
                const schedule = try a.dupe(Bus.Wire, expected.schedule);
                spec.* = .{ .geometry = expected.geometry, .expected_id = expected.expected_id, .schedule = schedule };
                specs_made += 1;
            }
            var root_capture: ?*Receiver.Fresh = null;
            errdefer if (root_capture) |fresh| fresh.deinit();
            for (self.forest.geometry.nodes, 0..) |node, index| {
                const live = try LiveBudget.create(backing, budget, limits.max_live_bytes);
                defer live.destroy();
                const scratch = live.allocator();
                _ = try self.fixed_catalogue.?.policy(@intCast(index), self.independently_expected_catalogue);
                const local_policy = self.nodePolicy(@intCast(index));
                var path: [96]u8 = undefined;
                // Original leaves above and every recursive node below are
                // freshly verified under independent keys in reconstruction.
                // No private witness rows are built to nominate a node key.
                const bytes = if (action == .reconstruct)
                    try Files.readPinned(scratch, dir, try nodeFilename(&path, @intCast(index)), action.reconstruct.nodes[index].byte_len, action.reconstruct.nodes[index].sha256, limits.max_proof_bytes)
                else produced: {
                    // The lease closes after rows, source Values and all captures.
                    var group = try Catalogue.Group.acquire(catalogue, node.children[0..node.child_count]);
                    defer group.deinit();
                    var captures: [4]Rows.Capture = undefined;
                    var made: usize = 0;
                    defer for (captures[0..made]) |capture| switch (capture) {
                        .raw => |fresh| @constCast(fresh).deinit(),
                        .fold => |fresh| @constCast(fresh).deinit(),
                        .node => |fresh| @constCast(fresh).deinit(),
                    };
                    for (node.children[0..node.child_count], 0..) |ref, child| {
                        var child_path: [96]u8 = undefined;
                        const pin = switch (ref) {
                            .leaf => |ordinal| leaf_files[ordinal],
                            .node => |ordinal| node_files[ordinal],
                        };
                        const filename = switch (ref) {
                            .leaf => |ordinal| try leafFilename(&child_path, ordinal),
                            .node => |ordinal| try nodeFilename(&child_path, ordinal),
                        };
                        const child_bytes = try Files.readPinned(scratch, dir, filename, pin.byte_len, pin.sha256, limits.max_proof_bytes);
                        defer scratch.free(child_bytes);
                        captures[child] = switch (ref) {
                            .leaf => |ordinal| if (ordinal < raw.len) .{ .raw = try Leaves.ForKind(.raw).verify(scratch, self.forest.raw[ordinal], child_bytes) } else .{ .fold = try Leaves.ForKind(.fold).verify(scratch, self.forest.fold[ordinal - raw.len], child_bytes) },
                            .node => |ordinal| .{ .node = try Receiver.verify(scratch, self.nodePolicy(ordinal), child_bytes) },
                        };
                        made += 1;
                    }
                    var public = try Bus.Owner.prepareSources(scratch, local_policy.public, limits.public);
                    defer public.deinit();
                    var rows = try Rows.prepare(scratch, &public, captures[0..made], limits.transcript_capacity, limits.rows);
                    defer rows.deinit();
                    try rows.recursive.rows.partitionHashRows();
                    const expected = specs[index];
                    try ExpectedSetup.requireNodeMetadata(expected.geometry, rows.recursive.context, try FixedKey.rowLogs(rows.recursive.rows.fixed), rows.wires);
                    const key = try Protocol.Key.fromGeometry(expected.geometry, expected.schedule);
                    const admission = try Protocol.Admission.init(key, expected.expected_id, expected.schedule, .{ .public = &public });
                    break :produced try chooseBytes(Backend, Protocol, scratch, dir, try nodeFilename(&path, @intCast(index)), null, &rows.recursive, admission, limits.max_proof_bytes);
                };
                defer scratch.free(bytes);
                const fresh = try Receiver.verify(scratch, self.nodePolicy(@intCast(index)), bytes);
                var owns_fresh = true;
                defer if (owns_fresh) fresh.deinit();
                total = try std.math.add(u64, total, bytes.len);
                if (total > limits.max_total_proof_bytes) return error.PageForestPolicyResourceLimit;
                if (action == .publish) {
                    try Files.publish(dir, try nodeFilename(&path, @intCast(index)), bytes);
                    node_published += 1;
                }
                node_files[index] = .{ .byte_len = bytes.len, .sha256 = Files.hash(bytes) };
                if (self.forest.geometry.root == @as(u32, @intCast(index))) {
                    root_capture = fresh;
                    owns_fresh = false;
                }
            }
            self.identity = self.computeIdentity();
            try self.require(policy_pin);
            // No descendant lease is retained: fresh root owns only compact
            // Summary and genuine core Parent capture under independent setup.
            return .{ .owner = self, .root = root_capture };
        }
    };
}

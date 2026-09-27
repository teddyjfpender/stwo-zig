//! Genuine capture-free VERSION16 setup: original native Word factories,
//! original compact verifier compiler, exact merge graph and closed suppliers.
//! Keys are derived topologically; transported Spec arrays cannot nominate one.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Base = @import("blake3_execution_parent_protocol.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Bus = @import("block_v5_memory_source_page_forest_bus_v1.zig");
const SummaryBus = @import("block_v5_memory_source_page_forest_summary_bus_v1.zig");
const Authority = @import("block_v5_memory_source_page_forest_plan_v1.zig");
const LeafCatalogue = @import("../prover/block_v5_memory_source_page_leaf_catalogue_v1.zig");
const Protocol = @import("block_v5_memory_source_page_forest_protocol_v1.zig");
const Shape = @import("block_v5_memory_source_page_forest_recursive_shape_admission_v1.zig");
const Context = @import("block_v5_memory_source_page_forest_fixed_context_v1.zig");
const Child = @import("air/block_v5_compact_recursive_fixed_child_v1.zig");
const Graph = @import("air/block_v5_memory_source_page_forest_graph_v1.zig");
const FixedGraph = @import("air/block_v5_recursive_fixed_graph_attach_v1.zig");
const Identifiers = @import("air/block_v5_requester_public_fixed_identifier_ports_v1.zig");
const Attach = @import("block_v5_recursive_fixed_attachments_v1.zig").Scoped;
const Storage = @import("air/blake3_parent_row_storage.zig");
const FixedJoin = @import("air/block_v5_requester_public_fixed_join_v1.zig");
const Inventory = @import("block_v5_compact_fixed_spec_inventory_v1.zig");
pub const Limits = struct {
    max_metadata_bytes: usize = 1 << 30,
    max_live_bytes: usize = 8 << 30,
    max_nodes: usize = 1 << 20,
    max_rows_per_cohort: usize = 1 << 24,
    leaf: @import("block_v5_memory_source_page_recursive_fixed_roster_v1.zig").Limits = .{},
    pieces: @import("block_v5_recursive_parent_fixed_pieces_v1.zig").Limits = .{},
    public: Bus.Limits = .{},
    public_supply: @import("air/block_v5_closed_public_supply_v1.zig").Limits = .{},
    pub fn validate(self: Limits, capacity: u32) !void {
        if (capacity == 0 or self.max_metadata_bytes == 0 or self.max_live_bytes == 0 or self.max_nodes == 0 or self.max_rows_per_cohort == 0 or self.max_rows_per_cohort > 1 << 24) return error.PageForestFixedResourceLimit;
    }
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    fixed: Storage.FixedTuple(false),
    context: Base.Context,
    closure: [32]u8,
    index: u32,
    expected_plan: [32]u8,
    pub const complete_block_authority = false;
    pub fn validateLive(self: *const Owned, live: *@import("block_v5_memory_source_page_forest_preparation_v1.zig").Prepared) !void {
        try live.recursive.rows.partitionHashRows();
        if (live.wires.len != 0 or !std.meta.eql(self.context, live.recursive.context)) return error.UntrustedPageForestFixedAssembly;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedPageForestFixedAssembly;
            for (self.fixed[i], live.recursive.rows.fixed[i]) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedPageForestFixedAssembly;
        }
    }
    pub fn deinit(self: *Owned) void {
        const budget = self.budget;
        FixedJoin.deinit(self.allocator, &self.fixed);
        self.* = undefined;
        budget.destroy();
    }
};
pub const Catalogue = struct {
    allocator: std.mem.Allocator,
    backing: std.mem.Allocator,
    budget: *Budget,
    forest: *const Authority.Owned,
    expected_plan: [32]u8,
    leaf_catalogue: ?*LeafCatalogue.Catalogue,
    specs: []Bus.Spec,
    inventory: Inventory.Owned,
    independently_expected: [32]u8,
    capacity: u32,
    profile: Base.Profile,
    limits: Limits,
    pub const complete_block_authority = false;
    pub fn require(self: *const Catalogue, independently_expected: [32]u8) !void {
        try self.limits.validate(self.capacity);
        try self.forest.require(self.expected_plan);
        if (self.specs.len != self.forest.geometry.nodes.len or self.specs.len > self.limits.max_nodes or !std.meta.eql(self.independently_expected, independently_expected) or !std.meta.eql(identity(self.forest, self.expected_plan, self.specs.len, self.inventory.root, self.capacity, self.profile), independently_expected)) return error.UntrustedPageForestFixedCatalogue;
    }
    /// Bounded membership for the selected compact recipe and its <=4
    /// direct lower specs. This grants setup consistency, never proof acceptance.
    pub fn requireSelected(self: *const Catalogue, index: u32, independently_expected: [32]u8) !void {
        _ = try self.policy(index, independently_expected);
    }
    pub fn policy(self: *const Catalogue, index: u32, independently_expected: [32]u8) !Bus.Policy {
        try self.require(independently_expected);
        if (index >= self.specs.len) return error.UntrustedPageForestFixedCatalogue;
        try self.inventory.require(index, self.specs[index], self.inventory.root);
        const planned = try self.forest.node(index, self.expected_plan);
        for (planned.children[0..planned.child_count]) |ref| if (ref == .node) try self.inventory.require(ref.node, self.specs[ref.node], self.inventory.root);
        const selected = Bus.Policy{ .forest = self.forest, .expected_plan = self.expected_plan, .specs = self.specs, .index = index };
        try selected.validate();
        return selected;
    }
    pub fn deinit(self: *Catalogue) void {
        const budget = self.budget;
        self.inventory.deinit();
        self.allocator.free(self.specs);
        self.* = undefined;
        budget.destroy();
    }
};
fn identity(forest: *const Authority.Owned, expected_plan: [32]u8, count: usize, inventory: [32]u8, capacity: u32, profile: Base.Profile) [32]u8 {
    var c = core.channel.blake3.Channel{};
    c.mixU32s(&.{ 0x50474646, 16, capacity, @intFromEnum(profile), @intCast(count) });
    c.mixRoot(expected_plan);
    c.mixRoot(forest.recipe_root);
    c.mixRoot(Protocol.sourceAuthority());
    c.mixRoot(inventory);
    return c.digestBytes();
}
fn appendGraph(a: std.mem.Allocator, builder: *Attach, ids: *Context.Owned, public: *const Bus.Owner) !void {
    var graph = try Graph.prepare(a, public);
    defer graph.deinit();
    var fixed = try FixedGraph.Owned.derive(a, &graph.circuit, graph.sources);
    defer fixed.deinit();
    var identifiers = try Identifiers.Owned.init(a, &.{graph.circuit.graph()}, &.{FixedGraph.CIRCUIT});
    defer identifiers.deinit();
    try builder.appendGraphWithArithmetic(fixed.fixed, fixed.wires, fixed.identity, try identifiers.port());
    ids.attachment(builder.attachments.items[builder.attachments.items.len - 1]);
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Family = @This();
        /// Only this kernel consumes a Spec array: all lower specs were derived
        /// earlier in this constructor, never supplied by a file/caller factory.
        fn deriveLocal(backing: std.mem.Allocator, policy: Bus.Policy, capacity: u32, profile: Base.Profile, limits: Limits, catalogue: ?*LeafCatalogue.Catalogue) !Owned {
            @setEvalBranchQuota(30_000);
            try limits.validate(capacity);
            if (!std.meta.eql(profile.config(), policy.forest.context.fold_plan.config)) return error.UntrustedPageForestFixedSecurity;
            const budget = try Budget.createRetainingParent(backing, limits.max_live_bytes);
            errdefer budget.destroy();
            const a = budget.allocator();
            // Direct leaf descriptors live only through this local setup.
            // Compact lower-node admissions do not reacquire descendants.
            var group: ?LeafCatalogue.Group = null;
            defer if (group) |*owned| owned.deinit();
            if (catalogue) |owner| {
                if (owner.context() != policy.forest.context) return error.UntrustedPageForestFixedCatalogue;
                try policy.forest.require(policy.expected_plan);
                if (policy.index >= policy.forest.geometry.nodes.len) return error.UntrustedPageForestFixedCatalogue;
                const planned = policy.forest.geometry.nodes[policy.index];
                group = try LeafCatalogue.Group.acquire(owner, planned.children[0..planned.child_count]);
                // Semantic quotient constants are independent setup inputs,
                // never nominated by decoded original PAGE claims.
                for (group.?.slots[0..group.?.count]) |*scope| switch (scope.*) {
                    .raw => |*active| {
                        const expected = try active.expectedClaims();
                        if (!std.meta.eql(expected, policy.forest.raw[active.index].claims.semantic.claims)) return error.UntrustedPageForestExpectedSemanticClaims;
                    },
                    .fold => |*active| {
                        const expected = try active.expectedClaims();
                        if (!std.meta.eql(expected, policy.forest.fold[active.index].claims.semantic.claims)) return error.UntrustedPageForestExpectedSemanticClaims;
                    },
                };
            }
            var public = try Bus.Owner.prepareSources(a, policy, limits.public);
            defer public.deinit();
            const node = try policy.forest.node(policy.index, policy.expected_plan);
            var ids = Context.Owned.init(policy.index, node, policy.expected_plan, Protocol.sourceAuthority());
            var builder = try Attach.init(a, .{ .max_children = 4, .max_rows = limits.max_rows_per_cohort });
            defer builder.deinit();
            for (node.children[0..node.child_count], 0..) |ref, ordinal| switch (ref) {
                .leaf => |index| {
                    inline for (.{ .raw, .fold }) |kind| if ((kind == .raw and index < policy.forest.raw.len) or (kind == .fold and index >= policy.forest.raw.len)) {
                        const Typed = Shape.ForKind(kind);
                        const p = if (kind == .raw) policy.forest.raw[index] else policy.forest.fold[index - policy.forest.raw.len];
                        var expected: ?@import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig").Claims = null;
                        for (group.?.slots[0..group.?.count]) |*slot| switch (slot.*) {
                            .raw => |*active| if (kind == .raw and active.index == index) {
                                expected = try active.expectedClaims();
                            },
                            .fold => |*active| if (kind == .fold and active.index == index - policy.forest.raw.len) {
                                expected = try active.expectedClaims();
                            },
                        };
                        var source = try Typed.Source.derive(Backend, a, p, expected orelse return error.MissingIndependentPageSemanticClaims, capacity, profile, limits.leaf);
                        defer source.deinit();
                        const child = try Child.append(a, &builder, try Typed.Admission.init(&source), @intCast(ordinal), Typed.PUBLIC_CIRCUIT, capacity, limits.pieces);
                        ids.child(child.namespace, child.context);
                    };
                },
                .node => |index| {
                    var lower_policy = policy;
                    lower_policy.index = index;
                    var lower = try SummaryBus.Owner.init(a, lower_policy, limits.public);
                    defer lower.deinit();
                    var source = try Shape.Node.Source.init(a, &lower);
                    defer source.deinit();
                    const child = try Child.append(a, &builder, try Shape.Node.Admission.init(&source), @intCast(ordinal), Shape.Node.PUBLIC_CIRCUIT, capacity, limits.pieces);
                    ids.child(child.namespace, child.context);
                },
            };
            try appendGraph(a, &builder, &ids, &public);
            if (builder.child_count != node.child_count or builder.main_identifier_rows != 0) return error.MissingRecursiveFixedMainIdentifierPort;
            const closure = try builder.closePublicSupply(Bus.SourceValues{ .public = &public }, limits.public_supply);
            ids.attachment(closure);
            var fixed = FixedJoin.empty();
            errdefer FixedJoin.deinit(a, &fixed);
            inline for (0..Storage.Airs.len) |i| fixed[i] = try builder.fixed[i].toOwnedSlice(a);
            try FixedJoin.partition(a, &fixed);
            try public.validateSources();
            return .{ .allocator = a, .budget = budget, .fixed = fixed, .context = ids.finish(policy.forest.context.fold_plan.config), .closure = closure, .index = policy.index, .expected_plan = policy.expected_plan };
        }
        /// Exact original ordered census; at most four original children and
        /// one local setup resident. Only compact independently derived specs
        /// persist. Metadata and live lanes share the retained aggregate backing.
        fn deriveAdmitted(backing: std.mem.Allocator, forest: *const Authority.Owned, independently_expected_plan: [32]u8, capacity: u32, profile: Base.Profile, limits: Limits, catalogue: ?*LeafCatalogue.Catalogue) !Catalogue {
            try limits.validate(capacity);
            if (catalogue == null) return error.MissingIndependentPageSemanticClaims;
            try forest.require(independently_expected_plan);
            if (forest.geometry.nodes.len > limits.max_nodes) return error.PageForestFixedResourceLimit;
            const budget = try Budget.createRetainingParent(backing, limits.max_metadata_bytes);
            errdefer budget.destroy();
            const a = budget.allocator();
            const specs = try a.alloc(Bus.Spec, forest.geometry.nodes.len);
            errdefer a.free(specs);
            for (specs, 0..) |*spec, i| {
                // Current/future slots are uninitialized and never admitted;
                // original validateSources reads only already-derived children.
                const policy = Bus.Policy{ .forest = forest, .expected_plan = independently_expected_plan, .specs = specs, .index = @intCast(i) };
                var owned = try Family.deriveLocal(backing, policy, capacity, profile, limits, catalogue);
                defer owned.deinit();
                const geometry = try Parent.ForBackend(Backend).deriveKeyFromFixed(owned.allocator, owned.fixed, owned.context, profile);
                const key = try Protocol.Key.fromGeometry(geometry, &.{});
                spec.* = .{ .geometry = geometry, .expected_id = try key.identity(), .schedule = &.{} };
                try policy.validate();
            }
            var inventory = try Inventory.Owned.init(a, 16, specs, limits.max_nodes);
            errdefer inventory.deinit();
            const pinned = identity(forest, independently_expected_plan, specs.len, inventory.root, capacity, profile);
            return .{ .allocator = a, .backing = backing, .budget = budget, .forest = forest, .expected_plan = independently_expected_plan, .leaf_catalogue = catalogue, .specs = specs, .inventory = inventory, .independently_expected = pinned, .capacity = capacity, .profile = profile, .limits = limits };
        }
        pub fn derive(backing: std.mem.Allocator, forest: *const Authority.Owned, independently_expected_plan: [32]u8, capacity: u32, profile: Base.Profile, limits: Limits) !Catalogue {
            return Family.deriveAdmitted(backing, forest, independently_expected_plan, capacity, profile, limits, null);
        }
        /// Durable typed provider supplies only the <=4 current original leaf
        /// admissions. Scope teardown restores inactive compact pin slots.
        pub fn deriveWithCatalogue(backing: std.mem.Allocator, forest: *const Authority.Owned, independently_expected_plan: [32]u8, capacity: u32, profile: Base.Profile, limits: Limits, catalogue: *LeafCatalogue.Catalogue) !Catalogue {
            return Family.deriveAdmitted(backing, forest, independently_expected_plan, capacity, profile, limits, catalogue);
        }
        pub fn materialize(self: *const Catalogue, index: u32, independently_expected: [32]u8) !Owned {
            const policy = try self.policy(index, independently_expected);
            var owned = try Family.deriveLocal(self.backing, policy, self.capacity, self.profile, self.limits, self.leaf_catalogue);
            errdefer owned.deinit();
            const geometry = try Parent.ForBackend(Backend).deriveKeyFromFixed(owned.allocator, owned.fixed, owned.context, self.profile);
            const key = try Protocol.Key.fromGeometry(geometry, &.{});
            const expected = self.specs[index];
            if (!std.meta.eql(geometry, expected.geometry) or !std.meta.eql(try key.identity(), expected.expected_id)) return error.UntrustedPageForestFixedCatalogue;
            return owned;
        }
    };
}

//! Process-local immutable setup reuse. No serialized token is proof authority.
//! Independently admitted Prepared catalogues must outlive this owner; source,
//! proposal vectors, coverage and local routing data are independently owned.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Full = @import("block_v5_heterogeneous_policy_v1.zig");
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const Recipes = @import("../prover/block_v5_execution_recipe_v1.zig");
const Scoped = @import("block_v5_heterogeneous_scoped_plan_v1.zig");
const Cohorts = @import("block_v5_heterogeneous_scoped_cohorts_v1.zig");
const Routes = @import("block_v5_heterogeneous_scoped_routes_v1.zig");
const Bus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Source = @import("block_v5_heterogeneous_scoped_source_v1.zig");
const Original = @import("block_v5_heterogeneous_child_frames_v1.zig");
const Protocol = @import("block_v5_reusable_heterogeneous_scoped_protocol_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Key = Protocol.Key;
pub const VERSION = Protocol.VERSION;
pub const Profile = Protocol.Profile;
pub const Context = Protocol.Context;
pub const Pins = struct {
    job: [32]u8,
    coverage: [32]u8,
    source: [32]u8,
    recipe: Recipes.Recipe,
    scoped: [32]u8,
    routing: [32]u8,
    /// Expected IDs from independent typed setup reconstruction, never files.
    node_ids: []const [32]u8,
    pub fn contextIdentity(self: Pins) [32]u8 {
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42355a41, 1, @intFromEnum(self.recipe) }); // B5ZA local admission owner.
        inline for (.{ self.job, self.coverage, self.source, self.scoped, self.routing }) |digest| channel.mixRoot(digest);
        return channel.digestBytes();
    }
    pub fn identity(self: Pins) [32]u8 {
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42355a41, 2 });
        channel.mixRoot(self.contextIdentity());
        channel.mixU64(self.node_ids.len);
        for (self.node_ids) |id| channel.mixRoot(id);
        return channel.digestBytes();
    }
};
pub const NodeSpec = struct {
    /// Independently admitted original typed graph/setup context.
    unbound_context: Context,
    key: Key,
    expected_id: [32]u8,
    wires: []const Bus.Wire,
    children: []const Bus.ChildPin,
    outputs: []const Q,
    public_input: [32]u8,
    source_seal: [32]u8,
};
pub const Limits = struct {
    max_live_borrows: usize = 64,
    max_owned_bytes: usize = 1 << 30,
    max_policy_source_cells: usize = 1 << 26,
    scoped: Scoped.Limits = .{},
    cohorts: Cohorts.Limits = .{},
    routes: Routes.Limits = .{},
};
pub const Guard = struct {
    mutex: std.Thread.Mutex = .{},
    active: usize = 0,
    limit: usize,
    pub fn acquire(self: *Guard) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.active >= self.limit) return error.ScopedOwnerBorrowLimit;
        self.active += 1;
    }
    pub fn release(self: *Guard) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.active == 0) @panic("unbalanced compact setup borrow");
        self.active -= 1;
    }
    pub fn requireUnused(self: *Guard) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.active != 0) return error.ActiveScopedOwnerBorrow;
    }
};
pub const Borrow = struct {
    owner: *Owner,
    pub fn deinit(self: *Borrow) void {
        self.owner.guard.release();
        self.* = undefined;
    }
};
const Node = struct { spec: NodeSpec, source: Source.Source, local_pin: [32]u8 };
pub const Owner = struct {
    backing: std.mem.Allocator,
    budget: *Budget,
    arena: std.heap.ArenaAllocator,
    pins: Pins,
    pinned_identity: [32]u8,
    pinned_context: [32]u8,
    pinned_node_ids: []const [32]u8,
    coverage: Coverage.Plan,
    full: Full.Policy,
    scoped: Scoped.Plan,
    cohorts: Cohorts.Plan,
    routes: Routes.Plan,
    leaves: []Source.Source,
    leaf_pins: []const [32]u8,
    nodes: []Node,
    initialized: usize,
    ready: bool,
    guard: Guard,
    limits: Limits,
    pub const proof_authority = false;
    pub const complete_block_authority = false;
    pub fn deinit(self: *Owner) void {
        self.guard.requireUnused() catch @panic("destroying borrowed compact setup owner");
        self.ready = false;
        for (self.nodes[0..self.initialized]) |*owned_node| owned_node.source.deinit();
        for (self.leaves) |*leaf_source| leaf_source.deinit();
        for (self.full.children) |*child| @constCast(child).deinit();
        self.routes.deinit();
        self.cohorts.deinit();
        self.scoped.deinit();
        self.arena.deinit();
        const budget = self.budget;
        budget.allocator().destroy(self);
        budget.destroy();
    }
    pub fn borrow(self: *const Owner) !Borrow {
        if (!self.ready) return error.ScopedOwnerLifetime;
        try self.requirePins();
        const mutable = @constCast(self);
        try mutable.guard.acquire();
        return .{ .owner = mutable };
    }
    fn requirePins(self: *const Owner) !void {
        // Constant global comparisons plus at most the selected node's local
        // fingerprint. Never walk the full node-id roster at each fold.
        if (!std.meta.eql(self.pinned_context, self.pins.contextIdentity()) or
            !std.meta.eql(self.pins.coverage, self.coverage.pinned_digest) or
            !std.meta.eql(self.pins.source, self.coverage.meta.seal_digest) or self.pins.recipe != self.coverage.meta.recipe or
            !std.meta.eql(self.pins.scoped, self.scoped.digest) or !std.meta.eql(self.pins.routing, self.routes.digest)) return error.MutatedScopedOwnerPins;
    }
    /// This borrow has process-local provenance. Files cannot mint an Owner.
    pub fn node(self: *const Owner, index: u32) !Admission {
        if (!self.ready or index >= self.initialized) return error.ScopedOwnerLifetime;
        return self.admission(index);
    }
    fn admission(self: *const Owner, index: u32) !Admission {
        try self.requirePins();
        if (index >= self.nodes.len) return error.InvalidScopedOwnedNode;
        const spec = self.nodes[index].spec;
        return .{ .key = spec.key, .expected_id = spec.expected_id, .wires = spec.wires, .values = .{ .owner = self, .index = index }, .expected_public = spec.public_input };
    }
    pub fn source(self: *const Owner, ref: Cohorts.Ref) !Source.Source {
        try self.requirePins();
        return switch (ref) {
            .leaf => |ordinal| block: {
                if (ordinal >= self.leaves.len or !Scoped.includes(self.scoped.recipe, self.full.children[ordinal].physical)) return error.InvalidScopedOwnedNode;
                try self.leaves[ordinal].validate();
                if (!std.meta.eql(self.leaves[ordinal].seal, self.leaf_pins[ordinal])) return error.MutatedScopedOwnedSource;
                break :block self.leaves[ordinal];
            },
            .node => |index| block: {
                if (index >= self.initialized) return error.ScopedOwnerLifetime;
                try self.nodes[index].source.validate();
                if (!std.meta.eql(self.nodes[index].source.seal, self.nodes[index].spec.source_seal)) return error.MutatedScopedOwnedSource;
                break :block self.nodes[index].source;
            },
        };
    }
    /// Hash only this node's exact route and direct-leaf selectors. Global
    /// accounting requirements are not rescanned through every descendant.
    fn localIdentity(self: *const Owner, index: u32) ![32]u8 {
        return fingerprintLocal(&self.routes, index, self.nodes[index].spec, self.pinned_identity);
    }
    pub fn validateNode(self: *const Owner, index: u32) !void {
        try self.requirePins();
        if (index >= self.nodes.len) return error.MutatedScopedOwnedNode;
        try requireFingerprint(&self.routes, index, self.nodes[index].spec, self.pinned_identity, self.nodes[index].local_pin);
        const spec = self.nodes[index].spec;
        var context = spec.unbound_context;
        bindPinnedContext(&context, self.pinned_context);
        if (index >= self.pinned_node_ids.len or !std.meta.eql(spec.expected_id, self.pinned_node_ids[index]) or !std.meta.eql(context, spec.key.context)) return error.UntrustedScopedOwnerContext;
        if (!std.meta.eql(try spec.key.identity(), spec.expected_id) or !std.meta.eql(try Bus.scheduleDigest(spec.wires), spec.key.public_schedule_digest)) return error.UntrustedReusableScopedOwnerKey;
        const cohort = self.cohorts.nodes[index];
        if (spec.children.len != cohort.child_count or spec.outputs.len != self.routes.nodes[index].exports.len) return error.InvalidScopedPublicCensus;
        for (spec.outputs) |value| for (value.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.NoncanonicalScopedSummary;
        if (!std.meta.eql(spec.key.config, spec.key.context.child_config) or !std.meta.eql(spec.key.config, self.coverage.meta.security.recursive)) return error.ScopedSecurityMismatch;
        for (cohort.children[0..cohort.child_count], spec.children) |ref, pin| {
            const child = try self.source(ref);
            if (!std.meta.eql(child.key, pin.key) or !std.meta.eql(child.expected_id, pin.id) or !std.meta.eql(child.public_input_digest, pin.public_input) or !std.meta.eql(child.seal, pin.source_seal) or
                !std.meta.eql(child.key.config, spec.key.config) or !std.meta.eql(child.key.context.child_config, spec.key.config)) return error.UntrustedScopedPublicSource;
            if (ref == .node) {
                const expected = self.routes.nodes[ref.node].exports;
                if (child.slots.len != expected.len or !std.meta.eql(child.span, self.cohorts.nodes[ref.node].span)) return error.InvalidScopedPublicCensus;
                for (child.slots, expected) |slot, id| if (slot.requirement != id) return error.InvalidScopedPublicCensus;
            }
        }
    }
    /// Node setup is independently chosen. Domain-bind its context to the
    /// independently reconstructed job/coverage/source/recipe authority.
    pub fn bindContext(self: *const Owner, context: *@import("blake3_execution_parent_protocol.zig").Context) !void {
        try self.requirePins();
        bindPinnedContext(context, self.pinned_context);
    }
};
fn bindPinnedContext(context: *@import("blake3_execution_parent_protocol.zig").Context, pin: [32]u8) void {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42355a43, 1 }); // B5ZC owner-bound setup context.
    channel.mixRoot(context.child_key_id);
    channel.mixRoot(pin);
    context.child_key_id = channel.digestBytes();
    for (&context.graph_ids) |*digest| {
        channel = .{};
        channel.mixU32s(&.{ 0x42355a43, 1 });
        channel.mixRoot(digest.*);
        channel.mixRoot(pin);
        digest.* = channel.digestBytes();
    }
    channel = .{};
    channel.mixU32s(&.{ 0x42355a43, 1 });
    channel.mixRoot(context.transcript_plan_id);
    channel.mixRoot(pin);
    context.transcript_plan_id = channel.digestBytes();
}
fn fingerprintLocal(routes: *const Routes.Plan, index: u32, spec: NodeSpec, pinned: [32]u8) ![32]u8 {
    if (index >= routes.nodes.len or index >= routes.cohorts.nodes.len) return error.InvalidScopedOwnedNode;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42355a4e, 1, index }); // B5ZN local selectors/shape.
    channel.mixRoot(pinned);
    channel.mixRoot(spec.expected_id);
    channel.mixRoot(spec.public_input);
    channel.mixRoot(spec.source_seal);
    channel.mixRoot(try spec.key.identity());
    channel.mixRoot(try Bus.scheduleDigest(spec.wires));
    channel.mixFelts(spec.outputs);
    const cohort = routes.cohorts.nodes[index];
    if (cohort.child_count < 2 or cohort.child_count > 4) return error.InvalidScopedOwnedNode;
    channel.mixU32s(&.{cohort.child_count});
    for (cohort.children[0..cohort.child_count]) |ref| channel.mixU32s(&.{ @intFromEnum(std.meta.activeTag(ref)), switch (ref) {
        .leaf, .node => |ordinal| ordinal,
    } });
    for (spec.children) |pin| {
        channel.mixRoot(try pin.key.identity());
        channel.mixRoot(pin.id);
        channel.mixRoot(pin.public_input);
        channel.mixRoot(pin.source_seal);
    }
    inline for (.{ routes.nodes[index].inputs, routes.nodes[index].exports, routes.nodes[index].closed }) |ids| {
        channel.mixU64(ids.len);
        for (ids) |id| {
            if (id >= routes.scoped.requirements.len) return error.InvalidScopedOwnedNode;
            const requirement = routes.scoped.requirements[id];
            channel.mixU32s(&.{ id, @intFromEnum(requirement.key.kind), requirement.key.scope, requirement.key.coordinate, @intFromEnum(requirement.disposition) });
            for (cohort.children[0..cohort.child_count]) |ref| if (ref == .leaf) {
                const terms = Scoped.Plan.termsFor(requirement, ref.leaf);
                channel.mixU64(terms.len);
                for (terms) |term| {
                    channel.mixU32s(&.{ @intFromEnum(std.meta.activeTag(term.selection)), @intFromBool(term.negative) });
                    switch (term.selection) {
                        .felt => |selected| channel.mixU32s(&.{ selected.child, @intFromEnum(selected.kind), selected.index, selected.frame, selected.felt }),
                        .byte => |selected| channel.mixU32s(&.{ selected.child, selected.cell, selected.part }),
                        .words => |selected| {
                            channel.mixU32s(&.{selected.child});
                            for (selected.selectors) |word| channel.mixU32s(&.{ word.frame, word.word });
                        },
                    }
                }
            };
        }
    }
    if (cohort.span) |span| channel.mixRoot(try span.identity()) else channel.mixRoot(@splat(0));
    return channel.digestBytes();
}
fn requireFingerprint(routes: *const Routes.Plan, index: u32, spec: NodeSpec, pinned: [32]u8, expected: [32]u8) !void {
    if (!std.meta.eql(try fingerprintLocal(routes, index, spec, pinned), expected)) return error.MutatedScopedOwnedNode;
}
/// Copied slice contents are owned; true Prepared pointers remain immutable
/// borrows. No underlying template/circuit is duplicated or assumed alive.
fn clone(comptime T: type, a: std.mem.Allocator, value: T) !T {
    return switch (@typeInfo(T)) {
        .pointer => |info| if (info.size == .slice) block: {
            const result = try a.alloc(info.child, value.len);
            for (result, value) |*dst, src| dst.* = try clone(info.child, a, src);
            break :block result;
        } else value,
        .array => block: {
            var result: T = undefined;
            for (&result, value) |*dst, src| dst.* = try clone(@TypeOf(src), a, src);
            break :block result;
        },
        .optional => |info| if (value) |item| try clone(info.child, a, item) else null,
        .@"struct" => block: {
            var result = value;
            inline for (std.meta.fields(T)) |field| {
                if (!field.is_comptime) @field(result, field.name) = try clone(field.type, a, @field(value, field.name));
            }
            break :block result;
        },
        .@"union" => |info| if (info.tag_type != null) block: {
            switch (value) {
                inline else => |payload, tag| break :block @unionInit(T, @tagName(tag), try clone(@TypeOf(payload), a, payload)),
            }
        } else value,
        else => value,
    };
}
/// Original init and the late-bound path share one normative reconstruction.
/// This setup owns stable coverage/frame/route storage while real child proofs
/// determine each node's expected geometry. No serialized setup is accepted.
pub const JobPins = struct { job: [32]u8, coverage: [32]u8, source: [32]u8, recipe: Recipes.Recipe };
pub const JobSetup = struct {
    owned: ?*Owner,
    pub fn deinit(self: *JobSetup) void {
        if (self.owned) |owner| owner.deinit();
        self.owned = null;
    }
    pub fn routes(self: *const JobSetup) !*const Routes.Plan {
        return &(self.owned orelse return error.ScopedOwnerLifetime).routes;
    }
    pub fn source(self: *const JobSetup, ordinal: u32) !Source.Source {
        return (self.owned orelse return error.ScopedOwnerLifetime).source(.{ .leaf = ordinal });
    }
    pub fn derivedPins(self: *const JobSetup) !Pins {
        return (self.owned orelse return error.ScopedOwnerLifetime).pins;
    }
    /// Consumes setup on success AND failure; deinit remains safe afterward.
    /// Prepared borrows remain external and must outlive the returned Owner.
    pub fn finish(self: *JobSetup, pins: Pins, specs: []const NodeSpec) !*Owner {
        const owner = self.owned orelse return error.ScopedOwnerLifetime;
        self.owned = null;
        errdefer owner.deinit();
        return finishSetup(owner, pins, specs);
    }
};
pub fn ForRecipe(comptime recipe: Scoped.Recipe) type {
    return struct {
        pub fn prepareJob(backing: std.mem.Allocator, full: Full.Policy, pins: JobPins, limits: Limits) !JobSetup {
            return prepareJobRecipe(recipe, backing, full, pins, limits);
        }
        pub fn init(backing: std.mem.Allocator, full: Full.Policy, pins: Pins, specs: []const NodeSpec, limits: Limits) !*Owner {
            var setup = try prepareJobRecipe(recipe, backing, full, .{ .job = pins.job, .coverage = pins.coverage, .source = pins.source, .recipe = pins.recipe }, limits);
            defer setup.deinit();
            return setup.finish(pins, specs);
        }
    };
}
pub const prepareJob = ForRecipe(.complete).prepareJob;
fn prepareJobRecipe(comptime recipe: Scoped.Recipe, backing: std.mem.Allocator, full: Full.Policy, pins: JobPins, limits: Limits) !JobSetup {
    if (limits.max_owned_bytes == 0 or limits.max_live_borrows == 0 or std.mem.allEqual(u8, &pins.job, 0)) return error.ScopedOwnerResourceLimit;
    try full.validate();
    if (!std.meta.eql(pins.coverage, full.plan.pinned_digest) or !std.meta.eql(pins.source, full.plan.meta.seal_digest) or pins.recipe != full.plan.meta.recipe) return error.UntrustedScopedOwnerPins;
    const budget = try Budget.create(backing, limits.max_owned_bytes);
    errdefer budget.destroy();
    const self = try budget.allocator().create(Owner);
    errdefer budget.allocator().destroy(self);
    self.arena = std.heap.ArenaAllocator.init(budget.allocator());
    errdefer self.arena.deinit();
    const a = self.arena.allocator();
    self.backing = backing;
    self.budget = budget;
    self.pins = .{ .job = pins.job, .coverage = pins.coverage, .source = pins.source, .recipe = pins.recipe, .scoped = @splat(0), .routing = @splat(0), .node_ids = &.{} };
    self.pinned_node_ids = &.{};
    self.pinned_identity = @splat(0);
    self.pinned_context = @splat(0);
    self.limits = limits;
    self.ready = false;
    self.guard = .{ .limit = limits.max_live_borrows };
    self.initialized = 0;
    const logical = try a.dupe(@TypeOf(full.plan.logical_owner[0]), full.plan.logical_owner);
    const mappings = try a.dupe(Coverage.Mapping, full.plan.mappings_owner);
    const physical = try a.dupe(Coverage.Physical, full.plan.physical_owner);
    const topology = try a.dupe(Coverage.Node, full.plan.nodes_owner);
    var meta = full.plan.meta;
    meta.logical = logical;
    meta.mappings = mappings;
    meta.physical = physical;
    meta.nodes = topology[0..full.plan.meta.nodes.len];
    self.coverage = .{ .a = a, .meta = meta, .logical_owner = logical, .mappings_owner = mappings, .physical_owner = physical, .nodes_owner = topology, .pinned_digest = pins.coverage };
    const expected = try clone([]const Full.Expected, a, full.expected);
    const children = try a.alloc(Original.Child, expected.len);
    var normalized: usize = 0;
    errdefer for (children[0..normalized]) |*child| child.deinit();
    for (expected, children, 0..) |policy, *child, index| {
        child.* = try policy.normalize(a, &self.coverage, @intCast(index));
        normalized += 1;
        if (child.span) |span| if (!std.meta.eql(span.job_id, pins.job)) return error.UntrustedScopedOwnerJob;
    }
    self.full = .{ .plan = &self.coverage, .children = children, .expected = expected };
    self.scoped = try Scoped.ForRecipe(recipe).init(a, self.full, limits.scoped);
    errdefer self.scoped.deinit();
    self.cohorts = try Cohorts.init(a, &self.scoped, limits.cohorts);
    errdefer self.cohorts.deinit();
    self.routes = try Routes.init(a, &self.scoped, &self.cohorts, limits.routes);
    errdefer self.routes.deinit();
    self.pins.scoped = self.scoped.digest;
    self.pins.routing = self.routes.digest;
    self.pinned_context = self.pins.contextIdentity();
    self.leaves = try a.alloc(Source.Source, children.len);
    const leaf_pins = try a.alloc([32]u8, children.len);
    self.leaf_pins = leaf_pins;
    var leaf_count: usize = 0;
    var cells: usize = 0;
    errdefer for (self.leaves[0..leaf_count]) |*leaf| leaf.deinit();
    for (self.leaves, leaf_pins, children, 0..) |*leaf, *pin, *child, index| {
        leaf.* = try Source.fromLeaf(a, child, @intCast(index), self.routes.digest);
        leaf_count += 1;
        pin.* = leaf.seal;
        cells = try std.math.add(usize, cells, leaf.cells.len);
        if (cells > limits.max_policy_source_cells) return error.ScopedOwnerResourceLimit;
    }
    self.nodes = try a.alloc(Node, self.cohorts.nodes.len);
    if (self.nodes.len > limits.cohorts.max_nodes) return error.ScopedOwnerResourceLimit;
    return .{ .owned = self };
}
fn finishSetup(self: *Owner, pins: Pins, specs: []const NodeSpec) !*Owner {
    if (self.ready or self.initialized != 0 or pins.node_ids.len != specs.len or specs.len != self.nodes.len) return error.UntrustedScopedOwnerPins;
    if (!std.meta.eql(pins.contextIdentity(), self.pinned_context)) return error.UntrustedScopedOwnerPins;
    const a = self.arena.allocator();
    self.pins = pins;
    self.pins.node_ids = try a.dupe([32]u8, pins.node_ids);
    self.pinned_node_ids = try a.dupe([32]u8, pins.node_ids);
    self.pinned_identity = pins.identity();
    var cells: usize = 0;
    for (self.leaves) |leaf| cells = try std.math.add(usize, cells, leaf.cells.len);

    for (self.nodes, specs, 0..) |*node, spec, index| {
        if (spec.children.len != self.cohorts.nodes[index].child_count or spec.outputs.len != self.routes.nodes[index].exports.len or spec.wires.len == 0 or spec.wires.len > Source.MAX_CELLS) return error.ScopedOwnerResourceLimit;
        _ = try Bus.scheduleDigest(spec.wires);
        node.spec = try clone(NodeSpec, a, spec);
        node.local_pin = try self.localIdentity(@intCast(index));
        const authority = try self.admission(@intCast(index));
        try authority.validate();
        node.source = try authority.source(a);
        self.initialized += 1;
        if (!std.meta.eql(node.source.seal, spec.source_seal) or !std.meta.eql(node.source.public_input_digest, spec.public_input)) return error.UntrustedScopedOwnedSource;
        cells = try std.math.add(usize, cells, node.source.cells.len);
        if (cells > self.limits.max_policy_source_cells) return error.ScopedOwnerResourceLimit;
    }
    self.ready = true;
    return self;
}
pub fn init(backing: std.mem.Allocator, full: Full.Policy, pins: Pins, specs: []const NodeSpec, limits: Limits) !*Owner {
    var setup = try prepareJob(backing, full, .{ .job = pins.job, .coverage = pins.coverage, .source = pins.source, .recipe = pins.recipe }, limits);
    defer setup.deinit();
    return setup.finish(pins, specs);
}
/// Same B5ZC kernel for independently derived late-bound setup. The caller
/// must derive `pin` from prepareJob().derivedPins(), never a received digest.
pub fn bindIndependentContext(context: *Context, pin: [32]u8) void {
    bindPinnedContext(context, pin);
}
// Filled in this file so a node cannot be minted through a serialized token or
// a user-supplied skip switch. Every method follows the same original protocol.
pub const Values = struct {
    owner: *const Owner,
    index: u32,
    /// Stack child views are supplied by a genuine caller for the duration of
    /// one use. If omitted, the owner's own immutable sources are selected.
    children: ?[]const Source.Source = null,
    pub fn original(self: Values, storage: *[4]Source.Source) !Bus.Values {
        if (self.index >= self.owner.nodes.len) return error.InvalidScopedOwnedNode;
        const cohort = self.owner.cohorts.nodes[self.index];
        const spec = self.owner.nodes[self.index].spec;
        const selected = if (self.children) |children| children else block: {
            for (cohort.children[0..cohort.child_count], 0..) |ref, slot| storage[slot] = switch (ref) {
                .leaf => |ordinal| if (ordinal < self.owner.leaves.len) self.owner.leaves[ordinal] else return error.InvalidScopedOwnedNode,
                .node => |ordinal| if (ordinal < self.owner.initialized) self.owner.nodes[ordinal].source else return error.ScopedOwnerLifetime,
            };
            break :block storage[0..cohort.child_count];
        };
        return .{ .routes = &self.owner.routes, .index = self.index, .children = selected, .pins = spec.children, .outputs = spec.outputs };
    }
    pub fn validate(self: Values) !void {
        try self.owner.validateNode(self.index);
        if (self.children) |children| {
            const cohort = self.owner.cohorts.nodes[self.index];
            if (children.len != cohort.child_count) return error.InvalidScopedPublicCensus;
            for (children, cohort.children[0..cohort.child_count]) |*child, ref| {
                const expected = try self.owner.source(ref);
                try child.validate();
                if (!std.meta.eql(child.ref, ref) or !std.meta.eql(child.seal, expected.seal)) return error.UntrustedScopedPublicSource;
            }
        }
    }
    pub fn at(self: Values, wire: Bus.Wire) ![4]M {
        var storage: [4]Source.Source = undefined;
        return (try self.original(&storage)).at(wire);
    }
    pub fn mix(self: Values, channel: anytype) void {
        // No allocation/error exists after local admission; original policy
        // framing is preserved byte-for-byte and contains no descendant mix.
        var storage: [4]Source.Source = undefined;
        const values = self.original(&storage) catch unreachable;
        values.mix(channel);
    }
    // Source.fromNode's structural policy fields are provided through Adapter
    // below rather than a fabricated original receipt.
};
pub const Admission = struct {
    pub const CLAIM_TAG = Protocol.Admission.CLAIM_TAG;
    key: Key,
    expected_id: [32]u8,
    wires: []const Bus.Wire,
    values: Values,
    expected_public: [32]u8,
    pub fn source(self: *const Admission, a: std.mem.Allocator) !Source.Source {
        try self.validate();
        var storage: [4]Source.Source = undefined;
        const adapter = SourceAdapter{ .authority = self, .key = self.key, .expected_id = self.expected_id, .wires = self.wires, .values = try self.values.original(&storage) };
        return Source.fromNode(a, adapter);
    }
    pub fn validate(self: *const Admission) !void {
        try self.values.validate();
        const spec = self.values.owner.nodes[self.values.index].spec;
        if (!std.meta.eql(self.key, spec.key) or !std.meta.eql(self.expected_id, spec.expected_id) or !sameWires(self.wires, spec.wires) or !std.meta.eql(self.expected_public, spec.public_input)) return error.UntrustedReusableScopedOwnerKey;
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
    pub fn admitRoot(self: *const Admission, root: [32]u8) !void {
        try self.validate();
        if (!std.meta.eql(root, self.key.preprocessed_root)) return error.UntrustedBlake3ParentRoot;
    }
    pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
        try self.validate();
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42355a49, VERSION });
        channel.mixRoot(self.expected_id);
        self.values.mix(&channel);
        if (!std.meta.eql(channel.digestBytes(), self.expected_public)) return error.UntrustedScopedOwnerPublicInput;
        return channel.digestBytes();
    }
    pub fn mix(self: *const Admission, channel: anytype) !void {
        try self.validate();
        channel.mixU32s(&.{ 0x42355a50, VERSION, @intFromEnum(self.key.profile) });
        self.key.config.mixInto(channel);
        channel.mixRoot(self.expected_id);
        self.values.mix(channel);
    }
    pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const Q) !void {
        try self.validate();
        if (claims.len != @import("blake3_native_parent_artifact.zig").CLAIM_COUNT) return error.InvalidBlake3ParentClaims;
        channel.mixU32s(&.{ CLAIM_TAG, VERSION, @import("blake3_native_parent_artifact.zig").CLAIM_COUNT });
        channel.mixFelts(claims);
    }
    pub fn validateClaimsForRelations(self: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
        try self.validate();
        const relation = try relations.getExact(.recursion_wire);
        var sum = Q.zero();
        for (self.wires) |wire| {
            const denominator = try relation.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try self.values.at(wire)));
            if (denominator.isZero()) return error.RecursivePublicDenominatorZero;
            const term = Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv());
            sum = if (wire.negative) sum.sub(term) else sum.add(term);
        }
        for (claims) |claim| {
            for (claim.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidBlake3ParentClaims;
            sum = sum.add(claim);
        }
        if (!sum.isZero()) return error.InvalidReusableScopedParentPublicClosure;
    }
};
fn sameWires(left: []const Bus.Wire, right: []const Bus.Wire) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}
pub const testing = struct {
    pub const localFingerprint = fingerprintLocal;
    pub const requireLocalFingerprint = requireFingerprint;
    pub const cloneOwned = clone;
    pub const bindSetupContext = bindPinnedContext;
};

const SourceAdapter = struct {
    pub const CLAIM_TAG = Admission.CLAIM_TAG;
    authority: *const Admission,
    key: Key,
    expected_id: [32]u8,
    wires: []const Bus.Wire,
    values: Bus.Values,
    pub fn validate(self: *const @This()) !void {
        try self.authority.validate();
    }
    pub fn mix(self: *const @This(), channel: anytype) !void {
        try self.authority.mix(channel);
    }
    pub fn publicInputIdentity(self: *const @This()) ![32]u8 {
        return self.authority.publicInputIdentity();
    }
};

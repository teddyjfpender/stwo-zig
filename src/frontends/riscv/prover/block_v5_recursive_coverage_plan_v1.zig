//! Heterogeneous recursive coverage *planning*. This never verifies a proof,
//! loads a source file, issues an open equation, or attests block closure.
//! Independent policy supplies the exact roster; transported metadata is only
//! a candidate compared with that policy. Provider nodes have no PC span.
const std = @import("std");
const core = @import("stwo_core");
const Seal = @import("block_v5_source_seal_v1.zig");
const Recipes = @import("block_v5_execution_recipe_v1.zig");
pub const VERSION: u32 = 1;
comptime {
    if (Seal.family_count != 14 or @import("../air/lookups/tables/schema.zig").KIND_COUNT != 6) @compileError("coverage v1 requires the exact fourteen-family/six-table schema");
}
pub const NativeProtocol = enum(u32) { native_v3 = 1, capacity_v1 = 2 };
pub const MemoryProtocol = enum(u32) { ram_lanes_v1 = 1, legacy_word = 2 };
pub const FanIn = enum(u32) { pair = 2, quartet = 4 };
pub const Kind = enum(u32) { native_arithmetic, native_fused, caller_arithmetic, caller_fused, ram_lanes, range16, rom, native_lookup };
pub const KIND_COUNT = std.meta.fields(Kind).len;
pub const Subtype = enum(u32) { native_v3, capacity_v1, native_fused_v2, capacity_fused_v1, caller_family11_v1, caller_fused_v1, ram_lanes_v1, range16_v1, rom_v1, six_table_lookup_v1 };
/// Source graph availability only; not proof qualification or acceptance.
pub const Adapter = enum { existing_typed_adapter, missing_typed_adapter };
/// Compatibility for callers with only a broad kind. Fusion remains
/// conservative because NativeV3 and capacity fusion are different protocols.
/// Physical availability must use the independently pinned typed subtype.
pub fn adapter(kind: Kind) Adapter {
    return switch (kind) {
        .native_arithmetic, .caller_arithmetic, .caller_fused, .ram_lanes, .range16, .rom, .native_lookup => .existing_typed_adapter,
        .native_fused => .missing_typed_adapter,
    };
}
/// Source-graph availability ONLY: the original typed verifier is still
/// mandatory, and no source/global closure or successful proof is asserted.
pub fn adapterForSubtype(selected: Subtype) Adapter {
    return switch (selected) {
        .native_v3,
        .capacity_v1,
        .capacity_fused_v1,
        .caller_family11_v1,
        .caller_fused_v1,
        .ram_lanes_v1,
        .range16_v1,
        .rom_v1,
        .six_table_lookup_v1,
        => .existing_typed_adapter,
        .native_fused_v2 => .missing_typed_adapter,
    };
}
pub const Security = struct {
    base: core.pcs.PcsConfig,
    recursive: core.pcs.PcsConfig,
    pub fn require(self: Security, config: core.pcs.PcsConfig) !void {
        try @import("blake3_execution_protocol.zig").validateConfig(config);
        // Current independent receivers select precisely matching setups.
        // Relaxation would require an explicit proved security policy version.
        if (!std.meta.eql(self.base, config) or !std.meta.eql(self.recursive, config) or config.fri_config.n_queries == 0)
            return error.UntrustedV5CoverageSecurity;
    }
};
pub const NativePresence = struct { projection_slots: u32, ram_slots: u32, ram_events: u64 };
pub const SourceKind = enum(u32) { sealed_roster, native_catalog, program_plan, lookup_demand_roster, ram_plan, register_windows, initial_image, public_input, first_touches, final_image };
pub const SOURCE_COUNT = std.meta.fields(SourceKind).len;
/// No source proof currently exists for these descriptors. Their identity and
/// exact count pin a future obligation; SHA/file custody is not a receipt.
pub const SourceRequirement = struct { kind: SourceKind, identity: [32]u8, count: u64 };
pub const Inventory = struct {
    seal: Seal.Pins,
    entries: []const Seal.Entry,
    expected_seal_digest: [32]u8,
    recipe: Recipes.Recipe,
    native_protocol: NativeProtocol,
    memory_protocol: MemoryProtocol,
    native: []const NativePresence,
    callers: []const u32, // Actual execution ordinals, never compact caller IDs.
    caller_ram_events: []const u64,
    ram_events: u64,
    program_fetches: u64,
    register_window_version: u32,
    sources: [SOURCE_COUNT]SourceRequirement,
};
pub const Limits = struct {
    max_logical: usize = 32768,
    max_physical: usize = 32768,
    max_executions: usize = 8192,
    max_nodes: usize = 32768,
    max_owned_bytes: usize = 64 << 20,
    pub fn requireInput(self: Limits, logical: usize, executions: usize) !void {
        if (self.max_physical == 0) return error.V5CoverageResourceLimit;
        var conservative = self;
        conservative.max_physical = std.math.maxInt(usize);
        conservative.max_nodes = std.math.maxInt(usize);
        try conservative.require(logical, logical, executions);
    }
    pub fn require(self: Limits, logical: usize, physical: usize, executions: usize) !void {
        if (logical > self.max_logical or physical == 0 or physical > self.max_physical or executions == 0 or executions > self.max_executions or physical - 1 > self.max_nodes or
            logical > std.math.maxInt(u32) or physical > std.math.maxInt(u32)) return error.V5CoverageResourceLimit;
        var bytes = try std.math.mul(usize, logical, @sizeOf(Seal.Entry) + @sizeOf(Mapping));
        bytes = try std.math.add(usize, bytes, try std.math.mul(usize, physical, @sizeOf(Physical) + 2 * @sizeOf(Ref)));
        bytes = try std.math.add(usize, bytes, try std.math.mul(usize, physical - 1, @sizeOf(Node)));
        // ForStack's temporary inventory + demand + provider-plan vectors are
        // concurrent with these owners; bound them before their allocation.
        bytes = try std.math.add(usize, bytes, try std.math.mul(usize, executions, @sizeOf(NativePresence) + 7 * @sizeOf(u64) + @sizeOf(@import("block_v5_native_lookup_plan_v1.zig").Plan) + @sizeOf(u32)));
        if (bytes > self.max_owned_bytes) return error.V5CoverageResourceLimit;
    }
};
pub const Mapping = union(enum) { unassigned, physical: u32, native_typed_absence: u32 };
pub const Physical = struct {
    kind: Kind,
    subtype: Subtype,
    index: u32,
    // One physical verifier covers one or two precise logical B5SS entries.
    logical: [2]u32,
    logical_count: u32,
    instance_id: [32]u8,
    roots: Seal.Roots,
};
pub const Ref = union(enum) { leaf: u32, node: u32 };
pub const Node = struct {
    children: [4]Ref,
    child_count: u32,
    first_leaf: u32,
    leaf_count: u32,
    schema_counts: [KIND_COUNT]u32,
};
pub const Metadata = struct {
    version: u32,
    recipe: Recipes.Recipe,
    native_protocol: NativeProtocol,
    security: Security,
    seal_digest: [32]u8,
    ram_events: u64,
    program_fetches: u64,
    register_window_version: u32,
    fan_in: FanIn,
    logical: []const Seal.Entry,
    mappings: []const Mapping,
    physical: []const Physical,
    sources: [SOURCE_COUNT]SourceRequirement,
    nodes: []const Node,
    root: Ref,
};
pub const Plan = struct {
    a: std.mem.Allocator,
    meta: Metadata,
    logical_owner: []Seal.Entry,
    mappings_owner: []Mapping,
    physical_owner: []Physical,
    nodes_owner: []Node,
    pinned_digest: [32]u8,
    pub fn deinit(self: *Plan) void {
        self.a.free(self.nodes_owner);
        self.a.free(self.physical_owner);
        self.a.free(self.mappings_owner);
        self.a.free(self.logical_owner);
        self.* = undefined;
    }
    /// Comparison to independently reconstructed expected metadata, not a
    /// verifier. Neither successful comparison nor digest is an open equation.
    pub fn requireExact(self: *const Plan, candidate: Metadata) !void {
        try self.meta.security.require(self.meta.security.base);
        if (self.meta.logical.len != self.logical_owner.len or self.meta.mappings.len != self.mappings_owner.len or self.meta.physical.len != self.physical_owner.len or self.meta.nodes.len > self.nodes_owner.len or !std.meta.eql(self.pinned_digest, self.identity())) return error.MutatedV5CoverageIndependentPolicy;
        if (candidate.version != VERSION or candidate.recipe != self.meta.recipe or candidate.native_protocol != self.meta.native_protocol or
            !std.meta.eql(candidate.security, self.meta.security) or !std.meta.eql(candidate.seal_digest, self.meta.seal_digest) or candidate.fan_in != self.meta.fan_in or candidate.ram_events != self.meta.ram_events or candidate.program_fetches != self.meta.program_fetches or candidate.register_window_version != self.meta.register_window_version or
            !std.meta.eql(candidate.sources, self.meta.sources) or !std.meta.eql(candidate.root, self.meta.root) or
            candidate.logical.len != self.meta.logical.len or candidate.mappings.len != self.meta.mappings.len or candidate.physical.len != self.meta.physical.len or candidate.nodes.len != self.meta.nodes.len)
            return error.UntrustedV5CoverageMetadata;
        for (candidate.logical, self.meta.logical) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedV5CoverageMetadata;
        for (candidate.mappings, self.meta.mappings) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedV5CoverageMetadata;
        for (candidate.physical, self.meta.physical) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedV5CoverageMetadata;
        for (candidate.nodes, self.meta.nodes) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedV5CoverageMetadata;
    }
    /// Descriptor commitment for a future independently pinned BlockStatement.
    /// Hashing coverage is transport/policy binding, not proof of coverage.
    pub fn identity(self: *const Plan) [32]u8 {
        var channel = core.proof_suites.Blake3.Channel{};
        const m = self.meta;
        channel.mixU32s(&.{ 0x42354356, m.version, @intFromEnum(m.recipe), @intFromEnum(m.native_protocol), @intFromEnum(m.fan_in), m.register_window_version });
        m.security.base.mixInto(&channel);
        m.security.recursive.mixInto(&channel);
        channel.mixRoot(m.seal_digest);
        channel.mixU64(m.ram_events);
        channel.mixU64(m.program_fetches);
        channel.mixU64(m.logical.len);
        for (m.logical, m.mappings) |entry, mapping| {
            channel.mixU32s(&.{ @intFromEnum(entry.family), entry.index });
            channel.mixRoot(entry.instance_id);
            for (entry.roots) |root| channel.mixRoot(root);
            channel.mixU32s(&.{@intFromEnum(std.meta.activeTag(mapping))});
            switch (mapping) {
                .unassigned => {},
                .physical, .native_typed_absence => |index| channel.mixU32s(&.{index}),
            }
        }
        channel.mixU64(m.physical.len);
        for (m.physical) |proof| {
            channel.mixU32s(&.{ @intFromEnum(proof.kind), @intFromEnum(proof.subtype), proof.index, proof.logical_count, proof.logical[0], proof.logical[1] });
            channel.mixRoot(proof.instance_id);
            for (proof.roots) |root| channel.mixRoot(root);
        }
        for (m.sources) |source| {
            channel.mixU32s(&.{@intFromEnum(source.kind)});
            channel.mixRoot(source.identity);
            channel.mixU64(source.count);
        }
        channel.mixU64(m.nodes.len);
        for (m.nodes) |node| {
            channel.mixU32s(&.{ node.child_count, node.first_leaf, node.leaf_count });
            for (node.children) |child| mixRef(&channel, child);
            channel.mixU32s(&node.schema_counts);
        }
        mixRef(&channel, m.root);
        return channel.digestBytes();
    }
    pub fn pendingAdapters(self: *const Plan) struct { physical: usize, sources: usize } {
        var missing: usize = 0;
        for (self.meta.physical) |proof| if (adapterForSubtype(proof.subtype) == .missing_typed_adapter) {
            missing += 1;
        };
        return .{ .physical = missing, .sources = SOURCE_COUNT };
    }
};
const Roster = struct {
    entries: []const Seal.Entry,
    offsets: [Seal.family_count + 1]usize,
    fn init(entries: []const Seal.Entry, counts: [Seal.family_count]u32) !Roster {
        var out = Roster{ .entries = entries, .offsets = undefined };
        out.offsets[0] = 0;
        for (counts, 0..) |family_count, i| out.offsets[i + 1] = try std.math.add(usize, out.offsets[i], family_count);
        if (out.offsets[Seal.family_count] != entries.len) return error.InvalidV5CoverageRoster;
        return out;
    }
    fn ordinal(self: Roster, family: Seal.Family, index: u32) !u32 {
        const f = @intFromEnum(family) - 1;
        var lo = self.offsets[f];
        var hi = self.offsets[f + 1];
        while (lo < hi) {
            const middle = lo + (hi - lo) / 2;
            if (self.entries[middle].index < index) lo = middle + 1 else hi = middle;
        }
        if (lo == self.offsets[f + 1] or self.entries[lo].family != family or self.entries[lo].index != index) return error.MissingV5CoverageObligation;
        return @intCast(lo);
    }
};
fn count(pins: Seal.Pins, family: Seal.Family) u32 {
    return pins.counts[@intFromEnum(family) - 1];
}
fn subtype(kind: Kind, native: NativeProtocol) Subtype {
    return switch (kind) {
        .native_arithmetic => if (native == .capacity_v1) .capacity_v1 else .native_v3,
        .native_fused => if (native == .capacity_v1) .capacity_fused_v1 else .native_fused_v2,
        .caller_arithmetic => .caller_family11_v1,
        .caller_fused => .caller_fused_v1,
        .ram_lanes => .ram_lanes_v1,
        .range16 => .range16_v1,
        .rom => .rom_v1,
        .native_lookup => .six_table_lookup_v1,
    };
}
fn appendPhysical(physical: []Physical, used: *usize, mappings: []Mapping, roster: Roster, kind: Kind, protocol: NativeProtocol, index: u32, primary: Seal.Family, secondary: ?Seal.Family) !void {
    const ordinal = try roster.ordinal(primary, index);
    const second = if (secondary) |family| try roster.ordinal(family, index) else ordinal;
    if (used.* >= physical.len or mappings[ordinal] != .unassigned or (secondary != null and mappings[second] != .unassigned)) return error.DuplicateV5CoverageObligation;
    physical[used.*] = .{ .kind = kind, .subtype = subtype(kind, protocol), .index = index, .logical = .{ ordinal, second }, .logical_count = if (secondary == null) 1 else 2, .instance_id = roster.entries[ordinal].instance_id, .roots = roster.entries[ordinal].roots };
    mappings[ordinal] = .{ .physical = @intCast(used.*) };
    if (secondary != null) mappings[second] = .{ .physical = @intCast(used.*) };
    used.* += 1;
}
fn bounds(ref: Ref, nodes: []const Node) struct { first: u32, count: u32 } {
    return switch (ref) {
        .leaf => |i| .{ .first = i, .count = 1 },
        .node => |i| .{ .first = nodes[i].first_leaf, .count = nodes[i].leaf_count },
    };
}
fn topology(a: std.mem.Allocator, proofs: []const Physical, storage: []Node, fan_in: FanIn) !struct { count: usize, root: Ref } {
    var current = try a.alloc(Ref, proofs.len);
    defer a.free(current);
    var next = try a.alloc(Ref, proofs.len);
    defer a.free(next);
    for (current, 0..) |*ref, index| ref.* = .{ .leaf = @intCast(index) };
    var live = proofs.len;
    var used: usize = 0;
    while (live > 1) {
        var at: usize = 0;
        var emitted: usize = 0;
        while (at < live) {
            const take: usize = @min(@as(usize, @intFromEnum(fan_in)), live - at);
            if (take == 1) {
                next[emitted] = current[at];
            } else {
                if (used >= storage.len) return error.V5CoverageResourceLimit;
                const first = bounds(current[at], storage[0..used]);
                var node = Node{ .children = @splat(current[at]), .child_count = @intCast(take), .first_leaf = first.first, .leaf_count = 0, .schema_counts = @splat(0) };
                for (current[at..][0..take], 0..) |child, j| {
                    const b = bounds(child, storage[0..used]);
                    if (b.first != node.first_leaf + node.leaf_count) return error.NonadjacentV5CoverageTopology;
                    node.children[j] = child;
                    node.leaf_count = try std.math.add(u32, node.leaf_count, b.count);
                    switch (child) {
                        .leaf => |i| node.schema_counts[@intFromEnum(proofs[i].kind)] += 1,
                        .node => |i| for (&node.schema_counts, storage[i].schema_counts) |*sum, value| {
                            sum.* = try std.math.add(u32, sum.*, value);
                        },
                    }
                }
                storage[used] = node;
                next[emitted] = .{ .node = @intCast(used) };
                used += 1;
            }
            at += take;
            emitted += 1;
        }
        std.mem.swap([]Ref, &current, &next);
        live = emitted;
    }
    return .{ .count = used, .root = current[0] };
}
/// Low-level planning admission for independently supplied *metadata*. For
/// production, ForStack.prepare derives every inventory from real Global.Pins.
/// This API deliberately returns no verification token and loads no artifacts.
pub fn prepareMetadata(a: std.mem.Allocator, inventory: Inventory, security: Security, fan_in: FanIn, limits: Limits) !Plan {
    // Conservative bound before seal traversal or any owned allocation.
    try limits.requireInput(inventory.entries.len, inventory.native.len);
    try security.require(inventory.seal.config);
    try inventory.recipe.requireCompiled();
    try inventory.recipe.requireMode(inventory.seal.register_custody_mode);
    try inventory.recipe.requireWindowVersion(inventory.register_window_version);
    if (inventory.seal.register_custody_mode != 1 or inventory.memory_protocol != .ram_lanes_v1) return error.UnsupportedV5CoverageMemoryProtocol;
    // These legacy/provider families have no supported canonical subtype.
    for ([_]Seal.Family{ .initial_register, .initial_input, .initial_rw, .hash }) |family| if (count(inventory.seal, family) != 0) return error.UnsupportedV5CoverageFamily;
    const sealed = try Seal.seal(inventory.seal, inventory.entries);
    try sealed.requireComplete(inventory.seal, inventory.entries);
    if (!std.meta.eql(sealed.digest, inventory.expected_seal_digest) or inventory.native.len != sealed.execution_instance_count or inventory.callers.len != count(inventory.seal, .precompile) or inventory.caller_ram_events.len != inventory.callers.len) return error.InvalidV5CoverageInventory;
    for (inventory.callers, 0..) |index, ordinal| if (index >= inventory.native.len or (ordinal != 0 and index <= inventory.callers[ordinal - 1])) return error.InvalidV5CoverageCallerRoster;
    var all_events: u64 = 0;
    var fused_count: usize = 0;
    for (inventory.native) |presence| {
        if ((presence.projection_slots == 0 and presence.ram_slots != 0) or (presence.ram_slots == 0 and presence.ram_events != 0)) return error.InvalidV5CoverageTypedAbsence;
        fused_count += @intFromBool(presence.projection_slots != 0);
        all_events = try std.math.add(u64, all_events, presence.ram_events);
    }
    for (inventory.caller_ram_events) |events| all_events = try std.math.add(u64, all_events, events);
    if (all_events != inventory.ram_events) return error.InvalidV5CoverageInventory;
    const memory_count = count(inventory.seal, .memory);
    const range_count = count(inventory.seal, .memory_range);
    if ((memory_count == 0) != (inventory.ram_events == 0) or (memory_count == 0 and range_count != 0)) return error.InvalidV5CoverageTypedAbsence;
    if (count(inventory.seal, .native_lookup) == 0 or (memory_count == 0) != (range_count == 0)) return error.InvalidV5CoverageProviderRoster;
    for (inventory.sources, 0..) |source, index| if (@intFromEnum(source.kind) != index or std.mem.allEqual(u8, &source.identity, 0)) return error.UntrustedV5CoverageSourceRequirement;
    const expected_catalog = if (std.mem.allEqual(u8, &sealed.native_template_catalog_digest, 0)) inventory.seal.native_template_id else sealed.native_template_catalog_digest;
    const identities = [_]struct { kind: SourceKind, digest: [32]u8 }{
        .{ .kind = .sealed_roster, .digest = sealed.digest },
        .{ .kind = .native_catalog, .digest = expected_catalog },
        .{ .kind = .program_plan, .digest = sealed.program_plan_digest },
        .{ .kind = .ram_plan, .digest = inventory.seal.memory_plan_digest },
        .{ .kind = .register_windows, .digest = sealed.register_endpoint_plan_digest },
        .{ .kind = .initial_image, .digest = sealed.initial_source_plan_digest },
        .{ .kind = .final_image, .digest = sealed.rw_endpoint_plan_digest },
    };
    for (identities) |item| if (!std.meta.eql(inventory.sources[@intFromEnum(item.kind)].identity, item.digest)) return error.UntrustedV5CoverageSourceRequirement;
    var demand_channel = core.proof_suites.Blake3.Channel{};
    demand_channel.mixU32s(&.{ 0x42354344, VERSION });
    for (inventory.entries) |entry| if (entry.family == .native_lookup) demand_channel.mixRoot(entry.instance_id);
    if (!std.meta.eql(inventory.sources[@intFromEnum(SourceKind.lookup_demand_roster)].identity, demand_channel.digestBytes()) or
        inventory.sources[@intFromEnum(SourceKind.lookup_demand_roster)].count != count(inventory.seal, .native_lookup) or
        inventory.sources[@intFromEnum(SourceKind.sealed_roster)].count != inventory.entries.len or
        inventory.sources[@intFromEnum(SourceKind.native_catalog)].count != inventory.native.len or
        inventory.sources[@intFromEnum(SourceKind.register_windows)].count != inventory.native.len or
        inventory.sources[@intFromEnum(SourceKind.ram_plan)].count != inventory.ram_events or
        inventory.sources[@intFromEnum(SourceKind.program_plan)].count != inventory.program_fetches or inventory.program_fetches >= core.fields.m31.Modulus or
        inventory.sources[@intFromEnum(SourceKind.first_touches)].count > inventory.ram_events or
        inventory.sources[@intFromEnum(SourceKind.final_image)].count > inventory.sources[@intFromEnum(SourceKind.first_touches)].count)
        return error.UntrustedV5CoverageSourceRequirement;
    var physical_count = try std.math.add(usize, inventory.native.len, fused_count);
    physical_count = try std.math.add(usize, physical_count, try std.math.mul(usize, inventory.callers.len, 2));
    for ([_]Seal.Family{ .memory, .memory_range, .native_lookup, .program }) |family| physical_count = try std.math.add(usize, physical_count, count(inventory.seal, family));
    try limits.require(inventory.entries.len, physical_count, inventory.native.len);
    const logical = try a.dupe(Seal.Entry, inventory.entries);
    errdefer a.free(logical);
    const mappings = try a.alloc(Mapping, logical.len);
    errdefer a.free(mappings);
    @memset(mappings, .unassigned);
    const physical = try a.alloc(Physical, physical_count);
    errdefer a.free(physical);
    const nodes = try a.alloc(Node, physical_count - 1);
    errdefer a.free(nodes);
    const roster = try Roster.init(logical, inventory.seal.counts);
    var used: usize = 0;
    for (inventory.native, 0..) |_, index| try appendPhysical(physical, &used, mappings, roster, .native_arithmetic, inventory.native_protocol, @intCast(index), .execution, null);
    for (inventory.native, 0..) |presence, index| {
        if (presence.projection_slots != 0) {
            try appendPhysical(physical, &used, mappings, roster, .native_fused, inventory.native_protocol, @intCast(index), .program_request, .execution_sidecar);
        } else for ([_]Seal.Family{ .program_request, .execution_sidecar }) |family| {
            const ordinal = try roster.ordinal(family, @intCast(index));
            if (mappings[ordinal] != .unassigned) return error.DuplicateV5CoverageObligation;
            mappings[ordinal] = .{ .native_typed_absence = @intCast(index) };
        }
    }
    for (inventory.callers) |index| try appendPhysical(physical, &used, mappings, roster, .caller_arithmetic, inventory.native_protocol, index, .precompile, null);
    for (inventory.callers) |index| try appendPhysical(physical, &used, mappings, roster, .caller_fused, inventory.native_protocol, index, .program_extension_request, .execution_external_sidecar);
    for (0..memory_count) |index| try appendPhysical(physical, &used, mappings, roster, .ram_lanes, inventory.native_protocol, @intCast(index), .memory, null);
    for (0..range_count) |index| try appendPhysical(physical, &used, mappings, roster, .range16, inventory.native_protocol, @intCast(index), .memory_range, null);
    try appendPhysical(physical, &used, mappings, roster, .rom, inventory.native_protocol, 0, .program, null);
    for (0..count(inventory.seal, .native_lookup)) |index| try appendPhysical(physical, &used, mappings, roster, .native_lookup, inventory.native_protocol, @intCast(index), .native_lookup, null);
    if (used != physical.len) return error.InvalidV5CoverageInventory;
    for (mappings) |mapping| if (mapping == .unassigned) return error.MissingV5CoverageObligation;
    const tree = try topology(a, physical, nodes, fan_in);
    var result = Plan{ .a = a, .pinned_digest = undefined, .logical_owner = logical, .mappings_owner = mappings, .physical_owner = physical, .nodes_owner = nodes, .meta = .{ .version = VERSION, .recipe = inventory.recipe, .native_protocol = inventory.native_protocol, .security = security, .seal_digest = sealed.digest, .ram_events = inventory.ram_events, .program_fetches = inventory.program_fetches, .register_window_version = inventory.register_window_version, .fan_in = fan_in, .logical = logical, .mappings = mappings, .physical = physical, .sources = inventory.sources, .nodes = nodes[0..tree.count], .root = tree.root } };
    result.pinned_digest = result.identity();
    return result;
}

/// Typed canonical policy derivation. Uses real base admits, inventories,
/// source/range plans and integer demand bounds, never claims or a fake receipt.
pub fn ForStack(comptime Stack: type) type {
    return struct {
        const Global = @import("block_v5_global_receiver_impl_v1.zig").ForStack(Stack);
        const Programs = Stack.Programs;
        const FusedSource = Stack.FusedSource;
        pub fn prepare(a: std.mem.Allocator, pins: Global.Pins, security: Security, fan_in: FanIn, limits: Limits) !Plan {
            try limits.requireInput(pins.tables.roster.len, pins.tables.executions.len);
            if (pins.tables.providers.len != count(pins.tables.seal, .native_lookup) or pins.tables.providers.len > pins.tables.roster.len) return error.InvalidV5CoverageProviderRoster;
            try security.require(pins.tables.seal.config);
            const sealed = try pins.validate();
            if (sealed.register_custody_mode != 1) return error.UnsupportedV5CoverageMemoryProtocol;
            const lane_pins = switch (pins.memory.memory) {
                .lanes => |value| value,
                .word => return error.UnsupportedV5CoverageMemoryProtocol,
            };
            try @import("block_v5_ram_lanes_receiver_v1.zig").admit(a, lane_pins, sealed, lane_pins.limits);
            const windows = pins.tables.register_windows orelse return error.MissingV5RegisterWindowPlan;
            if (windows.windows.len != pins.tables.executions.len) return error.InvalidV5CoverageInventory;
            const native = try a.alloc(NativePresence, pins.tables.executions.len);
            defer a.free(native);
            const callers = try a.alloc(u32, pins.tables.extensions.len);
            defer a.free(callers);
            const caller_events = try a.alloc(u64, callers.len);
            defer a.free(caller_events);
            const Demand = @import("block_v5_native_lookup_plan_v1.zig");
            const demands = try a.alloc([6]u64, native.len);
            defer a.free(demands);
            const provider_plans = try a.alloc(Demand.Plan, pins.tables.providers.len);
            defer a.free(provider_plans);
            const roster = try Roster.init(pins.tables.roster, pins.tables.seal.counts);
            var caller_at: usize = 0;
            var all_events: u64 = 0;
            var all_fetches: u64 = 0;
            for (pins.tables.executions, native, demands, windows.windows, 0..) |execution, *presence, *demand, window, index| {
                try windows.requireNative(execution.shape);
                try window.requirePublic(@intCast(index), execution.admission.context.first_cycle, &execution.shape.public_data);
                const external = Programs.externalRetirements(execution);
                all_fetches = try std.math.add(u64, all_fetches, external);
                for (execution.shape.component_descs[0..execution.shape.n_components]) |desc| all_fetches = try std.math.add(u64, all_fetches, desc.n_rows);
                const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = execution.admission.context.first_cycle, .cycle_count = execution.shape.public_data.clock };
                const memory_pin = Stack.FusedReceiver.MemoryPin{ .frame = frame, .expected_events = pins.memory.ordinary_events[index], .witness_root = pins.memory.opcode_witness_roots[index] };
                _ = try Stack.FusedReceiver.admit(a, @intCast(index), Programs.fusedPin(execution), memory_pin, sealed, pins.tables.seal, pins.tables.roster, pins.tables.catalog);
                const projections = try FusedSource.slotsFromShapeForMode(a, execution.shape, external, 1);
                defer a.free(projections);
                const memory = if (Stack.is_capacity) try FusedSource.memorySlots(a, execution.shape, external, frame, 1) else try @import("block_execution_sidecar_batch_v2.zig").slotsFromStatementForMode(a, execution.shape, frame, 1);
                defer a.free(memory);
                presence.* = .{ .projection_slots = std.math.cast(u32, projections.len) orelse return error.V5CoverageResourceLimit, .ram_slots = std.math.cast(u32, memory.len) orelse return error.V5CoverageResourceLimit, .ram_events = memory_pin.expected_events };
                _ = try @import("block_v5_memory_byte_demand_v1.zig").opcodeDemandFromShapeForMode(a, execution.shape, frame, memory_pin.expected_events, 1);
                demand.* = try Demand.nativeDemand(execution.shape, external);
                var events = memory_pin.expected_events;
                if (caller_at < pins.tables.extensions.len and pins.tables.extensions[caller_at].execution_index == index) {
                    const extension = pins.tables.extensions[caller_at];
                    try windows.requireCaller(extension.statement);
                    if (extension.total_steps != frame.cycle_count or external != @import("blake3_ethereum_sha_profile.zig").externalCount(extension.statement)) return error.InvalidV5CoverageCallerRoster;
                    const caller_entry = pins.tables.roster[try roster.ordinal(.precompile, @intCast(index))];
                    const execution_entry = pins.tables.roster[try roster.ordinal(.execution, @intCast(index))];
                    const rw_events = try @import("block_execution_external_trace_v2.zig").expectedEventCountForMode(extension.statement, 1);
                    try @import("block_v5_caller_fused_receiver_v1.zig").admit(a, @intCast(index), .{ .statement = extension.statement, .total_steps = extension.total_steps, .execution_instance_id = execution_entry.instance_id, .expected_key_id = extension.expected_key_id, .expected_caller_instance_id = caller_entry.instance_id, .roots = caller_entry.roots, .witness_root = pins.memory.extensions[caller_at].witness_root, .frame = frame, .expected_rw_events = rw_events }, sealed, pins.tables.seal, pins.tables.roster);
                    callers[caller_at] = @intCast(index);
                    caller_events[caller_at] = rw_events;
                    events = try std.math.add(u64, events, rw_events);
                    try @import("block_v5_precompile_table_demand_v1.zig").add(a, demand, extension.statement, extension.total_steps, pins.tables.seal.config);
                    caller_at += 1;
                } else if (external != 0) return error.InvalidV5CoverageCallerRoster;
                try Demand.addDemand(demand, try Demand.sidecarMemoryDemand(events));
                all_events = try std.math.add(u64, all_events, events);
            }
            if (caller_at != callers.len or all_events != lane_pins.expected_total_events or all_fetches != pins.program.expected_fetches) return error.InvalidV5CoverageInventory;
            for (pins.tables.providers, provider_plans) |provider, *plan| {
                plan.* = provider.plan;
                try @import("block_v5_native_lookup_proof_v1.zig").admit(provider.plan, provider.roots, sealed, pins.tables.seal, pins.tables.roster);
            }
            try Demand.validateDemandRoster(provider_plans, demands);
            const source = lane_pins.source;
            if (!std.meta.eql(try source.digest(), sealed.rw_endpoint_plan_digest) or !std.meta.eql(try source.initial.digest(), sealed.initial_source_plan_digest) or !std.meta.eql(source.expected_final_rw_root, sealed.expected_final_rw_root) or !std.meta.eql(source.initial.initial_registers, windows.initial_registers)) return error.UntrustedV5CoverageSourceRequirement;
            if (all_events == 0 and (source.initial.first_touches.records != 0 or source.endpoints.records != 0 or !std.meta.eql(source.expected_final_rw_root, source.initial.initial_rw_root))) return error.InvalidV5CoverageTypedAbsence;
            const rom = pins.tables.roster[try roster.ordinal(.program, 0)];
            if (!std.meta.eql(rom.instance_id, try @import("block_v5_program_table_proof_v1.zig").instanceId(pins.program))) return error.UntrustedV5CoverageProgramPlan;
            var demand_channel = core.proof_suites.Blake3.Channel{};
            demand_channel.mixU32s(&.{ 0x42354344, VERSION });
            for (provider_plans) |plan| demand_channel.mixRoot(try plan.identity());
            const catalog_digest = try pins.tables.catalog.digest();
            const sources = [SOURCE_COUNT]SourceRequirement{
                .{ .kind = .sealed_roster, .identity = sealed.digest, .count = pins.tables.roster.len },
                .{ .kind = .native_catalog, .identity = if (std.mem.allEqual(u8, &catalog_digest, 0)) pins.tables.seal.native_template_id else catalog_digest, .count = native.len },
                .{ .kind = .program_plan, .identity = sealed.program_plan_digest, .count = pins.program.expected_fetches },
                .{ .kind = .lookup_demand_roster, .identity = demand_channel.digestBytes(), .count = provider_plans.len },
                .{ .kind = .ram_plan, .identity = pins.tables.seal.memory_plan_digest, .count = all_events },
                .{ .kind = .register_windows, .identity = try windows.digest(), .count = windows.windows.len },
                .{ .kind = .initial_image, .identity = try source.initial.digest(), .count = try std.math.add(u64, source.initial.input_words.records, source.initial.rw_words.records) },
                .{ .kind = .public_input, .identity = source.initial.public_input_sha256, .count = source.initial.public_input_len },
                .{ .kind = .first_touches, .identity = source.initial.first_touches.sha256, .count = source.initial.first_touches.records },
                .{ .kind = .final_image, .identity = try source.digest(), .count = source.endpoints.records },
            };
            return prepareMetadata(a, .{ .seal = pins.tables.seal, .entries = pins.tables.roster, .expected_seal_digest = sealed.digest, .recipe = pins.execution_recipe, .native_protocol = if (Stack.is_capacity) .capacity_v1 else .native_v3, .memory_protocol = .ram_lanes_v1, .native = native, .callers = callers, .caller_ram_events = caller_events, .ram_events = all_events, .program_fetches = all_fetches, .register_window_version = windows.version, .sources = sources }, security, fan_in, limits);
        }
    };
}

fn mixRef(channel: *core.proof_suites.Blake3.Channel, ref: Ref) void {
    channel.mixU32s(&.{ @intFromEnum(std.meta.activeTag(ref)), switch (ref) {
        .leaf, .node => |index| index,
    } });
}

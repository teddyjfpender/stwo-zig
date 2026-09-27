//! Literal independent policy fixtures exercise coverage planning, not proof
//! verification. No captured proof, claimed sum, guest or PCS is fabricated.
const std = @import("std");
const core = @import("stwo_core");
const Coverage = @import("block_v5_recursive_coverage_plan_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Recipe = @import("block_v5_execution_recipe_v1.zig").canonical;
const config = @import("../recursion/blake3_execution_parent_protocol.zig").PCS_CONFIG;
const Fixture = struct {
    entries: [18]Seal.Entry,
    len: usize,
    pins: Seal.Pins,
    sealed: Seal.Sealed,
    native: [3]Coverage.NativePresence,
    caller_events: [1]u64 = .{3},
    callers: [1]u32 = .{1},
    sources: [Coverage.SOURCE_COUNT]Coverage.SourceRequirement,
    total_events: u64,
    fn init(comptime empty_ram: bool, comptime empty_fused: bool) !Fixture {
        var counts: [Seal.family_count]u32 = @splat(0);
        counts[@intFromEnum(Seal.Family.program) - 1] = 1;
        for ([_]Seal.Family{ .execution, .execution_sidecar, .program_request }) |family| counts[@intFromEnum(family) - 1] = if (empty_ram) 1 else 3;
        if (!empty_ram) {
            for ([_]Seal.Family{ .precompile, .program_extension_request, .execution_external_sidecar }) |family| counts[@intFromEnum(family) - 1] = 1;
            counts[@intFromEnum(Seal.Family.memory) - 1] = 3;
            counts[@intFromEnum(Seal.Family.memory_range) - 1] = 1;
        }
        counts[@intFromEnum(Seal.Family.native_lookup) - 1] = 1;
        var entries: [18]Seal.Entry = undefined;
        var at: usize = 0;
        for (counts, 0..) |n, f| for (0..n) |ordinal| {
            const family: Seal.Family = @enumFromInt(f + 1);
            const sparse = family == .precompile or family == .program_extension_request or family == .execution_external_sidecar;
            entries[at] = .{ .family = family, .index = if (sparse) 1 else @intCast(ordinal), .instance_id = @splat(@intCast(20 + at)), .roots = .{ @splat(@intCast(60 + at)), @splat(@intCast(100 + at)) } };
            at += 1;
        };
        const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .expected_final_rw_root = @splat(8), .rw_endpoint_plan_digest = @splat(9), .register_endpoint_plan_digest = @splat(10), .register_custody_mode = 1, .config = config, .counts = counts };
        const sealed = try Seal.seal(pins, entries[0..at]);
        var sources: [Coverage.SOURCE_COUNT]Coverage.SourceRequirement = undefined;
        for (&sources, 0..) |*source, index| source.* = .{ .kind = @enumFromInt(index), .identity = @splat(@intCast(180 + index)), .count = 0 };
        sources[@intFromEnum(Coverage.SourceKind.sealed_roster)] = .{ .kind = .sealed_roster, .identity = sealed.digest, .count = at };
        sources[@intFromEnum(Coverage.SourceKind.native_catalog)] = .{ .kind = .native_catalog, .identity = pins.native_template_id, .count = if (empty_ram) 1 else 3 };
        sources[@intFromEnum(Coverage.SourceKind.program_plan)] = .{ .kind = .program_plan, .identity = pins.program_plan_digest, .count = 11 };
        var demand = core.proof_suites.Blake3.Channel{};
        demand.mixU32s(&.{ 0x42354344, Coverage.VERSION });
        for (entries[0..at]) |entry| if (entry.family == .native_lookup) demand.mixRoot(entry.instance_id);
        sources[@intFromEnum(Coverage.SourceKind.lookup_demand_roster)] = .{ .kind = .lookup_demand_roster, .identity = demand.digestBytes(), .count = 1 };
        sources[@intFromEnum(Coverage.SourceKind.ram_plan)] = .{ .kind = .ram_plan, .identity = pins.memory_plan_digest, .count = if (empty_ram) 0 else 9 };
        sources[@intFromEnum(Coverage.SourceKind.register_windows)] = .{ .kind = .register_windows, .identity = pins.register_endpoint_plan_digest, .count = if (empty_ram) 1 else 3 };
        sources[@intFromEnum(Coverage.SourceKind.initial_image)] = .{ .kind = .initial_image, .identity = pins.initial_source_plan_digest, .count = 2 };
        sources[@intFromEnum(Coverage.SourceKind.final_image)] = .{ .kind = .final_image, .identity = pins.rw_endpoint_plan_digest, .count = if (empty_ram) 0 else 2 };
        sources[@intFromEnum(Coverage.SourceKind.first_touches)].count = if (empty_ram) 0 else 2;
        return .{ .entries = entries, .len = at, .pins = pins, .sealed = sealed, .sources = sources, .native = .{
            .{ .projection_slots = if (empty_fused) 0 else 2, .ram_slots = if (empty_ram) 0 else 1, .ram_events = if (empty_ram) 0 else 4 },
            .{ .projection_slots = 3, .ram_slots = 1, .ram_events = 2 },
            .{ .projection_slots = 0, .ram_slots = 0, .ram_events = 0 },
        }, .total_events = if (empty_ram) 0 else 9 };
    }
    fn inventory(self: *const Fixture) Coverage.Inventory {
        return .{ .seal = self.pins, .entries = self.entries[0..self.len], .expected_seal_digest = self.sealed.digest, .recipe = Recipe, .native_protocol = .capacity_v1, .memory_protocol = .ram_lanes_v1, .native = self.native[0..self.pins.counts[@intFromEnum(Seal.Family.execution) - 1]], .callers = if (self.total_events == 0) self.callers[0..0] else &self.callers, .caller_ram_events = if (self.total_events == 0) self.caller_events[0..0] else &self.caller_events, .ram_events = self.total_events, .program_fetches = 11, .register_window_version = Recipe.windowVersion(), .sources = self.sources };
    }
};
const security = Coverage.Security{ .base = config, .recursive = config };
fn metadata(a: std.mem.Allocator, inventory: Coverage.Inventory, fan: Coverage.FanIn) !Coverage.Plan {
    return Coverage.prepareMetadata(a, inventory, security, fan, .{});
}
test "cpu requester job: independently planned pending count distinguishes capacity from unsupported legacy fusion" {
    const fixture = try Fixture.init(false, false);
    var capacity = try metadata(std.testing.allocator, fixture.inventory(), .quartet);
    defer capacity.deinit();
    try std.testing.expectEqual(@as(usize, 0), capacity.pendingAdapters().physical);
    try std.testing.expectEqual(@as(usize, 10), capacity.pendingAdapters().sources);
    var legacy_inventory = fixture.inventory();
    legacy_inventory.native_protocol = .native_v3;
    var legacy = try metadata(std.testing.allocator, legacy_inventory, .quartet);
    defer legacy.deinit();
    try std.testing.expectEqual(@as(usize, 2), legacy.pendingAdapters().physical);
    try std.testing.expectEqual(@as(usize, 10), legacy.pendingAdapters().sources);
    for (capacity.meta.physical, legacy.meta.physical) |actual, old| {
        if (actual.kind == .native_fused) {
            try std.testing.expectEqual(Coverage.Subtype.capacity_fused_v1, actual.subtype);
            try std.testing.expectEqual(Coverage.Subtype.native_fused_v2, old.subtype);
        }
    }
    // This count is source availability, never a fresh typed equation.
}
test "coverage metadata: exact logical physical census sparse caller triplet and odd topology" {
    const fixture = try Fixture.init(false, false);
    var plan = try metadata(std.testing.allocator, fixture.inventory(), .quartet);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 18), plan.meta.logical.len);
    try std.testing.expectEqual(@as(usize, 13), plan.meta.physical.len);
    try std.testing.expectEqual(@as(usize, 4), plan.meta.nodes.len);
    const root = plan.meta.nodes[plan.meta.root.node];
    try std.testing.expectEqual(@as(u32, 13), root.leaf_count);
    try std.testing.expectEqualDeep([Coverage.KIND_COUNT]u32{ 3, 2, 1, 1, 3, 1, 1, 1 }, root.schema_counts);
    for (plan.meta.physical) |proof| if (proof.kind == .caller_arithmetic or proof.kind == .caller_fused) try std.testing.expectEqual(@as(u32, 1), proof.index);
    var absences: usize = 0;
    for (plan.meta.mappings) |mapping| if (mapping == .native_typed_absence) {
        try std.testing.expectEqual(@as(u32, 2), mapping.native_typed_absence);
        absences += 1;
    };
    try std.testing.expectEqual(@as(usize, 2), absences);
    try std.testing.expectEqual(@as(usize, 0), plan.pendingAdapters().physical);
    try std.testing.expectEqual(@as(usize, 10), plan.pendingAdapters().sources);
    try plan.requireExact(plan.meta);
    const identity = plan.identity();
    try std.testing.expect(!std.mem.allEqual(u8, &identity, 0));
    var pair = try metadata(std.testing.allocator, fixture.inventory(), .pair);
    defer pair.deinit();
    try std.testing.expectEqual(@as(usize, 12), pair.meta.nodes.len);
    try std.testing.expect(!std.meta.eql(identity, pair.identity()));
    try std.testing.expectEqualDeep(root.schema_counts, pair.meta.nodes[pair.meta.root.node].schema_counts);
}
test "coverage metadata: genuine typed empty RAM inventory has no RAM range or dummy leaves" {
    const register_only = try Fixture.init(true, false);
    var plan = try metadata(std.testing.allocator, register_only.inventory(), .quartet);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 4), plan.meta.physical.len);
    for (plan.meta.physical) |proof| try std.testing.expect(proof.kind != .ram_lanes and proof.kind != .range16 and proof.kind != .caller_fused);
    // Register-only execution still needs its genuine fused projection proof.
    try std.testing.expectEqual(Coverage.Kind.native_fused, plan.meta.physical[1].kind);
    const no_requests = try Fixture.init(true, true);
    var absence = try metadata(std.testing.allocator, no_requests.inventory(), .pair);
    defer absence.deinit();
    try std.testing.expectEqual(@as(usize, 3), absence.meta.physical.len);
    var n: usize = 0;
    for (absence.meta.mappings) |mapping| if (mapping == .native_typed_absence) {
        n += 1;
    };
    try std.testing.expectEqual(@as(usize, 2), n);
}
test "coverage metadata: missing duplicate sparse subtype hash mode security and source obligations reject" {
    const fixture = try Fixture.init(false, false);
    var inventory = fixture.inventory();
    inventory.memory_protocol = .legacy_word;
    try std.testing.expectError(error.UnsupportedV5CoverageMemoryProtocol, metadata(std.testing.allocator, inventory, .pair));
    inventory = fixture.inventory();
    inventory.seal.counts[@intFromEnum(Seal.Family.hash) - 1] = 1;
    try std.testing.expectError(error.UnsupportedV5CoverageFamily, metadata(std.testing.allocator, inventory, .pair));
    inventory = fixture.inventory();
    inventory.ram_events += 1;
    try std.testing.expectError(error.InvalidV5CoverageInventory, metadata(std.testing.allocator, inventory, .pair));
    inventory = fixture.inventory();
    inventory.sources[@intFromEnum(Coverage.SourceKind.lookup_demand_roster)].identity[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5CoverageSourceRequirement, metadata(std.testing.allocator, inventory, .pair));
    inventory = fixture.inventory();
    inventory.sources[@intFromEnum(Coverage.SourceKind.sealed_roster)].count -= 1;
    try std.testing.expectError(error.UntrustedV5CoverageSourceRequirement, metadata(std.testing.allocator, inventory, .pair));
    var weak = security;
    weak.recursive.pow_bits += 1;
    try std.testing.expectError(error.UntrustedV5CoverageSecurity, Coverage.prepareMetadata(std.testing.allocator, fixture.inventory(), weak, .pair, .{}));
    var native = fixture.native;
    native[0].projection_slots = 0;
    inventory = fixture.inventory();
    inventory.native = &native;
    try std.testing.expectError(error.InvalidV5CoverageTypedAbsence, metadata(std.testing.allocator, inventory, .pair));
    const compact_caller = [_]u32{0};
    inventory = fixture.inventory();
    inventory.callers = &compact_caller;
    try std.testing.expectError(error.MissingV5CoverageObligation, metadata(std.testing.allocator, inventory, .pair));
    var entries = fixture.entries;
    entries[2] = entries[1];
    inventory = fixture.inventory();
    inventory.entries = &entries;
    try std.testing.expectError(error.InvalidBlockV5FirstRoundOrder, metadata(std.testing.allocator, inventory, .pair));
}
test "coverage metadata: transported topology key roots logical maps and proof subtypes are only candidates" {
    const fixture = try Fixture.init(false, false);
    var plan = try metadata(std.testing.allocator, fixture.inventory(), .quartet);
    defer plan.deinit();
    var candidate = plan.meta;
    candidate.physical = candidate.physical[0 .. candidate.physical.len - 1];
    try std.testing.expectError(error.UntrustedV5CoverageMetadata, plan.requireExact(candidate));
    candidate = plan.meta;
    candidate.register_window_version += 1;
    try std.testing.expectError(error.UntrustedV5CoverageMetadata, plan.requireExact(candidate));
    candidate = plan.meta;
    candidate.native_protocol = .native_v3;
    try std.testing.expectError(error.UntrustedV5CoverageMetadata, plan.requireExact(candidate));
    const physical = try std.testing.allocator.dupe(Coverage.Physical, plan.meta.physical);
    defer std.testing.allocator.free(physical);
    candidate = plan.meta;
    candidate.physical = physical;
    physical[1].subtype = .native_fused_v2;
    try std.testing.expectError(error.UntrustedV5CoverageMetadata, plan.requireExact(candidate));
    physical[1] = plan.meta.physical[1];
    physical[1].roots[0][0] ^= 1;
    try std.testing.expectError(error.UntrustedV5CoverageMetadata, plan.requireExact(candidate));
    physical[1] = plan.meta.physical[1];
    physical[1].logical[1] = physical[0].logical[0];
    try std.testing.expectError(error.UntrustedV5CoverageMetadata, plan.requireExact(candidate));
    const old_kind = plan.physical_owner[0].kind;
    plan.physical_owner[0].kind = .caller_arithmetic;
    try std.testing.expectError(error.MutatedV5CoverageIndependentPolicy, plan.requireExact(plan.meta));
    plan.physical_owner[0].kind = old_kind;
    try plan.requireExact(plan.meta);
    const nodes = try std.testing.allocator.dupe(Coverage.Node, plan.meta.nodes);
    defer std.testing.allocator.free(nodes);
    candidate = plan.meta;
    candidate.nodes = nodes;
    nodes[0].schema_counts[0] += 1;
    try std.testing.expectError(error.UntrustedV5CoverageMetadata, plan.requireExact(candidate));
    nodes[0] = plan.meta.nodes[0];
    std.mem.swap(Coverage.Ref, &nodes[0].children[0], &nodes[0].children[1]);
    try std.testing.expectError(error.UntrustedV5CoverageMetadata, plan.requireExact(candidate));
}
fn faults(a: std.mem.Allocator) !void {
    const fixture = try Fixture.init(false, false);
    var plan = try metadata(a, fixture.inventory(), .quartet);
    defer plan.deinit();
    try plan.requireExact(plan.meta);
}
test "coverage metadata: every owned allocation fails cleanly and caps precede allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, faults, .{});
    const fixture = try Fixture.init(false, false);
    try std.testing.expectError(error.V5CoverageResourceLimit, Coverage.prepareMetadata(std.testing.allocator, fixture.inventory(), security, .pair, .{ .max_logical = 17 }));
    try std.testing.expectError(error.V5CoverageResourceLimit, Coverage.prepareMetadata(std.testing.allocator, fixture.inventory(), security, .pair, .{ .max_owned_bytes = 1 }));
}

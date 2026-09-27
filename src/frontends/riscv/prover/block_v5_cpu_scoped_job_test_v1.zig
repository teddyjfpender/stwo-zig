//! Pure independently pinned census, byte decoding and setup lifecycle guards.
//! No proof, host receipt, guest, commitment or device execution is fabricated.
const std = @import("std");
const core = @import("stwo_core");
const Coverage = @import("block_v5_recursive_coverage_plan_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Recipe = @import("block_v5_execution_recipe_v1.zig").canonical;
const Parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const Sources = @import("block_v5_cpu_scoped_job_sources_v1.zig");
const Fold = @import("block_v5_cpu_scoped_job_fold_v1.zig");
const Setup = @import("../recursion/block_v5_heterogeneous_scoped_owner_v1.zig");
const Source = @import("../recursion/block_v5_heterogeneous_scoped_source_v1.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Fixture = struct {
    entries: [18]Seal.Entry,
    pins: Seal.Pins,
    sealed: Seal.Sealed,
    sources: [Coverage.SOURCE_COUNT]Coverage.SourceRequirement,
    native: [3]Coverage.NativePresence = .{
        .{ .projection_slots = 2, .ram_slots = 1, .ram_events = 4 },
        .{ .projection_slots = 3, .ram_slots = 1, .ram_events = 2 },
        .{ .projection_slots = 0, .ram_slots = 0, .ram_events = 0 },
    },
    fn init() !Fixture {
        var counts: [Seal.family_count]u32 = @splat(0);
        counts[@intFromEnum(Seal.Family.program) - 1] = 1;
        for ([_]Seal.Family{ .execution, .execution_sidecar, .program_request, .memory }) |family| counts[@intFromEnum(family) - 1] = 3;
        for ([_]Seal.Family{ .precompile, .program_extension_request, .execution_external_sidecar, .memory_range, .native_lookup }) |family| counts[@intFromEnum(family) - 1] = 1;
        var entries: [18]Seal.Entry = undefined;
        var at: usize = 0;
        for (counts, 0..) |count, f| for (0..count) |index| {
            const family: Seal.Family = @enumFromInt(f + 1);
            const sparse = family == .precompile or family == .program_extension_request or family == .execution_external_sidecar;
            entries[at] = .{ .family = family, .index = if (sparse) 1 else @intCast(index), .instance_id = @splat(@intCast(at + 20)), .roots = .{ @splat(@intCast(at + 60)), @splat(@intCast(at + 100)) } };
            at += 1;
        };
        if (at != entries.len) return error.TestUnexpectedResult;
        const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .expected_final_rw_root = @splat(8), .rw_endpoint_plan_digest = @splat(9), .register_endpoint_plan_digest = @splat(10), .register_custody_mode = 1, .config = Parent.PCS_CONFIG, .counts = counts };
        const sealed = try Seal.seal(pins, &entries);
        var sources: [Coverage.SOURCE_COUNT]Coverage.SourceRequirement = undefined;
        for (&sources, 0..) |*source, index| source.* = .{ .kind = @enumFromInt(index), .identity = @splat(@intCast(index + 180)), .count = 0 };
        sources[@intFromEnum(Coverage.SourceKind.sealed_roster)] = .{ .kind = .sealed_roster, .identity = sealed.digest, .count = entries.len };
        sources[@intFromEnum(Coverage.SourceKind.native_catalog)] = .{ .kind = .native_catalog, .identity = pins.native_template_id, .count = 3 };
        sources[@intFromEnum(Coverage.SourceKind.program_plan)] = .{ .kind = .program_plan, .identity = pins.program_plan_digest, .count = 11 };
        var demand = core.proof_suites.Blake3.Channel{};
        demand.mixU32s(&.{ 0x42354344, Coverage.VERSION });
        for (entries) |entry| if (entry.family == .native_lookup) demand.mixRoot(entry.instance_id);
        sources[@intFromEnum(Coverage.SourceKind.lookup_demand_roster)] = .{ .kind = .lookup_demand_roster, .identity = demand.digestBytes(), .count = 1 };
        sources[@intFromEnum(Coverage.SourceKind.ram_plan)] = .{ .kind = .ram_plan, .identity = pins.memory_plan_digest, .count = 9 };
        sources[@intFromEnum(Coverage.SourceKind.register_windows)] = .{ .kind = .register_windows, .identity = pins.register_endpoint_plan_digest, .count = 3 };
        sources[@intFromEnum(Coverage.SourceKind.initial_image)] = .{ .kind = .initial_image, .identity = pins.initial_source_plan_digest, .count = 2 };
        sources[@intFromEnum(Coverage.SourceKind.final_image)] = .{ .kind = .final_image, .identity = pins.rw_endpoint_plan_digest, .count = 2 };
        sources[@intFromEnum(Coverage.SourceKind.first_touches)].count = 2;
        return .{ .entries = entries, .pins = pins, .sealed = sealed, .sources = sources };
    }
    fn inventory(self: *const Fixture) Coverage.Inventory {
        return .{ .seal = self.pins, .entries = &self.entries, .expected_seal_digest = self.sealed.digest, .recipe = Recipe, .native_protocol = .capacity_v1, .memory_protocol = .ram_lanes_v1, .native = &self.native, .callers = &.{1}, .caller_ram_events = &.{3}, .ram_events = 9, .program_fetches = 11, .register_window_version = Recipe.windowVersion(), .sources = self.sources };
    }
};
fn plan(a: std.mem.Allocator, inventory: Coverage.Inventory) !Coverage.Plan {
    return Coverage.prepareMetadata(a, inventory, .{ .base = Parent.PCS_CONFIG, .recursive = Parent.PCS_CONFIG }, .quartet, .{});
}
test "cpu scoped job: exact eight-family nonrounded sparse physical roster preserves independently pinned typed absence" {
    const fixture = try Fixture.init();
    var admitted = try plan(std.testing.allocator, fixture.inventory());
    defer admitted.deinit();
    try admitted.requireExact(admitted.meta);
    try std.testing.expectEqual(@as(usize, 18), admitted.meta.logical.len);
    try std.testing.expectEqual(@as(usize, 13), admitted.meta.physical.len);
    const root = admitted.meta.nodes[admitted.meta.root.node];
    try std.testing.expectEqualDeep([Coverage.KIND_COUNT]u32{ 3, 2, 1, 1, 3, 1, 1, 1 }, root.schema_counts);
    try std.testing.expectEqual(@as(u32, 2), admitted.meta.physical[try Sources.physicalOrdinal(&admitted, .native_arithmetic, 2)].index);
    try std.testing.expectError(error.UnadmittedCpuScopedLeaf, Sources.physicalOrdinal(&admitted, .native_fused, 2));
    try std.testing.expectError(error.UnadmittedCpuScopedLeaf, Sources.physicalOrdinal(&admitted, .caller_fused, 0));
    _ = try Sources.physicalOrdinal(&admitted, .caller_fused, 1);
    for (admitted.meta.nodes) |node| try std.testing.expect(node.child_count <= 4);
}
test "cpu scoped job: stale event census source requirement and sparse claimant cannot reseal independent coverage" {
    const fixture = try Fixture.init();
    var changed = fixture.inventory();
    changed.ram_events += 1;
    try std.testing.expectError(error.InvalidV5CoverageInventory, plan(std.testing.allocator, changed));
    changed = fixture.inventory();
    changed.sources[@intFromEnum(Coverage.SourceKind.lookup_demand_roster)].identity[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5CoverageSourceRequirement, plan(std.testing.allocator, changed));
    changed = fixture.inventory();
    changed.callers = &.{0};
    const rejected = plan(std.testing.allocator, changed);
    if (rejected) |result| {
        var owned = result;
        owned.deinit();
        return error.TestUnexpectedResult;
    } else |_| {}
}
fn ownership(a: std.mem.Allocator, fixture: *const Fixture) !void {
    var admitted = try plan(a, fixture.inventory());
    defer admitted.deinit();
    try admitted.requireExact(admitted.meta);
}
test "cpu scoped job: every new exact roster allocation failure releases owned policy without proof side effects" {
    const fixture = try Fixture.init();
    try ownership(std.testing.allocator, &fixture);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ownership, .{&fixture});
}
test "cpu scoped job: compact output reads exact four canonical little endian limbs and rejects malformed bytes" {
    const value = Q.fromU32Unchecked(3, 5, 7, 11);
    var cells: [4][4]M = undefined;
    for (&cells, value.toM31Array()) |*cell, word| {
        for (cell, 0..) |*byte, part| byte.* = M.fromCanonical((word.v >> @as(u5, @intCast(8 * part))) & 255);
    }
    var source: Source.Source = undefined;
    source.cells = &cells;
    source.slots = &.{.{ .requirement = 19, .first = 0 }};
    try std.testing.expect((try Fold.slotValue(&source, 19)).eql(value));
    try std.testing.expectError(error.MissingScopedSourceSlot, Fold.slotValue(&source, 18));
    cells[0][0].v = 256;
    try std.testing.expectError(error.NoncanonicalScopedSummary, Fold.slotValue(&source, 19));
    cells[0] = .{ M.fromCanonical(255), M.fromCanonical(255), M.fromCanonical(255), M.fromCanonical(127) };
    try std.testing.expectError(error.NoncanonicalScopedSummary, Fold.slotValue(&source, 19));
    source.slots = &.{.{ .requirement = 19, .first = 1 }};
    try std.testing.expectError(error.InvalidScopedSource, Fold.slotValue(&source, 19));
}
test "cpu scoped job: original and independently bound setup context use identical B5ZC kernel" {
    const pins = Setup.Pins{ .job = @splat(1), .coverage = @splat(2), .source = @splat(3), .recipe = Recipe, .scoped = @splat(4), .routing = @splat(5), .node_ids = &.{@splat(6)} };
    var original = Parent.Context{ .child_key_id = @splat(7), .child_config = Parent.PCS_CONFIG, .graph_ids = @splat(@splat(8)), .transcript_plan_id = @splat(9) };
    var incremental = original;
    Setup.testing.bindSetupContext(&original, pins.contextIdentity());
    Setup.bindIndependentContext(&incremental, pins.contextIdentity());
    try std.testing.expectEqualDeep(original, incremental);
    var changed = pins;
    changed.source[0] ^= 1;
    var stale = Parent.Context{ .child_key_id = @splat(7), .child_config = Parent.PCS_CONFIG, .graph_ids = @splat(@splat(8)), .transcript_plan_id = @splat(9) };
    Setup.bindIndependentContext(&stale, changed.contextIdentity());
    try std.testing.expect(!std.meta.eql(stale, original));
}
test "cpu scoped job: setup consumes failure safely and rejects resource policy before dereferencing source" {
    var empty = Setup.JobSetup{ .owned = null };
    empty.deinit();
    try std.testing.expectError(error.ScopedOwnerLifetime, empty.routes());
    try std.testing.expectError(error.ScopedOwnerLifetime, empty.finish(undefined, &.{}));
    try std.testing.expectError(error.ScopedOwnerResourceLimit, Setup.prepareJob(std.testing.allocator, undefined, undefined, .{ .max_owned_bytes = 0 }));
    try std.testing.expectError(error.CpuScopedFoldResourceLimit, (Fold.Limits{ .max_live_bytes = 0 }).validate());
    try std.testing.expectError(error.InvalidCpuScopedJobOptions, (@import("block_v5_cpu_scoped_job_v1.zig").Options{ .max_manifest_bytes = 0 }).validate());
    try std.testing.expect(!Sources.Owner.source_authority and !Fold.Result.complete_block_authority);
}
test "cpu scoped job: legacy span grammar rejects wide native cycles instead of truncating actual u64 authority" {
    const span = @import("../recursion/block_v5_pc_clock_span_v1.zig").Span{ .job_id = @splat(1), .source_image_digest = @splat(3), .sealed_digest = @splat(2), .job_segment_count = 1, .first_index = 0, .segment_count = 1, .first_cycle = 1, .last_cycle = (@as(u64, 1) << 30), .initial_pc = 8, .final_pc = 12 };
    const result = @import("../recursion/block_v5_open_parent_public_bus_v1.zig").validateSpanBound(span);
    if (result) |_| return error.TestUnexpectedResult else |_| {}
}
const Store = @import("block_v5_recursive_execution_leaf_store_v1.zig").ForFamily(.caller_arithmetic);
const CallerFixture = @import("block_v5_recursive_execution_leaf_store_test_v1.zig").Fixture;
fn readerTransport(a: std.mem.Allocator, dir: std.fs.Dir, fixture: *const CallerFixture, admitted: *const Store.Codec.Admission.Prepared, template: *const Store.TemplatePolicy) !void {
    const policies = [_]Store.Policy{.{ .prepared = admitted, .template = template }};
    const expected_files = [_]@import("block_v5_recursive_execution_leaf_store_v1.zig").FilePin{.{ .index = 2, .byte_len = 99, .sha256 = @splat(11) }};
    var reader = try Store.Store.initReader(a, dir, fixture.roster(), &policies, &expected_files, .{});
    defer reader.deinit();
    const proposals = try reader.sourceFilePins(a);
    defer a.free(proposals);
    try std.testing.expectEqualDeep(expected_files[0], proposals[0]);
    try std.testing.expectError(error.InvalidRecursiveExecutionStoreMode, reader.filePins(a));
    try std.testing.expectError(error.IncompleteRecursiveExecutionVerification, reader.requireVerified());
    // The file does not exist. A pinned transport proposal cannot create a
    // verified slot, let alone an original equation or a whole-block result.
}
fn readerFixture(a: std.mem.Allocator, dir: std.fs.Dir, inject: bool) !void {
    const fixture = try CallerFixture.init(a);
    var admitted = try Store.Codec.Admission.Prepared.init(a, fixture.caller.statement, fixture.caller.frame.cycle_count, fixture.caller.binding, fixture.caller.sealed, fixture.caller.pins, &fixture.entries, .{});
    defer admitted.deinit();
    const wires = [_]Store.Codec.Bus.Wire{.{ .circuit = 1500, .wire = 0, .uses = 1, .source = .open_sum, .coordinate = 0 }};
    // Literal admitted template model tests transport ownership ONLY, never
    // cryptographic setup derivation. Production rederives actual row geometry.
    const geometry = Parent.Key{ .profile = .diagnostic_q8_pow0, .config = admitted.config, .context = .{ .child_key_id = admitted.template_id, .child_config = admitted.config, .graph_ids = .{ @splat(6), @splat(7), @splat(8) }, .transcript_plan_id = @splat(9) }, .log_sizes = @splat(4), .preprocessed_root = @splat(10) };
    const key = try Store.Codec.Protocol.Key.fromGeometry(geometry, &wires);
    const template = Store.TemplatePolicy{ .key = key, .key_id = try key.identity(), .schedule = &wires };
    if (inject) {
        // Genuine source admission is outside injection: enumerate every NEW
        // reader policy/pin/snapshot allocation without repeating its setup.
        try std.testing.checkAllAllocationFailures(a, readerTransport, .{ dir, &fixture, &admitted, &template });
    } else try readerTransport(a, dir, &fixture, &admitted, &template);
}
test "cpu scoped job: bounded reader pin snapshot preserves writer API and cannot confer verified state" {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try readerFixture(std.testing.allocator, dir.dir, false);
}
test "cpu scoped job: all new reader snapshot allocation failures release authentic source borrows" {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try readerFixture(std.testing.allocator, dir.dir, true);
}

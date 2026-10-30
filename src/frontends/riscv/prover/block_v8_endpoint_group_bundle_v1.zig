//! Complete ORIGINAL bundle receiver for bounded Groups. Each genuine Group
//! STARK verifies ONCE and exports all its sources. No per-cohort replay of
//! that verification, producer receipt, retained tree or host witness is trusted.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("stwo_prover_engine");
const Scope = @import("block_v8_endpoint_group_scope_v1.zig");
const Metadata = @import("block_v8_endpoint_group_statement_wire_v1.zig");
const Codec = @import("block_v8_endpoint_group_codec_v1.zig");
const Window = @import("block_v7_real_window_policy_v2.zig");
const BridgeScope = @import("block_v8_endpoint_global_bridge_scope_v1.zig");
const Bridge = @import("block_v8_endpoint_global_bridge_proof_v1.zig");
const Compact = @import("block_v8_compact_ram_proof_v1.zig");
pub const production_active = false;
pub const External = @import("block_v8_endpoint_local_bundle_v1.zig").External;
pub const Summary = struct {
    scope: enum { declared_window_originals_closed } = .declared_window_originals_closed,
    global_argument: enum { compact_endpoint } = .compact_endpoint,
    elf_sha256: [32]u8,
    incoming_sha256: [32]u8,
    outgoing_sha256: [32]u8,
    epoch: [32]u8,
    cycles: u64,
    cohorts: u32,
    groups: u32,
    group_original_verifications: u32,
    bridge_batches: u32,
    endpoint_events: u64,
    logical_ram_accesses: u64,
    program_fetches: u64,
    external_retirements: u64,
};
pub const Input = struct {
    group_count: u32,
    cohort_policy: Window.CohortPolicy,
    bridge_batches: u32,
    selected_initial_addresses: []const u32,
    global_memory: *const Compact.Proof,
};
pub const Limits = struct {
    max_live_bytes: usize = 12 << 30,
    max_cohorts: u32 = 4096,
    max_cohort_cycles: u32 = 1 << 20,
    initial: @import("block_v7_initial_intervals_v1.zig").Limits = .{},
    metadata: Metadata.Limits = .{},
    group: Codec.Limits = .{},
    bridge: Bridge.Limits = .{},
    memory: Compact.Limits = .{},
};
/// Provider.loadGroup(a,index) returns only bounded metadata/proof byte leases.
/// loadBridge(a,index,first,count,max_log) returns a borrowed typed original;
/// max_log is derived here from the freshly verified Group sources, not a report.
pub fn verify(backing: std.mem.Allocator, external: External, input: Input, provider: anytype, limits: Limits) !Summary {
    const count = input.cohort_policy.cohort_count;
    if (limits.max_live_bytes == 0 or count == 0 or count > @min(limits.max_cohorts, BridgeScope.MAX_SOURCES) or input.group_count == 0 or input.group_count > count or input.group_count < try std.math.divCeil(u32, count, 32) or input.bridge_batches != try std.math.divCeil(u32, count, BridgeScope.MAX_BATCH_SOURCES) or input.cohort_policy.max_cohort_cycles > limits.max_cohort_cycles or input.selected_initial_addresses.len > limits.initial.max_initialized_words) return error.InvalidEndpointGroupBundleRoster;
    try input.cohort_policy.validate(external.trusted.window.cycles);
    const budget = try E.host_budget_allocator.SharedHostBudget.createRetainingParent(backing, limits.max_live_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    var window = try Window.Owned.deriveCohortsForAddressesWithBoundary(a, external.elf, external.incoming, external.outgoing, external.trusted, input.cohort_policy, input.selected_initial_addresses, external.boundary, limits.initial);
    defer window.deinit();
    const trusted = Scope.Trusted{ .elf = external.elf, .elf_sha256 = external.trusted.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = external.config, .cohort_count = count };
    const sources = try a.alloc(BridgeScope.Source, count);
    defer a.free(sources);
    var registers = window.boundary.initial_cpu.regs;
    var pc = window.boundary.initial_cpu.pc;
    var cycle: u64 = 1;
    var next: u32 = 0;
    var endpoints: u64 = 0;
    var logical: u64 = 0;
    var fetches: u64 = 0;
    var external_retirements: u64 = 0;
    for (0..input.group_count) |group_index| {
        var lease = try provider.loadGroup(a, @as(u32, @intCast(group_index)));
        defer lease.deinit();
        const statement = try Metadata.decode(a, lease.metadata, trusted, limits.metadata);
        defer statement.deinit();
        var verified = try Codec.verifyBytes(a, lease.proof, trusted, statement.input, limits.group);
        defer verified.deinit();
        const g = verified.summary;
        if (g.cohorts == 0 or g.cohorts > @import("block_v8_endpoint_group_layout_v1.zig").maxMembers(statement.input.profile) or g.sources.len != g.cohorts or g.cohorts > count - next or g.first_cohort_ordinal != next or g.last_cohort_ordinal != next + g.cohorts - 1 or g.global_first_cycle != cycle or g.initial_pc != pc or !std.meta.eql(g.initial_regs, registers)) return error.UntrustedEndpointGroupBundleCpuChain;
        var group_cycles: u64 = 0;
        for (g.sources) |source| {
            if (source.policy.source_ordinal != next or source.frame.clock_frame != .leaf_local or source.frame.global_first_cycle != cycle or source.frame.cycle_count == 0 or source.frame.cycle_count > input.cohort_policy.max_cohort_cycles) return error.UntrustedEndpointGroupBundleSource;
            group_cycles = try std.math.add(u64, group_cycles, source.frame.cycle_count);
            cycle = try std.math.add(u64, cycle, source.frame.cycle_count);
            if (cycle - 1 > external.trusted.window.cycles) return error.UntrustedEndpointGroupBundleCpuChain;
            endpoints = try std.math.add(u64, endpoints, source.endpoint_count);
            sources[next] = .{ .local_identity = source.local_identity, .local_epoch = source.local_epoch, .endpoint_root = source.endpoint_root, .endpoint_count = source.endpoint_count, .policy = source.policy };
            next += 1;
        }
        if (group_cycles != g.cycles) return error.UntrustedEndpointGroupBundleCpuChain;
        pc = g.final_pc;
        registers = g.final_regs;
        logical = try std.math.add(u64, logical, g.logical_ram_accesses);
        fetches = try std.math.add(u64, fetches, g.program_fetches);
        external_retirements = try std.math.add(u64, external_retirements, g.external_retirements);
    }
    if (next != count or cycle - 1 != external.trusted.window.cycles or pc != window.boundary.final_cpu.pc or !std.meta.eql(registers, window.boundary.final_cpu.regs)) return error.IncompleteEndpointGroupBundleCoverage;
    const policy = Compact.Policy{ .window = &window, .config = external.config, .event_count = std.math.cast(u32, endpoints) orelse return error.InvalidEndpointGroupBundleGlobalGeometry };
    if (input.global_memory.event_count != endpoints) return error.InvalidEndpointGroupBundleGlobalGeometry;
    var roster = try BridgeScope.Owned.init(a, try policy.digest(), external.config, sources, try policy.entry(input.global_memory.roots));
    defer roster.deinit();
    var transition = core.fields.qm31.QM31.zero();
    next = 0;
    for (0..input.bridge_batches) |batch_index| {
        const n = @min(@as(u32, BridgeScope.MAX_BATCH_SOURCES), count - next);
        var max_log: u32 = 4;
        for (sources[next..][0..n]) |source| max_log = @max(max_log, std.math.log2_int_ceil(u32, source.endpoint_count));
        var lease = try provider.loadBridge(a, @as(u32, @intCast(batch_index)), next, n, max_log);
        defer lease.deinit();
        if (lease.first != next or lease.count != n) return error.IncompleteEndpointGroupBridgeCoverage;
        var batch = try roster.batch(a, next, n);
        defer batch.deinit();
        transition = transition.add(try Bridge.verifyConditional(a, batch, &lease.proof.stark, lease.proof.claims, limits.bridge));
        next += n;
    }
    const memory = try Compact.verifyConditional(a, policy, roster.epoch, roster.entries, input.global_memory, limits.memory);
    if (memory.event_count != roster.endpoint_count or !transition.add(memory.transition).isZero()) return error.UnclosedEndpointGroupBundleGlobalMemory;
    return .{ .elf_sha256 = external.trusted.elf_sha256, .incoming_sha256 = external.trusted.incoming_sha256, .outgoing_sha256 = external.trusted.outgoing_sha256, .epoch = roster.epoch.digest, .cycles = cycle - 1, .cohorts = count, .groups = input.group_count, .group_original_verifications = input.group_count, .bridge_batches = input.bridge_batches, .endpoint_events = memory.event_count, .logical_ram_accesses = logical, .program_fetches = fetches, .external_retirements = external_retirements };
}

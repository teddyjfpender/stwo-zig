//! Inactive bounded native-only Group producer: one witness per cohort, one
//! shared provider set and one original STARK. Endpoint roots remain available
//! for the separately authenticated late RAM bridge; this is not a block root.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Prepare = @import("block_v8_endpoint_execution_v1.zig");
const Execution = @import("block_v5_cpu_execution_source_v1.zig");
const Scope = @import("block_v8_endpoint_group_scope_v1.zig");
const Context = @import("block_v8_endpoint_group_context_v1.zig");
const Original = @import("block_v8_endpoint_group_proof_v1.zig");
const Statement = @import("block_v8_endpoint_group_statement_v1.zig");
const Metadata = @import("block_v8_endpoint_group_statement_wire_v1.zig");
const Codec = @import("block_v8_endpoint_group_codec_v1.zig");
const Layout = @import("block_v8_endpoint_group_layout_v1.zig");
const Collector = @import("block_v8_ram_endpoint_collector_v1.zig");
const Range = @import("block_v8_endpoint_range_provider_v1.zig");
const GroupRange = @import("block_v8_endpoint_group_range_v1.zig");
const LP = @import("block_v5_native_lookup_plan_v1.zig");
const Lookup = @import("block_v7_lookup_compact_proof_v1.zig");
const ROM = @import("block_v7_program_provider_v1.zig");
const Image = @import("block_v8_endpoint_local_program_v1.zig");
const Sparse = @import("block_v8_sparse_rom_v1.zig");
const SparseROM = @import("block_v8_sparse_rom_provider_v1.zig");
const Capture = @import("block_v7_real_window_capture_v1.zig");
const Window = @import("block_v7_real_window_policy_v2.zig");
const Retained = @import("block_v8_endpoint_local_retained_v1.zig");
const Column = E.pcs.ColumnEvaluation;
pub const production_active = false;
pub const Request = Prepare.Request;
pub const Options = struct {
    batch_native_projections: bool = false,
    profile: Layout.Profile = .compact_v1,
    cohort_cycles: u32 = 1 << 19,
    max_cycles: u32 = 1 << 22,
    max_endpoint_events: usize = 1 << 24,
    max_retained_endpoint_bytes: usize = 2 << 30,
    initial: @import("block_v7_initial_intervals_v1.zig").Limits = .{},
    collector: Collector.Limits = .{},
    range: Range.Limits = .{},
    lookup: Lookup.Limits = .{},
    proof: Original.Limits = .{},
    codec: Codec.Limits = .{},
    metadata: Metadata.Limits = .{},
    program_flavor: @import("block_v8_endpoint_local_scope_v1.zig").RomFlavor = .sparse_elf,
};
pub const Stats = struct {
    batch_native_projections: bool = false,
    cycles: u32 = 0,
    cohorts: u32 = 0,
    trace_trees: usize = 0,
    execution_ns: u64 = 0,
    restore_ns: u64 = 0,
    native_witness_ns: u64 = 0,
    preparation_ns: u64 = 0,
    endpoint_preparation_ns: u64 = 0,
    census_ns: u64 = 0,
    runner_release_ns: u64 = 0,
    shared_providers_ns: u64 = 0,
    original_ns: u64 = 0,
    artifact_ns: u64 = 0,
    producer_release_ns: u64 = 0,
    fresh_verification_ns: u64 = 0,
    whole_ns: u64 = 0,
    logical_ram_events: u64 = 0,
    endpoint_count: u64 = 0,
    native_main_cells: u64 = 0,
    endpoint_cells: u64 = 0,
    ram_clock_rows: u64 = 0,
    register_clock_rows: u64 = 0,
    program_selected_pcs: usize = 0,
    program_log_size: u32 = 0,
    proof_bytes: usize = 0,
    charged_peak_bytes: usize = 0,
    original: Original.Timings = .{},
};
pub fn Outcome(comptime received: bool) type {
    return struct {
        const Self = @This();
        a: std.mem.Allocator,
        budget: *E.host_budget_allocator.SharedHostBudget,
        statement: *Statement.Owned,
        proof_bytes: []u8,
        metadata_bytes: []u8,
        verified: if (received) Original.OwnedVerified else void,
        endpoints: []Collector.Owned,
        leases: []?*Retained.Owned,
        stats: Stats,
        pub fn deinit(self: *Self) void {
            const a = self.a;
            const budget = self.budget;
            for (self.leases) |lease| if (lease) |v| v.deinit();
            a.free(self.leases);
            for (self.endpoints) |*ep| ep.deinit();
            a.free(self.endpoints);
            if (received) self.verified.deinit();
            a.free(self.proof_bytes);
            a.free(self.metadata_bytes);
            self.statement.deinit();
            a.destroy(self);
            budget.destroy();
        }
    };
}
pub const Result = Outcome(true);
/// A generation product, with NO verified relation or admission receipt.
pub const UncheckedResult = Outcome(false);
const Member = struct { current: ?*Execution.Current = null, native: ?*@import("blake3_execution_trace.zig").Owner = null, endpoints: ?Collector.Owned = null };
/// All wide owners are confined to this source preparation. Only the narrow
/// endpoint matrices/tree leases and public metadata survive run().
const Prepared = struct {
    a: std.mem.Allocator,
    image: ?Image.Owned = null,
    member: []Member = &.{},
    inputs: []Scope.MemberInput = &.{},
    stages: []Context.MemberStages = &.{},
    fixed: [][]const Column = &.{},
    ranges: ?Range.Owned = null,
    lookup: ?Lookup.For(Cpu).Stage = null,
    program: ?ROM.ForBackend(Cpu).FirstRound = null,
    sparse: ?Sparse.Owned = null,
    multiplicities: []u64 = &.{},
    plan: @import("block_v5_program_table_v1.zig").Plan = undefined,
    lookup_plan: LP.Plan = undefined,
    trusted: Scope.Trusted = undefined,
    fn deinit(self: *Prepared) void {
        if (self.program) |*v| v.deinit(self.a);
        if (self.sparse) |*v| v.deinit();
        if (self.lookup) |*v| v.deinit();
        if (self.ranges) |*v| v.deinit();
        for (self.member) |*m| {
            if (m.endpoints) |*v| v.deinit();
            if (m.current) |v| v.deinit();
            if (m.native) |v| v.deinit();
        }
        self.a.free(self.member);
        self.a.free(self.inputs);
        self.a.free(self.stages);
        self.a.free(self.fixed);
        self.a.free(self.multiplicities);
        if (self.image) |*v| v.deinit();
    }
    fn input(self: *const Prepared, flavor: @import("block_v8_endpoint_local_scope_v1.zig").RomFlavor, profile: Layout.Profile) Scope.Input {
        return .{ .profile = profile, .members = self.inputs, .fixed_root = @splat(0), .range_main_root = @splat(0), .rom_flavor = flavor, .sparse_support = if (self.sparse) |v| v.entries else &.{}, .program_plan = self.plan, .program_roots = self.program.?.roots, .lookup_plan = self.lookup_plan, .lookup_layout = self.lookup.?.layout, .lookup_roots = self.lookup.?.roots };
    }
    fn init(a: std.mem.Allocator, request: Request, options: Options, stats: *Stats) !Prepared {
        var self = Prepared{ .a = a };
        errdefer self.deinit();
        const cycles = request.trusted_window.window.cycles;
        const n = try std.math.divCeil(u32, cycles, options.cohort_cycles);
        _ = try Layout.Plan.initWithProfile(n, 0, options.profile);
        self.trusted = .{ .elf = request.elf, .elf_sha256 = request.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = request.config, .cohort_count = n };
        self.image = try Image.Owned.init(a, request.elf, request.elf_sha256, .rv32im_zkvm_ethereum_sha_v1, options.initial);
        // Snapshot validation is public context admission, not a substitute for
        // late global memory closure. It is done once per declared group window.
        var window = try Window.Owned.deriveCohorts(a, request.elf, request.incoming, request.outgoing, request.trusted_window, .{ .cohort_count = n, .max_cohort_cycles = options.cohort_cycles }, options.initial);
        defer window.deinit();
        if (!std.meta.eql(window.program_root, self.image.?.root.bytes)) return error.UntrustedEndpointGroupProgram;
        self.member = try a.alloc(Member, n);
        for (self.member) |*m| m.* = .{};
        self.inputs = try a.alloc(Scope.MemberInput, n);
        self.stages = try a.alloc(Context.MemberStages, n);
        self.fixed = try a.alloc([]const Column, n);
        self.multiplicities = try a.alloc(u64, self.image.?.leaves.len / 4);
        @memset(self.multiplicities, 0);
        const matrices = try a.alloc(@import("block_v7_memory_trace_v1.zig").Matrix, n);
        defer a.free(matrices);
        const counts = try a.alloc(u32, n);
        defer a.free(counts);
        var counters = try @import("../air/lookups/tables/counter.zig").Set.init(a);
        defer counters.deinit(a);
        var demand: [6]u64 = @splat(0);
        var expected: u64 = 0;
        var timer = try std.time.Timer.start();
        var session = try @import("../runner/mod.zig").EthereumShaExecutionSession.init(a, request.elf, .{ .input = &.{}, .clock_frame = .leaf_local, .trace_retention = .segment_owned, .stop_on_halt_flag = true, .require_current_output_accesses = false });
        defer session.deinit();
        try Prepare.restoreSession(a, &session, request.incoming);
        stats.restore_ns = timer.lap();
        var continuation: ?@import("../runner/result.zig").ContinuationToken = null;
        var completed: u32 = 0;
        for (self.member, 0..) |*m, i| {
            const count = @min(options.cohort_cycles, cycles - completed);
            const segment = if (continuation) |token| try session.resumeSegment(token, count) else try session.startSegment(count);
            stats.execution_ns += timer.lap();
            m.current = try Prepare.makeCurrent(a, segment, self.image.?.root.bytes);
            const current = m.current.?;
            stats.native_witness_ns += timer.lap();
            if (current.segment.base.cycle_count != count or current.segment.base.continuation == null) return error.EndpointGroupIncompleteWindow;
            continuation = current.segment.base.continuation;
            stats.ram_clock_rows += current.segment.base.state_chain_tracker.clock_updates_mem.items.len;
            stats.register_clock_rows += current.segment.base.state_chain_tracker.clock_updates_reg.items.len;
            for (current.owner.main.items) |column| stats.native_main_cells += column.values.len;
            const frame = Collector.Frame{ .clock_frame = current.segment.base.clock_frame, .global_first_cycle = current.segment.base.global_first_cycle, .cycle_count = count };
            const events = try Prepare.extractEvents(a, current.owner, frame, options.collector.max_events);
            defer a.free(events);
            m.endpoints = try Collector.collectGlobal(a, .{ .frame = frame, .cohort_ordinal = @intCast(i), .cohort_count = n }, events, options.collector);
            matrices[i] = m.endpoints.?.matrix;
            counts[i] = @intCast(m.endpoints.?.endpoints.len);
            stats.logical_ram_events = try std.math.add(u64, stats.logical_ram_events, events.len);
            stats.endpoint_count = try std.math.add(u64, stats.endpoint_count, counts[i]);
            stats.endpoint_cells = try std.math.add(u64, stats.endpoint_cells, m.endpoints.?.matrix.storage.len);
            if (stats.endpoint_count > options.max_endpoint_events) return error.EndpointGroupEventLimit;
            stats.endpoint_preparation_ns += timer.lap();
            counters.mergeFrom(&current.owner.opcode_columns.lookup_counters.?);
            try LP.addDemand(&demand, try LP.nativeDemand(&current.owner.statement, 0));
            var census = try Prepare.collectProgramCensus(a, current, self.image.?.root, self.image.?.leaves, self.image.?.info.memory_layout.program_base);
            defer census.deinit();
            for (self.multiplicities, census.multiplicities) |*value, addend| value.* = try std.math.add(u64, value.*, addend);
            expected = try std.math.add(u64, expected, census.plan.expected_fetches);
            stats.census_ns += timer.lap();
            self.inputs[i] = .{ .shape = &current.owner.statement, .frame = frame, .cohort_ordinal = @intCast(i), .endpoint_count = counts[i], .native_main_root = @splat(0), .endpoint_main_root = @splat(0) };
            self.stages[i] = .{ .native_main = current.owner.main.items, .endpoints = &m.endpoints.? };
            self.fixed[i] = current.owner.preprocessed.items;
            // Explicit owner transfer: Current destroys the real segment/io,
            // while the native witness remains owned exactly once by Member.
            m.native = try current.takeNativeOwner();
            current.deinit();
            m.current = null;
            stats.runner_release_ns += timer.lap();
            completed += count;
        }
        var actual = try Capture.snapshot(a, session.cpu, &session.memory, .{ .max_window_cycles = cycles });
        defer actual.deinit(a);
        if (!std.meta.eql(actual.identity(), request.trusted_window.outgoing_sha256)) return error.EndpointGroupOutgoingMismatch;
        self.ranges = try GroupRange.initForProfile(a, matrices, counts, options.range, options.profile);
        try self.ranges.?.appendToLookup(counters.get(.range_check_8_8), &demand);
        self.lookup_plan = .{ .index = 0, .first_execution = 0, .execution_count = n, .max_requests = demand };
        self.lookup = try Lookup.For(Cpu).Stage.init(a, &counters, self.lookup_plan, request.config, null, options.lookup);
        self.plan = .{ .program_root = self.image.?.root, .leaves = self.image.?.leaves, .multiplicities = self.multiplicities, .expected_fetches = expected, .log_size = @max(7, std.math.log2_int_ceil(usize, self.multiplicities.len)) };
        if (options.program_flavor == .sparse_elf) {
            var support: std.ArrayList(Sparse.Entry) = .empty;
            defer support.deinit(a);
            for (self.multiplicities, 0..) |value, index| if (value != 0) try support.append(a, .{ .pc = self.image.?.info.memory_layout.program_base + 4 * @as(u32, @intCast(index)), .count = value });
            self.sparse = try Sparse.Owned.fromImage(a, .{ .elf = request.elf, .elf_sha256 = request.elf_sha256, .profile = self.trusted.profile, .program_root = self.image.?.root, .expected_fetches = expected }, support.items, &self.image.?, .{ .initial = options.initial });
            self.plan = .{ .program_root = self.image.?.root, .leaves = &.{}, .multiplicities = &.{}, .expected_fetches = expected, .log_size = self.sparse.?.log_size };
            stats.program_selected_pcs = self.sparse.?.entries.len;
            self.program = try SparseROM.ForBackend(Cpu).commit(a, &self.sparse.?, request.config);
        } else {
            stats.program_selected_pcs = self.multiplicities.len;
            self.program = try ROM.ForBackend(Cpu).commit(a, self.plan, request.config);
        }
        stats.program_log_size = self.plan.log_size;
        stats.shared_providers_ns = timer.lap();
        return self;
    }
};
fn runMode(comptime receive: bool, budget: *E.host_budget_allocator.SharedHostBudget, pool: *E.work_pool.WorkPool, request: Request, options: Options) !*Outcome(receive) {
    const cycles = request.trusted_window.window.cycles;
    if (cycles == 0 or cycles > options.max_cycles or options.cohort_cycles == 0 or options.cohort_cycles > 1 << 24 or options.max_retained_endpoint_bytes == 0 or !std.meta.eql(request.elf_sha256, request.trusted_window.elf_sha256)) return error.InvalidEndpointGroupExecution;
    const n = try std.math.divCeil(u32, cycles, options.cohort_cycles);
    _ = try Layout.Plan.initWithProfile(n, 0, options.profile);
    var binding = try E.work_pool.ScopedPoolBinding.init(pool);
    defer binding.deinit();
    const a = budget.allocator();
    var whole = try std.time.Timer.start();
    var timer = try std.time.Timer.start();
    const result = try a.create(Outcome(receive));
    errdefer a.destroy(result);
    var stats = Stats{ .batch_native_projections = options.batch_native_projections, .cycles = cycles, .cohorts = n, .trace_trees = (try Layout.Plan.initWithProfile(n, 0, options.profile)).traces() };
    var prepared = try Prepared.init(a, request, options, &stats);
    var prepared_live = true;
    defer if (prepared_live) prepared.deinit();
    stats.preparation_ns = timer.lap();
    const proof = try Original.produceWithOptions(a, prepared.trusted, prepared.input(options.program_flavor, options.profile), prepared.fixed, .{ .members = prepared.stages, .endpoint_range = &prepared.ranges.?, .program = &prepared.program.?, .program_allocator = a, .lookup = &prepared.lookup.? }, options.proof, .{ .batch_native_projections = options.batch_native_projections, .program = &prepared.image.?, .max_retained_endpoint_bytes = options.max_retained_endpoint_bytes, .timings = &stats.original });
    var proof_live = true;
    defer if (proof_live) proof.deinit();
    stats.original_ns = timer.lap();
    var input = prepared.input(options.program_flavor, options.profile);
    input.members = proof.members;
    input.fixed_root = proof.fixed_root;
    input.range_main_root = proof.range_main_root;
    var statement = try Statement.Owned.init(a, prepared.trusted, input);
    var statement_live = true;
    errdefer if (statement_live) statement.deinit();
    const metadata_bytes = try Metadata.encode(a, prepared.trusted, input, options.metadata);
    errdefer a.free(metadata_bytes);
    const bytes = try Codec.encode(a, proof, prepared.trusted, input, options.codec);
    errdefer a.free(bytes);
    const endpoints = try a.alloc(Collector.Owned, n);
    errdefer a.free(endpoints);
    const leases = try a.alloc(?*Retained.Owned, n);
    errdefer a.free(leases);
    // No fallible operation occurs while moving the narrow owners.
    for (prepared.member, endpoints) |*member, *ep| {
        ep.* = member.endpoints.?;
        member.endpoints = null;
    }
    for (proof.endpoint_leases, leases) |*source, *lease| {
        lease.* = source.*;
        source.* = null;
    }
    errdefer for (endpoints) |*ep| ep.deinit();
    errdefer for (leases) |lease| if (lease) |value| value.deinit();
    stats.artifact_ns = timer.lap();
    proof.deinit();
    proof_live = false;
    prepared.deinit();
    prepared_live = false;
    if (receive) {
        statement.deinit();
        statement_live = false;
    }
    stats.producer_release_ns = timer.lap();
    var verified: if (receive) Original.OwnedVerified else void = undefined;
    if (receive) {
        statement = try Metadata.decode(a, metadata_bytes, .{ .elf = request.elf, .elf_sha256 = request.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = request.config, .cohort_count = n }, options.metadata);
        statement_live = true;
        verified = try Codec.verifyBytes(a, bytes, statement.trusted, statement.input, options.codec);
        errdefer verified.deinit();
        // Plain CPU boundaries must match independently pinned snapshots. RAM
        // remains OPEN until the later endpoint bridge/global original.
        if (verified.summary.global_first_cycle != 1 or !std.meta.eql(verified.summary.initial_regs, request.incoming.cpu.regs) or !std.meta.eql(verified.summary.final_regs, request.outgoing.cpu.regs) or verified.summary.initial_pc != request.incoming.cpu.pc or verified.summary.final_pc != request.outgoing.cpu.pc) return error.EndpointGroupBoundaryMismatch;
        stats.fresh_verification_ns = timer.lap();
    }
    stats.proof_bytes = bytes.len;
    stats.whole_ns = whole.read();
    stats.charged_peak_bytes = budget.snapshot().peak_live_bytes;
    result.* = .{ .a = a, .budget = budget.retain(), .statement = statement, .proof_bytes = bytes, .metadata_bytes = metadata_bytes, .verified = verified, .endpoints = endpoints, .leases = leases, .stats = stats };
    return result;
}

/// Standalone original qualification, receiving actual bytes once.
pub fn run(budget: *E.host_budget_allocator.SharedHostBudget, pool: *E.work_pool.WorkPool, request: Request, options: Options) !*Result {
    return runMode(true, budget, pool, request, options);
}
/// Build/prove/serialize only. The returned bytes and endpoint leases are
/// nominations, not proof authority. A complete bundle MUST verify those
/// original bytes itself exactly once before accepting any exported source.
pub fn runUnchecked(budget: *E.host_budget_allocator.SharedHostBudget, pool: *E.work_pool.WorkPool, request: Request, options: Options) !*UncheckedResult {
    return runMode(false, budget, pool, request, options);
}

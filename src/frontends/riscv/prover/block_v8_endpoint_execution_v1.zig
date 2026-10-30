//! Experimental, native-only B8 execution window. Builds each native witness
//! once; never constructs an old per-access WORD witness or checkpoint.
//! A window proves no skipped prefix and is not whole-block publication.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Capture = @import("block_v7_real_window_capture_v1.zig");
const Window = @import("block_v7_real_window_policy_v2.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Execution = @import("block_v5_cpu_execution_source_v1.zig");
const Native = @import("blake3_execution_trace.zig");
const Collect = @import("block_v8_ram_endpoint_collector_v1.zig");
const Range = @import("block_v8_endpoint_range_provider_v1.zig");
const Scope = @import("block_v8_endpoint_whole_scope_v1.zig");
const Whole = @import("block_v8_endpoint_whole_proof_v1.zig");
const Statement = @import("block_v8_endpoint_whole_statement_v1.zig");
const Memory = @import("block_v7_window_memory_joint_v1.zig");
const Lookup = @import("block_v7_lookup_compact_proof_v1.zig");
const LP = @import("block_v5_native_lookup_plan_v1.zig");
const Counters = @import("../air/lookups/tables/counter.zig");
const ROM = @import("block_v7_program_provider_v1.zig");
const Bridge = @import("block_execution_access_bridge_v2.zig");
const Trace = @import("../runner/trace.zig");
const Q = core.fields.qm31.QM31;
pub const production_active = false;
pub const Request = struct {
    elf: []const u8,
    elf_sha256: [32]u8,
    config: core.pcs.PcsConfig,
    incoming: Capture.Snapshot,
    outgoing: Capture.Snapshot,
    trusted_window: Window.Trusted,
};
pub const Options = struct {
    max_cycles: u32 = 1 << 23,
    max_events: usize = 1 << 24,
    initial: Initial.Limits = .{},
    capture: Capture.Limits = .{ .max_window_cycles = 1 << 23 },
    collector: Collect.Limits = .{},
    range: Range.Limits = .{},
    memory: Memory.Limits = .{ .memory = .{ .max_events = 1 << 24, .max_row_log = 24, .max_matrix_bytes = 4 << 30 }, .max_live_bytes = 16 << 30 },
    proof: Whole.Limits = .{ .context = .{ .memory = .{ .memory = .{ .max_events = 1 << 24, .max_row_log = 24, .max_matrix_bytes = 4 << 30 }, .max_live_bytes = 16 << 30 } } },
    ram_rows_per_shard: u32 = 1 << 20,
};
pub const Stats = struct {
    // Remains false until the independent every-access halt policy is proved.
    semantics_qualified: bool = false,
    policy_ns: u64 = 0,
    restore_ns: u64 = 0,
    execution_ns: u64 = 0,
    snapshot_check_ns: u64 = 0,
    native_witness_ns: u64 = 0,
    event_extraction_ns: u64 = 0,
    endpoints_ns: u64 = 0,
    sparse_policy_ns: u64 = 0,
    ranges_lookup_ns: u64 = 0,
    rom_census_ns: u64 = 0,
    runner_release_ns: u64 = 0,
    program_ns: u64 = 0,
    memory_ns: u64 = 0,
    original_ns: u64 = 0,
    metadata_ns: u64 = 0,
    release_ns: u64 = 0,
    fresh_verification_ns: u64 = 0,
    whole_ns: u64 = 0,
    cycles: u32 = 0,
    logical_ram_events: usize = 0,
    endpoint_count: usize = 0,
    native_components: u32 = 0,
    native_main_cells: u64 = 0,
    endpoint_cells: u64 = 0,
    global_ram_rows: u64 = 0,
    original: Whole.ProveTimings = .{},
};
pub const Artifact = struct {
    a: std.mem.Allocator,
    proof: *Whole.Proof,
    statement: *Statement.Owned,
    stats: Stats,
    pub fn deinit(self: *Artifact) void {
        self.proof.deinit();
        self.statement.deinit();
        self.a.destroy(self);
    }
};
pub fn makeCurrent(a: std.mem.Allocator, owned: @import("../runner/result.zig").EthereumShaSegmentResult, root: [32]u8) !*Execution.Current {
    var segment = owned;
    errdefer segment.deinit();
    if (try Execution.externalCount(&segment) != 0) return error.UnsupportedEndpointExecutionCaller;
    var io = try @import("blake3_segment_public.zig").Owned.init(a, &segment.base);
    errdefer io.deinit();
    io.data.program_root = .{ .bytes = root };
    io.data.initial_rw_root = null;
    io.data.final_rw_root = null;
    io.data.io_entries.input_len = 0;
    io.data.io_entries.input_words = &.{};
    io.data.io_entries.output_len = 0;
    io.data.io_entries.output_words = &.{};
    const owner = try Native.Owner.initWithExternal(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker, 0);
    errdefer owner.deinit();
    try owner.sealNativeOnly();
    const current = try a.create(Execution.Current);
    current.* = .{ .a = a, .segment = segment, .io = io, .owner = owner, .recipe = .custody_v2 };
    return current;
}
/// Restore exact complete-snapshot semantics once at the start of a window.
/// Missing initialized mutable words mean zero, not their ELF loader value.
/// Both whole-original and late-memory execution share this implementation.
pub fn restoreSession(a: std.mem.Allocator, session: *@import("../runner/mod.zig").EthereumShaExecutionSession, incoming: Capture.Snapshot) !void {
    const addresses = try a.alloc(u32, incoming.words.len);
    defer a.free(addresses);
    for (addresses, incoming.words) |*address, word| address.* = word.address;
    for (try session.memory.canonicalAlignedWordAddresses()) |address| session.memory.writeU32AssumePrepared(address, 0);
    try session.memory.prepareAlignedWordWrites(addresses);
    for (incoming.words) |word| session.memory.writeU32AssumePrepared(word.address, word.value);
    session.cpu = incoming.cpu;
}
/// Read actual RAM tuples from the same native main columns consumed by the
/// typed AIR. Synthetic RAM clock-gap rows are deliberately not real accesses.
/// The restored native clock relation, not this host extraction, proves gaps.
pub fn extractEvents(a: std.mem.Allocator, owner: *const Native.Owner, frame: Collect.Frame, max_events: usize) ![]Collect.Transition {
    var events: std.ArrayList(Collect.Transition) = .empty;
    errdefer events.deinit(a);
    for (owner.statement.component_descs[0..owner.statement.n_components], 0..) |desc, ci| {
        // All non-load/store opcode families have only register tuples. Do not
        // accidentally project their word-index register addresses into RAM.
        if (desc.family != .load_store) continue;
        const width = Trace.nColumnsForFamily(desc.family);
        const columns = &owner.opcode_columns.components[ci];
        var row: [Trace.MAX_FAMILY_COLUMNS]Q = undefined;
        for (0..(@as(usize, 1) << @intCast(desc.log_size))) |physical| {
            for (row[0..width], columns.columns[0..width]) |*value, column| value.* = Q.fromBase(column[physical]);
            const pairs = try Bridge.fromCommittedMain(Q, desc.family, row[0..width]);
            for (pairs.items[0..pairs.len], 0..) |pair, slot| {
                if (!Bridge.hasConditionalSpace(desc.family, slot)) continue;
                const decoded = try Bridge.decodePair(try Bridge.rwPairForMode(Q, desc.family, slot, pair, 1));
                if (!decoded.active) continue;
                if (decoded.space != 1 or pair.address_unit != .byte_address) return error.InvalidEndpointExecutionRamProjection;
                if (events.items.len >= max_events) return error.EndpointExecutionEventLimit;
                try events.append(a, .{ .space = 1, .address = decoded.source_address, .clock = try frame.globalClock(decoded.local_clock), .before = decoded.before, .after = decoded.after });
            }
        }
    }
    return events.toOwnedSlice(a);
}
pub const LookupPreparation = struct {
    ranges: Range.Owned,
    lookup: Lookup.For(Cpu).Stage,
    plan: LP.Plan,
    pub fn init(a: std.mem.Allocator, owner: *const Native.Owner, endpoints: *const Collect.Owned, config: core.pcs.PcsConfig, range_limits: Range.Limits, lookup_limits: Lookup.Limits) !LookupPreparation {
        var ranges = try Range.Owned.init(a, endpoints.matrix, @intCast(endpoints.endpoints.len), range_limits);
        errdefer ranges.deinit();
        var counters = try Counters.Set.init(a);
        defer counters.deinit(a);
        counters.mergeFrom(&owner.opcode_columns.lookup_counters.?);
        var demand = try @import("block_v8_native_endpoint_profile_v1.zig").nativeDemand(&owner.statement, owner.native_profile);
        try ranges.appendToLookup(counters.get(.range_check_8_8), &demand);
        const plan = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = demand };
        const lookup = try Lookup.For(Cpu).Stage.init(a, &counters, plan, config, null, lookup_limits);
        return .{ .ranges = ranges, .lookup = lookup, .plan = plan };
    }
    pub fn deinit(self: *LookupPreparation) void {
        self.lookup.deinit();
        self.ranges.deinit();
    }
};
pub const ProgramCensus = struct {
    a: std.mem.Allocator,
    multiplicities: []u64,
    plan: @import("block_v5_program_table_v1.zig").Plan,
    pub fn deinit(self: *ProgramCensus) void {
        self.a.free(self.multiplicities);
    }
};
pub fn collectProgramCensus(a: std.mem.Allocator, current: *const Execution.Current, program_root: @import("../air/memory_commitment/blake3_state_tree.zig").Digest, leaves: []const @import("../air/memory_commitment/blake3_state_tree.zig").Leaf, program_base: u32) !ProgramCensus {
    const multiplicities = try a.alloc(u64, leaves.len / 4);
    errdefer a.free(multiplicities);
    @memset(multiplicities, 0);
    const fetches = try Execution.fetches(a, current, false);
    defer a.free(fetches);
    var total: u64 = 0;
    for (fetches) |fetch| {
        if (fetch.address < program_base or fetch.address & 3 != 0 or (fetch.address - program_base) / 4 >= multiplicities.len) return error.InvalidEndpointProgramFetch;
        const at = (fetch.address - program_base) / 4;
        multiplicities[at] = try std.math.add(u64, multiplicities[at], fetch.multiplicity);
        total = try std.math.add(u64, total, fetch.multiplicity);
    }
    return .{ .a = a, .multiplicities = multiplicities, .plan = .{ .program_root = program_root, .leaves = leaves, .multiplicities = multiplicities, .expected_fetches = total, .log_size = @max(7, std.math.log2_int_ceil(usize, multiplicities.len)) } };
}
pub fn run(budget: *engine.host_budget_allocator.SharedHostBudget, pool: *engine.work_pool.WorkPool, request: Request, options: Options) !*Artifact {
    const a = budget.allocator();
    if (request.trusted_window.window.cycles == 0 or request.trusted_window.window.cycles > options.max_cycles or options.ram_rows_per_shard == 0 or options.max_events == 0 or !std.meta.eql(request.elf_sha256, request.trusted_window.elf_sha256)) return error.InvalidEndpointExecutionRequest;
    var binding = try engine.work_pool.ScopedPoolBinding.init(pool);
    defer binding.deinit();
    var whole = try std.time.Timer.start();
    var timer = try std.time.Timer.start();
    var stats = Stats{ .cycles = request.trusted_window.window.cycles };
    const artifact = try a.create(Artifact);
    errdefer a.destroy(artifact);
    // This block's producers all expire before the fresh receiver below.
    {
        var selected = try Window.Owned.derive(a, request.elf, request.incoming, request.outgoing, request.trusted_window, options.initial);
        defer selected.deinit();
        var image = try @import("block_v7_program_image_v1.zig").Owned.init(a, request.elf, &selected.initial, options.initial);
        defer image.deinit();
        stats.policy_ns = timer.lap();
        var session = try @import("../runner/mod.zig").EthereumShaExecutionSession.init(a, request.elf, .{ .input = &.{}, .trace_retention = .segment_owned, .clock_frame = .leaf_local, .stop_on_halt_flag = true, .require_current_output_accesses = false });
        var session_live = true;
        defer if (session_live) session.deinit();
        try restoreSession(a, &session, request.incoming);
        stats.restore_ns = timer.lap();
        const segment = try session.startSegment(stats.cycles);
        // makeCurrent owns segment on every success and failure path.
        stats.execution_ns = timer.lap();
        const current = try makeCurrent(a, segment, image.root.bytes);
        var current_live = true;
        defer if (current_live) current.deinit();
        stats.native_witness_ns = timer.lap();
        if (current.segment.base.cycle_count != stats.cycles or current.segment.base.continuation == null) return error.EndpointExecutionWindowIncomplete;
        var outgoing = try Capture.snapshot(a, session.cpu, &session.memory, options.capture);
        defer outgoing.deinit(a);
        if (!std.meta.eql(outgoing.identity(), request.trusted_window.outgoing_sha256)) return error.EndpointExecutionOutgoingMismatch;
        stats.snapshot_check_ns = timer.lap();
        const owner = current.owner;
        var native_transferred = false;
        defer if (native_transferred) owner.deinit();
        stats.native_components = owner.statement.n_components;
        for (owner.main.items) |column| stats.native_main_cells += column.values.len;
        const frame = Collect.Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = stats.cycles };
        const events = try extractEvents(a, owner, frame, options.max_events);
        defer a.free(events);
        stats.logical_ram_events = events.len;
        stats.event_extraction_ns = timer.lap();
        var endpoints = try Collect.collectGlobal(a, .{ .frame = frame, .cohort_ordinal = 0, .cohort_count = 1 }, events, options.collector);
        defer endpoints.deinit();
        stats.endpoint_count = endpoints.endpoints.len;
        stats.endpoint_cells = endpoints.matrix.columns.len * (@as(usize, 1) << @intCast(endpoints.matrix.log));
        stats.endpoints_ns = timer.lap();
        const selected_addresses = try a.alloc(u32, endpoints.endpoints.len);
        defer a.free(selected_addresses);
        for (selected_addresses, endpoints.endpoints) |*address, endpoint| address.* = endpoint.address;
        try selected.selectAddresses(selected_addresses, options.initial);
        const policy = @import("block_v7_execution_policy_v1.zig").Policy{ .initialized = &selected.initial, .program_root = image.root.bytes, .terminal = .{ .final_cycle = stats.cycles, .halt_address = selected.initial.info.halt_flag, .length_address = selected.initial.info.output_len, .data_address = selected.initial.info.output_data, .output_end = selected.initial.info.output_end, .output = @splat(0) }, .config = request.config, .window = &selected };
        stats.sparse_policy_ns = timer.lap();
        var providers = try LookupPreparation.init(a, owner, &endpoints, request.config, options.range, options.proof.context.lookup);
        defer providers.deinit();
        const lookup_plan = providers.plan;
        stats.ranges_lookup_ns = timer.lap();
        var census = try collectProgramCensus(a, current, image.root, image.leaves, selected.initial.info.memory_layout.program_base);
        defer census.deinit();
        const program_plan = census.plan;
        stats.rom_census_ns = timer.lap();
        // Columns are independently owned. Retire the original execution rows,
        // clock tracker, segment snapshots and runner memory before the wide
        // PCS/proof peak; no re-execution or reconstructed witness is needed.
        _ = try current.takeNativeOwner();
        native_transferred = true;
        current.deinit();
        current_live = false;
        session.deinit();
        session_live = false;
        stats.runner_release_ns = timer.lap();

        var program = try ROM.ForBackend(Cpu).commit(a, program_plan, request.config);
        defer program.deinit(a);
        stats.program_ns = timer.lap();
        const memory = try Memory.For(Cpu).Stage.init(a, policy, endpoints.net_transitions, 0, options.ram_rows_per_shard, options.memory);
        defer memory.deinit();
        const geometries = try a.alloc(@import("block_v5_ram_lanes_protocol_v1.zig").Claim, memory.witness.ram.len);
        defer a.free(geometries);
        for (geometries, memory.witness.ram) |*geometry, part| {
            geometry.* = part.geometry;
            stats.global_ram_rows += @as(u64, 1) << @intCast(part.geometry.row_log);
        }
        stats.memory_ns = timer.lap();
        const trusted = @import("block_v7_execution_receiver_v1.zig").Trusted{ .elf = request.elf, .elf_sha256 = request.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .terminal = policy.terminal, .config = request.config, .window = &selected };
        var input = Scope.Input{ .shape = &owner.statement, .frame = frame, .endpoint_count = @intCast(endpoints.endpoints.len), .native_roots = @splat(@splat(0)), .program_plan = program_plan, .program_roots = program.roots, .lookup_plan = lookup_plan, .lookup_layout = providers.lookup.layout, .lookup_roots = providers.lookup.roots, .memory_geometry = geometries, .memory_roots = memory.roots, .memory_interval_log = memory.witness.interval.log };
        artifact.proof = try Whole.produceWithOptions(a, trusted, input, owner.preprocessed.items, .{ .native_main = owner.main.items, .endpoints = &endpoints, .endpoint_range = &providers.ranges, .program = &program, .program_allocator = a, .lookup = &providers.lookup, .memory = memory }, options.proof, .{ .timings = &stats.original });
        errdefer artifact.proof.deinit();
        stats.original_ns = timer.lap();
        input.native_roots = artifact.proof.native_roots;
        artifact.statement = try Statement.Owned.init(a, trusted, input);
        errdefer artifact.statement.deinit();
        stats.metadata_ns = timer.lap();
    }
    errdefer artifact.proof.deinit();
    errdefer artifact.statement.deinit();
    stats.release_ns = timer.lap();
    // Re-derive complete snapshot trust independently after all native/endpoint
    // witnesses, runtime state and source provider stages have been destroyed.
    const selection = artifact.statement.trusted.window.?.selection orelse return error.MissingEndpointExecutionSelection;
    var external = try Window.Owned.deriveForAddresses(a, request.elf, request.incoming, request.outgoing, request.trusted_window, selection.addresses, options.initial);
    defer external.deinit();
    var trusted = artifact.statement.trusted;
    trusted.window = &external;
    _ = try Whole.verify(a, trusted, artifact.statement.input, &artifact.proof.stark, artifact.proof.claims, options.proof);
    stats.fresh_verification_ns = timer.lap();
    stats.whole_ns = whole.read();
    artifact.a = a;
    artifact.stats = stats;
    return artifact;
}

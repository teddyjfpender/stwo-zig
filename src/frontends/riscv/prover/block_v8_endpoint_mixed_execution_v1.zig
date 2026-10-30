//! Resident captured-window preparation over the actual native/caller stream.
//! No WORD sidecar, caller checkpoint or duplicate companion proof is built.
//! Source preparation is not proof authority and skips no proof obligation.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Execution = @import("block_v5_cpu_execution_source_v1.zig");
const Prepare = @import("block_v8_endpoint_execution_v1.zig");
const Scope = @import("block_v8_endpoint_mixed_scope_v1.zig");
const Context = @import("block_v8_endpoint_mixed_context_v1.zig");
const Raw = @import("block_v8_endpoint_caller_raw_stage_v1.zig");
const Image = @import("block_v8_endpoint_local_program_v1.zig");
const Collector = @import("block_v8_ram_endpoint_collector_v1.zig");
const Range = @import("block_v8_endpoint_range_provider_v1.zig");
const Lookup = @import("block_v7_lookup_compact_proof_v1.zig");
const ROM = @import("block_v7_program_provider_v1.zig");
const Capture = @import("block_v7_real_window_capture_v1.zig");
const P = @import("blake3_ethereum_sha_profile.zig");
const LP = @import("block_v5_native_lookup_plan_v1.zig");
const Q = core.fields.qm31.QM31;
pub const Request = Prepare.Request;
pub const Options = struct {
    max_cycles: u32 = 1 << 20,
    native_wide_shards: bool = false,
    max_endpoint_events: usize = 1 << 24,
    caller: Raw.Limits = .{},
    collector: Collector.Limits = .{},
    boundary: @import("block_v8_execution_boundary_ports_v1.zig").Options = .{},
    program_flavor: Scope.RomFlavor = .sparse_elf,
};
pub const Stats = struct { image_ns: u64 = 0, restore_ns: u64 = 0, execution_ns: u64 = 0, native_ns: u64 = 0, caller_ns: u64 = 0, endpoint_ns: u64 = 0, providers_ns: u64 = 0, whole_ns: u64 = 0 };
pub const Owned = struct {
    a: std.mem.Allocator,
    elf: []u8 = &.{},
    image: ?Image.Owned = null,
    current: ?*Execution.Current = null,
    caller: ?*Raw.Owned = null,
    endpoints: ?Collector.Owned = null,
    ranges: ?Range.Owned = null,
    census: ?Prepare.ProgramCensus = null,
    lookup: ?Lookup.For(Cpu).Stage = null,
    program: ?ROM.ForBackend(Cpu).FirstRound = null,
    /// External snapshots are borrowed; request owner must outlive preparation.
    incoming: ?Capture.Snapshot = null,
    outgoing: ?Capture.Snapshot = null,
    sparse_rom: ?@import("block_v8_sparse_rom_v1.zig").Owned = null,
    program_flavor: Scope.RomFlavor = .legacy_complete,
    stats: Stats = .{},
    lookup_plan: LP.Plan = undefined,
    trusted: Scope.Trusted = undefined,
    pub fn init(a: std.mem.Allocator, request: Request, options: Options) !*Owned {
        const cycles = request.trusted_window.window.cycles;
        try options.boundary.validate();
        if (options.boundary.initial) |initial| {
            if (request.trusted_window.window.skip_cycles != 0 or !std.meta.eql(initial.snapshot_id, request.incoming.identity()) or !std.meta.eql(initial.cpu, request.incoming.cpu)) return error.UntrustedMixedInitialBoundary;
        }
        if (options.boundary.terminal) |terminal| {
            if (try std.math.add(u64, request.trusted_window.window.skip_cycles, cycles) != terminal.policy.final_cycle) return error.UntrustedMixedTerminalCoverage;
        }
        if (cycles == 0 or cycles > options.max_cycles or options.max_endpoint_events == 0 or !std.meta.eql(request.elf_sha256, request.trusted_window.elf_sha256) or !std.meta.eql(request.incoming.identity(), request.trusted_window.incoming_sha256) or !std.meta.eql(request.outgoing.identity(), request.trusted_window.outgoing_sha256)) return error.UntrustedMixedExecutionRequest;
        var whole = try std.time.Timer.start();
        var timer = try std.time.Timer.start();
        const self = try a.create(Owned);
        self.* = .{ .a = a, .program_flavor = options.program_flavor };
        errdefer self.deinit();
        self.elf = try a.dupe(u8, request.elf);
        const config = request.config;
        const pin = Capture.sha(self.elf);
        if (!std.meta.eql(pin, request.elf_sha256)) return error.UntrustedMixedExecutionElf;
        self.trusted = .{ .elf = self.elf, .elf_sha256 = pin, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = 1 };
        if (options.boundary.terminal) |terminal| {
            self.trusted.terminal_cycle = cycles;
            self.trusted.boundary_policy_id = terminal.policy_id;
        }
        self.image = try Image.Owned.init(a, self.elf, pin, .rv32im_zkvm_ethereum_sha_v1, .{});
        self.stats.image_ns = timer.lap();
        var session = try @import("../runner/mod.zig").EthereumShaExecutionSession.init(a, self.elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned, .native_wide_shards = options.native_wide_shards, .stop_on_halt_flag = true, .require_current_output_accesses = false });
        defer session.deinit();
        try Prepare.restoreSession(a, &session, request.incoming);
        self.incoming = request.incoming;
        self.outgoing = request.outgoing;
        self.stats.restore_ns = timer.lap();
        var segment = try session.startSegment(cycles);
        var segment_live = true;
        defer if (segment_live) segment.deinit();
        if (segment.base.cycle_count != cycles) return error.IncompleteMixedExecutionWindow;
        if (options.boundary.terminal) |terminal| {
            if (terminal.policy.halt_address != self.image.?.info.halt_flag or segment.base.continuation != null or segment.base.completion_reason != .halt_flag or segment.base.completion_address != terminal.policy.halt_address or segment.base.completion_value != 1 or segment.base.completion_clock != @import("../access_clock.zig").maximum(cycles)) return error.IncompleteMixedTerminalWindow;
        } else if (segment.base.continuation == null) return error.IncompleteMixedExecutionWindow;
        var actual = try Capture.snapshot(a, session.cpu, &session.memory, .{ .max_window_cycles = cycles });
        defer actual.deinit(a);
        if (!std.meta.eql(actual.identity(), request.trusted_window.outgoing_sha256)) return error.MixedExecutionOutgoingMismatch;
        self.stats.execution_ns = timer.lap();
        self.caller = try Raw.Owned.initSegment(a, &segment, options.caller);
        self.stats.caller_ns = timer.lap();
        const external = P.externalCount(&self.caller.?.witness.statement);
        if (external == 0 or external >= cycles) return error.InvalidMixedExecutionCensus;
        var io = try @import("blake3_segment_public.zig").Owned.init(a, &segment.base);
        var io_live = true;
        defer if (io_live) io.deinit();
        io.data.program_root = self.image.?.root;
        io.data.initial_rw_root = null;
        io.data.final_rw_root = null;
        io.data.io_entries.input_len = 0;
        io.data.io_entries.input_words = &.{};
        io.data.io_entries.output_len = 0;
        io.data.io_entries.output_words = &.{};
        const native = try @import("blake3_execution_trace.zig").Owner.initWithExternal(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker, external);
        var native_live = true;
        defer if (native_live) native.deinit();
        try native.sealNativeOnly();
        const current = try a.create(Execution.Current);
        current.* = .{ .a = a, .segment = segment, .io = io, .owner = native, .recipe = .custody_v2 };
        self.current = current;
        segment_live = false;
        io_live = false;
        native_live = false;
        self.stats.native_ns = timer.lap();
        const frame = Collector.Frame{ .clock_frame = current.segment.base.clock_frame, .global_first_cycle = current.segment.base.global_first_cycle, .cycle_count = cycles };
        const native_events = try Prepare.extractEvents(a, native, frame, options.max_endpoint_events);
        defer a.free(native_events);
        var events: std.ArrayList(Collector.Transition) = .empty;
        defer events.deinit(a);
        try events.appendSlice(a, native_events);
        try appendCallerEvents(a, &events, self.caller.?, frame, options.max_endpoint_events);
        self.endpoints = try Collector.collectGlobal(a, .{ .frame = frame, .cohort_ordinal = 0, .cohort_count = 1 }, events.items, options.collector);
        self.ranges = try Range.Owned.init(a, self.endpoints.?.matrix, @intCast(self.endpoints.?.endpoints.len), .{});
        self.stats.endpoint_ns = timer.lap();
        var counters = try @import("../air/lookups/tables/counter.zig").Set.init(a);
        defer counters.deinit(a);
        counters.mergeFrom(&native.opcode_columns.lookup_counters.?);
        try (@import("../air/guest_precompile/ethereum_lookup_registration.zig").Context{ .keccak = current.segment.extension.keccakf_calls.records(), .recovery = current.segment.extension.signer_recovery_calls.records() }).register(&counters);
        try @import("block_v7_caller_active_columns_v1.zig").registerLookup(a, &self.caller.?.witness, &counters);
        var demand = try LP.nativeDemand(&native.statement, external);
        try @import("block_v5_precompile_table_demand_v1.zig").add(a, &demand, &self.caller.?.witness.statement, cycles, config);
        try self.ranges.?.appendToLookup(counters.get(.range_check_8_8), &demand);
        self.lookup_plan = .{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = demand };
        self.lookup = try Lookup.For(Cpu).Stage.init(a, &counters, self.lookup_plan, config, null, .{});
        self.census = try Prepare.collectProgramCensus(a, current, self.image.?.root, self.image.?.leaves, self.image.?.info.memory_layout.program_base);
        if (options.program_flavor == .sparse_elf) {
            const Sparse = @import("block_v8_sparse_rom_v1.zig");
            var support: std.ArrayList(Sparse.Entry) = .empty;
            defer support.deinit(a);
            for (self.census.?.plan.multiplicities, 0..) |count, i| if (count != 0) try support.append(a, .{ .pc = self.image.?.info.memory_layout.program_base + 4 * @as(u32, @intCast(i)), .count = count });
            self.sparse_rom = try Sparse.Owned.fromImage(a, .{ .elf = self.elf, .elf_sha256 = pin, .profile = self.trusted.profile, .program_root = self.image.?.root, .expected_fetches = self.census.?.plan.expected_fetches }, support.items, &self.image.?, .{});
            self.program = try @import("block_v8_sparse_rom_provider_v1.zig").ForBackend(Cpu).commit(a, &self.sparse_rom.?, config);
            a.free(self.census.?.multiplicities);
            self.census.?.multiplicities = &.{};
            self.census.?.plan.multiplicities = &.{};
        } else self.program = try ROM.ForBackend(Cpu).commit(a, self.census.?.plan, config);
        self.stats.providers_ns = timer.lap();
        self.stats.whole_ns = whole.read();
        return self;
    }
    pub fn input(self: *const Owned) Scope.Input {
        const current = self.current.?;
        const plan = if (self.sparse_rom) |sparse| @import("block_v5_program_table_v1.zig").Plan{ .program_root = sparse.trusted.program_root, .leaves = &.{}, .multiplicities = &.{}, .expected_fetches = sparse.trusted.expected_fetches, .log_size = sparse.log_size } else self.census.?.plan;
        return .{ .rom_flavor = self.program_flavor, .sparse_support = if (self.sparse_rom) |sparse| sparse.entries else &.{}, .shape = &current.owner.statement, .caller_statement = &self.caller.?.witness.statement, .frame = .{ .clock_frame = current.segment.base.clock_frame, .global_first_cycle = current.segment.base.global_first_cycle, .cycle_count = @intCast(current.segment.base.cycle_count) }, .cohort_ordinal = 0, .endpoint_count = @intCast(self.endpoints.?.endpoints.len), .native_roots = @splat(@splat(0)), .caller_roots = @splat(@splat(0)), .program_plan = plan, .program_roots = self.program.?.roots, .lookup_plan = self.lookup_plan, .lookup_layout = self.lookup.?.layout, .lookup_roots = self.lookup.?.roots };
    }
    pub fn stages(self: *Owned) Context.Stages {
        return .{ .native_main = self.current.?.owner.main.items, .caller = self.caller.?, .caller_main = self.caller.?.main, .endpoints = &self.endpoints.?, .endpoint_range = &self.ranges.?, .program = &self.program.?, .program_allocator = self.a, .lookup = &self.lookup.? };
    }
    pub fn deinit(self: *Owned) void {
        if (self.program) |*v| v.deinit(self.a);
        if (self.lookup) |*v| v.deinit();
        if (self.census) |*v| v.deinit();
        if (self.ranges) |*v| v.deinit();
        if (self.endpoints) |*v| v.deinit();
        if (self.caller) |v| v.deinit();
        if (self.current) |v| v.deinit();
        if (self.sparse_rom) |*v| v.deinit();
        if (self.image) |*v| v.deinit();
        self.a.free(self.elf);
        self.a.destroy(self);
    }
};
fn appendCallerEvents(a: std.mem.Allocator, events: *std.ArrayList(Collector.Transition), raw: *const Raw.Owned, frame: Collector.Frame, maximum: usize) !void {
    for (raw.plan.ram.descriptors) |descriptor| {
        const rows = @as(usize, 1) << @intCast(descriptor.log_size);
        for (0..rows) |row| {
            const Samples = struct {
                raw: *const Raw.Owned,
                descriptor: @TypeOf(descriptor),
                row: usize,
                pub fn at(self: @This(), tree: usize, index: usize, ordinal: usize) !Q {
                    const columns = if (tree == 0) self.raw.fixed else if (tree == 1) self.raw.main else return error.InvalidMixedExecutionSample;
                    if (index >= columns.len or columns[index].log_size != self.descriptor.log_size or ordinal > 1) return error.InvalidMixedExecutionSample;
                    const physical = if (ordinal == 0) self.row else core.utils.offsetBitReversedCircleDomainIndex(self.row, self.descriptor.log_size, self.descriptor.log_size, 27);
                    return Q.fromBase(columns[index].values[physical]);
                }
            };
            const access = try @import("block_v8_caller_ram_component_v1.zig").accessFromSamples(descriptor, Samples{ .raw = raw, .descriptor = descriptor, .row = row });
            const decoded = try @import("block_execution_access_bridge_v2.zig").decodePair(access.pair);
            if (!decoded.active) continue;
            if (decoded.space != 1 or access.pair.address_unit != .byte_address) return error.InvalidMixedExecutionRam;
            if (events.items.len >= maximum) return error.MixedExecutionEventLimit;
            try events.append(a, .{ .space = 1, .address = decoded.source_address, .clock = try frame.globalClock(decoded.local_clock), .before = decoded.before, .after = decoded.after });
        }
    }
}

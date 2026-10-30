//! Actual executed mixed-cohort preparation. No WORD/access sidecar or old
//! caller commitment is constructed. This is test support, not proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Execution = @import("../block_v5_cpu_execution_source_v1.zig");
const Prepare = @import("../block_v8_endpoint_execution_v1.zig");
const Scope = @import("../block_v8_endpoint_mixed_scope_v1.zig");
const Context = @import("../block_v8_endpoint_mixed_context_v1.zig");
const Raw = @import("../block_v8_endpoint_caller_raw_stage_v1.zig");
const Image = @import("../block_v8_endpoint_local_program_v1.zig");
const Collector = @import("../block_v8_ram_endpoint_collector_v1.zig");
const Range = @import("../block_v8_endpoint_range_provider_v1.zig");
const Lookup = @import("../block_v7_lookup_compact_proof_v1.zig");
const ROM = @import("../block_v7_program_provider_v1.zig");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const P = @import("../blake3_ethereum_sha_profile.zig");
const LP = @import("../block_v5_native_lookup_plan_v1.zig");
const Q = core.fields.qm31.QM31;
pub const Kind = enum { sha_keccak, recovery, transient_halt, transient_halt_control };
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
    incoming: ?Capture.Snapshot = null,
    outgoing: ?Capture.Snapshot = null,
    lookup_plan: LP.Plan = undefined,
    trusted: Scope.Trusted = undefined,
    pub fn init(a: std.mem.Allocator, kind: Kind, config: core.pcs.PcsConfig) !*Owned {
        return initMode(a, kind, config, false);
    }
    /// Global initialization requires a positive aligned private-input ABI
    /// span. This synthetic fixture supplies an unused span before execution;
    /// the legacy standalone fixture ELF and snapshots remain unchanged.
    pub fn initForGlobal(a: std.mem.Allocator, kind: Kind, config: core.pcs.PcsConfig) !*Owned {
        return initMode(a, kind, config, true);
    }
    fn initMode(a: std.mem.Allocator, kind: Kind, config: core.pcs.PcsConfig, for_global: bool) !*Owned {
        const self = try a.create(Owned);
        self.* = .{ .a = a };
        errdefer self.deinit();
        const Elf = @import("../../runner/guest_precompile/test_elf.zig");
        self.elf = switch (kind) {
            .sha_keccak => blk: {
                const s = Elf.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
                const e = Elf.withReleaseAbi(s.len, &s);
                break :blk try a.dupe(u8, &e);
            },
            .recovery => blk: {
                const s = Elf.buildEthereumWithCompletionForProfile(.self_loop, .rv32im_zkvm_ethereum_sha_v1);
                const e = Elf.withReleaseAbi(s.len, &s);
                break :blk try a.dupe(u8, &e);
            },
            .transient_halt, .transient_halt_control => blk: {
                const original = Elf.buildEthereumWithCompletionForProfile(.self_loop, .rv32im_zkvm_ethereum_sha_v1);
                var e = Elf.withReleaseAbi(original.len, &original);
                const code_offset = std.mem.readInt(u32, e[56..60], .little);
                const status_offset = @import("../../isa/ethereum_signer_recovery.zig").status_offset;
                const clear_status = ((status_offset >> 5) << 25) | ((status_offset & 31) << 7) | (5 << 15) | (2 << 12) | 0x23;
                std.mem.writeInt(u32, e[code_offset + 3 * 4 ..][0..4], clear_status, .little);
                std.mem.writeInt(u32, e[code_offset + 4 * 4 ..][0..4], 0x0000006f, .little);
                if (kind == .transient_halt) {
                    const table = std.mem.readInt(u32, e[264..268], .little);
                    for (@import("../../runner/elf_loader.zig").RELEASE_ABI_SYMBOLS, 0..) |symbol, i| if (std.mem.eql(u8, symbol, "__halt_flag")) {
                        std.mem.writeInt(u32, e[table + (i + 1) * 16 + 4 ..][0..4], 0x100100 + status_offset, .little);
                    };
                }
                break :blk try a.dupe(u8, &e);
            },
        };
        if (for_global) {
            const table = std.mem.readInt(u32, self.elf[264..268], .little);
            for ([2]usize{ 7, 8 }, [2]u32{ 0x100800, 0x100810 }) |index, value| std.mem.writeInt(u32, self.elf[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
        }
        const pin = Capture.sha(self.elf);
        self.trusted = .{ .elf = self.elf, .elf_sha256 = pin, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = 1 };
        self.image = try Image.Owned.init(a, self.elf, pin, .rv32im_zkvm_ethereum_sha_v1, .{});
        var session = try @import("../../runner/mod.zig").EthereumShaExecutionSession.init(a, self.elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned, .stop_on_halt_flag = false });
        defer session.deinit();
        const cycles: u32 = if (kind == .sha_keccak) 6 else 4;
        self.incoming = try Capture.snapshot(a, session.cpu, &session.memory, .{});
        var segment = try session.startSegment(cycles);
        var segment_live = true;
        defer if (segment_live) segment.deinit();
        self.outgoing = try Capture.snapshot(a, session.cpu, &session.memory, .{});
        self.caller = try Raw.Owned.initSegment(a, &segment, .{});
        const external = P.externalCount(&self.caller.?.witness.statement);
        if (external == 0 or external >= cycles) return error.InvalidMixedFixtureCensus;
        var io = try @import("../blake3_segment_public.zig").Owned.init(a, &segment.base);
        var io_live = true;
        defer if (io_live) io.deinit();
        io.data.program_root = self.image.?.root;
        io.data.initial_rw_root = null;
        io.data.final_rw_root = null;
        io.data.io_entries.input_len = 0;
        io.data.io_entries.input_words = &.{};
        io.data.io_entries.output_len = 0;
        io.data.io_entries.output_words = &.{};
        const native = try @import("../blake3_execution_trace.zig").Owner.initWithExternal(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker, external);
        var native_live = true;
        defer if (native_live) native.deinit();
        try native.sealNativeOnly();
        const current = try a.create(Execution.Current);
        current.* = .{ .a = a, .segment = segment, .io = io, .owner = native, .recipe = .custody_v2 };
        self.current = current;
        segment_live = false;
        io_live = false;
        native_live = false;
        const frame = Collector.Frame{ .clock_frame = current.segment.base.clock_frame, .global_first_cycle = current.segment.base.global_first_cycle, .cycle_count = cycles };
        const native_events = try Prepare.extractEvents(a, native, frame, 1 << 20);
        defer a.free(native_events);
        var events: std.ArrayList(Collector.Transition) = .empty;
        defer events.deinit(a);
        try events.appendSlice(a, native_events);
        try appendCallerEvents(a, &events, self.caller.?, frame, 1 << 20);
        self.endpoints = try Collector.collectGlobal(a, .{ .frame = frame, .cohort_ordinal = 0, .cohort_count = 1 }, events.items, .{});
        self.ranges = try Range.Owned.init(a, self.endpoints.?.matrix, @intCast(self.endpoints.?.endpoints.len), .{});
        var counters = try @import("../../air/lookups/tables/counter.zig").Set.init(a);
        defer counters.deinit(a);
        counters.mergeFrom(&native.opcode_columns.lookup_counters.?);
        try (@import("../../air/guest_precompile/ethereum_lookup_registration.zig").Context{ .keccak = current.segment.extension.keccakf_calls.records(), .recovery = current.segment.extension.signer_recovery_calls.records() }).register(&counters);
        try @import("../block_v7_caller_active_columns_v1.zig").registerLookup(a, &self.caller.?.witness, &counters);
        var demand = try LP.nativeDemand(&native.statement, external);
        try @import("../block_v5_precompile_table_demand_v1.zig").add(a, &demand, &self.caller.?.witness.statement, cycles, config);
        try self.ranges.?.appendToLookup(counters.get(.range_check_8_8), &demand);
        self.lookup_plan = .{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = demand };
        self.lookup = try Lookup.For(Cpu).Stage.init(a, &counters, self.lookup_plan, config, null, .{});
        self.census = try Prepare.collectProgramCensus(a, current, self.image.?.root, self.image.?.leaves, self.image.?.info.memory_layout.program_base);
        self.program = try ROM.ForBackend(Cpu).commit(a, self.census.?.plan, config);
        return self;
    }
    pub fn input(self: *const Owned) Scope.Input {
        const current = self.current.?;
        return .{ .shape = &current.owner.statement, .caller_statement = &self.caller.?.witness.statement, .frame = .{ .clock_frame = current.segment.base.clock_frame, .global_first_cycle = current.segment.base.global_first_cycle, .cycle_count = @intCast(current.segment.base.cycle_count) }, .cohort_ordinal = 0, .endpoint_count = @intCast(self.endpoints.?.endpoints.len), .native_roots = @splat(@splat(0)), .caller_roots = @splat(@splat(0)), .program_plan = self.census.?.plan, .program_roots = self.program.?.roots, .lookup_plan = self.lookup_plan, .lookup_layout = self.lookup.?.layout, .lookup_roots = self.lookup.?.roots };
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
        if (self.image) |*v| v.deinit();
        if (self.outgoing) |*v| v.deinit(self.a);
        if (self.incoming) |*v| v.deinit(self.a);
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
                    const columns = if (tree == 0) self.raw.fixed else if (tree == 1) self.raw.main else return error.InvalidMixedFixtureSample;
                    if (index >= columns.len or columns[index].log_size != self.descriptor.log_size or ordinal > 1) return error.InvalidMixedFixtureSample;
                    const physical = if (ordinal == 0) self.row else core.utils.offsetBitReversedCircleDomainIndex(self.row, self.descriptor.log_size, self.descriptor.log_size, 27);
                    return Q.fromBase(columns[index].values[physical]);
                }
            };
            const access = try @import("../block_v8_caller_ram_component_v1.zig").accessFromSamples(descriptor, Samples{ .raw = raw, .descriptor = descriptor, .row = row });
            const decoded = try @import("../block_execution_access_bridge_v2.zig").decodePair(access.pair);
            if (!decoded.active) continue;
            if (decoded.space != 1 or access.pair.address_unit != .byte_address) return error.InvalidMixedFixtureRam;
            if (events.items.len >= maximum) return error.MixedFixtureEventLimit;
            try events.append(a, .{ .space = 1, .address = decoded.source_address, .clock = try frame.globalClock(decoded.local_clock), .before = decoded.before, .after = decoded.after });
        }
    }
}

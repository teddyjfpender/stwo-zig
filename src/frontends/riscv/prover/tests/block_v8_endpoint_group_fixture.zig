//! Genuine continuous native cohorts with shared provider preparation. Test
//! support only: it constructs no old WORD witness and grants no proof receipt.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Scope = @import("../block_v8_endpoint_group_scope_v1.zig");
const Context = @import("../block_v8_endpoint_group_context_v1.zig");
const Prepare = @import("../block_v8_endpoint_execution_v1.zig");
const Execution = @import("../block_v5_cpu_execution_source_v1.zig");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Image = @import("../block_v8_endpoint_local_program_v1.zig");
const Collector = @import("../block_v8_ram_endpoint_collector_v1.zig");
const Range = @import("../block_v8_endpoint_range_provider_v1.zig");
const GroupRange = @import("../block_v8_endpoint_group_range_v1.zig");
const Lookup = @import("../block_v7_lookup_compact_proof_v1.zig");
const ROM = @import("../block_v7_program_provider_v1.zig");
const LP = @import("../block_v5_native_lookup_plan_v1.zig");
const code = [_]u32{ 0x001000b7, 0x20008093, 0x0000a103, 0x00110113, 0x0020a023, 0xff5ff06f };
const elf_bytes = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 256, .rv32im_zkvm_ethereum_sha_v1);
pub const Member = struct { current: ?*Execution.Current = null, endpoints: ?Collector.Owned = null };
pub const Owned = struct {
    a: std.mem.Allocator,
    image: ?Image.Owned = null,
    captured: ?Capture.Captured = null,
    member: []Member = &.{},
    inputs: []Scope.MemberInput = &.{},
    stages_values: []Context.MemberStages = &.{},
    fixed: [][]const @import("stwo_prover_engine").pcs.ColumnEvaluation = &.{},
    ranges: ?Range.Owned = null,
    lookup: ?Lookup.For(Cpu).Stage = null,
    program: ?ROM.ForBackend(Cpu).FirstRound = null,
    multiplicities: []u64 = &.{},
    plan: @import("../block_v5_program_table_v1.zig").Plan = undefined,
    lookup_plan: LP.Plan = undefined,
    trusted: Scope.Trusted = undefined,
    pub fn init(a: std.mem.Allocator, n: u32, config: core.pcs.PcsConfig) !*Owned {
        if (n == 0 or n > 8) return error.InvalidGroupFixtureSize;
        const self = try a.create(Owned);
        self.* = .{ .a = a };
        errdefer self.deinit();
        const pin = Capture.sha(&elf_bytes);
        self.trusted = .{ .elf = &elf_bytes, .elf_sha256 = pin, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = n };
        self.image = try Image.Owned.init(a, &elf_bytes, pin, .rv32im_zkvm_ethereum_sha_v1, .{});
        self.captured = try Capture.capture(a, &elf_bytes, &.{}, .{ .elf = pin, .input = Capture.sha(&.{}) }, .{ .skip_cycles = 2, .cycles = 4 * n }, .{});
        var session = try @import("../../runner/mod.zig").EthereumShaExecutionSession.init(a, &elf_bytes, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
        defer session.deinit();
        try Prepare.restoreSession(a, &session, self.captured.?.incoming);
        self.member = try a.alloc(Member, n);
        for (self.member) |*m| m.* = .{};
        self.inputs = try a.alloc(Scope.MemberInput, n);
        self.stages_values = try a.alloc(Context.MemberStages, n);
        self.fixed = try a.alloc([]const @import("stwo_prover_engine").pcs.ColumnEvaluation, n);
        const matrices = try a.alloc(@import("../block_v7_memory_trace_v1.zig").Matrix, n);
        defer a.free(matrices);
        const counts = try a.alloc(u32, n);
        defer a.free(counts);
        self.multiplicities = try a.alloc(u64, self.image.?.leaves.len / 4);
        @memset(self.multiplicities, 0);
        var expected: u64 = 0;
        var counters = try @import("../../air/lookups/tables/counter.zig").Set.init(a);
        defer counters.deinit(a);
        var demand: [6]u64 = @splat(0);
        var continuation: ?@import("../../runner/result.zig").ContinuationToken = null;
        for (self.member, 0..) |*m, i| {
            const segment = if (continuation) |token| try session.resumeSegment(token, 4) else try session.startSegment(4);
            m.current = try Prepare.makeCurrent(a, segment, self.image.?.root.bytes);
            const current = m.current.?;
            continuation = current.segment.base.continuation;
            const frame = Collector.Frame{ .clock_frame = current.segment.base.clock_frame, .global_first_cycle = current.segment.base.global_first_cycle, .cycle_count = 4 };
            const events = try Prepare.extractEvents(a, current.owner, frame, 1 << 20);
            defer a.free(events);
            m.endpoints = try Collector.collectGlobal(a, .{ .frame = frame, .cohort_ordinal = @intCast(i), .cohort_count = n }, events, .{});
            matrices[i] = m.endpoints.?.matrix;
            counts[i] = @intCast(m.endpoints.?.endpoints.len);
            counters.mergeFrom(&current.owner.opcode_columns.lookup_counters.?);
            try LP.addDemand(&demand, try LP.nativeDemand(&current.owner.statement, 0));
            var census = try Prepare.collectProgramCensus(a, current, self.image.?.root, self.image.?.leaves, self.image.?.info.memory_layout.program_base);
            defer census.deinit();
            for (self.multiplicities, census.multiplicities) |*value, addend| value.* = try std.math.add(u64, value.*, addend);
            expected = try std.math.add(u64, expected, census.plan.expected_fetches);
            self.inputs[i] = .{ .shape = &current.owner.statement, .frame = frame, .cohort_ordinal = @intCast(i), .endpoint_count = counts[i], .native_main_root = @splat(0), .endpoint_main_root = @splat(0) };
            self.stages_values[i] = .{ .native_main = current.owner.main.items, .endpoints = &m.endpoints.? };
            self.fixed[i] = current.owner.preprocessed.items;
        }
        self.ranges = try GroupRange.init(a, matrices, counts, .{});
        try self.ranges.?.appendToLookup(counters.get(.range_check_8_8), &demand);
        self.lookup_plan = .{ .index = 0, .first_execution = 0, .execution_count = n, .max_requests = demand };
        self.lookup = try Lookup.For(Cpu).Stage.init(a, &counters, self.lookup_plan, config, null, .{});
        self.plan = .{ .program_root = self.image.?.root, .leaves = self.image.?.leaves, .multiplicities = self.multiplicities, .expected_fetches = expected, .log_size = @max(7, std.math.log2_int_ceil(usize, self.multiplicities.len)) };
        self.program = try ROM.ForBackend(Cpu).commit(a, self.plan, config);
        return self;
    }
    pub fn input(self: *const Owned) Scope.Input {
        return .{ .members = self.inputs, .fixed_root = @splat(0), .range_main_root = @splat(0), .program_plan = self.plan, .program_roots = self.program.?.roots, .lookup_plan = self.lookup_plan, .lookup_layout = self.lookup.?.layout, .lookup_roots = self.lookup.?.roots };
    }
    pub fn stages(self: *Owned) Context.Stages {
        return .{ .members = self.stages_values, .endpoint_range = &self.ranges.?, .program = &self.program.?, .program_allocator = self.a, .lookup = &self.lookup.? };
    }
    pub fn deinit(self: *Owned) void {
        if (self.program) |*v| v.deinit(self.a);
        if (self.lookup) |*v| v.deinit();
        if (self.ranges) |*v| v.deinit();
        self.a.free(self.fixed);
        self.a.free(self.stages_values);
        self.a.free(self.inputs);
        self.a.free(self.multiplicities);
        for (self.member) |*m| {
            if (m.endpoints) |*v| v.deinit();
            if (m.current) |v| v.deinit();
        }
        self.a.free(self.member);
        if (self.captured) |*v| v.deinit();
        if (self.image) |*v| v.deinit();
        self.a.destroy(self);
    }
};

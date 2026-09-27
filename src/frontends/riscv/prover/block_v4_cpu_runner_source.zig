//! Bounded, replayable Ethereum-SHA execution source for the block-v4 CPU
//! assembler and its fresh receiver. Preflight and replay are host claims,
//! never proof authority; the receiver verifies each staged STARK separately.
const std = @import("std");
const core = @import("stwo_core");
const Session = @import("../runner/mod.zig").EthereumShaExecutionSession;
const Segment = @import("../runner/result.zig").EthereumShaSegmentResult;
const Continuation = @import("../runner/result.zig").ContinuationToken;
const Schedule = @import("../runner/balanced_schedule.zig").Schedule;
const preflight = @import("blake3_execution_preflight.zig");
const host_preflight = @import("block_v4_cpu_host_preflight_v1.zig");
const statement = @import("blake3_segment_statement.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
const Recipe = @import("block_v5_execution_recipe_v1.zig").Recipe;

pub const Pass = enum { first, second, verification };

/// All roots and file hashes here come from the caller's independent public
/// statement, not from the preflight run. The full job may be supplied when
/// its exact segment count is already pinned; otherwise the returned job is
/// only a proposed statement for later verifier admission.
pub const Pins = struct {
    elf_sha256: [32]u8,
    input_sha256: [32]u8,
    oracle_sha256: [32]u8,
    initial_rw_root: span.Digest,
    program_root: @import("../air/memory_commitment/blake3_state_tree.zig").Digest,
    /// SHA-256 of the exact JSON bytes containing the explicit u32 budgets.
    /// Required when `initWithSchedule` receives an explicit work schedule.
    schedule_json_sha256: ?[32]u8 = null,
    expected_job: ?span.JobContext = null,
    /// Explicit physical native/caller recipe. Legacy source APIs retain0.
    execution_recipe: Recipe = .custody_v2,
};

const Boundary = struct {
    states: statement.Boundary,
    cycles: u64,
    terminal: bool,
};

pub const Source = struct {
    allocator: std.mem.Allocator,
    elf: []u8,
    input: []u8,
    oracle: []u8,
    owned_budgets: ?[]u32,
    schedule: Schedule,
    job: span.JobContext,
    planned: preflight.Planned,
    execution_recipe: Recipe = .custody_v2,
    boundaries: []Boundary,
    active: bool = false,
    first_opened: bool = false,
    first_complete: bool = false,
    second_opened: bool = false,
    second_complete: bool = false,
    verification_opened: bool = false,

    /// The schedule has the *exact* ceil(cycles/limit) leaf count, reserving
    /// enough final cycles to prove the guest's output publication locally.
    pub fn init(a: std.mem.Allocator, elf: []const u8, input: []const u8, oracle: []const u8, limit: u32, config: core.pcs.PcsConfig, pins: Pins) !Source {
        return initWithSchedule(a, elf, input, oracle, limit, config, pins, null);
    }

    /// A pinned JSON schedule may use more exact-count leaves than the
    /// cycle-balanced minimum to respect per-component proving geometry.
    /// The optional verification pass reexecutes these same pinned bytes and
    /// boundaries to reconstruct one PreparedVerifier at a time; it does not
    /// replace fresh native/sidecar proof verification.
    pub fn initWithSchedule(a: std.mem.Allocator, elf: []const u8, input: []const u8, oracle: []const u8, limit: u32, config: core.pcs.PcsConfig, pins: Pins, schedule_json: ?[]const u8) !Source {
        return initCommon(a, elf, input, oracle, limit, config, pins, schedule_json, null);
    }

    /// Reuse already-obtained host endpoints without executing a second
    /// preflight. Independent source/job pins and all replay checks remain
    /// mandatory; Planned itself never authorizes a proof or an endpoint.
    pub fn initFromPlan(a: std.mem.Allocator, elf: []const u8, input: []const u8, oracle: []const u8, limit: u32, config: core.pcs.PcsConfig, pins: Pins, planned: preflight.Planned) !Source {
        return initFromPlanWithSchedule(a, elf, input, oracle, limit, config, pins, planned, null);
    }

    pub fn initFromPlanWithSchedule(a: std.mem.Allocator, elf: []const u8, input: []const u8, oracle: []const u8, limit: u32, config: core.pcs.PcsConfig, pins: Pins, planned: preflight.Planned, schedule_json: ?[]const u8) !Source {
        if (pins.expected_job == null) return error.MissingPinnedBlockJob;
        return initCommon(a, elf, input, oracle, limit, config, pins, schedule_json, planned);
    }

    fn initCommon(a: std.mem.Allocator, elf: []const u8, input: []const u8, oracle: []const u8, limit: u32, config: core.pcs.PcsConfig, pins: Pins, schedule_json: ?[]const u8, supplied_plan: ?preflight.Planned) !Source {
        if (limit == 0 or elf.len == 0) return error.InvalidBlockRunnerSource;
        const elf_hash = sha256(elf);
        const input_hash = sha256(input);
        const oracle_hash = sha256(oracle);
        if (!std.mem.eql(u8, &elf_hash, &pins.elf_sha256) or
            !std.mem.eql(u8, &input_hash, &pins.input_sha256) or
            !std.mem.eql(u8, &oracle_hash, &pins.oracle_sha256))
            return error.UntrustedBlockRunnerInput;
        var budgets: ?[]u32 = null;
        errdefer if (budgets) |owned| a.free(owned);
        if (schedule_json) |encoded| {
            const pinned_schedule_hash = pins.schedule_json_sha256 orelse return error.UntrustedBlockRunnerSchedule;
            if (pins.expected_job == null) return error.MissingPinnedBlockJob;
            if (encoded.len > 1024 * 1024) return error.InvalidBlockRunnerScheduleSize;
            const actual_schedule_hash = sha256(encoded);
            if (!std.mem.eql(u8, &actual_schedule_hash, &pinned_schedule_hash)) return error.UntrustedBlockRunnerSchedule;
            var parsed = try std.json.parseFromSlice([]u32, a, encoded, .{ .allocate = .alloc_always });
            defer parsed.deinit();
            if (parsed.value.len == 0 or parsed.value.len > 1024) return error.InvalidBlockRunnerScheduleSize;
            budgets = try a.dupe(u32, parsed.value);
        } else if (pins.schedule_json_sha256 != null) return error.UntrustedBlockRunnerSchedule;
        var planned = if (supplied_plan) |already_obtained| already_obtained else if (schedule_json != null)
            try host_preflight.run(a, elf, input, oracle, limit)
        else
            try preflight.runEthereumForProfile(.rv32im_zkvm_ethereum_sha_v1, a, elf, input, oracle, limit);
        if (!std.meta.eql(planned.first.machine.rw_memory, pins.initial_rw_root) or
            !std.meta.eql(planned.first.program, pins.program_root) or
            !std.meta.eql(planned.last.program, pins.program_root))
            return error.UntrustedBlockRunnerEndpoint;
        const schedule = if (budgets) |owned|
            try Schedule.initExplicitExact(planned.last.cycle, limit, planned.required_terminal_cycles, owned)
        else
            try Schedule.initExactWithTerminalSuffix(planned.last.cycle, limit, planned.required_terminal_cycles);
        if (schedule.segments > 1024) return error.InvalidBlockRunnerScheduleSize;
        planned.schedule = schedule;
        const job = try v3.initJobFromEndpoints(config, planned.first, planned.last, schedule.segments, pins.initial_rw_root);
        if (pins.expected_job) |expected| if (!std.meta.eql(job, expected)) return error.UntrustedBlockRunnerJob;
        const owned_elf = try a.dupe(u8, elf);
        errdefer a.free(owned_elf);
        const owned_input = try a.dupe(u8, input);
        errdefer a.free(owned_input);
        const owned_oracle = try a.dupe(u8, oracle);
        errdefer a.free(owned_oracle);
        const boundaries = try a.alloc(Boundary, schedule.segments);
        errdefer a.free(boundaries);
        return .{ .allocator = a, .elf = owned_elf, .input = owned_input, .oracle = owned_oracle, .owned_budgets = budgets, .schedule = schedule, .job = job, .planned = planned, .execution_recipe = pins.execution_recipe, .boundaries = boundaries };
    }

    pub fn deinit(self: *Source) void {
        // A Reader borrows Source. Its lifetime must end first.
        std.debug.assert(!self.active);
        self.allocator.free(self.boundaries);
        if (self.owned_budgets) |owned| self.allocator.free(owned);
        self.allocator.free(self.oracle);
        self.allocator.free(self.input);
        self.allocator.free(self.elf);
        self.* = undefined;
    }

    pub fn openPass(self: *Source, pass: Pass) !Reader {
        if (self.active) return error.BlockRunnerPassAlreadyOpen;
        switch (pass) {
            .first => if (self.first_opened) return error.BlockRunnerPassAlreadyOpened,
            .second => if (!self.first_complete or self.second_opened) return error.BlockRunnerFirstPassIncomplete,
            .verification => if (!self.second_complete or self.verification_opened) return error.BlockRunnerSecondPassIncomplete,
        }
        var session = try Session.init(self.allocator, self.elf, .{
            .input = self.input,
            .strict_completion = true,
            .stop_on_halt_flag = true,
            .trace_retention = .segment_owned,
            .clock_frame = .leaf_local,
            .x0_local_custody_version = self.execution_recipe.nativeVersion(),
        });
        errdefer session.deinit();
        self.active = true;
        switch (pass) {
            .first => self.first_opened = true,
            .second => self.second_opened = true,
            .verification => self.verification_opened = true,
        }
        return .{ .source = self, .pass = pass, .session = session };
    }
};

/// `next` transfers one owned result. The caller releases that result before
/// calling `next` again to keep trace residency bounded to one segment.
pub const Reader = struct {
    source: *Source,
    pass: Pass,
    session: Session,
    next_index: u32 = 0,
    continuation: ?Continuation = null,
    finished: bool = false,

    pub fn deinit(self: *Reader) void {
        self.session.deinit();
        self.source.active = false;
        self.* = undefined;
    }

    pub fn next(self: *Reader) !?Segment {
        if (self.finished) return null;
        const source = self.source;
        const index = self.next_index;
        if (index >= source.schedule.segments) return error.BlockRunnerScheduleOverrun;
        const budget = try source.schedule.budget(index);
        var result = if (index == 0) try self.session.startSegment(budget) else try self.session.resumeSegment(self.continuation orelse return error.BlockRunnerMissingContinuation, budget);
        errdefer result.deinit();
        const base = &result.base;
        const terminal = index == source.schedule.segments - 1;
        if (base.segment_index != index or base.global_first_cycle != try source.schedule.firstCycle(index) or
            base.cycle_count != budget or base.clock_frame != .leaf_local or
            base.segment_role.is_first != (index == 0) or base.segment_role.is_last != terminal or
            base.isComplete() != terminal)
            return error.BlockRunnerBoundaryMismatch;
        if (terminal) {
            if (base.continuation != null or !std.mem.eql(u8, base.output orelse return error.BlockRunnerMissingOutput, source.oracle))
                return error.BlockRunnerOutputMismatch;
        } else if (base.continuation == null or base.output != null) return error.BlockRunnerUnexpectedCompletion;

        const boundary = Boundary{
            .states = try statement.boundary(source.allocator, base),
            .cycles = @intCast(base.cycle_count),
            .terminal = terminal,
        };
        if (index == 0 and !std.meta.eql(boundary.states.entry, source.planned.first.machine))
            return error.BlockRunnerInitialBoundaryMismatch;
        if (index != 0 and !std.meta.eql(source.boundaries[index - 1].states.exit, boundary.states.entry))
            return error.BlockRunnerDiscontinuity;
        if (terminal and (!std.meta.eql(boundary.states.exit, source.planned.last.machine) or
            base.global_first_cycle - 1 + @as(u64, @intCast(base.cycle_count)) != source.planned.last.cycle))
            return error.BlockRunnerFinalBoundaryMismatch;
        if (self.pass == .first) source.boundaries[index] = boundary else if (!std.meta.eql(source.boundaries[index], boundary))
            return error.BlockRunnerReplayMismatch;

        self.next_index += 1;
        self.continuation = base.continuation;
        if (terminal) {
            self.finished = true;
            switch (self.pass) {
                .first => source.first_complete = true,
                .second => source.second_complete = true,
                .verification => {},
            }
        }
        return result;
    }
};

pub fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

test "exact Ethereum-SHA runner source streams and checks both replays" {
    const a = std.testing.allocator;
    var instructions: [20]u32 = @splat(0x00000013);
    instructions[0] = 0x00100137;
    instructions[1] = 0x00100193;
    instructions[13] = 0x00312223;
    instructions[14] = 0x00312423;
    instructions[17] = 0x00312023;
    instructions[18] = 0x0000006f;
    instructions[19] = @import("../isa/sha256_compression_v1.zig").encode(5, 6);
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 0, .rv32im_zkvm_ethereum_sha_v1);
    const oracle = [_]u8{1};
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const planned = try preflight.runEthereumForProfile(.rv32im_zkvm_ethereum_sha_v1, a, &elf, &.{}, &oracle, 6);
    const exact = try Schedule.initExactWithTerminalSuffix(planned.last.cycle, 6, planned.required_terminal_cycles);
    const expected_job = try v3.initJobFromEndpoints(config, planned.first, planned.last, exact.segments, planned.first.machine.rw_memory);
    const pins = Pins{ .elf_sha256 = sha256(&elf), .input_sha256 = sha256(&.{}), .oracle_sha256 = sha256(&oracle), .initial_rw_root = planned.first.machine.rw_memory, .program_root = planned.first.program, .expected_job = expected_job };
    var missing_job = pins;
    missing_job.expected_job = null;
    try std.testing.expectError(error.MissingPinnedBlockJob, Source.initFromPlan(a, &elf, &.{}, &oracle, 6, config, missing_job, planned));
    var changed_plan = planned;
    changed_plan.first.machine.rw_memory[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockRunnerEndpoint, Source.initFromPlan(a, &elf, &.{}, &oracle, 6, config, pins, changed_plan));
    changed_plan = planned;
    changed_plan.last.machine.pc +%= 4;
    try std.testing.expectError(error.UntrustedBlockRunnerJob, Source.initFromPlan(a, &elf, &.{}, &oracle, 6, config, pins, changed_plan));
    try std.testing.expectError(error.UntrustedBlockRunnerInput, Source.initFromPlan(a, &elf, &.{}, &.{2}, 6, config, pins, planned));
    try std.testing.expectError(error.UntrustedBlockRunnerInput, Source.init(a, &elf, &.{}, &.{2}, 6, config, pins));
    const four_budgets = "[5,4,4,5]";
    try std.testing.expectError(error.UntrustedBlockRunnerSchedule, Source.initWithSchedule(a, &elf, &.{}, &oracle, 6, config, pins, four_budgets));
    var schedule_pins = pins;
    schedule_pins.schedule_json_sha256 = sha256(four_budgets);
    try std.testing.expectError(error.UntrustedBlockRunnerJob, Source.initWithSchedule(a, &elf, &.{}, &oracle, 6, config, schedule_pins, four_budgets));
    schedule_pins.expected_job = try v3.initJobFromEndpoints(config, planned.first, planned.last, 4, planned.first.machine.rw_memory);
    {
        var explicit = try Source.initWithSchedule(a, &elf, &.{}, &oracle, 6, config, schedule_pins, four_budgets);
        defer explicit.deinit();
        try std.testing.expectEqual(@as(u32, 4), explicit.schedule.segments);
        try std.testing.expectEqual(@as(u32, 5), try explicit.schedule.budget(3));
        var reused = try Source.initFromPlanWithSchedule(a, &elf, &.{}, &oracle, 6, config, schedule_pins, planned, four_budgets);
        defer reused.deinit();
        try std.testing.expectEqualDeep(explicit.job, reused.job);
        try std.testing.expectEqualSlices(u32, explicit.owned_budgets.?, reused.owned_budgets.?);
    }
    var original = try Source.init(a, &elf, &.{}, &oracle, 6, config, pins);
    defer original.deinit();
    var source = try Source.initFromPlan(a, &elf, &.{}, &oracle, 6, config, pins, planned);
    defer source.deinit();
    try std.testing.expectEqualDeep(original.job, source.job);
    try std.testing.expectEqual(@as(u32, 3), source.schedule.segments);
    try std.testing.expectError(error.BlockRunnerFirstPassIncomplete, source.openPass(.second));
    for ([_]Pass{ .first, .second, .verification }) |pass| {
        var reader = try source.openPass(pass);
        defer reader.deinit();
        for (0..source.schedule.segments) |i| {
            var segment = (try reader.next()) orelse return error.MissingTestSegment;
            try std.testing.expectEqual(@as(u32, @intCast(i)), segment.base.segment_index);
            segment.deinit();
        }
        try std.testing.expect((try reader.next()) == null);
    }
    // Passes are one-shot: a forged later run cannot overwrite the first
    // boundary commitments after they have been used for sealing.
    try std.testing.expectError(error.BlockRunnerFirstPassIncomplete, source.openPass(.second));

    var tampered = try Source.init(a, &elf, &.{}, &oracle, 6, config, pins);
    defer tampered.deinit();
    {
        var first = try tampered.openPass(.first);
        defer first.deinit();
        while (try first.next()) |owned| {
            var segment = owned;
            segment.deinit();
        }
    }
    tampered.boundaries[0].cycles += 1;
    {
        var second = try tampered.openPass(.second);
        defer second.deinit();
        try std.testing.expectError(error.BlockRunnerReplayMismatch, second.next());
    }
}

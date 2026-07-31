//! Single-pass replay of the pinned Pokemon battle checkpoint.
//!
//! `Session` owns the pinned corpus and one heap-stable live machine. `next`
//! returns one `OwnedChunk` whose prover input borrows the session ROM and owns
//! every other allocation. The caller must finish consuming and deinitialize
//! that chunk before requesting another. No concrete proving backend crosses
//! this boundary.

const std = @import("std");
const cartridge = @import("cartridge/mod.zig");
const memory_image = @import("memory.zig");
const sameboy_checkpoint = @import("checkpoint/sameboy.zig");
const oracle = @import("sameboy_instruction_trace.zig");
const replay_profile = @import("pokemon_checkpoint_replay_profile.zig");
const dma_capture = @import("pokemon_checkpoint_fixture_dma.zig");
const endpoint = @import("pokemon_checkpoint_fixture_endpoints.zig");
const prover = @import("machine_environment_prover.zig");
const ram_observation = @import("ram_observation.zig");
const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");
const dma_binding = @import("air/dma_binding.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");

const MAX_LOOKAHEAD_ROWS = replay_profile.MAX_LOOKAHEAD_ROWS;
pub const DEFAULT_ROWS = replay_profile.DEFAULT_ROWS;
pub const MAX_ROWS = replay_profile.MAX_ROWS;
pub const Profile = replay_profile.Profile;
pub const Options = replay_profile.Options;
pub const Expectation = replay_profile.Expectation;
pub const VERIFIED_PREFIX = replay_profile.VERIFIED_PREFIX;
pub const PROOF_FAST_VERIFIED_PREFIX =
    replay_profile.PROOF_FAST_VERIFIED_PREFIX;
const readRom = replay_profile.readRom;
const readTrace = replay_profile.readTrace;
const readCheckpoint = replay_profile.readCheckpoint;
const artifactsFor = replay_profile.artifactsFor;
const actionsFor = replay_profile.actionsFor;
const normalizeCheckpoint = replay_profile.normalizeCheckpoint;

const PARTY_DATA_START: u16 = 0xd163;
const PARTY_DATA_END: u16 = 0xd2f7;
const PARTY_COUNT_ADDRESS: u16 = PARTY_DATA_START;
const PARTY_SPECIES_ADDRESS: u16 = PARTY_DATA_START + 1;
const PINNED_PARTY_COUNT: u8 = 1;
const PINNED_FIRST_SPECIES: u8 = 0x84;

const OBSERVATION_REGIONS = [_]ram_observation.Region{.{
    .space = .system,
    .start = PARTY_DATA_START,
    .length = PARTY_DATA_END - PARTY_DATA_START,
}};

pub const Summary = struct {
    index: usize,
    row_start: usize,
    rows: usize,
    oracle_start: usize,
    callbacks: usize,
    initial_mcycle: u32,
    mcycles: u32,
    actions: usize,
    dma_source_bytes: usize,
    incoming_instruction_rows: ?usize,
    initial_endpoint_normalization_mask: u16,
    final_endpoint_normalization_mask: u16,
};

pub const FinishSummary = struct {
    lookahead_rows: usize,
    lookahead_mcycles: u32,
    oracle_records: usize,
    actions: usize,
};

const State = enum {
    ready,
    chunk_live,
    finished,
    failed,
};

/// Heap-allocated because `memory` and `scheduler` point into this object.
pub const Session = struct {
    allocator: std.mem.Allocator,
    options: Options,
    actions: []const @import("action_schedule.zig").Action,
    rom_bytes: []u8,
    trace_bytes: []u8,
    cartridge_value: cartridge.Cartridge,
    checkpoint: sameboy_checkpoint.Checkpoint,
    joypad: runner.joypad.State,
    ppu: runner.ppu_mmio.State,
    apu: runner.apu_mmio.State,
    memory: runner.cartridge_memory.Memory,
    scheduler: machine.CartridgeMachine,
    comparator: oracle.Comparator,
    next_action: usize,
    current_mcycle: u32,
    absolute_rows: usize,
    next_index: usize,
    expected_instruction_rows: ?usize,
    state: State,

    /// Loads, hashes, and validates each pinned artifact exactly once.
    pub fn init(
        allocator: std.mem.Allocator,
        corpus_root: []const u8,
        options: Options,
    ) !*Session {
        try options.validate();
        var directory = std.fs.cwd().openDir(corpus_root, .{}) catch
            return error.MissingPinnedPokemonCorpus;
        defer directory.close();

        const artifacts = artifactsFor(options.profile);
        const rom_bytes = try readRom(allocator, &directory, artifacts);
        var rom_owned = true;
        errdefer if (rom_owned) allocator.free(rom_bytes);
        const trace_bytes = try readTrace(allocator, &directory, artifacts);
        var trace_owned = true;
        errdefer if (trace_owned) allocator.free(trace_bytes);
        var checkpoint = try readCheckpoint(
            allocator,
            &directory,
            rom_bytes,
            artifacts,
        );
        var checkpoint_owned = true;
        errdefer if (checkpoint_owned) checkpoint.deinit();
        try normalizeCheckpoint(options.profile, &checkpoint);

        const restored_timer = try checkpoint.toTimer();
        const restored_dma = try checkpoint.toDma(artifacts.initial_mcycle);
        const session = try allocator.create(Session);
        var session_shell_owned = true;
        errdefer if (session_shell_owned) allocator.destroy(session);
        session.* = .{
            .allocator = allocator,
            .options = options,
            .actions = actionsFor(options.profile),
            .rom_bytes = rom_bytes,
            .trace_bytes = trace_bytes,
            .cartridge_value = try cartridge.Cartridge.init(rom_bytes),
            .checkpoint = checkpoint,
            .joypad = try checkpoint.toJoypad(artifacts.initial_pressed),
            .ppu = try checkpoint.toPpuMmio(),
            .apu = try checkpoint.toApuMmio(),
            .memory = undefined,
            .scheduler = undefined,
            .comparator = .{
                .trace = try oracle.Trace.init(trace_bytes),
                .initial_boundary_mcycle = artifacts.initial_mcycle,
            },
            .next_action = 0,
            .current_mcycle = artifacts.initial_mcycle,
            .absolute_rows = 0,
            .next_index = 0,
            .expected_instruction_rows = null,
            .state = .ready,
        };
        rom_owned = false;
        trace_owned = false;
        checkpoint_owned = false;
        session_shell_owned = false;
        errdefer session.releaseOwned();

        session.memory = runner.cartridge_memory.Memory.init(
            session.cartridge_value,
            session.checkpoint.sram,
            session.checkpoint.system,
            session.checkpoint.mapper,
            session.checkpoint.data_bus,
        );
        try session.memory.attachJoypad(&session.joypad);
        errdefer session.memory.detachJoypad();
        try session.memory.attachPpu(&session.ppu);
        errdefer session.memory.detachPpu();
        try session.memory.attachApu(&session.apu);
        errdefer session.memory.detachApu();
        session.scheduler = try machine.CartridgeMachine.restore(
            &session.memory,
            session.checkpoint.cpu,
            restored_timer,
            session.checkpoint.halt_bug,
        );
        session.scheduler.dma =
            try @import("runner/live_dma.zig").Controller.init(restored_dma);
        try session.memory.attachDma(&session.scheduler.dma);
        session.memory.detachDma();
        return session;
    }

    /// Replays one fixed-size chunk. Returned input is valid until `deinit`.
    pub fn next(
        self: *Session,
        expected: ?Expectation,
    ) !OwnedChunk {
        if (self.state != .ready) return error.SessionNotReady;
        errdefer self.state = .failed;

        var initial = try Boundary.capture(self);
        errdefer initial.deinit(self.allocator);
        var execution = try self.executeChunk();
        errdefer execution.deinit(self.allocator);
        var final = try Boundary.capture(self);
        errdefer final.deinit(self.allocator);

        try validateIncoming(
            self.expected_instruction_rows,
            execution.first_instruction_rows,
        );
        if (expected) |counts| try validateCounts(execution, counts);

        const summary = Summary{
            .index = self.next_index,
            .row_start = self.absolute_rows - self.options.rows,
            .rows = self.options.rows,
            .oracle_start = execution.oracle_start,
            .callbacks = execution.callbacks,
            .initial_mcycle = initial.mcycle,
            .mcycles = execution.mcycles,
            .actions = execution.actions.len,
            .dma_source_bytes = execution.dma_source_bytes.len,
            .incoming_instruction_rows = execution.first_instruction_rows,
            .initial_endpoint_normalization_mask = initial.normalization.changed_mask,
            .final_endpoint_normalization_mask = final.normalization.changed_mask,
        };
        const chunk = OwnedChunk{
            .allocator = self.allocator,
            .session = self,
            .initial = initial,
            .final = final,
            .execution = execution,
            .summary_value = summary,
            .intermediate_observations = partyObservations(initial.mcycle),
        };
        self.expected_instruction_rows = if (expected) |counts|
            counts.next_instruction_rows
        else
            null;
        self.next_index += 1;
        self.state = .chunk_live;
        return chunk;
    }

    /// Performs only the final outgoing callback check, then seals the session.
    pub fn finish(self: *Session) !FinishSummary {
        if (self.state != .ready) return error.SessionNotReady;
        errdefer self.state = .failed;
        const oracle_start = self.comparator.next_record;
        const action_start = self.next_action;
        var rows: usize = 0;
        var mcycles: u32 = 0;
        while (self.comparator.next_record == oracle_start and
            rows < MAX_LOOKAHEAD_ROWS)
        {
            try self.applyPendingAction();
            const result = try self.stepCanonical();
            mcycles = try addMcycles(mcycles, result.m_cycles);
            rows += 1;
        }
        if (self.comparator.next_record != oracle_start + 1)
            return error.InstructionCountMismatch;
        try validateIncoming(self.expected_instruction_rows, rows);
        try validateTerminalActions(action_start, self.next_action);
        self.state = .finished;
        return .{
            .lookahead_rows = rows,
            .lookahead_mcycles = mcycles,
            .oracle_records = self.comparator.next_record,
            .actions = self.next_action - action_start,
        };
    }

    pub fn deinit(self: *Session) void {
        std.debug.assert(self.state != .chunk_live);
        self.memory.detachApu();
        self.memory.detachPpu();
        self.memory.detachJoypad();
        self.releaseOwned();
    }

    fn executeChunk(self: *Session) !Execution {
        const results = try self.allocator.alloc(
            machine.CartridgeStepResult,
            self.options.rows,
        );
        errdefer self.allocator.free(results);
        const oracle_start = self.comparator.next_record;
        const action_start = self.next_action;
        const initial_dma = self.scheduler.dma.state;
        var capture = dma_capture.Capture.init(initial_dma);
        defer capture.deinit(self.allocator);
        var callbacks: usize = 0;
        var mcycles: u32 = 0;
        var first_instruction_rows: ?usize = null;

        for (results, 0..) |*result, row| {
            try self.applyPendingAction();
            result.* = try self.stepCanonical();
            try capture.observe(
                self.allocator,
                result.*,
                self.checkpoint.system,
            );
            mcycles = try addMcycles(mcycles, result.m_cycles);
            if (result.event == .instruction) {
                callbacks += 1;
                if (first_instruction_rows == null)
                    first_instruction_rows = row + 1;
            }
        }
        if (callbacks == 0) return error.EmptyInstructionChunk;
        const oracle_end = std.math.add(
            usize,
            oracle_start,
            callbacks,
        ) catch return error.OracleRecordOverflow;
        if (self.comparator.next_record != oracle_end)
            return error.InstructionCountMismatch;
        const dma_source_bytes = try capture.finish(
            self.allocator,
            self.scheduler.dma.state,
        );
        errdefer self.allocator.free(dma_source_bytes);
        try validateDma(
            self.allocator,
            initial_dma,
            self.current_mcycle - mcycles,
            self.current_mcycle,
            results,
            dma_source_bytes,
            self.scheduler.dma.state,
        );
        return .{
            .results = results,
            .dma_source_bytes = dma_source_bytes,
            .actions = self.actions[action_start..self.next_action],
            .oracle_start = oracle_start,
            .callbacks = callbacks,
            .mcycles = mcycles,
            .first_instruction_rows = first_instruction_rows,
        };
    }

    fn applyPendingAction(self: *Session) !void {
        if (self.next_action >= self.actions.len) return;
        const action = self.actions[self.next_action];
        if (action.mcycle < self.current_mcycle)
            return error.ActionNotOnMachineBoundary;
        if (action.mcycle == self.current_mcycle) {
            try self.memory.setJoypadPressed(action.pressed);
            self.next_action += 1;
        }
    }

    fn stepCanonical(self: *Session) !machine.CartridgeStepResult {
        const result = self.scheduler.step() catch |err| {
            printDivergence(
                self.absolute_rows,
                self.comparator.next_record,
                err,
            );
            return err;
        };
        if (!result.hasCanonicalShape())
            return error.NonCanonicalMachineRow;
        self.comparator.observe(result) catch |err| {
            printDivergence(
                self.absolute_rows,
                self.comparator.next_record,
                err,
            );
            return err;
        };
        self.current_mcycle = try addMcycles(
            self.current_mcycle,
            result.m_cycles,
        );
        self.absolute_rows = std.math.add(
            usize,
            self.absolute_rows,
            1,
        ) catch return error.MachineRowOverflow;
        return result;
    }

    fn releaseOwned(self: *Session) void {
        const allocator = self.allocator;
        self.checkpoint.deinit();
        allocator.free(self.trace_bytes);
        allocator.free(self.rom_bytes);
        allocator.destroy(self);
    }
};

/// One backend-neutral proof input. It must not outlive its `Session`.
pub const OwnedChunk = struct {
    allocator: std.mem.Allocator,
    session: *Session,
    initial: Boundary,
    final: Boundary,
    execution: Execution,
    summary_value: Summary,
    intermediate_observations: [2]observation.Sample,

    pub fn input(self: *const OwnedChunk) prover.Input {
        return .{
            .rom = self.session.cartridge_value,
            .initial_images = self.initial.images(),
            .final_images = self.final.images(),
            .initial_mcycle = self.initial.mcycle,
            .initial_joypad = self.initial.joypad,
            .initial_timer = self.initial.timer,
            .initial_ppu = self.initial.ppu,
            .initial_apu = self.initial.apu,
            .initial_dma = self.initial.dma,
            .actions = self.execution.actions,
            .observation_regions = &OBSERVATION_REGIONS,
            .intermediate_observations = &self.intermediate_observations,
            .results = self.execution.results,
            .dma_source_bytes = self.execution.dma_source_bytes,
        };
    }

    pub fn summary(self: *const OwnedChunk) Summary {
        return self.summary_value;
    }

    pub fn deinit(self: *OwnedChunk) void {
        std.debug.assert(self.session.state == .chunk_live);
        self.execution.deinit(self.allocator);
        self.final.deinit(self.allocator);
        self.initial.deinit(self.allocator);
        self.session.state = .ready;
        self.* = undefined;
    }
};

const Boundary = struct {
    system: *[memory_lookup.SYSTEM_SIZE]u8,
    sram: *[memory_lookup.SRAM_SIZE]u8,
    mcycle: u32,
    joypad: runner.joypad.State,
    timer: runner.timer.Timer,
    ppu: ppu_binding.State,
    apu: runner.apu_mmio.State,
    dma: runner.dma.State,
    normalization: endpoint.Normalization,

    fn capture(session: *Session) !Boundary {
        const allocator = session.allocator;
        const system = try allocator.create([memory_lookup.SYSTEM_SIZE]u8);
        errdefer allocator.destroy(system);
        @memcpy(system, session.checkpoint.system);
        const sram = try allocator.create([memory_lookup.SRAM_SIZE]u8);
        errdefer allocator.destroy(sram);
        @memcpy(sram, session.checkpoint.sram);
        const ppu = ppuBindingState(session.ppu);
        const normalization = endpoint.normalize(
            system,
            session.joypad,
            session.scheduler.timer,
            ppu,
            session.scheduler.dma.state,
        );
        try endpoint.validate(system, normalization);
        try endpoint.validateApu(system, session.apu);
        try validateEndpointNormalization(
            normalization,
            session.scheduler.timer.tac,
        );
        try validatePinnedParty(system);
        return .{
            .system = system,
            .sram = sram,
            .mcycle = session.current_mcycle,
            .joypad = session.joypad,
            .timer = session.scheduler.timer,
            .ppu = ppu,
            .apu = session.apu,
            .dma = session.scheduler.dma.state,
            .normalization = normalization,
        };
    }

    fn images(self: Boundary) memory_lookup.Images {
        return .{
            .system = memory_image.Image.init(self.system) catch unreachable,
            .sram = memory_lookup.SramImage.init(self.sram) catch unreachable,
        };
    }

    fn deinit(self: *Boundary, allocator: std.mem.Allocator) void {
        allocator.destroy(self.sram);
        allocator.destroy(self.system);
        self.* = undefined;
    }
};

const Execution = struct {
    results: []machine.CartridgeStepResult,
    dma_source_bytes: []u8,
    actions: []const @import("action_schedule.zig").Action,
    oracle_start: usize,
    callbacks: usize,
    mcycles: u32,
    first_instruction_rows: ?usize,

    fn deinit(self: *Execution, allocator: std.mem.Allocator) void {
        allocator.free(self.dma_source_bytes);
        allocator.free(self.results);
        self.* = undefined;
    }
};

fn validateDma(
    allocator: std.mem.Allocator,
    initial: runner.dma.State,
    initial_mcycle: u32,
    final_mcycle: u32,
    results: []const machine.CartridgeStepResult,
    source_bytes: []const u8,
    final: runner.dma.State,
) !void {
    var trace = try dma_binding.generateFromMachineExecution(
        allocator,
        initial_mcycle,
        final_mcycle,
        initial,
        results,
        source_bytes,
    );
    defer trace.deinit(allocator);
    if (!std.meta.eql(trace.final_state, final))
        return error.LiveDmaStateMismatch;
}

fn validateCounts(execution: Execution, expected: Expectation) !void {
    if (expected.callbacks == 0 or expected.mcycles == 0)
        return error.InvalidExpectedCounts;
    if (expected.next_instruction_rows) |rows|
        if (rows == 0 or rows > MAX_LOOKAHEAD_ROWS)
            return error.InvalidExpectedCounts;
    if (execution.callbacks != expected.callbacks or
        execution.mcycles != expected.mcycles or
        execution.dma_source_bytes.len != expected.dma_source_bytes or
        execution.actions.len != expected.actions)
    {
        return error.ChunkCountMismatch;
    }
}

fn validateIncoming(expected: ?usize, actual: ?usize) !void {
    if (expected) |rows| {
        if (actual == null or actual.? != rows)
            return error.NextInstructionDistanceMismatch;
    }
}

fn validateEndpointNormalization(
    normalization: endpoint.Normalization,
    raw_tac: u8,
) !void {
    if (normalization.changed_mask != 1 << 4 or
        normalization.before[4] != raw_tac)
    {
        return error.UnpinnedEndpointNormalization;
    }
}

fn validateTerminalActions(before: usize, after: usize) !void {
    if (after != before) return error.ActionInsideTerminalLookahead;
}

fn partyObservations(mcycle: u32) [2]observation.Sample {
    return .{
        .{
            .mcycle = mcycle,
            .key = PARTY_COUNT_ADDRESS,
            .expected = PINNED_PARTY_COUNT,
        },
        .{
            .mcycle = mcycle,
            .key = PARTY_SPECIES_ADDRESS,
            .expected = PINNED_FIRST_SPECIES,
        },
    };
}

fn validatePinnedParty(
    system: *const [memory_lookup.SYSTEM_SIZE]u8,
) !void {
    if (system[PARTY_COUNT_ADDRESS] != PINNED_PARTY_COUNT)
        return error.PinnedPartyCountMismatch;
    if (system[PARTY_SPECIES_ADDRESS] != PINNED_FIRST_SPECIES)
        return error.PinnedPartySpeciesMismatch;
}

fn ppuBindingState(ppu: runner.ppu_mmio.State) ppu_binding.State {
    return .{
        .timing = ppu.timing,
        .lcdc = ppu.lcdc,
        .scy = ppu.scy,
        .scx = ppu.scx,
        .wy = ppu.wy,
    };
}
fn addMcycles(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch
        return error.MachineClockOverflow;
}

fn printDivergence(
    machine_row: usize,
    oracle_record: usize,
    err: anyerror,
) void {
    std.debug.print(
        "SM83 Pokemon replay: DIVERGENCE machine_row={d} " ++
            "oracle_record={d} error={s}\n",
        .{ machine_row, oracle_record, @errorName(err) },
    );
}

fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

test "stream options require prover-compatible power-of-two rows" {
    try (Options{}).validate();
    try (Options{ .rows = 16 }).validate();
    try (Options{ .rows = MAX_ROWS }).validate();
    try std.testing.expectError(
        error.InvalidChunkRows,
        (Options{ .rows = 8 }).validate(),
    );
    try std.testing.expectError(
        error.InvalidChunkRows,
        (Options{ .rows = 48 }).validate(),
    );
    try std.testing.expectError(
        error.InvalidChunkRows,
        (Options{ .rows = MAX_ROWS << 1 }).validate(),
    );
}

test "next chunk carries the prior outgoing instruction distance" {
    try validateIncoming(null, null);
    try validateIncoming(10_427, 10_427);
    try std.testing.expectError(
        error.NextInstructionDistanceMismatch,
        validateIncoming(10_427, null),
    );
    try std.testing.expectError(
        error.NextInstructionDistanceMismatch,
        validateIncoming(10_427, 10_426),
    );
}

test "endpoint and terminal lookahead mutations fail closed" {
    var normalization = std.mem.zeroes(endpoint.Normalization);
    normalization.changed_mask = 1 << 4;
    normalization.before[4] = 5;
    try validateEndpointNormalization(normalization, 5);
    normalization.changed_mask = 0;
    try std.testing.expectError(
        error.UnpinnedEndpointNormalization,
        validateEndpointNormalization(normalization, 5),
    );
    normalization.changed_mask = 1 << 4;
    try std.testing.expectError(
        error.UnpinnedEndpointNormalization,
        validateEndpointNormalization(normalization, 4),
    );
    try validateTerminalActions(2, 2);
    try std.testing.expectError(
        error.ActionInsideTerminalLookahead,
        validateTerminalActions(2, 3),
    );
}

test "public observations retain the pinned party identity" {
    try ram_observation.validate(&OBSERVATION_REGIONS);
    const samples = partyObservations(artifactsFor(.visual).initial_mcycle);
    try observation.validateSchedule(&samples);
    try std.testing.expectEqual(PINNED_PARTY_COUNT, samples[0].expected);
    try std.testing.expectEqual(PINNED_FIRST_SPECIES, samples[1].expected);
}

test "replay profiles select pinned inputs and fast normalization fails closed" {
    const visual = artifactsFor(.visual);
    const fast = artifactsFor(.proof_fast);
    try std.testing.expect(!std.mem.eql(
        u8,
        visual.rom_sha256,
        fast.rom_sha256,
    ));
    try std.testing.expectEqual(
        runner.joypad.Key.start.mask(),
        visual.initial_pressed,
    );
    try std.testing.expectEqual(
        runner.joypad.Key.a.mask(),
        fast.initial_pressed,
    );
    try std.testing.expectEqual(@as(usize, 69), actionsFor(.proof_fast).len);

    var system = std.mem.zeroes([memory_lookup.SYSTEM_SIZE]u8);
    var checkpoint: sameboy_checkpoint.Checkpoint = undefined;
    checkpoint.timer = std.mem.zeroes(sameboy_checkpoint.TimerState);
    checkpoint.ppu = std.mem.zeroes(sameboy_checkpoint.PpuState);
    checkpoint.system = &system;
    try normalizeCheckpoint(.visual, &checkpoint);
    try std.testing.expectError(
        error.UnpinnedProofFastPpuBoundary,
        normalizeCheckpoint(.proof_fast, &checkpoint),
    );
}

test "proof-fast replay stays exact across adjacent chunks" {
    const corpus_root = std.posix.getenv("SM83_POKEMON_CORPUS") orelse
        return error.SkipZigTest;
    var session = try Session.init(
        std.testing.allocator,
        corpus_root,
        .{ .profile = .proof_fast },
    );
    defer session.deinit();
    var oracle_start: usize = 0;
    for (PROOF_FAST_VERIFIED_PREFIX, 0..) |expected, index| {
        var chunk = try session.next(expected);
        const summary = chunk.summary();
        try std.testing.expectEqual(index, summary.index);
        try std.testing.expectEqual(index * DEFAULT_ROWS, summary.row_start);
        try std.testing.expectEqual(oracle_start, summary.oracle_start);
        oracle_start += expected.callbacks;
        chunk.deinit();
    }
    const terminal = try session.finish();
    try std.testing.expectEqual(@as(usize, 14_498), terminal.lookahead_rows);
    try std.testing.expectEqual(oracle_start + 1, terminal.oracle_records);
}

test "pinned battle chunks stream once with exact adjacent endpoints" {
    const corpus_root = std.posix.getenv("SM83_POKEMON_CORPUS") orelse
        return error.SkipZigTest;
    const ChainBoundary = struct {
        machine_state: machine.MachineState,
        mapper: cartridge.mbc3.State,
        system_digest: [32]u8,
        sram_digest: [32]u8,
        joypad: runner.joypad.State,
        timer: runner.timer.Timer,
        ppu: ppu_binding.State,
        apu: runner.apu_mmio.State,
        dma: runner.dma.State,
        mcycle: u32,
    };

    var session = try Session.init(
        std.testing.allocator,
        corpus_root,
        .{},
    );
    defer session.deinit();
    var previous: ?ChainBoundary = null;
    for (VERIFIED_PREFIX, 0..) |counts, index| {
        var chunk = try session.next(counts);
        errdefer chunk.deinit();
        const input = chunk.input();
        if (previous) |boundary| {
            try std.testing.expectEqual(
                boundary.machine_state,
                input.results[0].before,
            );
            try std.testing.expectEqual(
                boundary.mapper,
                input.results[0].mapper_before,
            );
            try std.testing.expectEqualSlices(
                u8,
                &boundary.system_digest,
                &digest(input.initial_images.system.bytes),
            );
            try std.testing.expectEqualSlices(
                u8,
                &boundary.sram_digest,
                &digest(input.initial_images.sram.bytes),
            );
            try std.testing.expectEqual(boundary.joypad, input.initial_joypad);
            try std.testing.expectEqual(boundary.timer, input.initial_timer);
            try std.testing.expectEqual(boundary.ppu, input.initial_ppu);
            try std.testing.expectEqual(boundary.apu, input.initial_apu);
            try std.testing.expectEqual(boundary.dma, input.initial_dma);
            try std.testing.expectEqual(boundary.mcycle, input.initial_mcycle);
        }
        const last = input.results[input.results.len - 1];
        previous = .{
            .machine_state = last.after,
            .mapper = last.mapper_after,
            .system_digest = digest(input.final_images.system.bytes),
            .sram_digest = digest(input.final_images.sram.bytes),
            .joypad = chunk.final.joypad,
            .timer = chunk.final.timer,
            .ppu = chunk.final.ppu,
            .apu = chunk.final.apu,
            .dma = chunk.final.dma,
            .mcycle = input.initial_mcycle + counts.mcycles,
        };
        try std.testing.expectEqual(index, chunk.summary().index);
        chunk.deinit();
    }
    const terminal = try session.finish();
    try std.testing.expectEqual(@as(usize, 7_468), terminal.lookahead_rows);
}

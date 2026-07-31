//! Owned first Pokémon machine-environment proof input.
//!
//! This fixture is deliberately an input owner, not a proving entry point. It
//! restores one hash-pinned PE-AGI checkpoint, executes a pinned power-of-two
//! canonical cartridge-machine prefix with every supported device attached,
//! streams every instruction callback against the pinned SameBoy oracle, and
//! captures owned final images before bounded instruction lookahead.

const std = @import("std");
const cartridge = @import("cartridge/mod.zig");
const sameboy_checkpoint = @import("checkpoint/sameboy.zig");
const oracle = @import("sameboy_instruction_trace.zig");
const artifact = @import("pokemon_checkpoint_fixture_artifact.zig");
const fixture_input = @import("pokemon_checkpoint_fixture_input.zig");
const dma_capture = @import("pokemon_checkpoint_fixture_dma.zig");
const endpoint = @import("pokemon_checkpoint_fixture_endpoints.zig");
const machine_environment_prover =
    @import("machine_environment_prover.zig");
const ram_observation = @import("ram_observation.zig");
const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");
const dma_binding = @import("air/dma_binding.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");

pub const Artifacts = fixture_input.Artifacts;
pub const Profile = fixture_input.Profile;
const VISUAL_ARTIFACTS = fixture_input.VISUAL_ARTIFACTS;
const PROOF_FAST_ARTIFACTS = fixture_input.PROOF_FAST_ARTIFACTS;
const MAX_LOOKAHEAD_ROWS = fixture_input.MAX_LOOKAHEAD_ROWS;
const LOOKAHEAD_ORACLE_RECORDS = fixture_input.LOOKAHEAD_ORACLE_RECORDS;
const FRAME_TICKS_8MHZ = fixture_input.FRAME_TICKS_8MHZ;
const ENDPOINT_NORMALIZATION_MASK =
    fixture_input.ENDPOINT_NORMALIZATION_MASK;
const profileSpec = fixture_input.profileSpec;
const PARTY_DATA_START = fixture_input.PARTY_DATA_START;
const PARTY_DATA_LENGTH = fixture_input.PARTY_DATA_LENGTH;
const PARTY_COUNT_ADDRESS = fixture_input.PARTY_COUNT_ADDRESS;
const PARTY_SPECIES_ADDRESS = fixture_input.PARTY_SPECIES_ADDRESS;
const PINNED_PARTY_COUNT = fixture_input.PINNED_PARTY_COUNT;
const PINNED_FIRST_SPECIES = fixture_input.PINNED_FIRST_SPECIES;
const OBSERVATION_REGIONS = fixture_input.OBSERVATION_REGIONS;
const images = fixture_input.images;
const ppuBindingState = fixture_input.ppuBindingState;
pub const artifactsFor = fixture_input.artifactsFor;
pub const actionsFor = fixture_input.actionsFor;
const isProofFast = fixture_input.isProofFast;
pub const normalizeProofFastPpuBoundary =
    fixture_input.normalizeProofFastPpuBoundary;
const normalizeProofFastPpuMode = fixture_input.normalizeProofFastPpuMode;
const partyObservations = fixture_input.partyObservations;
const validateDmaSourceArity = fixture_input.validateDmaSourceArity;
const validatePositiveCounts = fixture_input.validatePositiveCounts;
const validatePinnedParty = fixture_input.validatePinnedParty;

pub const Summary = struct {
    initial_mcycle: u32,
    rows: usize,
    skipped_rows: usize,
    callbacks: usize,
    mcycles: u32,
    lookahead_rows: usize,
    oracle_records: usize,
    party_count: u8,
    first_species: u8,
    dma_source_bytes: usize,
    initial_endpoint_normalization_mask: u16,
    final_endpoint_normalization_mask: u16,
};

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    profile: Profile,
    rom_bytes: []u8,
    cartridge_value: cartridge.Cartridge,
    initial_system: *[memory_lookup.SYSTEM_SIZE]u8,
    initial_sram: *[memory_lookup.SRAM_SIZE]u8,
    final_system: *[memory_lookup.SYSTEM_SIZE]u8,
    final_sram: *[memory_lookup.SRAM_SIZE]u8,
    dma_source_bytes: []u8,
    results: []machine.CartridgeStepResult,
    initial_joypad: runner.joypad.State,
    initial_timer: runner.timer.Timer,
    initial_ppu: ppu_binding.State,
    initial_apu: runner.apu_mmio.State,
    initial_dma: runner.dma.State,
    actions: []const @import("action_schedule.zig").Action,
    intermediate_observations: [2]observation.Sample,
    initial_normalization: endpoint.Normalization,
    final_normalization: endpoint.Normalization,
    initial_mcycle: u32,
    oracle_start: usize,
    prefix_instructions: usize,
    prefix_mcycles: u32,
    lookahead_rows: usize,
    oracle_records: usize,

    pub fn load(
        allocator: std.mem.Allocator,
        corpus_root: []const u8,
    ) !Fixture {
        return loadProfile(allocator, corpus_root, .short);
    }

    pub fn loadProfile(
        allocator: std.mem.Allocator,
        corpus_root: []const u8,
        profile: Profile,
    ) !Fixture {
        const spec = profileSpec(profile);
        const artifacts = artifactsFor(profile);
        const actions_schedule = actionsFor(profile);
        var directory = std.fs.cwd().openDir(corpus_root, .{}) catch
            return error.MissingPinnedPokemonCorpus;
        defer directory.close();

        const rom_bytes = try artifact.readPinned(
            allocator,
            &directory,
            artifacts.rom_path,
            cartridge.header.ROM_SIZE,
            artifacts.rom_sha256,
        );
        errdefer allocator.free(rom_bytes);
        if (rom_bytes.len != cartridge.header.ROM_SIZE)
            return error.InvalidRomSize;
        const cartridge_value = try cartridge.Cartridge.init(rom_bytes);

        const checkpoint_bytes = try artifact.readPinned(
            allocator,
            &directory,
            artifacts.checkpoint_path,
            sameboy_checkpoint.CHECKPOINT_SIZE,
            artifacts.checkpoint_sha256,
        );
        defer allocator.free(checkpoint_bytes);
        if (checkpoint_bytes.len != sameboy_checkpoint.CHECKPOINT_SIZE)
            return error.InvalidCheckpointSize;

        const trace_bytes = try artifact.readPinned(
            allocator,
            &directory,
            artifacts.trace_path,
            artifacts.trace_size,
            artifacts.trace_sha256,
        );
        defer allocator.free(trace_bytes);
        if (trace_bytes.len != artifacts.trace_size)
            return error.InvalidTraceSize;
        const trace = try oracle.Trace.init(trace_bytes);
        if (trace.count() != artifacts.trace_records)
            return error.InvalidTraceRecordCount;
        try trace.validateAll();
        if (try (try trace.record(0)).callbackMcycle() !=
            artifacts.initial_mcycle)
            return error.InvalidInitialClock;

        var checkpoint = try sameboy_checkpoint.import(
            allocator,
            checkpoint_bytes,
            rom_bytes,
        );
        defer checkpoint.deinit();
        if (isProofFast(profile))
            try normalizeProofFastPpuBoundary(&checkpoint);
        const restored_timer = try checkpoint.toTimer();
        var joypad = try checkpoint.toJoypad(artifacts.initial_pressed);
        var ppu = try checkpoint.toPpuMmio();
        var apu = try checkpoint.toApuMmio();
        const restored_dma = try checkpoint.toDma(artifacts.initial_mcycle);

        var memory = runner.cartridge_memory.Memory.init(
            cartridge_value,
            checkpoint.sram,
            checkpoint.system,
            checkpoint.mapper,
            checkpoint.data_bus,
        );
        try memory.attachJoypad(&joypad);
        defer memory.detachJoypad();
        try memory.attachPpu(&ppu);
        defer memory.detachPpu();
        try memory.attachApu(&apu);
        defer memory.detachApu();
        var scheduler = try machine.CartridgeMachine.restore(
            &memory,
            checkpoint.cpu,
            restored_timer,
            checkpoint.halt_bug,
        );
        scheduler.dma =
            try @import("runner/live_dma.zig").Controller.init(restored_dma);
        try memory.attachDma(&scheduler.dma);
        memory.detachDma();

        var comparator = oracle.Comparator{
            .trace = trace,
            .initial_boundary_mcycle = artifacts.initial_mcycle,
        };
        var next_action: usize = 0;
        var skipped_instructions: usize = 0;
        var skipped_mcycles: u32 = 0;
        for (0..spec.skip_rows) |row| {
            const current_mcycle = try addMcycles(
                artifacts.initial_mcycle,
                skipped_mcycles,
            );
            try applyPendingAction(
                &memory,
                actions_schedule,
                &next_action,
                current_mcycle,
            );
            const result = scheduler.step() catch |err| {
                printDivergence(row, comparator.next_record, err);
                return err;
            };
            try observeCanonical(&comparator, result, row);
            skipped_mcycles = try addMcycles(
                skipped_mcycles,
                result.m_cycles,
            );
            skipped_instructions +=
                @intFromBool(result.event == .instruction);
        }
        if (skipped_instructions != spec.skip_instructions or
            skipped_mcycles != spec.skip_mcycles or
            comparator.next_record != spec.skip_instructions)
        {
            return error.InvalidSkippedFixtureCounts;
        }

        const initial_mcycle = try addMcycles(
            artifacts.initial_mcycle,
            skipped_mcycles,
        );
        const initial_joypad = joypad;
        const initial_timer = scheduler.timer;
        const initial_ppu = ppuBindingState(ppu);
        const initial_apu = apu;
        const initial_dma = scheduler.dma.state;
        const initial_system =
            try allocator.create([memory_lookup.SYSTEM_SIZE]u8);
        errdefer allocator.destroy(initial_system);
        @memcpy(initial_system, checkpoint.system);
        const initial_normalization = endpoint.normalize(
            initial_system,
            initial_joypad,
            initial_timer,
            initial_ppu,
            initial_dma,
        );
        try endpoint.validate(
            initial_system,
            initial_normalization,
        );
        try endpoint.validateApu(initial_system, initial_apu);
        const initial_sram =
            try allocator.create([memory_lookup.SRAM_SIZE]u8);
        errdefer allocator.destroy(initial_sram);
        @memcpy(initial_sram, checkpoint.sram);
        try validatePinnedParty(initial_system);
        const intermediate_observations = partyObservations(initial_mcycle);

        const results =
            try allocator.alloc(machine.CartridgeStepResult, spec.rows);
        errdefer allocator.free(results);
        const oracle_start = comparator.next_record;
        const action_start = next_action;
        var prefix_instructions: usize = 0;
        var prefix_mcycles: u32 = 0;
        var dma_sources = dma_capture.Capture.init(initial_dma);
        defer dma_sources.deinit(allocator);
        for (results, 0..) |*result, row| {
            const current_mcycle =
                try addMcycles(initial_mcycle, prefix_mcycles);
            try applyPendingAction(
                &memory,
                actions_schedule,
                &next_action,
                current_mcycle,
            );
            result.* = scheduler.step() catch |err| {
                printDivergence(
                    spec.skip_rows + row,
                    comparator.next_record,
                    err,
                );
                return err;
            };
            try observeCanonical(
                &comparator,
                result.*,
                spec.skip_rows + row,
            );
            try dma_sources.observe(
                allocator,
                result.*,
                checkpoint.system,
            );
            prefix_mcycles = try addMcycles(
                prefix_mcycles,
                result.m_cycles,
            );
            prefix_instructions +=
                @intFromBool(result.event == .instruction);
        }
        const action_end = next_action;
        const actions = actions_schedule[action_start..action_end];
        try validatePositiveCounts(
            spec,
            oracle_start,
            prefix_instructions,
            prefix_mcycles,
            0,
            comparator.next_record,
            false,
        );
        if (actions.len != spec.actions)
            return error.InvalidFixtureActionCount;

        const final_mcycle =
            try addMcycles(initial_mcycle, prefix_mcycles);
        const dma_source_bytes = try dma_sources.finish(
            allocator,
            scheduler.dma.state,
        );
        errdefer allocator.free(dma_source_bytes);
        var dma_trace = try dma_binding.generateFromMachineExecution(
            allocator,
            initial_mcycle,
            final_mcycle,
            initial_dma,
            results,
            dma_source_bytes,
        );
        defer dma_trace.deinit(allocator);
        var dma_source_count: usize = 0;
        for (dma_trace.rows) |row|
            dma_source_count += @intFromBool(row.transition.transfer != null);
        try validateDmaSourceArity(
            dma_source_count,
            spec.dma_source_bytes,
        );
        if (!std.meta.eql(dma_trace.final_state, scheduler.dma.state))
            return error.LiveDmaStateMismatch;

        const final_ppu = ppuBindingState(ppu);
        const final_system =
            try allocator.create([memory_lookup.SYSTEM_SIZE]u8);
        errdefer allocator.destroy(final_system);
        @memcpy(final_system, checkpoint.system);
        const final_normalization = endpoint.normalize(
            final_system,
            joypad,
            scheduler.timer,
            final_ppu,
            scheduler.dma.state,
        );
        try endpoint.validate(
            final_system,
            final_normalization,
        );
        try endpoint.validateApu(final_system, apu);
        const final_sram =
            try allocator.create([memory_lookup.SRAM_SIZE]u8);
        errdefer allocator.destroy(final_sram);
        @memcpy(final_sram, checkpoint.sram);
        try validatePinnedParty(final_system);

        const consumed_at_boundary = comparator.next_record;
        var lookahead_rows: usize = 0;
        var lookahead_mcycles: u32 = 0;
        while (comparator.next_record == consumed_at_boundary and
            lookahead_rows < MAX_LOOKAHEAD_ROWS)
        {
            const current_mcycle =
                try addMcycles(final_mcycle, lookahead_mcycles);
            try applyPendingAction(
                &memory,
                actions_schedule,
                &next_action,
                current_mcycle,
            );
            const result = scheduler.step() catch |err| {
                printDivergence(
                    spec.skip_rows + spec.rows + lookahead_rows,
                    comparator.next_record,
                    err,
                );
                return err;
            };
            if (!result.hasCanonicalShape())
                return error.NonCanonicalMachineRow;
            comparator.observe(result) catch |err| {
                printDivergence(
                    spec.skip_rows + spec.rows + lookahead_rows,
                    comparator.next_record,
                    err,
                );
                return err;
            };
            lookahead_mcycles = try addMcycles(
                lookahead_mcycles,
                result.m_cycles,
            );
            lookahead_rows += 1;
        }
        if (comparator.next_record !=
            consumed_at_boundary + LOOKAHEAD_ORACLE_RECORDS)
        {
            return error.InstructionCountMismatch;
        }
        try validatePositiveCounts(
            spec,
            oracle_start,
            prefix_instructions,
            prefix_mcycles,
            lookahead_rows,
            comparator.next_record,
            true,
        );

        try endpoint.validate(
            initial_system,
            initial_normalization,
        );
        const fixture = Fixture{
            .allocator = allocator,
            .profile = profile,
            .rom_bytes = rom_bytes,
            .cartridge_value = cartridge_value,
            .initial_system = initial_system,
            .initial_sram = initial_sram,
            .final_system = final_system,
            .final_sram = final_sram,
            .dma_source_bytes = dma_source_bytes,
            .results = results,
            .initial_joypad = initial_joypad,
            .initial_timer = initial_timer,
            .initial_ppu = initial_ppu,
            .initial_apu = initial_apu,
            .initial_dma = initial_dma,
            .actions = actions,
            .intermediate_observations = intermediate_observations,
            .initial_normalization = initial_normalization,
            .final_normalization = final_normalization,
            .initial_mcycle = initial_mcycle,
            .oracle_start = oracle_start,
            .prefix_instructions = prefix_instructions,
            .prefix_mcycles = prefix_mcycles,
            .lookahead_rows = lookahead_rows,
            .oracle_records = comparator.next_record,
        };
        try fixture.validate();
        return fixture;
    }

    pub fn deinit(self: *Fixture) void {
        self.allocator.free(self.results);
        self.allocator.free(self.dma_source_bytes);
        self.allocator.destroy(self.final_sram);
        self.allocator.destroy(self.final_system);
        self.allocator.destroy(self.initial_sram);
        self.allocator.destroy(self.initial_system);
        self.allocator.free(self.rom_bytes);
        self.* = undefined;
    }

    pub fn input(self: *const Fixture) machine_environment_prover.Input {
        return .{
            .rom = self.cartridge_value,
            .initial_images = images(
                self.initial_system,
                self.initial_sram,
            ),
            .final_images = images(
                self.final_system,
                self.final_sram,
            ),
            .initial_mcycle = self.initial_mcycle,
            .initial_joypad = self.initial_joypad,
            .initial_timer = self.initial_timer,
            .initial_ppu = self.initial_ppu,
            .initial_apu = self.initial_apu,
            .initial_dma = self.initial_dma,
            .actions = self.actions,
            .observation_regions = &OBSERVATION_REGIONS,
            .intermediate_observations = &self.intermediate_observations,
            .results = self.results,
            .dma_source_bytes = self.dma_source_bytes,
        };
    }

    pub fn summary(self: *const Fixture) Summary {
        return .{
            .initial_mcycle = self.initial_mcycle,
            .rows = self.results.len,
            .skipped_rows = profileSpec(self.profile).skip_rows,
            .callbacks = self.prefix_instructions,
            .mcycles = self.prefix_mcycles,
            .lookahead_rows = self.lookahead_rows,
            .oracle_records = self.oracle_records,
            .party_count = self.final_system[PARTY_COUNT_ADDRESS],
            .first_species = self.final_system[PARTY_SPECIES_ADDRESS],
            .dma_source_bytes = self.input().dma_source_bytes.len,
            .initial_endpoint_normalization_mask = self.initial_normalization.changed_mask,
            .final_endpoint_normalization_mask = self.final_normalization.changed_mask,
        };
    }

    fn validate(self: *const Fixture) !void {
        const spec = profileSpec(self.profile);
        if (self.results.len != spec.rows or
            !std.math.isPowerOfTwo(self.results.len))
        {
            return error.InvalidFixtureRowCount;
        }
        try validatePositiveCounts(
            spec,
            self.oracle_start,
            self.prefix_instructions,
            self.prefix_mcycles,
            self.lookahead_rows,
            self.oracle_records,
            true,
        );
        if (self.initial_dma.clock != self.initial_mcycle)
            return error.InvalidInitialClock;
        for (self.results) |result|
            if (!result.hasCanonicalShape())
                return error.NonCanonicalMachineRow;
        try validatePinnedParty(self.initial_system);
        try validatePinnedParty(self.final_system);
        try ram_observation.validate(&OBSERVATION_REGIONS);
        try observation.validateSchedule(&self.intermediate_observations);
        try endpoint.validate(
            self.initial_system,
            self.initial_normalization,
        );
        try endpoint.validateApu(self.initial_system, self.initial_apu);
        try endpoint.validate(
            self.final_system,
            self.final_normalization,
        );
        if (self.initial_normalization.changed_mask !=
            ENDPOINT_NORMALIZATION_MASK or
            self.final_normalization.changed_mask !=
                ENDPOINT_NORMALIZATION_MASK or
            self.initial_normalization.before[4] != 0 or
            self.final_normalization.before[4] != 0 or
            self.initial_normalization.before[4] != self.initial_timer.tac or
            self.initial_normalization.after[4] !=
                self.initial_timer.readTac() or
            self.final_normalization.after[4] != 0xf8)
        {
            return error.UnpinnedEndpointNormalization;
        }

        const request = self.input();
        try validateDmaSourceArity(
            request.dma_source_bytes.len,
            spec.dma_source_bytes,
        );
        if (request.results.len != spec.rows or
            request.actions.len != spec.actions or
            request.observation_regions.len == 0 or
            request.intermediate_observations.len < 2)
        {
            return error.InvalidProverInputShape;
        }
    }
};

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    const profile: Profile = if (arguments.len == 2)
        .short
    else if (arguments.len == 3 and
        std.mem.eql(u8, arguments[2], "--proof-fast"))
        .proof_fast_short
    else if (arguments.len == 3 and
        std.mem.eql(u8, arguments[2], "--proof-fast-dma-probe"))
        .proof_fast_dma_probe
    else if (arguments.len == 3 and
        std.mem.eql(u8, arguments[2], "--proof-fast-chunk-1"))
        .proof_fast_chunk_1
    else if (arguments.len == 3 and
        std.mem.eql(u8, arguments[2], "--proof-fast-chunk-2"))
        .proof_fast_chunk_2
    else if (arguments.len == 3 and
        std.mem.eql(u8, arguments[2], "--start-release"))
        .start_release
    else if (arguments.len == 3 and
        std.mem.eql(u8, arguments[2], "--battle-chunk-1"))
        .battle_chunk_1
    else if (arguments.len == 3 and
        std.mem.eql(u8, arguments[2], "--battle-chunk-2"))
        .battle_chunk_2
    else {
        std.debug.print(
            "usage: pokemon_checkpoint_fixture /path/to/PE-AGI/v1 " ++
                "[--proof-fast|--proof-fast-dma-probe|" ++
                "--proof-fast-chunk-1|" ++
                "--proof-fast-chunk-2|--start-release|" ++
                "--battle-chunk-1|--battle-chunk-2]\n",
            .{},
        );
        return error.InvalidArguments;
    };

    var fixture = try Fixture.loadProfile(allocator, arguments[1], profile);
    defer fixture.deinit();
    var prepared = try machine_environment_prover.prepare(
        allocator,
        fixture.input(),
    );
    defer prepared.deinit(allocator);
    try prepared.validateGeometry();
    const summary = fixture.summary();
    std.debug.print(
        "SM83 Pokemon fixture: PREPARED rows={d} callbacks={d} " ++
            "mcycles={d} lookahead_rows={d} oracle_records={d} " ++
            "party_count={d} first_species=0x{x:0>2} dma_sources={d} " ++
            "endpoint_masks=0x{x}/0x{x} initial_mcycle={d} " ++
            "skipped_rows={d}\n",
        .{
            summary.rows,
            summary.callbacks,
            summary.mcycles,
            summary.lookahead_rows,
            summary.oracle_records,
            summary.party_count,
            summary.first_species,
            summary.dma_source_bytes,
            summary.initial_endpoint_normalization_mask,
            summary.final_endpoint_normalization_mask,
            summary.initial_mcycle,
            summary.skipped_rows,
        },
    );
}

fn addMcycles(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch
        return error.MachineClockOverflow;
}

fn applyPendingAction(
    memory: *runner.cartridge_memory.Memory,
    actions: []const @import("action_schedule.zig").Action,
    next_action: *usize,
    current_mcycle: u32,
) !void {
    if (next_action.* >= actions.len) return;
    const action = actions[next_action.*];
    if (action.mcycle < current_mcycle)
        return error.ActionNotOnMachineBoundary;
    if (action.mcycle == current_mcycle) {
        try memory.setJoypadPressed(action.pressed);
        next_action.* += 1;
    }
}

fn observeCanonical(
    comparator: *oracle.Comparator,
    result: machine.CartridgeStepResult,
    machine_row: usize,
) !void {
    if (!result.hasCanonicalShape()) {
        printDivergence(
            machine_row,
            comparator.next_record,
            error.NonCanonicalMachineRow,
        );
        return error.NonCanonicalMachineRow;
    }
    comparator.observe(result) catch |err| {
        printDivergence(machine_row, comparator.next_record, err);
        return err;
    };
}

fn printDivergence(
    machine_row: usize,
    oracle_record: usize,
    err: anyerror,
) void {
    std.debug.print(
        "SM83 Pokemon fixture: DIVERGENCE machine_row={d} " ++
            "oracle_record={d} error={s}\n",
        .{ machine_row, oracle_record, @errorName(err) },
    );
}

test "Pokemon fixture constants pin proof input and party observations" {
    const short = profileSpec(.short);
    try std.testing.expect(std.math.isPowerOfTwo(short.rows));
    try std.testing.expectEqual(
        VISUAL_ARTIFACTS.trace_size / oracle.RECORD_SIZE,
        VISUAL_ARTIFACTS.trace_records,
    );
    try std.testing.expectEqual(@as(u32, 0x194), PARTY_DATA_LENGTH);
    try std.testing.expectEqual(PARTY_DATA_START, PARTY_COUNT_ADDRESS);
    try std.testing.expectEqual(
        PARTY_DATA_START + 1,
        PARTY_SPECIES_ADDRESS,
    );
    try ram_observation.validate(&OBSERVATION_REGIONS);
    const observations = partyObservations(VISUAL_ARTIFACTS.initial_mcycle);
    try observation.validateSchedule(&observations);
    try std.testing.expect(PINNED_PARTY_COUNT != 0);
    try std.testing.expect(PINNED_FIRST_SPECIES != 0);
    try std.testing.expectEqual(
        @as(u64, 761),
        (@as(u64, VISUAL_ARTIFACTS.initial_mcycle) * 8) /
            FRAME_TICKS_8MHZ,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        ((@as(u64, VISUAL_ARTIFACTS.initial_mcycle) * 8) /
            FRAME_TICKS_8MHZ - 1) % 40,
    );
    try std.testing.expectEqual(@as(u8, 0x80), VISUAL_ARTIFACTS.initial_pressed);
    try std.testing.expectEqual(
        short.instructions + LOOKAHEAD_ORACLE_RECORDS,
        short.instructions + 1,
    );
}

test "proof-fast fixture constants pin independent artifacts and A input" {
    try std.testing.expectEqual(
        PROOF_FAST_ARTIFACTS.trace_size / oracle.RECORD_SIZE,
        PROOF_FAST_ARTIFACTS.trace_records,
    );
    try std.testing.expectEqual(
        runner.joypad.Key.a.mask(),
        PROOF_FAST_ARTIFACTS.initial_pressed,
    );
    try std.testing.expectEqual(
        @as(u64, 341),
        (@as(u64, PROOF_FAST_ARTIFACTS.initial_mcycle) * 8) /
            FRAME_TICKS_8MHZ,
    );
    try std.testing.expectEqual(
        @as(usize, 69),
        actionsFor(.proof_fast_short).len,
    );
}

test "proof-fast boundary normalizes only raw PPU mode latches" {
    var mode: u8 = 3;
    var stat: u8 = 0x83;
    try normalizeProofFastPpuMode(&mode, &stat);
    try std.testing.expectEqual(@as(u8, 0), mode);
    try std.testing.expectEqual(@as(u8, 0x80), stat);

    mode = 2;
    stat = 0x83;
    try std.testing.expectError(
        error.UnpinnedProofFastPpuBoundary,
        normalizeProofFastPpuMode(&mode, &stat),
    );
    mode = 3;
    stat = 0x82;
    try std.testing.expectError(
        error.UnpinnedProofFastPpuBoundary,
        normalizeProofFastPpuMode(&mode, &stat),
    );
}

test "pinned fixture counts and DMA arity fail closed" {
    const short = profileSpec(.short);
    try validatePositiveCounts(
        short,
        0,
        short.instructions,
        short.mcycles,
        short.lookahead_rows,
        short.instructions + LOOKAHEAD_ORACLE_RECORDS,
        true,
    );
    try std.testing.expectError(
        error.InvalidFixturePositiveCounts,
        validatePositiveCounts(
            short,
            0,
            short.instructions - 1,
            short.mcycles,
            short.lookahead_rows,
            short.instructions + LOOKAHEAD_ORACLE_RECORDS,
            true,
        ),
    );
    try std.testing.expectError(
        error.InvalidFixturePositiveCounts,
        validatePositiveCounts(
            short,
            0,
            short.instructions,
            short.mcycles,
            0,
            short.instructions + LOOKAHEAD_ORACLE_RECORDS,
            true,
        ),
    );
    try validateDmaSourceArity(short.dma_source_bytes, 0);
    try std.testing.expectError(
        error.DmaSourceArityMismatch,
        validateDmaSourceArity(short.dma_source_bytes + 1, 0),
    );
}

//! Canonical lookup interactions for the complete SM83 machine environment.
//!
//! The v3 relation and column order is an exact prefix. Machine-only lookups
//! append in `machine_environment_geometry` order and share the one mutable
//! memory relation produced by the chronological replay.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const transaction = @import("stwo_prover_engine").transaction;
const action_schedule = @import("action_schedule.zig");
const cartridge_statement = @import("cartridge_proof_statement.zig");
const cartridge = @import("cartridge/mod.zig");
const environment = @import("environment_statement.zig");
const environment_interaction =
    @import("environment_proof_interaction.zig");
const geometry = @import("machine_environment_geometry.zig");
const replay_mod = @import("machine_environment_memory_replay.zig");
const statement = @import("machine_environment_statement.zig");
const joypad_trace = @import("joypad_trace.zig");
const machine = @import("runner/machine.zig");
const action_lookup = @import("air/joypad_action_lookup.zig");
const dma_binding = @import("air/dma_binding.zig");
const dma_execution = @import("air/dma_execution_lookup.zig");
const dma_memory = @import("air/dma_memory_lookup.zig");
const intermediate_observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const joypad_if = @import("air/joypad_if_memory_lookup.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const joypad_mmio = @import("air/joypad_mmio_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const ppu_if = @import("air/ppu_if_memory_lookup.zig");
const ppu_execution_policy = @import("ppu_execution_policy.zig");
const ppu_mmio = @import("air/ppu_mmio_lookup.zig");
const rom_lookup = @import("air/cartridge_rom_lookup.zig");
const scheduler_memory = @import("air/scheduler_memory_lookup.zig");
const service_memory =
    @import("air/interrupt_service_memory_lookup.zig");
const timer_binding = @import("air/timer_binding.zig");
const timer_if = @import("air/timer_if_memory_lookup.zig");
const timer_mmio = @import("air/timer_mmio_lookup.zig");
const apu_execution = @import("air/apu_execution_lookup.zig");
const ram_observation = @import("ram_observation.zig");

pub const Claims = struct {
    base: environment_interaction.Claims,
    scheduler_memory: scheduler_memory.Claims,
    service_memory: service_memory.Claims,
    ppu_mmio: ppu_mmio.Claims,
    ppu_if: QM31,
    ppu_policy: ppu_execution_policy.Claims,
    dma_execution: dma_execution.Claims,
    dma_memory: [2]QM31,
    apu_execution: apu_execution.Claims,

    pub fn applyTo(
        self: Claims,
        target: *statement.ExecutionStatement,
    ) void {
        target.base.base.rom_lookup_claims = self.base.rom;
        target.base.base.memory_lookup_claims = self.base.memory;
        target.base.action_lookup_claims = self.base.actions;
        target.base.joypad_mmio_lookup_claims = self.base.mmio;
        target.base.joypad_if_memory_claim = self.base.joypad_if;
        target.base.timer_mmio_lookup_claims = self.base.timer_mmio;
        target.base.timer_if_memory_claim = self.base.timer_if;
        target.base.intermediate_observation_memory_claim =
            self.base.intermediate_observation;
        target.scheduler_memory_lookup_claims =
            self.scheduler_memory;
        target.interrupt_service_memory_lookup_claims =
            self.service_memory;
        target.ppu_mmio_lookup_claims = self.ppu_mmio;
        target.ppu_if_memory_claim = self.ppu_if;
        target.ppu_execution_policy_claims = self.ppu_policy;
        target.dma_execution_lookup_claims = self.dma_execution;
        target.dma_memory_claims = self.dma_memory;
        target.apu_execution_lookup_claims = self.apu_execution;
    }
};

pub const Prepared = struct {
    columns: transaction.OwnedColumns,
    rom_relation: rom_lookup.Relation,
    memory_relation: memory_lookup.Relation,
    action_relation: action_lookup.Relation,
    joypad_mmio_relations: joypad_mmio.Relations,
    timer_mmio_relations: timer_mmio.Relations,
    ppu_mmio_relations: ppu_mmio.Relations,
    dma_execution_relations: dma_execution.Relations,
    apu_execution_relation: apu_execution.Relation,
    claims: Claims,

    pub fn deinit(self: *Prepared, allocator: std.mem.Allocator) void {
        self.columns.deinit(allocator);
        self.* = undefined;
    }
};

pub const Input = struct {
    request: statement.ExecutionStatement,
    results: []const machine.CartridgeStepResult,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    actions: []const action_schedule.Action,
    observation_regions: []const ram_observation.Region,
    intermediate_observations: []const intermediate_observation.Sample,
    joypad_events: []const joypad_trace.EventRow,
    timer_events: []const timer_binding.EventRow,
    ppu_events: []const ppu_binding.EventRow,
    dma_events: []const dma_binding.EventRow,
    apu_trace: apu_execution.ExecutionTrace,
    replay: *const replay_mod.Replay,
    boundary_final_clocks: []const M31,
};

pub fn generate(
    allocator: std.mem.Allocator,
    channel: anytype,
    input: Input,
) !Prepared {
    const request = input.request;
    const base = request.base.base;
    try statement.validate(
        request,
        input.rom,
        input.initial_images,
        input.final_images,
        input.actions,
        input.observation_regions,
        input.intermediate_observations,
    );
    if (input.replay.initial_mcycle != base.initial.mcycle or
        input.replay.final_mcycle != base.final.mcycle)
        return error.ReplayClockMismatch;

    var scheduler_witness = try scheduler_memory.generateWitness(
        allocator,
        input.results,
        .{
            .initial_mcycle = base.initial.mcycle,
            .final_mcycle = base.final.mcycle,
        },
        input.replay.scheduler_predecessors,
    );
    defer scheduler_witness.deinit();
    var service_witness = try service_memory.generateWitness(
        allocator,
        input.results,
        .{
            .initial_mcycle = base.initial.mcycle,
            .final_mcycle = base.final.mcycle,
            .expected_service_count = request.expected_service_count,
        },
        input.replay.service_predecessors,
    );
    defer service_witness.deinit();
    var joypad_if_witness = try joypad_if.generateWitness(
        allocator,
        request.base.joypad_log_size,
        input.joypad_events,
        input.replay.joypad_predecessors,
    );
    defer joypad_if_witness.deinit();
    var timer_if_witness = try timer_if.generateWitness(
        allocator,
        request.base.timer_log_size,
        input.timer_events,
        input.replay.timer_predecessors,
    );
    defer timer_if_witness.deinit();
    var observation_witness =
        try intermediate_observation.generateWitness(
            allocator,
            request.base.intermediate_observation_log_size,
            input.intermediate_observations,
            input.replay.observation_predecessors,
        );
    defer observation_witness.deinit();
    var ppu_auxiliary = try ppu_mmio.generateAuxiliaryWitness(
        allocator,
        request.ppu_log_size,
        input.ppu_events,
    );
    defer ppu_auxiliary.deinit();
    var ppu_if_witness = try ppu_if.generateWitness(
        allocator,
        request.ppu_log_size,
        input.ppu_events,
        input.replay.ppu_predecessors,
    );
    defer ppu_if_witness.deinit();
    var ppu_policy_witness = try ppu_execution_policy.generateWitness(
        allocator,
        request.ppu_log_size,
        input.ppu_events,
        input.results,
    );
    defer ppu_policy_witness.deinit();
    var dma_memory_witness = try dma_memory.generateWitness(
        allocator,
        request.dma_log_size,
        input.dma_events,
        input.replay.dma_predecessors,
    );
    defer dma_memory_witness.deinit();
    var apu_auxiliary = try apu_execution.generateAuxiliaryWitness(
        allocator,
        input.apu_trace,
        input.results,
        base.initial.mcycle,
    );
    defer apu_auxiliary.deinit();

    // Relation draw order is protocol data. Keep the exact v3 prefix.
    const rom_relation = try rom_lookup.Relation.draw(allocator, channel);
    const memory_relation =
        try memory_lookup.Relation.draw(allocator, channel);
    const action_relation =
        try action_lookup.Relation.draw(allocator, channel);
    const joypad_mmio_relations =
        try joypad_mmio.Relations.draw(allocator, channel);
    const timer_mmio_relations =
        try timer_mmio.Relations.draw(allocator, channel);
    const ppu_mmio_relations =
        try ppu_mmio.Relations.draw(allocator, channel);
    const dma_execution_relations =
        try dma_execution.Relations.draw(allocator, channel);
    const apu_execution_relation =
        try apu_execution.Relation.draw(allocator, channel);

    const execution_log_size = base.log_size;
    var rom = try rom_lookup.generate(
        allocator,
        input.results,
        input.rom.bytes,
        rom_relation,
    );
    errdefer rom.deinit();
    var memory = try memory_lookup.generateInteraction(
        allocator,
        input.replay.memory.accesses,
        execution_log_size,
        input.initial_images,
        input.final_images,
        memory_relation,
    );
    errdefer memory.deinit();
    try replaceBoundary(
        allocator,
        &memory,
        input.initial_images,
        input.final_images,
        input.boundary_final_clocks,
        memory_relation,
    );
    var actions = try action_lookup.generateInteraction(
        allocator,
        request.base.joypad_log_size,
        base.initial.mcycle,
        base.final.mcycle,
        input.actions,
        input.joypad_events,
        input.results,
        action_relation,
    );
    errdefer actions.deinit();
    var joypad = try joypad_mmio.generateInteraction(
        allocator,
        input.results,
        base.initial.mcycle,
        request.base.joypad_log_size,
        input.joypad_events,
        joypad_mmio_relations,
    );
    errdefer joypad.deinit();
    var joypad_interrupt = try joypad_if.generateInteraction(
        allocator,
        joypad_if_witness.accesses,
        request.base.joypad_log_size,
        memory_relation,
    );
    errdefer joypad_interrupt.deinit();
    var timer = try timer_mmio.generateInteraction(
        allocator,
        input.results,
        base.initial.mcycle,
        request.base.timer_log_size,
        input.timer_events,
        timer_mmio_relations,
    );
    errdefer timer.deinit();
    var timer_interrupt = try timer_if.generateInteraction(
        allocator,
        timer_if_witness.accesses,
        request.base.timer_log_size,
        memory_relation,
    );
    errdefer timer_interrupt.deinit();
    var observations = try intermediate_observation.generateInteraction(
        allocator,
        observation_witness.accesses,
        request.base.intermediate_observation_log_size,
        request.base.intermediate_observation_schedule_claim,
        memory_relation,
    );
    errdefer observations.deinit();
    var scheduler = try scheduler_memory.generateInteraction(
        allocator,
        scheduler_witness.samples,
        execution_log_size,
        memory_relation,
    );
    errdefer scheduler.deinit();
    var service = try service_memory.generateInteraction(
        allocator,
        service_witness.samples,
        execution_log_size,
        memory_relation,
    );
    errdefer service.deinit();
    var ppu = try ppu_mmio.generateInteraction(
        allocator,
        input.results,
        base.initial.mcycle,
        input.ppu_events,
        &ppu_auxiliary,
        ppu_mmio_relations,
    );
    errdefer ppu.deinit();
    var ppu_interrupt = try ppu_if.generateInteraction(
        allocator,
        ppu_if_witness.accesses,
        request.ppu_log_size,
        memory_relation,
    );
    errdefer ppu_interrupt.deinit();
    var dma = try dma_execution.generateInteraction(
        allocator,
        input.results,
        base.initial.mcycle,
        request.dma_log_size,
        input.dma_events,
        dma_execution_relations,
    );
    errdefer dma.deinit();
    var ppu_policy = try ppu_execution_policy.generateInteraction(
        allocator,
        input.results,
        request.dma_log_size,
        input.dma_events,
        request.ppu_log_size,
        input.ppu_events,
        &ppu_policy_witness,
        dma_execution_relations,
    );
    errdefer ppu_policy.deinit();
    var dma_mutable = try dma_memory.generateInteraction(
        allocator,
        dma_memory_witness.accesses,
        request.dma_log_size,
        memory_relation,
    );
    errdefer dma_mutable.deinit();
    var apu = try apu_execution.generateInteraction(
        allocator,
        input.apu_trace,
        input.results,
        base.initial.mcycle,
        &apu_auxiliary,
        apu_execution_relation,
    );
    errdefer apu.deinit();

    const claims = Claims{
        .base = .{
            .rom = rom.claims,
            .memory = memory.claims,
            .actions = actions.claims,
            .mmio = joypad.claims,
            .joypad_if = joypad_interrupt.claim,
            .timer_mmio = timer.claims,
            .timer_if = timer_interrupt.claim,
            .intermediate_observation = observations.claim,
        },
        .scheduler_memory = scheduler.claims,
        .service_memory = service.claims,
        .ppu_mmio = ppu.claims,
        .ppu_if = ppu_interrupt.claim,
        .ppu_policy = ppu_policy.claims,
        .dma_execution = dma.claims,
        .dma_memory = dma_mutable.claims,
        .apu_execution = apu.claims,
    };
    try verifyCancellation(request, claims);

    const columns = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        geometry.N_INTERACTION_COLUMNS,
    );
    errdefer allocator.free(columns);
    assembleColumns(
        columns,
        execution_log_size,
        request,
        &rom,
        &memory,
        &actions,
        &joypad,
        &joypad_interrupt,
        &timer,
        &timer_interrupt,
        &observations,
        &scheduler,
        &service,
        &ppu,
        &ppu_interrupt,
        &ppu_policy,
        &dma,
        &dma_mutable,
        &apu,
    );
    return .{
        .columns = transaction.OwnedColumns.init(columns),
        .rom_relation = rom_relation,
        .memory_relation = memory_relation,
        .action_relation = action_relation,
        .joypad_mmio_relations = joypad_mmio_relations,
        .timer_mmio_relations = timer_mmio_relations,
        .ppu_mmio_relations = ppu_mmio_relations,
        .dma_execution_relations = dma_execution_relations,
        .apu_execution_relation = apu_execution_relation,
        .claims = claims,
    };
}

pub fn verifyCancellation(
    request: statement.ExecutionStatement,
    claims: Claims,
) !void {
    var claimed = request;
    claims.applyTo(&claimed);
    try statement.verifyLookupCancellation(claimed);
}

/// Device endpoints replace the ordinary mutable-memory boundary.
pub fn memoryBoundaryEnabled(row: usize) bool {
    return replay_mod.memoryBoundaryEnabled(row);
}

fn assembleColumns(
    columns: []prover_pcs.ColumnEvaluation,
    execution_log_size: u32,
    request: statement.ExecutionStatement,
    rom: *const rom_lookup.Trace,
    memory: *const memory_lookup.Interaction,
    actions: *const action_lookup.Interaction,
    joypad: *const joypad_mmio.Interaction,
    joypad_interrupt: *const joypad_if.Interaction,
    timer: *const timer_mmio.Interaction,
    timer_interrupt: *const timer_if.Interaction,
    observations: *const intermediate_observation.Interaction,
    scheduler: *const scheduler_memory.Interaction,
    service: *const service_memory.Interaction,
    ppu: *const ppu_mmio.Interaction,
    ppu_interrupt: *const ppu_if.Interaction,
    ppu_policy: *const ppu_execution_policy.Interaction,
    dma: *const dma_execution.Interaction,
    dma_mutable: *const dma_memory.Interaction,
    apu: *const apu_execution.Interaction,
) void {
    set(
        columns[cartridge_statement.ROM_EXECUTION_INTERACTION_OFFSET..cartridge_statement.MUTABLE_EXECUTION_INTERACTION_OFFSET],
        rom.columns[0..rom_lookup.N_EXECUTION_COLUMNS],
        execution_log_size,
    );
    set(
        columns[cartridge_statement.MUTABLE_EXECUTION_INTERACTION_OFFSET..cartridge_statement.ROM_TABLE_INTERACTION_OFFSET],
        memory.columns[0..memory_lookup.N_EXECUTION_COLUMNS],
        execution_log_size,
    );
    set(
        columns[cartridge_statement.ROM_TABLE_INTERACTION_OFFSET..cartridge_statement.MUTABLE_BOUNDARY_INTERACTION_OFFSET],
        rom.columns[rom_lookup.N_EXECUTION_COLUMNS..],
        rom_lookup.ROM_LOG_SIZE,
    );
    set(
        columns[cartridge_statement.MUTABLE_BOUNDARY_INTERACTION_OFFSET..environment.ACTION_INTERACTION_OFFSET],
        memory.columns[memory_lookup.N_EXECUTION_COLUMNS..],
        memory_lookup.BOUNDARY_LOG_SIZE,
    );
    set(
        columns[environment.ACTION_INTERACTION_OFFSET..environment.MMIO_EXECUTION_INTERACTION_OFFSET],
        &actions.columns,
        request.base.joypad_log_size,
    );
    set(
        columns[environment.MMIO_EXECUTION_INTERACTION_OFFSET..environment.MMIO_JOYPAD_INTERACTION_OFFSET],
        &joypad.execution_columns,
        execution_log_size,
    );
    set(
        columns[environment.MMIO_JOYPAD_INTERACTION_OFFSET..environment.JOYPAD_IF_INTERACTION_OFFSET],
        &joypad.joypad_columns,
        request.base.joypad_log_size,
    );
    set(
        columns[environment.JOYPAD_IF_INTERACTION_OFFSET..environment.TIMER_MMIO_EXECUTION_INTERACTION_OFFSET],
        &joypad_interrupt.columns,
        request.base.joypad_log_size,
    );
    set(
        columns[environment.TIMER_MMIO_EXECUTION_INTERACTION_OFFSET..environment.TIMER_MMIO_TIMER_INTERACTION_OFFSET],
        &timer.execution_columns,
        execution_log_size,
    );
    set(
        columns[environment.TIMER_MMIO_TIMER_INTERACTION_OFFSET..environment.TIMER_IF_INTERACTION_OFFSET],
        &timer.timer_columns,
        request.base.timer_log_size,
    );
    set(
        columns[environment.TIMER_IF_INTERACTION_OFFSET..environment.INTERMEDIATE_OBSERVATION_INTERACTION_OFFSET],
        &timer_interrupt.columns,
        request.base.timer_log_size,
    );
    set(
        columns[environment.INTERMEDIATE_OBSERVATION_INTERACTION_OFFSET..geometry.SCHEDULER_MEMORY_INTERACTION_OFFSET],
        &observations.columns,
        request.base.intermediate_observation_log_size,
    );
    set(
        columns[geometry.SCHEDULER_MEMORY_INTERACTION_OFFSET..geometry.SERVICE_MEMORY_INTERACTION_OFFSET],
        &scheduler.columns,
        execution_log_size,
    );
    set(
        columns[geometry.SERVICE_MEMORY_INTERACTION_OFFSET..geometry.PPU_MMIO_EXECUTION_INTERACTION_OFFSET],
        &service.columns,
        execution_log_size,
    );
    set(
        columns[geometry.PPU_MMIO_EXECUTION_INTERACTION_OFFSET..geometry.PPU_MMIO_PPU_INTERACTION_OFFSET],
        &ppu.execution_columns,
        execution_log_size,
    );
    set(
        columns[geometry.PPU_MMIO_PPU_INTERACTION_OFFSET..geometry.PPU_IF_INTERACTION_OFFSET],
        &ppu.ppu_columns,
        request.ppu_log_size,
    );
    set(
        columns[geometry.PPU_IF_INTERACTION_OFFSET..geometry.PPU_POLICY_DMA_INTERACTION_OFFSET],
        &ppu_interrupt.columns,
        request.ppu_log_size,
    );
    set(
        columns[geometry.PPU_POLICY_DMA_INTERACTION_OFFSET..geometry.PPU_POLICY_PPU_INTERACTION_OFFSET],
        &ppu_policy.dma_columns,
        request.dma_log_size,
    );
    set(
        columns[geometry.PPU_POLICY_PPU_INTERACTION_OFFSET..geometry.DMA_EXECUTION_INTERACTION_OFFSET],
        &ppu_policy.ppu_columns,
        request.ppu_log_size,
    );
    set(
        columns[geometry.DMA_EXECUTION_INTERACTION_OFFSET..geometry.DMA_DMA_INTERACTION_OFFSET],
        &dma.execution_columns,
        execution_log_size,
    );
    set(
        columns[geometry.DMA_DMA_INTERACTION_OFFSET..geometry.DMA_MEMORY_INTERACTION_OFFSET],
        &dma.dma_columns,
        request.dma_log_size,
    );
    set(
        columns[geometry.DMA_MEMORY_INTERACTION_OFFSET..geometry.APU_EXECUTION_INTERACTION_OFFSET],
        &dma_mutable.columns,
        request.dma_log_size,
    );
    set(
        columns[geometry.APU_EXECUTION_INTERACTION_OFFSET..geometry.APU_APU_INTERACTION_OFFSET],
        &apu.execution_columns,
        execution_log_size,
    );
    set(
        columns[geometry.APU_APU_INTERACTION_OFFSET..],
        &apu.apu_columns,
        request.apu_log_size,
    );
}

fn replaceBoundary(
    allocator: std.mem.Allocator,
    interaction: *memory_lookup.Interaction,
    initial: memory_lookup.Images,
    final: memory_lookup.Images,
    final_clock_column: []const M31,
    relation: memory_lookup.Relation,
) !void {
    if (final_clock_column.len != memory_lookup.BOUNDARY_SIZE)
        return error.InvalidBoundaryClocks;
    const count =
        memory_lookup.N_INTERACTION_COLUMNS -
        memory_lookup.N_EXECUTION_COLUMNS;
    var replacement: [count][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (replacement[0..initialized]) |column|
        allocator.free(column);
    for (&replacement) |*column| {
        column.* = try allocator.alloc(
            M31,
            memory_lookup.BOUNDARY_SIZE,
        );
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    var claim = QM31.zero();
    for (0..memory_lookup.BOUNDARY_SIZE) |row| {
        const enabled = memoryBoundaryEnabled(row);
        const storage = try core_air_utils.circleBitReversedIndex(
            memory_lookup.BOUNDARY_LOG_SIZE,
            row,
        );
        const entry = if (enabled)
            try memory_lookup.boundaryPairForRow(
                row,
                .{
                    .enabled = true,
                    .address = @intCast(row),
                    .initial_value = imageByte(initial, row),
                    .final_clock = final_clock_column[storage].toU32(),
                    .final_value = imageByte(final, row),
                },
                relation,
            )
        else
            memory_lookup.RowPair{
                .n1 = QM31.zero(),
                .d1 = QM31.one(),
                .n2 = QM31.zero(),
                .d2 = QM31.one(),
            };
        claim = try joypad_if.accumulate(claim, entry);
        writeSecure(&replacement, storage, claim);
    }
    for (
        interaction.columns[memory_lookup.N_EXECUTION_COLUMNS..],
    ) |column| allocator.free(column);
    @memcpy(
        interaction.columns[memory_lookup.N_EXECUTION_COLUMNS..],
        &replacement,
    );
    interaction.claims.boundary = claim;
}

fn imageByte(images: memory_lookup.Images, key: usize) u8 {
    if (key < memory_lookup.SYSTEM_SIZE)
        return images.system.bytes[key];
    return images.sram.bytes[key - memory_lookup.SRAM_KEY_OFFSET];
}

fn set(
    destination: []prover_pcs.ColumnEvaluation,
    sources: []const []M31,
    log_size: u32,
) void {
    std.debug.assert(destination.len == sources.len);
    for (destination, sources) |*column, values|
        column.* = .{ .log_size = log_size, .values = values };
}

fn writeSecure(
    columns: []const []M31,
    row: usize,
    value: QM31,
) void {
    for (columns, value.toM31Array()) |column, coordinate|
        column[row] = coordinate;
}

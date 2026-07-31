//! Canonical lookup interactions for the joypad-enabled environment proof.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const transaction = @import("stwo_prover_engine").transaction;
const action_schedule = @import("action_schedule.zig");
const base = @import("cartridge_proof_statement.zig");
const cartridge = @import("cartridge/mod.zig");
const environment = @import("environment_statement.zig");
const joypad_trace = @import("joypad_trace.zig");
const runner = @import("runner/mod.zig");
const action_lookup = @import("air/joypad_action_lookup.zig");
const joypad_if = @import("air/joypad_if_memory_lookup.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const mmio_lookup = @import("air/joypad_mmio_lookup.zig");
const rom_lookup = @import("air/cartridge_rom_lookup.zig");
const timer_binding = @import("air/timer_binding.zig");
const timer_if = @import("air/timer_if_memory_lookup.zig");
const timer_mmio_lookup = @import("air/timer_mmio_lookup.zig");
const intermediate_observation =
    @import("air/intermediate_ram_observation_lookup.zig");

pub const Claims = struct {
    rom: rom_lookup.Claims,
    memory: memory_lookup.Claims,
    actions: action_lookup.Claims,
    mmio: mmio_lookup.Claims,
    joypad_if: QM31,
    timer_mmio: timer_mmio_lookup.Claims,
    timer_if: QM31,
    intermediate_observation: QM31,
};

pub const Prepared = struct {
    columns: transaction.OwnedColumns,
    rom_relation: rom_lookup.Relation,
    memory_relation: memory_lookup.Relation,
    action_relation: action_lookup.Relation,
    mmio_relations: mmio_lookup.Relations,
    timer_mmio_relations: timer_mmio_lookup.Relations,
    claims: Claims,

    pub fn deinit(self: *Prepared, allocator: std.mem.Allocator) void {
        self.columns.deinit(allocator);
        self.* = undefined;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    channel: anytype,
    steps: []const runner.CartridgeStepTrace,
    rom: cartridge.Cartridge,
    initial: memory_lookup.Images,
    final: memory_lookup.Images,
    actions: []const action_schedule.Action,
    initial_mcycle: u32,
    final_mcycle: u32,
    joypad_log_size: u32,
    events: []const joypad_trace.EventRow,
    timer_log_size: u32,
    timer_events: []const timer_binding.EventRow,
    memory_accesses: []const memory_lookup.Access,
    final_clock_column: []const M31,
    if_accesses: []const joypad_if.Access,
    timer_if_accesses: []const timer_if.Access,
    intermediate_observation_log_size: u32,
    intermediate_observation_schedule_claim: intermediate_observation.ScheduleClaim,
    intermediate_observation_accesses: []const intermediate_observation.Access,
) !Prepared {
    const execution_log_size: u32 =
        @intCast(std.math.log2_int(usize, steps.len));
    const rom_relation = try rom_lookup.Relation.draw(allocator, channel);
    const memory_relation =
        try memory_lookup.Relation.draw(allocator, channel);
    const action_relation =
        try action_lookup.Relation.draw(allocator, channel);
    const mmio_relations =
        try mmio_lookup.Relations.draw(allocator, channel);
    const timer_mmio_relations =
        try timer_mmio_lookup.Relations.draw(allocator, channel);

    var rom_interaction = try rom_lookup.generate(
        allocator,
        steps,
        rom.bytes,
        rom_relation,
    );
    defer rom_interaction.deinit();
    var memory_interaction = try memory_lookup.generateInteraction(
        allocator,
        memory_accesses,
        execution_log_size,
        initial,
        final,
        memory_relation,
    );
    defer memory_interaction.deinit();
    try replaceBoundary(
        allocator,
        &memory_interaction,
        initial,
        final,
        final_clock_column,
        memory_relation,
    );
    var action_interaction = try action_lookup.generateInteraction(
        allocator,
        joypad_log_size,
        initial_mcycle,
        final_mcycle,
        actions,
        events,
        steps,
        action_relation,
    );
    var action_owned = true;
    defer if (action_owned) action_interaction.deinit();
    var mmio_interaction = try mmio_lookup.generateInteraction(
        allocator,
        steps,
        initial_mcycle,
        joypad_log_size,
        events,
        mmio_relations,
    );
    var mmio_owned = true;
    defer if (mmio_owned) mmio_interaction.deinit();
    var if_interaction = try joypad_if.generateInteraction(
        allocator,
        if_accesses,
        joypad_log_size,
        memory_relation,
    );
    var if_owned = true;
    defer if (if_owned) if_interaction.deinit();
    var timer_mmio_interaction =
        try timer_mmio_lookup.generateInteraction(
            allocator,
            steps,
            initial_mcycle,
            timer_log_size,
            timer_events,
            timer_mmio_relations,
        );
    var timer_mmio_owned = true;
    defer if (timer_mmio_owned) timer_mmio_interaction.deinit();
    var timer_if_interaction = try timer_if.generateInteraction(
        allocator,
        timer_if_accesses,
        timer_log_size,
        memory_relation,
    );
    var timer_if_owned = true;
    defer if (timer_if_owned) timer_if_interaction.deinit();
    var intermediate_observation_interaction =
        try intermediate_observation.generateInteraction(
            allocator,
            intermediate_observation_accesses,
            intermediate_observation_log_size,
            intermediate_observation_schedule_claim,
            memory_relation,
        );
    var intermediate_observation_owned = true;
    defer if (intermediate_observation_owned)
        intermediate_observation_interaction.deinit();

    const columns = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        environment.N_INTERACTION_COLUMNS,
    );
    errdefer allocator.free(columns);
    setEvaluations(
        columns[base.ROM_EXECUTION_INTERACTION_OFFSET..base.MUTABLE_EXECUTION_INTERACTION_OFFSET],
        rom_interaction.columns[0..rom_lookup.N_EXECUTION_COLUMNS],
        execution_log_size,
    );
    setEvaluations(
        columns[base.MUTABLE_EXECUTION_INTERACTION_OFFSET..base.ROM_TABLE_INTERACTION_OFFSET],
        memory_interaction.columns[0..memory_lookup.N_EXECUTION_COLUMNS],
        execution_log_size,
    );
    setEvaluations(
        columns[base.ROM_TABLE_INTERACTION_OFFSET..base.MUTABLE_BOUNDARY_INTERACTION_OFFSET],
        rom_interaction.columns[rom_lookup.N_EXECUTION_COLUMNS..],
        rom_lookup.ROM_LOG_SIZE,
    );
    setEvaluations(
        columns[base.MUTABLE_BOUNDARY_INTERACTION_OFFSET..environment.ACTION_INTERACTION_OFFSET],
        memory_interaction.columns[memory_lookup.N_EXECUTION_COLUMNS..],
        memory_lookup.BOUNDARY_LOG_SIZE,
    );
    setEvaluations(
        columns[environment.ACTION_INTERACTION_OFFSET..environment.MMIO_EXECUTION_INTERACTION_OFFSET],
        &action_interaction.columns,
        joypad_log_size,
    );
    setEvaluations(
        columns[environment.MMIO_EXECUTION_INTERACTION_OFFSET..environment.MMIO_JOYPAD_INTERACTION_OFFSET],
        &mmio_interaction.execution_columns,
        execution_log_size,
    );
    setEvaluations(
        columns[environment.MMIO_JOYPAD_INTERACTION_OFFSET..environment.JOYPAD_IF_INTERACTION_OFFSET],
        &mmio_interaction.joypad_columns,
        joypad_log_size,
    );
    setEvaluations(
        columns[environment.JOYPAD_IF_INTERACTION_OFFSET..environment.TIMER_MMIO_EXECUTION_INTERACTION_OFFSET],
        &if_interaction.columns,
        joypad_log_size,
    );
    setEvaluations(
        columns[environment.TIMER_MMIO_EXECUTION_INTERACTION_OFFSET..environment.TIMER_MMIO_TIMER_INTERACTION_OFFSET],
        &timer_mmio_interaction.execution_columns,
        execution_log_size,
    );
    setEvaluations(
        columns[environment.TIMER_MMIO_TIMER_INTERACTION_OFFSET..environment.TIMER_IF_INTERACTION_OFFSET],
        &timer_mmio_interaction.timer_columns,
        timer_log_size,
    );
    setEvaluations(
        columns[environment.TIMER_IF_INTERACTION_OFFSET..environment.INTERMEDIATE_OBSERVATION_INTERACTION_OFFSET],
        &timer_if_interaction.columns,
        timer_log_size,
    );
    setEvaluations(
        columns[environment.INTERMEDIATE_OBSERVATION_INTERACTION_OFFSET..],
        &intermediate_observation_interaction.columns,
        intermediate_observation_log_size,
    );

    const claims = Claims{
        .rom = rom_interaction.claims,
        .memory = memory_interaction.claims,
        .actions = action_interaction.claims,
        .mmio = mmio_interaction.claims,
        .joypad_if = if_interaction.claim,
        .timer_mmio = timer_mmio_interaction.claims,
        .timer_if = timer_if_interaction.claim,
        .intermediate_observation = intermediate_observation_interaction.claim,
    };
    try verifyCancellation(claims);
    rom_interaction.disown();
    memory_interaction.disown();
    action_owned = false;
    mmio_owned = false;
    if_owned = false;
    timer_mmio_owned = false;
    timer_if_owned = false;
    intermediate_observation_owned = false;
    return .{
        .columns = transaction.OwnedColumns.init(columns),
        .rom_relation = rom_relation,
        .memory_relation = memory_relation,
        .action_relation = action_relation,
        .mmio_relations = mmio_relations,
        .timer_mmio_relations = timer_mmio_relations,
        .claims = claims,
    };
}

pub fn verifyCancellation(claims: Claims) !void {
    try rom_lookup.verifyCancellation(claims.rom);
    try action_lookup.verifyCancellation(claims.actions);
    try mmio_lookup.verifyCancellation(claims.mmio);
    try timer_mmio_lookup.verifyCancellation(claims.timer_mmio);
    if (!claims.memory.total()
        .add(claims.joypad_if)
        .add(claims.timer_if)
        .add(claims.intermediate_observation).isZero())
        return error.CartridgeMemoryLookupSumNonZero;
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
    const N_BOUNDARY_COLUMNS =
        memory_lookup.N_INTERACTION_COLUMNS -
        memory_lookup.N_EXECUTION_COLUMNS;
    var replacement: [N_BOUNDARY_COLUMNS][]M31 = undefined;
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
        const enabled = environment.memoryBoundaryEnabled(row);
        const storage = try core_air_utils.circleBitReversedIndex(
            memory_lookup.BOUNDARY_LOG_SIZE,
            row,
        );
        const entry = if (enabled)
            memory_lookup.BoundaryEntry{
                .enabled = true,
                .address = @intCast(row),
                .initial_value = imageByte(initial, row),
                .final_clock = final_clock_column[storage].toU32(),
                .final_value = imageByte(final, row),
            }
        else
            memory_lookup.BoundaryEntry{
                .enabled = false,
                .address = 0,
                .initial_value = 0,
                .final_clock = 0,
                .final_value = 0,
            };
        const pair = if (enabled)
            try memory_lookup.boundaryPairForRow(
                row,
                entry,
                relation,
            )
        else
            memory_lookup.RowPair{
                .n1 = QM31.zero(),
                .d1 = QM31.one(),
                .n2 = QM31.zero(),
                .d2 = QM31.one(),
            };
        claim = try joypad_if.accumulate(claim, pair);
        writeSecure(
            &replacement,
            storage,
            claim,
        );
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

fn setEvaluations(
    destination: []prover_pcs.ColumnEvaluation,
    sources: []const []M31,
    log_size: u32,
) void {
    std.debug.assert(destination.len == sources.len);
    for (destination, sources) |*column, values|
        column.* = .{ .log_size = log_size, .values = values };
}

fn writeSecure(columns: []const []M31, row: usize, value: QM31) void {
    for (columns, value.toM31Array()) |column, coordinate|
        column[row] = coordinate;
}

//! Public v3 environment wrapper for detached cartridge execution.
//!
//! It commits actions, joypad and timer endpoints, selected final RAM
//! observations, required intermediate RAM samples, and every lookup claim.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const channel_blake2s = @import("stwo_core").channel.blake2s;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const M31 = @import("stwo_core").fields.m31.M31;
const pcs_core = @import("stwo_core").pcs;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover_pcs = @import("stwo_prover_engine").pcs;
const action_schedule = @import("action_schedule.zig");
const base_statement = @import("cartridge_proof_statement.zig");
const cartridge = @import("cartridge/mod.zig");
const action_lookup = @import("air/joypad_action_lookup.zig");
const intermediate_observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const joypad_binding = @import("air/joypad_binding.zig");
const joypad_if_lookup = @import("air/joypad_if_memory_lookup.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const mmio_lookup = @import("air/joypad_mmio_lookup.zig");
const rom_lookup = @import("air/cartridge_rom_lookup.zig");
const timer_binding = @import("air/timer_binding.zig");
const timer_if_lookup = @import("air/timer_if_memory_lookup.zig");
const timer_mmio_lookup = @import("air/timer_mmio_lookup.zig");
const ram_observation = @import("ram_observation.zig");
const joypad = @import("runner/joypad.zig");
const timer = @import("runner/timer.zig");
pub const Channel = channel_blake2s.Blake2sChannel;
pub const DOMAIN_TAG: u32 = 0x534d_4502;
pub const VERSION: u32 = 3;
const Hasher = blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const JOYPAD_FIRST_PREPROCESSED = base_statement.N_PREPROCESSED_COLUMNS;
pub const JOYPAD_LAST_PREPROCESSED = JOYPAD_FIRST_PREPROCESSED + 1;
pub const ACTION_ACTIVE_PREPROCESSED = JOYPAD_LAST_PREPROCESSED + 1;
pub const ACTION_MCYCLE_PREPROCESSED = ACTION_ACTIVE_PREPROCESSED + 1;
pub const ACTION_PRESSED_PREPROCESSED = ACTION_MCYCLE_PREPROCESSED + 1;
pub const TIMER_FIRST_PREPROCESSED = ACTION_PRESSED_PREPROCESSED + 1;
pub const TIMER_LAST_PREPROCESSED = TIMER_FIRST_PREPROCESSED + 1;
pub const INTERMEDIATE_OBSERVATION_FIRST_PREPROCESSED =
    TIMER_LAST_PREPROCESSED + 1;
pub const OBSERVATION_ACTIVE_PREPROCESSED =
    INTERMEDIATE_OBSERVATION_FIRST_PREPROCESSED + 1;
pub const OBSERVATION_MCYCLE_PREPROCESSED = OBSERVATION_ACTIVE_PREPROCESSED + 1;
pub const OBSERVATION_KEY_PREPROCESSED = OBSERVATION_MCYCLE_PREPROCESSED + 1;
pub const OBSERVATION_VALUE_PREPROCESSED = OBSERVATION_KEY_PREPROCESSED + 1;
pub const N_PREPROCESSED_COLUMNS = OBSERVATION_VALUE_PREPROCESSED + 1;
pub const JOYPAD_BINDING_MAIN_OFFSET = base_statement.N_MAIN_COLUMNS;
pub const JOYPAD_IF_MAIN_OFFSET: usize =
    JOYPAD_BINDING_MAIN_OFFSET + joypad_binding.N_MAIN_COLUMNS;
pub const TIMER_BINDING_MAIN_OFFSET: usize =
    JOYPAD_IF_MAIN_OFFSET + joypad_if_lookup.N_MAIN_COLUMNS;
pub const TIMER_IF_MAIN_OFFSET: usize =
    TIMER_BINDING_MAIN_OFFSET + timer_binding.N_MAIN_COLUMNS;
pub const INTERMEDIATE_OBSERVATION_MAIN_OFFSET: usize =
    TIMER_IF_MAIN_OFFSET + timer_if_lookup.N_MAIN_COLUMNS;
pub const N_MAIN_COLUMNS: usize =
    INTERMEDIATE_OBSERVATION_MAIN_OFFSET +
    intermediate_observation.N_MAIN_COLUMNS;
pub const ACTION_INTERACTION_OFFSET: usize =
    base_statement.N_INTERACTION_COLUMNS;
pub const MMIO_EXECUTION_INTERACTION_OFFSET: usize =
    ACTION_INTERACTION_OFFSET + action_lookup.N_INTERACTION_COLUMNS;
pub const MMIO_JOYPAD_INTERACTION_OFFSET: usize =
    MMIO_EXECUTION_INTERACTION_OFFSET +
    mmio_lookup.N_EXECUTION_INTERACTION_COLUMNS;
pub const JOYPAD_IF_INTERACTION_OFFSET: usize =
    MMIO_JOYPAD_INTERACTION_OFFSET +
    mmio_lookup.N_JOYPAD_INTERACTION_COLUMNS;
pub const TIMER_MMIO_EXECUTION_INTERACTION_OFFSET: usize =
    JOYPAD_IF_INTERACTION_OFFSET +
    joypad_if_lookup.N_INTERACTION_COLUMNS;
pub const TIMER_MMIO_TIMER_INTERACTION_OFFSET: usize =
    TIMER_MMIO_EXECUTION_INTERACTION_OFFSET +
    timer_mmio_lookup.N_EXECUTION_INTERACTION_COLUMNS;
pub const TIMER_IF_INTERACTION_OFFSET: usize =
    TIMER_MMIO_TIMER_INTERACTION_OFFSET +
    timer_mmio_lookup.N_TIMER_INTERACTION_COLUMNS;
pub const INTERMEDIATE_OBSERVATION_INTERACTION_OFFSET: usize =
    TIMER_IF_INTERACTION_OFFSET +
    timer_if_lookup.N_INTERACTION_COLUMNS;
pub const N_INTERACTION_COLUMNS: usize =
    INTERMEDIATE_OBSERVATION_INTERACTION_OFFSET +
    intermediate_observation.N_INTERACTION_COLUMNS;
pub const ExecutionStatement = struct {
    version: u32,
    base: base_statement.ExecutionStatement,
    action_count: u32,
    action_digest: action_schedule.Digest,
    initial_joypad: joypad.State,
    final_joypad: joypad.State,
    joypad_log_size: u32,
    initial_timer: timer.Timer,
    final_timer: timer.Timer,
    timer_log_size: u32,
    observation_region_count: u32,
    observation_digest: [32]u8,
    intermediate_observation_log_size: u32,
    intermediate_observation_schedule_claim: intermediate_observation.ScheduleClaim,
    action_lookup_claims: action_lookup.Claims,
    joypad_mmio_lookup_claims: mmio_lookup.Claims,
    joypad_if_memory_claim: QM31,
    timer_mmio_lookup_claims: timer_mmio_lookup.Claims,
    timer_if_memory_claim: QM31,
    intermediate_observation_memory_claim: QM31,
};
pub const Error = error{
    InvalidEnvironmentVersion,
    InvalidJoypadLogSize,
    InvalidTimerLogSize,
    ActionCountMismatch,
    ActionDigestMismatch,
    ObservationRegionCountMismatch,
    ObservationDigestMismatch,
    IntermediateObservationCountMismatch,
    IntermediateObservationDigestMismatch,
    IntermediateObservationOutOfSegment,
    InvalidIntermediateObservationLogSize,
    EmptyObservationSchedule,
    InitialJoypadP1Mismatch,
    FinalJoypadP1Mismatch,
    InitialTimerRegisterMismatch,
    FinalTimerRegisterMismatch,
};
pub fn init(
    base: base_statement.ExecutionStatement,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    actions: []const action_schedule.Action,
    initial_joypad: joypad.State,
    final_joypad: joypad.State,
    joypad_log_size: u32,
    initial_timer: timer.Timer,
    final_timer: timer.Timer,
    timer_log_size: u32,
    observation_regions: []const ram_observation.Region,
    intermediate_observations: []const intermediate_observation.Sample,
    intermediate_observation_log_size: u32,
) !ExecutionStatement {
    try base_statement.validate(
        base,
        rom,
        initial_images,
        final_images,
    );
    try validateJoypadEndpoints(
        initial_images,
        final_images,
        initial_joypad,
        final_joypad,
    );
    try validateJoypadLogSize(base.log_size, joypad_log_size);
    try validateTimerEndpoints(
        initial_images,
        final_images,
        initial_timer,
        final_timer,
    );
    try validateTimerLogSize(base.log_size, timer_log_size);
    const action_count = std.math.cast(u32, actions.len) orelse
        return error.TooManyActions;
    const observation_region_count =
        std.math.cast(u32, observation_regions.len) orelse
        return error.TooManyRegions;
    const intermediate_claim =
        try intermediate_observation.scheduleClaim(
            intermediate_observations,
        );
    try validateIntermediateObservations(
        base,
        intermediate_observations,
        intermediate_observation_log_size,
    );
    return .{
        .version = VERSION,
        .base = base,
        .action_count = action_count,
        .action_digest = try action_schedule.digest(
            base.initial.mcycle,
            base.final.mcycle,
            actions,
        ),
        .initial_joypad = initial_joypad,
        .final_joypad = final_joypad,
        .joypad_log_size = joypad_log_size,
        .initial_timer = initial_timer,
        .final_timer = final_timer,
        .timer_log_size = timer_log_size,
        .observation_region_count = observation_region_count,
        .observation_digest = try ram_observation.digest(
            final_images,
            observation_regions,
        ),
        .intermediate_observation_log_size = intermediate_observation_log_size,
        .intermediate_observation_schedule_claim = intermediate_claim,
        .action_lookup_claims = .{
            .events = QM31.zero(),
            .public = QM31.zero(),
        },
        .joypad_mmio_lookup_claims = .{
            .execution = [_][mmio_lookup.N_EXECUTION_SUMS]QM31{
                [_]QM31{QM31.zero()} ** mmio_lookup.N_EXECUTION_SUMS,
            } ** mmio_lookup.N_RELATIONS,
            .joypad = [_]QM31{QM31.zero()} ** mmio_lookup.N_RELATIONS,
        },
        .joypad_if_memory_claim = QM31.zero(),
        .timer_mmio_lookup_claims = .{
            .execution = [_][timer_mmio_lookup.N_EXECUTION_SUMS]QM31{
                [_]QM31{QM31.zero()} **
                    timer_mmio_lookup.N_EXECUTION_SUMS,
            } ** timer_mmio_lookup.N_RELATIONS,
            .timer = [_]QM31{QM31.zero()} **
                timer_mmio_lookup.N_RELATIONS,
        },
        .timer_if_memory_claim = QM31.zero(),
        .intermediate_observation_memory_claim = QM31.zero(),
    };
}

pub fn validate(
    statement: ExecutionStatement,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    actions: []const action_schedule.Action,
    observation_regions: []const ram_observation.Region,
    intermediate_observations: []const intermediate_observation.Sample,
) !void {
    try validateShape(statement);
    try base_statement.validate(
        statement.base,
        rom,
        initial_images,
        final_images,
    );
    try validateJoypadEndpoints(
        initial_images,
        final_images,
        statement.initial_joypad,
        statement.final_joypad,
    );
    try validateJoypadLogSize(
        statement.base.log_size,
        statement.joypad_log_size,
    );
    try validateTimerEndpoints(
        initial_images,
        final_images,
        statement.initial_timer,
        statement.final_timer,
    );
    try validateTimerLogSize(
        statement.base.log_size,
        statement.timer_log_size,
    );

    const action_count = std.math.cast(u32, actions.len) orelse
        return error.TooManyActions;
    if (statement.action_count != action_count)
        return error.ActionCountMismatch;
    const expected_actions = try action_schedule.digest(
        statement.base.initial.mcycle,
        statement.base.final.mcycle,
        actions,
    );
    if (!std.mem.eql(
        u8,
        &statement.action_digest,
        &expected_actions,
    )) return error.ActionDigestMismatch;

    const observation_count =
        std.math.cast(u32, observation_regions.len) orelse
        return error.TooManyRegions;
    if (statement.observation_region_count != observation_count)
        return error.ObservationRegionCountMismatch;
    const expected_observation = try ram_observation.digest(
        final_images,
        observation_regions,
    );
    if (!std.mem.eql(
        u8,
        &statement.observation_digest,
        &expected_observation,
    )) return error.ObservationDigestMismatch;

    try validateIntermediateObservations(
        statement.base,
        intermediate_observations,
        statement.intermediate_observation_log_size,
    );
    const intermediate_claim =
        try intermediate_observation.scheduleClaim(
            intermediate_observations,
        );
    if (statement.intermediate_observation_schedule_claim.count !=
        intermediate_claim.count)
        return error.IntermediateObservationCountMismatch;
    if (!std.mem.eql(
        u8,
        &statement.intermediate_observation_schedule_claim.digest,
        &intermediate_claim.digest,
    )) return error.IntermediateObservationDigestMismatch;
}
pub fn validateShape(statement: ExecutionStatement) !void {
    if (statement.version != VERSION)
        return error.InvalidEnvironmentVersion;
    try base_statement.validateShape(statement.base);
    try validateJoypadLogSize(
        statement.base.log_size,
        statement.joypad_log_size,
    );
    try validateTimerLogSize(
        statement.base.log_size,
        statement.timer_log_size,
    );
    try validateIntermediateObservationLogSize(
        statement.intermediate_observation_log_size,
        statement.intermediate_observation_schedule_claim.count,
    );
}
/// Mixes the v3 environment fields, then the complete base public statement.
pub fn mixPublic(
    channel: *Channel,
    statement: ExecutionStatement,
) void {
    channel.mixU32s(&.{
        DOMAIN_TAG,
        statement.version,
        statement.action_count,
    });
    mixDigest(channel, statement.action_digest);
    mixJoypad(channel, statement.initial_joypad);
    mixJoypad(channel, statement.final_joypad);
    mixTimer(channel, statement.initial_timer);
    mixTimer(channel, statement.final_timer);
    channel.mixU32s(&.{
        statement.joypad_log_size,
        statement.timer_log_size,
        statement.observation_region_count,
        statement.intermediate_observation_log_size,
    });
    mixDigest(channel, statement.observation_digest);
    statement.intermediate_observation_schedule_claim.mixInto(channel);
    base_statement.mixPublic(channel, statement.base);
}

/// Mixes every post-relation lookup claim in commitment order.
pub fn mixLookupClaims(
    channel: *Channel,
    statement: ExecutionStatement,
) void {
    base_statement.mixLookupClaims(
        channel,
        statement.base.rom_lookup_claims,
        statement.base.memory_lookup_claims,
    );
    channel.mixFelts(&.{
        statement.action_lookup_claims.events,
        statement.action_lookup_claims.public,
    });
    for (statement.joypad_mmio_lookup_claims.execution) |claims|
        channel.mixFelts(&claims);
    channel.mixFelts(&statement.joypad_mmio_lookup_claims.joypad);
    channel.mixFelts(&.{statement.joypad_if_memory_claim});
    for (statement.timer_mmio_lookup_claims.execution) |claims|
        channel.mixFelts(&claims);
    channel.mixFelts(&statement.timer_mmio_lookup_claims.timer);
    channel.mixFelts(&.{statement.timer_if_memory_claim});
    channel.mixFelts(
        &.{statement.intermediate_observation_memory_claim},
    );
}

pub fn verifyLookupCancellation(
    statement: ExecutionStatement,
) !void {
    try rom_lookup.verifyCancellation(
        statement.base.rom_lookup_claims,
    );
    try action_lookup.verifyCancellation(
        statement.action_lookup_claims,
    );
    try mmio_lookup.verifyCancellation(
        statement.joypad_mmio_lookup_claims,
    );
    try timer_mmio_lookup.verifyCancellation(
        statement.timer_mmio_lookup_claims,
    );
    if (!statement.base.memory_lookup_claims.total()
        .add(statement.joypad_if_memory_claim)
        .add(statement.timer_if_memory_claim)
        .add(statement.intermediate_observation_memory_claim).isZero())
        return error.CartridgeMemoryLookupSumNonZero;
}

/// Device-owned registers are committed by endpoint AIRs, not by the ordinary
/// mutable-memory boundary.
pub fn memoryBoundaryEnabled(row: usize) bool {
    return row < memory_lookup.KEY_COUNT and
        row != joypad.P1_ADDRESS and
        (row < timer_binding.FIRST_ADDRESS or
            row > timer_binding.FIRST_ADDRESS + 3);
}
pub fn preprocessedLogSizes(
    execution_log_size: u32,
    joypad_log_size: u32,
    timer_log_size: u32,
    intermediate_observation_log_size: u32,
) [N_PREPROCESSED_COLUMNS]u32 {
    var result: [N_PREPROCESSED_COLUMNS]u32 = undefined;
    const base_logs =
        base_statement.preprocessedLogSizes(execution_log_size);
    @memcpy(
        result[0..base_statement.N_PREPROCESSED_COLUMNS],
        &base_logs,
    );
    @memset(
        result[JOYPAD_FIRST_PREPROCESSED..TIMER_FIRST_PREPROCESSED],
        joypad_log_size,
    );
    @memset(
        result[TIMER_FIRST_PREPROCESSED..INTERMEDIATE_OBSERVATION_FIRST_PREPROCESSED],
        timer_log_size,
    );
    @memset(
        result[INTERMEDIATE_OBSERVATION_FIRST_PREPROCESSED..],
        intermediate_observation_log_size,
    );
    return result;
}
pub fn mainLogSizes(
    execution_log_size: u32,
    joypad_log_size: u32,
    timer_log_size: u32,
    intermediate_observation_log_size: u32,
) [N_MAIN_COLUMNS]u32 {
    var result: [N_MAIN_COLUMNS]u32 = undefined;
    const base_logs = base_statement.mainLogSizes(execution_log_size);
    @memcpy(result[0..base_statement.N_MAIN_COLUMNS], &base_logs);
    @memset(
        result[JOYPAD_BINDING_MAIN_OFFSET..TIMER_BINDING_MAIN_OFFSET],
        joypad_log_size,
    );
    @memset(
        result[TIMER_BINDING_MAIN_OFFSET..INTERMEDIATE_OBSERVATION_MAIN_OFFSET],
        timer_log_size,
    );
    @memset(
        result[INTERMEDIATE_OBSERVATION_MAIN_OFFSET..],
        intermediate_observation_log_size,
    );
    return result;
}
pub fn interactionLogSizes(
    execution_log_size: u32,
    joypad_log_size: u32,
    timer_log_size: u32,
    intermediate_observation_log_size: u32,
) [N_INTERACTION_COLUMNS]u32 {
    var result: [N_INTERACTION_COLUMNS]u32 = undefined;
    const base_logs =
        base_statement.interactionLogSizes(execution_log_size);
    @memcpy(
        result[0..base_statement.N_INTERACTION_COLUMNS],
        &base_logs,
    );
    @memset(
        result[ACTION_INTERACTION_OFFSET..MMIO_EXECUTION_INTERACTION_OFFSET],
        joypad_log_size,
    );
    @memset(
        result[MMIO_EXECUTION_INTERACTION_OFFSET..MMIO_JOYPAD_INTERACTION_OFFSET],
        execution_log_size,
    );
    @memset(
        result[MMIO_JOYPAD_INTERACTION_OFFSET..TIMER_MMIO_EXECUTION_INTERACTION_OFFSET],
        joypad_log_size,
    );
    @memset(
        result[TIMER_MMIO_EXECUTION_INTERACTION_OFFSET..TIMER_MMIO_TIMER_INTERACTION_OFFSET],
        execution_log_size,
    );
    @memset(
        result[TIMER_MMIO_TIMER_INTERACTION_OFFSET..INTERMEDIATE_OBSERVATION_INTERACTION_OFFSET],
        timer_log_size,
    );
    @memset(
        result[INTERMEDIATE_OBSERVATION_INTERACTION_OFFSET..],
        intermediate_observation_log_size,
    );
    return result;
}

pub fn validatePreparedGeometry(
    preprocessed: []const prover_pcs.ColumnEvaluation,
    main: []const prover_pcs.ColumnEvaluation,
    interaction: []const prover_pcs.ColumnEvaluation,
    statement: ExecutionStatement,
) !void {
    try validateColumnLogs(
        preprocessed,
        &preprocessedLogSizes(
            statement.base.log_size,
            statement.joypad_log_size,
            statement.timer_log_size,
            statement.intermediate_observation_log_size,
        ),
    );
    try validateColumnLogs(
        main,
        &mainLogSizes(
            statement.base.log_size,
            statement.joypad_log_size,
            statement.timer_log_size,
            statement.intermediate_observation_log_size,
        ),
    );
    try validateColumnLogs(
        interaction,
        &interactionLogSizes(
            statement.base.log_size,
            statement.joypad_log_size,
            statement.timer_log_size,
            statement.intermediate_observation_log_size,
        ),
    );
}

pub fn canonicalPreprocessed(
    allocator: std.mem.Allocator,
    statement: ExecutionStatement,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    actions: []const action_schedule.Action,
    observation_regions: []const ram_observation.Region,
    intermediate_observations: []const intermediate_observation.Sample,
) ![]prover_pcs.ColumnEvaluation {
    try validate(
        statement,
        rom,
        initial_images,
        final_images,
        actions,
        observation_regions,
        intermediate_observations,
    );
    const base_columns = try base_statement.canonicalPreprocessed(
        allocator,
        statement.base.log_size,
        rom,
        initial_images,
        final_images,
    );
    var base_owned = true;
    errdefer if (base_owned) freeColumns(allocator, base_columns);
    const columns = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        N_PREPROCESSED_COLUMNS,
    );
    @memcpy(
        columns[0..base_statement.N_PREPROCESSED_COLUMNS],
        base_columns,
    );
    allocator.free(base_columns);
    base_owned = false;
    inline for (.{
        base_statement.MEMORY_ENABLED_PREPROCESSED,
        base_statement.MEMORY_ADDRESS_PREPROCESSED,
        base_statement.MEMORY_INITIAL_PREPROCESSED,
        base_statement.MEMORY_FINAL_PREPROCESSED,
    }) |column| {
        try set(
            columns,
            column,
            memory_lookup.BOUNDARY_LOG_SIZE,
            joypad.P1_ADDRESS,
            0,
        );
        inline for (0..4) |register| try set(
            columns,
            column,
            memory_lookup.BOUNDARY_LOG_SIZE,
            timer_binding.FIRST_ADDRESS + register,
            0,
        );
    }
    var initialized = base_statement.N_PREPROCESSED_COLUMNS;
    errdefer {
        for (columns[0..initialized]) |column|
            allocator.free(@constCast(column.values));
        allocator.free(columns);
    }
    for (columns[base_statement.N_PREPROCESSED_COLUMNS..]) |*column| {
        const index = initialized;
        const log_size = if (index < TIMER_FIRST_PREPROCESSED)
            statement.joypad_log_size
        else if (index < INTERMEDIATE_OBSERVATION_FIRST_PREPROCESSED)
            statement.timer_log_size
        else
            statement.intermediate_observation_log_size;
        const values = try allocator.alloc(
            M31,
            @as(usize, 1) << @intCast(log_size),
        );
        @memset(values, M31.zero());
        column.* = .{
            .log_size = log_size,
            .values = values,
        };
        initialized += 1;
    }
    try set(columns, JOYPAD_FIRST_PREPROCESSED, statement.joypad_log_size, 0, 1);
    try set(
        columns,
        JOYPAD_LAST_PREPROCESSED,
        statement.joypad_log_size,
        (@as(usize, 1) << @intCast(statement.joypad_log_size)) - 1,
        1,
    );
    try set(columns, TIMER_FIRST_PREPROCESSED, statement.timer_log_size, 0, 1);
    try set(
        columns,
        TIMER_LAST_PREPROCESSED,
        statement.timer_log_size,
        (@as(usize, 1) << @intCast(statement.timer_log_size)) - 1,
        1,
    );
    try set(
        columns,
        INTERMEDIATE_OBSERVATION_FIRST_PREPROCESSED,
        statement.intermediate_observation_log_size,
        0,
        1,
    );
    var table = try action_lookup.generatePublicTable(
        allocator,
        statement.joypad_log_size,
        statement.base.initial.mcycle,
        statement.base.final.mcycle,
        actions,
    );
    defer table.deinit();
    for (
        columns[ACTION_ACTIVE_PREPROCESSED..TIMER_FIRST_PREPROCESSED],
        table.columns,
    ) |destination, source| @memcpy(
        @constCast(destination.values),
        source,
    );
    var observation_table =
        try intermediate_observation.generatePublicTable(
            allocator,
            statement.intermediate_observation_log_size,
            intermediate_observations,
        );
    defer observation_table.deinit();
    for (
        columns[OBSERVATION_ACTIVE_PREPROCESSED..],
        observation_table.columns,
    ) |destination, source| @memcpy(
        @constCast(destination.values),
        source,
    );
    return columns;
}

pub fn verifyPreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: ExecutionStatement,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    actions: []const action_schedule.Action,
    observation_regions: []const ram_observation.Region,
    intermediate_observations: []const intermediate_observation.Sample,
    actual: Hasher.Hash,
) !void {
    const columns = try canonicalPreprocessed(
        allocator,
        statement,
        rom,
        initial_images,
        final_images,
        actions,
        observation_regions,
        intermediate_observations,
    );
    var moved = false;
    errdefer if (!moved) freeColumns(allocator, columns);
    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    moved = true;
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1 or !std.meta.eql(roots.items[0], actual))
        return error.InvalidPreprocessedCommitment;
}
fn validateJoypadEndpoints(
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    initial: joypad.State,
    final: joypad.State,
) !void {
    try initial.validate();
    try final.validate();
    if (initial_images.system.bytes[joypad.P1_ADDRESS] !=
        initial.readP1())
        return error.InitialJoypadP1Mismatch;
    if (final_images.system.bytes[joypad.P1_ADDRESS] !=
        final.readP1())
        return error.FinalJoypadP1Mismatch;
}
fn validateJoypadLogSize(
    execution_log_size: u32,
    joypad_log_size: u32,
) !void {
    const maximum = std.math.add(u32, execution_log_size, 5) catch
        return error.InvalidJoypadLogSize;
    if (joypad_log_size < 4 or joypad_log_size > maximum or
        joypad_log_size >= @bitSizeOf(usize))
        return error.InvalidJoypadLogSize;
}
fn validateTimerEndpoints(
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    initial: timer.Timer,
    final: timer.Timer,
) !void {
    inline for ([_]timer_binding.Register{
        .div,
        .tima,
        .tma,
        .tac,
    }) |register| {
        const address: usize =
            timer_binding.FIRST_ADDRESS + @intFromEnum(register);
        if (initial_images.system.bytes[address] !=
            timer_binding.readTimerRegister(initial, register))
            return error.InitialTimerRegisterMismatch;
        if (final_images.system.bytes[address] !=
            timer_binding.readTimerRegister(final, register))
            return error.FinalTimerRegisterMismatch;
    }
}
fn validateTimerLogSize(
    execution_log_size: u32,
    timer_log_size: u32,
) !void {
    const maximum = std.math.add(u32, execution_log_size, 4) catch
        return error.InvalidTimerLogSize;
    if (timer_log_size < 4 or timer_log_size > maximum or
        timer_log_size >= @bitSizeOf(usize))
        return error.InvalidTimerLogSize;
}
fn validateIntermediateObservations(
    base: base_statement.ExecutionStatement,
    observations: []const intermediate_observation.Sample,
    log_size: u32,
) !void {
    try intermediate_observation.validateSchedule(observations);
    for (observations) |observation|
        if (observation.mcycle < base.initial.mcycle or
            observation.mcycle >= base.final.mcycle)
            return error.IntermediateObservationOutOfSegment;
    try validateIntermediateObservationLogSize(
        log_size,
        std.math.cast(u32, observations.len) orelse
            return error.TooManyObservations,
    );
}
fn validateIntermediateObservationLogSize(
    log_size: u32,
    count: u32,
) !void {
    if (count == 0) return error.EmptyObservationSchedule;
    if (log_size < 4 or log_size > 24 or
        log_size >= @bitSizeOf(usize) or
        @as(usize, count) > @as(usize, 1) << @intCast(log_size))
        return error.InvalidIntermediateObservationLogSize;
}
fn validateColumnLogs(
    columns: []const prover_pcs.ColumnEvaluation,
    expected: []const u32,
) !void {
    if (columns.len != expected.len)
        return error.InvalidPreparedGeometry;
    for (columns, expected) |column, log_size| {
        if (column.log_size != log_size or
            column.values.len != @as(usize, 1) << @intCast(log_size))
            return error.InvalidPreparedGeometry;
    }
}
fn set(
    columns: []const prover_pcs.ColumnEvaluation,
    column: usize,
    log_size: u32,
    logical_row: usize,
    value: u32,
) !void {
    const storage = try core_air_utils.circleBitReversedIndex(
        log_size,
        logical_row,
    );
    @constCast(columns[column].values)[storage] =
        M31.fromCanonical(value);
}
fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
) void {
    for (columns) |column|
        allocator.free(@constCast(column.values));
    allocator.free(columns);
}
fn mixJoypad(channel: *Channel, state: joypad.State) void {
    channel.mixU32s(&.{
        state.p1,
        state.pressed,
        state.pending_selection,
        state.switching_delay,
    });
}
fn mixTimer(channel: *Channel, state: timer.Timer) void {
    channel.mixU32s(&.{
        state.div_counter,
        state.tima,
        state.tma,
        state.tac,
        @intFromEnum(state.reload_state),
    });
}
fn mixDigest(channel: *Channel, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(
            u32,
            digest[4 * index ..][0..4],
            .little,
        );
    channel.mixU32s(&words);
}

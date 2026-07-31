//! Public statement, commitment geometry, and canonical preprocessing.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const channel_blake2s = @import("stwo_core").channel.blake2s;
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const pcs_core = @import("stwo_core").pcs;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover_pcs = @import("stwo_prover_engine").pcs;
const execution = @import("air/execution.zig");
const family_trace = @import("air/family_trace.zig");
const memory_lookup = @import("air/memory_lookup.zig");
const program_lookup = @import("air/program_lookup.zig");
const memory_mod = @import("memory.zig");
const rom_mod = @import("rom.zig");
const runner = @import("runner/mod.zig");

const Hasher = blake2_merkle.Blake2sPrefixedMerkleHasher;
const Channel = channel_blake2s.Blake2sChannel;
const TAC: usize = 0xff07;

pub const FAMILY_MAIN_OFFSET: usize = execution.N_MAIN_COLUMNS;
pub const MEMORY_ACCESS_OFFSET: usize =
    FAMILY_MAIN_OFFSET + family_trace.N_MAIN_COLUMNS;
pub const ROM_MULTIPLICITY_OFFSET: usize =
    MEMORY_ACCESS_OFFSET + memory_lookup.N_MAIN_COLUMNS;
pub const MEMORY_BOUNDARY_OFFSET: usize = ROM_MULTIPLICITY_OFFSET + 1;
pub const N_MAIN_COLUMNS: usize = MEMORY_BOUNDARY_OFFSET + 1;
pub const MEMORY_EXECUTION_INTERACTION_OFFSET: usize =
    program_lookup.N_EXECUTION_COLUMNS;
pub const PROGRAM_ROM_INTERACTION_OFFSET: usize =
    MEMORY_EXECUTION_INTERACTION_OFFSET + memory_lookup.N_EXECUTION_COLUMNS;
pub const MEMORY_BOUNDARY_INTERACTION_OFFSET: usize =
    PROGRAM_ROM_INTERACTION_OFFSET + program_lookup.N_ROM_COLUMNS;
pub const N_INTERACTION_COLUMNS: usize =
    MEMORY_BOUNDARY_INTERACTION_OFFSET + memory_lookup.N_BOUNDARY_COLUMNS;
pub const N_PREPROCESSED_COLUMNS: usize = 9;

pub const ExecutionStatement = struct {
    log_size: u32,
    initial: execution.Boundary,
    final: execution.Boundary,
    rom_digest: [32]u8,
    initial_memory_digest: [32]u8,
    final_memory_digest: [32]u8,
    program_lookup_claims: program_lookup.Claims,
    memory_lookup_claims: memory_lookup.Claims,
};

pub fn init(
    log_size: u32,
    initial: execution.Boundary,
    final: execution.Boundary,
    rom: rom_mod.Rom,
    initial_memory: memory_mod.Image,
    final_memory: memory_mod.Image,
) ExecutionStatement {
    return .{
        .log_size = log_size,
        .initial = initial,
        .final = final,
        .rom_digest = rom.digest(),
        .initial_memory_digest = initial_memory.digest(),
        .final_memory_digest = final_memory.digest(),
        .program_lookup_claims = .{
            .execution = .{ QM31.zero(), QM31.zero() },
            .rom = QM31.zero(),
        },
        .memory_lookup_claims = .{
            .execution = .{QM31.zero()} ** memory_lookup.N_EXECUTION_SUMS,
            .boundary = QM31.zero(),
        },
    };
}

pub fn validate(
    statement: ExecutionStatement,
    rom: rom_mod.Rom,
    initial_memory: memory_mod.Image,
    final_memory: memory_mod.Image,
) !void {
    try validateShape(statement);
    try initial_memory.validateRom(rom);
    try final_memory.validateRom(rom);
    if (initial_memory.bytes[TAC] & 0x04 != 0 or
        final_memory.bytes[TAC] & 0x04 != 0)
        return error.UnsupportedTimerState;
    if (!std.mem.eql(u8, &statement.rom_digest, &rom.digest()))
        return error.RomDigestMismatch;
    if (!std.mem.eql(
        u8,
        &statement.initial_memory_digest,
        &initial_memory.digest(),
    )) return error.InitialMemoryDigestMismatch;
    if (!std.mem.eql(
        u8,
        &statement.final_memory_digest,
        &final_memory.digest(),
    )) return error.FinalMemoryDigestMismatch;
}

pub fn validateShape(statement: ExecutionStatement) !void {
    if (statement.log_size < 4 or statement.log_size > 24)
        return error.InvalidLogSize;
    if (statement.initial.cpu.f & 0x0f != 0 or
        statement.final.cpu.f & 0x0f != 0 or
        statement.initial.mcycle >= M31_MODULUS or
        statement.final.mcycle >= M31_MODULUS or
        statement.final.mcycle < statement.initial.mcycle)
        return error.InvalidProofShape;
    const rows = @as(u64, 1) << @intCast(statement.log_size);
    const mcycles = @as(u64, statement.final.mcycle) - statement.initial.mcycle;
    if (mcycles < rows or mcycles > rows * execution.N_BUS_CYCLES)
        return error.InvalidProofShape;
}

pub fn preprocessedLogSizes(log_size: u32) [N_PREPROCESSED_COLUMNS]u32 {
    return .{
        log_size,
        log_size,
        rom_mod.LOG_SIZE,
        rom_mod.LOG_SIZE,
        rom_mod.LOG_SIZE,
        16,
        16,
        16,
        16,
    };
}

pub fn mainLogSizes(log_size: u32) [N_MAIN_COLUMNS]u32 {
    var result: [N_MAIN_COLUMNS]u32 = undefined;
    @memset(result[0..ROM_MULTIPLICITY_OFFSET], log_size);
    result[ROM_MULTIPLICITY_OFFSET] = rom_mod.LOG_SIZE;
    result[MEMORY_BOUNDARY_OFFSET] = 16;
    return result;
}

pub fn interactionLogSizes(log_size: u32) [N_INTERACTION_COLUMNS]u32 {
    var result: [N_INTERACTION_COLUMNS]u32 = undefined;
    @memset(result[0..PROGRAM_ROM_INTERACTION_OFFSET], log_size);
    @memset(
        result[PROGRAM_ROM_INTERACTION_OFFSET..MEMORY_BOUNDARY_INTERACTION_OFFSET],
        rom_mod.LOG_SIZE,
    );
    @memset(result[MEMORY_BOUNDARY_INTERACTION_OFFSET..], 16);
    return result;
}

pub fn validatePreparedGeometry(
    preprocessed: []const prover_pcs.ColumnEvaluation,
    main: []const prover_pcs.ColumnEvaluation,
    log_size: u32,
) !void {
    const preprocessed_logs = preprocessedLogSizes(log_size);
    const main_logs = mainLogSizes(log_size);
    if (preprocessed.len != preprocessed_logs.len or main.len != main_logs.len)
        return error.InvalidPreparedGeometry;
    for (preprocessed, preprocessed_logs) |column, expected| {
        if (column.log_size != expected) return error.InvalidPreparedGeometry;
    }
    for (main, main_logs) |column, expected| {
        if (column.log_size != expected) return error.InvalidPreparedGeometry;
    }
}

pub fn verifyPreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: rom_mod.Rom,
    initial_memory: memory_mod.Image,
    final_memory: memory_mod.Image,
    statement: ExecutionStatement,
    actual: Hasher.Hash,
) !void {
    const columns = try canonicalPreprocessed(
        allocator,
        statement.log_size,
        rom,
        initial_memory,
        final_memory,
    );
    var columns_moved = false;
    errdefer if (!columns_moved) {
        for (columns) |column| allocator.free(@constCast(column.values));
        allocator.free(columns);
    };
    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    columns_moved = true;
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1 or !std.meta.eql(roots.items[0], actual))
        return error.InvalidPreprocessedCommitment;
}

pub fn canonicalPreprocessed(
    allocator: std.mem.Allocator,
    log_size: u32,
    rom: rom_mod.Rom,
    initial_memory: memory_mod.Image,
    final_memory: memory_mod.Image,
) ![]prover_pcs.ColumnEvaluation {
    const execution_size = @as(usize, 1) << @intCast(log_size);
    const columns = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        N_PREPROCESSED_COLUMNS,
    );
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(@constCast(column.values));
        allocator.free(columns);
    }
    for (columns[0..2]) |*column| {
        const values = try allocator.alloc(M31, execution_size);
        @memset(values, M31.zero());
        column.* = .{ .log_size = log_size, .values = values };
        initialized += 1;
    }
    for (columns[2..5]) |*column| {
        const values = try allocator.alloc(M31, rom_mod.SIZE);
        @memset(values, M31.zero());
        column.* = .{ .log_size = rom_mod.LOG_SIZE, .values = values };
        initialized += 1;
    }
    for (columns[5..]) |*column| {
        const values = try allocator.alloc(M31, memory_mod.SIZE);
        @memset(values, M31.zero());
        column.* = .{ .log_size = 16, .values = values };
        initialized += 1;
    }
    @constCast(columns[0].values)[
        try core_air_utils.circleBitReversedIndex(log_size, 0)
    ] = M31.one();
    @constCast(columns[1].values)[
        try core_air_utils.circleBitReversedIndex(
            log_size,
            execution_size - 1,
        )
    ] = M31.one();
    @constCast(columns[2].values)[
        try core_air_utils.circleBitReversedIndex(rom_mod.LOG_SIZE, 0)
    ] = M31.one();
    @constCast(columns[5].values)[
        try core_air_utils.circleBitReversedIndex(16, 0)
    ] = M31.one();
    for (0..rom_mod.SIZE) |address| {
        const storage = try core_air_utils.circleBitReversedIndex(
            rom_mod.LOG_SIZE,
            address,
        );
        @constCast(columns[3].values)[storage] = M31.fromCanonical(@intCast(address));
        @constCast(columns[4].values)[storage] = M31.fromCanonical(rom.bytes[address]);
    }
    for (0..memory_mod.SIZE) |address| {
        const storage = try core_air_utils.circleBitReversedIndex(16, address);
        @constCast(columns[6].values)[storage] = M31.fromCanonical(@intCast(address));
        @constCast(columns[7].values)[storage] =
            M31.fromCanonical(initial_memory.bytes[address]);
        @constCast(columns[8].values)[storage] =
            M31.fromCanonical(final_memory.bytes[address]);
    }
    return columns;
}

pub fn mutateUnusedRomByte(
    preprocessed: []const prover_pcs.ColumnEvaluation,
    steps: []const runner.StepTrace,
) !void {
    var candidate = rom_mod.SIZE;
    const address = while (candidate > 0) {
        candidate -= 1;
        var used = false;
        for (steps) |step| {
            for (step.activeCycles()[0..step.decoded.instruction.length]) |cycle| {
                if (cycle.address == candidate) used = true;
            }
        }
        if (!used) break candidate;
    } else return error.NoUnusedRomByte;
    const storage = try core_air_utils.circleBitReversedIndex(
        rom_mod.LOG_SIZE,
        address,
    );
    const values = @constCast(preprocessed[4].values);
    values[storage] = values[storage].add(M31.one());
}

pub fn mutateUnusedMemoryByte(
    preprocessed: []const prover_pcs.ColumnEvaluation,
    accesses: []const memory_lookup.Access,
) !void {
    var candidate = memory_mod.SIZE;
    const address = while (candidate > 0) {
        candidate -= 1;
        var used = false;
        for (accesses) |access| {
            if (access.enabled and access.address == candidate) {
                used = true;
                break;
            }
        }
        if (!used) break candidate;
    } else return error.NoUnusedMemoryByte;
    const storage = try core_air_utils.circleBitReversedIndex(16, address);
    for ([_]usize{ 7, 8 }) |column| {
        const values = @constCast(preprocessed[column].values);
        values[storage] = values[storage].add(M31.one());
    }
}

pub fn mixPublic(channel: *Channel, statement: ExecutionStatement) void {
    var values: [2 + 2 * execution.N_STATE_COLUMNS]u32 = undefined;
    values[0] = statement.log_size;
    values[1] = statement.initial.mcycle;
    const initial = execution.stateFromCpu(M31, statement.initial.cpu);
    const final = execution.stateFromCpu(M31, statement.final.cpu);
    for (initial.values, values[2 .. 2 + execution.N_STATE_COLUMNS]) |value, *output| {
        output.* = value.toU32();
    }
    for (
        final.values,
        values[2 + execution.N_STATE_COLUMNS ..],
    ) |value, *output| {
        output.* = value.toU32();
    }
    channel.mixU32s(&values);
    channel.mixU32s(&.{statement.final.mcycle});
    for ([_][32]u8{
        statement.rom_digest,
        statement.initial_memory_digest,
        statement.final_memory_digest,
    }) |digest| {
        var digest_words: [8]u32 = undefined;
        for (&digest_words, 0..) |*word, index| {
            word.* = std.mem.readInt(
                u32,
                digest[4 * index ..][0..4],
                .little,
            );
        }
        channel.mixU32s(&digest_words);
    }
}

pub fn mixLookupClaims(
    channel: *Channel,
    program_claims: program_lookup.Claims,
    memory_claims: memory_lookup.Claims,
) void {
    channel.mixFelts(&.{
        program_claims.execution[0],
        program_claims.execution[1],
        program_claims.rom,
    });
    channel.mixFelts(&memory_claims.execution);
    channel.mixFelts(&.{memory_claims.boundary});
}

test "proof statement rejects enabled timer memory until its overlay exists" {
    var bytes = [_]u8{0} ** memory_mod.SIZE;
    bytes[TAC] = 0x04;
    const memory = try memory_mod.Image.init(&bytes);
    const rom = try rom_mod.Rom.init(bytes[0..rom_mod.SIZE]);
    const statement = init(
        4,
        .{ .cpu = .{}, .mcycle = 0 },
        .{ .cpu = .{}, .mcycle = 16 },
        rom,
        memory,
        memory,
    );
    try std.testing.expectError(
        error.UnsupportedTimerState,
        validate(statement, rom, memory, memory),
    );
    var noncanonical_clock = statement;
    noncanonical_clock.initial.mcycle = M31_MODULUS - 16;
    noncanonical_clock.final.mcycle = M31_MODULUS;
    try std.testing.expectError(
        error.InvalidProofShape,
        validateShape(noncanonical_clock),
    );
}

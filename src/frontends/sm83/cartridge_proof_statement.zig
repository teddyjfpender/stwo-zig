//! Public statement and commitment geometry for CPU-only cartridge proofs.
//!
//! Detached MBC3 proof over public ROM/memory/SRAM/mapper; devices absent.

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
const cartridge_access = @import("air/cartridge_access_component.zig");
const rom_lookup = @import("air/cartridge_rom_lookup.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const cartridge = @import("cartridge/mod.zig");
const memory = @import("memory.zig");

const Channel = channel_blake2s.Blake2sChannel;
const Hasher = blake2_merkle.Blake2sPrefixedMerkleHasher;

/// Transcript domain separation for the detached-device statement.
pub const MODE_TAG: u32 = 0x534d_4301;

pub const EXECUTION_MAIN_OFFSET: usize = 0;
pub const FAMILY_MAIN_OFFSET: usize =
    EXECUTION_MAIN_OFFSET + execution.N_MAIN_COLUMNS;
pub const PACKED_ACCESS_MAIN_OFFSET: usize =
    FAMILY_MAIN_OFFSET + family_trace.N_MAIN_COLUMNS;
pub const MUTABLE_WITNESS_MAIN_OFFSET: usize =
    PACKED_ACCESS_MAIN_OFFSET + cartridge_access.N_MAIN_COLUMNS;
pub const ROM_MULTIPLICITY_MAIN_OFFSET: usize =
    MUTABLE_WITNESS_MAIN_OFFSET + memory_lookup.N_MAIN_COLUMNS;
pub const FINAL_CLOCK_MAIN_OFFSET: usize =
    ROM_MULTIPLICITY_MAIN_OFFSET + 1;
pub const N_MAIN_COLUMNS: usize = FINAL_CLOCK_MAIN_OFFSET + 1;

pub const ROM_EXECUTION_INTERACTION_OFFSET: usize = 0;
pub const MUTABLE_EXECUTION_INTERACTION_OFFSET: usize =
    ROM_EXECUTION_INTERACTION_OFFSET + rom_lookup.N_EXECUTION_COLUMNS;
pub const ROM_TABLE_INTERACTION_OFFSET: usize =
    MUTABLE_EXECUTION_INTERACTION_OFFSET +
    memory_lookup.N_EXECUTION_COLUMNS;
pub const MUTABLE_BOUNDARY_INTERACTION_OFFSET: usize =
    ROM_TABLE_INTERACTION_OFFSET + rom_lookup.N_ROM_COLUMNS;
pub const N_INTERACTION_COLUMNS: usize =
    MUTABLE_BOUNDARY_INTERACTION_OFFSET +
    memory_lookup.N_BOUNDARY_COLUMNS;

pub const EXECUTION_FIRST_PREPROCESSED: usize = 0;
pub const EXECUTION_LAST_PREPROCESSED: usize = 1;
pub const ROM_FIRST_PREPROCESSED: usize = 2;
pub const ROM_ADDRESS_PREPROCESSED: usize = 3;
pub const ROM_VALUE_PREPROCESSED: usize = 4;
pub const MEMORY_FIRST_PREPROCESSED: usize = 5;
pub const MEMORY_ENABLED_PREPROCESSED: usize = 6;
pub const MEMORY_ADDRESS_PREPROCESSED: usize = 7;
pub const MEMORY_INITIAL_PREPROCESSED: usize = 8;
pub const MEMORY_FINAL_PREPROCESSED: usize = 9;
pub const N_PREPROCESSED_COLUMNS: usize = 10;

comptime {
    std.debug.assert(@TypeOf((cartridge.State{}).rom_bank_register) == u7);
    std.debug.assert(@TypeOf((cartridge.State{}).ram_bank_register) == u3);
    std.debug.assert(@TypeOf((cartridge.State{}).ram_enabled) == bool);
    std.debug.assert(rom_lookup.ROM_SIZE == cartridge.header.ROM_SIZE);
    std.debug.assert(memory_lookup.SYSTEM_SIZE == memory.SIZE);
    std.debug.assert(memory_lookup.SRAM_SIZE == cartridge.header.RAM_SIZE);
}

pub const ExecutionStatement = struct {
    log_size: u32,
    initial: execution.Boundary,
    final: execution.Boundary,
    initial_mapper: cartridge.State,
    final_mapper: cartridge.State,
    rom_digest: [32]u8,
    initial_system_digest: [32]u8,
    final_system_digest: [32]u8,
    initial_sram_digest: [32]u8,
    final_sram_digest: [32]u8,
    rom_lookup_claims: rom_lookup.Claims,
    memory_lookup_claims: memory_lookup.Claims,
};

pub fn init(
    log_size: u32,
    initial: execution.Boundary,
    final: execution.Boundary,
    initial_mapper: cartridge.State,
    final_mapper: cartridge.State,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
) ExecutionStatement {
    return .{
        .log_size = log_size,
        .initial = initial,
        .final = final,
        .initial_mapper = initial_mapper,
        .final_mapper = final_mapper,
        .rom_digest = rom.digest(),
        .initial_system_digest = initial_images.system.digest(),
        .final_system_digest = final_images.system.digest(),
        .initial_sram_digest = digest(initial_images.sram.bytes),
        .final_sram_digest = digest(final_images.sram.bytes),
        .rom_lookup_claims = .{
            .execution = .{QM31.zero()} ** rom_lookup.N_EXECUTION_SUMS,
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
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
) !void {
    try validateShape(statement);
    const canonical_cartridge = try cartridge.Cartridge.init(rom.bytes);
    if (initial_images.system.bytes.len != memory_lookup.SYSTEM_SIZE or
        final_images.system.bytes.len != memory_lookup.SYSTEM_SIZE)
        return error.InvalidSystemMemoryShape;
    if (initial_images.sram.bytes.len != memory_lookup.SRAM_SIZE or
        final_images.sram.bytes.len != memory_lookup.SRAM_SIZE)
        return error.InvalidSramShape;
    if (!std.meta.eql(rom.header, canonical_cartridge.header))
        return error.CartridgeHeaderMismatch;
    if (!std.mem.eql(u8, &statement.rom_digest, &rom.digest()))
        return error.RomDigestMismatch;
    if (!std.mem.eql(
        u8,
        &statement.initial_system_digest,
        &initial_images.system.digest(),
    )) return error.InitialSystemDigestMismatch;
    if (!std.mem.eql(
        u8,
        &statement.final_system_digest,
        &final_images.system.digest(),
    )) return error.FinalSystemDigestMismatch;
    if (!std.mem.eql(
        u8,
        &statement.initial_sram_digest,
        &digest(initial_images.sram.bytes),
    )) return error.InitialSramDigestMismatch;
    if (!std.mem.eql(
        u8,
        &statement.final_sram_digest,
        &digest(final_images.sram.bytes),
    )) return error.FinalSramDigestMismatch;
}

pub fn validateShape(statement: ExecutionStatement) !void {
    if (statement.log_size < 4 or statement.log_size > 24)
        return error.InvalidLogSize;
    if (statement.initial.cpu.f & 0x0f != 0 or
        statement.final.cpu.f & 0x0f != 0 or
        statement.initial.mcycle >= M31_MODULUS or
        statement.final.mcycle >= M31_MODULUS or
        statement.final.mcycle >
            memory_lookup.memory_clock.MAX_FINAL_MCYCLE or
        statement.final.mcycle < statement.initial.mcycle)
        return error.InvalidProofShape;
    const rows = @as(u64, 1) << @intCast(statement.log_size);
    const mcycles = @as(u64, statement.final.mcycle) -
        statement.initial.mcycle;
    if (mcycles < rows or mcycles > rows * execution.N_BUS_CYCLES)
        return error.InvalidProofShape;
}

pub fn preprocessedLogSizes(
    log_size: u32,
) [N_PREPROCESSED_COLUMNS]u32 {
    return .{
        log_size,
        log_size,
        rom_lookup.ROM_LOG_SIZE,
        rom_lookup.ROM_LOG_SIZE,
        rom_lookup.ROM_LOG_SIZE,
        memory_lookup.BOUNDARY_LOG_SIZE,
        memory_lookup.BOUNDARY_LOG_SIZE,
        memory_lookup.BOUNDARY_LOG_SIZE,
        memory_lookup.BOUNDARY_LOG_SIZE,
        memory_lookup.BOUNDARY_LOG_SIZE,
    };
}

pub fn mainLogSizes(log_size: u32) [N_MAIN_COLUMNS]u32 {
    var result: [N_MAIN_COLUMNS]u32 = undefined;
    @memset(result[0..ROM_MULTIPLICITY_MAIN_OFFSET], log_size);
    result[ROM_MULTIPLICITY_MAIN_OFFSET] = rom_lookup.ROM_LOG_SIZE;
    result[FINAL_CLOCK_MAIN_OFFSET] = memory_lookup.BOUNDARY_LOG_SIZE;
    return result;
}

pub fn interactionLogSizes(
    log_size: u32,
) [N_INTERACTION_COLUMNS]u32 {
    var result: [N_INTERACTION_COLUMNS]u32 = undefined;
    @memset(result[0..ROM_TABLE_INTERACTION_OFFSET], log_size);
    @memset(
        result[ROM_TABLE_INTERACTION_OFFSET..MUTABLE_BOUNDARY_INTERACTION_OFFSET],
        rom_lookup.ROM_LOG_SIZE,
    );
    @memset(
        result[MUTABLE_BOUNDARY_INTERACTION_OFFSET..],
        memory_lookup.BOUNDARY_LOG_SIZE,
    );
    return result;
}

pub fn validatePreparedGeometry(
    preprocessed: []const prover_pcs.ColumnEvaluation,
    main: []const prover_pcs.ColumnEvaluation,
    interaction: []const prover_pcs.ColumnEvaluation,
    log_size: u32,
) !void {
    try validateColumnLogs(preprocessed, &preprocessedLogSizes(log_size));
    try validateColumnLogs(main, &mainLogSizes(log_size));
    try validateColumnLogs(interaction, &interactionLogSizes(log_size));
}

pub fn verifyPreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: ExecutionStatement,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    actual: Hasher.Hash,
) !void {
    const columns = try canonicalPreprocessed(
        allocator,
        statement.log_size,
        rom,
        initial_images,
        final_images,
    );
    var columns_moved = false;
    errdefer if (!columns_moved) freeColumns(allocator, columns);
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
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
) ![]prover_pcs.ColumnEvaluation {
    if (log_size < 4 or log_size > 24) return error.InvalidLogSize;
    if (rom.bytes.len != rom_lookup.ROM_SIZE)
        return error.InvalidRomSize;
    if (initial_images.system.bytes.len != memory_lookup.SYSTEM_SIZE or
        final_images.system.bytes.len != memory_lookup.SYSTEM_SIZE)
        return error.InvalidSystemMemoryShape;
    if (initial_images.sram.bytes.len != memory_lookup.SRAM_SIZE or
        final_images.sram.bytes.len != memory_lookup.SRAM_SIZE)
        return error.InvalidSramShape;

    const logs = preprocessedLogSizes(log_size);
    const columns = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        N_PREPROCESSED_COLUMNS,
    );
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column|
            allocator.free(@constCast(column.values));
        allocator.free(columns);
    }
    for (columns, logs) |*column, column_log_size| {
        const values = try allocator.alloc(
            M31,
            @as(usize, 1) << @intCast(column_log_size),
        );
        @memset(values, M31.zero());
        column.* = .{
            .log_size = column_log_size,
            .values = values,
        };
        initialized += 1;
    }

    try set(columns, EXECUTION_FIRST_PREPROCESSED, log_size, 0, 1);
    try set(
        columns,
        EXECUTION_LAST_PREPROCESSED,
        log_size,
        (@as(usize, 1) << @intCast(log_size)) - 1,
        1,
    );
    try set(
        columns,
        ROM_FIRST_PREPROCESSED,
        rom_lookup.ROM_LOG_SIZE,
        0,
        1,
    );
    for (0..rom_lookup.ROM_SIZE) |address| {
        try set(
            columns,
            ROM_ADDRESS_PREPROCESSED,
            rom_lookup.ROM_LOG_SIZE,
            address,
            @intCast(address),
        );
        try set(
            columns,
            ROM_VALUE_PREPROCESSED,
            rom_lookup.ROM_LOG_SIZE,
            address,
            rom.bytes[address],
        );
    }
    try set(
        columns,
        MEMORY_FIRST_PREPROCESSED,
        memory_lookup.BOUNDARY_LOG_SIZE,
        0,
        1,
    );
    for (0..memory_lookup.KEY_COUNT) |address| {
        try set(
            columns,
            MEMORY_ENABLED_PREPROCESSED,
            memory_lookup.BOUNDARY_LOG_SIZE,
            address,
            1,
        );
        try set(
            columns,
            MEMORY_ADDRESS_PREPROCESSED,
            memory_lookup.BOUNDARY_LOG_SIZE,
            address,
            @intCast(address),
        );
        const initial_byte = imageByte(initial_images, address);
        const final_byte = imageByte(final_images, address);
        try set(
            columns,
            MEMORY_INITIAL_PREPROCESSED,
            memory_lookup.BOUNDARY_LOG_SIZE,
            address,
            initial_byte,
        );
        try set(
            columns,
            MEMORY_FINAL_PREPROCESSED,
            memory_lookup.BOUNDARY_LOG_SIZE,
            address,
            final_byte,
        );
    }
    return columns;
}

pub fn mutateUnusedRomByte(
    preprocessed: []const prover_pcs.ColumnEvaluation,
) !void {
    try mutate(
        preprocessed,
        ROM_VALUE_PREPROCESSED,
        rom_lookup.ROM_LOG_SIZE,
        rom_lookup.ROM_SIZE - 1,
    );
}

pub fn mutateUnusedSystemByte(
    preprocessed: []const prover_pcs.ColumnEvaluation,
) !void {
    try mutateBoundary(preprocessed, memory_lookup.SYSTEM_SIZE - 1);
}

pub fn mutateUnusedSramByte(
    preprocessed: []const prover_pcs.ColumnEvaluation,
) !void {
    try mutateBoundary(preprocessed, memory_lookup.KEY_COUNT - 1);
}

pub fn mixPublic(channel: *Channel, statement: ExecutionStatement) void {
    channel.mixU32s(&.{
        MODE_TAG,
        statement.log_size,
        statement.initial.mcycle,
    });
    mixCpu(channel, statement.initial.cpu);
    channel.mixU32s(&.{statement.final.mcycle});
    mixCpu(channel, statement.final.cpu);
    mixMapper(channel, statement.initial_mapper);
    mixMapper(channel, statement.final_mapper);
    for ([_][32]u8{
        statement.rom_digest,
        statement.initial_system_digest,
        statement.final_system_digest,
        statement.initial_sram_digest,
        statement.final_sram_digest,
    }) |value| mixDigest(channel, value);
}

pub fn mixLookupClaims(
    channel: *Channel,
    rom_claims: rom_lookup.Claims,
    memory_claims: memory_lookup.Claims,
) void {
    channel.mixFelts(&rom_claims.execution);
    channel.mixFelts(&.{rom_claims.rom});
    channel.mixFelts(&memory_claims.execution);
    channel.mixFelts(&.{memory_claims.boundary});
}

fn validateColumnLogs(
    columns: []const prover_pcs.ColumnEvaluation,
    expected: []const u32,
) !void {
    if (columns.len != expected.len)
        return error.InvalidPreparedGeometry;
    for (columns, expected) |column, expected_log_size| {
        if (column.log_size != expected_log_size or
            column.values.len !=
                @as(usize, 1) << @intCast(expected_log_size))
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

fn mutate(
    columns: []const prover_pcs.ColumnEvaluation,
    column: usize,
    log_size: u32,
    logical_row: usize,
) !void {
    if (columns.len != N_PREPROCESSED_COLUMNS)
        return error.InvalidPreparedGeometry;
    const storage = try core_air_utils.circleBitReversedIndex(
        log_size,
        logical_row,
    );
    const values = @constCast(columns[column].values);
    values[storage] = values[storage].add(M31.one());
}

fn restore(
    columns: []const prover_pcs.ColumnEvaluation,
    column: usize,
    log_size: u32,
    logical_row: usize,
) !void {
    if (columns.len != N_PREPROCESSED_COLUMNS)
        return error.InvalidPreparedGeometry;
    const storage = try core_air_utils.circleBitReversedIndex(
        log_size,
        logical_row,
    );
    const values = @constCast(columns[column].values);
    values[storage] = values[storage].sub(M31.one());
}

fn mutateBoundary(
    columns: []const prover_pcs.ColumnEvaluation,
    address: usize,
) !void {
    try mutate(
        columns,
        MEMORY_INITIAL_PREPROCESSED,
        memory_lookup.BOUNDARY_LOG_SIZE,
        address,
    );
    try mutate(
        columns,
        MEMORY_FINAL_PREPROCESSED,
        memory_lookup.BOUNDARY_LOG_SIZE,
        address,
    );
}

fn imageByte(images: memory_lookup.Images, address: usize) u8 {
    return if (address < memory_lookup.SYSTEM_SIZE)
        images.system.bytes[address]
    else
        images.sram.bytes[address - memory_lookup.SRAM_KEY_OFFSET];
}

fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

fn mixCpu(channel: *Channel, cpu: @import("runner/mod.zig").Cpu) void {
    const state = execution.stateFromCpu(M31, cpu);
    var values: [execution.N_STATE_COLUMNS]u32 = undefined;
    for (state.values, &values) |value, *output|
        output.* = value.toU32();
    channel.mixU32s(&values);
}

fn mixMapper(channel: *Channel, state: cartridge.State) void {
    channel.mixU32s(&.{
        state.rom_bank_register,
        state.ram_bank_register,
        @intFromBool(state.ram_enabled),
    });
}

fn mixDigest(channel: *Channel, value: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index| {
        word.* = std.mem.readInt(
            u32,
            value[4 * index ..][0..4],
            .little,
        );
    }
    channel.mixU32s(&words);
}

fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}

fn preprocessingFingerprint(
    columns: []const prover_pcs.ColumnEvaluation,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var bytes: [4]u8 = undefined;
    for (columns) |column| {
        std.mem.writeInt(u32, &bytes, column.log_size, .little);
        hash.update(&bytes);
        for (column.values) |value| {
            std.mem.writeInt(u32, &bytes, value.toU32(), .little);
            hash.update(&bytes);
        }
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

const Fixture = struct {
    rom_bytes: *[cartridge.header.ROM_SIZE]u8,
    initial_system: *[memory.SIZE]u8,
    final_system: *[memory.SIZE]u8,
    initial_sram: *[cartridge.header.RAM_SIZE]u8,
    final_sram: *[cartridge.header.RAM_SIZE]u8,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,

    fn initFixture(allocator: std.mem.Allocator) !Fixture {
        const rom_bytes = try allocator.create(
            [cartridge.header.ROM_SIZE]u8,
        );
        errdefer allocator.destroy(rom_bytes);
        const initial_system = try allocator.create([memory.SIZE]u8);
        errdefer allocator.destroy(initial_system);
        const final_system = try allocator.create([memory.SIZE]u8);
        errdefer allocator.destroy(final_system);
        const initial_sram = try allocator.create(
            [cartridge.header.RAM_SIZE]u8,
        );
        errdefer allocator.destroy(initial_sram);
        const final_sram = try allocator.create(
            [cartridge.header.RAM_SIZE]u8,
        );
        errdefer allocator.destroy(final_sram);
        @memset(rom_bytes, 0);
        @memset(initial_system, 0);
        @memset(initial_sram, 0);
        rom_bytes[cartridge.header.CARTRIDGE_TYPE_OFFSET] =
            cartridge.header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
        rom_bytes[cartridge.header.ROM_SIZE_CODE_OFFSET] =
            cartridge.header.ROM_SIZE_CODE_1_MIB;
        rom_bytes[cartridge.header.RAM_SIZE_CODE_OFFSET] =
            cartridge.header.RAM_SIZE_CODE_32_KIB;
        rom_bytes[cartridge.header.HEADER_CHECKSUM_OFFSET] =
            cartridge.header.headerChecksum(rom_bytes);
        const checksum = cartridge.header.globalChecksum(rom_bytes);
        std.mem.writeInt(
            u16,
            rom_bytes[cartridge.header.GLOBAL_CHECKSUM_OFFSET..cartridge.header.HEADER_END][0..2],
            checksum,
            .big,
        );
        @memcpy(final_system, initial_system);
        @memcpy(final_sram, initial_sram);
        final_system[0xc000] = 7;
        final_sram[0] = 9;
        const rom = try cartridge.Cartridge.init(rom_bytes);
        const initial_images: memory_lookup.Images = .{
            .system = try memory.Image.init(initial_system),
            .sram = try memory_lookup.SramImage.init(initial_sram),
        };
        const final_images: memory_lookup.Images = .{
            .system = try memory.Image.init(final_system),
            .sram = try memory_lookup.SramImage.init(final_sram),
        };
        return .{
            .rom_bytes = rom_bytes,
            .initial_system = initial_system,
            .final_system = final_system,
            .initial_sram = initial_sram,
            .final_sram = final_sram,
            .rom = rom,
            .initial_images = initial_images,
            .final_images = final_images,
        };
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        allocator.destroy(self.final_sram);
        allocator.destroy(self.initial_sram);
        allocator.destroy(self.final_system);
        allocator.destroy(self.initial_system);
        allocator.destroy(self.rom_bytes);
        self.* = undefined;
    }

    fn statement(self: Fixture) ExecutionStatement {
        return init(
            4,
            .{ .cpu = .{}, .mcycle = 0 },
            .{ .cpu = .{}, .mcycle = 16 },
            .{},
            .{
                .rom_bank_register = 3,
                .ram_bank_register = 2,
                .ram_enabled = true,
            },
            self.rom,
            self.initial_images,
            self.final_images,
        );
    }
};

test "cartridge statement canonical preprocessing fixes all domains" {
    var fixture = try Fixture.initFixture(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    const statement = fixture.statement();
    try validate(
        statement,
        fixture.rom,
        fixture.initial_images,
        fixture.final_images,
    );
    const columns = try canonicalPreprocessed(
        std.testing.allocator,
        statement.log_size,
        fixture.rom,
        fixture.initial_images,
        fixture.final_images,
    );
    defer freeColumns(std.testing.allocator, columns);
    try validateColumnLogs(columns, &preprocessedLogSizes(4));
    const padding = try core_air_utils.circleBitReversedIndex(
        memory_lookup.BOUNDARY_LOG_SIZE,
        memory_lookup.KEY_COUNT,
    );
    for ([_]usize{
        MEMORY_ENABLED_PREPROCESSED,
        MEMORY_ADDRESS_PREPROCESSED,
        MEMORY_INITIAL_PREPROCESSED,
        MEMORY_FINAL_PREPROCESSED,
    }) |column| try std.testing.expect(columns[column].values[padding].isZero());
    try std.testing.expect(!std.mem.allEqual(
        u8,
        &preprocessingFingerprint(columns),
        0,
    ));
}

test "cartridge statement unused ROM system and SRAM mutations change root material" {
    var fixture = try Fixture.initFixture(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    const columns = try canonicalPreprocessed(
        std.testing.allocator,
        4,
        fixture.rom,
        fixture.initial_images,
        fixture.final_images,
    );
    defer freeColumns(std.testing.allocator, columns);
    const baseline = preprocessingFingerprint(columns);
    try mutateUnusedRomByte(columns);
    try std.testing.expect(!std.mem.eql(
        u8,
        &baseline,
        &preprocessingFingerprint(columns),
    ));
    try restore(
        columns,
        ROM_VALUE_PREPROCESSED,
        rom_lookup.ROM_LOG_SIZE,
        rom_lookup.ROM_SIZE - 1,
    );
    try std.testing.expectEqualSlices(
        u8,
        &baseline,
        &preprocessingFingerprint(columns),
    );
    try mutateUnusedSystemByte(columns);
    try std.testing.expect(!std.mem.eql(
        u8,
        &baseline,
        &preprocessingFingerprint(columns),
    ));
    for ([_]usize{
        MEMORY_INITIAL_PREPROCESSED,
        MEMORY_FINAL_PREPROCESSED,
    }) |column| try restore(
        columns,
        column,
        memory_lookup.BOUNDARY_LOG_SIZE,
        memory_lookup.SYSTEM_SIZE - 1,
    );
    try std.testing.expectEqualSlices(
        u8,
        &baseline,
        &preprocessingFingerprint(columns),
    );
    try mutateUnusedSramByte(columns);
    try std.testing.expect(!std.mem.eql(
        u8,
        &baseline,
        &preprocessingFingerprint(columns),
    ));
}

test "cartridge statement mapper and claim mutations change the transcript" {
    var fixture = try Fixture.initFixture(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    const statement = fixture.statement();
    var baseline = Channel{};
    mixPublic(&baseline, statement);
    mixLookupClaims(
        &baseline,
        statement.rom_lookup_claims,
        statement.memory_lookup_claims,
    );
    var mutated_statement = statement;
    mutated_statement.final_mapper.rom_bank_register = 4;
    var mutated = Channel{};
    mixPublic(&mutated, mutated_statement);
    mixLookupClaims(
        &mutated,
        mutated_statement.rom_lookup_claims,
        mutated_statement.memory_lookup_claims,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &baseline.digestBytes(),
        &mutated.digestBytes(),
    ));
    var claim_statement = statement;
    claim_statement.rom_lookup_claims.rom = QM31.one();
    var claim_mutated = Channel{};
    mixPublic(&claim_mutated, claim_statement);
    mixLookupClaims(
        &claim_mutated,
        claim_statement.rom_lookup_claims,
        claim_statement.memory_lookup_claims,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &baseline.digestBytes(),
        &claim_mutated.digestBytes(),
    ));
}

test "cartridge statement rejects shape and digest substitutions" {
    var fixture = try Fixture.initFixture(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    const statement = fixture.statement();
    var bad_shape = statement;
    bad_shape.log_size = 3;
    try std.testing.expectError(error.InvalidLogSize, validateShape(bad_shape));
    bad_shape = statement;
    bad_shape.initial.mcycle = M31_MODULUS - 16;
    bad_shape.final.mcycle = M31_MODULUS;
    try std.testing.expectError(
        error.InvalidProofShape,
        validateShape(bad_shape),
    );
    bad_shape = statement;
    bad_shape.initial.mcycle =
        memory_lookup.memory_clock.MAX_FINAL_MCYCLE - 16;
    bad_shape.final.mcycle =
        memory_lookup.memory_clock.MAX_FINAL_MCYCLE + 1;
    try std.testing.expectError(
        error.InvalidProofShape,
        validateShape(bad_shape),
    );
    fixture.final_system[0xffff] = 1;
    try std.testing.expectError(
        error.FinalSystemDigestMismatch,
        validate(
            statement,
            fixture.rom,
            fixture.initial_images,
            fixture.final_images,
        ),
    );
    fixture.final_system[0xffff] = 0;
    fixture.final_sram[cartridge.header.RAM_SIZE - 1] = 1;
    try std.testing.expectError(
        error.FinalSramDigestMismatch,
        validate(
            statement,
            fixture.rom,
            fixture.initial_images,
            fixture.final_images,
        ),
    );
}

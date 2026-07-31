//! Geometry, ownership, and detachment controls for v7 trace assembly.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const transaction = @import("stwo_prover_engine").transaction;
const subject = @import("machine_environment_trace.zig");
const geometry = @import("machine_environment_geometry.zig");
const environment = @import("environment_statement.zig");
const base = @import("cartridge_proof_statement.zig");
const replay_mod = @import("machine_environment_memory_replay.zig");
const cartridge_prover = @import("cartridge_prover.zig");
const execution = @import("air/execution.zig");
const execution_trace = @import("air/execution_trace.zig");
const family_trace = @import("air/family_trace.zig");
const machine_trace = @import("air/machine_scheduler_trace.zig");
const scheduler_component = @import("air/scheduler_component.zig");
const scheduler_binding = @import("air/scheduler_binding.zig");
const scheduler_memory = @import("air/scheduler_memory_lookup.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const rom_lookup = @import("air/cartridge_rom_lookup.zig");
const joypad_binding = @import("air/joypad_binding.zig");
const joypad_if = @import("air/joypad_if_memory_lookup.zig");
const timer_binding = @import("air/timer_binding.zig");
const timer_if = @import("air/timer_if_memory_lookup.zig");
const observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const service_memory =
    @import("air/interrupt_service_memory_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const ppu_mmio = @import("air/ppu_mmio_lookup.zig");
const ppu_if = @import("air/ppu_if_memory_lookup.zig");
const ppu_execution_policy = @import("ppu_execution_policy.zig");
const dma_binding = @import("air/dma_binding.zig");
const dma_memory = @import("air/dma_memory_lookup.zig");
const apu_binding = @import("air/apu_binding.zig");
const apu_execution = @import("air/apu_execution_lookup.zig");

const LOG_SIZE: u32 = 4;
const SIZE: usize = 1 << LOG_SIZE;

test "machine environment trace preserves v6 prefix and exact v7 geometry" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const prefix_columns = fixture.v3_preprocessed.columns.?;
    var prefix_pointers: [environment.N_PREPROCESSED_COLUMNS][*]const M31 = undefined;
    for (prefix_columns, &prefix_pointers) |column, *pointer|
        pointer.* = column.values.ptr;
    const multiplicity_pointer = fixture.rom_multiplicity.values.?.ptr;
    const final_clock_pointer = fixture.replay.memory.final_clocks.ptr;
    const ppu_auxiliary_pointer =
        fixture.ppu_auxiliary.ly_write_values.ptr;
    const ordinary_row: usize = 0xc000;
    const ordinary_storage = try boundaryStorage(ordinary_row);
    const ordinary_value = prefix_columns[
        base.MEMORY_ADDRESS_PREPROCESSED
    ].values[ordinary_storage];

    var prepared = try subject.assemble(
        std.testing.allocator,
        fixture.sources(),
    );
    defer prepared.deinit(std.testing.allocator);
    try prepared.validate();
    const preprocessed = prepared.trace.preprocessed.columns.?;
    const main = prepared.trace.main.columns.?;
    try std.testing.expectEqual(
        geometry.N_PREPROCESSED_COLUMNS,
        preprocessed.len,
    );
    try std.testing.expectEqual(geometry.N_MAIN_COLUMNS, main.len);
    for (
        preprocessed[0..environment.N_PREPROCESSED_COLUMNS],
        prefix_pointers,
    ) |column, pointer| try std.testing.expectEqual(
        pointer,
        column.values.ptr,
    );
    try expectPointersAt(
        main,
        base.EXECUTION_MAIN_OFFSET,
        fixture.machine.execution.main,
    );
    try expectPointersAt(
        main,
        base.FAMILY_MAIN_OFFSET,
        fixture.machine.families.main,
    );
    try expectPointersAt(
        main,
        base.PACKED_ACCESS_MAIN_OFFSET,
        fixture.packed_access.columns,
    );
    try expectPointersAt(
        main,
        base.MUTABLE_WITNESS_MAIN_OFFSET,
        fixture.replay.memory.main,
    );
    try std.testing.expectEqual(
        multiplicity_pointer,
        main[base.ROM_MULTIPLICITY_MAIN_OFFSET].values.ptr,
    );
    try std.testing.expectEqual(
        final_clock_pointer,
        main[base.FINAL_CLOCK_MAIN_OFFSET].values.ptr,
    );
    try expectPointersAt(
        main,
        environment.JOYPAD_BINDING_MAIN_OFFSET,
        fixture.joypad_binding.main,
    );
    try expectPointersAt(
        main,
        environment.JOYPAD_IF_MAIN_OFFSET,
        fixture.joypad_if.main,
    );
    try expectPointersAt(
        main,
        environment.TIMER_BINDING_MAIN_OFFSET,
        fixture.timer_binding.main,
    );
    try expectPointersAt(
        main,
        environment.TIMER_IF_MAIN_OFFSET,
        fixture.timer_if.main,
    );
    try expectPointersAt(
        main,
        environment.INTERMEDIATE_OBSERVATION_MAIN_OFFSET,
        fixture.observation.main,
    );
    try expectPointersAt(
        main,
        geometry.SCHEDULER_MAIN_OFFSET,
        fixture.machine.scheduler_main,
    );
    try expectPointersAt(
        main,
        geometry.SCHEDULER_PROVENANCE_MAIN_OFFSET,
        fixture.machine.provenance_main,
    );
    try expectPointersAt(
        main,
        geometry.SCHEDULER_MEMORY_MAIN_OFFSET,
        fixture.machine.scheduler_memory.main,
    );
    try expectPointersAt(
        main,
        geometry.SERVICE_MEMORY_MAIN_OFFSET,
        fixture.service_memory.main,
    );
    try expectPointersAt(
        main,
        geometry.PPU_BINDING_MAIN_OFFSET,
        fixture.ppu_binding.main,
    );
    try std.testing.expectEqual(
        ppu_auxiliary_pointer,
        main[geometry.PPU_AUXILIARY_MAIN_OFFSET].values.ptr,
    );
    try expectPointersAt(
        main,
        geometry.PPU_IF_MAIN_OFFSET,
        fixture.ppu_if.main,
    );
    try expectPointersAt(
        main,
        geometry.PPU_EXECUTION_POLICY_MAIN_OFFSET,
        fixture.ppu_policy.main,
    );
    try expectPointersAt(
        main,
        geometry.DMA_BINDING_MAIN_OFFSET,
        fixture.dma_binding.main,
    );
    try expectPointersAt(
        main,
        geometry.DMA_MEMORY_MAIN_OFFSET,
        fixture.dma_memory.main,
    );
    try expectPointersAt(
        main,
        geometry.APU_BINDING_MAIN_OFFSET,
        fixture.apu_binding.main,
    );
    try std.testing.expectEqual(
        fixture.apu_auxiliary.execution_order_before.ptr,
        main[geometry.APU_EXECUTION_ORDER_MAIN_OFFSET].values.ptr,
    );
    try std.testing.expectEqual(
        fixture.apu_auxiliary.apu_mcycle.ptr,
        main[geometry.APU_MCYCLE_MAIN_OFFSET].values.ptr,
    );
    try std.testing.expectEqual(
        fixture.apu_auxiliary.apu_order.ptr,
        main[geometry.APU_ORDER_MAIN_OFFSET].values.ptr,
    );
    try expectLogs(preprocessed, &prepared.logs.preprocessed());
    try expectLogs(main, &prepared.logs.main());
    try expectSelectors(preprocessed);

    inline for (.{ 0xff40, 0xff41, 0xff44, 0xff45 }) |address| {
        const storage = try boundaryStorage(address);
        inline for (.{
            base.MEMORY_ENABLED_PREPROCESSED,
            base.MEMORY_ADDRESS_PREPROCESSED,
            base.MEMORY_INITIAL_PREPROCESSED,
            base.MEMORY_FINAL_PREPROCESSED,
        }) |boundary_column| try std.testing.expect(
            preprocessed[boundary_column].values[storage].isZero(),
        );
    }
    const dma_storage = try boundaryStorage(0xff46);
    try std.testing.expect(
        !preprocessed[base.MEMORY_ENABLED_PREPROCESSED]
            .values[dma_storage].isZero(),
    );
    try std.testing.expectEqual(
        ordinary_value,
        preprocessed[base.MEMORY_ADDRESS_PREPROCESSED]
            .values[ordinary_storage],
    );
}

test "machine environment trace transfers only columns and retains lookup metadata" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var prepared = try subject.assemble(
        std.testing.allocator,
        fixture.sources(),
    );
    defer prepared.deinit(std.testing.allocator);

    try std.testing.expect(fixture.v3_preprocessed.columns == null);
    try std.testing.expect(fixture.rom_multiplicity.values == null);
    try std.testing.expect(!fixture.machine.scheduler_main_owned);
    try std.testing.expect(!fixture.machine.provenance_main_owned);
    try std.testing.expect(!fixture.machine.scheduler_memory.main_owned);
    try std.testing.expect(!fixture.packed_access.owned);
    try std.testing.expect(!fixture.replay.memory.columns_owned);
    try std.testing.expect(!fixture.service_memory.main_owned);
    try std.testing.expect(!fixture.ppu_auxiliary.values_owned);
    try std.testing.expect(!fixture.ppu_policy.owned);
    try std.testing.expect(!fixture.apu_binding.owned);
    try std.testing.expect(!fixture.apu_auxiliary.owned);
    try std.testing.expectEqual(SIZE, fixture.machine.scheduler_memory.samples.len);
    try std.testing.expectEqual(SIZE, fixture.service_memory.samples.len);
    try std.testing.expectEqual(@as(usize, 1), fixture.replay.scheduler_predecessors.len);
    try std.testing.expectEqual(@as(usize, 0), fixture.replay.memory.accesses.len);
}

test "machine environment trace fails closed on detached column geometry" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const original = fixture.service_memory.main[0];
    fixture.service_memory.main[0] = original[0 .. original.len - 1];
    try std.testing.expectError(
        error.DetachedColumnLength,
        subject.assemble(std.testing.allocator, fixture.sources()),
    );
    try std.testing.expect(fixture.v3_preprocessed.columns != null);
    try std.testing.expect(fixture.rom_multiplicity.values != null);
    try std.testing.expect(fixture.machine.scheduler_main_owned);
    try std.testing.expect(fixture.service_memory.main_owned);
    fixture.service_memory.main[0] = original;

    fixture.ppu_auxiliary.log_size += 1;
    try std.testing.expectError(
        error.DetachedWitnessLog,
        subject.assemble(std.testing.allocator, fixture.sources()),
    );
    fixture.ppu_auxiliary.log_size -= 1;

    const prefix = fixture.v3_preprocessed.columns.?;
    prefix[0].log_size += 1;
    try std.testing.expectError(
        error.DetachedColumnLog,
        subject.assemble(std.testing.allocator, fixture.sources()),
    );
    prefix[0].log_size -= 1;
}

test "machine environment preprocessed extension consumes only on success" {
    const allocator = std.testing.allocator;
    var prefix = transaction.OwnedColumns.init(
        try v3Preprocessed(allocator),
    );
    defer prefix.deinit(allocator);
    const columns_value = prefix.columns.?;
    columns_value[0].log_size += 1;
    try std.testing.expectError(
        error.DetachedColumnLength,
        subject.extendPreprocessed(
            allocator,
            &prefix,
            LOG_SIZE,
            LOG_SIZE,
            LOG_SIZE,
        ),
    );
    try std.testing.expect(prefix.columns != null);
    columns_value[0].log_size -= 1;
    const first_pointer = columns_value[0].values.ptr;
    var extended = try subject.extendPreprocessed(
        allocator,
        &prefix,
        LOG_SIZE,
        LOG_SIZE,
        LOG_SIZE,
    );
    defer extended.deinit(allocator);
    try std.testing.expect(prefix.columns == null);
    try std.testing.expectEqual(
        first_pointer,
        extended.columns.?[0].values.ptr,
    );
    try expectSelectors(extended.columns.?);
}

const Fixture = struct {
    v3_preprocessed: transaction.OwnedColumns,
    machine: machine_trace.Trace,
    packed_access: cartridge_prover.PackedTrace,
    replay: replay_mod.Replay,
    rom_multiplicity: subject.OwnedColumn,
    joypad_binding: joypad_binding.Witness,
    joypad_if: joypad_if.Witness,
    timer_binding: timer_binding.Witness,
    timer_if: timer_if.Witness,
    observation: observation.Witness,
    service_memory: service_memory.Witness,
    ppu_binding: ppu_binding.Witness,
    ppu_auxiliary: ppu_mmio.AuxiliaryWitness,
    ppu_if: ppu_if.Witness,
    ppu_policy: ppu_execution_policy.Witness,
    dma_binding: dma_binding.Witness,
    dma_memory: dma_memory.Witness,
    apu_binding: apu_binding.Witness,
    apu_auxiliary: apu_execution.AuxiliaryWitness,

    fn init() !Fixture {
        const allocator = std.testing.allocator;
        const v3 = try v3Preprocessed(allocator);
        const execution_witness = execution_trace.Trace{
            .log_size = LOG_SIZE,
            .is_first = try valuesColumn(allocator, LOG_SIZE, 1),
            .is_last = try valuesColumn(allocator, LOG_SIZE, 2),
            .main = try columns(
                execution.N_MAIN_COLUMNS,
                allocator,
                LOG_SIZE,
                3,
            ),
            .initial = undefined,
            .final = undefined,
            .allocator = allocator,
        };
        const families = family_trace.Trace{
            .log_size = LOG_SIZE,
            .main = try columns(
                family_trace.N_MAIN_COLUMNS,
                allocator,
                LOG_SIZE,
                4,
            ),
            .allocator = allocator,
        };
        const scheduler_witness = scheduler_memory.Witness{
            .log_size = LOG_SIZE,
            .main = try columns(
                scheduler_memory.N_MAIN_COLUMNS,
                allocator,
                LOG_SIZE,
                5,
            ),
            .samples = try allocator.alloc(
                scheduler_memory.RowSamples,
                SIZE,
            ),
            .allocator = allocator,
        };
        @memset(
            scheduler_witness.samples,
            [_]scheduler_memory.Sample{.{}} **
                scheduler_memory.N_SAMPLES,
        );
        return .{
            .v3_preprocessed = transaction.OwnedColumns.init(v3),
            .machine = .{
                .log_size = LOG_SIZE,
                .execution = execution_witness,
                .scheduler_main = try columns(
                    scheduler_component.N_MAIN_COLUMNS,
                    allocator,
                    LOG_SIZE,
                    6,
                ),
                .provenance_main = try columns(
                    scheduler_binding.N_PROVENANCE_COLUMNS,
                    allocator,
                    LOG_SIZE,
                    7,
                ),
                .scheduler_memory = scheduler_witness,
                .families = families,
                .scheduler_initial = undefined,
                .scheduler_final = undefined,
                .allocator = allocator,
            },
            .packed_access = .{
                .columns = try columns(
                    @import("air/cartridge_access_component.zig").N_MAIN_COLUMNS,
                    allocator,
                    LOG_SIZE,
                    8,
                ),
                .allocator = allocator,
            },
            .replay = try replay(allocator),
            .rom_multiplicity = subject.OwnedColumn.init(
                rom_lookup.ROM_LOG_SIZE,
                try valuesColumn(allocator, rom_lookup.ROM_LOG_SIZE, 9),
            ),
            .joypad_binding = witness(
                joypad_binding.Witness,
                joypad_binding.N_MAIN_COLUMNS,
                allocator,
                10,
            ),
            .joypad_if = accessWitness(
                joypad_if.Witness,
                joypad_if.N_MAIN_COLUMNS,
                joypad_if.Access,
                allocator,
                11,
            ),
            .timer_binding = witness(
                timer_binding.Witness,
                timer_binding.N_MAIN_COLUMNS,
                allocator,
                12,
            ),
            .timer_if = accessWitness(
                timer_if.Witness,
                timer_if.N_MAIN_COLUMNS,
                timer_if.Access,
                allocator,
                13,
            ),
            .observation = accessWitness(
                observation.Witness,
                observation.N_MAIN_COLUMNS,
                observation.Access,
                allocator,
                14,
            ),
            .service_memory = .{
                .log_size = LOG_SIZE,
                .main = try columns(
                    service_memory.N_MAIN_COLUMNS,
                    allocator,
                    LOG_SIZE,
                    15,
                ),
                .samples = try allocator.alloc(
                    service_memory.RowSamples,
                    SIZE,
                ),
                .service_count = 1,
                .allocator = allocator,
            },
            .ppu_binding = witness(
                ppu_binding.Witness,
                ppu_binding.N_MAIN_COLUMNS,
                allocator,
                16,
            ),
            .ppu_auxiliary = .{
                .log_size = LOG_SIZE,
                .event_count = 1,
                .ly_write_values = try valuesColumn(
                    allocator,
                    LOG_SIZE,
                    17,
                ),
                .allocator = allocator,
            },
            .ppu_if = accessWitness(
                ppu_if.Witness,
                ppu_if.N_MAIN_COLUMNS,
                ppu_if.Access,
                allocator,
                18,
            ),
            .ppu_policy = witness(
                ppu_execution_policy.Witness,
                ppu_execution_policy.N_MAIN_COLUMNS,
                allocator,
                19,
            ),
            .dma_binding = witness(
                dma_binding.Witness,
                dma_binding.N_MAIN_COLUMNS,
                allocator,
                21,
            ),
            .dma_memory = accessWitness(
                dma_memory.Witness,
                dma_memory.N_MAIN_COLUMNS,
                dma_memory.AccessPair,
                allocator,
                22,
            ),
            .apu_binding = witness(
                apu_binding.Witness,
                apu_binding.layout.N_MAIN_COLUMNS,
                allocator,
                23,
            ),
            .apu_auxiliary = .{
                .execution_log_size = LOG_SIZE,
                .apu_log_size = LOG_SIZE,
                .event_count = 1,
                .execution_order_before = try valuesColumn(
                    allocator,
                    LOG_SIZE,
                    24,
                ),
                .apu_mcycle = try valuesColumn(allocator, LOG_SIZE, 25),
                .apu_order = try valuesColumn(allocator, LOG_SIZE, 26),
                .allocator = allocator,
            },
        };
    }

    fn sources(self: *Fixture) subject.Sources {
        return .{
            .v3_preprocessed = &self.v3_preprocessed,
            .machine = &self.machine,
            .packed_access = &self.packed_access,
            .memory_replay = &self.replay,
            .rom_multiplicity = &self.rom_multiplicity,
            .joypad_binding = &self.joypad_binding,
            .joypad_if = &self.joypad_if,
            .timer_binding = &self.timer_binding,
            .timer_if = &self.timer_if,
            .observation = &self.observation,
            .service_memory = &self.service_memory,
            .ppu_binding = &self.ppu_binding,
            .ppu_auxiliary = &self.ppu_auxiliary,
            .ppu_if = &self.ppu_if,
            .ppu_policy = &self.ppu_policy,
            .dma_binding = &self.dma_binding,
            .dma_memory = &self.dma_memory,
            .apu_binding = &self.apu_binding,
            .apu_auxiliary = &self.apu_auxiliary,
        };
    }

    fn deinit(self: *Fixture) void {
        const allocator = std.testing.allocator;
        self.dma_memory.deinit();
        self.dma_binding.deinit();
        self.apu_auxiliary.deinit();
        self.apu_binding.deinit();
        self.ppu_policy.deinit();
        self.ppu_if.deinit();
        self.ppu_auxiliary.deinit();
        self.ppu_binding.deinit();
        self.service_memory.deinit();
        self.observation.deinit();
        self.timer_if.deinit();
        self.timer_binding.deinit();
        self.joypad_if.deinit();
        self.joypad_binding.deinit();
        self.rom_multiplicity.deinit(allocator);
        self.replay.deinit();
        self.packed_access.deinit();
        self.machine.deinit();
        self.v3_preprocessed.deinit(allocator);
        self.* = undefined;
    }
};

fn replay(allocator: std.mem.Allocator) !replay_mod.Replay {
    return .{
        .memory = .{
            .main = try columns(
                memory_lookup.N_MAIN_COLUMNS,
                allocator,
                LOG_SIZE,
                21,
            ),
            .final_clocks = try valuesColumn(
                allocator,
                memory_lookup.BOUNDARY_LOG_SIZE,
                22,
            ),
            .accesses = try allocator.alloc(memory_lookup.Access, 0),
            .allocator = allocator,
        },
        .scheduler_predecessors = try allocator.alloc(
            scheduler_memory.Predecessors,
            1,
        ),
        .service_predecessors = try allocator.alloc(
            replay_mod.ServicePredecessors,
            0,
        ),
        .joypad_predecessors = try allocator.alloc(joypad_if.Predecessor, 0),
        .timer_predecessors = try allocator.alloc(timer_if.Predecessor, 0),
        .ppu_predecessors = try allocator.alloc(ppu_if.Predecessor, 0),
        .dma_predecessors = try allocator.alloc(dma_memory.Predecessors, 0),
        .observation_predecessors = try allocator.alloc(
            observation.Predecessor,
            0,
        ),
        .initial_mcycle = 0,
        .final_mcycle = SIZE,
        .allocator = allocator,
    };
}

fn v3Preprocessed(
    allocator: std.mem.Allocator,
) ![]prover_pcs.ColumnEvaluation {
    const logs = environment.preprocessedLogSizes(
        LOG_SIZE,
        LOG_SIZE,
        LOG_SIZE,
        LOG_SIZE,
    );
    const result = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        environment.N_PREPROCESSED_COLUMNS,
    );
    for (result, logs, 0..) |*evaluation, log_size, index|
        evaluation.* = .{
            .log_size = log_size,
            .values = try valuesColumn(
                allocator,
                log_size,
                @intCast(index + 1),
            ),
        };
    return result;
}

fn witness(
    comptime T: type,
    comptime N: usize,
    allocator: std.mem.Allocator,
    seed: u32,
) T {
    return .{
        .log_size = LOG_SIZE,
        .event_count = 1,
        .main = columns(N, allocator, LOG_SIZE, seed) catch unreachable,
        .allocator = allocator,
    };
}

fn accessWitness(
    comptime T: type,
    comptime N: usize,
    comptime Access: type,
    allocator: std.mem.Allocator,
    seed: u32,
) T {
    return .{
        .log_size = LOG_SIZE,
        .main = columns(N, allocator, LOG_SIZE, seed) catch unreachable,
        .accesses = allocator.alloc(Access, 0) catch unreachable,
        .allocator = allocator,
    };
}

fn columns(
    comptime N: usize,
    allocator: std.mem.Allocator,
    log_size: u32,
    seed: u32,
) ![N][]M31 {
    var result: [N][]M31 = undefined;
    for (&result, 0..) |*values, index|
        values.* = try valuesColumn(
            allocator,
            log_size,
            seed + @as(u32, @intCast(index)),
        );
    return result;
}

fn valuesColumn(
    allocator: std.mem.Allocator,
    log_size: u32,
    seed: u32,
) ![]M31 {
    const values = try allocator.alloc(
        M31,
        @as(usize, 1) << @intCast(log_size),
    );
    @memset(values, M31.fromCanonical(seed));
    return values;
}

fn expectLogs(
    columns_value: []const prover_pcs.ColumnEvaluation,
    expected: []const u32,
) !void {
    try std.testing.expectEqual(expected.len, columns_value.len);
    for (columns_value, expected) |column_value, log_size|
        try std.testing.expectEqual(log_size, column_value.log_size);
}

fn expectPointersAt(
    destination: []const prover_pcs.ColumnEvaluation,
    offset: usize,
    sources: anytype,
) !void {
    try std.testing.expect(offset + sources.len <= destination.len);
    for (
        destination[offset .. offset + sources.len],
        sources,
    ) |column, values| try std.testing.expectEqual(
        values.ptr,
        column.values.ptr,
    );
}

fn expectSelectors(
    preprocessed: []const prover_pcs.ColumnEvaluation,
) !void {
    inline for (.{
        .{ geometry.PPU_FIRST_PREPROCESSED, true },
        .{ geometry.PPU_LAST_PREPROCESSED, false },
        .{ geometry.DMA_FIRST_PREPROCESSED, true },
        .{ geometry.DMA_LAST_PREPROCESSED, false },
        .{ geometry.APU_FIRST_PREPROCESSED, true },
        .{ geometry.APU_LAST_PREPROCESSED, false },
    }) |item| {
        const values = preprocessed[item[0]].values;
        const row = if (item[1]) 0 else values.len - 1;
        const storage = try core_air_utils.circleBitReversedIndex(
            LOG_SIZE,
            row,
        );
        for (values, 0..) |value, index|
            try std.testing.expectEqual(index == storage, value.eql(M31.one()));
    }
}

fn boundaryStorage(row: usize) !usize {
    return core_air_utils.circleBitReversedIndex(
        memory_lookup.BOUNDARY_LOG_SIZE,
        row,
    );
}

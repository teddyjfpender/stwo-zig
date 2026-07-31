//! Prover-domain controls for the packed cartridge-access component.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const cartridge = @import("../cartridge/mod.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");
const cartridge_access = @import("cartridge_access.zig");
const cartridge_access_component = @import("cartridge_access_component.zig");
const cartridge_rom_lookup = @import("cartridge_rom_lookup.zig");
const cartridge_rom_lookup_component =
    @import("cartridge_rom_lookup_component.zig");
const execution = @import("execution.zig");

test "cartridge access domain rejects bus address and mapper endpoint mutations" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 4;
    const evaluation_log_size: u32 = log_size + 1;
    const evaluation_size: usize = 1 << evaluation_log_size;
    const bank_one = cartridge.mbc3.State{ .rom_bank_register = 1 };
    const component = cartridge_access_component.Component{
        .log_size = log_size,
        .is_first_column = 0,
        .is_last_column = 1,
        .execution_offset = 0,
        .main_offset = execution.N_MAIN_COLUMNS,
        .initial = bank_one,
        .final = bank_one,
    };
    const rom_relation = cartridge_rom_lookup.Relation.dummy();
    const shared_rom = cartridge_rom_lookup_component.Component{
        .kind = .execution,
        .log_size = log_size,
        .is_first_column = 0,
        .main_offset = execution.N_MAIN_COLUMNS,
        .interaction_offset = 0,
        .owns_execution_source = false,
        .relation = &rom_relation,
        .claims = .{QM31.zero()} **
            cartridge_rom_lookup.N_EXECUTION_SUMS,
    };
    var shared_bounds = try shared_rom.traceLogDegreeBounds(allocator);
    defer shared_bounds.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 0), shared_bounds.items[1].len);
    var shared_mask = try shared_rom.maskPoints(
        allocator,
        @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN,
        shared_rom.maxConstraintLogDegreeBound(),
    );
    defer shared_mask.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 0), shared_mask.items[1].len);
    try std.testing.expectEqual(
        evaluation_log_size,
        component.maxConstraintLogDegreeBound(),
    );

    var first_values = [_]M31{M31.zero()} ** evaluation_size;
    var last_values = [_]M31{M31.zero()} ** evaluation_size;
    first_values[
        try core_air_utils.circleBitReversedIndex(evaluation_log_size, 0)
    ] = M31.one();
    last_values[
        try core_air_utils.circleBitReversedIndex(
            evaluation_log_size,
            evaluation_size - 1,
        )
    ] = M31.one();
    var preprocessed = [_]prover_component.Poly{
        .{ .log_size = evaluation_log_size, .values = &first_values },
        .{ .log_size = evaluation_log_size, .values = &last_values },
    };

    const honest_trace = try syntheticRead(bank_one);
    const machine_witness = execution.columns(
        honest_trace.instruction,
        0,
    );
    const access_witness =
        try cartridge_access_component.columns(honest_trace);
    var execution_values: [execution.N_MAIN_COLUMNS][evaluation_size]M31 = undefined;
    var execution_polynomials: [execution.N_MAIN_COLUMNS]prover_component.Poly = undefined;
    for (
        &execution_values,
        &execution_polynomials,
        machine_witness,
    ) |*values, *polynomial, value| {
        @memset(values, value);
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    }
    var access_values: [cartridge_access_component.N_MAIN_COLUMNS][evaluation_size]M31 =
        undefined;
    var access_polynomials: [cartridge_access_component.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    for (
        &access_values,
        &access_polynomials,
        access_witness,
    ) |*values, *polynomial, value| {
        @memset(values, value);
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    }
    var main: [
        execution.N_MAIN_COLUMNS +
            cartridge_access_component.N_MAIN_COLUMNS
    ]prover_component.Poly =
        undefined;
    @memcpy(main[0..execution.N_MAIN_COLUMNS], &execution_polynomials);
    @memcpy(main[execution.N_MAIN_COLUMNS..], &access_polynomials);
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
    };
    const trace = prover_component.Trace{
        .polys = @import("stwo_core").pcs.TreeVec(
            []const prover_component.Poly,
        ).initOwned(&trees),
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    try expectDomain(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        true,
    );

    const bus = 2 * execution.N_STATE_COLUMNS;
    @memset(&execution_values[bus + 3], M31.zero());
    @memset(&execution_values[bus + 4], M31.one());
    try expectDomain(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    @memset(&execution_values[bus + 3], M31.one());
    @memset(&execution_values[bus + 4], M31.zero());

    @memset(&execution_values[bus], M31.fromCanonical(0x4001));
    try expectDomain(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    @memset(&execution_values[bus], M31.fromCanonical(0x4000));

    const bank_two_trace = try syntheticRead(
        .{ .rom_bank_register = 2 },
    );
    const bank_two =
        try cartridge_access_component.columns(bank_two_trace);
    for (&access_values, bank_two) |*values, value|
        @memset(values, value);
    try expectDomain(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
}

test "cartridge access domain isolates every device permission" {
    const devices = [_]struct {
        address: u16,
        region: runner.cartridge_memory.Region,
    }{
        .{
            .address = runner.joypad.P1_ADDRESS,
            .region = .joypad_mmio,
        },
        .{ .address = 0xff04, .region = .timer_mmio },
        .{ .address = 0xff40, .region = .ppu_mmio },
    };
    for (devices, 0..) |device, device_index| {
        const step = try syntheticDeviceRead(
            device.address,
            device.region,
        );
        for (0..devices.len) |permission_index| {
            var permissions = DevicePermissions{};
            switch (permission_index) {
                0 => permissions.joypad = true,
                1 => permissions.timer = true,
                2 => permissions.ppu = true,
                else => unreachable,
            }
            try expectAccessDomain(
                step,
                permissions,
                false,
                device_index == permission_index,
            );
        }
        try expectAccessDomain(step, .{}, false, false);
        try expectAccessDomain(
            step,
            .{ .joypad = true, .timer = true, .ppu = true },
            true,
            false,
        );
    }
}

test "cartridge access domain rejects ordinary FF0F rows" {
    try expectAccessDomain(
        try syntheticDeviceRead(
            runner.cartridge_memory.INTERRUPT_FLAGS,
            .system,
        ),
        .{},
        false,
        false,
    );
}

const DevicePermissions = struct {
    joypad: bool = false,
    timer: bool = false,
    ppu: bool = false,
};

fn expectAccessDomain(
    step: runner.CartridgeStepTrace,
    permissions: DevicePermissions,
    relabel_system: bool,
    expected_zero: bool,
) !void {
    const allocator = std.testing.allocator;
    const log_size: u32 = 4;
    const evaluation_log_size: u32 = log_size + 1;
    const evaluation_size: usize = 1 << evaluation_log_size;
    const component = cartridge_access_component.Component{
        .log_size = log_size,
        .is_first_column = 0,
        .is_last_column = 1,
        .execution_offset = 0,
        .main_offset = execution.N_MAIN_COLUMNS,
        .initial = .{},
        .final = .{},
        .allow_joypad_mmio = permissions.joypad,
        .allow_timer_mmio = permissions.timer,
        .allow_ppu_mmio = permissions.ppu,
    };

    var first_values = [_]M31{M31.zero()} ** evaluation_size;
    var last_values = [_]M31{M31.zero()} ** evaluation_size;
    first_values[
        try core_air_utils.circleBitReversedIndex(evaluation_log_size, 0)
    ] = M31.one();
    last_values[
        try core_air_utils.circleBitReversedIndex(
            evaluation_log_size,
            evaluation_size - 1,
        )
    ] = M31.one();
    var preprocessed = [_]prover_component.Poly{
        .{ .log_size = evaluation_log_size, .values = &first_values },
        .{ .log_size = evaluation_log_size, .values = &last_values },
    };

    const machine_witness = execution.columns(step.instruction, 0);
    var access_witness = try cartridge_access_component.columns(step);
    if (relabel_system) {
        const original = step.accesses[0].?.region;
        access_witness[
            cartridge_access.REGION_OFFSET + @intFromEnum(original)
        ] = M31.zero();
        access_witness[
            cartridge_access.REGION_OFFSET +
                @intFromEnum(runner.cartridge_memory.Region.system)
        ] = M31.one();
    }
    var execution_values: [execution.N_MAIN_COLUMNS][evaluation_size]M31 =
        undefined;
    var execution_polynomials: [execution.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    for (
        &execution_values,
        &execution_polynomials,
        machine_witness,
    ) |*values, *polynomial, value| {
        @memset(values, value);
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    }
    var access_values: [cartridge_access_component.N_MAIN_COLUMNS][evaluation_size]M31 =
        undefined;
    var access_polynomials: [cartridge_access_component.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    for (
        &access_values,
        &access_polynomials,
        access_witness,
    ) |*values, *polynomial, value| {
        @memset(values, value);
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    }
    var main: [
        execution.N_MAIN_COLUMNS +
            cartridge_access_component.N_MAIN_COLUMNS
    ]prover_component.Poly = undefined;
    @memcpy(main[0..execution.N_MAIN_COLUMNS], &execution_polynomials);
    @memcpy(main[execution.N_MAIN_COLUMNS..], &access_polynomials);
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
    };
    const trace = prover_component.Trace{
        .polys = @import("stwo_core").pcs.TreeVec(
            []const prover_component.Poly,
        ).initOwned(&trees),
    };
    try expectDomain(
        allocator,
        &component,
        &trace,
        QM31.fromU32Unchecked(3, 5, 7, 11),
        evaluation_log_size,
        expected_zero,
    );
}

fn expectDomain(
    allocator: std.mem.Allocator,
    component: *const cartridge_access_component.Component,
    trace: *const prover_component.Trace,
    challenge: QM31,
    evaluation_log_size: u32,
    expected_zero: bool,
) !void {
    var domain = try accumulation.DomainEvaluationAccumulator.init(
        allocator,
        challenge,
        evaluation_log_size,
        component.nConstraints(),
    );
    defer domain.deinit();
    try component.evaluateConstraintQuotientsOnDomain(trace, &domain);
    var result = try domain.finalize();
    defer result.deinit(allocator);
    var all_zero = true;
    for (0..result.len()) |row|
        all_zero = all_zero and result.at(row).isZero();
    try std.testing.expectEqual(expected_zero, all_zero);
}

fn syntheticRead(
    mapper: cartridge.mbc3.State,
) !runner.CartridgeStepTrace {
    const offset: runner.cartridge_memory.PhysicalOffset =
        @as(runner.cartridge_memory.PhysicalOffset, mapper.selectedRomBank()) *
        @as(
            runner.cartridge_memory.PhysicalOffset,
            cartridge.header.ROM_BANK_SIZE,
        );
    var trace: runner.CartridgeStepTrace = undefined;
    trace.instruction.before = .{};
    trace.instruction.after = .{ .pc = 1 };
    trace.instruction.decoded = try isa.decode(&.{0x42});
    trace.instruction.cycle_count = 1;
    trace.instruction.branch_taken = false;
    trace.instruction.result = null;
    trace.instruction.cycles[0] = .{
        .address = 0x4000,
        .value = 0x42,
        .action = .read,
    };
    trace.accesses = [_]?runner.cartridge_memory.Access{null} ** 6;
    trace.accesses[0] = .{
        .logical_address = 0x4000,
        .action = .read,
        .region = .cartridge_rom,
        .physical_offset = offset,
        .mapper_before = mapper,
        .mapper_after = mapper,
        .value = 0x42,
    };
    return trace;
}

fn syntheticDeviceRead(
    address: u16,
    region: runner.cartridge_memory.Region,
) !runner.CartridgeStepTrace {
    var trace = try syntheticRead(.{});
    trace.instruction.cycles[0].address = address;
    trace.accesses[0].?.logical_address = address;
    trace.accesses[0].?.region = region;
    trace.accesses[0].?.physical_offset = null;
    return trace;
}

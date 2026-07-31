const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const runner = @import("../runner/mod.zig");
const ppu_binding = @import("ppu_binding.zig");
const subject = @import("ppu_mmio_lookup.zig");

const memory = runner.cartridge_memory;
const mapper = @import("../cartridge/mbc3.zig");

test "PPU MMIO interaction fails closed on empty execution" {
    var auxiliary = try subject.generateAuxiliaryWitness(
        std.testing.allocator,
        4,
        &.{},
    );
    defer auxiliary.deinit();
    try std.testing.expectError(
        error.InvalidExecutionTraceLength,
        subject.generateInteraction(
            std.testing.allocator,
            &.{},
            0,
            &.{},
            &auxiliary,
            subject.Relations.dummy(),
        ),
    );
}

test "PPU ticks writes and reads cancel only at exact clocks addresses and values" {
    const scenario = scenarioInputs();
    var trace = try ppu_binding.generateFromExecution(
        std.testing.allocator,
        100,
        116,
        .{},
        &scenario.steps,
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 67), trace.rows.len);

    var auxiliary = try subject.generateAuxiliaryWitness(
        std.testing.allocator,
        7,
        trace.rows,
    );
    defer auxiliary.deinit();
    const relations = subject.Relations.dummy();
    var interaction = try subject.generateInteraction(
        std.testing.allocator,
        &scenario.steps,
        100,
        trace.rows,
        &auxiliary,
        relations,
    );
    defer interaction.deinit();
    try subject.verifyCancellation(interaction.claims);
    try std.testing.expectEqual(
        @as(usize, 72),
        interaction.execution_columns.len,
    );
    try std.testing.expectEqual(
        @as(usize, 12),
        interaction.ppu_columns.len,
    );

    const provenance = trace.rows[0].provenance;
    trace.rows[0].provenance = .detached;
    try std.testing.expectError(
        error.InvalidPpuWriteProvenance,
        subject.generateInteraction(
            std.testing.allocator,
            &scenario.steps,
            100,
            trace.rows,
            &auxiliary,
            relations,
        ),
    );
    trace.rows[0].provenance = provenance;

    var wrong_steps = scenario.steps;
    wrong_steps[5].instruction.cycles[0].value ^= 1;
    wrong_steps[5].accesses[0].?.value ^= 1;
    try std.testing.expectError(
        error.InvalidPpuReadProvenance,
        subject.generateInteraction(
            std.testing.allocator,
            &wrong_steps,
            100,
            trace.rows,
            &auxiliary,
            relations,
        ),
    );

    wrong_steps = scenario.steps;
    wrong_steps[5].instruction.cycles[0].address = 0xff44;
    wrong_steps[5].accesses[0].?.logical_address = 0xff44;
    try std.testing.expectError(
        error.InvalidPpuReadProvenance,
        subject.generateInteraction(
            std.testing.allocator,
            &wrong_steps,
            100,
            trace.rows,
            &auxiliary,
            relations,
        ),
    );

    var wrong_rows = try std.testing.allocator.dupe(
        ppu_binding.EventRow,
        trace.rows,
    );
    defer std.testing.allocator.free(wrong_rows);
    wrong_rows[0].mcycle += 1;
    try std.testing.expectError(
        error.DisconnectedPpuTrace,
        subject.generateInteraction(
            std.testing.allocator,
            &scenario.steps,
            100,
            wrong_rows,
            &auxiliary,
            relations,
        ),
    );
}

test "PPU lookup rejects omitted duplicated and forged LY-write witnesses" {
    const scenario = scenarioInputs();
    var trace = try ppu_binding.generateFromExecution(
        std.testing.allocator,
        100,
        116,
        .{},
        &scenario.steps,
    );
    defer trace.deinit(std.testing.allocator);
    const relations = subject.Relations.dummy();

    var omitted_auxiliary = try subject.generateAuxiliaryWitness(
        std.testing.allocator,
        7,
        trace.rows[0 .. trace.rows.len - 1],
    );
    defer omitted_auxiliary.deinit();
    try std.testing.expectError(
        error.InvalidPpuTraceEndpoint,
        subject.generateInteraction(
            std.testing.allocator,
            &scenario.steps,
            100,
            trace.rows[0 .. trace.rows.len - 1],
            &omitted_auxiliary,
            relations,
        ),
    );

    var duplicated_rows = try std.testing.allocator.alloc(
        ppu_binding.EventRow,
        trace.rows.len + 1,
    );
    defer std.testing.allocator.free(duplicated_rows);
    @memcpy(duplicated_rows[0..trace.rows.len], trace.rows);
    duplicated_rows[trace.rows.len] = trace.rows[trace.rows.len - 1];
    var duplicated_auxiliary = try subject.generateAuxiliaryWitness(
        std.testing.allocator,
        7,
        duplicated_rows,
    );
    defer duplicated_auxiliary.deinit();
    try std.testing.expectError(
        error.DisconnectedPpuTrace,
        subject.generateInteraction(
            std.testing.allocator,
            &scenario.steps,
            100,
            duplicated_rows,
            &duplicated_auxiliary,
            relations,
        ),
    );

    var auxiliary = try subject.generateAuxiliaryWitness(
        std.testing.allocator,
        7,
        trace.rows,
    );
    defer auxiliary.deinit();
    const ly_row = for (trace.rows, 0..) |row, index| {
        if (row.ignored_ly_write != null) break index;
    } else unreachable;
    const storage = try core_air_utils.circleBitReversedIndex(7, ly_row);
    try std.testing.expectEqual(
        M31.fromCanonical(0xa5),
        auxiliary.ly_write_values[storage],
    );
    auxiliary.ly_write_values[storage] = M31.fromCanonical(0xa4);
    var forged = try subject.generateInteraction(
        std.testing.allocator,
        &scenario.steps,
        100,
        trace.rows,
        &auxiliary,
        relations,
    );
    defer forged.deinit();
    try std.testing.expectError(
        error.PpuMmioLookupSumNonZero,
        subject.verifyCancellation(forged.claims),
    );
}

test "PPU latch writes select exact MMIO addresses and bytes" {
    const scenario = scenarioInputs();
    var trace = try ppu_binding.generateFromExecution(
        std.testing.allocator,
        100,
        116,
        .{},
        &scenario.steps,
    );
    defer trace.deinit(std.testing.allocator);
    const relations = subject.Relations.dummy();
    const cases = [_]struct {
        register: ppu_binding.Register,
        address: u16,
        value: u8,
    }{
        .{ .register = .scy, .address = 0xff42, .value = 0x12 },
        .{ .register = .scx, .address = 0xff43, .value = 0x34 },
        .{ .register = .wy, .address = 0xff4a, .value = 0x56 },
    };
    for (cases) |case| {
        const row = for (trace.rows) |row| {
            if (row.latch_write) |write|
                if (write.register == case.register) break row;
        } else unreachable;
        const lifted = try liftPpu(
            try ppu_binding.columns(row),
            M31.zero(),
        );
        const entry = subject.ppuPairs(lifted, relations)[
            @intFromEnum(subject.RelationIndex.write)
        ];
        try std.testing.expectEqual(QM31.one(), entry.numerator);
        try std.testing.expectEqual(
            relations.at(.write).combine(
                QM31.fromBase(M31.fromCanonical(row.mcycle)),
                QM31.fromBase(M31.fromCanonical(case.address)),
                QM31.fromBase(M31.fromCanonical(case.value)),
            ),
            entry.denominator,
        );
    }
}

test "PPU auxiliary is constrained against inactive and non-LY vacuity" {
    const inactive = try liftPpu(
        ppu_binding.inactiveColumns(),
        M31.zero(),
    );
    for (subject.ppuPairs(inactive, subject.Relations.dummy())) |entry| {
        try std.testing.expect(entry.numerator.isZero());
        try std.testing.expectEqual(QM31.one(), entry.denominator);
    }
    try std.testing.expect(allZero(
        &subject.ppuBindingConstraints(QM31, inactive),
    ));

    var inactive_garbage = inactive;
    inactive_garbage.ly_write_value = QM31.one();
    try std.testing.expect(!allZero(
        &subject.ppuBindingConstraints(QM31, inactive_garbage),
    ));

    const scenario = scenarioInputs();
    var trace = try ppu_binding.generateFromExecution(
        std.testing.allocator,
        100,
        116,
        .{},
        &scenario.steps,
    );
    defer trace.deinit(std.testing.allocator);
    const ordinary = try liftPpu(
        try ppu_binding.columns(trace.rows[0]),
        M31.one(),
    );
    try std.testing.expect(!allZero(
        &subject.ppuBindingConstraints(QM31, ordinary),
    ));
}

test "PPU claims cancel independently and reject relation substitution" {
    var claims = zeroClaims();
    const value = QM31.fromU32Unchecked(1, 2, 3, 4);
    claims.execution[0][0] = value.neg();
    claims.ppu[0] = value;
    try subject.verifyCancellation(claims);

    claims.ppu[0] = value.add(QM31.one());
    try std.testing.expectError(
        error.PpuMmioLookupSumNonZero,
        subject.verifyCancellation(claims),
    );
    claims.ppu[0] = value;
    claims.execution[1][0] = value.neg();
    claims.ppu[2] = value;
    try std.testing.expectError(
        error.PpuMmioLookupSumNonZero,
        subject.verifyCancellation(claims),
    );
}

const Scenario = struct {
    steps: [16]runner.CartridgeStepTrace,
    cycles: [16]ppu_binding.Cycle,
};

fn scenarioInputs() Scenario {
    const state = mapper.State{};
    var steps = [_]runner.CartridgeStepTrace{
        systemStep(state),
    } ** 16;
    var cycles = [_]ppu_binding.Cycle{.{}} ** 16;
    setAccess(&steps, &cycles, 0, .lcdc, .write, 0x11);
    setAccess(&steps, &cycles, 1, .lcdc, .read, 0x11);
    setAccess(&steps, &cycles, 2, .stat, .write, 0x78);
    setAccess(&steps, &cycles, 3, .stat, .read, 0xf8);
    setAccess(&steps, &cycles, 4, .lyc, .write, 0x22);
    setAccess(&steps, &cycles, 5, .lyc, .read, 0x22);
    setAccess(&steps, &cycles, 6, .ly, .write, 0xa5);
    setAccess(&steps, &cycles, 7, .ly, .read, 0);
    setAccess(&steps, &cycles, 8, .scy, .write, 0x12);
    setAccess(&steps, &cycles, 9, .scy, .read, 0x12);
    setAccess(&steps, &cycles, 10, .scx, .write, 0x34);
    setAccess(&steps, &cycles, 11, .scx, .read, 0x34);
    setAccess(&steps, &cycles, 12, .wy, .write, 0x56);
    setAccess(&steps, &cycles, 13, .wy, .read, 0x56);
    return .{ .steps = steps, .cycles = cycles };
}

fn setAccess(
    steps: *[16]runner.CartridgeStepTrace,
    cycles: *[16]ppu_binding.Cycle,
    index: usize,
    register: ppu_binding.Register,
    action: memory.Action,
    value: u8,
) void {
    const address: u16 = switch (register) {
        .lcdc => 0xff40,
        .stat => 0xff41,
        .scy => 0xff42,
        .scx => 0xff43,
        .ly => 0xff44,
        .lyc => 0xff45,
        .wy => 0xff4a,
    };
    steps[index] = accessStep(
        mapper.State{},
        address,
        action,
        .ppu_mmio,
        value,
    );
    cycles[index].access = switch (action) {
        .read => .{ .read = .{
            .register = register,
            .value = value,
        } },
        .write => .{ .write = .{
            .register = register,
            .value = value,
        } },
    };
}

fn systemStep(state: mapper.State) runner.CartridgeStepTrace {
    return accessStep(state, 0xc000, .read, .system, 0x42);
}

fn accessStep(
    state: mapper.State,
    address: u16,
    action: memory.Action,
    region: memory.Region,
    value: u8,
) runner.CartridgeStepTrace {
    var step: runner.CartridgeStepTrace = undefined;
    step.instruction.cycle_count = 1;
    step.instruction.cycles[0] = .{
        .address = address,
        .value = value,
        .action = switch (action) {
            .read => .read,
            .write => .write,
        },
    };
    step.accesses = [_]?memory.Access{null} ** 6;
    step.accesses[0] = .{
        .logical_address = address,
        .action = action,
        .region = region,
        .physical_offset = null,
        .mapper_before = state,
        .mapper_after = state,
        .value = value,
    };
    return step;
}

fn liftPpu(
    columns: [ppu_binding.N_MAIN_COLUMNS]M31,
    auxiliary: M31,
) !subject.PpuRow(QM31) {
    var lifted: [ppu_binding.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, columns) |*target, source|
        target.* = QM31.fromBase(source);
    return subject.ppuRow(
        QM31,
        &lifted,
        QM31.fromBase(auxiliary),
    );
}

fn zeroClaims() subject.Claims {
    return .{
        .execution = [_][subject.N_EXECUTION_SUMS]QM31{
            [_]QM31{QM31.zero()} ** subject.N_EXECUTION_SUMS,
        } ** subject.N_RELATIONS,
        .ppu = [_]QM31{QM31.zero()} ** subject.N_RELATIONS,
    };
}

fn allZero(values: []const QM31) bool {
    for (values) |value|
        if (!value.isZero()) return false;
    return true;
}

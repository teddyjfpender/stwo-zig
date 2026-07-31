const std = @import("std");
const sm83 = @import("mod.zig");
const corpus_scope = @import("corpus_scope.zig");

const RamCell = [2]u16;
const Cycle = struct { u16, u8, []const u8 };

const State = struct {
    pc: u16,
    sp: u16,
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    e: u8,
    f: u8,
    h: u8,
    l: u8,
    ime: u8,
    ie: ?u8 = null,
    ei: ?u8 = null,
    ram: []const RamCell,
};

const Case = struct {
    name: []const u8,
    initial: State,
    final: State,
    cycles: []const Cycle,
};

const family_count = @typeInfo(sm83.isa.Family).@"enum".fields.len;

const Counts = struct {
    files: usize = 0,
    cases: usize = 0,
    stop_authority_conflicts: usize = 0,
    redundant_ei_authority_conflicts: usize = 0,
    halt_driver_cycles: usize = 0,
    alu8_air_cases: usize = 0,
    daa_air_cases: usize = 0,
    incdec8_air_cases: usize = 0,
    incdec16_air_cases: usize = 0,
    rotate_accumulator_air_cases: usize = 0,
    load8_air_cases: usize = 0,
    alu16_air_cases: usize = 0,
    cb_rotate_shift_air_cases: usize = 0,
    cb_bit_air_cases: usize = 0,
    cb_res_set_air_cases: usize = 0,
    load16_air_cases: usize = 0,
    misc_air_cases: usize = 0,
    branch_air_cases: usize = 0,
    stack_air_cases: usize = 0,
    interrupt_air_cases: usize = 0,
    families: [family_count]usize = .{0} ** family_count,
};

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    const filter = parseFilter(arguments) catch |err| {
        std.debug.print(
            "usage: zig build test-corpus --build-file src/frontends/sm83/build.zig " ++
                "-Doptimize=ReleaseFast -- /path/to/SingleStepTests/sm83/v1 " ++
                "[--opcode 80|cb:11 | --family alu8]\n",
            .{},
        );
        return err;
    };

    var directory = std.fs.cwd().openDir(arguments[1], .{}) catch |err| {
        std.debug.print(
            "SM83 corpus gate: cannot open {s}: {s}; run the test-corpus command with " ++
                "the pinned SingleStepTests/sm83 v1 directory\n",
            .{ arguments[1], @errorName(err) },
        );
        return err;
    };
    defer directory.close();

    var memory = try sm83.Memory.init(allocator);
    defer memory.deinit();
    var digest = std.crypto.hash.sha2.Sha256.init(.{});
    var counts = Counts{};

    for (sm83.isa.base_table, 0..) |instruction, opcode| {
        if (!instruction.isLegal() or instruction.operation == .prefix) continue;
        var name_buffer: [7]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "{x:0>2}.json", .{opcode});
        try runFile(
            allocator,
            directory,
            name,
            filter.includes(instruction, @intCast(opcode)),
            &memory,
            &digest,
            &counts,
        );
    }
    for (0..256) |opcode| {
        var name_buffer: [10]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "cb {x:0>2}.json", .{opcode});
        try runFile(
            allocator,
            directory,
            name,
            filter.includes(sm83.isa.cb_table[opcode], 0xcb00 | @as(u16, @intCast(opcode))),
            &memory,
            &digest,
            &counts,
        );
    }

    var actual_digest: [32]u8 = undefined;
    digest.final(&actual_digest);
    var expected_digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_digest, sm83.isa.authority.single_step_v1_sha256);
    if (!std.mem.eql(u8, &actual_digest, &expected_digest)) {
        std.debug.print(
            "SM83 corpus gate: content hash mismatch: expected {s}, got {x}; " ++
                "checkout SingleStepTests/sm83 revision {s}\n",
            .{
                sm83.isa.authority.single_step_v1_sha256,
                actual_digest,
                sm83.isa.authority.single_step_revision,
            },
        );
        return error.CorpusHashMismatch;
    }
    const cycle_exact = counts.cases -
        counts.stop_authority_conflicts -
        counts.halt_driver_cycles;
    switch (filter) {
        .all => try validateFullCounts(counts),
        .opcode => {
            if (counts.files == 0 or counts.cases == 0)
                return fail("scope", "selected scope ran zero cases", .{});
            if (counts.cases != counts.files * 1000)
                return fail("scope", "expected 1000 cases per file, got {d}/{d}", .{
                    counts.cases,
                    counts.files,
                });
        },
        .family => |family| {
            if (counts.files == 0 or counts.cases == 0)
                return fail("scope", "selected scope ran zero cases", .{});
            if (counts.cases != counts.files * 1000)
                return fail("scope", "expected 1000 cases per file, got {d}/{d}", .{
                    counts.cases,
                    counts.files,
                });
            if (family == .interrupt and
                (counts.files != 3 or
                    counts.cases != 3_000 or
                    cycle_exact != 3_000 or
                    counts.interrupt_air_cases != 3_000))
            {
                return fail(
                    "scope",
                    "expected interrupt files/cases/cycle-exact/AIR 3/3000/3000/3000, got {d}/{d}/{d}/{d}",
                    .{
                        counts.files,
                        counts.cases,
                        cycle_exact,
                        counts.interrupt_air_cases,
                    },
                );
            }
        },
    }
    const expected_redundant_ei_conflicts: usize = switch (filter) {
        .all => 485,
        .opcode => |opcode| if (opcode == 0xfb) 485 else 0,
        .family => |family| if (family == .interrupt) 485 else 0,
    };
    if (counts.redundant_ei_authority_conflicts !=
        expected_redundant_ei_conflicts)
    {
        return fail(
            "scope",
            "expected {d} redundant-EI authority conflicts, got {d}",
            .{
                expected_redundant_ei_conflicts,
                counts.redundant_ei_authority_conflicts,
            },
        );
    }

    var label_buffer: [32]u8 = undefined;
    const label = switch (filter) {
        .all => "all",
        .opcode => |opcode| if (opcode > 0xff)
            try std.fmt.bufPrint(&label_buffer, "opcode=cb:{x:0>2}", .{@as(u8, @truncate(opcode))})
        else
            try std.fmt.bufPrint(&label_buffer, "opcode={x:0>2}", .{@as(u8, @truncate(opcode))}),
        .family => |family| try std.fmt.bufPrint(
            &label_buffer,
            "family={s}",
            .{@tagName(family)},
        ),
    };
    std.debug.print(
        "SM83 SingleStepTests: PASS (scope {s}; {d} files, {d} cases; " ++
            "{d} cycle-exact; {d} ALU8 AIR rows; {d} DAA AIR rows; " ++
            "{d} INC/DEC8 AIR rows; {d} INC/DEC16 AIR rows; " ++
            "{d} accumulator-rotate AIR rows; {d} LOAD8 AIR rows; " ++
            "{d} ALU16 AIR rows; {d} CB rotate/shift AIR rows; " ++
            "{d} CB BIT AIR rows; {d} CB RES/SET AIR rows; " ++
            "{d} LOAD16 AIR rows; {d} MISC AIR rows; {d} BRANCH AIR rows; " ++
            "{d} STACK AIR rows; {d} INTERRUPT AIR rows; " ++
            "{d} HALT state-only; {d} STOP authority conflicts; " ++
            "{d} redundant-EI authority conflicts; sha256 {x})\n",
        .{
            label,
            counts.files,
            counts.cases,
            cycle_exact,
            counts.alu8_air_cases,
            counts.daa_air_cases,
            counts.incdec8_air_cases,
            counts.incdec16_air_cases,
            counts.rotate_accumulator_air_cases,
            counts.load8_air_cases,
            counts.alu16_air_cases,
            counts.cb_rotate_shift_air_cases,
            counts.cb_bit_air_cases,
            counts.cb_res_set_air_cases,
            counts.load16_air_cases,
            counts.misc_air_cases,
            counts.branch_air_cases,
            counts.stack_air_cases,
            counts.interrupt_air_cases,
            counts.halt_driver_cycles,
            counts.stop_authority_conflicts,
            counts.redundant_ei_authority_conflicts,
            actual_digest,
        },
    );
}

fn parseFilter(arguments: []const []const u8) !corpus_scope.Filter {
    if (arguments.len == 2) return .all;
    if (arguments.len != 4) return error.InvalidArguments;
    if (std.mem.eql(u8, arguments[2], "--opcode"))
        return corpus_scope.parseOpcode(arguments[3]);
    if (std.mem.eql(u8, arguments[2], "--family"))
        return corpus_scope.parseFamily(arguments[3]);
    return error.InvalidArguments;
}

fn validateFullCounts(counts: Counts) !void {
    if (counts.files != 500 or counts.cases != 500_000)
        return fail("aggregate", "expected 500 files and 500000 cases, got {d} and {d}", .{
            counts.files,
            counts.cases,
        });
    if (counts.stop_authority_conflicts != 1000 or
        counts.halt_driver_cycles != 1000 or
        counts.redundant_ei_authority_conflicts != 485)
        return fail(
            "aggregate",
            "expected exact known corpus limitations STOP=1000 HALT=1000 redundant-EI=485, got {d}, {d}, and {d}",
            .{
                counts.stop_authority_conflicts,
                counts.halt_driver_cycles,
                counts.redundant_ei_authority_conflicts,
            },
        );
    if (counts.alu8_air_cases != 72_000)
        return fail("aggregate", "expected 72000 ALU8 AIR cases, got {d}", .{
            counts.alu8_air_cases,
        });
    if (counts.daa_air_cases != 1000)
        return fail("aggregate", "expected 1000 DAA AIR cases, got {d}", .{
            counts.daa_air_cases,
        });
    if (counts.incdec8_air_cases != 16_000)
        return fail("aggregate", "expected 16000 INC/DEC8 AIR cases, got {d}", .{
            counts.incdec8_air_cases,
        });
    if (counts.incdec16_air_cases != 8_000)
        return fail("aggregate", "expected 8000 INC/DEC16 AIR cases, got {d}", .{
            counts.incdec16_air_cases,
        });
    if (counts.rotate_accumulator_air_cases != 4_000)
        return fail("aggregate", "expected 4000 accumulator-rotate AIR cases, got {d}", .{
            counts.rotate_accumulator_air_cases,
        });
    if (counts.load8_air_cases != 85_000)
        return fail("aggregate", "expected 85000 LOAD8 AIR cases, got {d}", .{
            counts.load8_air_cases,
        });
    if (counts.alu16_air_cases != 6_000)
        return fail("aggregate", "expected 6000 ALU16 AIR cases, got {d}", .{
            counts.alu16_air_cases,
        });
    if (counts.cb_rotate_shift_air_cases != 64_000)
        return fail("aggregate", "expected 64000 CB rotate/shift AIR cases, got {d}", .{
            counts.cb_rotate_shift_air_cases,
        });
    if (counts.cb_bit_air_cases != 64_000)
        return fail("aggregate", "expected 64000 CB BIT AIR cases, got {d}", .{
            counts.cb_bit_air_cases,
        });
    if (counts.cb_res_set_air_cases != 128_000)
        return fail("aggregate", "expected 128000 CB RES/SET AIR cases, got {d}", .{
            counts.cb_res_set_air_cases,
        });
    if (counts.load16_air_cases != 6_000)
        return fail("aggregate", "expected 6000 LOAD16 AIR cases, got {d}", .{
            counts.load16_air_cases,
        });
    if (counts.misc_air_cases != 6_000)
        return fail("aggregate", "expected 6000 MISC AIR cases, got {d}", .{
            counts.misc_air_cases,
        });
    if (counts.branch_air_cases != 29_000)
        return fail("aggregate", "expected 29000 BRANCH AIR cases, got {d}", .{
            counts.branch_air_cases,
        });
    if (counts.stack_air_cases != 8_000)
        return fail("aggregate", "expected 8000 STACK AIR cases, got {d}", .{
            counts.stack_air_cases,
        });
    if (counts.interrupt_air_cases != 3_000)
        return fail("aggregate", "expected 3000 INTERRUPT AIR cases, got {d}", .{
            counts.interrupt_air_cases,
        });
    for (counts.families, 0..) |count, family| {
        if (family == @intFromEnum(sm83.isa.Family.illegal)) continue;
        if (count == 0)
            return fail("aggregate", "opcode family {s} ran zero cases", .{
                @tagName(@as(sm83.isa.Family, @enumFromInt(family))),
            });
    }
}

fn runFile(
    allocator: std.mem.Allocator,
    directory: std.fs.Dir,
    name: []const u8,
    selected: bool,
    memory: *sm83.Memory,
    digest: *std.crypto.hash.sha2.Sha256,
    counts: *Counts,
) !void {
    const bytes = directory.readFileAlloc(allocator, name, 1024 * 1024) catch |err| {
        std.debug.print(
            "SM83 corpus gate: cannot read {s}: {s}; the corpus is required, not skipped\n",
            .{ name, @errorName(err) },
        );
        return err;
    };
    defer allocator.free(bytes);
    digest.update(bytes);
    if (!selected) return;

    const parsed = try std.json.parseFromSlice([]const Case, allocator, bytes, .{});
    defer parsed.deinit();
    if (parsed.value.len != 1000)
        return fail(name, "expected 1000 cases, got {d}", .{parsed.value.len});

    for (parsed.value) |case| {
        for (case.initial.ram) |cell| memory.write(cell[0], @truncate(cell[1]));
        var state = cpuFrom(case.initial);
        const trace = sm83.step(&state, memory) catch |err|
            return fail(case.name, "runner failed: {s}", .{@errorName(err)});

        const opcode = trace.decoded.raw_opcode;
        if (opcode == 0x10) {
            _ = try compareCpuExceptPc(
                case.name,
                opcode,
                case.initial,
                state,
                case.final,
            );
            counts.stop_authority_conflicts += 1;
        } else {
            counts.redundant_ei_authority_conflicts += @intFromBool(
                try compareCpu(
                    case.name,
                    opcode,
                    case.initial,
                    state,
                    case.final,
                ),
            );
        }
        for (case.final.ram) |cell| {
            const actual = memory.read(cell[0]);
            if (actual != @as(u8, @truncate(cell[1])))
                return fail(case.name, "RAM[{x:0>4}] expected {x:0>2}, got {x:0>2}", .{
                    cell[0],
                    cell[1],
                    actual,
                });
        }
        if (opcode == 0x10) {
            // SingleStepTests models STOP as one byte plus two driver idle
            // cycles. GBDev and SameBoy consume the second byte.
        } else if (opcode == 0x76) {
            counts.halt_driver_cycles += 1;
        } else {
            try compareCycles(case.name, trace.activeCycles(), case.cycles);
        }
        if (trace.decoded.instruction.family() == .alu8) {
            const air_columns = sm83.air.alu8.columns(
                try sm83.air.alu8.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.alu8.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates ALU8 AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.alu8.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates ALU8 execution binding",
                    .{},
                );
            counts.alu8_air_cases += 1;
        }
        if (trace.decoded.instruction.operation == .decimal_adjust) {
            const air_columns = sm83.air.daa.columns(
                try sm83.air.daa.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.daa.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates DAA AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.daa.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates DAA execution binding",
                    .{},
                );
            counts.daa_air_cases += 1;
        }
        if (trace.decoded.instruction.family() == .increment_decrement8) {
            const air_columns = sm83.air.incdec8.columns(
                try sm83.air.incdec8.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.incdec8.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates INC/DEC8 AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.incdec8.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates INC/DEC8 execution binding",
                    .{},
                );
            counts.incdec8_air_cases += 1;
        }
        if (trace.decoded.instruction.family() == .increment_decrement16) {
            const air_columns = sm83.air.incdec16.columns(
                try sm83.air.incdec16.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.incdec16.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates INC/DEC16 AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.incdec16.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates INC/DEC16 execution binding",
                    .{},
                );
            counts.incdec16_air_cases += 1;
        }
        if (trace.decoded.instruction.family() == .rotate_accumulator) {
            const air_columns = sm83.air.rotate_accumulator.columns(
                try sm83.air.rotate_accumulator.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.rotate_accumulator.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates accumulator-rotate AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.rotate_accumulator.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates accumulator-rotate execution binding",
                    .{},
                );
            counts.rotate_accumulator_air_cases += 1;
        }
        if (trace.decoded.instruction.family() == .load8) {
            const air_columns = sm83.air.load8.columns(
                try sm83.air.load8.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.load8.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates LOAD8 AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.load8.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates LOAD8 execution binding",
                    .{},
                );
            counts.load8_air_cases += 1;
        }
        if (trace.decoded.instruction.family() == .alu16) {
            const air_columns = sm83.air.alu16.columns(
                try sm83.air.alu16.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.alu16.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates ALU16 AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.alu16.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates ALU16 execution binding",
                    .{},
                );
            counts.alu16_air_cases += 1;
        }
        if (trace.decoded.instruction.family() == .rotate_shift) {
            const air_columns = sm83.air.cb_rotate_shift.columns(
                try sm83.air.cb_rotate_shift.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.cb_rotate_shift.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates CB rotate/shift AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.cb_rotate_shift.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates CB rotate/shift execution binding",
                    .{},
                );
            counts.cb_rotate_shift_air_cases += 1;
        }
        if (trace.decoded.instruction.family() == .bit) {
            const air_columns = sm83.air.cb_bit.columns(
                try sm83.air.cb_bit.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.cb_bit.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates CB BIT AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.cb_bit.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates CB BIT execution binding",
                    .{},
                );
            counts.cb_bit_air_cases += 1;
        }
        if (trace.decoded.instruction.family() == .reset_set) {
            const air_columns = sm83.air.cb_res_set.columns(
                try sm83.air.cb_res_set.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.cb_res_set.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates CB RES/SET AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.cb_res_set.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates CB RES/SET execution binding",
                    .{},
                );
            counts.cb_res_set_air_cases += 1;
        }
        if (trace.decoded.instruction.family() == .load16) {
            const air_columns = sm83.air.load16.columns(
                try sm83.air.load16.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.load16.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates LOAD16 AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.load16.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates LOAD16 execution binding",
                    .{},
                );
            counts.load16_air_cases += 1;
        }
        if (trace.decoded.instruction.family() == .misc and
            trace.decoded.instruction.operation != .decimal_adjust)
        {
            const air_columns = sm83.air.misc.columns(
                try sm83.air.misc.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.misc.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates MISC AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.misc.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates MISC execution binding",
                    .{},
                );
            counts.misc_air_cases += 1;
        }
        if (trace.decoded.instruction.family() == .branch) {
            const air_columns = sm83.air.branch.columns(
                try sm83.air.branch.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.branch.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates BRANCH AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.branch.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates BRANCH execution binding",
                    .{},
                );
            counts.branch_air_cases += 1;
        }
        if (trace.decoded.instruction.family() == .stack) {
            const air_columns = sm83.air.stack.columns(
                try sm83.air.stack.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.stack.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates STACK AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.stack.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates STACK execution binding",
                    .{},
                );
            counts.stack_air_cases += 1;
        }
        if (trace.decoded.instruction.family() == .interrupt) {
            const air_columns = sm83.air.interrupt.columns(
                try sm83.air.interrupt.ValidatedStep.init(trace),
            );
            if (!(try sm83.air.interrupt.evaluate(air_columns)).allZero())
                return fail(case.name, "honest runner row violates INTERRUPT AIR", .{});
            const execution_columns = sm83.air.execution.columns(trace, 0);
            if (!(try sm83.air.interrupt.evaluateBound(
                air_columns,
                execution_columns,
            )).allZero())
                return fail(
                    case.name,
                    "honest runner row violates INTERRUPT execution binding",
                    .{},
                );
            counts.interrupt_air_cases += 1;
        }
        counts.cases += 1;
        counts.families[@intFromEnum(trace.decoded.instruction.family())] += 1;

        for (case.initial.ram) |cell| memory.write(cell[0], 0);
        for (case.final.ram) |cell| memory.write(cell[0], 0);
    }
    counts.files += 1;
}

fn cpuFrom(source: State) sm83.Cpu {
    return .{
        .pc = source.pc,
        .sp = source.sp,
        .a = source.a,
        .b = source.b,
        .c = source.c,
        .d = source.d,
        .e = source.e,
        .f = source.f & 0xf0,
        .h = source.h,
        .l = source.l,
        .ime = source.ime != 0,
        .ime_enable_pending = if (source.ei) |value| value != 0 else false,
    };
}

fn compareCpu(
    name: []const u8,
    opcode: u16,
    initial: State,
    actual: sm83.Cpu,
    expected: State,
) !bool {
    inline for (.{ "a", "b", "c", "d", "e", "f", "h", "l", "pc", "sp" }) |field| {
        if (@field(actual, field) != @field(expected, field))
            return fail(name, field ++ " expected {x}, got {x}", .{
                @field(expected, field),
                @field(actual, field),
            });
    }
    if (actual.ime != (expected.ime != 0))
        return fail(name, "IME expected {d}, got {d}", .{
            expected.ime,
            @intFromBool(actual.ime),
        });
    if (expected.ei) |pending| {
        if (actual.ime_enable_pending != (pending != 0))
            if (redundantEiAuthorityConflict(
                opcode,
                initial,
                actual,
                expected,
            )) {
                return true;
            } else return fail(name, "EI pending expected {d}, got {d}", .{
                pending,
                @intFromBool(actual.ime_enable_pending),
            });
    }
    return false;
}

fn compareCpuExceptPc(
    name: []const u8,
    opcode: u16,
    initial: State,
    actual: sm83.Cpu,
    expected: State,
) !bool {
    var normalized = actual;
    normalized.pc = expected.pc;
    return compareCpu(name, opcode, initial, normalized, expected);
}

fn redundantEiAuthorityConflict(
    opcode: u16,
    initial: State,
    actual: sm83.Cpu,
    expected: State,
) bool {
    return opcode == 0xfb and
        initial.ime == 1 and
        initial.ei == null and
        expected.ime == 1 and
        expected.ei != null and
        expected.ei.? == 1 and
        actual.ime and
        !actual.ime_enable_pending;
}

fn compareCycles(name: []const u8, actual: []const sm83.runner.BusCycle, expected: []const Cycle) !void {
    if (actual.len != expected.len)
        return fail(name, "cycle count expected {d}, got {d}", .{ expected.len, actual.len });
    for (actual, expected, 0..) |got, want, index| {
        const action: sm83.runner.BusAction =
            if (std.mem.eql(u8, want[2], "r-m"))
                .read
            else if (std.mem.eql(u8, want[2], "-wm"))
                .write
            else if (std.mem.eql(u8, want[2], "---"))
                .idle
            else
                return fail(name, "unknown cycle action {s}", .{want[2]});
        if (got.address != want[0] or got.value != want[1] or got.action != action)
            return fail(
                name,
                "cycle {d} expected ({x:0>4},{x:0>2},{s}), got ({x:0>4},{x:0>2},{s})",
                .{
                    index,
                    want[0],
                    want[1],
                    want[2],
                    got.address,
                    got.value,
                    @tagName(got.action),
                },
            );
    }
}

fn fail(name: []const u8, comptime format: []const u8, arguments: anytype) error{DifferentialMismatch} {
    std.debug.print("SM83 corpus gate [{s}]: " ++ format ++ "\n", .{name} ++ arguments);
    std.debug.print(
        "diagnostic: rerun `zig build test-corpus --build-file " ++
            "src/frontends/sm83/build.zig -Doptimize=ReleaseFast -- <corpus-v1>`\n",
        .{},
    );
    return error.DifferentialMismatch;
}

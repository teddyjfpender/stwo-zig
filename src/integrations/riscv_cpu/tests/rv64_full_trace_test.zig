const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend");
const air = rv.rv64_air;
const Q = core.fields.qm31.QM31;
const E = air.evaluation;
const S = @import("../rv64_full_statement.zig");
const Trace = @import("../rv64_full_trace.zig").Trace;
const a = std.testing.allocator;

test "full physical trace owns canonical padding counts and closes all CPU equations" {
    const program_base: u64 = 0x100001000;
    const data_address: u64 = 0xf123456780002000;
    const program = [_]u32{ 0x00108093, 0x001080b3, 0x0020f1b3, 0x4021d1b3, 0x00323023, 0x00023283, 0x02208333, 0x0220d3b3 }; // ADDI; aliased ADD; AND; SRA; SD; LD; MUL; DIVU
    var memory = rv.rv64.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = program_base, .size = program.len * 4, .permissions = .{ .read = true, .execute = true } });
    try memory.map(.{ .start = data_address, .size = 8, .permissions = .{ .read = true, .write = true } });
    for (program, 0..) |raw, i| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, raw, .little);
        try memory.initialize(program_base + 4 * i, &bytes);
    }
    var cpu = rv.rv64.machine.Cpu.init(program_base, 0);
    cpu.regs[1] = 0xfffffffffffffffd;
    cpu.regs[2] = 0x800000000000003f;
    cpu.regs[4] = data_address;
    const initial = cpu.regs;
    var records: [program.len]rv.rv64.machine.Retirement = undefined;
    for (&records) |*record| record.* = try cpu.step(&memory);
    const cells = [_]S.Cell{.{ .address = data_address, .initial = 0, .final = memory.backing.load(data_address, 8).value }};
    const memory_clocks = [_]u32{24};
    var statement = S.Statement{ .program = .{ .base = program_base, .words = &program }, .steps = program.len, .initial_pc = program_base, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .cells = &cells, .register_clocks = @splat(0), .memory_clocks = &memory_clocks, .opcodes = @splat(false) };
    const opcodes = [_]rv.rv64.decode.Opcode{ .ADDI, .ADD, .AND, .SRA, .SD, .LD, .MUL, .DIVU };
    for (opcodes) |op| statement.opcodes[@intFromEnum(op)] = true;
    statement.register_clocks[1] = 29;
    statement.register_clocks[2] = 30;
    statement.register_clocks[3] = 18;
    statement.register_clocks[4] = 21;
    statement.register_clocks[5] = 23;
    statement.register_clocks[6] = 27;
    statement.register_clocks[7] = 31;
    var setup = try air.program.setup.Setup.init(a, statement.program);
    defer setup.deinit();
    const plan = air.encoding.Plan.fromOpcodes(&opcodes);
    try std.testing.checkAllAllocationFailures(a, initializeAndRelease, .{ &records, statement, &setup, &plan });
    var trace = try Trace.init(a, &records, statement, &setup, &plan);
    defer trace.deinit();
    try std.testing.expectError(error.InvalidRv64FullTree, trace.columns(a, 0));
    try std.testing.expectEqual(@as(u64, 1), trace.rom_counts[0]);
    try std.testing.expectEqual(@as(u64, 1), trace.rom_counts[1]);
    var total: u64 = 0;
    for (trace.byte_counts) |count| total += count;
    try std.testing.expectEqual(@as(u64, @intCast(plan.range_count * trace.domainSize())), total);
    var channel = air.protocol.Channel{};
    const challenges = air.full.component.Challenges{ .state = air.relations.Challenges.draw(&channel), .rom = air.program.compact.draw(&channel), .bytes = channel.drawSecureFelt(), .bitwise = air.providers.tables.Challenges.draw(&channel), .shifts = air.providers.tables.Challenges.draw(&channel) };
    var failed = challenges;
    failed.state.offset = Q.zero();
    failed.state.coefficients = @splat(Q.zero());
    try std.testing.expectError(error.DivisionByZero, trace.generateInteraction(failed));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    failed.state.offset = Q.zero().sub(Q.one());
    failed.state.coefficients[1] = Q.one(); // Only register-x1 denominators vanish.
    try std.testing.expectError(error.DivisionByZero, trace.generateInteraction(failed));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    const saved_state = trace.state_metadata[0].words[0];
    trace.state_metadata[0].words[0] ^= 1;
    try std.testing.expectError(error.InvalidRv64FullStateClosure, trace.generateInteraction(challenges));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    trace.state_metadata[0].words[0] = saved_state;
    const claims = try trace.generateInteraction(challenges);
    try std.testing.expectEqual(@as(usize, 0), trace.state_metadata.len);
    try std.testing.expectEqual(@as(usize, 0), trace.lookup_metadata.len);
    try std.testing.expect(claims.state.eql(try statement.expectedState(challenges.state)));
    var byte_claim = Q.zero();
    for (trace.byte_counts, 0..) |count, value| byte_claim = byte_claim.add((try challenges.bytes.sub(E.q(@intCast(value))).inv()).mulM31(core.fields.m31.M31.fromCanonical(@intCast(count))));
    try std.testing.expect(byte_claim.eql(claims.bytes));
    for ([_]air.providers.tables.Kind{ .byte_and, .byte_shift }) |kind| {
        var table_claim = Q.zero();
        const counts = if (kind == .byte_and) trace.and_counts else trace.shift_counts;
        const challenge = if (kind == .byte_and) challenges.bitwise else challenges.shifts;
        for (counts, 0..) |count, index| {
            if (count == 0) continue;
            var tuple: [6]Q = undefined;
            for (kind.tupleAt(index), 0..) |value, c| tuple[c] = E.q(value);
            table_claim = table_claim.add((try challenge.denominator(tuple[0..kind.arity()]).inv()).mulM31(core.fields.m31.M31.fromCanonical(@intCast(count))));
        }
        try std.testing.expect(table_claim.eql(if (kind == .byte_and) claims.bitwise else claims.shifts));
    }
    const component = try air.full.component.Component.init(trace.log_size, &plan, .{ .steps = statement.steps, .initial_pc = statement.initial_pc, .final_pc = statement.final_pc }, challenges, claims, .{});
    const residuals = try a.alloc(Q, component.constraint_count);
    defer a.free(residuals);
    var physical: [air.layout.MAIN + air.full.frame.WIDTH]Q = undefined;
    var prior_main: [air.layout.MAIN + air.full.frame.WIDTH]Q = undefined;
    var current: [air.full.component.MAX_INTERACTION]Q = undefined;
    var prior: [air.full.component.MAX_INTERACTION]Q = undefined;
    for (0..trace.domainSize()) |i| {
        const row = air.witness.physical(i, trace.log_size);
        const previous = air.witness.physical((i + trace.domainSize() - 1) % trace.domainSize(), trace.log_size);
        for (0..component.mainCount()) |c| {
            physical[c] = Q.fromBase(trace.main[c * trace.domainSize() + row]);
            prior_main[c] = Q.fromBase(trace.main[c * trace.domainSize() + previous]);
        }
        for (0..component.interactionCount()) |c| {
            current[c] = Q.fromBase(trace.interaction[c * trace.domainSize() + row]);
            prior[c] = Q.fromBase(trace.interaction[c * trace.domainSize() + previous]);
        }
        var sink = E.Sink{ .values = residuals };
        component.emit(.{ E.q(@intCast(i)), E.q(@intFromBool(i == 0)), E.q(@intFromBool(i + 1 == trace.domainSize())) }, physical[0..component.mainCount()], prior_main[0..component.mainCount()], current[0..component.interactionCount()], prior[0..component.interactionCount()], &sink);
        for (residuals, 0..) |residual, c| if (!residual.isZero()) {
            std.debug.print("full trace residual row={d} constraint={d}\n", .{ i, c });
            return error.InvalidFullTraceConstraint;
        };
    }
    var bad = records;
    bad[1].previous_rd = @TypeOf(bad[1].previous_rd).fromInt(99);
    try std.testing.expectError(error.InvalidRv64FullRegisterChain, Trace.init(a, &bad, statement, &setup, &plan));
    bad = records;
    bad[5].memory.?.before_word = @TypeOf(bad[5].memory.?.before_word).fromInt(0);
    try std.testing.expectError(error.InvalidRv64FullMemoryChain, Trace.init(a, &bad, statement, &setup, &plan));
    bad = records;
    bad[0].next_pc = @TypeOf(bad[0].next_pc).fromInt(program_base + 5);
    bad[1].pc = bad[0].next_pc;
    try std.testing.expectError(error.InvalidRv64RomExecution, Trace.init(a, &bad, statement, &setup, &plan));
    var invalid_program = program;
    invalid_program[0] = 0; // Invalid ROM bytes may exist, but cannot retire.
    var invalid_public = statement;
    invalid_public.program.words = &invalid_program;
    var invalid_setup = try air.program.setup.Setup.init(a, invalid_public.program);
    defer invalid_setup.deinit();
    try std.testing.expectError(error.InvalidRv64RomExecution, Trace.init(a, &records, invalid_public, &invalid_setup, &plan));
    // Retained metadata is prover advice. Altering it cannot authenticate a
    // different byte against the already counted and committed provider.
    var forged_lookup = try Trace.init(a, &records, statement, &setup, &plan);
    defer forged_lookup.deinit();
    forged_lookup.lookup_metadata[0] ^= 1;
    const forged_claims = try forged_lookup.generateInteraction(challenges);
    try std.testing.expect(!forged_claims.bytes.eql(byte_claim));
    // PCS owns its coefficients after main commitment. All lookup/state
    // obligations must still close after releasing the source wide columns.
    var released = try Trace.init(a, &records, statement, &setup, &plan);
    defer released.deinit();
    try exerciseMainHandoff(a, &released);
    const released_claims = try released.generateInteraction(challenges);
    try std.testing.expect(released_claims.state.eql(claims.state));
    try std.testing.expect(released_claims.rom.eql(claims.rom));
    try std.testing.expect(released_claims.bytes.eql(claims.bytes));
    try std.testing.expect(released_claims.bitwise.eql(claims.bitwise));
    try std.testing.expect(released_claims.shifts.eql(claims.shifts));
    a.free(released.interaction);
    released.interaction = &.{};
    try std.testing.expectError(error.InvalidRv64FullTracePhase, released.generateInteraction(challenges));
}

fn initializeAndRelease(allocator: std.mem.Allocator, records: []const rv.rv64.machine.Retirement, statement: S.Statement, setup: *const air.program.setup.Setup, plan: *const air.encoding.Plan) !void {
    var trace = try Trace.init(allocator, records, statement, setup, plan);
    defer trace.deinit();
    try exerciseMainHandoff(allocator, &trace);
}

fn exerciseMainHandoff(allocator: std.mem.Allocator, trace: *Trace) !void {
    const M = core.fields.m31.M31;
    const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
    var logs: [4]u32 = .{ trace.program.log_size, 8, 0, 0 };
    var count: usize = 2;
    if (trace.plan.byte_bitwise) {
        logs[count] = 16;
        count += 1;
    }
    if (trace.plan.support.shifts) {
        logs[count] = 11;
        count += 1;
    }
    var columns: [4]Column = undefined;
    var initialized: usize = 0;
    defer for (columns[0..initialized]) |column| allocator.free(column.values);
    for (logs[0..count], 0..) |log, i| {
        const values = try allocator.alloc(M, @as(usize, 1) << @intCast(log));
        @memset(values, M.fromCanonical(@intCast(i + 1)));
        columns[i] = .{ .log_size = log, .values = values };
        initialized += 1;
    }
    const original = trace.main_backing;
    const metadata = trace.state_metadata;
    var other = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer other.deinit();
    try std.testing.expectError(error.Rv64FullCommitAllocatorMismatch, trace.takeMainForCommit(other.allocator(), columns[0..count]));
    try std.testing.expectEqual(original.ptr, trace.main_backing.ptr);
    try std.testing.expectError(error.InvalidRv64FullProviderShape, trace.takeMainForCommit(allocator, columns[0 .. count - 1]));
    var transfer = trace.takeMainForCommit(allocator, columns[0..count]) catch |err| {
        try std.testing.expectEqual(original.ptr, trace.main_backing.ptr);
        try std.testing.expectEqual(original.len, trace.main_backing.len);
        try std.testing.expectEqual(metadata.ptr, trace.state_metadata.ptr);
        return err;
    };
    defer transfer.deinit(allocator);
    try std.testing.expectEqual(original.ptr, transfer.backing[0].ptr);
    try std.testing.expectEqual(original.len, transfer.backing[0].len);
    try std.testing.expectEqual(@as(usize, 0), trace.main.len);
    try std.testing.expectEqual(@as(usize, 0), trace.main_backing.len);
    try std.testing.expectEqual(metadata.ptr, trace.state_metadata.ptr);
    try std.testing.expectError(error.InvalidRv64FullMainPhase, trace.takeMainForCommit(allocator, columns[0..count]));
    const width = trace.plan.main_count + air.full.frame.WIDTH;
    for (columns[0..count], transfer.columns[width..], 0..) |source, copied, i| {
        try std.testing.expect(source.values.ptr != copied.values.ptr);
        try std.testing.expectEqualSlices(M, source.values, copied.values);
        for (source.values) |value| try std.testing.expect(value.eql(M.fromCanonical(@intCast(i + 1))));
    }
}

test "full physical trace state inversion batches preserve prefixes across 512-row boundary" {
    const count = 513;
    var program: [count]u32 = undefined;
    for (&program, 0..) |*raw, i| raw.* = ([_]u32{ 0x00108093, 0x0020f1b3, 0x4021d1b3 })[i % 3];
    var memory = rv.rv64.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 0x1000, .size = count * 4, .permissions = .{ .read = true, .execute = true } });
    for (program, 0..) |raw, i| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, raw, .little);
        try memory.initialize(0x1000 + 4 * i, &bytes);
    }
    var cpu = rv.rv64.machine.Cpu.init(0x1000, 0);
    cpu.regs[1] = 0x87654321abcdef00;
    cpu.regs[2] = 0x800000000000003f;
    const initial = cpu.regs;
    const records = try a.alloc(rv.rv64.machine.Retirement, count);
    defer a.free(records);
    for (records) |*record| record.* = try cpu.step(&memory);
    var statement = S.Statement{ .program = .{ .base = 0x1000, .words = &program }, .steps = count, .initial_pc = 0x1000, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .cells = &.{}, .register_clocks = @splat(0), .memory_clocks = &.{}, .opcodes = @splat(false) };
    const opcodes = [_]rv.rv64.decode.Opcode{ .ADDI, .AND, .SRA };
    for (opcodes) |opcode| statement.opcodes[@intFromEnum(opcode)] = true;
    statement.register_clocks[1] = 2045;
    statement.register_clocks[2] = 2050;
    statement.register_clocks[3] = 2051;
    var setup = try air.program.setup.Setup.init(a, statement.program);
    defer setup.deinit();
    const plan = air.encoding.Plan.fromOpcodes(&opcodes);
    var trace = try Trace.init(a, records, statement, &setup, &plan);
    defer trace.deinit();
    var pool: @import("stwo_prover_engine").work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    try std.testing.checkAllAllocationFailures(a, initializeParallelAndRelease, .{ records, statement, &setup, &plan, &pool });
    var parallel = try Trace.initWithPool(a, records, statement, &setup, &plan, &pool);
    defer parallel.deinit();
    for (trace.main, parallel.main) |serial_value, parallel_value| try std.testing.expect(serial_value.eql(parallel_value));
    try std.testing.expect(std.mem.eql(u8, trace.lookup_metadata, parallel.lookup_metadata));
    try std.testing.expectEqualSlices(u64, &trace.byte_counts, &parallel.byte_counts);
    try std.testing.expectEqualSlices(u64, trace.and_counts, parallel.and_counts);
    try std.testing.expectEqualSlices(u64, trace.shift_counts, parallel.shift_counts);
    var small_stack: @import("stwo_prover_engine").work_pool.WorkPool = undefined;
    try small_stack.initInPlaceWithOptions(.{ .worker_count = 2, .stack_size = 64 * 1024, .backing_allocator = a });
    defer small_stack.deinit();
    try std.testing.expectError(error.InvalidRv64ProjectionStack, Trace.initWithPool(a, records, statement, &setup, &plan, &small_stack));
    try std.testing.expectEqual(@as(usize, 1024), trace.domainSize());
    var channel = air.protocol.Channel{};
    const challenges = air.full.component.Challenges{ .state = air.relations.Challenges.draw(&channel), .rom = air.program.compact.draw(&channel), .bytes = channel.drawSecureFelt(), .bitwise = air.providers.tables.Challenges.draw(&channel), .shifts = air.providers.tables.Challenges.draw(&channel) };
    const claims = try trace.generateInteraction(challenges);
    try std.testing.expectError(error.InvalidRv64InteractionStack, parallel.generateInteractionWithPool(challenges, &small_stack));
    var failed = challenges;
    failed.state.offset = Q.zero();
    failed.state.coefficients = @splat(Q.zero());
    try std.testing.expectError(error.DivisionByZero, parallel.generateInteractionWithPool(failed, &pool));
    try std.testing.expectEqual(@as(usize, 0), parallel.interaction.len);
    try std.testing.checkAllAllocationFailures(a, initializeParallelGenerateAndRelease, .{ records, statement, &setup, &plan, &pool, challenges });
    const parallel_claims = try parallel.generateInteractionWithPool(challenges, &pool);
    try std.testing.expect(parallel_claims.state.eql(claims.state));
    for (trace.interaction, parallel.interaction) |serial_value, parallel_value| try std.testing.expect(serial_value.eql(parallel_value));
    try std.testing.expect(claims.state.eql(try statement.expectedState(challenges.state)));
    // Compare the first prefix after the batch boundary against independent
    // direct inversions of the initial and current public register cells.
    const row = air.witness.physical(512, trace.log_size);
    const prefix = Q.fromM31(trace.interaction[32 * trace.domainSize() + row], trace.interaction[33 * trace.domainSize() + row], trace.interaction[34 * trace.domainSize() + row], trace.interaction[35 * trace.domainSize() + row]);
    try std.testing.expect(prefix.eql(claims.state));
}

fn initializeParallelAndRelease(allocator: std.mem.Allocator, records: []const rv.rv64.machine.Retirement, statement: S.Statement, setup: *const air.program.setup.Setup, plan: *const air.encoding.Plan, pool: *@import("stwo_prover_engine").work_pool.WorkPool) !void {
    var trace = try Trace.initWithPool(allocator, records, statement, setup, plan, pool);
    defer trace.deinit();
}
fn initializeParallelGenerateAndRelease(allocator: std.mem.Allocator, records: []const rv.rv64.machine.Retirement, statement: S.Statement, setup: *const air.program.setup.Setup, plan: *const air.encoding.Plan, pool: *@import("stwo_prover_engine").work_pool.WorkPool, challenges: air.full.component.Challenges) !void {
    var trace = try Trace.initWithPool(allocator, records, statement, setup, plan, pool);
    defer trace.deinit();
    _ = try trace.generateInteractionWithPool(challenges, pool);
}

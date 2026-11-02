const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const S = @import("../rv64_full_statement.zig");
const Trace = @import("../rv64_full_trace.zig").Trace;
const M = core.fields.m31.M31;
const a = std.testing.allocator;

test "borrowed CPU excludes immutable ROM rows and unused compact capacity before allocation or writes" {
    const pc = 0x1000;
    const words = try a.alloc(u32, 4096);
    defer a.free(words);
    @memset(words, 0x00108093);
    var program = try air.program.setup.Setup.init(a, .{ .base = pc, .words = words });
    defer program.deinit();
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = pc, .size = 4, .permissions = .{ .read = true, .execute = true } });
    var instruction: [4]u8 = undefined;
    std.mem.writeInt(u32, &instruction, words[0], .little);
    try memory.initialize(pc, &instruction);
    var cpu = rv.machine.Cpu.init(pc, 0);
    const initial = cpu.regs;
    const record = try cpu.step(&memory);
    var statement = S.Statement{ .program = .{ .base = pc, .words = words }, .steps = 1, .initial_pc = pc, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .register_clocks = @splat(0), .memory_clocks = &.{}, .cells = &.{}, .opcodes = @splat(false) };
    statement.opcodes[@intFromEnum(rv.decode.Opcode.ADDI)] = true;
    statement.register_clocks[1] = 3;
    var tape = try rv.compact_tape.Tape.init(a, 4096, pc, 0, .rv64im);
    defer tape.deinit();
    @memset(std.mem.sliceAsBytes(tape.storage), 0xa5);
    try tape.append(record);
    const rows_before = try a.dupe(u8, std.mem.sliceAsBytes(program.rows));
    defer a.free(rows_before);
    const tape_before = try a.dupe(u8, std.mem.sliceAsBytes(tape.storage));
    defer a.free(tape_before);
    for ([_]air.control_policy.Policy{ .bytes_v1, .limbs24_v2 }) |control| {
        var plan = air.encoding.Plan.fromOpcodes(&.{.ADDI});
        plan.control_policy = control;
        const cells = (plan.main_count + air.full.frame.widthWithControl(.rv64im, control)) * (@as(usize, 1) << @intCast(statement.logSize()));
        const row_alias = std.mem.bytesAsSlice(M, std.mem.sliceAsBytes(program.rows))[0..cells];
        // Alias ONLY unused capacity, beyond the one published step.
        const tape_alias = std.mem.bytesAsSlice(M, std.mem.sliceAsBytes(tape.storage[1..]))[0..cells];
        for ([_][]M{ row_alias, tape_alias }) |alias| {
            var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
            try std.testing.expectError(error.OverlappingCryptoMainBuffers, Trace.initWithPrivateTapeBorrowedMain(failing.allocator(), &tape, 1, .{ 1, 1 }, statement, .{ .cells = &.{}, .memory_clocks = &.{} }, &program, &plan, alias));
            try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqualSlices(u8, rows_before, std.mem.sliceAsBytes(program.rows));
            try std.testing.expectEqualSlices(u8, tape_before, std.mem.sliceAsBytes(tape.storage));
        }
        const valid = try a.alloc(M, cells);
        defer a.free(valid);
        @memset(valid, M.fromCanonical(37));
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        try std.testing.expectError(error.OutOfMemory, Trace.initWithPrivateTapeBorrowedMain(failing.allocator(), &tape, 1, .{ 1, 1 }, statement, .{ .cells = &.{}, .memory_clocks = &.{} }, &program, &plan, valid));
        try std.testing.expect(failing.has_induced_failure);
        for (valid) |value| try std.testing.expectEqualDeep(M.fromCanonical(37), value);
        try std.testing.expectEqualSlices(u8, rows_before, std.mem.sliceAsBytes(program.rows));
        try std.testing.expectEqualSlices(u8, tape_before, std.mem.sliceAsBytes(tape.storage));
    }
}

fn ramBuffers(a0: std.mem.Allocator, shapes: air.memory.private_trace.Shapes, owned: *?[]M) !air.memory.private_trace.MainBuffers {
    const T = air.memory.private_trace;
    var total: usize = 256 + 16 + 303 * (@as(usize, 1) << @intCast(shapes.provider_log));
    for (T.TABLES) |table| total += T.mainWidth(table) * (@as(usize, 1) << @intCast(T.tableLog(shapes, table)));
    const backing = try a0.alloc(M, total);
    owned.* = backing;
    @memset(backing, M.fromCanonical(73));
    var result: T.MainBuffers = undefined;
    var at: usize = 0;
    for (T.TABLES) |table| {
        const len = T.mainWidth(table) * (@as(usize, 1) << @intCast(T.tableLog(shapes, table)));
        result.callers[@intFromEnum(table)] = backing[at..][0..len];
        at += len;
    }
    result.provider = backing[at..][0 .. 303 * (@as(usize, 1) << @intCast(shapes.provider_log))];
    at += result.provider.len;
    result.policy_tail = backing[at..][0..16];
    at += 16;
    result.byte_tail = backing[at..][0..256];
    return result;
}
test "borrowed RAM excludes native opening payload before allocation mutation or partial ownership move" {
    const R = air.memory;
    const T = R.private_trace;
    var failing = std.testing.FailingAllocator.init(a, .{});
    const metadata_allocator = failing.allocator();
    {
        var cache = try R.values.Cache.empty(a, .chunk512);
        defer cache.deinit();
        var policy = try R.policy.Policy.init(a, &.{.{ .first = 0x1000, .last = 0x15ff, .flags = 3 }});
        defer policy.deinit();
        const before: [3][64]u64 = @splat(@splat(0));
        var after = before;
        var clocks: [3][64]u32 = @splat(@splat(0));
        const rights: [3][64]u2 = @splat(@splat(3));
        var openings: [3]R.batch.Opening = undefined;
        for (&openings, 0..) |*opening, i| {
            after[i][0] = 17 + i;
            clocks[i][0] = @intCast(4 * i + 4);
            opening.* = .{ .index = 8 + i, .before = &before[i], .after = &after[i], .terminal_clocks = &clocks[i], .rights = &rights[i] };
        }
        var captured = try R.openings.Owned.copy(metadata_allocator, .chunk512, &openings);
        defer captured.deinit();
        var preparation = try T.Preparation.init(metadata_allocator, .chunk512, &policy, captured.chunks);
        defer preparation.deinit();
        var backing: ?[]M = null;
        defer if (backing) |data| a.free(data);
        var buffers = try ramBuffers(a, preparation.shapes, &backing);
        const before_words = try a.dupe(u64, captured.words);
        defer a.free(before_words);
        const before_backing = try a.dupe(M, backing.?);
        defer a.free(before_backing);
        const edge = @intFromEnum(T.Table.edge_cells);
        const edge_owner = buffers.callers[edge];
        buffers.callers[edge] = std.mem.bytesAsSlice(M, std.mem.sliceAsBytes(captured.words))[0..buffers.callers[edge].len];
        // Inputs were legitimately allocated through this owner. Arm the very
        // first constructor allocation only after native preparation completes.
        failing.alloc_index = 0;
        failing.fail_index = 0;
        try std.testing.expectError(error.OverlappingCryptoMainBuffers, T.Trace.initPreparedBorrowedOwned(metadata_allocator, &cache, &preparation, &captured, buffers));
        try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expect(preparation.available and captured.chunks.len == 3);
        try std.testing.expectEqualSlices(u64, before_words, captured.words);
        try std.testing.expectEqualSlices(M, before_backing, backing.?);
        buffers.callers[edge] = edge_owner;
        failing.fail_index = std.math.maxInt(usize);
        var trace = try T.Trace.initPreparedBorrowedOwned(metadata_allocator, &cache, &preparation, &captured, buffers);
        trace.deinit();
        // The historical preparation.source descriptors have now been freed
        // by the moved trace. A retry must reject phase before dereferencing.
        failing.alloc_index = 0;
        failing.fail_index = 0;
        try std.testing.expectError(error.InvalidPrivateRamPreparation, T.Trace.initPreparedBorrowedOwned(metadata_allocator, &cache, &preparation, &captured, buffers));
        try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    }
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

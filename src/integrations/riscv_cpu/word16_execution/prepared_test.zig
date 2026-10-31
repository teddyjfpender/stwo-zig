const std = @import("std");
const core = @import("stwo_core");
const front = @import("stwo_riscv_frontend");
const Prepared = @import("prepared.zig");
const Sources = @import("sources.zig");
const Setup = @import("setup.zig").Setup;
const Program = @import("program.zig").Program;
const CPU = @import("cpu_source.zig");
const Execution = @import("execution.zig");
const X = front.rv64_air.word16_execution;
const a = std.testing.allocator;
const WORDS = [_]u32{ 0x00004033, 0xfe000ee3 }; // XOR x0,x0,x0; BEQ x0,x0,-4
var image_context: u8 = 0;
const ZeroImage = struct {
    fn word(_: *const anyopaque, _: u64) !u64 {
        return 0;
    }
    fn rights(_: *const anyopaque, _: u64) !u2 {
        return 0;
    }
};
fn image() @import("memory/statement.zig").Image {
    return .{ .context = &image_context, .initial_word = ZeroImage.word, .rights_at = ZeroImage.rights };
}
const Fixture = struct {
    tape: front.rv64.compact_tape.Tape,
    boundary: X.types.Boundary,
    fn init() !@This() {
        var tape = try front.rv64.compact_tape.Tape.init(a, 130, 4096, 0, .ethereum_services_v2);
        tape.len = 130;
        for (tape.storage[0..130], 0..) |*step, i| step.* = .{ .next_pc = if (i % 2 == 0) 4100 else 4096, .lhs = 0, .rhs = 0, .previous_rd = 0, .result = 0, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = @intFromBool(i % 2 == 1) };
        return .{ .tape = tape, .boundary = .{ .steps = 130, .initial_pc = 4096, .final_pc = 4096, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) } };
    }
    fn deinit(self: *@This()) void {
        self.tape.deinit();
    }
};
fn admission() Execution.Admission {
    return .{ .image = image(), .image_identity = @splat(9), .initial_pc = 4096, .initial_registers = @splat(0) };
}
test "Prepared groups exact full words and operation IDs in stable order with bounded allocation ownership" {
    const input = [_]Prepared.Binary.Fact{ .{ .op = .xor, .a = 0x100000000, .b = 7, .c = 0x100000007 }, .{ .op = .or_, .a = 3, .b = 4, .c = 7 }, .{ .op = .xor, .a = 0x100000000, .b = 7, .c = 0x100000007 }, .{ .op = .xor, .a = 0, .b = 7, .c = 7 } };
    var grouped = try Prepared.Binary.collect(a, &input, true);
    defer grouped.deinit();
    try std.testing.expectEqual(@as(usize, 3), grouped.facts.len);
    try std.testing.expectEqualSlices(u32, &.{ 2, 1, 1 }, grouped.weights);
    try std.testing.expectEqualDeep(input[0], grouped.facts[0]);
    try std.testing.expectEqualDeep(input[3], grouped.facts[2]);
    var raw = try Prepared.Binary.collect(a, &input, false);
    defer raw.deinit();
    try std.testing.expectEqualSlices(Prepared.Binary.Fact, &input, raw.facts);
    try std.testing.expectEqualSlices(u32, &.{ 1, 1, 1, 1 }, raw.weights);
    const Runner = struct {
        fn run(allocator: std.mem.Allocator, fs: []const Prepared.Binary.Fact) !void {
            var g = try Prepared.Binary.collect(allocator, fs, true);
            defer g.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{&input});
}
test "One CPU witness chooses grouped geometry then rebinds moved Program and fresh-verifies actual weighted proof" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var program = try Program.init(a, .{ .base = 4096, .words = &WORDS });
    var owns_program = true;
    defer if (owns_program) program.deinit();
    var prepared = try Prepared.Prepared.init(a, &program, fixture.boundary, 1, 8, &fixture.tape, .{});
    defer prepared.deinit();
    try std.testing.expectEqual(@as(u32, 65), prepared.raw_counts.alu);
    try std.testing.expectEqual(@as(u32, 65), prepared.raw_counts.binary);
    try std.testing.expectEqual(@as(usize, 1), prepared.alu.facts.len);
    try std.testing.expectEqual(@as(usize, 1), prepared.binary.facts.len);
    try std.testing.expectEqual(@as(u32, 65), prepared.alu.weights[0]);
    try std.testing.expectEqual(@as(u32, 65), prepared.binary.weights[0]);
    const geometry = try prepared.geometry();
    try std.testing.expectEqual(@as(u32, 5), geometry.alu_log);
    try std.testing.expectEqual(@as(u32, 5), geometry.binary_log);
    const cpu_main = try a.dupe(core.fields.m31.M31, prepared.cpu.?.main);
    defer a.free(cpu_main);
    owns_program = false;
    var setup = try Setup.initOwnedProgram(a, program, geometry);
    defer setup.deinit();
    var source = try Sources.Source.fromPrepared(a, &setup.materials, image(), &prepared);
    var owns_source = true;
    defer if (owns_source) source.deinit();
    try std.testing.expect(source.cpu.program == &setup.materials.program);
    try std.testing.expect(prepared.cpu == null and prepared.jalr == null);
    try std.testing.expectEqualSlices(core.fields.m31.M31, cpu_main, source.cpu.main);
    var mass: u64 = 0;
    for (source.alu.range16_counts) |v| mass += v;
    try std.testing.expectEqual(@as(u64, 20 * 32), mass);
    var and_mass: u64 = 0;
    for (source.binary.and_counts) |v| and_mass += v;
    try std.testing.expectEqual(@as(u64, 8 * 32), and_mass);
    owns_source = false;
    var encoded = try Execution.provePrepared(a, &setup, admission(), source, null);
    defer encoded.deinit(a);
    var fresh = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, geometry);
    defer fresh.deinit();
    try Execution.verify(a, &fresh, admission(), encoded);
    var wrong = encoded;
    wrong.request.cpu.final_registers[1] = 1;
    if (Execution.verify(a, &fresh, admission(), wrong)) |_| return error.AcceptedWrongPreparedBoundary else |_| {}
}
test "Legacy wrappers and caller-prepared unit BINARY retain identical full proof bytes at raw geometry" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, .{ .cpu_log = 8, .alu_log = 7, .binary_log = 7 });
    defer setup.deinit();
    var legacy = try Execution.prove(a, &setup, admission(), fixture.boundary, &fixture.tape, null);
    defer legacy.deinit(a);
    var prepared = try Prepared.Prepared.init(a, &setup.materials.program, fixture.boundary, 1, 8, &fixture.tape, .{ .deduplicate_binary = false, .jalr_log = 5 });
    defer prepared.deinit();
    const source = try Sources.Source.fromPrepared(a, &setup.materials, image(), &prepared);
    var explicit = try Execution.provePrepared(a, &setup, admission(), source, null);
    defer explicit.deinit(a);
    try std.testing.expectEqualSlices(u8, legacy.bytes, explicit.bytes);
    try std.testing.expectEqualDeep(legacy.claims, explicit.claims);
    const borrowed_source = try Sources.Source.init(a, &setup.materials, image(), fixture.boundary, 1, &fixture.tape);
    var borrowed = try Execution.provePreparedBorrowedMain(a, &setup, admission(), borrowed_source, null);
    defer borrowed.deinit(a);
    try std.testing.expectEqualSlices(u8, explicit.bytes, borrowed.bytes);
    try std.testing.expectEqualDeep(explicit.claims, borrowed.claims);
    const borrowed_inter_source = try Sources.Source.init(a, &setup.materials, image(), fixture.boundary, 1, &fixture.tape);
    var borrowed_inter = try Execution.provePreparedBorrowedInteraction(a, &setup, admission(), borrowed_inter_source, null);
    defer borrowed_inter.deinit(a);
    try std.testing.expectEqualSlices(u8, explicit.bytes, borrowed_inter.bytes);
    try std.testing.expectEqualDeep(explicit.claims, borrowed_inter.claims);
    const batch64_source = try Sources.Source.init(a, &setup.materials, image(), fixture.boundary, 1, &fixture.tape);
    var batch64 = try Execution.provePreparedWithOptions(a, &setup, admission(), batch64_source, null, .{ .main_batch_columns = 64, .interaction_batch_columns = 64 });
    defer batch64.deinit(a);
    try std.testing.expectEqualSlices(u8, explicit.bytes, batch64.bytes);
    try std.testing.expectEqualDeep(explicit.claims, batch64.claims);
    try std.testing.expectError(error.InvalidExecutionCommitBatch, (Execution.ProveOptions{ .main_batch_columns = 0 }).validate());
    try std.testing.expectError(error.InvalidExecutionCommitBatch, (Execution.ProveOptions{ .interaction_batch_columns = 257 }).validate());
    var fresh = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, setup.materials.geometry);
    defer fresh.deinit();
    try Execution.verify(a, &fresh, admission(), explicit);
}
test "Prepared transfer rejects mismatched setup before move and all allocation failures preserve single owners" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var program = try Program.init(a, .{ .base = 4096, .words = &WORDS });
    defer program.deinit();
    var prepared = try Prepared.Prepared.init(a, &program, fixture.boundary, 1, 8, &fixture.tape, .{});
    defer prepared.deinit();
    var other = try Program.init(a, .{ .base = 8192, .words = &WORDS });
    defer other.deinit();
    try std.testing.expectError(error.PreparedProgramMismatch, prepared.takeCpu(&other, 8));
    try std.testing.expect(prepared.cpu != null);
    try std.testing.expectError(error.PreparedGeometryMismatch, prepared.takeCpu(&program, 7));
    try std.testing.expect(prepared.cpu != null);
    const Runner = struct {
        fn run(allocator: std.mem.Allocator, p: *const Program, f: *const Fixture) !void {
            var native = try Prepared.Prepared.init(allocator, p, f.boundary, 1, 8, &f.tape, .{});
            defer native.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{ &program, &fixture });
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, try prepared.geometry());
    defer setup.deinit();
    const Joined = struct {
        fn run(allocator: std.mem.Allocator, materials: *const @import("setup.zig").Materials, f: *const Fixture) !void {
            var native = try Prepared.Prepared.init(a, &materials.program, f.boundary, 1, 8, &f.tape, .{});
            defer native.deinit();
            var source = try Sources.Source.fromPrepared(allocator, materials, image(), &native);
            defer source.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(a, Joined.run, .{ &setup.materials, &fixture });
    const movable = try Program.init(a, .{ .base = 4096, .words = &WORDS });
    var doomed = try Prepared.Prepared.init(a, &movable, fixture.boundary, 1, 8, &fixture.tape, .{});
    defer doomed.deinit();
    // Setup consumes/frees Program even on validation failure; native cleanup
    // must not dereference the now-invalid borrowed Program address.
    try std.testing.expectError(error.InvalidExecutionGeometry, Setup.initOwnedProgram(a, movable, .{ .cpu_log = 4 }));
}

test "Wrong grouped multiplicity remains rejected by actual closed CPU debt and invalid weight ownership stays balanced" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, .{ .cpu_log = 8 });
    defer setup.deinit();
    var prepared = try Prepared.Prepared.init(a, &setup.materials.program, fixture.boundary, 1, 8, &fixture.tape, .{});
    defer prepared.deinit();
    prepared.binary.weights[0] = 64;
    const source = try Sources.Source.fromPrepared(a, &setup.materials, image(), &prepared);
    try std.testing.expectEqual(@as(usize, 0), prepared.binary.facts.len);
    try std.testing.expectError(error.UnclosedExecutionRelations, Execution.provePrepared(a, &setup, admission(), source, null));
    var invalid = try Prepared.Prepared.init(a, &setup.materials.program, fixture.boundary, 1, 8, &fixture.tape, .{});
    defer invalid.deinit();
    invalid.binary.weights[0] = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidBinaryWeights, Sources.Source.fromPrepared(a, &setup.materials, image(), &invalid));
    try std.testing.expect(invalid.cpu == null and invalid.jalr == null);
}

test "Joined sources retire CPU fact lists while LS boundaries and immutable row reconstruction survive" {
    const Mixed = @import("../tests/rv64_word16_execution_fixture.zig").Fixture;
    var fixture = try Mixed.init(a);
    defer fixture.deinit();
    var program = try Program.initWithAuthority(a, &fixture.image.authority);
    var owns_program = true;
    defer if (owns_program) program.deinit();
    var prepared = try Prepared.Prepared.init(a, &program, fixture.boundary, 1, 5, &fixture.tape, .{});
    defer prepared.deinit();
    const ram_events = prepared.raw_counts.memory;
    try std.testing.expect(ram_events > 0);
    const geometry = try prepared.geometry();
    owns_program = false;
    var setup = try Setup.initOwnedProgram(a, program, geometry);
    defer setup.deinit();
    var source = try Sources.Source.fromPrepared(a, &setup.materials, @import("memory/statement.zig").fromOwner(&fixture.image), &prepared);
    defer source.deinit();
    try std.testing.expectEqual(@as(usize, 0), source.cpu.functions.items.len);
    try std.testing.expectEqual(@as(usize, 0), source.cpu.memory.items.len);
    try std.testing.expectEqual(@as(usize, 0), source.cpu.services.items.len);
    try std.testing.expectEqual(ram_events, source.memory.ls.rows);
    try std.testing.expectEqual(ram_events, source.request().memory.ls_count);
    try std.testing.expect(source.request().memory.initial.len > 0);
    try std.testing.expectEqual(source.memory.statement.initial.len, source.memory.statement.terminal.len);
    _ = try source.cpu.row(10);
}

test "MAIN ownership transfers original wide matrices only after every fallible allocation" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, .{ .cpu_log = 8, .alu_log = 7, .binary_log = 7 });
    defer setup.deinit();
    var failing = std.testing.FailingAllocator.init(a, .{});
    const fa = failing.allocator();
    var source = try Sources.Source.init(fa, &setup.materials, image(), fixture.boundary, 1, &fixture.tape);
    defer source.deinit();
    const cpu_ptr = source.cpu.main.ptr;
    const ls_ptr = source.memory.ls.main.ptr;
    const and_ptr = source.and_table.main.ptr;
    const shift_table_ptr = source.shift_table.main.ptr;
    // Headers, backing-list and the two generator multiplicity copies are the
    // only allocations. Every failure leaves all original owners untouched.
    for (0..4) |fail_after| {
        failing.fail_index = failing.alloc_index + fail_after;
        try std.testing.expectError(error.OutOfMemory, source.takeMainForCommit());
        failing.fail_index = std.math.maxInt(usize);
        try std.testing.expectEqual(cpu_ptr, source.cpu.main.ptr);
        try std.testing.expectEqual(ls_ptr, source.memory.ls.main.ptr);
        try std.testing.expectEqual(and_ptr, source.and_table.main.ptr);
        try std.testing.expect(source.alu.owns_main and source.memory.ls.owns_main);
    }
    source.binary.owns_main = false;
    try std.testing.expectError(error.BorrowedExecutionMain, source.takeMainForCommit());
    source.binary.owns_main = true;
    const owned = try source.takeMainForCommit();
    defer owned.deinit(fa);
    try std.testing.expectEqual(cpu_ptr, owned.columns[0].values.ptr);
    var found_ls = false;
    for (owned.backings) |buffer| {
        if (buffer.ptr == ls_ptr) found_ls = true;
        try std.testing.expect(buffer.ptr != and_ptr and buffer.ptr != shift_table_ptr);
    }
    try std.testing.expect(found_ls);
    try std.testing.expectEqual(@as(usize, 0), source.cpu.main.len);
    try std.testing.expectEqual(@as(usize, 0), source.memory.ls.main.len);
    try std.testing.expect(!source.alu.owns_main and !source.memory.ls.owns_main);
    try std.testing.expectEqual(and_ptr, source.and_table.main.ptr);
    try std.testing.expectEqual(shift_table_ptr, source.shift_table.main.ptr);
}

test "INTER ownership moves every original allocation after both allocation failures and preserves physical claims" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, .{ .cpu_log = 8, .alu_log = 7, .binary_log = 7 });
    defer setup.deinit();
    var failing = std.testing.FailingAllocator.init(a, .{});
    const fa = failing.allocator();
    var source = try Sources.Source.init(fa, &setup.materials, image(), fixture.boundary, 1, &fixture.tape);
    defer source.deinit();
    try std.testing.expectError(error.InvalidExecutionInteractionOwnershipPhase, source.takeInteractionForCommit());
    try source.releaseMain();
    const Protocol = @import("protocol.zig");
    var channel = Protocol.T.P.Channel{};
    const claims = try source.generate(Protocol.draw(&channel));
    const before = try source.columns(a, 2);
    defer a.free(before);
    for (0..2) |fail_after| {
        failing.fail_index = failing.alloc_index + fail_after;
        try std.testing.expectError(error.OutOfMemory, source.takeInteractionForCommit());
        failing.fail_index = std.math.maxInt(usize);
        const after = try source.columns(a, 2);
        defer a.free(after);
        for (before, after) |expected, actual| {
            try std.testing.expectEqual(expected.values.ptr, actual.values.ptr);
            try std.testing.expectEqual(expected.values.len, actual.values.len);
        }
        try std.testing.expectEqualDeep(claims, source.claims.?);
    }
    const owned = try source.takeInteractionForCommit();
    defer owned.deinit(fa);
    try std.testing.expectEqual(@as(usize, 17), owned.backings.len);
    for (before, owned.columns) |expected, actual| {
        try std.testing.expectEqual(expected.values.ptr, actual.values.ptr);
        try std.testing.expectEqual(expected.values.len, actual.values.len);
    }
    try std.testing.expectEqualDeep(claims, source.claims.?);
    try std.testing.expectEqual(@as(usize, 0), source.cpu.interaction.len);
    try std.testing.expectEqual(@as(usize, 0), source.memory.ls.interaction.len);
    try std.testing.expectEqual(@as(usize, 0), source.boundary.len);
    source.releaseCommittedInteraction(); // Already transferred, never free twice.
    if (source.takeInteractionForCommit()) |again| {
        again.deinit(fa);
        return error.AcceptedRepeatedInteractionTransfer;
    } else |_| {}
}

test "Prepared capture groups without CPU MAIN then projects once after Tape destruction with exact proof and retry" {
    var fixture = try Fixture.init();
    var tape_alive = true;
    defer if (tape_alive) fixture.deinit();
    var setup = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, .{ .cpu_log = 8, .alu_log = 7, .binary_log = 7 });
    defer setup.deinit();
    const options: Prepared.Options = .{ .deduplicate_binary = false, .jalr_log = 5 };
    var eager = try Prepared.Prepared.init(a, &setup.materials.program, fixture.boundary, 1, 8, &fixture.tape, options);
    defer eager.deinit();
    var captured = try Prepared.Prepared.capture(a, &setup.materials.program, fixture.boundary, 1, 8, &fixture.tape, options);
    defer captured.deinit();
    try std.testing.expectEqual(@as(usize, 0), captured.cpu.?.main.len);
    try std.testing.expect(!captured.cpu.?.main_projection_closed);
    try std.testing.expectEqualDeep(try eager.geometry(), try captured.geometry());
    try std.testing.expectEqualDeep(eager.raw_counts, captured.raw_counts);
    try std.testing.expectEqualDeep(eager.alu.facts, captured.alu.facts);
    try std.testing.expectEqualDeep(eager.binary.facts, captured.binary.facts);
    var failing = std.testing.FailingAllocator.init(a, .{});
    var retryable = try Prepared.Prepared.capture(failing.allocator(), &setup.materials.program, fixture.boundary, 1, 8, &fixture.tape, options);
    defer retryable.deinit();
    fixture.deinit();
    tape_alive = false;
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, retryable.ensureCpuMain(&setup.materials.program, 8));
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expect(retryable.cpu != null);
    try std.testing.expectEqual(@as(usize, 0), retryable.cpu.?.main.len);
    try std.testing.expect(!retryable.cpu.?.main_projection_closed);
    try std.testing.expectEqualDeep(captured.alu.facts, retryable.alu.facts);
    try retryable.ensureCpuMain(&setup.materials.program, 8);
    try std.testing.expectEqualSlices(core.fields.m31.M31, eager.cpu.?.main, retryable.cpu.?.main);
    const eager_source = try Sources.Source.fromPrepared(a, &setup.materials, image(), &eager);
    const captured_source = try Sources.Source.fromPrepared(a, &setup.materials, image(), &captured);
    try std.testing.expectEqualSlices(core.fields.m31.M31, eager_source.cpu.main, captured_source.cpu.main);
    try std.testing.expectEqualSlices(u64, eager_source.counts16, captured_source.counts16);
    try std.testing.expectEqualSlices(u64, eager_source.counts8, captured_source.counts8);
    var expected = try Execution.provePrepared(a, &setup, admission(), eager_source, null);
    defer expected.deinit(a);
    var actual = try Execution.provePrepared(a, &setup, admission(), captured_source, null);
    defer actual.deinit(a);
    try std.testing.expectEqualSlices(u8, expected.bytes, actual.bytes);
    try std.testing.expectEqualDeep(expected.claims, actual.claims);
    var fresh = try Setup.init(a, .{ .base = 4096, .words = &WORDS }, setup.materials.geometry);
    defer fresh.deinit();
    try Execution.verify(a, &fresh, admission(), actual);
}

test "Capture keeps Keccak service ownership opt-in and rejects other service tags" {
    var program = try Program.init(a, .{ .base = 4096, .words = &.{0x00000073} });
    defer program.deinit();
    var tape = try front.rv64.compact_tape.Tape.init(a, 1, 4096, 0, .ethereum_services_v2);
    defer tape.deinit();
    tape.len = 1;
    const pointer: u64 = 0x8000000000001000;
    tape.storage[0] = .{ .next_pc = 4100, .lhs = pointer, .rhs = 0x10001, .previous_rd = 0, .result = 0, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
    var public: X.types.Boundary = .{ .steps = 1, .initial_pc = 4096, .final_pc = 4100, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
    public.initial_registers[10] = pointer;
    public.initial_registers[17] = 0x10001;
    public.final_registers = public.initial_registers;
    public.register_clocks[10] = 1;
    public.register_clocks[17] = 2;
    try std.testing.expectError(error.UnqualifiedWord16ServiceOwners, Prepared.Prepared.capture(a, &program, public, 1, 5, &tape, .{}));
    var captured = try Prepared.Prepared.captureForKeccak(a, &program, public, 1, 5, &tape, .{});
    defer captured.deinit();
    try std.testing.expectEqual(@as(usize, 0), captured.cpu.?.main.len);
    try std.testing.expectEqual(@as(u32, 1), captured.raw_counts.service);
    try std.testing.expectEqual(@as(usize, 1), captured.cpu.?.services.items.len);
    try std.testing.expectEqual(pointer, captured.cpu.?.services.items[0].pointer);
    try captured.ensureCpuMain(&program, 5);
    try std.testing.expect(captured.cpu.?.main_projection_closed);
    tape.storage[0].rhs = 0x20001;
    public.initial_registers[17] = 0x20001;
    public.final_registers[17] = 0x20001;
    try std.testing.expectError(error.UnqualifiedWord16ServiceOwners, Prepared.Prepared.captureForKeccak(a, &program, public, 1, 5, &tape, .{}));
    try std.testing.expectError(error.UnqualifiedWord16ServiceOwners, Prepared.Prepared.initForKeccak(a, &program, public, 1, 5, &tape, .{}));
}

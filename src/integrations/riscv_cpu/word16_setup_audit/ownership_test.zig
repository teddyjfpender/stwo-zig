const std = @import("std");
const core = @import("stwo_core");
const Audit = @import("ownership.zig");
const a = std.testing.allocator;
test "allocation ledger counts identical owners once and rejects overlapping owner claims" {
    const values = try a.alloc(u32, 32);
    defer a.free(values);
    var account = Audit.Accountant{ .allocator = a };
    defer account.deinit();
    var first = Audit.Record{ .kind = "first", .index = 0 };
    var alias = Audit.Record{ .kind = "alias", .index = 1 };
    try account.add(&first, "original_fixed", values);
    try account.add(&alias, "original_fixed", values);
    try std.testing.expectEqual(@as(u64, 128), first.payload.original_fixed);
    try std.testing.expectEqual(@as(u64, 0), alias.payload.total());
    try std.testing.expectError(error.OverlappingOwnedAuditRanges, account.add(&alias, "coefficients", values[1..]));
    try std.testing.expectEqual(@as(u64, 128), account.totals.total());
}
test "real sealed compact key owns native coefficients and retained lease aliases payload" {
    const R = @import("../word16_global_execution/services/roster.zig");
    var setup = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &.{0x00108093} }, .{ .cpu_log = 5 }, .{});
    defer setup.deinit();
    var account = Audit.Accountant{ .allocator = a };
    defer account.deinit();
    var first = Audit.Record{ .kind = "tree", .index = 0 };
    try account.tree(&first, setup.key.tree);
    try std.testing.expect(first.payload.coefficients > 0 and first.payload.merkle > 0);
    try std.testing.expectEqual(@as(u64, 0), first.retained_evaluation_bytes);
    try std.testing.expectEqual(@as(u64, 0), first.uncovered_coefficient_bytes);
    var native: u64 = 0;
    for (setup.key.tree.columns) |column| native += (@as(u64, 1) << @intCast(column.log_size - 1)) * @sizeOf(core.fields.m31.M31);
    try std.testing.expectEqual(native, first.coefficient_view_bytes);
    try std.testing.expectEqual(native, first.payload.coefficients);
    var lease = setup.key.tree.retainShared();
    defer lease.deinit(a);
    var second = Audit.Record{ .kind = "lease", .index = 1 };
    try account.tree(&second, lease);
    try std.testing.expectEqual(@as(u64, 0), second.payload.total());
    try std.testing.expectEqual(first.coefficient_view_bytes, second.coefficient_view_bytes);
}

const Program = @import("../word16_execution/program.zig").Program;
const Setup = @import("../word16_execution/setup.zig");
const Rom = @import("../word16_execution/rom_source.zig").Source;
const X = @import("stwo_riscv_frontend").rv64_air.word16_execution;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;

test "retired ROM tuples preserve sparse full64 addresses invalid entries edges and padding" {
    var program = try Program.init(a, .{ .base = 4096, .words = &.{ 0x00000463, 0, 0x0020f1b3 }, .addresses = &.{ 4096, 0x8000000000001000, std.math.maxInt(u64) - 3 } });
    defer program.deinit();
    const before = try a.dupe(M, program.fixed);
    defer a.free(before);
    const identity = program.identity;
    try program.releaseFixedWitness();
    try std.testing.expectError(error.ExecutionFixedWitnessRetired, program.releaseFixedWitness());
    for (0..program.size()) |logical| {
        const tuple = try program.tupleAt(logical);
        const p = X.layout.physical(logical, program.log_size);
        for (tuple, 0..) |value, c| try std.testing.expectEqualDeep(before[c * program.size() + p], value);
    }
    try std.testing.expectEqualDeep(identity, program.identity);
    try std.testing.expectEqual(@as(usize, 2), try program.lookup(std.math.maxInt(u64) - 3));
    try std.testing.expectError(error.UnknownExecutionPc, program.lookup(0));
    try std.testing.expectError(error.InvalidExecutionRomShape, program.tupleAt(program.size()));
}

test "retired ROM produces exact dictionaries claims and interactions including padding poles" {
    var program = try Program.init(a, .{ .base = 4096, .words = &.{ 0x00000463, 0, 0x0020f1b3 } });
    defer program.deinit();
    const counts = try a.alloc(u64, program.size());
    defer a.free(counts);
    @memset(counts, 0);
    counts[X.layout.physical(0, program.log_size)] = 3;
    var before = try Rom.init(a, &program, counts);
    defer before.deinit();
    var ch: @FieldType(X.types.Challenges, "rom") = .{ .offset = Q.fromBase(M.fromCanonical(191)), .coefficients = undefined };
    for (&ch.coefficients, 0..) |*coef, i| coef.* = Q.fromBase(M.fromCanonical(@intCast(i + 1)));
    const expected = try before.generate(ch);
    try program.releaseFixedWitness();
    var after = try Rom.init(a, &program, counts);
    defer after.deinit();
    try std.testing.expectEqualDeep(expected, try after.generate(ch));
    try std.testing.expectEqualSlices(Q, before.dictionary, after.dictionary);
    try std.testing.expectEqualSlices(M, before.interaction, after.interaction);
    try std.testing.expectError(error.ExecutionFixedWitnessRetired, after.columns(a, 0));
    var retry = try Rom.init(a, &program, counts);
    defer retry.deinit();
    var pole = ch;
    pole.offset = Q.zero(); // the mandatory padding tuple is all zero
    if (retry.generate(pole)) |_| return error.AcceptedRomPaddingPole else |_| {}
    try std.testing.expectEqual(@as(usize, 0), retry.interaction.len);
    try std.testing.expectEqualDeep(expected, try retry.generate(ch));
    counts[X.layout.physical(program.size() - 1, program.log_size)] = 1;
    try std.testing.expectError(error.ExecutionRomMassExceeded, Rom.init(a, &program, counts));
}

test "fixed retirement preflight failure is atomic and sealed leases remain valid" {
    var setup = try Setup.Setup.init(a, .{ .base = 4096, .words = &.{0x0020f1b3} }, .{ .cpu_log = 5 });
    defer setup.deinit();
    const fixed = setup.materials.cpu_fixed;
    setup.materials.cpu_fixed = fixed[0 .. fixed.len - 1];
    if (setup.releaseFixedWitness()) |_| return error.AcceptedInvalidFixedShape else |_| {}
    setup.materials.cpu_fixed = fixed;
    try std.testing.expect(!setup.materials.fixed_retired and setup.materials.program.fixed.len != 0);
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    setup.materials.allocator = failing.allocator();
    try std.testing.expectError(error.OutOfMemory, setup.releaseFixedWitness());
    setup.materials.allocator = a;
    try std.testing.expect(!setup.materials.fixed_retired);
    const root = setup.fixed_root;
    const logs = try setup.materials.logs(a, 0);
    defer a.free(logs);
    try setup.releaseFixedWitness();
    try std.testing.expectEqualDeep(root, setup.fixed_root);
    try std.testing.expectError(error.ExecutionFixedWitnessRetired, setup.materials.fixedColumns(a));
    const actual_logs = try setup.materials.logs(a, 0);
    defer a.free(actual_logs);
    try std.testing.expectEqualSlices(u32, logs, actual_logs);
    var scheme = try Setup.T.Scheme.init(a, Setup.T.P.config());
    defer scheme.deinit(a);
    var channel = Setup.T.P.Channel{};
    try setup.appendFixed(a, &scheme, &channel);
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    try std.testing.expectEqualDeep(root.value, roots.items[0]);
}

test "mixed execution proof bytes and independent verifier remain exact after fixed retirement" {
    const Fixture = @import("../tests/rv64_word16_execution_fixture.zig").Fixture;
    const E = @import("../word16_execution/execution.zig");
    const Memory = @import("../word16_execution/memory/statement.zig");
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    var setup = try Setup.Setup.initWithAuthority(a, &fixture.image.authority, .{ .cpu_log = 5 });
    defer setup.deinit();
    const admission = E.Admission{ .image = Memory.fromOwner(&fixture.image), .image_identity = fixture.image.identity, .initial_pc = fixture.image.initial_pc, .initial_registers = fixture.image.initial_registers };
    var original = try E.prove(a, &setup, admission, fixture.boundary, &fixture.tape, null);
    defer original.deinit(a);
    try setup.releaseFixedWitness();
    var actual = try E.prove(a, &setup, admission, fixture.boundary, &fixture.tape, null);
    defer actual.deinit(a);
    try std.testing.expectEqualSlices(u8, original.bytes, actual.bytes);
    try std.testing.expectEqualDeep(original.claims, actual.claims);
    var fresh = try Setup.Setup.initWithAuthority(a, &fixture.image.authority, .{ .cpu_log = 5 });
    defer fresh.deinit();
    try fresh.releaseFixedWitness();
    try E.verify(a, &fresh, admission, actual);
}

test "combined service setup retirement releases bridge matrices and preserves key ownership" {
    const R = @import("../word16_global_execution/services/roster.zig");
    var setup = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &.{0x00108093} }, .{ .cpu_log = 5 }, .{ .keccak = 5 });
    defer setup.deinit();
    const root = setup.key.root;
    const coefficients = setup.key.tree.coefficients.?[0].coefficients().ptr;
    try std.testing.expect(setup.fixed[0].len != 0);
    try setup.releaseFixedWitness();
    try std.testing.expectEqualDeep(root, setup.key.root);
    try std.testing.expectEqual(coefficients, setup.key.tree.coefficients.?[0].coefficients().ptr);
    for (setup.fixed) |f| try std.testing.expectEqual(@as(usize, 0), f.len);
    try std.testing.expectError(error.ExecutionFixedWitnessRetired, setup.fixedColumns(a));
    try std.testing.expectError(error.ExecutionFixedWitnessRetired, setup.releaseFixedWitness());
}

test "retired ROM allocation failures preserve retry and cleanup" {
    var program = try Program.init(a, .{ .base = 4096, .words = &.{0x0020f1b3} });
    defer program.deinit();
    try program.releaseFixedWitness();
    const counts = try a.alloc(u64, program.size());
    defer a.free(counts);
    @memset(counts, 0);
    counts[X.layout.physical(0, program.log_size)] = 1;
    const Runner = struct {
        fn run(allocator: std.mem.Allocator, p: *const Program, cs: []const u64) !void {
            var source = try Rom.init(allocator, p, cs);
            defer source.deinit();
            _ = try source.generate(.{ .offset = Q.one(), .coefficients = @splat(Q.zero()) });
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{ &program, counts });
}

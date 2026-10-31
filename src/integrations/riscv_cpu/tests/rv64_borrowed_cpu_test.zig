const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const CPU = @import("../rv64_keccak_cpu.zig");
const Full = @import("../rv64_full.zig");
const Fixture = @import("rv64_ethereum_fixture.zig");
const a = std.testing.allocator;
test "CPU borrowed main is exact and metadata survives release of its outer arena" {
    const fixture = try Fixture.Fixture.create(a, .ethereum_services_v2);
    defer fixture.deinit();
    var public = fixture.public;
    public.statement.cells = &.{};
    public.statement.memory_clocks = &.{};
    var setup = try CPU.PreparedMaterials.init(a, public);
    defer setup.deinit();
    var tape = try rv.compact_tape.Tape.init(a, Fixture.program.len, Fixture.pc, 1 << 40, .ethereum_services_v2);
    defer tape.deinit();
    var ki: usize = 0;
    var si: usize = 0;
    for (fixture.records) |record| {
        if (record.opcode == .ECALL) {
            if (record.rhs.toInt() == rv.execution_profile.KECCAK_TAG) {
                var call = fixture.kcalls[ki];
                call.clock += tape.initial_clock;
                try tape.appendService(call);
                ki += 1;
            } else {
                var call = fixture.scalls[si];
                call.clock += tape.initial_clock;
                try tape.appendSecp(call);
                si += 1;
            }
        } else {
            var row = record;
            row.clock += tape.initial_clock;
            try tape.append(row);
        }
    }
    const boundary = Full.Trace.PrivateBoundary{ .cells = fixture.public.statement.cells, .memory_clocks = fixture.public.statement.memory_clocks };
    var owned = try Full.Trace.initWithPrivateTape(a, &tape, 1, .{ 1, 1 }, public.statement, boundary, &setup.base.program, &setup.base.plan);
    defer owned.deinit();
    const width = setup.base.plan.main_count + air.full.frame.width(.ethereum_services_v2);
    const matrix = try a.alloc(@import("stwo_core").fields.m31.M31, width * owned.domainSize());
    var matrix_owned = true;
    defer if (matrix_owned) a.free(matrix);
    var borrowed = try Full.Trace.initWithPrivateTapeBorrowedMain(a, &tape, 1, .{ 1, 1 }, public.statement, boundary, &setup.base.program, &setup.base.plan, matrix);
    defer borrowed.deinit();
    try std.testing.expect(borrowed.borrowed_main);
    try std.testing.expectEqual(@as(usize, 0), borrowed.main_backing.len);
    try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, owned.main, borrowed.main);
    try std.testing.expectEqualSlices(u8, owned.lookup_metadata, borrowed.lookup_metadata);
    try std.testing.expectEqualDeep(owned.state_metadata, borrowed.state_metadata);
    try std.testing.expectError(error.BorrowedRv64MainCannotTransfer, borrowed.takeMainForCommit(a, &.{}));
    try owned.releaseMain();
    try borrowed.releaseMain();
    a.free(matrix);
    matrix_owned = false;
    tape.clearRetainingCapacity();
    var channel = air.protocol.Channel{};
    const ch = Full.Support.challenges(&channel, &setup.base);
    const first = try owned.generateInteraction(ch);
    const second = try borrowed.generateInteraction(ch);
    try std.testing.expectEqualDeep(first, second);
    try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, owned.interaction, borrowed.interaction);
    try std.testing.expectError(error.InvalidRv64FullMainPhase, borrowed.releaseMain());
}

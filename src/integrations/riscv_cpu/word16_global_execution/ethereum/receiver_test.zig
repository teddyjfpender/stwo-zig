const std = @import("std");
const F = @import("terminal_fixture.zig");
const Program = @import("../../word16_execution/program.zig").Program;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Memory = @import("../../word16_execution/memory/statement.zig");
const Driver = @import("../../word16_execution/driver.zig");
const C = @import("../services/collector.zig");
const E = @import("../services/execution.zig");
const P = @import("../services/protocol.zig");
const Keys = @import("keys.zig");
const Receiver = @import("receiver.zig");
const a = std.testing.allocator;
test "combined physical receiver requires authenticated Ethereum completion and rejects proof corruption" {
    for ([_]F.Mode{ .honest, .wrong_halt, .wrong_length, .wrong_output, .early }) |mode| {
        var f = try F.Fixture.init(a, mode);
        defer f.deinit();
        var program = try Program.initWithAuthority(a, &f.image.authority);
        defer program.deinit();
        var native = try Native.captureForCombinedServicesLEv2(a, &program, f.boundary, 1, 5, &f.tape, .{});
        defer native.deinit();
        var advice = try C.collect(a, &.{&native}, &.{&f.tape}, Memory.fromOwner(&f.image));
        defer advice.deinit();
        var keys = try Keys.Owner.init(a, &f.image, &.{.{ .geometry = .{ .cpu_log = 5 }, .bridges = .{} }}, &.{});
        defer keys.deinit();
        const expected = P.Expected{ .admission = Driver.admission(&f.image), .program_identity = program.identity, .total_steps = f.boundary.steps, .max_total_steps = 32, .final_pc = f.boundary.final_pc, .final_registers = f.boundary.final_registers };
        var bundle = try E.produce(a, keys.cpus, keys.truths, &.{&native}, &advice, expected);
        defer bundle.deinit(a);
        // An early prefix is valid under prefix-only acceptance, never completion.
        try std.testing.expectEqual(@as(?[43]u8, null), try Receiver.verify(a, &f.image, &keys, &bundle, 32, 32, false));
        const result = Receiver.verify(a, &f.image, &keys, &bundle, 32, 32, true);
        switch (mode) {
            .honest => {
                try std.testing.expectEqualSlices(u8, &f.image.expected_output, &(try result).?);
                const saved = bundle.cpus[0].bytes[0];
                bundle.cpus[0].bytes[0] ^= 1;
                if (Receiver.verify(a, &f.image, &keys, &bundle, 32, 32, true)) |_| return error.AcceptedCorruptPhysicalProof else |_| {}
                bundle.cpus[0].bytes[0] = saved;
            },
            .wrong_halt => try std.testing.expectError(error.EthereumHaltNotSet, result),
            .wrong_length => try std.testing.expectError(error.EthereumOutputLengthMismatch, result),
            .wrong_output => try std.testing.expectError(error.EthereumOutputMismatch, result),
            .early => if (result) |_| return error.AcceptedEarlyPrefix else |_| {},
        }
    }
}

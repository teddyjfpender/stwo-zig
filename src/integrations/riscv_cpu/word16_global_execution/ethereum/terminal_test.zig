const std = @import("std");
const E = @import("../../word16_execution/execution.zig");
const Setup = @import("../../word16_execution/setup.zig").Setup;
const Driver = @import("../../word16_execution/driver.zig");
const Terminal = @import("terminal.zig");
const F = @import("terminal_fixture.zig");
const a = std.testing.allocator;
test "actual valid execution proofs require independently expected PC halt length and43byte RAM output" {
    for ([_]F.Mode{ .honest, .wrong_halt, .wrong_length, .wrong_output, .early }) |mode| {
        var f = try F.Fixture.init(a, mode);
        defer f.deinit();
        var setup = try Setup.initWithAuthority(a, &f.image.authority, .{ .cpu_log = 5 });
        defer setup.deinit();
        var proof = try E.prove(a, &setup, Driver.admission(&f.image), f.boundary, &f.tape, null);
        defer proof.deinit(a);
        var fresh = try Setup.initWithAuthority(a, &f.image.authority, .{ .cpu_log = 5 });
        defer fresh.deinit();
        try E.verify(a, &fresh, Driver.admission(&f.image), proof);
        // Every false completion is still a VALID ordinary execution prefix.
        const result = Terminal.require(&f.image, proof.request.cpu, proof.request.memory.terminal);
        switch (mode) {
            .honest => try std.testing.expectEqualSlices(u8, &f.image.expected_output, &(try result)),
            .wrong_halt => try std.testing.expectError(error.EthereumHaltNotSet, result),
            .wrong_length => try std.testing.expectError(error.EthereumOutputLengthMismatch, result),
            .wrong_output => try std.testing.expectError(error.EthereumOutputMismatch, result),
            .early => try std.testing.expectError(error.EthereumTerminalPcMismatch, result),
        }
    }
}

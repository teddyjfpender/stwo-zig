const std = @import("std");
const F = @import("terminal_fixture.zig");
const Program = @import("../../word16_execution/program.zig").Program;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Memory = @import("../../word16_execution/memory/statement.zig");
const Driver = @import("../../word16_execution/driver.zig");
const Collector = @import("../services/collector.zig");
const Coordinator = @import("../services/gkr_local/coordinator.zig");
const Config = @import("../services/gkr_local/coordinator_fixture.zig").config;
const P = @import("../services/protocol.zig");
const Keys = @import("keys.zig");
const Receiver = @import("gkr_receiver.zig");
const Admission = @import("receiver.zig");
const a = std.testing.allocator;
test "wide GKR Ethereum receiver authenticates terminal RAM and never promotes prefix completion" {
    const Fixed = @import("../services/gkr_local/fixed_authority.zig").Fixed;
    const FixedSet = @import("../services/gkr_local/fixed_authority_set.zig").Set;
    const Candidate = @import("../../word16_execution/om31_security_candidate.zig");
    for ([_]bool{ false, true }) |candidate| {
        const config = if (candidate) Candidate.config() else try Config();
        for ([_]F.Mode{ .honest, .wrong_halt, .wrong_length, .wrong_output, .early }) |mode| {
            var f = try F.Fixture.init(a, mode);
            defer f.deinit();
            var program = try Program.initWithAuthority(a, &f.image.authority);
            defer program.deinit();
            var native = try Native.captureForCombinedServicesLEv2(a, &program, f.boundary, 1, 5, &f.tape, .{});
            defer native.deinit();
            var advice = try Collector.collect(a, &.{&native}, &.{&f.tape}, Memory.fromOwner(&f.image));
            defer advice.deinit();
            const declarations = &.{@import("../services/wire.zig").CpuDeclaration{ .geometry = .{ .cpu_log = 5 }, .bridges = .{} }};
            var keys = try Keys.Owner.init(a, &f.image, declarations, &.{});
            defer keys.deinit();
            var cache: ?Fixed.Cache = if (candidate) try Fixed.Cache.init(a, 1 << 30) else null;
            defer if (cache) |*owner| owner.deinit();
            var authority: ?FixedSet = if (cache) |*owner| try FixedSet.init(a, owner, keys.cpus, keys.truths, config) else null;
            defer if (authority) |*owner| owner.deinit();
            const expected = P.Expected{ .admission = Driver.admission(&f.image), .program_identity = program.identity, .total_steps = f.boundary.steps, .max_total_steps = 32, .final_pc = f.boundary.final_pc, .final_registers = f.boundary.final_registers };
            var bundle = try Coordinator.produceWithAuthority(a, keys.cpus, keys.truths, &.{&native}, &advice, expected, config, .{ .gkr_budget = 2 << 30 }, if (authority) |*owner| owner else null);
            defer bundle.deinit(a);
            // Rebuild trusted image-based setup; neither the producer's admitted key
            // nor its claimed final endpoint supplies receiver authority.
            var fresh = try Keys.Owner.init(a, &f.image, declarations, &.{});
            defer fresh.deinit();
            var fresh_cache: ?Fixed.Cache = if (candidate) try Fixed.Cache.init(a, 1 << 30) else null;
            defer if (fresh_cache) |*owner| owner.deinit();
            var fresh_authority: ?FixedSet = if (fresh_cache) |*owner| try FixedSet.init(a, owner, fresh.cpus, fresh.truths, config) else null;
            defer if (fresh_authority) |*owner| owner.deinit();
            try std.testing.expectEqual(@as(?[43]u8, null), try Receiver.verifyWithAuthority(a, &f.image, &fresh, &bundle, 32, 32, false, config, if (fresh_authority) |*owner| owner else null));
            const result = Receiver.verifyWithAuthority(a, &f.image, &fresh, &bundle, 32, 32, true, config, if (fresh_authority) |*owner| owner else null);
            switch (mode) {
                .honest => {
                    try std.testing.expectEqualSlices(u8, &f.image.expected_output, &(try result).?);
                    bundle.requests[0].base.cpu.initial_pc += 4;
                    try std.testing.expectError(error.UntrustedEthereumGenesis, Admission.expectedFromRequests(&f.image, program.identity, bundle.requests, 32, 32, true));
                    bundle.requests[0].base.cpu.initial_pc -= 4;
                    bundle.cpus[0].bytes[0] ^= 1;
                    if (Receiver.verifyWithAuthority(a, &f.image, &fresh, &bundle, 32, 32, true, config, if (fresh_authority) |*owner| owner else null)) |_| return error.AcceptedCorruptWidePhysicalProof else |_| {}
                    bundle.cpus[0].bytes[0] ^= 1;
                },
                .wrong_halt => try std.testing.expectError(error.EthereumHaltNotSet, result),
                .wrong_length => try std.testing.expectError(error.EthereumOutputLengthMismatch, result),
                .wrong_output => try std.testing.expectError(error.EthereumOutputMismatch, result),
                .early => try std.testing.expectError(error.EthereumTerminalPcMismatch, result),
            }
        }
    }
}

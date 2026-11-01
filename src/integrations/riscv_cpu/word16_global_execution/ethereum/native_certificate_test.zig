const std = @import("std");
const NativeCertificate = @import("native_certificate.zig");
const F = @import("terminal_fixture.zig");
const Program = @import("../../word16_execution/program.zig").Program;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Memory = @import("../../word16_execution/memory/statement.zig");
const Driver = @import("../../word16_execution/driver.zig");
const Collector = @import("../services/collector.zig");
const E = @import("../services/execution.zig");
const P = @import("../services/protocol.zig");
const Keys = @import("keys.zig");
const a = std.testing.allocator;

test "complete native Word16 Ethereum certificate binds real proof, trusted image and exact 43-byte output" {
    var f = try F.Fixture.init(a, .honest);
    defer f.deinit();
    var program = try Program.initWithAuthority(a, &f.image.authority);
    defer program.deinit();
    var native = try Native.captureForCombinedServicesLEv2(a, &program, f.boundary, 1, 5, &f.tape, .{});
    defer native.deinit();
    var advice = try Collector.collect(a, &.{&native}, &.{&f.tape}, Memory.fromOwner(&f.image));
    defer advice.deinit();
    var keys = try Keys.Owner.init(a, &f.image, &.{.{ .geometry = .{ .cpu_log = 5 }, .bridges = .{} }}, &.{});
    defer keys.deinit();
    const expected = P.Expected{ .admission = Driver.admission(&f.image), .program_identity = program.identity, .total_steps = f.boundary.steps, .max_total_steps = 32, .final_pc = f.boundary.final_pc, .final_registers = f.boundary.final_registers };
    var bundle = try E.produce(a, keys.cpus, keys.truths, &.{&native}, &advice, expected);
    defer bundle.deinit(a);

    const got = try NativeCertificate.verifyAndCommit(a, &f.image, &keys, &bundle, 32, 32);
    try std.testing.expectEqualSlices(u8, &f.image.expected_output, &got.output);
    try std.testing.expect(!NativeCertificate.Certificate.recursively_verified);
    try std.testing.expectEqual(@as(u32, 1), got.native.cpu_proofs);
    try std.testing.expectEqual(@as(u32, 0), got.native.truth_proofs);
    _ = try NativeCertificate.verifyPinned(a, &f.image, &keys, &bundle, 32, 32, got.digest);

    var altered = got.digest;
    altered[0] ^= 1;
    try std.testing.expectError(error.EthereumNativeCertificateMismatch, NativeCertificate.verifyPinned(a, &f.image, &keys, &bundle, 32, 32, altered));
    const saved_output = f.image.expected_output[0];
    f.image.expected_output[0] ^= 1;
    if (NativeCertificate.verifyAndCommit(a, &f.image, &keys, &bundle, 32, 32)) |_|
        return error.AcceptedDifferentOutput
    else |_| {}
    f.image.expected_output[0] = saved_output;
    const saved = bundle.cpus[0].bytes[0];
    bundle.cpus[0].bytes[0] ^= 1;
    if (NativeCertificate.verifyAndCommit(a, &f.image, &keys, &bundle, 32, 32)) |_|
        return error.AcceptedCorruptEthereumProof
    else |_| {}
    bundle.cpus[0].bytes[0] = saved;
    _ = try NativeCertificate.verifyPinned(a, &f.image, &keys, &bundle, 32, 32, got.digest);
}

test "complete native Word16 certificate refuses valid execution prefixes with false terminal statements" {
    for ([_]F.Mode{ .wrong_halt, .wrong_length, .wrong_output, .early }) |mode| {
        var f = try F.Fixture.init(a, mode);
        defer f.deinit();
        var program = try Program.initWithAuthority(a, &f.image.authority);
        defer program.deinit();
        var native = try Native.captureForCombinedServicesLEv2(a, &program, f.boundary, 1, 5, &f.tape, .{});
        defer native.deinit();
        var advice = try Collector.collect(a, &.{&native}, &.{&f.tape}, Memory.fromOwner(&f.image));
        defer advice.deinit();
        var keys = try Keys.Owner.init(a, &f.image, &.{.{ .geometry = .{ .cpu_log = 5 }, .bridges = .{} }}, &.{});
        defer keys.deinit();
        const expected = P.Expected{ .admission = Driver.admission(&f.image), .program_identity = program.identity, .total_steps = f.boundary.steps, .max_total_steps = 32, .final_pc = f.boundary.final_pc, .final_registers = f.boundary.final_registers };
        var bundle = try E.produce(a, keys.cpus, keys.truths, &.{&native}, &advice, expected);
        defer bundle.deinit(a);
        if (NativeCertificate.verifyAndCommit(a, &f.image, &keys, &bundle, 32, 32)) |_|
            return error.AcceptedFalseTerminalStatement
        else |_| {}
    }
}

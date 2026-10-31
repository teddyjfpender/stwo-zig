const std = @import("std");
const E = @import("execution.zig");
const W = @import("stage1_worker.zig").Stage1Worker;
const P = @import("protocol.zig");
const S = @import("../word16_execution/sources.zig").Source;
const Setup = @import("../word16_execution/setup.zig").Setup;
const Memory = @import("../word16_execution/memory/statement.zig");
const Fixture = @import("../tests/rv64_word16_execution_fixture.zig").Fixture;
const a = std.testing.allocator;
fn expected(f: *const Fixture, setup: *const Setup) P.Expected {
    return .{ .admission = .{ .image = Memory.fromOwner(&f.image), .image_identity = f.image.identity, .initial_pc = f.image.initial_pc, .initial_registers = f.image.initial_registers }, .program_identity = setup.materials.program.identity, .total_steps = f.boundary.steps, .max_total_steps = f.boundary.steps, .final_pc = f.boundary.final_pc, .final_registers = f.boundary.final_registers };
}
test "Owned worker seals MAIN before root-only manifest and rejects context changes before FS resume" {
    var f = try Fixture.init(a);
    defer f.deinit();
    var setup = try Setup.initWithAuthority(a, &f.image.authority, .{ .cpu_log = 5 });
    defer setup.deinit();
    const source = try S.init(a, &setup.materials, Memory.fromOwner(&f.image), f.boundary, 1, &f.tape);
    var worker = try W.init(a, &setup, source, expected(&f, &setup), 0, 0);
    defer worker.deinit();
    var empty = try P.Manifest.init(a, &.{@splat(0)}, &.{.{ .fixed = .{ .bytes = @splat(0) }, .main = .{ .bytes = @splat(0) } }});
    defer empty.deinit();
    try std.testing.expectError(error.InvalidGlobalWorkerPhase, worker.complete(&empty));
    const sealed = try worker.seal();
    try std.testing.expectEqual(W.Phase.sealed, worker.phase);
    try std.testing.expectEqual(@as(usize, 0), worker.source.?.cpu.main.len);
    try std.testing.expectEqual(@as(usize, 0), worker.source.?.memory.ls.main.len);
    try std.testing.expect(worker.source.?.cpu.metadata.len != 0);
    try std.testing.expectError(error.InvalidGlobalWorkerPhase, worker.seal());
    var manifest = try W.manifestFromSeals(a, &.{sealed});
    defer manifest.deinit();
    var wrong_root = sealed;
    wrong_root.roots.main.bytes[0] ^= 1;
    var wrong = try W.manifestFromSeals(a, &.{wrong_root});
    defer wrong.deinit();
    const before = worker.channel.digestBytes();
    try std.testing.expectError(error.GlobalStage1RootMismatch, worker.complete(&wrong));
    try std.testing.expectEqualSlices(u8, &before, &worker.channel.digestBytes());
    try std.testing.expectEqual(W.Phase.sealed, worker.phase);
    var encoded = try worker.complete(&manifest);
    defer encoded.deinit(a);
    try std.testing.expectEqual(W.Phase.completed, worker.phase);
    try std.testing.expect(worker.source == null and !worker.owns_scheme);
    try std.testing.expectError(error.InvalidGlobalWorkerPhase, worker.complete(&manifest));
    var proofs = [_]E.Encoded{encoded};
    const bundle = E.Bundle{ .manifest = manifest, .proofs = &proofs };
    var fresh = try Setup.initWithAuthority(a, &f.image.authority, .{ .cpu_log = 5 });
    defer fresh.deinit();
    try E.verify(a, &.{&fresh}, expected(&f, &fresh), &bundle);
    var wrong_ordinal = sealed;
    wrong_ordinal.ordinal = 1;
    try std.testing.expectError(error.GlobalExecutionInventoryMismatch, W.manifestFromSeals(a, &.{wrong_ordinal}));
}
test "Worker failed seal publishes no descriptor and drains single-owner allocation failures" {
    var f = try Fixture.init(a);
    defer f.deinit();
    var setup = try Setup.initWithAuthority(a, &f.image.authority, .{ .cpu_log = 5 });
    defer setup.deinit();
    var failures: usize = 0;
    for (0..8) |index| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = std.math.maxInt(usize) });
        const source = try S.init(failing.allocator(), &setup.materials, Memory.fromOwner(&f.image), f.boundary, 1, &f.tape);
        failing.fail_index = failing.alloc_index + index;
        var worker = W.init(failing.allocator(), &setup, source, expected(&f, &setup), 0, 0) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failures += 1;
            continue;
        };
        if (worker.seal()) |_| {} else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(W.Phase.failed, worker.phase);
            try std.testing.expect(worker.sealed == null);
            try std.testing.expectError(error.InvalidGlobalWorkerPhase, worker.complete(&undefined));
            failures += 1;
        }
        worker.deinit();
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
    try std.testing.expect(failures != 0);
}

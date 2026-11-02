const std = @import("std");
const E = @import("execution.zig");
const W = @import("stage1_worker.zig").Stage1Worker;
const Store = @import("retained_main_store.zig").Store;
const P = @import("protocol.zig");
const S = @import("../word16_execution/sources.zig").Source;
const Setup = @import("../word16_execution/setup.zig").Setup;
const Memory = @import("../word16_execution/memory/statement.zig");
const Fixture = @import("../tests/rv64_word16_execution_fixture.zig").Fixture;
const a = std.testing.allocator;
fn expected(f: *const Fixture, setup: *const Setup) P.Expected {
    return .{ .admission = .{ .image = Memory.fromOwner(&f.image), .image_identity = f.image.identity, .initial_pc = f.image.initial_pc, .initial_registers = f.image.initial_registers }, .program_identity = setup.materials.program.identity, .total_steps = f.boundary.steps, .max_total_steps = f.boundary.steps, .final_pc = f.boundary.final_pc, .final_registers = f.boundary.final_registers };
}
const Result = struct { bytes: []u8, claims: P.Old.Claims, roots: P.Receipt, manifest: [32]u8 };
fn run(store: ?*Store) !Result {
    var f = try Fixture.init(a);
    defer f.deinit();
    var setup = try Setup.initWithAuthority(a, &f.image.authority, .{ .cpu_log = 5 });
    defer setup.deinit();
    const source = try S.init(a, &setup.materials, Memory.fromOwner(&f.image), f.boundary, 1, &f.tape);
    var worker = try W.init(a, &setup, source, expected(&f, &setup), 0, 0);
    defer worker.deinit();
    const sealed = try worker.seal();
    if (store) |backing| {
        const before = worker.channel.digestBytes();
        const bytes = try worker.spillSealedMain(backing);
        try std.testing.expect(bytes > 0);
        try std.testing.expectEqualSlices(u8, &before, &worker.channel.digestBytes());
        try std.testing.expectEqual(W.Phase.sealed, worker.phase);
        try std.testing.expectEqual(bytes, backing.stats().live_bytes);
        try std.testing.expectError(error.UnsupportedRetainedMainTree, worker.spillSealedMain(backing));
    }
    var manifest = try W.manifestFromSeals(a, &.{sealed});
    defer manifest.deinit();
    var encoded = try worker.complete(&manifest);
    defer encoded.deinit(a);
    var proofs = [_]E.Encoded{encoded};
    const bundle = E.Bundle{ .manifest = manifest, .proofs = &proofs };
    var fresh = try Setup.initWithAuthority(a, &f.image.authority, .{ .cpu_log = 5 });
    defer fresh.deinit();
    try E.verify(a, &.{&fresh}, expected(&f, &fresh), &bundle);
    return .{ .bytes = try a.dupe(u8, encoded.bytes), .claims = encoded.claims, .roots = sealed.roots, .manifest = manifest.digest };
}
test "file-retained compact MAIN preserves complete global proof roots claims and fresh verification" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.init(path, 64 * 1024 * 1024);
    defer store.deinit();
    const ordinary = try run(null);
    defer a.free(ordinary.bytes);
    const mapped = try run(&store);
    defer a.free(mapped.bytes);
    try std.testing.expectEqualSlices(u8, ordinary.bytes, mapped.bytes);
    try std.testing.expectEqualDeep(ordinary.claims, mapped.claims);
    try std.testing.expectEqualDeep(ordinary.roots, mapped.roots);
    try std.testing.expectEqualDeep(ordinary.manifest, mapped.manifest);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expect(store.stats().total_bytes > 0);
    try std.testing.expectEqual(@as(usize, 0), store.backing.live_bytes.load(.acquire));
    var entries = tmp.dir.iterate();
    try std.testing.expectEqual(null, try entries.next());
}
test "retained MAIN budget failure preserves every coefficient and FS state for ordinary completion" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.init(path, 1);
    defer store.deinit();
    var f = try Fixture.init(a);
    defer f.deinit();
    var setup = try Setup.initWithAuthority(a, &f.image.authority, .{ .cpu_log = 5 });
    defer setup.deinit();
    const source = try S.init(a, &setup.materials, Memory.fromOwner(&f.image), f.boundary, 1, &f.tape);
    var worker = try W.init(a, &setup, source, expected(&f, &setup), 0, 0);
    defer worker.deinit();
    const sealed = try worker.seal();
    const before = worker.channel.digestBytes();
    const coefficients = worker.scheme.trees.items[1].coefficients.?;
    const pointer = coefficients[0].coeffs.ptr;
    try std.testing.expectError(error.RetainedMainBudgetExceeded, worker.spillSealedMain(&store));
    try std.testing.expectEqual(pointer, coefficients[0].coeffs.ptr);
    try std.testing.expectEqualSlices(u8, &before, &worker.channel.digestBytes());
    try std.testing.expectEqual(W.Phase.sealed, worker.phase);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.backing.total_bytes.load(.acquire));
    var manifest = try W.manifestFromSeals(a, &.{sealed});
    defer manifest.deinit();
    var encoded = try worker.complete(&manifest);
    defer encoded.deinit(a);
    var proofs = [_]E.Encoded{encoded};
    const bundle = E.Bundle{ .manifest = manifest, .proofs = &proofs };
    try E.verify(a, &.{&setup}, expected(&f, &setup), &bundle);
}

test "abandoned sealed file-backed worker releases its mappings without a completed proof" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.init(path, 64 * 1024 * 1024);
    defer store.deinit();
    var f = try Fixture.init(a);
    defer f.deinit();
    var setup = try Setup.initWithAuthority(a, &f.image.authority, .{ .cpu_log = 5 });
    defer setup.deinit();
    {
        const source = try S.init(a, &setup.materials, Memory.fromOwner(&f.image), f.boundary, 1, &f.tape);
        var worker = try W.init(a, &setup, source, expected(&f, &setup), 0, 0);
        defer worker.deinit();
        _ = try worker.seal();
        _ = try worker.spillSealedMain(&store);
        try std.testing.expect(store.backing.live_bytes.load(.acquire) > 0);
    }
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.backing.live_bytes.load(.acquire));
    var entries = tmp.dir.iterate();
    try std.testing.expectEqual(null, try entries.next());
}
test "spill owner allocation failure returns its reserved budget before a successful retry" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.init(path, 64 * 1024 * 1024);
    defer store.deinit();
    var f = try Fixture.init(a);
    defer f.deinit();
    var setup = try Setup.initWithAuthority(a, &f.image.authority, .{ .cpu_log = 5 });
    defer setup.deinit();
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = std.math.maxInt(usize) });
    const source = try S.init(failing.allocator(), &setup.materials, Memory.fromOwner(&f.image), f.boundary, 1, &f.tape);
    var worker = try W.init(failing.allocator(), &setup, source, expected(&f, &setup), 0, 0);
    defer worker.deinit();
    _ = try worker.seal();
    const digest = worker.channel.digestBytes();
    const pointer = worker.scheme.trees.items[1].coefficients.?[0].coeffs.ptr;
    failing.fail_index = failing.alloc_index;
    // Directly reach the spill transaction; worker root inspection itself
    // allocates and would otherwise consume the injected failure first.
    try std.testing.expectError(error.OutOfMemory, store.spill(failing.allocator(), &worker.scheme.trees.items[1]));
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.backing.total_bytes.load(.acquire));
    try std.testing.expectEqual(pointer, worker.scheme.trees.items[1].coefficients.?[0].coeffs.ptr);
    try std.testing.expectEqualSlices(u8, &digest, &worker.channel.digestBytes());
    failing.fail_index = std.math.maxInt(usize);
    _ = try worker.spillSealedMain(&store);
}

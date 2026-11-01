const std = @import("std");
const engine = @import("stwo_prover_engine");
const M = @import("stwo_core").fields.m31.M31;
const P = @import("protocol.zig");
const Store = @import("retained_main_store.zig").Store;
const F = @import("services/fixture.zig");
const E = @import("services/execution.zig");
const a = std.testing.allocator;
fn scheme(allocator: std.mem.Allocator) !P.T.Scheme {
    var out = try P.T.Scheme.init(allocator, P.T.P.config());
    errdefer out.deinit(allocator);
    out.setCompactPolynomialStorage(5);
    var values: [2][32]M = undefined;
    for (&values, 0..) |*row, c| for (row, 0..) |*v, i| {
        v.* = M.fromCanonical(@intCast(9 * i * i + c * 17));
    };
    var columns: [2]engine.pcs.ColumnEvaluation = undefined;
    for (&columns, &values) |*column, *row| column.* = .{ .values = row, .log_size = 5 };
    var ch = P.T.P.Channel{};
    try out.commitBorrowedStreaming(allocator, &columns, 8, &ch);
    return out;
}
fn pathFor(tmp: anytype) ![]u8 {
    return tmp.dir.realpathAlloc(a, ".");
}
fn emptyDirectory(dir: std.fs.Dir) !void {
    var it = dir.iterate();
    try std.testing.expectEqual(null, try it.next());
}
fn assertParked(tree: *P.T.Scheme.CommittedTree) !void {
    for (tree.coefficients.?, tree.columns) |coefficient, column| {
        try std.testing.expectEqual(@as(usize, 0), coefficient.coeffs.len);
        try std.testing.expectEqual(@as(usize, 0), column.coefficient_values.?.len);
        try std.testing.expect(!coefficient.owns_coeffs);
    }
}
test "Parked native MAIN has no mapped or readable payload until a read-only restore" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try pathFor(tmp);
    defer a.free(path);
    var store = try Store.initParked(path, 64 << 20);
    defer store.deinit();
    var s = try scheme(a);
    var owns = true;
    defer if (owns) s.deinit(a);
    const root = s.trees.items[0].root();
    const first = try a.dupe(M, s.trees.items[0].coefficients.?[0].coeffs);
    defer a.free(first);
    const bytes = try store.spill(a, &s.trees.items[0]);
    try assertParked(&s.trees.items[0]);
    try std.testing.expectEqual(root, s.trees.items[0].root());
    try std.testing.expectEqual(bytes, store.stats().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.backing.live_bytes.load(.acquire));
    try std.testing.expectError(error.InvalidLength, s.polynomials(a));
    try emptyDirectory(tmp.dir);
    try std.testing.expectEqual(bytes, try store.restore(&s.trees.items[0]));
    try std.testing.expectEqualSlices(M, first, s.trees.items[0].coefficients.?[0].coeffs);
    try std.testing.expectEqual(s.trees.items[0].coefficients.?[0].coeffs.ptr, s.trees.items[0].columns[0].coefficient_values.?.ptr);
    try std.testing.expectEqual(bytes, store.stats().live_mapped_bytes);
    try std.testing.expectEqual(bytes, store.stats().peak_mapped_bytes);
    try std.testing.expectEqual(@as(usize, 0), try store.restore(&s.trees.items[0]));
    s.deinit(a);
    owns = false;
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
    try emptyDirectory(tmp.dir);
}
fn foreignRelease(_: ?*anyopaque, _: u64) void {}
test "Parked restore rejects foreign callbacks contexts stores and late shape tampering before mapping" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try pathFor(tmp);
    defer a.free(path);
    var store = try Store.initParked(path, 64 << 20);
    defer store.deinit();
    var foreign = try Store.initParked(path, 64 << 20);
    defer foreign.deinit();
    var foreign_mapped = try Store.init(path, 64 << 20);
    defer foreign_mapped.deinit();
    var s = try scheme(a);
    defer s.deinit(a);
    const tree = &s.trees.items[0];
    try std.testing.expectError(error.MissingRetainedMainOwner, store.restore(tree));
    _ = try store.spill(a, tree);
    try std.testing.expectError(error.ForeignRetainedMainOwner, foreign.restore(tree));
    try std.testing.expectError(error.ForeignRetainedMainOwner, foreign_mapped.restore(tree));
    const token = tree.backing_teardown.?;
    defer tree.backing_teardown = token;
    tree.backing_teardown.?.release_fn = foreignRelease;
    tree.backing_teardown.?.context = @ptrFromInt(1);
    try std.testing.expectError(error.ForeignRetainedMainOwner, store.restore(tree));
    tree.backing_teardown = token;
    tree.backing_teardown.?.context = @ptrFromInt(1);
    try std.testing.expectError(error.ForeignRetainedMainOwner, store.restore(tree));
    tree.backing_teardown = token;
    tree.backing_teardown.?.value += 1;
    try std.testing.expectError(error.RetainedMainShapeMismatch, store.restore(tree));
    tree.backing_teardown = token;
    tree.coefficients.?[1].log_size += 1;
    try std.testing.expectError(error.RetainedMainShapeMismatch, store.restore(tree));
    tree.coefficients.?[1].log_size -= 1;
    tree.columns[1].log_size += 1;
    try std.testing.expectError(error.RetainedMainShapeMismatch, store.restore(tree));
    tree.columns[1].log_size -= 1;
    try assertParked(tree);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
    _ = try store.restore(tree);
}
test "Abandoned parked owner closes its unlinked FD without ever mapping" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try pathFor(tmp);
    defer a.free(path);
    var store = try Store.initParked(path, 64 << 20);
    defer store.deinit();
    {
        var s = try scheme(a);
        defer s.deinit(a);
        _ = try store.spill(a, &s.trees.items[0]);
    }
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.stats().peak_mapped_bytes);
    try std.testing.expect(store.parking.head == null);
    try emptyDirectory(tmp.dir);
}
test "Parking allocation failures and disk-cap refusal preserve original coefficients for retry" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try pathFor(tmp);
    defer a.free(path);
    var limited = try Store.initParked(path, 1);
    defer limited.deinit();
    var store = try Store.initParked(path, 64 << 20);
    defer store.deinit();
    for (0..2) |fail| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = std.math.maxInt(usize) });
        var s = try scheme(failing.allocator());
        defer s.deinit(failing.allocator());
        const tree = &s.trees.items[0];
        const pointer = tree.coefficients.?[0].coeffs.ptr;
        const root = tree.root();
        try std.testing.expectError(error.RetainedMainBudgetExceeded, limited.spill(failing.allocator(), tree));
        failing.fail_index = failing.alloc_index + fail;
        try std.testing.expectError(error.OutOfMemory, store.spill(failing.allocator(), tree));
        try std.testing.expectEqual(pointer, tree.coefficients.?[0].coeffs.ptr);
        try std.testing.expectEqual(root, tree.root());
        try std.testing.expect(tree.backing_teardown == null);
        try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
        try std.testing.expect(store.parking.head == null);
        failing.fail_index = std.math.maxInt(usize);
        _ = try store.spill(failing.allocator(), tree);
        _ = try store.restore(tree);
    }
    try emptyDirectory(tmp.dir);
}
test "Reserved file helper rejects impossible lengths and preserves exact native data across remapping" {
    const Reserved = engine.file_backed_allocator.ReservedFile;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try std.testing.expectError(error.InvalidMappingLength, Reserved.init(tmp.dir, 0));
    try std.testing.expectError(error.Overflow, Reserved.init(tmp.dir, std.math.maxInt(usize)));
    var file = try Reserved.init(tmp.dir, 4097);
    var owns_file = true;
    defer if (owns_file) file.deinit();
    const memory = try file.map(false);
    @memset(memory, 0xa5);
    try std.posix.msync(memory, std.posix.MSF.SYNC);
    std.posix.munmap(memory);
    try file.file.setEndPos(file.size + 1);
    try std.testing.expectError(error.ReservedFileLengthMismatch, file.map(true));
    try file.file.setEndPos(file.size);
    {
        const restored = try file.map(true);
        defer std.posix.munmap(restored);
        try std.testing.expect(std.mem.allEqual(u8, restored, 0xa5));
    }
    const fd = file.file.handle;
    file.deinit();
    owns_file = false;
    const closed = std.posix.system.fcntl(fd, std.posix.F.GETFD, @as(usize, 0));
    try std.testing.expectEqual(std.posix.E.BADF, std.posix.errno(closed));
    try emptyDirectory(tmp.dir);
}
fn equalBundles(left: *const E.Bundle, right: *const E.Bundle) !void {
    try std.testing.expectEqualDeep(left.manifest.roots, right.manifest.roots);
    try std.testing.expectEqualDeep(left.manifest.specs, right.manifest.specs);
    try std.testing.expectEqualDeep(left.manifest.digest, right.manifest.digest);
    for (left.cpus, right.cpus) |l, r| {
        try std.testing.expectEqualDeep(l.request, r.request);
        try std.testing.expectEqualDeep(l.claims, r.claims);
        try std.testing.expectEqualSlices(u8, l.bytes, r.bytes);
    }
    for (left.truths, right.truths) |l, r| {
        try std.testing.expectEqualDeep(l.claims, r.claims);
        try std.testing.expectEqualSlices(u8, l.bytes, r.bytes);
    }
}
test "Parked mixed CPU Keccak ADD DOUBLE q70 bundles match every byte and fresh receiver at one and two lanes" {
    var c = try F.Case.init(a);
    defer c.deinit();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try pathFor(tmp);
    defer a.free(path);
    var store = try Store.initParked(path, 128 << 20);
    defer store.deinit();
    for ([_]u8{ 1, 2 }) |lanes| {
        var captured = try F.Captured.init(a);
        defer captured.deinit();
        var candidate = try E.produceWithOptions(a, &c.keys(), &c.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, c.expected(), .{ .retained_main = &store, .schedule = .{ .lanes = lanes, .workers_per_lane = 2 } });
        defer candidate.deinit(a);
        try equalBundles(&c.bundle, &candidate);
        var wire_tmp = std.testing.tmpDir(.{});
        defer wire_tmp.cleanup();
        var old_dir = try wire_tmp.dir.makeOpenPath("old", .{});
        defer old_dir.close();
        var new_dir = try wire_tmp.dir.makeOpenPath("parked", .{});
        defer new_dir.close();
        const Wire = @import("services/wire.zig");
        try Wire.write(a, old_dir, &c.keys(), &c.truths(), &c.bundle);
        try Wire.write(a, new_dir, &c.keys(), &c.truths(), &candidate);
        for ([_][]const u8{ "bundle.json", "cells.bin", "cpu-0.bin", "cpu-1.bin", "truth-0.bin", "truth-1.bin", "truth-2.bin" }) |name| {
            const old = try old_dir.readFileAlloc(a, name, 16 << 20);
            defer a.free(old);
            const new = try new_dir.readFileAlloc(a, name, 16 << 20);
            defer a.free(new);
            try std.testing.expectEqualSlices(u8, old, new);
        }
        // Independent expected setup / pristine image projection.
        var fresh = try F.Case.init(a);
        defer fresh.deinit();
        try E.verify(a, &fresh.keys(), &fresh.truths(), fresh.expected(), &candidate);
        try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
        try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
    }
    try std.testing.expect(store.stats().peak_mapped_bytes > 0);
    try std.testing.expect(store.stats().peak_mapped_bytes < store.stats().peak_reserved_bytes);
    try emptyDirectory(tmp.dir);
}

test "Partially parked stage1 inventory drains all FDs when the next worker exceeds disk budget" {
    var c = try F.Case.init(a);
    defer c.deinit();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try pathFor(tmp);
    defer a.free(path);
    const logs = try c.keys()[0].logs(a, 1);
    defer a.free(logs);
    var bytes: usize = 0;
    for (logs) |log| bytes += (@as(usize, 1) << @intCast(log)) * @sizeOf(M);
    const cap = try engine.file_backed_allocator.ReservedFile.roundedLength(bytes);
    var store = try Store.initParked(path, cap);
    defer store.deinit();
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    try std.testing.expectError(error.RetainedMainBudgetExceeded, E.produceWithOptions(a, &c.keys(), &c.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, c.expected(), .{ .retained_main = &store, .schedule = .{ .lanes = 2, .workers_per_lane = 2 } }));
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
    try std.testing.expectEqual(cap, store.stats().total_bytes);
    try std.testing.expect(store.parking.head == null);
    try emptyDirectory(tmp.dir);
}

test "Retained native alias preflight preserves every owner before file creation" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try pathFor(tmp);
    defer a.free(path);
    var store = try Store.initParked(path, 64 << 20);
    defer store.deinit();
    var s = try scheme(a);
    defer s.deinit(a);
    const tree = &s.trees.items[0];
    const saved = tree.coefficients.?[1];
    const view = tree.columns[1].coefficient_values;
    tree.coefficients.?[1] = tree.coefficients.?[0];
    tree.columns[1].coefficient_values = tree.columns[0].coefficient_values;
    const attempt = store.spill(a, tree);
    tree.coefficients.?[1] = saved;
    tree.columns[1].coefficient_values = view;
    try std.testing.expectError(error.UnsupportedRetainedMainAlias, attempt);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expect(tree.backing_teardown == null);
    try emptyDirectory(tmp.dir);
}

test "Parked metadata retains the original managed allocator until final tree teardown" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try pathFor(tmp);
    defer a.free(path);
    var store = try Store.initParked(path, 64 << 20);
    defer store.deinit();
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 16 << 20);
    var owns_budget = true;
    defer if (owns_budget) budget.destroy();
    const allocator = budget.allocator();
    var s = try scheme(allocator);
    var owns_scheme = true;
    defer if (owns_scheme) s.deinit(allocator);
    _ = try store.spill(allocator, &s.trees.items[0]);
    var tree = s.trees.pop().?;
    defer tree.deinit(allocator);
    // The caller still owns unrelated Scheme container allocations. Retire
    // that shell first; the detached tree must retain its own allocator lease.
    s.deinit(allocator);
    owns_scheme = false;
    budget.destroy();
    owns_budget = false;
    _ = try store.restore(&tree);
    try std.testing.expectEqual(@as(usize, 32), tree.coefficients.?[0].coeffs.len);
}

test "FD creation failure returns disk reservation and leaves native values retryable" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try pathFor(tmp);
    defer a.free(path);
    var store = try Store.initParked(path, 64 << 20);
    defer store.deinit();
    var non_directory = try tmp.dir.createFile("not-dir", .{});
    defer non_directory.close();
    var s = try scheme(a);
    defer s.deinit(a);
    const pointer = s.trees.items[0].coefficients.?[0].coeffs.ptr;
    const dir = store.backing.dir;
    store.backing.dir = .{ .fd = non_directory.handle };
    const attempt = store.spill(a, &s.trees.items[0]);
    store.backing.dir = dir;
    try std.testing.expectError(error.NotDir, attempt);
    try std.testing.expectEqual(pointer, s.trees.items[0].coefficients.?[0].coeffs.ptr);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expect(store.parking.head == null);
    _ = try store.spill(a, &s.trees.items[0]);
    _ = try store.restore(&s.trees.items[0]);
}

test "FileBackedAllocator default mapped delegation retains realloc and alignment behavior" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try pathFor(tmp);
    defer a.free(path);
    var backing = try engine.file_backed_allocator.FileBackedAllocator.init(path);
    defer backing.deinit();
    const allocator = backing.allocator();
    try std.testing.expectEqual(null, allocator.rawAlloc(16, .fromByteUnits(std.heap.pageSize() * 2), @returnAddress()));
    var data = try allocator.alloc(u32, 1025);
    var owns = true;
    defer if (owns) allocator.free(data);
    for (data, 0..) |*value, i| value.* = @intCast(i * 13);
    data = try allocator.realloc(data, 32769);
    for (data[0..1025], 0..) |value, i| try std.testing.expectEqual(@as(u32, @intCast(i * 13)), value);
    allocator.free(data);
    owns = false;
    try std.testing.expectEqual(@as(usize, 0), backing.live_bytes.load(.acquire));
    try emptyDirectory(tmp.dir);
}
fn oldProof(store: ?*Store) ![]u8 {
    const Fixture = @import("../tests/rv64_word16_execution_fixture.zig").Fixture;
    const Setup = @import("../word16_execution/setup.zig").Setup;
    const Source = @import("../word16_execution/sources.zig").Source;
    const Memory = @import("../word16_execution/memory/statement.zig");
    const Worker = @import("stage1_worker.zig").Stage1Worker;
    const Old = @import("execution.zig");
    var f = try Fixture.init(a);
    defer f.deinit();
    var setup = try Setup.initWithAuthority(a, &f.image.authority, .{ .cpu_log = 5 });
    defer setup.deinit();
    const expected = P.Expected{ .admission = .{ .image = Memory.fromOwner(&f.image), .image_identity = f.image.identity, .initial_pc = f.image.initial_pc, .initial_registers = f.image.initial_registers }, .program_identity = setup.materials.program.identity, .total_steps = f.boundary.steps, .max_total_steps = f.boundary.steps, .final_pc = f.boundary.final_pc, .final_registers = f.boundary.final_registers };
    const source = try Source.init(a, &setup.materials, Memory.fromOwner(&f.image), f.boundary, 1, &f.tape);
    var worker = try Worker.init(a, &setup, source, expected, 0, 0);
    defer worker.deinit();
    const sealed = try worker.seal();
    if (store) |owner| {
        _ = try worker.spillSealedMain(owner);
        try assertParked(&worker.scheme.trees.items[1]);
        try std.testing.expectEqualDeep(sealed.roots.main.bytes, worker.scheme.trees.items[1].root());
    }
    var manifest = try Worker.manifestFromSeals(a, &.{sealed});
    defer manifest.deinit();
    var proof = try worker.complete(&manifest);
    defer proof.deinit(a);
    var proofs = [_]Old.Encoded{proof};
    const bundle = Old.Bundle{ .manifest = manifest, .proofs = &proofs };
    var fresh = try Setup.initWithAuthority(a, &f.image.authority, .{ .cpu_log = 5 });
    defer fresh.deinit();
    try Old.verify(a, &.{&fresh}, expected, &bundle);
    return a.dupe(u8, proof.bytes);
}
test "Original Stage1Worker also restores parked MAIN only after interaction commitment" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try pathFor(tmp);
    defer a.free(path);
    var store = try Store.initParked(path, 64 << 20);
    defer store.deinit();
    const normal = try oldProof(null);
    defer a.free(normal);
    const parked = try oldProof(&store);
    defer a.free(parked);
    try std.testing.expectEqualSlices(u8, normal, parked);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try emptyDirectory(tmp.dir);
}

test "Failed parked remapping preserves empty sentinels and FD custody for exact retry" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try pathFor(tmp);
    defer a.free(path);
    var store = try Store.initParked(path, 64 << 20);
    defer store.deinit();
    var s = try scheme(a);
    defer s.deinit(a);
    const tree = &s.trees.items[0];
    const values = try a.dupe(M, tree.coefficients.?[0].coeffs);
    defer a.free(values);
    _ = try store.spill(a, tree);
    const owner = store.parking.head.?;
    try owner.file.file.setEndPos(owner.file.size + 1);
    try std.testing.expectError(error.ReservedFileLengthMismatch, store.restore(tree));
    try assertParked(tree);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
    try std.testing.expectEqual(owner.file.size, store.stats().live_bytes);
    // Restore the original length without altering any coefficient byte.
    try owner.file.file.setEndPos(owner.file.size);
    _ = try store.restore(tree);
    try std.testing.expectEqualSlices(M, values, tree.coefficients.?[0].coeffs);
}

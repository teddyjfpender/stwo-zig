//! Genuine independent admission and ownership only; no accepted proof.
const std = @import("std");
const Pairs = @import("block_v5_caller_recursive_admission_pair_v1.zig");
const CatalogModule = @import("block_v5_caller_recursive_admission_catalog_v1.zig");
const Pipeline = @import("block_v5_caller_recursive_pipeline_v1.zig");
const Session = Pipeline.ForBackend(@import("stwo_cpu_backend").CpuBackend).Session;
const Original = @import("block_v5_caller_capture_unit_test.zig").Fixture;
const Sparse = @import("block_v5_recursive_execution_leaf_store_test_v1.zig").Fixture;
fn callerSink(_: *anyopaque, _: u32, _: *@import("block_v5_precompile_family_proof_v1.zig").Proof) !void {
    return error.UnexpectedProofInvocation;
}
fn baseFusedSink(_: *anyopaque, _: u32, _: *@import("block_v5_caller_fused_proof_v1.zig").Proof) !void {
    return error.UnexpectedProofInvocation;
}
fn arithmeticSink(_: *anyopaque, _: u32, _: *@import("block_v5_caller_arithmetic_recursive_stage_v1.zig").Artifact) !void {
    return error.UnexpectedProofInvocation;
}
fn recursiveFusedSink(_: *anyopaque, _: u32, _: *@import("block_v5_caller_fused_recursive_stage_v1.zig").Artifact) !void {
    return error.UnexpectedProofInvocation;
}
const options = Pipeline.ForBackend(@import("stwo_cpu_backend").CpuBackend).Options{
    .arithmetic = .{ .profile = .diagnostic_q8_pow0 },
    .fused = .{ .profile = .diagnostic_q8_pow0 },
};
fn borrow(a: std.mem.Allocator, pair: *Pairs.Pair, context: *u8) !Session {
    return Session.initBorrowed(a, pair, .{ .context = context, .put_caller = callerSink, .put_fused = baseFusedSink }, .{ .arithmetic = .{ .context = context, .put_caller_arithmetic = arithmeticSink }, .fused = .{ .context = context, .put_caller_fused = recursiveFusedSink } }, options);
}
fn sessionLifetime(a: std.mem.Allocator, fixture: *const Original) !void {
    const pair = try Pairs.Pair.create(a, 0, fixture.pin(), fixture.sealed, fixture.pins, &fixture.entries, .{});
    defer pair.deinit();
    const original_logs = pair.arithmetic.logs[0].ptr;
    const original_schedule = pair.fused.schedule.main.ptr;
    var context: u8 = 0;
    {
        var first = try borrow(a, pair, &context);
        defer first.deinit();
        var second = try borrow(a, pair, &context);
        defer second.deinit();
        try std.testing.expectEqual(@as(usize, 2), pair.sessions);
        try std.testing.expect(first.arithmetic == &pair.arithmetic and second.fused == &pair.fused);
        try std.testing.expect(!first.owns_admissions and !second.owns_admissions);
        try std.testing.expectEqual(original_logs, first.arithmetic.logs[0].ptr);
        try std.testing.expectError(error.IncompleteRecursiveCallerPublication, first.requireFinished());
    }
    try std.testing.expectEqual(@as(usize, 0), pair.sessions);
    try std.testing.expectEqual(original_logs, pair.arithmetic.logs[0].ptr);
    try std.testing.expectEqual(original_schedule, pair.fused.schedule.main.ptr);
    // This is exactly the policy later borrowed by a durable store/receiver.
    try pair.require();
}
fn allocationBoundaries(a: std.mem.Allocator, comptime exercise: anytype, fixture: anytype) !void {
    // Original admission AIR constructors already have exhaustive fault gates.
    // Replaying every internal IR allocation here makes a new owner test
    // quadratic in that unrelated work. Check new owner/partial-owner and
    // final admission-validation failures using the genuine production bodies.
    var census = std.testing.FailingAllocator.init(a, .{});
    try exercise(census.allocator(), fixture);
    try std.testing.expect(census.alloc_index > 3);
    const indices = [_]usize{ 0, 1, 2, census.alloc_index - 1 };
    for (indices) |index| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = index });
        try std.testing.expectError(error.OutOfMemory, exercise(failing.allocator(), fixture));
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}
test "caller admission ownership: overlapping sessions share stable original policies and later validation survives teardown" {
    const fixture = try Original.init(std.testing.allocator);
    try sessionLifetime(std.testing.allocator, &fixture);
}
test "caller admission ownership: pair owner and final borrowed-session validation allocation faults release geometry and leases" {
    const fixture = try Original.init(std.testing.allocator);
    try allocationBoundaries(std.testing.allocator, sessionLifetime, &fixture);
}
fn ownedLifetime(a: std.mem.Allocator, fixture: *const Original) !void {
    var context: u8 = 0;
    var session = try Session.init(a, 0, fixture.pin(), fixture.sealed, fixture.pins, &fixture.entries, .{ .context = &context, .put_caller = callerSink, .put_fused = baseFusedSink }, .{ .arithmetic = .{ .context = &context, .put_caller_arithmetic = arithmeticSink }, .fused = .{ .context = &context, .put_caller_fused = recursiveFusedSink } }, options);
    defer session.deinit();
    try std.testing.expect(session.owns_admissions);
    try std.testing.expectEqual(@as(usize, 1), session.admissions.sessions);
    try std.testing.expect(session.arithmetic == &session.admissions.arithmetic and session.fused == &session.admissions.fused);
}
test "caller admission ownership: original private session retains stable pair custody and unwinds owner allocation boundaries" {
    const fixture = try Original.init(std.testing.allocator);
    try ownedLifetime(std.testing.allocator, &fixture);
    try allocationBoundaries(std.testing.allocator, ownedLifetime, &fixture);
}
test "caller admission ownership: changed pair linkage limits and security reject without taking a lease" {
    const a = std.testing.allocator;
    const fixture = try Original.init(a);
    const pair = try Pairs.Pair.create(a, 0, fixture.pin(), fixture.sealed, fixture.pins, &fixture.entries, .{});
    defer pair.deinit();
    var context: u8 = 0;
    pair.arithmetic.binding.execution_index = 7;
    try std.testing.expectError(error.MixedRecursiveCallerAdmissions, borrow(a, pair, &context));
    pair.arithmetic.binding.execution_index = 0;
    var changed = options;
    changed.fused_limits.max_capture_bytes -= 1;
    const base = @import("block_v5_caller_pipeline_v1.zig").Sink{ .context = &context, .put_caller = callerSink, .put_fused = baseFusedSink };
    const recursive = Pipeline.Sinks{ .arithmetic = .{ .context = &context, .put_caller_arithmetic = arithmeticSink }, .fused = .{ .context = &context, .put_caller_fused = recursiveFusedSink } };
    try std.testing.expectError(error.UntrustedRecursiveCallerAdmissionOwner, Session.initBorrowed(a, pair, base, recursive, changed));
    changed = options;
    changed.fused.profile = .csp_q70_pow26;
    try std.testing.expectError(error.MixedRecursiveCallerSecurity, Session.initBorrowed(a, pair, base, recursive, changed));
    try std.testing.expectEqual(@as(usize, 0), pair.sessions);
}
fn sparseCatalog(a: std.mem.Allocator, fixture: *const Sparse) !void {
    const sources = [_]?Pairs.Pin{ null, null, fixture.caller.pin() };
    var catalog = try CatalogModule.Catalog.init(a, fixture.roster(), &sources, .{});
    defer catalog.deinit();
    try std.testing.expectEqual(@as(usize, 1), catalog.entries.len);
    const pair = try catalog.get(2);
    try std.testing.expectEqual(@as(u32, 2), pair.arithmetic.binding.execution_index);
    try std.testing.expectEqual(@as(u32, 2), pair.fused.binding.execution_index);
    try std.testing.expectError(error.UnadmittedRecursiveCallerIndex, catalog.get(0));
    try std.testing.expectError(error.UnadmittedRecursiveCallerIndex, catalog.get(3));
    var context: u8 = 0;
    var session = try borrow(a, pair, &context);
    session.deinit();
    try pair.require();
}
test "caller admission ownership: exact original sparse index2 roster builds once and keeps both policies after caller teardown" {
    const fixture = try Sparse.init(std.testing.allocator);
    try sparseCatalog(std.testing.allocator, &fixture);
}
test "caller admission ownership: sparse catalog slot pair and final validation allocation faults release partial ownership" {
    const fixture = try Sparse.init(std.testing.allocator);
    try allocationBoundaries(std.testing.allocator, sparseCatalog, &fixture);
}
test "caller admission ownership: missing duplicate shifted sources and catalog caps reject exact source census" {
    const a = std.testing.allocator;
    const fixture = try Sparse.init(a);
    const roster = fixture.roster();
    var sources = [_]?Pairs.Pin{ null, null, fixture.caller.pin() };
    try std.testing.expectError(error.UntrustedRecursiveCallerSourceCensus, CatalogModule.Catalog.init(a, roster, sources[0..2], .{}));
    try std.testing.expectError(error.RecursiveCallerCatalogResourceLimit, CatalogModule.Catalog.init(a, roster, &sources, .{ .max_slot_bytes = 1 }));
    sources[2] = null;
    try std.testing.expectError(error.IncompleteRecursiveCallerSources, CatalogModule.Catalog.init(a, roster, &sources, .{}));
    sources[0] = fixture.caller.pin();
    try std.testing.expectError(error.MissingRecursiveCallerSource, CatalogModule.Catalog.init(a, roster, &sources, .{}));
    sources[2] = fixture.caller.pin();
    try std.testing.expectError(error.IncompleteRecursiveCallerSources, CatalogModule.Catalog.init(a, roster, &sources, .{}));
}

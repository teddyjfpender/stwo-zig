//! Canonical allocator-bearing FRI storage. Device handle and ownership
//! context are separate, preserving existing Metal buffer ABI bindings.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Storage = @import("stwo_backend_contracts").resident_storage.ResidentStorage;
const shared = @import("../shared_runtime.zig");
const runtime = @import("../runtime.zig");
const extent = @import("fri_budget_v1.zig");
const external = engine.shared_external_memory;
const allocation_policy = @import("fri_allocation_policy_v1.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
extern fn stwo_zig_metal_qm31_resident_to_coordinates_v1(*anyopaque, *anyopaque, *anyopaque, u32, *f64, [*]u8, usize) bool;
const Owner = struct {
    a: std.mem.Allocator,
    buffer: runtime.ResidentBuffer,
    reservation: external.Reservation,
    binding: allocation_policy.Binding,
};

fn create(a: std.mem.Allocator, count: usize, policy: allocation_policy.Policy) !*Owner {
    const binding = try allocation_policy.Binding.init(a, policy);
    var reservation = try binding.reserve(try extent.secureValues(count));
    defer reservation.deinit();
    const owner = try a.create(Owner);
    errdefer a.destroy(owner);
    var lease = try shared.acquire();
    defer lease.deinit();
    const buffer = try lease.runtime.allocateResidentBuffer(reservation.bytes);
    shared.retainResidentResource();
    owner.* = .{ .a = a, .buffer = buffer, .reservation = reservation.take(), .binding = binding };
    return owner;
}
fn destroy(context: *anyopaque, handle: *anyopaque) void {
    const owner: *Owner = @ptrCast(@alignCast(context));
    std.debug.assert(owner.buffer.handle == handle);
    var reservation = owner.reservation.take();
    const a = owner.a;
    owner.buffer.deinit();
    shared.releaseResidentResource();
    a.destroy(owner);
    reservation.deinit();
}
fn storage(owner: *Owner) Storage {
    return .{ .handle = owner.buffer.handle, .destroyFn = shared.destroyResidentBuffer, .owner_context = owner, .destroyContextFn = destroy };
}
pub fn requireStorage(a: std.mem.Allocator, value: Storage, bytes: usize) !void {
    if (value.destroyContextFn != &destroy or value.owner_context == null) return error.InvalidFriResidentOwner;
    const owner: *Owner = @ptrCast(@alignCast(value.owner_context.?));
    if (owner.buffer.handle != value.handle or owner.buffer.byte_length != bytes) return error.InvalidFriResidentOwner;
    try owner.binding.require(a, &owner.reservation, bytes);
}
pub fn requireBorrowedStorage(a: std.mem.Allocator, value: Storage, bytes: usize, policy: allocation_policy.Policy) !void {
    const requester = try allocation_policy.Binding.init(a, policy);
    if (value.destroyContextFn != &destroy or value.owner_context == null) return error.InvalidFriResidentOwner;
    const owner: *Owner = @ptrCast(@alignCast(value.owner_context.?));
    if (owner.buffer.handle != value.handle or owner.buffer.byte_length != bytes) return error.InvalidFriResidentOwner;
    try owner.binding.requireBorrowed(requester, &owner.reservation, bytes);
}
pub fn allocateSecureColumn(a: std.mem.Allocator, count: usize) !engine.secure_column.SecureColumnByCoords {
    return allocateSecureColumnWithPolicy(a, count, .require_shared_budget);
}
pub fn allocateSecureColumnWithPolicy(a: std.mem.Allocator, count: usize, policy: allocation_policy.Policy) !engine.secure_column.SecureColumnByCoords {
    const owner = try create(a, count, policy);
    errdefer destroy(owner, owner.buffer.handle);
    return columnFromOwner(owner, count, null);
}
fn columnFromOwner(owner: *Owner, count: usize, source: ?engine.secure_column.SecureColumnByCoords) !engine.secure_column.SecureColumnByCoords {
    const values: [*]M = @ptrCast(@alignCast(owner.buffer.contents));
    var columns: [4][]M = undefined;
    for (&columns, 0..) |*column, i| {
        column.* = values[i * count .. (i + 1) * count];
        if (source) |borrowed| @memcpy(column.*, borrowed.columns[i]);
    }
    return engine.secure_column.SecureColumnByCoords.initResident(columns, storage(owner));
}
/// General direct-FRI compatibility ingress. No host AIR, transform or inverse
/// preparation is performed; the caller's arrays stay borrowed and unchanged.
/// Shared-budget canonical entrypoints require existing resident ownership.
pub fn fromHostOrdinary(a: std.mem.Allocator, source: engine.secure_column.SecureColumnByCoords) !engine.secure_column.SecureColumnByCoords {
    var lengths: [4]usize = undefined;
    for (source.columns, &lengths) |column, *length| length.* = column.len;
    const count = try allocation_policy.ordinaryHostIngress(a, source.resident_storage != null, lengths);
    const owner = try create(a, count, .explicit_unbudgeted);
    errdefer destroy(owner, owner.buffer.handle);
    return columnFromOwner(owner, count, source);
}
pub fn allocateLineEvaluation(a: std.mem.Allocator, domain: core.poly.line.LineDomain) !engine.line.LineEvaluation {
    return allocateLineEvaluationWithPolicy(a, domain, .require_shared_budget);
}
pub fn allocateLineEvaluationWithPolicy(a: std.mem.Allocator, domain: core.poly.line.LineDomain, policy: allocation_policy.Policy) !engine.line.LineEvaluation {
    const owner = try create(a, domain.size(), policy);
    errdefer destroy(owner, owner.buffer.handle);
    const values: [*]Q = @ptrCast(@alignCast(owner.buffer.contents));
    return engine.line.LineEvaluation.initResident(domain, values[0..domain.size()], storage(owner));
}
pub fn secureColumnFromLine(a: std.mem.Allocator, evaluation: engine.line.LineEvaluation) !engine.secure_column.SecureColumnByCoords {
    return secureColumnFromLineWithPolicy(a, evaluation, .require_shared_budget);
}
pub fn secureColumnFromLineWithPolicy(a: std.mem.Allocator, evaluation: engine.line.LineEvaluation, policy: allocation_policy.Policy) !engine.secure_column.SecureColumnByCoords {
    _ = try allocation_policy.Binding.init(a, policy);
    try requireBorrowedStorage(a, evaluation.resident_storage orelse return error.InvalidFriResidentOwner, try extent.secureValues(evaluation.len()), policy);
    var column = try allocateSecureColumnWithPolicy(a, evaluation.len(), policy);
    errdefer column.deinit(a);
    var lease = try shared.acquire();
    defer lease.deinit();
    // Both allocations have exact MTL ownership; this dedicated binding
    // converts directly, without alias discovery or hidden host copies.
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = @splat(0);
    if (!stwo_zig_metal_qm31_resident_to_coordinates_v1(lease.runtime.handle, evaluation.resident_storage.?.handle, column.resident_storage.?.handle, @intCast(evaluation.len()), &gpu_ms, &message, message.len)) return error.FriCoordinateConversionFailed;
    return column;
}

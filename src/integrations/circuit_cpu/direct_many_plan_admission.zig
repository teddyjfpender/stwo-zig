//! Resource-safe standalone admission for future bounded multi-call profiles.
//!
//! The V4 Plan source is part of the V4 template digest and cannot be edited
//! without changing V4 proof identities. This version-2 admission API checks
//! bounded source geometry before calling that legacy Plan. It is not a new
//! proof profile or a proof-admission capability; every method revalidates.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const many = @import("private_many_boundary.zig");

const CircuitView = circuit.common.preprocessed.CircuitView;
const DirectCircuit = circuit.common.direct_arithmetic.Circuit;

pub const admission_version: u32 = 2;
pub const max_rows: usize = 1 << 16;
pub const max_vars_per_row: usize = 4;
pub const extra_vars: usize = 32;

/// Bounded before any n_vars-sized producer or multiplicity allocation. The
/// generous variable ratio admits current S31 direct circuits while rejecting
/// sparse declarations that would consume disproportionate memory.
pub fn requireResourceShape(source: CircuitView) !void {
    const rows = source.nQm31OpsRows();
    if (rows < 16 or rows > max_rows or !std.math.isPowerOfTwo(rows))
        return error.InvalidManyCircuitRows;
    if (source.n_vars < 11 or source.n_vars > max_vars_per_row * rows + extra_vars)
        return error.InvalidManyCircuitVariables;
}

/// A versioned safe façade for direct callers. Its mutable fields do not
/// confer authority: validate and preprocessed recheck the version and bounds.
pub const BoundedPlan = struct {
    version: u32 = admission_version,
    legacy: many.Plan,

    pub fn fromLegacy(plan: many.Plan) BoundedPlan {
        return .{ .legacy = plan };
    }

    pub fn validate(self: BoundedPlan, source: CircuitView, allocator: std.mem.Allocator) !void {
        if (self.version != admission_version) return error.UnsupportedManyPlanAdmissionVersion;
        try requireResourceShape(source);
        try self.legacy.validate(source, allocator);
    }

    pub fn preprocessed(self: BoundedPlan, allocator: std.mem.Allocator, source: CircuitView) !DirectCircuit {
        if (self.version != admission_version) return error.UnsupportedManyPlanAdmissionVersion;
        try requireResourceShape(source);
        return self.legacy.preprocessed(allocator, source);
    }
};

test "version-2 bounded Plan rejects sparse variables before allocating" {
    const M31 = @import("stwo_core").fields.m31.M31;
    var gates: [16]circuit.builder.circuit.BinaryGate = undefined;
    for (&gates, 0..) |*gate, id|
        gate.* = .{ .in0 = 0, .in1 = 1, .out = @intCast(3 + id) };
    var source = CircuitView{ .n_vars = 19, .add = &gates, .output = &.{18} };
    var legacy: many.Plan = .{ .count = 1 };
    legacy.calls[0] = .{
        .call_id = 0,
        .rounds = 16,
        .constant = M31.fromCanonical(7),
        .input = .{ 3, 4, 5, 6 },
        .output = .{ 7, 8, 9, 10 },
    };
    const admitted = BoundedPlan.fromLegacy(legacy);
    try admitted.validate(source, std.testing.allocator);
    var pp = try admitted.preprocessed(std.testing.allocator, source);
    defer pp.deinit(std.testing.allocator);

    // Exact 16-row budget: 4 × 16 + 32 variables are admitted, the next
    // value fails before a one-byte allocator can be touched.
    source.n_vars = max_vars_per_row * 16 + extra_vars;
    try admitted.validate(source, std.testing.allocator);
    source.n_vars += 1;
    var tiny_storage: [1]u8 = undefined;
    var tiny = std.heap.FixedBufferAllocator.init(&tiny_storage);
    try std.testing.expectError(error.InvalidManyCircuitVariables, admitted.validate(source, tiny.allocator()));
    try std.testing.expectError(error.InvalidManyCircuitVariables, admitted.preprocessed(tiny.allocator(), source));

    source.n_vars = 1 << 30;
    try std.testing.expectError(error.InvalidManyCircuitVariables, admitted.validate(source, tiny.allocator()));
    try std.testing.expectError(error.InvalidManyCircuitVariables, admitted.preprocessed(tiny.allocator(), source));
    source.add = gates[0..15];
    try std.testing.expectError(error.InvalidManyCircuitRows, admitted.validate(source, tiny.allocator()));
    try std.testing.expectError(error.InvalidManyCircuitRows, admitted.preprocessed(tiny.allocator(), source));
    var wrong_version = admitted;
    wrong_version.version += 1;
    try std.testing.expectError(error.UnsupportedManyPlanAdmissionVersion, wrong_version.validate(source, tiny.allocator()));
}

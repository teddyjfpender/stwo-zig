//! Explicit known child formats. The receiver selects CPU8 versus catalog/ML6
//! from its admitted inventory, never from proposed proof bytes or a VK packet.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const C = @import("../context.zig");
const Q = C.Q;
pub const P6 = @import("../native_omul/proof.zig");
pub const P7 = @import("outer_proof.zig");
pub const Ref = union(enum) {
    r6: *const @import("../native_omul/authority.zig").Key,
    r7: *const @import("outer_authority.zig").Key,
    pub fn identity(self: Ref) [32]u8 {
        return switch (self) {
            .r6 => |key| key.base.identity,
            .r7 => |key| key.core.base.identity,
        };
    }
    pub fn root(self: Ref) [36]u8 {
        return switch (self) {
            .r6 => |key| key.base.fixed_root,
            .r7 => |key| key.core.base.fixed_root,
        };
    }
    pub fn profile(self: Ref) @import("../op_profile.zig").Profile {
        return switch (self) {
            .r6 => |key| key.base.profile,
            .r7 => |key| key.core.base.profile,
        };
    }
    pub fn nOutputs(self: Ref) usize {
        return switch (self) {
            .r6 => |key| key.base.n_outputs,
            .r7 => |key| key.core.base.n_outputs,
        };
    }
    pub fn geometry(self: Ref, a: std.mem.Allocator) !@import("../../rv64_recursion/om31_poseidon/mod.zig").Shape {
        return switch (self) {
            .r6 => |key| @import("../native_omul/capture.zig").geometry(a, key),
            .r7 => |key| @import("capture.zig").geometry(a, key),
        };
    }
    pub fn prove(self: Ref, a: std.mem.Allocator, ctx: *const C.Context, output: []const Q, recorder: *Engine.stage_profile.Recorder) ![]u8 {
        return switch (self) {
            .r6 => |key| P6.proveProfiled(a, ctx, key, output, recorder),
            .r7 => |key| P7.proveProfiled(a, ctx, key, output, recorder),
        };
    }
    pub fn verify(self: Ref, a: std.mem.Allocator, output: []const Q, bytes: []const u8) !void {
        return switch (self) {
            .r6 => |key| P6.verify(a, key, output, bytes),
            .r7 => |key| P7.verify(a, key, output, bytes),
        };
    }
    pub fn verifyCaptured(self: Ref, a: std.mem.Allocator, output: []const Q, bytes: []const u8) !Captured {
        return switch (self) {
            .r6 => |key| .{ .r6 = try P6.verifyCaptured(a, key, output, bytes) },
            .r7 => |key| .{ .r7 = try P7.verifyCaptured(a, key, output, bytes) },
        };
    }
};
pub const Borrowed = union(enum) { r6: *const P6.Captured, r7: *const P7.Captured };
pub const Captured = union(enum) {
    r6: P6.Captured,
    r7: P7.Captured,
    pub fn deinit(self: *Captured, a: std.mem.Allocator) void {
        switch (self.*) {
            inline else => |*proof| proof.deinit(a),
        }
        self.* = undefined;
    }
    pub fn borrow(self: *const Captured) Borrowed {
        return switch (self.*) {
            .r6 => |*proof| .{ .r6 = proof },
            .r7 => |*proof| .{ .r7 = proof },
        };
    }
};

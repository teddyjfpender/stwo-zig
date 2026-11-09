//! Borrowed views of the three typed detached-source native verifiers.
//! No pointer in a view may escape its synchronous callback without ownership.
const std = @import("std");
const C = @import("../full_p2_common.zig");
const Fold = @import("../native_omul/fold.zig");
const Emit = @import("../pure_p2_source_emission.zig").Emission;
const Profile = @import("../op_profile.zig").Profile;
pub const View = union(enum) {
    cpu: @import("../sponge_cpu/leaf.zig").View,
    detached: @import("../sponge_local_gkr/leaf.zig").View,
    truth: @import("../truth_local_gkr/leaf.zig").View,
    pub fn ordinal(self: View) u32 {
        return switch (self) {
            .cpu => |v| v.expected.ordinal,
            .detached => |v| v.ordinal,
            .truth => |v| v.expected.ordinal,
        };
    }
    pub fn manifest(self: View) [36]u8 {
        return switch (self) {
            inline else => |v| v.manifest,
        };
    }
    pub fn profile(self: View) Profile {
        return switch (self) {
            .cpu => |v| v.key.profile,
            .detached => |v| v.key.profile,
            .truth => |v| v.key.base.profile,
        };
    }
    pub fn expected(self: View, a: std.mem.Allocator) !Fold.Digest {
        return switch (self) {
            inline else => |v| v.expectedOutput(a),
        };
    }
    /// Normalize every PCS shape from the concrete independently owned source
    /// key. Caller-provided masks/geometry never become key authority.
    pub fn normalized(self: View, a: std.mem.Allocator) !View {
        const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
        const shape = try a.create(V.Shape);
        return switch (self) {
            .cpu => |v| blk: {
                try v.key.require(v.setup);
                const statement = try v.key.statement(v.setup, v.request, v.first, v.span, v.expected.ordinal);
                if (v.expected.kind != .sponge_cpu or !std.mem.eql(u8, &statement, &v.expected.statement)) return error.DetachedSourceAuthority;
                if (v.values.cap_log != 0) return error.DetachedSourceCapVariant;
                shape.* = try @import("../sponge_cpu/capture.zig").geometry(a, v.setup, v.key);
                var out = v;
                out.shape = shape;
                break :blk .{ .cpu = out };
            },
            .detached => |v| blk: {
                _ = try v.key.statementDetached(v.geometry);
                if (v.values.cap_log != 0) return error.DetachedSourceCapVariant;
                shape.* = try @import("../sponge_local_gkr/capture.zig").geometry(a, v.geometry, v.key);
                var out = v;
                out.shape = shape;
                break :blk .{ .detached = out };
            },
            .truth => |v| blk: {
                try @import("../truth_local_gkr/worker.zig").validateExpected(v.key, v.truth, v.expected);
                if (v.values.cap_log != 0) return error.DetachedSourceCapVariant;
                shape.* = try @import("../truth_local_gkr/statement.zig").geometry(a, v.key, v.truth);
                var out = v;
                out.shape = shape;
                break :blk .{ .truth = out };
            },
        };
    }
    pub fn emit(self: View, a: std.mem.Allocator, ctx: *C.Context, trace_only: bool) !Emit {
        return switch (self) {
            inline else => |v| v.emitInto(a, ctx, trace_only),
        };
    }
};

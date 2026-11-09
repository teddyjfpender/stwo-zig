//! The outer format is selected by concrete receiver-owned source kind:
//! CPU uses R7; catalog and Miller use the existing qualified R6 factories.
const std = @import("std");
const Views = @import("../pure_p2_root_source_view.zig");
const Old = @import("../native_omul/topology.zig");
const New = @import("source_key.zig").SourceKey;
const Keys = @import("execution_keys.zig");
pub const Binding = Old.Binding;
pub const Leaf = union(enum) {
    cpu: New,
    service: Old.SourceLeaf,
    pub fn init(a: std.mem.Allocator, view: Views.View) !Leaf {
        return switch (view) {
            .cpu => |v| .{ .cpu = try New.initCpu(a, v) },
            .catalog => |v| .{ .service = try Old.SourceLeaf.initCatalog(a, v) },
            .local_catalog => |v| .{ .service = try Old.SourceLeaf.initLocalCatalog(a, v) },
            .miller => |v| .{ .service = try Old.SourceLeaf.initMiller(a, v) },
            .local_miller => |v| .{ .service = try Old.SourceLeaf.initLocalMiller(a, v) },
        };
    }
    pub fn deinit(self: *Leaf) void {
        switch (self.*) {
            inline else => |*value| value.deinit(),
        }
        self.* = undefined;
    }
    pub fn binding(self: *const Leaf) Binding {
        return switch (self.*) {
            .cpu => |*value| .{ .ordinal = value.binding.cpu.ordinal, .native_identity = value.binding.cpu.native_identity, .kind = .cpu },
            .service => |*value| value.binding,
        };
    }
    pub fn key(self: *const Leaf) !Keys.Ref {
        return switch (self.*) {
            .cpu => |*value| .{ .r7 = &value.authority },
            .service => |*value| .{ .r6 = try value.key() },
        };
    }
    pub fn retire(self: *Leaf) void {
        switch (self.*) {
            .cpu => |*value| @import("../native_omul/verifier_key.zig").retireProverData(&value.authority.core),
            .service => |*value| value.retireProverData(),
        }
    }
};
/// Actual assignment construction shares the native verifier emitters. Only
/// CPU changes arithmetization; service assignments remain the R6 control.
pub fn build(a: std.mem.Allocator, view: Views.View) !@import("../context.zig").Context {
    return switch (view) {
        .cpu => |v| @import("cpu_source.zig").build(a, v, false, null),
        inline else => |v| blk: {
            var scope = @import("../native_omul/scope.zig").begin();
            defer scope.deinit();
            break :blk v.buildForProving(a);
        },
    };
}
pub fn output(a: std.mem.Allocator, view: Views.View) !@import("fold.zig").Digest {
    return switch (view) {
        inline else => |v| v.expectedOutput(a),
    };
}

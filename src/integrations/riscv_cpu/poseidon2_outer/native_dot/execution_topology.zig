//! R7 canonical topology, derived solely from independently compiled source
//! leaves. No producer key, root or parent layout declaration is consumed.
const std = @import("std");
const S = @import("execution_source.zig");
const Keys = @import("execution_keys.zig");
const K = @import("outer_authority.zig").Key;
const Profile = @import("../op_profile.zig").Profile;
pub const Format = enum { r6, r7 };
pub const Topology = struct {
    allocator: std.mem.Allocator,
    execution: [32]u8,
    profile: Profile,
    bindings: []S.Binding,
    formats: []Format,
    parents: std.ArrayList(*K) = .empty,
    final: Keys.Ref,
    pub fn deinit(self: *Topology) void {
        for (self.parents.items) |key| {
            key.deinit();
            self.allocator.destroy(key);
        }
        self.parents.deinit(self.allocator);
        self.allocator.free(self.formats);
        self.allocator.free(self.bindings);
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, profile: Profile, execution: [32]u8, leaves: []const S.Leaf, verify_only: bool) !Topology {
        if (leaves.len == 0 or leaves.len > 256) return error.R7TopologyCoverage;
        const first = try leaves[0].key();
        const bindings = try a.alloc(S.Binding, leaves.len);
        errdefer a.free(bindings);
        const formats = try a.alloc(Format, leaves.len);
        var self = Topology{ .allocator = a, .execution = execution, .profile = profile, .bindings = bindings, .formats = formats, .final = first };
        // `self` owns both arrays after this point.
        errdefer {
            for (self.parents.items) |key| {
                key.deinit();
                a.destroy(key);
            }
            self.parents.deinit(a);
            a.free(formats);
        }
        const level = try a.alloc(Keys.Ref, leaves.len);
        defer a.free(level);
        for (leaves, bindings, formats, level, 0..) |*leaf, *binding, *format, *slot, i| {
            binding.* = leaf.binding();
            if (binding.ordinal != i) return error.R7TopologyOrder;
            slot.* = try leaf.key();
            if (slot.profile() != profile or slot.nOutputs() != 9) return error.R7TopologyProfile;
            format.* = switch (slot.*) {
                .r6 => .r6,
                .r7 => .r7,
            };
            if (binding.kind == .cpu) {
                if (format.* != .r7) return error.R7TopologyFormat;
            } else if (binding.kind == .catalog or binding.kind == .miller) {
                if (format.* != .r6) return error.R7TopologyFormat;
            } else return error.R7UnsupportedSourceKind;
        }
        var n = level.len;
        while (n > 1) {
            var next: usize = 0;
            var i: usize = 0;
            while (i + 1 < n) : (i += 2) {
                var trace = try (@import("fold.zig").TraceSource{ .keys = .{ level[i], level[i + 1] } }).build(a);
                defer trace.deinit();
                const key = try a.create(K);
                key.* = K.init(a, &trace, profile) catch |err| {
                    a.destroy(key);
                    return err;
                };
                self.parents.append(a, key) catch |err| {
                    key.deinit();
                    a.destroy(key);
                    return err;
                };
                if (verify_only) @import("../native_omul/verifier_key.zig").retireProverData(&key.core);
                level[next] = .{ .r7 = key };
                next += 1;
            }
            if (i < n) {
                level[next] = level[i];
                next += 1;
            }
            n = next;
        }
        self.final = level[0];
        return self;
    }
};

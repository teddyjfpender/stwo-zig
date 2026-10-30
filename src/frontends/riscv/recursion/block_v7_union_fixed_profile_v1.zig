//! Capture-free PCS geometry for a joined original proof. This is compiler
//! metadata, not an in-circuit verifier or permission to publish a recursive
//! root. All source shapes, provider equations and tree maps are reconstructed.
const std = @import("std");
const core = @import("stwo_core");
const Shape = @import("block_v6_original_fixed_shape_v1.zig");
pub fn ForMode(comptime window: bool) type {
    const Multi = @import("../prover/block_v7_multi_union_proof_v1.zig").ForMode(window);
    const Statement = @import("../prover/block_v7_multi_union_statement_v1.zig").ForMode(window);
    return struct {
        pub const Limits = struct { original: Multi.Limits, shape: Shape.Limits = .{} };
        pub const Owned = struct {
            allocator: std.mem.Allocator,
            statement: *Statement.Owned,
            shape: Shape.Owned,
            trace_count: usize,
            constraint_count: usize,
            policy: [32]u8,
            fixed_root: [32]u8,
            seal: [32]u8,
            limits: Limits,
            pub const recursive_verifier_complete = false;
            pub const Admission = struct {
                profile: *Owned,
                components: Multi.AdmittedComponents,
                pub fn deinit(self: *Admission) void {
                    self.components.deinit();
                    self.profile.deinit();
                    self.* = undefined;
                }
            };
            pub fn derive(a: std.mem.Allocator, statement: *const Statement.Owned, claims: *const Multi.Claims, limits: Limits) !*Owned {
                var admitted = try deriveAdmitted(a, statement, claims, limits);
                admitted.components.deinit();
                return admitted.profile;
            }
            /// Retain the same independently reconstructed components for an
            /// immutable compiler owner. No second source/key admission occurs.
            pub fn deriveAdmitted(a: std.mem.Allocator, statement: *const Statement.Owned, claims: *const Multi.Claims, limits: Limits) !Admission {
                const detached = try Statement.Owned.init(a, statement.trusted, statement.input);
                errdefer detached.deinit();
                var components = try Multi.AdmittedComponents.init(a, detached.trusted, detached.input, claims, limits.original);
                errdefer components.deinit();
                var scratch = std.heap.ArenaAllocator.init(a);
                defer scratch.deinit();
                const logs = try components.traceLogs(scratch.allocator());
                var shape = try Shape.Owned.initForBoundedTraceTrees(a, logs, .{ .components = components.handles(), .n_preprocessed_columns = logs[0].len }, detached.input.epoch.config, limits.shape, limits.original.max_trace_trees);
                errdefer shape.deinit();
                var count: usize = 0;
                for (components.handles()) |component| count = try std.math.add(usize, count, component.nConstraints());
                const out = try a.create(Owned);
                errdefer a.destroy(out);
                out.* = .{ .allocator = a, .statement = detached, .shape = shape, .trace_count = logs.len, .constraint_count = count, .policy = try components.scope.policy.digest(), .fixed_root = try components.fixedRoot(), .seal = undefined, .limits = limits };
                out.seal = try out.identity();
                return .{ .profile = out, .components = components };
            }
            pub fn identity(self: *const Owned) ![32]u8 {
                var ch = core.proof_suites.Blake3.Channel{};
                ch.mixU32s(&.{ if (window) 0x42375546 else 0x42374d46, 1, Multi.VERSION, @intCast(self.trace_count), @intCast(self.constraint_count) });
                ch.mixRoot(self.policy);
                ch.mixRoot(self.fixed_root);
                ch.mixRoot(self.statement.input.epoch.digest);
                ch.mixRoot(self.shape.deepProfile().identityDigest());
                ch.mixRoot(self.shape.friProfile().identityDigest());
                ch.mixU32s(&.{ self.shape.split, self.shape.composition_log, self.shape.mask_log, self.shape.lifting_log });
                for (self.statement.input.entries) |entry| entry.mix(&ch);
                for (self.shape.columns) |columns| {
                    ch.mixU64(columns.len);
                    ch.mixU32s(columns);
                }
                return ch.digestBytes();
            }
            pub fn validateAgainst(self: *const Owned, claims: *const Multi.Claims) !void {
                if (!std.meta.eql(self.seal, try self.identity())) return error.MutatedUnionFixedProfile;
                const rebuilt = try derive(self.allocator, self.statement, claims, self.limits);
                defer rebuilt.deinit();
                if (!std.meta.eql(self.seal, rebuilt.seal)) return error.UntrustedUnionFixedProfile;
            }
            pub fn deinit(self: *Owned) void {
                const a = self.allocator;
                self.shape.deinit();
                self.statement.deinit();
                a.destroy(self);
            }
        };
    };
}

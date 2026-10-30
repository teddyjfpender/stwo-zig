//! Independent original joint-memory PCS geometry. Public proposal metadata is
//! not proof authority; the caller independently selects Policy/Epoch/roster.
//! No proof capture, witness columns, successful receipt or proposed key is used.
//! Finite protocol variants share implementation; window mode is a distinct key.
pub fn ForMode(comptime window: bool) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Air = if (window) @import("../prover/block_v7_window_memory_joint_air_v1.zig") else @import("../prover/block_v7_memory_joint_air_v1.zig");
        const Layout = if (window) @import("../prover/block_v7_window_memory_joint_layout_v1.zig") else @import("../prover/block_v7_memory_joint_layout_v1.zig");
        const Protocol = if (window) @import("../prover/block_v7_window_memory_joint_protocol_v1.zig") else @import("../prover/block_v7_memory_joint_protocol_v1.zig");
        const Policy = @import("../prover/block_v7_execution_policy_v1.zig").Policy;
        const E = @import("../prover/block_v7_execution_epoch_v1.zig");
        const Geometry = @import("../prover/block_v5_ram_lanes_protocol_v1.zig");
        const Shape = @import("block_v6_original_fixed_shape_v1.zig");
        const Deep = @import("air/pcs_deep_circuit.zig");
        const Fri = @import("air/fri_verifier_circuit.zig");
        pub const Input = struct {
            policy: Policy,
            epoch: E.Epoch,
            roster: []const E.Entry,
            roots: [2][32]u8,
            interval_log: u32,
            claims: Air.Claims,
        };
        pub const Limits = struct { layout: Layout.Limits = .{}, shape: Shape.Limits = .{}, max_roster: usize = 1 << 16 };
        pub const Owned = struct {
            pub const commitment_trees = 4;
            pub const fixed_setup_only = true;
            pub const complete_family_setup = false;
            pub const complete_block_authority = false;
            backing: std.mem.Allocator,
            arena: std.heap.ArenaAllocator,
            input: Input,
            limits: Limits,
            layout: Layout.Layout,
            shape: Shape.Owned,
            trace_logs: [3][]const u32,
            config: core.pcs.PcsConfig,
            columns: [4][]const u32,
            trees: []Deep.TreeProfile,
            layouts: []@import("sample_point_layout.zig").Layout,
            mask_logs: []const u32,
            widths: []u32,
            /// Common OODS mask domain, not the expanded composition degree.
            max_log: u32,
            mask_log: u32,
            lifting_log: u32,
            composition_log: u32,
            split: u32,
            seal: [32]u8,
            pub fn derive(a: std.mem.Allocator, input: Input, limits: Limits) !*Owned {
                try input.policy.validate();
                if (window != (input.policy.window != null)) return error.MismatchedV7MemoryMode;
                if (input.roster.len == 0 or input.roster.len > limits.max_roster or input.claims.ram.len == 0 or input.claims.ram.len > limits.layout.max_shards) return error.JointFixedProfileResourceLimit;
                const result = try a.create(Owned);
                errdefer a.destroy(result);
                result.arena = std.heap.ArenaAllocator.init(a);
                errdefer result.arena.deinit();
                const temp = result.arena.allocator();
                var owned_input = input;
                owned_input.roster = try temp.dupe(E.Entry, input.roster);
                owned_input.claims.ram = try temp.dupe(Air.RamClaim, input.claims.ram);
                const geometry = try temp.alloc(Geometry.Claim, input.claims.ram.len);
                for (geometry, input.claims.ram) |*g, claim| g.* = claim.geometry;
                var layout = try Layout.Layout.init(temp, geometry, input.interval_log, limits.layout);
                errdefer layout.deinit();
                const pin = try Protocol.entry(input.policy, &layout, input.roots);
                try Protocol.requireEpoch(input.policy, input.epoch, input.roster, pin);
                const drawn = try input.epoch.draw(temp);
                _ = try Protocol.proofChannel(drawn, pin, &layout, input.claims);
                const owner = if (window) try Air.Owner.init(temp, &layout, input.claims, drawn.memory, .from(drawn.word.initial), try input.policy.window.?.nonhaltConstants()) else try Air.Owner.init(temp, &layout, input.claims, drawn.memory, try @import("../prover/block_v7_halt_algebra_v1.zig").derive(input.policy.terminal));
                defer owner.deinit();
                var logs: [3][]const u32 = undefined;
                for (&logs, 0..) |*tree, i| tree.* = try layout.logs(temp, i);
                const all = core.air.components.Components{ .components = owner.verifiers, .n_preprocessed_columns = layout.columns[0] };
                var shape = try Shape.Owned.init(temp, &logs, all, input.policy.config, limits.shape);
                errdefer shape.deinit();
                result.* = Owned{ .backing = a, .arena = result.arena, .input = owned_input, .limits = limits, .layout = layout, .shape = shape, .trace_logs = logs, .config = input.policy.config, .columns = shape.columns[0..4].*, .trees = shape.trees, .layouts = shape.layouts, .mask_logs = shape.mask_logs, .widths = shape.widths, .max_log = shape.mask_log, .mask_log = shape.mask_log, .lifting_log = shape.lifting_log, .composition_log = shape.composition_log, .split = shape.split, .seal = undefined };
                result.seal = try result.identity();
                return result;
            }
            pub fn validate(self: *const Owned) !void {
                try self.validateAgainst(self.input, self.limits);
            }
            pub fn deepProfile(self: *const Owned) Deep.Profile {
                return self.shape.deepProfile();
            }
            pub fn friProfile(self: *const Owned) Fri.Profile {
                return self.shape.friProfile();
            }
            pub fn sampleCount(self: *const Owned) !usize {
                var n: usize = 0;
                for (self.layouts) |layout| n = try std.math.add(usize, n, layout.sampleCount());
                return n;
            }
            pub fn publicCount(self: *const Owned) !usize {
                const K = if (window) @import("air/block_v7_window_memory_kernels_v1.zig") else @import("air/block_v7_memory_composition_v1.zig");
                return std.math.add(usize, try std.math.mul(usize, self.input.claims.ram.len, K.publicCount(.ram)), if (window) 4 else 5);
            }
            pub fn identity(self: *const Owned) ![32]u8 {
                var ch = core.channel.blake3.Channel{};
                ch.mixU32s(&.{ if (window) 0x42375753 else 0x42374a53, 1, commitment_trees, self.mask_log, self.lifting_log, self.composition_log, self.split });
                ch.mixRoot(try self.input.policy.digest());
                ch.mixRoot(self.input.epoch.digest);
                ch.mixRoot(self.layout.digest);
                for (self.input.roots) |root| ch.mixRoot(root);
                ch.mixRoot(self.deepProfile().identityDigest());
                ch.mixRoot(self.friProfile().identityDigest());
                return ch.digestBytes();
            }
            /// Rebuild against external independently selected policy, not a resealed
            /// received shape. Fixed graph shape does not grant public-claim authority.
            pub fn validateAgainst(self: *const Owned, input: Input, limits: Limits) !void {
                var expected = try derive(self.arena.child_allocator, input, limits);
                defer expected.deinit();
                if (!std.meta.eql(self.seal, try self.identity()) or !std.meta.eql(self.seal, expected.seal) or
                    !std.meta.eql(self.config, expected.config) or self.max_log != expected.max_log or self.mask_log != expected.mask_log or
                    self.lifting_log != expected.lifting_log or self.composition_log != expected.composition_log or self.split != expected.split or
                    self.shape.mask_log != expected.shape.mask_log or self.shape.composition_log != expected.shape.composition_log or self.shape.split != expected.shape.split or
                    self.columns.len != expected.columns.len or self.layouts.len != expected.layouts.len or self.layout.parts.len != expected.layout.parts.len)
                    return error.UntrustedJointFixedProfile;
                for (self.columns, expected.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.UntrustedJointFixedProfile;
                if (!std.mem.eql(@import("sample_point_layout.zig").Layout, self.layouts, expected.layouts) or !std.mem.eql(u32, self.mask_logs, expected.mask_logs) or !std.mem.eql(u32, self.widths, expected.widths)) return error.UntrustedJointFixedProfile;
                for (self.layout.parts, expected.layout.parts) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedJointFixedProfile;
            }
            pub fn deinit(self: *Owned) void {
                self.shape.deinit();
                self.layout.deinit();
                self.arena.deinit();
                const a = self.backing;
                a.destroy(self);
            }
        };
    };
}

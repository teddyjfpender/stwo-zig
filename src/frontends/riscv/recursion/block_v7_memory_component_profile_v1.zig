//! Explicit original RAM/interval/range16/terminal admission. These are the
//! unchanged separate Source proofs; they are never relabelled joint proofs.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const K = @import("air/block_v7_memory_composition_v1.zig");
const Source = @import("../prover/block_v7_memory_source_v1.zig");
const E = @import("../prover/block_v7_execution_epoch_v1.zig");
const Policy = @import("../prover/block_v7_execution_policy_v1.zig").Policy;
const Geometry = @import("../prover/block_v5_ram_lanes_protocol_v1.zig");
const T = @import("../prover/block_v7_memory_trace_v1.zig");
const Pcs = @import("../prover/block_v5_word_pcs_v1.zig");
const Q = core.fields.qm31.QM31;
pub fn For(comptime family: K.Family) type {
    return struct {
        const Self = @This();
        pub const Spec = K.Spec(family);
        pub const planes = K.planes(family);
        pub const epoch_family: E.Family = @field(E.Family, @tagName(family));
        pub const Shape = @import("block_v5_word_recursive_shape_v1.zig").ForSpec(Spec).Shape;
        pub const Input = struct {
            policy: Policy,
            epoch: E.Epoch,
            roster: []const E.Entry,
            index: u32,
            row_log: u32,
            roots: [2][32]u8,
            sums: [planes]Q,
            geometry: ?Geometry.Claim = null,
        };
        pub const Limits = struct {
            shape: @import("block_v5_word_recursive_shape_v1.zig").Limits = .{},
            max_roster: usize = 1 << 16,
            max_matrix_bytes: usize = 1 << 30,
        };
        pub const Owned = struct {
            allocator: std.mem.Allocator,
            input: Input,
            limits: Limits,
            shape: *Shape,
            config: core.pcs.PcsConfig,
            columns: [4][]const u32,
            widths: []const u32,
            lifting_log: u32,
            seal: [32]u8,
            pub const commitment_trees = 4;
            pub fn derive(a: std.mem.Allocator, input: Input, limits: Limits) !*Owned {
                try validateInput(a, input, limits);
                const self = try a.create(Owned);
                errdefer a.destroy(self);
                const roster = try a.dupe(E.Entry, input.roster);
                errdefer a.free(roster);
                const shape = try Shape.init(a, input.row_log, input.policy.config, limits.shape);
                errdefer shape.deinit();
                var owned = input;
                owned.roster = roster;
                self.* = .{ .allocator = a, .input = owned, .limits = limits, .shape = shape, .config = input.policy.config, .columns = .{ shape.columns[0], shape.columns[1], shape.columns[2], shape.columns[3] }, .widths = shape.widths, .lifting_log = shape.lifting_log, .seal = undefined };
                self.seal = try self.identity();
                return self;
            }
            pub fn identity(self: *const Owned) ![32]u8 {
                var ch = suite.Channel{};
                ch.mixU32s(&.{ 0x42375749, 1, @intFromEnum(epoch_family) });
                ch.mixRoot(self.input.epoch.digest);
                (try entry(self.input)).mix(&ch);
                ch.mixRoot(self.shape.identity());
                return ch.digestBytes();
            }
            pub fn validate(self: *const Owned) !void {
                try validateInput(self.allocator, self.input, self.limits);
                try self.shape.validateAgainst(self.input.row_log, self.input.policy.config);
                if (self.lifting_log != self.shape.lifting_log or !std.meta.eql(self.seal, try self.identity()) or !std.meta.eql(self.config, self.input.policy.config) or !std.mem.eql(u32, self.widths, self.shape.widths)) return error.UntrustedV7MemoryComponentProfile;
                for (self.columns, self.shape.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.UntrustedV7MemoryComponentProfile;
            }
            pub fn deepProfile(self: *const Owned) @import("air/pcs_deep_circuit.zig").Profile {
                return self.shape.deepProfile();
            }
            pub fn friProfile(self: *const Owned) @import("air/fri_verifier_circuit.zig").Profile {
                return self.shape.friProfile();
            }
            pub fn publicCount(_: *const Owned) !usize {
                return K.publicCount(family);
            }
            pub fn deinit(self: *Owned) void {
                const a = self.allocator;
                self.shape.deinit();
                a.free(self.input.roster);
                a.destroy(self);
            }
        };
        pub fn entry(input: Input) !E.Entry {
            return Source.entry(input.policy, epoch_family, input.index, input.row_log, input.roots, input.geometry);
        }
        pub fn validateInput(a: std.mem.Allocator, input: Input, limits: Limits) !void {
            if (input.row_log == 0 or input.row_log > limits.shape.max_row_log or input.row_log > 24) return error.InvalidV7MemoryComponentGeometry;
            try input.policy.validate();
            if (limits.max_roster == 0 or input.roster.len == 0 or input.roster.len > limits.max_roster or !std.meta.eql(input.epoch.statement, try input.policy.digest()) or !std.meta.eql(input.epoch.config, input.policy.config)) return error.UntrustedV7MemoryComponentPolicy;
            try input.epoch.requireCompleteFamilies();
            if (input.epoch.counts[@intFromEnum(E.Family.memory_joint)] != 0) return error.InvalidV7MemoryComponentMode;
            if (family == .ram) {
                const g = input.geometry orelse return error.InvalidV7MemoryComponentGeometry;
                try g.validate();
                if (g.row_log != input.row_log or input.index >= input.epoch.counts[@intFromEnum(E.Family.ram)]) return error.InvalidV7MemoryComponentGeometry;
                _ = try K.ramPublic(g, input.sums, try @import("../prover/block_v7_halt_algebra_v1.zig").derive(input.policy.terminal));
            } else {
                if (input.geometry != null or input.index != 0) return error.InvalidV7MemoryComponentGeometry;
                const expected_log: u32 = switch (family) {
                    .interval => try intervalLog(input.policy),
                    .range16 => 16,
                    .terminal => 4,
                    .ram => unreachable,
                };
                if (input.row_log != expected_log) return error.InvalidV7MemoryComponentGeometry;
                _ = try @import("../prover/block_v7_memory_relations_v1.zig").normalize(planes, input.sums, @as(u32, 1) << @intCast(input.row_log));
            }
            try input.epoch.requireEntry(input.roster, try entry(input));
            const drawn = try input.epoch.draw(a);
            _ = try Source.channel(&drawn, try entry(input), &input.sums);
        }
        pub fn publicInputs(a: std.mem.Allocator, profile: *const Owned) ![]Q {
            if (family == .ram) return a.dupe(Q, &(try K.ramPublic(profile.input.geometry.?, profile.input.sums, try @import("../prover/block_v7_halt_algebra_v1.zig").derive(profile.input.policy.terminal))));
            return a.dupe(Q, &profile.input.sums);
        }
        pub const VerifiedCapture = struct {
            allocator: std.mem.Allocator,
            proof: core.verifier.ProofCapture(suite.Hasher),
            final_channel: suite.Channel,
            roots: [2][32]u8,
            sums: [planes]Q,
            profile: [32]u8,
            pub fn deinit(self: *@This()) void {
                self.proof.deinit(self.allocator);
                self.* = undefined;
            }
        };
        pub fn verifyAndCapture(comptime Backend: type, a: std.mem.Allocator, profile: *const Owned, received: *const @import("../prover/block_v7_memory_bundle_v1.zig").Item(planes)) !VerifiedCapture {
            try profile.validate();
            if (!std.meta.eql(profile.input.roots, received.roots) or !std.meta.eql(profile.input.sums, received.sums)) return error.UntrustedV7MemoryComponentProof;
            var fixed = try fixedColumns(a, profile.input, profile.limits.max_matrix_bytes);
            defer fixed.deinit();
            const drawn = try profile.input.epoch.draw(a);
            const spec: Spec = if (family == .ram) .{ .claim = profile.input.geometry.?, .halt = try @import("../prover/block_v7_halt_algebra_v1.zig").derive(profile.input.policy.terminal), .sums = profile.input.sums, .challenges = drawn.memory } else .{ .sums = profile.input.sums, .challenges = drawn.memory };
            const capture = try Pcs.For(Backend, Spec).verifyCaptureBorrowed(a, &received.stark, spec, profile.input.row_log, fixed.columns(), profile.input.roots, profile.config, try Source.firstChannel(profile.input.policy, epoch_family, profile.input.index, profile.input.row_log), try Source.channel(&drawn, try entry(profile.input), &profile.input.sums));
            return .{ .allocator = a, .proof = capture.proof, .final_channel = capture.final_channel, .roots = profile.input.roots, .sums = profile.input.sums, .profile = profile.seal };
        }
        pub fn requireFixedRoot(comptime Backend: type, a: std.mem.Allocator, profile: *const Owned) !void {
            return requireFixedRootWithLimit(Backend, a, profile, profile.limits.max_matrix_bytes);
        }
        /// Receiver policy bounds the proposed profile's allocation allowance.
        /// Check before any scratch/fixed matrix allocation, including provider
        /// census arrays. This does not change the committed fixed columns.
        pub fn requireFixedRootWithLimit(comptime Backend: type, a: std.mem.Allocator, profile: *const Owned, receiver_max_matrix_bytes: usize) !void {
            const max_matrix_bytes = @min(profile.limits.max_matrix_bytes, receiver_max_matrix_bytes);
            if (profile.input.row_log == 0 or profile.input.row_log > 24) return error.InvalidV7MemoryComponentGeometry;
            const width = Spec.FIXED_COUNT + if (family == .ram) @as(usize, 0) else Spec.MAIN_COUNT;
            const cells = try std.math.mul(usize, @as(usize, 1) << @intCast(profile.input.row_log), width);
            if (try std.math.mul(usize, cells, @sizeOf(core.fields.m31.M31)) > max_matrix_bytes) return error.V7MemoryResourceLimit;
            try profile.validate();
            var fixed = try fixedColumns(a, profile.input, max_matrix_bytes);
            defer fixed.deinit();
            const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
            var scheme = try Scheme.init(a, profile.config);
            defer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.never);
            var channel = try Source.firstChannel(profile.input.policy, epoch_family, profile.input.index, profile.input.row_log);
            try scheme.commitBorrowedStreaming(a, fixed.columns(), 16, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 1 or !std.meta.eql(roots.items[0], profile.input.roots[0])) return error.UntrustedV7MemoryComponentFixedRoot;
        }
        const Fixed = struct {
            allocator: std.mem.Allocator,
            ram: ?@import("../air/block/word_memory_lanes_trace_v1.zig").FixedTrace = null,
            provider: ?T.Matrix = null,
            view: [Spec.FIXED_COUNT]Pcs.Column,
            fn columns(self: *const @This()) []const Pcs.Column {
                return &self.view;
            }
            fn deinit(self: *@This()) void {
                if (self.ram) |*r| r.deinit();
                if (self.provider) |*p| p.deinit();
            }
        };
        fn fixedColumns(a: std.mem.Allocator, input: Input, max_bytes: usize) !Fixed {
            var result = Fixed{ .allocator = a, .view = undefined };
            errdefer result.deinit();
            if (family == .ram) {
                result.ram = try @import("../air/block/word_memory_lanes_trace_v1.zig").FixedTrace.init(a, input.geometry.?, max_bytes);
                for (&result.view, 0..) |*c, i| c.* = .{ .log_size = input.row_log, .values = result.ram.?.column(i) };
            } else {
                result.provider = switch (family) {
                    .interval => blk: {
                        const counts = try a.alloc(u32, input.policy.initialized.intervals.len);
                        defer a.free(counts);
                        @memset(counts, 0);
                        break :blk try T.interval(a, input.policy.initialized, counts, max_bytes);
                    },
                    .range16 => blk: {
                        const counts = try a.alloc(u32, 65536);
                        defer a.free(counts);
                        @memset(counts, 0);
                        break :blk try T.range16(a, counts, max_bytes);
                    },
                    .terminal => try T.terminal(a, try @import("../prover/block_v7_terminal_protocol_v1.zig").Plan.init(input.policy.terminal), 0, max_bytes),
                    .ram => unreachable,
                };
                if (result.provider.?.log != input.row_log) return error.InvalidV7MemoryComponentGeometry;
                @memcpy(&result.view, result.provider.?.columns[0..Spec.FIXED_COUNT]);
            }
            return result;
        }
    };
}
fn intervalLog(policy: Policy) !u32 {
    // Same row-domain calculation as the original interval matrix constructor.
    return @max(@as(u32, 4), std.math.log2_int_ceil(usize, policy.initialized.intervals.len));
}

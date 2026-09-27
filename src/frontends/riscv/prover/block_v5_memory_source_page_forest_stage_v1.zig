//! Actual bounded PAGE forest publisher. Verifies original leaves/lower parents,
//! proves their verifier equations plus source merges, then freshly verifies the
//! result before durable publication. No whole-block authority is issued.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Bus = @import("../recursion/block_v5_memory_source_page_forest_bus_v1.zig");
const Rows = @import("../recursion/block_v5_memory_source_page_forest_preparation_v1.zig");
const Protocol = @import("../recursion/block_v5_memory_source_page_forest_protocol_v1.zig");
const Receiver = @import("../recursion/block_v5_memory_source_page_forest_receiver_v1.zig");
const Leaves = @import("../recursion/block_v5_memory_source_page_forest_leaf_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
pub const Limits = struct { max_owned_bytes: usize = 8 << 30, max_child_proof_bytes: usize = 512 << 20, transcript_capacity: u32 = 1 << 24, rows: Rows.Limits = .{} };
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const Artifact = struct {
            allocator: std.mem.Allocator,
            owner: ?*Budget,
            bytes: []u8,
            schedule: []Bus.Wire,
            key: Protocol.Key,
            expected_id: [32]u8,
            public_input: [32]u8,
            pub const complete_source_authority = false;
            pub const page_claim_byte_merges_constrained = true;
            pub fn deinit(self: *Artifact) void {
                const lease = self.owner;
                self.allocator.free(self.bytes);
                self.allocator.free(self.schedule);
                self.* = undefined;
                if (lease) |owner| owner.destroy();
            }
        };
        pub const Sink = struct { context: ?*anyopaque, put_open: *const fn (?*anyopaque, *Artifact) anyerror!void };
        pub const Template = struct {
            allocator: std.mem.Allocator,
            owner: ?*Budget,
            spec: Bus.Spec,
            pub fn deinit(self: *Template) void {
                const lease = self.owner;
                self.allocator.free(self.spec.schedule);
                self.* = undefined;
                if (lease) |owner| owner.destroy();
            }
        };
        /// The receiver independently repeats this original fresh-child path
        /// once when reconstructing the job's expected setup. Artifact keys are
        /// never inputs. This result is setup metadata, not proof authority.
        pub fn deriveTemplate(backing: std.mem.Allocator, policy: Receiver.Policy, profile: Protocol.Profile, child_bytes: []const []const u8, limits: Limits) !Template {
            try policy.public.validateSources();
            const roster = try policy.public.forest.node(policy.public.index, policy.public.expected_plan);
            if (limits.max_owned_bytes == 0 or limits.transcript_capacity == 0 or child_bytes.len != roster.child_count) return error.PageForestResourceLimit;
            for (child_bytes) |bytes| if (bytes.len == 0 or bytes.len > limits.max_child_proof_bytes) return error.PageForestResourceLimit;
            const budget = try Budget.createRetainingParent(backing, limits.max_owned_bytes);
            defer budget.destroy();
            const a = budget.allocator();
            var captures: [4]Rows.Capture = undefined;
            var made: usize = 0;
            defer for (captures[0..made]) |capture| switch (capture) {
                .raw => |fresh| @constCast(fresh).deinit(),
                .fold => |fresh| @constCast(fresh).deinit(),
                .node => |fresh| @constCast(fresh).deinit(),
            };
            for (child_bytes, roster.children[0..roster.child_count], 0..) |bytes, ref, index| {
                captures[index] = switch (ref) {
                    .leaf => |ordinal| if (ordinal < policy.public.forest.raw.len) .{ .raw = try Leaves.ForKind(.raw).verify(a, policy.public.forest.raw[ordinal], bytes) } else .{ .fold = try Leaves.ForKind(.fold).verify(a, policy.public.forest.fold[ordinal - policy.public.forest.raw.len], bytes) },
                    .node => |ordinal| block: {
                        var lower = policy;
                        lower.public.index = ordinal;
                        break :block .{ .node = try Receiver.verify(a, lower, bytes) };
                    },
                };
                made += 1;
            }
            var public = try Bus.Owner.prepareSources(a, policy.public, policy.public_limits);
            defer public.deinit();
            var rows = try Rows.prepare(a, &public, captures[0..made], limits.transcript_capacity, limits.rows);
            defer rows.deinit();
            const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, profile);
            const key = try Protocol.Key.fromGeometry(geometry, rows.wires);
            const lease = if (Budget.fromAllocator(backing)) |owner| owner.retain() else null;
            errdefer if (lease) |owner| owner.destroy();
            const schedule = try backing.dupe(Bus.Wire, rows.wires);
            errdefer backing.free(schedule);
            return .{ .allocator = backing, .owner = lease, .spec = .{ .geometry = geometry, .schedule = schedule, .expected_id = try key.identity() } };
        }
        pub fn publish(backing: std.mem.Allocator, policy: Receiver.Policy, child_bytes: []const []const u8, limits: Limits, sink: Sink) !void {
            const admitted = try Receiver.admit(policy);
            const roster = try policy.public.forest.node(policy.public.index, policy.public.expected_plan);
            if (limits.max_owned_bytes == 0 or limits.transcript_capacity == 0 or limits.max_child_proof_bytes == 0 or child_bytes.len != roster.child_count) return error.PageForestResourceLimit;
            for (child_bytes) |bytes| if (bytes.len == 0 or bytes.len > limits.max_child_proof_bytes) return error.PageForestResourceLimit;
            const budget = try Budget.createRetainingParent(backing, limits.max_owned_bytes);
            defer budget.destroy();
            const a = budget.allocator();
            var captures: [4]Rows.Capture = undefined;
            var made: usize = 0;
            defer for (captures[0..made]) |capture| switch (capture) {
                .raw => |fresh| @constCast(fresh).deinit(),
                .fold => |fresh| @constCast(fresh).deinit(),
                .node => |fresh| @constCast(fresh).deinit(),
            };
            for (child_bytes, roster.children[0..roster.child_count], 0..) |bytes, ref, index| {
                captures[index] = switch (ref) {
                    .leaf => |ordinal| if (ordinal < policy.public.forest.raw.len) .{ .raw = try Leaves.ForKind(.raw).verify(a, policy.public.forest.raw[ordinal], bytes) } else .{ .fold = try Leaves.ForKind(.fold).verify(a, policy.public.forest.fold[ordinal - policy.public.forest.raw.len], bytes) },
                    .node => |ordinal| block: {
                        var lower = policy;
                        lower.public.index = ordinal;
                        break :block .{ .node = try Receiver.verify(a, lower, bytes) };
                    },
                };
                made += 1;
            }
            var public = try Bus.init(a, policy.public, policy.public_limits);
            defer public.deinit();
            const admission = try Protocol.Admission.init(admitted.key, admitted.expected_id, admitted.schedule, .{ .public = &public });
            var rows = try Rows.prepare(a, &public, captures[0..made], limits.transcript_capacity, limits.rows);
            defer rows.deinit();
            const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, admitted.key.profile);
            const key = try Protocol.Key.fromGeometry(geometry, rows.wires);
            if (!std.meta.eql(key, admitted.key) or !std.meta.eql(try key.identity(), admitted.expected_id) or !std.meta.eql(try Bus.scheduleDigest(rows.wires), try Bus.scheduleDigest(admitted.schedule))) return error.UntrustedPageForestNode;
            const Producer = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
            const producer = try Producer.init(a, &rows.recursive.rows, admission);
            defer producer.deinit();
            var proof = try producer.prove(a, &rows.recursive.rows);
            defer proof.deinit();
            const encoded = try Parent.codec.encode(a, &proof, &admission);
            defer a.free(encoded);
            const checked = try Receiver.verify(a, policy, encoded);
            defer checked.deinit();
            const lease = if (Budget.fromAllocator(backing)) |owner| owner.retain() else null;
            errdefer if (lease) |owner| owner.destroy();
            const output = try backing.dupe(u8, encoded);
            errdefer backing.free(output);
            const schedule = try backing.dupe(Bus.Wire, rows.wires);
            errdefer backing.free(schedule);
            var artifact = Artifact{ .allocator = backing, .owner = lease, .bytes = output, .schedule = schedule, .key = key, .expected_id = admitted.expected_id, .public_input = try admission.publicInputIdentity() };
            try sink.put_open(sink.context, &artifact);
        }
    };
}

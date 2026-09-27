//! Actual publisher for one independently admitted bounded request node. Proves genuine
//! original child verification AND all exact equality rows under one key,
//! then uses the same independent final fresh receiver before publication.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Bus = @import("../recursion/block_v5_input_request_forest_bus_v1.zig");
const Rows = @import("../recursion/block_v5_input_request_forest_preparation_v1.zig");
const Protocol = @import("../recursion/block_v5_input_request_forest_protocol_v1.zig");
const Receiver = @import("../recursion/block_v5_input_request_forest_receiver_v1.zig");
const Carrier = @import("../recursion/block_v5_input_tail_receiver_v1.zig");
const Window = @import("../recursion/block_v5_tail_linked_public_windows_receiver_v2.zig");
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
            /// Only a genuine final root receiver establishes full input request
            /// coverage. This is not source/global authority.
            input_request_root: bool,
            pub const complete_source_authority = false;
            pub fn deinit(self: *Artifact) void {
                const lease = self.owner;
                self.allocator.free(self.bytes);
                self.allocator.free(self.schedule);
                self.* = undefined;
                if (lease) |owner| owner.destroy();
            }
        };
        pub const Sink = struct { context: ?*anyopaque, put_open: *const fn (?*anyopaque, *Artifact) anyerror!void };
        pub fn publish(backing: std.mem.Allocator, policy: Receiver.Policy, carrier_bytes: ?[]const u8, consumer_bytes: []const []const u8, limits: Limits, sink: Sink) !void {
            const admitted_policy = try Receiver.admit(policy);
            const node = policy.public.forest.geometry.nodes[policy.public.index];
            if (limits.max_owned_bytes == 0 or limits.transcript_capacity == 0 or limits.max_child_proof_bytes == 0 or consumer_bytes.len != node.child_count or ((node.kind == .carrier) != (carrier_bytes != null))) return error.InputRequestNodeResourceLimit;
            if (carrier_bytes) |bytes| if (bytes.len == 0 or bytes.len > limits.max_child_proof_bytes) return error.InputRequestNodeResourceLimit;
            for (consumer_bytes) |bytes| if (bytes.len == 0 or bytes.len > limits.max_child_proof_bytes) return error.InputRequestNodeResourceLimit;
            const budget = try Budget.create(backing, limits.max_owned_bytes);
            defer budget.destroy();
            const a = budget.allocator();
            const carrier = if (carrier_bytes) |bytes| try Carrier.verify(a, policy.public.carrier, bytes) else null;
            defer if (carrier) |fresh| fresh.deinit();
            const consumers = try a.alloc(Rows.Verified, consumer_bytes.len);
            defer a.free(consumers);
            var made: usize = 0;
            defer for (consumers[0..made]) |fresh| switch (fresh) {
                .leaf => |v| @constCast(v).deinit(),
                .node => |v| @constCast(v).deinit(),
            };
            for (consumers, consumer_bytes, node.children[0..node.child_count]) |*fresh, bytes, ref| {
                fresh.* = switch (ref) {
                    .leaf => |ordinal| .{ .leaf = try Window.verify(a, policy.public.forest.policies[ordinal], bytes) },
                    .node => |ordinal| block: {
                        var p = policy;
                        p.public.index = ordinal;
                        break :block .{ .node = try Receiver.verify(a, p, bytes) };
                    },
                };
                made += 1;
            }
            var public = try Bus.init(a, policy.public, policy.public_limits);
            defer public.deinit();
            const admission = try Protocol.Admission.init(admitted_policy.key, admitted_policy.expected_id, admitted_policy.schedule, .{ .public = &public });
            var rows = try Rows.prepare(a, &public, consumers, carrier, limits.transcript_capacity, limits.rows);
            defer rows.deinit();
            const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, admitted_policy.key.profile);
            const key = try Protocol.Key.fromGeometry(geometry, rows.wires);
            if (!std.meta.eql(key, admitted_policy.key) or !std.meta.eql(try key.identity(), admitted_policy.expected_id) or !std.meta.eql(try Bus.scheduleDigest(rows.wires), try Bus.scheduleDigest(admitted_policy.schedule))) return error.UntrustedInputRequestNode;
            const Producer = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
            const producer = try Producer.init(a, &rows.recursive.rows, admission);
            defer producer.deinit();
            var proof = try producer.prove(a, &rows.recursive.rows);
            defer proof.deinit();
            const encoded = try Parent.codec.encode(a, &proof, &admission);
            defer a.free(encoded);
            const checked = if (node.kind == .carrier) try Receiver.verifyRoot(a, policy, encoded) else try Receiver.verify(a, policy, encoded);
            defer checked.deinit();
            var artifact = block: {
                const lease = if (Budget.fromAllocator(backing)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                const output = try backing.dupe(u8, encoded);
                errdefer backing.free(output);
                const schedule = try backing.dupe(Bus.Wire, rows.wires);
                errdefer backing.free(schedule);
                break :block Artifact{ .allocator = backing, .owner = lease, .bytes = output, .schedule = schedule, .key = key, .expected_id = admitted_policy.expected_id, .public_input = try admission.publicInputIdentity(), .input_request_root = node.kind == .carrier };
            };
            errdefer artifact.deinit();
            // A successful sink consumes the artifact; a failed sink leaves it intact.
            try sink.put_open(sink.context, &artifact);
        }
    };
}

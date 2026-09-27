//! Actual publisher for the locally admitted carrier ancestor. Proves genuine
//! original child verification AND all exact equality rows under one key,
//! then uses the same independent final fresh receiver before publication.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Bus = @import("../recursion/block_v5_input_tail_ancestor_bus_v1.zig");
const Rows = @import("../recursion/block_v5_input_tail_ancestor_preparation_v1.zig");
const Protocol = @import("../recursion/block_v5_input_tail_ancestor_protocol_v1.zig");
const Receiver = @import("../recursion/block_v5_input_tail_ancestor_receiver_v1.zig");
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
            pub const complete_source_authority = false;
            pub const local_carrier_links_constrained = true;
            pub fn deinit(self: *Artifact) void {
                const lease = self.owner;
                self.allocator.free(self.bytes);
                self.allocator.free(self.schedule);
                self.* = undefined;
                if (lease) |owner| owner.destroy();
            }
        };
        pub const Sink = struct { context: ?*anyopaque, put_open: *const fn (?*anyopaque, *Artifact) anyerror!void };
        pub fn publish(backing: std.mem.Allocator, policy: Receiver.Policy, carrier_bytes: []const u8, consumer_bytes: []const []const u8, limits: Limits, sink: Sink) !void {
            try policy.public.validate();
            if (limits.max_owned_bytes == 0 or limits.transcript_capacity == 0 or limits.max_child_proof_bytes == 0 or consumer_bytes.len != policy.public.consumers.len or carrier_bytes.len == 0 or carrier_bytes.len > limits.max_child_proof_bytes) return error.InputTailResourceLimit;
            for (consumer_bytes) |bytes| if (bytes.len == 0 or bytes.len > limits.max_child_proof_bytes) return error.InputTailResourceLimit;
            const budget = try Budget.create(backing, limits.max_owned_bytes);
            defer budget.destroy();
            const a = budget.allocator();
            const carrier = try Carrier.verify(a, policy.public.carrier, carrier_bytes);
            defer carrier.deinit();
            const consumers = try a.alloc(*const Window.Fresh, consumer_bytes.len);
            defer a.free(consumers);
            var made: usize = 0;
            defer for (consumers[0..made]) |fresh| @constCast(fresh).deinit();
            for (consumers, consumer_bytes, policy.public.consumers) |*fresh, bytes, p| {
                fresh.* = try Window.verify(a, p, bytes);
                made += 1;
            }
            var public = try Bus.init(a, policy.public, policy.public_limits);
            defer public.deinit();
            const admission = try Protocol.Admission.init(policy.key, policy.expected_id, policy.schedule, .{ .public = &public });
            var rows = try Rows.prepare(a, &public, carrier, consumers, limits.transcript_capacity, limits.rows);
            defer rows.deinit();
            const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, policy.key.profile);
            const key = try Protocol.Key.fromGeometry(geometry, rows.wires);
            if (!std.meta.eql(key, policy.key) or !std.meta.eql(try key.identity(), policy.expected_id) or !std.meta.eql(try Bus.scheduleDigest(rows.wires), try Bus.scheduleDigest(policy.schedule))) return error.UntrustedInputTailAncestor;
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
            var artifact = Artifact{ .allocator = backing, .owner = lease, .bytes = output, .schedule = schedule, .key = key, .expected_id = policy.expected_id, .public_input = try admission.publicInputIdentity() };
            try sink.put_open(sink.context, &artifact);
        }
    };
}

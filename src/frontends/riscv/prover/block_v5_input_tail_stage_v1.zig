//! Real once-per-job tail proof production and fresh standalone verification.
//! The sink transfers the proof artifact only after genuine fresh acceptance.
const std = @import("std");
const Public = @import("../recursion/block_v5_input_tail_public_v1.zig");
const Protocol = @import("../recursion/block_v5_input_tail_protocol_v1.zig");
const Rows = @import("../recursion/air/block_v5_input_tail_rows_v1.zig");
const Receiver = @import("../recursion/block_v5_input_tail_receiver_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const Artifact = struct {
            allocator: std.mem.Allocator,
            budget: ?*Budget,
            public: *Public.Owned,
            bytes: []u8,
            key: Protocol.Key,
            expected_id: [32]u8,
            public_input: [32]u8,
            pub const complete_source_authority = false;
            pub fn deinit(self: *Artifact) void {
                const owner = self.budget;
                self.allocator.free(self.bytes);
                self.public.deinit();
                self.* = undefined;
                if (owner) |budget| budget.destroy();
            }
        };
        pub const Sink = struct { context: ?*anyopaque, put_input_tail: *const fn (?*anyopaque, *Artifact) anyerror!void };
        pub fn publish(a: std.mem.Allocator, policy: Receiver.Policy, limits: Rows.Limits, sink: Sink) !void {
            const admitted = try Protocol.Admission.init(policy.key, policy.expected_id, policy.public, policy.expected_input);
            var rows = try Rows.prepare(a, policy.public, policy.expected_input, policy.key.config, limits);
            defer rows.deinit();
            const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(rows.recursive.rows.allocator, &rows.recursive, policy.key.profile);
            const key = Protocol.Key.fromGeometry(geometry);
            if (!std.meta.eql(key, policy.key) or !std.meta.eql(try key.identity(), policy.expected_id)) return error.UntrustedInputTailGeometry;
            const Producer = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
            const producer = try Producer.init(rows.recursive.rows.allocator, &rows.recursive.rows, admitted);
            defer producer.deinit();
            var proved = try producer.prove(rows.recursive.rows.allocator, &rows.recursive.rows);
            defer proved.deinit();
            const encoded = try Parent.codec.encode(rows.recursive.rows.allocator, &proved, &admitted);
            defer rows.recursive.rows.allocator.free(encoded);
            const checked = try Receiver.verify(rows.recursive.rows.allocator, policy, encoded);
            defer checked.deinit();
            const owner = if (Budget.fromAllocator(a)) |budget| budget.retain() else null;
            errdefer if (owner) |budget| budget.destroy();
            const bytes = try a.dupe(u8, encoded);
            errdefer a.free(bytes);
            const retained = policy.public.retain();
            errdefer retained.deinit();
            var artifact = Artifact{ .allocator = a, .budget = owner, .public = retained, .bytes = bytes, .key = key, .expected_id = policy.expected_id, .public_input = try admitted.publicInputIdentity() };
            try sink.put_input_tail(sink.context, &artifact);
        }
    };
}

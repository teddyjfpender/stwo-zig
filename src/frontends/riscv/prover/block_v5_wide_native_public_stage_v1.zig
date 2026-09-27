//! Real original proof verification, same-parent wide field graph, actual
//! recursive proving and fresh final receiver. Defaults remain unchanged.
const std = @import("std");
const Coverage = @import("block_v5_recursive_coverage_plan_v1.zig");
const Original = @import("../recursion/block_v5_wide_original_child_source_v1.zig");
const Public = @import("../recursion/block_v5_wide_native_public_values_v1.zig");
const Grammar = @import("../recursion/block_v5_reusable_wide_native_public_protocol_v1.zig");
const Receiver = @import("../recursion/block_v5_wide_native_public_receiver_v1.zig");
const Rows = @import("../recursion/block_v5_wide_native_public_preparation_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
pub const Limits = struct { max_owned_bytes: usize = 8 << 30, max_original_proof_bytes: usize = 512 << 20, transcript_capacity: u32 = 1 << 24, rows: Rows.Limits = .{} };
pub fn ForSubtype(comptime Backend: type, comptime subtype: Coverage.Subtype) type {
    const O = Original.ForSubtype(subtype);
    const P = Public.ForSubtype(subtype);
    const Protocol = Grammar.ForSubtype(subtype);
    const R = Receiver.ForSubtype(subtype);
    return struct {
        pub const Artifact = struct {
            allocator: std.mem.Allocator,
            allocation_owner: ?*@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
            bytes: []u8,
            key: Protocol.Key,
            expected_id: [32]u8,
            schedule: []Grammar.Wire,
            public_input: [32]u8,
            pub const complete_source_authority = false;
            pub fn deinit(self: *Artifact) void {
                self.allocator.free(self.bytes);
                self.allocator.free(self.schedule);
                const owner = self.allocation_owner;
                self.* = undefined;
                if (owner) |value| value.destroy();
            }
        };
        pub const Sink = struct { context: ?*anyopaque, put_open: *const fn (?*anyopaque, *Artifact) anyerror!void };
        pub fn publish(backing: std.mem.Allocator, policy: R.Policy, original_bytes: []const u8, limits: Limits, sink: Sink) !void {
            if (limits.max_owned_bytes == 0 or limits.transcript_capacity == 0 or original_bytes.len == 0 or original_bytes.len > limits.max_original_proof_bytes) return error.WideNativeParentResourceLimit;
            const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(backing, limits.max_owned_bytes);
            defer budget.destroy();
            const a = budget.allocator();
            var fresh = try O.verify(a, policy.original, original_bytes, policy.original_limits);
            defer fresh.deinit();
            var public = try P.Values.init(a, &fresh.source, policy.public_limits);
            defer public.deinit();
            const admitted = try Protocol.Admission.init(policy.key, policy.expected_id, policy.schedule, &public);
            var rows = try Rows.ForSubtype(subtype).prepare(a, &fresh, &public, limits.transcript_capacity, limits.rows);
            defer rows.deinit();
            const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, policy.key.profile);
            const key = try Protocol.Key.fromGeometry(geometry, rows.wires);
            if (!std.meta.eql(key, policy.key) or !std.meta.eql(try key.identity(), policy.expected_id) or !sameWires(rows.wires, policy.schedule)) return error.UntrustedWideNativeParentGeometry;
            const Producer = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
            const producer = try Producer.init(a, &rows.recursive.rows, admitted);
            defer producer.deinit();
            var proof = try producer.prove(a, &rows.recursive.rows);
            defer proof.deinit();
            const bytes = try Parent.codec.encode(a, &proof, &admitted);
            defer a.free(bytes);
            const checked = try R.verify(a, policy, bytes);
            defer checked.deinit();
            const output_owner = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.fromAllocator(backing);
            if (output_owner) |value| _ = value.retain();
            errdefer if (output_owner) |value| value.destroy();
            const owned = try backing.dupe(u8, bytes);
            errdefer backing.free(owned);
            const wires = try backing.dupe(Grammar.Wire, rows.wires);
            errdefer backing.free(wires);
            var artifact = Artifact{ .allocator = backing, .allocation_owner = output_owner, .bytes = owned, .key = key, .expected_id = policy.expected_id, .schedule = wires, .public_input = try admitted.publicInputIdentity() };
            // Success consumes Artifact; failure leaves allocations here.
            try sink.put_open(sink.context, &artifact);
        }
    };
}
fn sameWires(left: []const Grammar.Wire, right: []const Grammar.Wire) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}

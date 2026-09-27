//! Genuine original compact/public-child and compensation parent publication.
//! No canonical activation and no ClosedBlock/full source receipt.
const std = @import("std");
const Context = @import("../recursion/block_v5_heterogeneous_scoped_public_context_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_scoped_public_protocol_v1.zig");
const Receiver = @import("../recursion/block_v5_heterogeneous_scoped_public_receiver_v1.zig");
const Rows = @import("../recursion/block_v5_heterogeneous_scoped_public_preparation_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Bus = @import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const Limits = struct { max_owned_bytes: usize = 8 << 30, transcript_capacity: u32 = 1 << 24, rows: Rows.Limits = .{} };
pub const Artifact = struct {
    allocator: std.mem.Allocator,
    allocation_owner: ?*@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    bytes: []u8,
    key: Protocol.Key,
    expected_id: [32]u8,
    schedule: []Bus.Wire,
    plan: [32]u8,
    public_input: [32]u8,
    source_seal: [32]u8,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Artifact) void {
        self.allocator.free(self.bytes);
        self.allocator.free(self.schedule);
        const owner = self.allocation_owner;
        self.* = undefined;
        if (owner) |value| value.destroy();
    }
};
pub const Sink = struct {
    context: ?*anyopaque,
    /// Success consumes Artifact; failure leaves it owned by publisher.
    put_open: *const fn (?*anyopaque, *Artifact) anyerror!void,
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn publish(backing: std.mem.Allocator, expected: Receiver.Policy, compact_bytes: []const u8, public_bytes: []const u8, limits: Limits, sink: Sink) !void {
            if (limits.max_owned_bytes == 0 or limits.transcript_capacity == 0) return error.ScopedPublicBridgeResourceLimit;
            const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(backing, limits.max_owned_bytes);
            defer budget.destroy();
            const a = budget.allocator();
            const context = try Context.open(a, expected.sources, compact_bytes, public_bytes);
            defer context.deinit();
            const admitted = try Receiver.admission(context, expected);
            var rows = try Rows.prepare(a, context, limits.transcript_capacity, limits.rows);
            defer rows.deinit();
            const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, expected.key.profile);
            const key = try Protocol.Key.fromGeometry(geometry, rows.wires);
            if (!std.meta.eql(key, expected.key) or !std.meta.eql(try key.identity(), expected.expected_id) or !sameWires(rows.wires, expected.schedule)) return error.UntrustedScopedPublicParentGeometry;
            const Producer = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
            const producer = try Producer.init(a, &rows.recursive.rows, admitted);
            defer producer.deinit();
            var proof = try producer.prove(a, &rows.recursive.rows);
            defer proof.deinit();
            const bytes = try Parent.codec.encode(a, &proof, &admitted);
            defer a.free(bytes);
            if (bytes.len == 0 or bytes.len > expected.max_proof_bytes) return error.ScopedPublicBridgeResourceLimit;
            // Existing source captures are genuinely fresh and immutable. The
            // same actual final verifier is used without duplicating their
            // disk loads or replacing them with scalar receipts.
            var decoded = try Parent.codec.decode(a, bytes, &admitted);
            var fresh = try Parent.verify(&decoded, &admitted);
            defer fresh.deinit();
            try fresh.validate(&admitted, expected.expected_id);
            const output_owner = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.fromAllocator(backing);
            if (output_owner) |value| _ = value.retain();
            errdefer if (output_owner) |value| value.destroy();
            const owned_bytes = try backing.dupe(u8, bytes);
            errdefer backing.free(owned_bytes);
            const schedule = try backing.dupe(Bus.Wire, rows.wires);
            errdefer backing.free(schedule);
            var artifact = Artifact{ .allocator = backing, .allocation_owner = output_owner, .bytes = owned_bytes, .key = key, .expected_id = expected.expected_id, .schedule = schedule, .plan = context.plan.pinned_digest, .public_input = try admitted.publicInputIdentity(), .source_seal = context.policy.owner.pins.source };
            try sink.put_open(sink.context, &artifact);
        }
    };
}
fn sameWires(left: []const Bus.Wire, right: []const Bus.Wire) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}

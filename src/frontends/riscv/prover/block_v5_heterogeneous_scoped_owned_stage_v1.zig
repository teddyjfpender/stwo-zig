//! Bounded genuine compact hierarchy publication. Process-local setup ownership
//! removes repeated global derivation; actual fresh verification remains.
const std = @import("std");
const Owner = @import("../recursion/block_v5_heterogeneous_scoped_owner_v1.zig");
const Receiver = @import("../recursion/block_v5_heterogeneous_scoped_owned_receiver_v1.zig");
const Rows = @import("../recursion/block_v5_heterogeneous_scoped_owned_preparation_v1.zig");
const Source = @import("../recursion/block_v5_heterogeneous_scoped_source_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Original = @import("block_v5_heterogeneous_scoped_stage_v1.zig");
pub const Loader = Original.Loader;
pub const Sink = Original.Sink;
pub const Artifact = Original.Artifact;
pub const Limits = Original.Limits;
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn publish(backing: std.mem.Allocator, owner: *const Owner.Owner, loader: Loader, limits: Limits, sink: Sink) !void {
            if (!owner.ready or limits.max_owned_bytes == 0 or limits.max_child_bytes == 0 or limits.max_parent_bytes == 0 or limits.transcript_capacity == 0) return error.ScopedOwnerResourceLimit;
            var lease = try owner.borrow();
            defer lease.deinit();
            const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(backing, limits.max_owned_bytes);
            defer budget.destroy();
            const a = budget.allocator();
            if (owner.cohorts.root == .leaf) {
                const ordinal = owner.cohorts.root.leaf;
                const bytes = try loader.take_bytes(loader.context, a, .{ .leaf = ordinal });
                defer a.free(bytes);
                if (bytes.len == 0 or bytes.len > limits.max_child_bytes) return error.ScopedOwnerResourceLimit;
                var fresh = try Receiver.verifyLeaf(a, bytes, owner, ordinal);
                defer fresh.deinit();
                try deliver(backing, sink, .{ .leaf = ordinal }, bytes, null, fresh.source.expected_id, &.{}, owner.pins.routing, fresh.source.public_input_digest);
                return;
            }
            for (0..owner.cohorts.nodes.len) |index_usize| {
                const index: u32 = @intCast(index_usize);
                var admission = try owner.node(index);
                const cohort = owner.cohorts.nodes[index];
                var fresh: [4]Receiver.Fresh = undefined;
                var initialized: usize = 0;
                defer for (fresh[0..initialized]) |*child| child.deinit();
                var sources: [4]Source.Source = undefined;
                var captures: [4]*const @import("../recursion/blake3_native_parent_verifier.zig").Verified = undefined;
                for (cohort.children[0..cohort.child_count], 0..) |ref, slot| {
                    const bytes = try loader.take_bytes(loader.context, a, ref);
                    defer a.free(bytes);
                    if (bytes.len == 0 or bytes.len > limits.max_child_bytes) return error.ScopedOwnerResourceLimit;
                    fresh[slot] = switch (ref) {
                        .leaf => |ordinal| try Receiver.verifyLeaf(a, bytes, owner, ordinal),
                        .node => |ordinal| try Receiver.verify(a, bytes, owner, ordinal),
                    };
                    initialized += 1;
                    sources[slot] = fresh[slot].source;
                    captures[slot] = &fresh[slot].equation;
                }
                admission.values.children = sources[0..initialized];
                try admission.validate();
                var rows = try Rows.prepareVerifierRows(a, admission.values, captures[0..initialized], limits.transcript_capacity, limits.rows);
                defer rows.deinit();
                const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, admission.key.profile);
                const key = try Owner.Key.fromGeometry(geometry, rows.wires);
                if (!std.meta.eql(key, admission.key) or !std.meta.eql(try key.identity(), admission.expected_id) or !sameWires(rows.wires, admission.wires)) return error.UntrustedScopedParentGeometry;
                const Producer = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Owner);
                const producer = try Producer.init(a, &rows.recursive.rows, admission);
                defer producer.deinit();
                var proof = try producer.prove(a, &rows.recursive.rows);
                defer proof.deinit();
                const bytes = try Parent.codec.encode(a, &proof, &admission);
                defer a.free(bytes);
                if (bytes.len > limits.max_parent_bytes) return error.ScopedOwnerResourceLimit;
                var checked = try Receiver.verify(a, bytes, owner, index);
                defer checked.deinit();
                try deliver(backing, sink, .{ .node = index }, bytes, key, admission.expected_id, rows.wires, owner.pins.routing, checked.source.public_input_digest);
            }
        }
    };
}
fn deliver(a: std.mem.Allocator, sink: Sink, ref: @import("../recursion/block_v5_heterogeneous_scoped_cohorts_v1.zig").Ref, raw: []const u8, key: ?Owner.Key, id: [32]u8, schedule: []const @import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig").Wire, coverage: [32]u8, public_input: [32]u8) !void {
    const bytes = try a.dupe(u8, raw);
    errdefer a.free(bytes);
    const wires = try a.dupe(@import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig").Wire, schedule);
    errdefer a.free(wires);
    var artifact = Artifact{ .ref = ref, .bytes = bytes, .key = key, .key_id = id, .wires = wires, .coverage = coverage, .public_input = public_input };
    try sink.put_scoped_open(sink.context, &artifact);
}
fn sameWires(left: []const @import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig").Wire, right: @TypeOf(left)) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}

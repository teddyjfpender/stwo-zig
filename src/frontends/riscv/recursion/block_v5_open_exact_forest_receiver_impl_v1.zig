//! Typed production receive seam for the exact nested open v3 forest. Native
//! leaf policy must come from the complete receiver's internal fresh callback;
//! independently pinned recursive setups/schedules choose every verifier. The
//! actual outer STARK proves the entire mixed DAG, not a digest-only fold.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const mixed = @import("../prover/block_v5_open_exact_forest_plan_v1.zig");
const normalized = @import("block_v5_open_child_frames_v2.zig");
const bus = @import("block_v5_open_parent_public_bus_v2.zig");
const protocol = @import("block_v5_reusable_open_parent_protocol_v2.zig");
const parent = @import("blake3_execution_parent_proof.zig");
const open_receiver = @import("block_v5_open_parent_receiver_v2.zig");
const Common = @import("block_v5_open_exact_forest_receiver_v1.zig");
pub fn ForLeafAdapter(comptime LeafAdapter: type) type {
    return struct {
        pub const LeafPolicy = LeafAdapter.Policy;
        const NodePin = Common.NodePin;
        const OuterPins = Common.OuterPins;
        const FilePin = Common.FilePin;
        const Limits = Common.Limits;
        const Verified = Common.Verified;
        /// Metadata admission only. Used by detached transport before it opens
        /// any proof file; this returns no proof/receipt/closure authority.
        pub fn admitLeafPolicy(a: std.mem.Allocator, policy: LeafAdapter.Policy, profile: @import("blake3_execution_parent_protocol.zig").Profile) !void {
            const config = profile.config();
            if (!std.meta.eql(policy.native.config, config) or !std.meta.eql(policy.recursive_key.config, config) or
                !std.meta.eql(policy.recursive_key.context.child_config, config)) return error.V5ExactForestSecurityMismatch;
            var child = try LeafAdapter.normalize(a, policy);
            defer child.deinit();
        }
        /// Loader.load(a) returns one caller-owned byte slice. Length/hash pins are
        /// transport checks only; independent keys, native policies and exact topology
        /// select proof authority. The receiver owns verification and releases bytes.
        pub fn verifyLoaded(a: std.mem.Allocator, loader: anytype, file_pin: FilePin, leaves: []const LeafAdapter.Policy, parents: []const NodePin, outer: NodePin, public_pins: OuterPins, fresh_base_native_open_sum: Q) !Verified {
            if (leaves.len >= 1 << 30) return error.InvalidV5ExactNativeRoster;
            return verifyLoadedWithLimits(a, loader, file_pin, leaves, parents, outer, public_pins, fresh_base_native_open_sum, .{ .max_execution_count = @intCast(leaves.len), .max_outer_proof_bytes = file_pin.byte_len });
        }
        /// Limits are host resource admission, never proof/AIR parameters. The default
        /// wrapper uses the already trusted roster length and declared transport length.
        pub fn verifyLoadedWithLimits(a: std.mem.Allocator, loader: anytype, file_pin: FilePin, leaves: []const LeafAdapter.Policy, parents: []const NodePin, outer: NodePin, public_pins: OuterPins, fresh_base_native_open_sum: Q, limits: Limits) !Verified {
            if (leaves.len == 0 or leaves.len >= 1 << 30 or leaves.len != public_pins.segment_count) return error.InvalidV5ExactNativeRoster;
            const config = leaves[0].native.config;
            for (leaves) |leaf| {
                if (!std.meta.eql(leaf.native.config, config) or !std.meta.eql(leaf.recursive_key.config, config) or
                    !std.meta.eql(leaf.recursive_key.context.child_config, config)) return error.V5ExactForestSecurityMismatch;
            }
            for (parents) |pin| if (!std.meta.eql(pin.key.config, config) or !std.meta.eql(pin.key.context.child_config, config)) return error.V5ExactForestSecurityMismatch;
            if (!std.meta.eql(outer.key.config, config) or !std.meta.eql(outer.key.context.child_config, config)) return error.V5ExactForestSecurityMismatch;
            var plan = try mixed.plan(a, public_pins.segment_count, limits.max_execution_count);
            defer plan.deinit();
            if (parents.len != plan.tasks.len) return error.InvalidV5ExactRecursiveRoster;
            const native = try a.alloc(normalized.Child, leaves.len);
            defer a.free(native);
            var native_count: usize = 0;
            defer for (native[0..native_count]) |*child| child.deinit();
            var open = Q.zero();
            for (leaves, 0..) |policy, i| {
                native[i] = try LeafAdapter.normalize(a, policy);
                native_count += 1;
                if (native[i].span.first_index != i or native[i].span.segment_count != 1 or
                    !std.meta.eql(native[i].span.sealed_digest, public_pins.sealed_digest)) return error.UntrustedV5ExactNativeRoster;
                open = open.add(policy.exported.open_sum);
            }
            if (!open.eql(fresh_base_native_open_sum)) return error.NativeV5BaseRecursiveClaimMismatch;
            const nodes = try a.alloc(normalized.Child, parents.len);
            defer a.free(nodes);
            var node_count: usize = 0;
            defer for (nodes[0..node_count]) |*node| node.deinit();
            for (plan.tasks, parents, 0..) |task, pin, i| {
                var children: [4]normalized.Child = undefined;
                for (task.children[0..task.childCount()], children[0..task.childCount()]) |edge, *child| {
                    child.* = switch (edge.node) {
                        .leaf => |index| native[index],
                        .parent => |index| if (index < i) nodes[index] else return error.InvalidV5ExactRecursiveEdge,
                    };
                    if (child.span.first_index != edge.slots.first or child.span.segment_count != edge.slots.capacity()) return error.InvalidV5ExactRecursiveEdge;
                }
                const values = bus.Values{ .purpose = .local, .children = children[0..task.childCount()] };
                const admission = try protocol.Admission.init(pin.key, pin.expected_id, pin.schedule, values);
                nodes[i] = try normalized.fromOpenV2(a, admission);
                node_count += 1;
                if (nodes[i].span.first_index != task.slots.first or nodes[i].span.segment_count != task.slots.capacity()) return error.InvalidV5ExactRecursiveSpan;
            }
            var roots: [32]normalized.Child = undefined;
            for (plan.roots, roots[0..plan.roots.len]) |root, *child| {
                child.* = switch (root.node) {
                    .leaf => |index| native[index],
                    .parent => |index| nodes[index],
                };
                if (child.span.first_index != root.slots.first or child.span.segment_count != root.slots.capacity()) return error.InvalidV5ExactRootRoster;
            }
            const values = bus.Values{ .purpose = .exact_outer, .children = roots[0..plan.roots.len] };
            const span = try values.outputSpan();
            try public_pins.require(span);
            const admission = try protocol.Admission.init(outer.key, outer.expected_id, outer.schedule, values);
            if (file_pin.byte_len == 0 or file_pin.byte_len > limits.max_outer_proof_bytes or std.mem.allEqual(u8, &file_pin.sha256, 0)) return error.InvalidV5ExactOuterTransportPin;
            const bytes = try loader.load(a);
            defer a.free(bytes);
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
            if (bytes.len != file_pin.byte_len or !std.meta.eql(digest, file_pin.sha256)) return error.TamperedV5ExactOuterTransport;
            var owned = try parent.codec.decode(a, bytes, &admission);
            var equation = try parent.verify(&owned, &admission);
            errdefer equation.deinit();
            try equation.validate(&admission, outer.expected_id);
            return .{ .equation = equation, .sealed_digest = public_pins.sealed_digest, .execution_count = public_pins.segment_count, .combined_native_open_sum = open, .span = span };
        }
    };
}

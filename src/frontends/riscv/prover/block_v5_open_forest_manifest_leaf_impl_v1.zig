//! One detached transport checker for independently typed exact receivers.
const std = @import("std");
const core = @import("stwo_core");
const stage = @import("block_v5_open_forest_stage_v1.zig");
const exact = @import("../recursion/block_v5_open_exact_forest_receiver_v1.zig");
const bus = @import("../recursion/block_v5_open_parent_public_bus_v2.zig");
const Common = @import("block_v5_open_forest_manifest_v1.zig");
fn requireNode(received: exact.NodePin, independent: exact.NodePin) !void {
    if (!std.meta.eql(try independent.key.identity(), independent.expected_id) or
        !std.meta.eql(try bus.scheduleDigest(independent.schedule), independent.key.public_schedule_digest) or
        !std.meta.eql(received.expected_id, independent.expected_id) or
        !std.meta.eql(try received.key.identity(), independent.expected_id) or
        !std.meta.eql(try bus.scheduleDigest(received.schedule), independent.key.public_schedule_digest)) return error.UntrustedV5DetachedRecursivePolicy;
}

pub fn ForExactReceiver(comptime Receiver: type) type {
    return struct {
        /// The complete receiver must supply fresh native policies and independent
        /// parent/outer setup pins. SHA-pinned JSON cannot choose those authorities.
        pub fn verifyDetached(a: std.mem.Allocator, dir: std.fs.Dir, manifest_sha: [32]u8, fresh_leaves: []const Receiver.LeafPolicy, independent_parents: []const exact.NodePin, independent_outer: exact.NodePin, expected_public: exact.OuterPins, fresh_base_open_sum: core.fields.qm31.QM31, limits: Common.Limits) !exact.Verified {
            return verifyTransport(a, dir, manifest_sha, fresh_leaves, independent_parents, independent_outer, null, expected_public, fresh_base_open_sum, limits);
        }
        /// Complete reception additionally pins the outer transport independently of
        /// the manifest. A SHA-pinned proposal cannot replace that separate file pin.
        pub fn verifyDetachedPinned(a: std.mem.Allocator, dir: std.fs.Dir, manifest_sha: [32]u8, fresh_leaves: []const Receiver.LeafPolicy, independent_parents: []const exact.NodePin, independent_outer: exact.NodePin, expected_outer_file: exact.FilePin, expected_public: exact.OuterPins, fresh_base_open_sum: core.fields.qm31.QM31, limits: Common.Limits) !exact.Verified {
            return verifyTransport(a, dir, manifest_sha, fresh_leaves, independent_parents, independent_outer, expected_outer_file, expected_public, fresh_base_open_sum, limits);
        }
        fn verifyTransport(a: std.mem.Allocator, dir: std.fs.Dir, manifest_sha: [32]u8, fresh_leaves: []const Receiver.LeafPolicy, independent_parents: []const exact.NodePin, independent_outer: exact.NodePin, expected_outer_file: ?exact.FilePin, expected_public: exact.OuterPins, fresh_base_open_sum: core.fields.qm31.QM31, limits: Common.Limits) !exact.Verified {
            var owned = try Common.read(a, dir, manifest_sha, limits);
            defer owned.deinit();
            const wire = owned.view();
            if (wire.execution_count != fresh_leaves.len or independent_parents.len != wire.parents.len or
                !std.meta.eql(wire.public_pins, expected_public) or !wire.combined_native_open_sum.eql(fresh_base_open_sum)) return error.UntrustedV5DetachedForestStatement;
            for (wire.parents, independent_parents) |received, expected| try requireNode(received.node, expected);
            try requireNode(wire.outer.node, independent_outer);
            if (expected_outer_file) |file| {
                if (!std.meta.eql(file, wire.outer.file)) return error.UntrustedV5DetachedOuterFile;
            }
            // Reject foreign profiles, changed public counts/root metadata or
            // capacity/native authority before consuming any proof transport.
            for (fresh_leaves) |leaf| try Receiver.admitLeafPolicy(a, leaf, wire.profile);
            const outer_file = expected_outer_file orelse wire.outer.file;
            // Reopen one transport at a time. These hashes cannot replace the native
            // or recursive verifier equations checked inside the exact outer proof.
            var buffer: [80]u8 = undefined;
            for (wire.leaf_files, 0..) |pin, i| {
                const bytes = try stage.openPinned(a, dir, try stage.leafPath(@intCast(i), &buffer), pin, limits.max_proof_bytes);
                a.free(bytes);
            }
            for (wire.parents, 0..) |pin, i| {
                const bytes = try stage.openPinned(a, dir, try stage.parentPath(@intCast(i), &buffer), pin.file, limits.max_proof_bytes);
                a.free(bytes);
            }
            const Loader = struct {
                dir: std.fs.Dir,
                pin: exact.FilePin,
                max_bytes: usize,
                pub fn load(self: @This(), alloc: std.mem.Allocator) ![]u8 {
                    return stage.openPinned(alloc, self.dir, stage.OUTER_FILE, self.pin, self.max_bytes);
                }
            };
            return Receiver.verifyLoadedWithLimits(a, Loader{ .dir = dir, .pin = outer_file, .max_bytes = limits.max_proof_bytes }, outer_file, fresh_leaves, independent_parents, independent_outer, expected_public, fresh_base_open_sum, .{ .max_execution_count = limits.max_execution_count, .max_outer_proof_bytes = limits.max_proof_bytes });
        }
    };
}

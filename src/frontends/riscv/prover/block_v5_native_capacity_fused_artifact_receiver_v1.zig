//! B5CF transport policy. File bytes choose no source shape, capacity template,
//! count, root, frame, memory mode, catalog record or challenge seal.
const std = @import("std");
const Seal = @import("block_v5_source_seal_v1.zig");
const Catalog = @import("block_v5_native_capacity_catalog_v1.zig");
const Native = @import("block_v5_native_capacity_proof_v1.zig");
const Receiver = @import("block_v5_native_capacity_fused_receiver_v1.zig");
const Codec = @import("block_v5_native_capacity_fused_codec_v1.zig");
pub const Policy = struct {
    index: u32,
    native: Receiver.InstancePin,
    memory: Receiver.MemoryPin,
    sealed: Seal.Sealed,
    pins: Seal.Pins,
    entries: []const Seal.Entry,
    catalog: Catalog.Admission,
    wire_limits: Codec.Limits = .{},
    pub fn expected(self: Policy, a: std.mem.Allocator) !Codec.Expected {
        const roots = try Receiver.admit(a, self.index, self.native, self.memory, self.sealed, self.pins, self.entries, self.catalog);
        var native_id: ?[32]u8 = null;
        var fused_id: ?[32]u8 = null;
        for (self.entries) |entry| {
            if (entry.index != self.index) continue;
            if (entry.family == .execution) {
                if (native_id != null) return error.UntrustedCapacityFusedArtifactRoster;
                native_id = entry.instance_id;
            } else if (entry.family == .program_request) {
                if (fused_id != null) return error.UntrustedCapacityFusedArtifactRoster;
                fused_id = entry.instance_id;
            }
        }
        const derived = Codec.Expected{ .shape = self.native.shape, .external_retirements = self.native.external_retirements, .template_id = self.native.template_id, .native_instance_id = native_id orelse return error.UntrustedCapacityFusedArtifactRoster, .fused_instance_id = fused_id orelse return error.UntrustedCapacityFusedArtifactRoster, .native_roots = roots, .witness_root = self.memory.witness_root, .sealed_digest = self.sealed.digest, .index = self.index, .frame = self.memory.frame, .register_custody_mode = self.sealed.register_custody_mode, .config = self.pins.config, .fused_limits = self.native.limits };
        // Completely empty projection/access obligations have no file. Their
        // native frame remains mandatory and freshly verified by Receiver.
        var inventory = try Codec.Inventory.init(a, derived, self.wire_limits);
        inventory.deinit();
        return derived;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        /// Native proof transfers ownership on every path, including envelope
        /// rejection. Successful decoding transfers fused ownership to the
        /// genuine fresh CPU/backend receiver alongside the distinct base AIR.
        pub fn verifyOwned(a: std.mem.Allocator, raw: []const u8, native_received: Native.Proof, policy: Policy) !Receiver.Open {
            var native = native_received;
            var owns = true;
            defer if (owns) native.deinit(a);
            const expected = try policy.expected(a);
            const proof = try Codec.decode(a, raw, expected, policy.wire_limits);
            owns = false;
            return Receiver.ForBackend(Backend).verifyOwned(a, native, proof, policy.index, policy.native, policy.memory, policy.sealed, policy.pins, policy.entries, policy.catalog);
        }
        /// Private complete-receiver hook: freshly verified Capacity.OpenReceipt
        /// only. This path still runs the fused AIR/PCS/FRI verifier itself.
        pub fn verifyAfterFreshNative(a: std.mem.Allocator, raw: []const u8, fresh: *const Native.OpenReceipt, policy: Policy) !@import("block_v5_native_capacity_fused_proof_v1.zig").Verified {
            const expected = try policy.expected(a);
            const proof = try Codec.decode(a, raw, expected, policy.wire_limits);
            return Receiver.ForBackend(Backend).verifyAfterFreshNative(a, proof, fresh, policy.index, policy.native, policy.memory, policy.sealed, policy.pins, policy.entries, policy.catalog);
        }
    };
}

//! Capacity artifact policy derives keys, instance IDs and wire geometry from
//! independent source pins. Received bytes select none of these values.
const std = @import("std");
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Proof = @import("block_v5_native_capacity_proof_v1.zig");
const Codec = @import("block_v5_native_capacity_codec_v1.zig");
const Catalog = @import("block_v5_native_capacity_catalog_v1.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Statement = @import("../air/statement.zig");
pub const Policy = struct {
    shape: *const Statement.Blake3ExecutionStatement,
    external_retirements: u32,
    admission: Public.Admission,
    template: Protocol.Template,
    template_id: Protocol.Digest,
    index: u32,
    sealed: Seal.Sealed,
    pins: Seal.Pins,
    entries: []const Seal.Entry,
    catalog: ?Catalog.Admission = null,
    native_limits: Proof.Limits = .{},
    wire_limits: Codec.Limits = .{},

    pub fn expected(self: Policy, a: std.mem.Allocator) !Codec.Expected {
        try self.sealed.require(self.pins, self.entries);
        var source: ?Seal.Entry = null;
        for (self.entries) |entry| if (entry.family == .execution and entry.index == self.index) {
            if (source != null) return error.UntrustedNativeCapacityArtifactRoster;
            source = entry;
        };
        const entry = source orelse return error.UntrustedNativeCapacityArtifactRoster;
        const plan = try Protocol.Plan.fromShape(self.shape, self.external_retirements);
        try self.native_limits.require(&plan, self.shape);
        try self.wire_limits.validate();
        if (self.catalog) |catalog| {
            try Proof.admitWithCatalog(a, self.shape, self.external_retirements, self.admission, self.template, self.template_id, entry.instance_id, entry.roots, self.index, self.sealed, self.pins, self.entries, catalog);
        } else try Proof.admit(a, self.shape, self.external_retirements, self.admission, self.template, self.template_id, entry.instance_id, entry.roots, self.index, self.sealed, self.pins, self.entries);
        return .{ .shape = self.shape, .external_retirements = self.external_retirements, .template_id = self.template_id, .instance_id = entry.instance_id, .config = self.pins.config, .capacity_digest = self.template.capacity_digest, .native_limits = self.native_limits };
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Native = Proof.ForBackend(Backend);
        pub fn verify(a: std.mem.Allocator, raw: []const u8, policy: Policy) !Proof.OpenReceipt {
            const expected = try policy.expected(a);
            const received = try Codec.decode(a, raw, expected, policy.wire_limits);
            // Each actual verifier consumes the entire decoded proof on error
            // as well as success, after full source-policy admission.
            if (policy.catalog) |catalog| return Native.verifyOwnedWithCatalog(a, received, policy.shape, policy.external_retirements, policy.admission, policy.template, policy.template_id, policy.index, policy.sealed, policy.pins, policy.entries, policy.native_limits, catalog);
            return Native.verifyOwned(a, received, policy.shape, policy.external_retirements, policy.admission, policy.template, policy.template_id, policy.index, policy.sealed, policy.pins, policy.entries, policy.native_limits);
        }
        pub fn verifyCaptured(a: std.mem.Allocator, raw: []const u8, policy: Policy) !Proof.VerifiedCapture {
            const expected = try policy.expected(a);
            const received = try Codec.decode(a, raw, expected, policy.wire_limits);
            if (policy.catalog) |catalog| return Native.verifyCaptureOwnedWithCatalog(a, received, policy.shape, policy.external_retirements, policy.admission, policy.template, policy.template_id, policy.index, policy.sealed, policy.pins, policy.entries, policy.native_limits, catalog);
            return Native.verifyCaptureOwned(a, received, policy.shape, policy.external_retirements, policy.admission, policy.template, policy.template_id, policy.index, policy.sealed, policy.pins, policy.entries, policy.native_limits);
        }
    };
}

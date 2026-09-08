//! Fixed parent admission derives Tree0 from prepared AIR, never candidate proof
//! bytes. No parent proof capability is minted by this construction.
const std = @import("std");
const verifier = @import("recursive_common_fold_detached_verifier_v2.zig");
const field = @import("ethereum_wrapper_field_transcript_v1.zig");
pub const OwnedV1 = opaque {
    const Storage = struct { allocator: std.mem.Allocator, key: verifier.EthereumKeyV1, fields: field.SessionFieldsV1, source_identity: [32]u8 };
    pub fn create(comptime Cohort: type, allocator: std.mem.Allocator, cohort: *Cohort) !*OwnedV1 {
        const key_value = try verifier.EthereumKeyV1.fromPreparedCohort(Cohort, allocator, cohort);
        const fields_value = try key_value.sessionFields();
        const owned = try allocator.create(Storage);
        owned.* = .{ .allocator = allocator, .key = key_value, .fields = fields_value, .source_identity = cohort.source_owner.authorityIdentity() };
        return @ptrCast(owned);
    }
    fn storage(self: *const OwnedV1) *const Storage {
        return @ptrCast(@alignCast(self));
    }
    pub fn key(self: *const OwnedV1) *const verifier.EthereumKeyV1 {
        return &self.storage().key;
    }
    pub fn sessionFields(self: *const OwnedV1) field.SessionFieldsV1 {
        return self.storage().fields;
    }
    pub fn validateSource(self: *const OwnedV1, manifest: *const @import("recursive_common_fold_universal_manifest_v2.zig").Manifest, source_identity: [32]u8) !void {
        if (!std.meta.eql(self.storage().key.key.manifest, manifest.*) or !std.meta.eql(self.storage().source_identity, source_identity)) return error.EthereumFoldFixedAdmissionMismatch;
    }
    pub fn deinit(self: *OwnedV1) void {
        const owned: *Storage = @ptrCast(@alignCast(self));
        owned.allocator.destroy(owned);
    }
};

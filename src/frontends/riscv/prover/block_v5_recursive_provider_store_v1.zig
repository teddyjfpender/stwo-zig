//! Exact-count provider-leaf publication and mandatory fresh loading. Transport
//! pins and metadata are never proof authority or global recursive closure.
const std = @import("std");
const Seal = @import("block_v5_source_seal_v1.zig");
const CodecModule = @import("block_v5_recursive_provider_codec_v1.zig");
pub const Family = @import("block_v5_recursive_provider_family_v1.zig").Family;
pub const Limits = struct {
    codec: CodecModule.Limits = .{},
    max_files: usize = 1 << 16,
    max_slot_bytes: usize = 64 << 20,
    max_total_bytes: u64 = 64 << 30,
    pub fn validate(self: Limits) !void {
        try self.codec.validate();
        if (self.max_files == 0 or self.max_slot_bytes == 0 or self.max_total_bytes == 0)
            return error.InvalidRecursiveProviderStoreLimits;
    }
};
const Shared = @import("block_v5_recursive_leaf_store_core_v1.zig");
pub const Roster = Shared.Roster;
pub const FilePin = Shared.FilePin;
pub fn ForFamily(comptime family: Family) type {
    const Original = @import("block_v5_recursive_provider_definition_v1.zig").ForFamily(family);
    const C = CodecModule.ForDefinition(Original);
    const Definition = struct {
        pub const Codec = C;
        pub const Limits = @import("block_v5_recursive_provider_store_v1.zig").Limits;
        pub const TemplatePolicy = C.TemplatePolicy;
        pub const Stage = Original.Stage;
        pub const Receiver = Original.Receiver;
        pub const seal_family = Original.seal_family;
        pub const SINK_FIELD = Original.SINK_FIELD;
        pub const HEADER_BYTES = CodecModule.HEADER_BYTES;
        pub const allow_sparse = false;
        pub const index = Original.index;
        pub fn sealed(p: *const Original.Prepared) Seal.Sealed {
            return p.sealed;
        }
        pub fn pins(p: *const Original.Prepared) Seal.Pins {
            return p.pins;
        }
        pub fn maxFileBytes(limits: CodecModule.Limits) usize {
            return limits.max_file_bytes;
        }
        pub fn fileName(buffer: []u8, at: u32) ![]const u8 {
            return std.fmt.bufPrint(buffer, "block-v5-provider-{s}-{d}.leaf", .{ @tagName(family), at });
        }
        pub fn verifyView(a: std.mem.Allocator, view: *const C.View, policy: C.Policy) !Receiver.OpenEquation {
            var fresh = try Receiver.verify(a, view.proof, policy.template.key, policy.template.key_id, policy.template.schedule, policy.prepared, view.open);
            errdefer fresh.deinit();
            if (!std.meta.eql(fresh.public_values, view.values)) return error.UntrustedRecursiveProviderPublicInputs;
            return fresh;
        }
        pub const Errors = struct {
            pub const incomplete_policies = error.IncompleteRecursiveProviderPolicies;
            pub const slot_limit = error.RecursiveProviderSlotResourceLimit;
            pub const incomplete_files = error.IncompleteRecursiveProviderFiles;
            pub const untrusted_index = error.UntrustedRecursiveProviderFileIndex;
            pub const unadmitted_index = error.UnadmittedRecursiveProviderIndex;
            pub const invalid_mode = error.InvalidRecursiveProviderStoreMode;
            pub const duplicate_leaf = error.DuplicateRecursiveProviderLeaf;
            pub const total_limit = error.RecursiveProviderTotalResourceLimit;
            pub const invalid_load = error.InvalidRecursiveProviderLoadState;
            pub const incomplete_verification = error.IncompleteRecursiveProviderVerification;
            pub const untrusted_pin = error.UntrustedRecursiveProviderFilePin;
            pub const untrusted_roster = error.UntrustedRecursiveProviderRoster;
        };
    };
    return Shared.ForDefinition(Definition);
}

//! Exact execution/caller leaf staging over the shared durable ownership kernel.
//! Caller policies follow sparse original execution indices, never a rounded or
//! received file census. Each load invokes the original typed recursive verifier.
const std = @import("std");
const Seal = @import("block_v5_source_seal_v1.zig");
const Transport = @import("block_v5_recursive_execution_leaf_files_v1.zig");
const Shared = @import("block_v5_recursive_leaf_store_core_v1.zig");
const NativeSelection = @import("block_v5_native_fused_recursive_selection_v1.zig");
pub const Family = Transport.Family;
pub const Roster = Shared.Roster;
pub const FilePin = Shared.FilePin;
pub const Limits = struct {
    codec: Transport.Limits = .{},
    max_files: usize = 1 << 16,
    max_slot_bytes: usize = 64 << 20,
    max_total_bytes: u64 = 64 << 30,
    pub fn validate(self: Limits) !void {
        try self.codec.validate();
        if (self.max_files == 0 or self.max_slot_bytes == 0 or self.max_total_bytes == 0)
            return error.InvalidRecursiveExecutionStoreLimits;
    }
};
const StoreLimits = Limits;
pub fn ForFamily(comptime family: Family) type {
    const C = Transport.ForFamily(family);
    const Definition = struct {
        pub const Codec = C;
        pub const Limits = StoreLimits;
        pub const TemplatePolicy = C.Template;
        pub const Selection = NativeSelection.Selection;
        pub const Stage = C.Stage;
        pub const Receiver = C.Leaf;
        pub const seal_family: Seal.Family = if (family == .native_capacity_fused) .execution else .precompile;
        pub const SINK_FIELD = switch (family) {
            .caller_arithmetic => "put_caller_arithmetic",
            .caller_fused => "put_caller_fused",
            .native_capacity_fused => "put_fused",
        };
        pub const HEADER_BYTES = Transport.HEADER_BYTES;
        pub const allow_sparse = family != .native_capacity_fused;
        pub const index = C.index;
        pub const fileName = C.fileName;
        pub fn requireSelection(selection: *const Selection, roster: Roster, policies: []const C.Policy, limits: Transport.Limits) !void {
            if (comptime family == .native_capacity_fused) {
                try limits.validate();
                try selection.require(roster);
                if (policies.len != selection.indices.len) return error.IncompleteRecursiveExecutionPolicies;
                for (policies, selection.indices) |policy, selected| {
                    // Exact original native owner, not an independently mutable
                    // lookalike, underlies both selection and fused admission.
                    if (policy.prepared.native != selection.natives[selected] or C.index(policy.prepared) != selected)
                        return error.UntrustedRecursiveExecutionRoster;
                }
            } else return error.UnsupportedRecursiveLeafSelection;
        }
        pub fn sealed(p: *const C.Admission.Prepared) Seal.Sealed {
            return if (family == .native_capacity_fused) p.native.sealed else p.sealed;
        }
        pub fn pins(p: *const C.Admission.Prepared) Seal.Pins {
            return if (family == .native_capacity_fused) p.native.pins else p.pins;
        }
        pub fn maxFileBytes(limits: Transport.Limits) usize {
            return limits.codec.max_file_bytes;
        }
        pub fn verifyView(a: std.mem.Allocator, view: *const C.View, policy: C.Policy) !Receiver.OpenEquation {
            return view.verify(a, policy);
        }
        pub const Errors = struct {
            pub const incomplete_policies = error.IncompleteRecursiveExecutionPolicies;
            pub const slot_limit = error.RecursiveExecutionSlotResourceLimit;
            pub const incomplete_files = error.IncompleteRecursiveExecutionFiles;
            pub const untrusted_index = error.UntrustedRecursiveExecutionFileIndex;
            pub const unadmitted_index = error.UnadmittedRecursiveExecutionIndex;
            pub const invalid_mode = error.InvalidRecursiveExecutionStoreMode;
            pub const duplicate_leaf = error.DuplicateRecursiveExecutionLeaf;
            pub const total_limit = error.RecursiveExecutionTotalResourceLimit;
            pub const invalid_load = error.InvalidRecursiveExecutionLoadState;
            pub const incomplete_verification = error.IncompleteRecursiveExecutionVerification;
            pub const untrusted_pin = error.UntrustedRecursiveExecutionFilePin;
            pub const untrusted_roster = error.UntrustedRecursiveExecutionRoster;
        };
    };
    return Shared.ForDefinition(Definition);
}

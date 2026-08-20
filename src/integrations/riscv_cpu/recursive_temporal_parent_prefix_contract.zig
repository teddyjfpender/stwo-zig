const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const binary_outer = @import("recursive_binary_outer.zig");
const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
const pair_authority = @import("recursive_temporal_pair_authority_v2.zig");
const temporal_nonfri = @import("recursive_temporal_nonfri_source_v2.zig");
const support = @import("recursive_temporal_parent_prefix_support.zig");

const recursion = frontend.recursion;
const schedule = recursion.air.verifier_schedule;
const vm_claim = recursion.vm_public_claim;
const CHILD_COUNT = pair_authority.CHILD_COUNT;
const FORMAT_VERSION: u16 = 1;
const SCHEMA_VERSION: u16 = 1;
const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-parent-prefix-runtime/v1\x00";

pub const RuntimeInputsV1 = struct {
    artifacts: *const binary_outer.TemporalParentArtifactViewV1,
    prepared_leaves: [CHILD_COUNT]*const leaf_outer.PreparedNativeV2LeafOuter,

    pub fn validate(self: RuntimeInputsV1) !vm_claim.Shape {
        if (self.prepared_leaves[0] == self.prepared_leaves[1])
            return error.DuplicatePreparedLeaf;
        try self.artifacts.validate();
        for (
            self.prepared_leaves,
            self.artifacts.children,
        ) |prepared, artifact| {
            try prepared.validate();
            if (!std.mem.eql(
                u8,
                &prepared.identity,
                &artifact.publication.prepared_leaf_sha_id,
            )) return error.ChildPreparedLeafMismatch;
        }

        const left = self.prepared_leaves[0];
        const right = self.prepared_leaves[1];
        if (!support.plansEqual(&left.vm_plan, &right.vm_plan) or
            !support.plansEqual(&left.recursion_plan, &right.recursion_plan) or
            !std.meta.eql(left.pcs_config, right.pcs_config) or
            !std.meta.eql(left.verifier_keys, right.verifier_keys))
        {
            return error.RuntimeProfileMismatch;
        }

        // SegmentV2 exposes its boundary IO through authenticated digest
        // fields, not the legacy per-word VM public-IO slots. The recursive VM
        // verifier therefore has exactly the protocol-mandated zero-slot shape.
        const shape = try vm_claim.Shape.init(0, 0);
        const expected_vm_spec = try schedule.vmProgramSpec(
            shape.max_input_words,
            shape.max_output_words,
        );
        if (!std.meta.eql(left.vm_plan.spec, expected_vm_spec) or
            !std.meta.eql(
                left.recursion_plan.spec,
                schedule.RECURSION_PROGRAM_SPEC_V1,
            )) return error.RuntimeProfileMismatch;
        return shape;
    }
};

pub const PhaseV1 = enum(u8) {
    cold = 0,
    base_trees_filled = 1,
    prefix_trees_filled = 2,
};

/// Pointer-free receipt for the transactionally filled preprocessed and main
/// trees. The two receipts retain their protocol tree indices and exact
/// storage hashes; order cannot be supplied by a caller.
pub const BaseTreeReceiptsV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    trees: [2]temporal_nonfri.TemporalPrefixTreeReceiptV3,
    identity: [32]u8,

    pub fn init(
        custody: *const temporal_nonfri.TemporalRows0Through17CustodyV3,
        receipts: [2]temporal_nonfri.TemporalPrefixTreeReceiptV3,
    ) !BaseTreeReceiptsV1 {
        var result = BaseTreeReceiptsV1{
            .trees = receipts,
            .identity = undefined,
        };
        result.identity = support.baseReceiptIdentity(AUTHORITY_DOMAIN, &result);
        try result.validate(custody);
        return result;
    }

    pub fn validate(
        self: *const BaseTreeReceiptsV1,
        custody: *const temporal_nonfri.TemporalRows0Through17CustodyV3,
    ) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0) or
            self.trees[0].tree_index != temporal_nonfri.PREFIX_TREE0_INDEX or
            self.trees[1].tree_index != temporal_nonfri.PREFIX_TREE1_INDEX or
            !std.mem.eql(
                u8,
                &self.identity,
                &support.baseReceiptIdentity(AUTHORITY_DOMAIN, self),
            ))
        {
            return error.InvalidPrefixRuntime;
        }
        try self.trees[0].validate(custody);
        try self.trees[1].validate(custody);
    }
};

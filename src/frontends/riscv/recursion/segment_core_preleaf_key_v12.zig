//! Child-independent SegmentV2 authority for the direct core's rows 23/24.
//!
//! The selected statement and V10 key must come from verifier policy. In
//! particular, a proof capture is not an input to this constructor. This is
//! only a partial fixed key; it cannot authorize publication of a wrapper.
const std = @import("std");
const statement_mod = @import("../air/statement.zig");
const v10 = @import("air/segment_leaf_wrapper_template_v10.zig");
const v11 = @import("air/segment_leaf_wrapper_template_v11.zig");
const layout_mod = @import("segment_core_expected_layout_from_statement_v11.zig");
const masks_mod = @import("segment_core_expected_pcs_masks_v12.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;

pub fn buildForSegmentV2(
    allocator: std.mem.Allocator,
    selected_statement: *const statement_mod.RiscVStatement,
    selected_prior: *const v10.TemplateManifestV10,
) !v11.TemplateManifestV11 {
    try selected_prior.validate();
    const selected_core = &selected_prior.v9_template.v8_template.v7_template.v6_template.shape.core_profile;
    var logs = try layout_mod.OwnedLayout.buildSegmentV2FromCoreProfile(
        allocator,
        selected_statement,
        selected_core,
    );
    defer logs.deinit();
    var masks = try masks_mod.OwnedMasks.build(allocator, selected_statement, selected_core, &logs);
    defer masks.deinit();
    return v11.TemplateManifestV11.buildFromVerifierProfile(
        allocator,
        selected_prior,
        masks.expected(&logs),
    );
}

pub fn validateAgainstSegmentV2Authority(
    allocator: std.mem.Allocator,
    candidate: *const v11.TemplateManifestV11,
    selected_statement: *const statement_mod.RiscVStatement,
    selected_prior: *const v10.TemplateManifestV10,
) !void {
    const rebuilt = try buildForSegmentV2(allocator, selected_statement, selected_prior);
    if (!std.meta.eql(candidate.*, rebuilt)) return error.InvalidPreleafKeyV12;
}

//! Pre-leaf PCS mask order for the authenticated SegmentV2 component roster.
//!
//! The native verifier asks these same component owners for OODS masks. This
//! candidate asks them at a fixed, proof-independent point and retains only
//! the ordered mask tags. A claim with zero values supplies shape, never a
//! child-chosen PCS profile. Production activation remains gated on a complete
//! selected wrapper key and detached proof verification.
const std = @import("std");
const core = @import("stwo_core");
const statement_mod = @import("../air/statement.zig");
const lookup = @import("../air/lang/lookup_physical_manifest_v2.zig");
const relations_mod = @import("../air/relation_challenges.zig");
const preprocessed = @import("../prover/preprocessed.zig");
const assembly = @import("../prover/base_component_assembly.zig");
const workspace_mod = @import("../prover/proof_workspace.zig");
const layout_mod = @import("sample_point_layout.zig");
const core_profile = @import("air/segment_leaf_wrapper_template_v6.zig");
const row24 = @import("segment_core_pcs_row24_fixed_v11.zig");
const ordered = @import("segment_core_expected_layout_from_statement_v11.zig");
const protocol = @import("protocol.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;

pub const OwnedMasks = struct {
    allocator: std.mem.Allocator,
    layouts: []layout_mod.Layout,

    pub fn deinit(self: *OwnedMasks) void {
        self.allocator.free(self.layouts);
        self.* = undefined;
    }

    pub fn expected(self: *const OwnedMasks, tree_logs: *const ordered.OwnedLayout) row24.ExpectedProfile {
        return .{ .ordered_tree_logs = &tree_logs.views, .sample_layouts = self.layouts };
    }

    pub fn build(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        selected: *const core_profile.CoreProfileV6,
        tree_logs: *const ordered.OwnedLayout,
    ) !OwnedMasks {
        _ = try selected.reference();
        if (selected.vm.tree_count != ordered.TREE_COUNT or
            !std.meta.eql(selected.vm, selected.recursion))
            return error.InvalidPreleafPcsMaskProfile;
        const manifest = lookup.Manifest.native();
        const authenticated = try lookup.AuthenticatedStatement.init(statement, &manifest);
        const interaction_count = try authenticated.totalInteractionColumns(statement, &manifest);
        const preprocessed_logs = try preprocessed.logSizes(allocator, statement.*);
        defer allocator.free(preprocessed_logs);
        if (preprocessed_logs.len != tree_logs.trees[0].len or
            statement.nMainColumns() != tree_logs.trees[1].len or
            interaction_count != tree_logs.trees[2].len)
            return error.InvalidPreleafPcsMaskLayout;

        const claim = try allocator.create(statement_mod.RiscVInteractionClaim);
        defer allocator.destroy(claim);
        claim.initZeroInto();
        claim.n_components = statement.n_components;
        claim.n_infra = statement.n_infra;
        const relations = relations_mod.Relations.dummy();
        const workspace = try workspace_mod.VerificationWorkspace.create(allocator);
        defer workspace.destroy(allocator);
        try assembly.assembleIntoAuthenticatedLookupV2(
            .verifier,
            workspace,
            statement,
            claim,
            &relations,
            statement.nMainColumns(),
            interaction_count,
            &manifest,
            &authenticated,
        );
        const components = core.air.components.Components{
            .components = workspace.components.active(),
            .n_preprocessed_columns = preprocessed_logs.len,
        };
        var component_logs = try components.columnLogSizes(allocator);
        defer component_logs.deinitDeep(allocator);
        if (component_logs.items.len != ordered.TREE_COUNT - 1)
            return error.InvalidPreleafPcsMaskLayout;
        for (component_logs.items, tree_logs.views[0 .. ordered.TREE_COUNT - 1]) |actual, selected_logs| {
            if (actual.len != selected_logs.len) return error.InvalidPreleafPcsMaskLayout;
            for (actual, selected_logs) |raw, extended| {
                if (try std.math.add(u32, raw, protocol.FRI_LOG_BLOWUP_FACTOR) != extended)
                    return error.InvalidPreleafPcsMaskLayout;
            }
        }
        const split = try components.compositionLogSplit();
        if (split != core.verifier_types.COMPOSITION_LOG_SPLIT)
            return error.InvalidPreleafPcsMaskProfile;
        const mask_log = std.math.sub(u32, selected.vm.lifting_log_size, protocol.FRI_LOG_BLOWUP_FACTOR) catch
            return error.InvalidPreleafPcsMaskProfile;
        if (mask_log == 0) return error.InvalidPreleafPcsMaskProfile;
        const component_mask_log = core.verifier_types.compositionMaskLogSize(
            components.compositionLogDegreeBound(),
            split,
        ) orelse return error.InvalidPreleafPcsMaskProfile;
        const max_log = @max(component_mask_log, mask_log);
        const point = try core.circle.secureFieldPointFromRandomSeedChecked(
            core.fields.qm31.QM31.fromU32Unchecked(1, 2, 3, 4),
        );
        // `maskPoints` receives `max_log`; its previous-row offset is the
        // maximal coset step, even when the selected FRI lifting is smaller.
        const step = core.poly.circle.canonic.CanonicCoset.new(max_log).step();
        const previous = point.sub(.{
            .x = core.fields.qm31.QM31.fromBase(step.x),
            .y = core.fields.qm31.QM31.fromBase(step.y),
        });
        var masks = try components.maskPoints(allocator, point, max_log, false);
        defer masks.deinitDeep(allocator);
        if (masks.items.len != ordered.TREE_COUNT - 1)
            return error.InvalidPreleafPcsMaskLayout;
        var column_count: usize = 0;
        for (tree_logs.views) |tree| column_count = try std.math.add(usize, column_count, tree.len);
        const layouts = try allocator.alloc(layout_mod.Layout, column_count);
        errdefer allocator.free(layouts);
        var cursor: usize = 0;
        for (masks.items, tree_logs.views[0 .. ordered.TREE_COUNT - 1]) |columns, expected_logs| {
            if (columns.len != expected_logs.len) return error.InvalidPreleafPcsMaskLayout;
            for (columns) |points| {
                layouts[cursor] = try layout_mod.classifyColumn(points, point, previous);
                cursor += 1;
            }
        }
        for (tree_logs.views[3]) |_| {
            layouts[cursor] = .current;
            cursor += 1;
        }
        if (cursor != layouts.len) return error.InvalidPreleafPcsMaskLayout;
        return .{ .allocator = allocator, .layouts = layouts };
    }
};

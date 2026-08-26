const std = @import("std");
const integration = @import("stwo_riscv_cpu_integration");
const subject = integration.recursive_segment_v2_noncore_owner;
const real_gate = @import("recursive_segment_v2_noncore_owner_real_gate.zig");
const cohort = integration.recursive_segment_v2_outer_cohort;

test "SegmentV2 non-core owner exposes stable split-custody API" {
    std.testing.refAllDeclsRecursive(subject);
    std.testing.refAllDeclsRecursive(real_gate);
    std.testing.refAllDeclsRecursive(cohort);
    comptime {
        for (.{
            "init",
            "initInPlace",
            "deinit",
            "validate",
            "sourceManifests",
            "authorityIdentity",
            "mixAuthority",
            "fillPreprocessedInto",
            "fillMainInto",
            "prepareInteractions",
            "rebuildGeneratedInteractions",
            "fillInteractionInto",
            "validateGenerated",
            "initComponents",
        }) |name| if (!@hasDecl(subject.Owner, name))
            @compileError("missing non-core owner declaration: " ++ name);
        for (.{
            "validate",
            "validateAgainst",
            "bindClaimsInto",
            "installClaimsAndAudits",
        }) |name| if (!@hasDecl(subject.GeneratedInteractionsV2, name))
            @compileError("missing generated receipt declaration: " ++ name);
        for (.{
            "appendRows0Through17ToGate",
            "appendRows35Through38ToGate",
            "deinit",
        }) |name| if (!@hasDecl(subject.Components, name))
            @compileError("missing split component declaration: " ++ name);
    }
    try std.testing.expect(!subject.RETAINS_SELF_POINTERS);
    try std.testing.expect(subject.INTERACTION_GENERATION_IS_COLD);
    try std.testing.expectEqual([_]usize{ 0, 0, 0 }, subject.HOT_TREE_HEAP_ALLOCATIONS);
    try std.testing.expectEqual(@as(usize, 22), subject.OWNED_ROW_COUNT);
}

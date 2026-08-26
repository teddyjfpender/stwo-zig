//! SegmentV2 concrete owner surface for universal rows 18--34.
//!
//! The underlying AIR/witness implementation is the neutral binary FRI
//! cohort. This module selects the fixed 38-row SegmentV2 manifest contract
//! and the authenticated complete shared-Poseidon schedule; it does not copy
//! any of the sixteen typed equations or instantiate a second row-34
//! provider.

const base = @import("binary_fri_outer_bundle.zig");
const fixed_wire = @import("fixed_wire.zig");
const manifest_v2 = @import("air/segment_outer_adapter_manifest_v2.zig");
const shared_schedule = @import("segment_shared_poseidon_schedule_v2.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const FIRST_ROW: u8 = base.FIRST_ROW;
pub const LAST_ROW: u8 = base.LAST_ROW;
pub const ROW_COUNT: usize = base.ROW_COUNT;
pub const TYPED_ROW_COUNT: usize = base.TYPED_ROW_COUNT;
pub const HOT_TREE_HEAP_ALLOCATIONS = base.HOT_TREE_HEAP_ALLOCATIONS;
pub const HOT_ALL_TREES_HEAP_ALLOCATIONS = base.HOT_ALL_TREES_HEAP_ALLOCATIONS;
pub const ROW34_REPLAYED_SCALAR_PERMUTATIONS =
    base.ROW34_REPLAYED_SCALAR_PERMUTATIONS;
pub const COMPLETE_SHARED_PROVIDER_REQUIRED = true;
pub const PRODUCTION_ACTIVATION = false;

pub const AdaptersV2 = base.AdaptersForManifest(manifest_v2);
pub const ComponentsV2 = base.ComponentsForManifest(manifest_v2);
pub const ClaimsV2 = base.Claims;
pub const DomainAuditsV2 = base.DomainAudits;
pub const GeneratedInteractionsV2 = base.GeneratedInteractionsV1;
pub const AuditedInteractionsV2 = base.AuditedInteractionsV1;
pub const SharedPoseidonCallLayoutV2 =
    shared_schedule.SharedPoseidonCallLayoutV2;
pub const OwnedCompletePoseidonScheduleV2 =
    shared_schedule.OwnedCompletePoseidonScheduleV2;

pub fn Bundle(comptime dimensions: fixed_wire.Dimensions) type {
    return base.BundleForManifest(dimensions, manifest_v2);
}

pub fn bindClaimsInto(
    claims: ClaimsV2,
    vector: *manifest_v2.ClaimVector,
) !void {
    for (claims.asRows18Through34(), FIRST_ROW..) |claim, row|
        try vector.bind(@enumFromInt(row), claim);
}

comptime {
    if (FORMAT_VERSION != 1 or FIRST_ROW != 18 or LAST_ROW != 34 or
        ROW_COUNT != 17 or TYPED_ROW_COUNT != 16 or
        HOT_ALL_TREES_HEAP_ALLOCATIONS != 0 or
        ROW34_REPLAYED_SCALAR_PERMUTATIONS != 0 or
        !COMPLETE_SHARED_PROVIDER_REQUIRED)
    {
        @compileError("SegmentV2 core component owner drifted");
    }
}

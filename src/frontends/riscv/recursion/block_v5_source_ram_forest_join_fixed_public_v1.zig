//! Same original V20 framing/epoch/census checks over setup-only serializers.
//! This module has no verifier or constructor for successful child receipts.
const Original = @import("block_v5_source_ram_forest_join_public_v1.zig");
pub const Page = @import("block_v5_memory_source_page_forest_recursive_shape_admission_v1.zig").Node;
pub const Memory = @import("block_v5_ram_range_forest_recursive_shape_admission_v1.zig").Node;
const Impl = Original.ForSources(Page, Memory);
pub const VERSION = Original.VERSION;
pub const CLAIM_FIRST = Original.CLAIM_FIRST;
pub const Wire = Original.Wire;
pub const Limits = Original.Limits;
pub const Policy = Impl.Policy;
pub const Owner = Impl.Owner;
pub const Values = Impl.Values;
pub const scheduleDigest = Original.scheduleDigest;
pub fn supply(wires: []const Wire, values: Values, _: @import("air/universal_challenges.zig").UniversalRelations) !@import("stwo_core").fields.qm31.QM31 {
    _ = try scheduleDigest(wires);
    try values.validate();
    return .zero();
}

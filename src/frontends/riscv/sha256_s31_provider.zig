//! Narrow module boundary for S31's SHA witness planner. The packed SHA AIR
//! stays owned by the RISC-V frontend until S31 has a proof-bound roster.
const rows = @import("air/guest_precompile/sha256_compression_rows.zig");
pub const compression = @import("air/guest_precompile/sha256_compression.zig");
pub const Call = rows.Call;
pub const Rows = rows.Rows;
pub const Geometry = rows.Geometry;
pub const prepare = rows.prepare;
pub const graph = @import("air/guest_precompile/sha256_compression_graph.zig");
pub const topology = rows.topology;
pub const Source = @import("air/guest_precompile/sha256_packed_source.zig");
pub const Schedule = rows.Schedule;
pub const Round = rows.Round;
pub const FeedForward = rows.FeedForward;
pub const Boundary = @import("recursion/air/blake3_boundary.zig");
pub const Binding = @import("recursion/air/universal_relation_binding.zig");
pub const lookup_kinds = [_]@import("air/lookups/tables/schema.zig").Kind{ .bitwise, .range_check_8_8, .range_check_8_8_4, .range_check_20 };
/// The S31 three-call roster only emits these two table relations. The full
/// RISC-V SHA memory caller needs the larger four-kind `lookup_kinds` set.
pub const joint_lookup_kinds = [_]@import("air/lookups/tables/schema.zig").Kind{ .bitwise, .range_check_8_8 };
pub const wire_relation_id = @import("air/lang/relation.zig").id(.recursion_wire);
// A single RISC-V adapter module owns shared recursive AIR source files when
// S31 imports both Poseidon and SHA. Zig forbids the same source file being
// compiled as part of two distinct modules in one root graph.
pub const constants = @import("air/memory_commitment/poseidon2_constants.zig");
pub const channel = @import("recursion/poseidon2_channel.zig");
pub const permutation = @import("air/memory_commitment/poseidon2.zig");
pub const relation = @import("air/lang/relation.zig");
pub fn tableSchemaSourceDigest() [32]u8 {
    var digest: [32]u8 = undefined;
    @import("std").crypto.hash.sha2.Sha256.hash(@embedFile("air/lookups/tables/schema_definition.zig"), &digest, .{});
    return digest;
}
pub fn tableInteractionSourceDigest() [32]u8 {
    var digest: [32]u8 = undefined;
    @import("std").crypto.hash.sha2.Sha256.hash(@embedFile("air/lookups/tables/interaction.zig"), &digest, .{});
    return digest;
}
// The joined S31 circuit/SHA prover uses the same typed AIR projection,
// challenges, lookup tables, and component owner as the standalone SHA proof.
// Keep those imports behind this adapter so S31 does not define a second SHA
// semantics or table registry.
pub const row_columns = @import("recursion/air/blake3_row_columns.zig");
pub const binding = @import("recursion/air/universal_relation_binding.zig");
pub const framework = @import("recursion/air/framework_interaction.zig");
pub const universal = @import("recursion/air/universal_challenges.zig");
pub const sha_relations = @import("air/guest_precompile/sha256_relations.zig");
pub const shared_provider_relations = @import("recursion/air/universal_provider_relations.zig");
pub const component_roster = @import("recursion/air/universal_component_roster.zig");
pub const component_owner = @import("recursion/air/universal_component_owner.zig");
pub const component_geometry = @import("recursion/air/roster_composition_geometry.zig");
pub const preprocessed = @import("air/guest_precompile/sha256_preprocessed.zig");
pub const schema = @import("air/lookups/tables/schema.zig");
pub const Counter = @import("air/lookups/tables/counter.zig").Counter;
pub const Table = @import("air/lookups/tables/component.zig").LookupTableComponent;
pub const LookupTableVerifier = @import("air/lookups/tables/verifier.zig").LookupTableVerifier;
pub const table_interaction = @import("air/lookups/tables/interaction.zig");

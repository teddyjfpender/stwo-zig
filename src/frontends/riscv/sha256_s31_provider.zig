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
pub const wire_relation_id = @import("air/lang/relation.zig").id(.recursion_wire);

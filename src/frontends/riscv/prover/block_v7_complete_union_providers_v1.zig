//! Finite original-provider contexts for the complete heterogeneous STARK.
//! They supply equations and OPEN physical claims, never proof authority.
pub const Program = @import("block_v7_complete_union_program_v1.zig");
pub const Lookup = @import("block_v7_complete_union_lookup_v1.zig");
pub const Memory = @import("block_v7_complete_union_memory_v1.zig");

//! Exact old B5SC specialization. Shared ownership extraction must preserve
//! these bytes and all old source/equation schedules; no new proof is implied.
const std = @import("std");
pub const TAG: u32 = 0x42355343;
pub const VERSION: u32 = 1;
pub const FIXED_COUNT: usize = 15;
pub const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
pub const Stream = @import("block_v5_memory_source_stream_v1.zig");
pub const Equations = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
pub const MAIN_COUNT: usize = Equations.BIT_COUNT;
pub const Circuit = @import("block_v5_memory_source_circuit_v1.zig");
pub const Reader = Stream.Source;
pub const FILE_MAGIC = "B5SPBIT1";
pub const FILE_VERSION: u32 = 1;
pub const PAGE_TAG: u32 = 0x42355350;
pub const PAGE_VERSION: u32 = 1;
pub const CIRCUIT_BASE: u32 = 8_000_000;
pub const writeBits = @import("block_v5_memory_source_witness_bits_v1.zig").writeBits;
pub const restoreBits = @import("block_v5_memory_source_witness_bits_v1.zig").restoreBits;
pub const fixedAt = @import("block_v5_memory_source_fixed_recipe_v1.zig").ForSchedule(Stream).fixedAt;
pub const Protocol = @import("block_v5_memory_source_first_protocol_common_v1.zig").ForSchema(@This());
pub const Columns = @import("block_v5_memory_source_first_columns_common_v1.zig").ForSchema(@This());
pub const Round = @import("block_v5_memory_source_first_round_common_v1.zig").ForSchema(@This());
pub const Store = @import("block_v5_memory_source_page_store_common_v1.zig").ForSchema(@This());
pub const Replay = @import("block_v5_memory_source_page_replay_common_v1.zig").ForSchema(@This());
pub const Page = @import("block_v5_memory_source_page_protocol_common_v1.zig").ForSchema(@This());
pub const BindingPlan = @import("block_v5_memory_source_binding_plan_common_v1.zig").ForSchema(@This());
pub const BindingAir = @import("block_v5_memory_source_binding_air_common_v1.zig").ForSchema(@This());
pub const BindingInteraction = @import("block_v5_memory_source_binding_interaction_common_v1.zig").ForSchema(@This());
pub const BindingComponent = @import("block_v5_memory_source_binding_component_common_v1.zig").ForSchema(@This());
pub fn cursorInit(admitted: Source.Admitted, reader: Reader) !Stream.Cursor {
    return Stream.Cursor.init(admitted, reader);
}
pub fn cursorAdmission(cursor: *const Stream.Cursor) *const Source.Admitted {
    return &cursor.admitted;
}
pub fn abiId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/source-first-round/v1\x00");
    hash.update("B5SC;fixed15;main1728;kindAt-schedule;canonical-circle-placement;all-private-bits;zero-tail;no-equation-receipt\x00");
    hash.update("raw64,state8u32,address,previous,before,after,clock-u64,beforeHash32,afterHash32,sibling32;LE-bits\x00");
    hash.update("word-challenges-before-source-roster;9-source-pairs-after-full-source-roster;no-source-key-from-payload\x00");
    return hash.finalResult();
}
pub fn pageAbiId() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo-zig/memory-source-page/v1\x00;source-fixed0;private-main1;routing-fixed2;binding-interaction3;wire6;post-B5SC-AND-arithmetic-main-rosters-wire-draw;pair2-degree3;boolean-and-zero-tail;page-level-arithmetic\x00");
    h.update(&abiId());
    h.update(@import("../recursion/air/verifier_arithmetic_lowering.zig").DOMAIN);
    h.update(&@import("../recursion/air/qm31_mul_full.zig").SEMANTIC_DIGEST);
    h.update(&@import("../recursion/air/qm31_inv.zig").SEMANTIC_DIGEST);
    h.update(&@import("../recursion/air/linear_ops.zig").SEMANTIC_DIGEST);
    return h.finalResult();
}

//! Complete proof-local roster derived from independently admitted CPU setup.
//! Global RAM/KIO/Wire and public INIT/TERM are intentionally not GKR instances.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const Geometry = @import("../../../word16_execution/geometry.zig");
const R = @import("../roster.zig");
const Instance = @import("frame.zig").Instance;
pub fn terms(role: Geometry.Role) u32 {
    return switch (role) {
        .cpu => 15,
        .rom => 1,
        .boundary => 2,
        .alu, .alu_tail => A.word16_v1.alu_experiment.equations.RANGE_QUERIES + 1,
        .binary, .binary_tail => A.word16_v1.binary.AND_REQUESTS + 1,
        .shift, .shift_tail => A.word16_v1.shift_word_packed_experiment.equations.TABLE_QUERIES + A.word16_v1.shift_word_packed_experiment.equations.RANGE_QUERIES + 1,
        .jalr => 3,
        .division => A.arithmetic.division.word16_product.layout.RANGE_QUERIES + 3,
        .multiplication => A.arithmetic.multiplication.layout.BYTE_QUERIES + 1,
        .shift_table => A.word16_v1.shift_word_packed_experiment.table.MAIN,
        .and_table, .range16, .range8 => 1,
        .ls, .ls_tail => A.memory.load_store_v2.layout.LOCAL_FRACTIONS,
        .selection => 2,
        .initial, .terminal => 0,
    };
}
pub fn termsForSetup(setup: *const R.CpuSetup, role: Geometry.Role) u32 {
    if (setup.materials.geometry.cpu_u8_pairs) switch (role) {
        .cpu => return @import("fractions.zig").cpuTerms(true),
        .and_table => return @import("fractions.zig").andTableTerms(true),
        else => {},
    };
    return terms(role);
}
pub fn bridgeTerms(family: @import("../types.zig").Family) u32 {
    return if (family == .keccak)
        1 + A.crypto.keccak.word16_bridge.layout.U16.len + A.crypto.keccak.word16_bridge.layout.U8.len
    else
        1 + A.crypto.secp256k1.word16_bridge.layout.U16.len + A.crypto.secp256k1.word16_bridge.layout.U8.len;
}
pub fn fromSetup(a: std.mem.Allocator, setup: *const R.CpuSetup) ![]Instance {
    // Qualified v2 bridges and bulk on the historical CPU layout (fused-tail / byte-pair
    // CPU layouts fail closed with UnsupportedFusedTailInLocalGkr).
    try @import("bulk_scope.zig").setup(setup);
    var out = std.ArrayList(Instance).empty;
    errdefer out.deinit(a);
    for (setup.materials.shapes()) |shape| {
        const count = termsForSetup(setup, shape.role);
        if (!shape.present() or count == 0) continue;
        try out.append(a, .{ .origin = .{ .core = shape.role }, .row_log = shape.log, .terms = count, .fixed_offset = shape.offsets[0], .main_offset = shape.offsets[1] });
    }
    for (std.enums.values(@import("../types.zig").Family)) |family| if (setup.bridges.at(family)) |log| {
        const count = bridgeTerms(family);
        try out.append(a, .{ .origin = .{ .bridge = family }, .row_log = log, .terms = count, .fixed_offset = setup.offset(family, 0), .main_offset = setup.offset(family, 1) });
    };
    inline for (@import("../types.zig").bulk_kinds) |kind| if (setup.bridges.bulk.at(kind)) |log| {
        try out.append(a, .{ .origin = .{ .bulk = kind }, .row_log = log, .terms = @import("bulk_projection.zig").localTerms(kind), .fixed_offset = setup.bulkOffset(kind, 0), .main_offset = setup.bulkOffset(kind, 1) });
    };
    inline for (@import("../types.zig").sponge_kinds) |kind| if (setup.bridges.sponge.at(kind)) |log| {
        try out.append(a, .{ .origin = .{ .sponge = kind }, .row_log = log, .terms = @import("sponge_projection.zig").localTerms(kind), .fixed_offset = setup.spongeOffset(kind, 0), .main_offset = setup.spongeOffset(kind, 1) });
    };
    for (0..@import("../types.zig").DWORD_INSTANCES) |k| if (setup.bridges.dwordLog(k)) |log| {
        try out.append(a, .{ .origin = .{ .dword = @intCast(k) }, .row_log = log, .terms = @import("dword_projection.zig").LOCAL_TERMS, .fixed_offset = setup.dwordOffset(k, 0), .main_offset = setup.dwordOffset(k, 1) });
    };
    return out.toOwnedSlice(a);
}

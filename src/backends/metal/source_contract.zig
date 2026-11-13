//! Backend-owned Objective-C implementation bytes used by source-level
//! architecture assertions outside this package.

const std = @import("std");
const runtime_part = @embedFile("runtime.m");
const runtime_include = "#include \"runtime/library_setup.m\"\n";
const runtime_at = blk: {
    @setEvalBranchQuota(100_000);
    break :blk std.mem.indexOf(u8, runtime_part, runtime_include).?;
};
pub const runtime = runtime_part[0..runtime_at] ++ @embedFile("runtime/library_setup.m") ++ runtime_part[runtime_at + runtime_include.len ..];
const lifecycle_part = @embedFile("runtime/lifecycle_and_tree.m");
const lifecycle_include = "#include \"tree_readback.m\"\n";
const lifecycle_at = blk: {
    @setEvalBranchQuota(100_000);
    break :blk std.mem.indexOf(u8, lifecycle_part, lifecycle_include).?;
};
pub const lifecycle_and_tree = lifecycle_part[0..lifecycle_at] ++ @embedFile("runtime/tree_readback.m") ++ lifecycle_part[lifecycle_at + lifecycle_include.len ..];
const quotient_preparation_part = @embedFile("runtime/quotient_preparation.m");
const quotient_preparation = expandInclude(quotient_preparation_part, "#include \"quotient_preparation_types.h\"\n", @embedFile("runtime/quotient_preparation_types.h"));
pub const quotients = expandInclude(@embedFile("runtime/quotients.m"), "#include \"quotient_preparation.m\"\n", quotient_preparation);

fn expandInclude(comptime part: []const u8, comptime marker: []const u8, comptime included: []const u8) []const u8 {
    @setEvalBranchQuota(100_000);
    const at = std.mem.indexOf(u8, part, marker) orelse @compileError("private runtime owner include is missing");
    return part[0..at] ++ included ++ part[at + marker.len ..];
}
pub const composition = @embedFile("runtime/composition.m");

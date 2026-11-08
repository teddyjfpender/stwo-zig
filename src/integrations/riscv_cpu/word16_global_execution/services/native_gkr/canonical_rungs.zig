//! Additive strict class roster for native-GKR. Historical flat/strict tables
//! remain frozen; the new single-shard CPU family includes both public borders.
const std = @import("std");
const Canon = @import("../../ethereum/canon_native.zig");
const Old = @import("../../ethereum/canon_native_rungs.zig");
pub const SINGLE: [Old.R]Canon.CpuVector = blk: {
    var out: [Old.R]Canon.CpuVector = undefined;
    for (0..Old.R) |r| for (&out[r], Old.CPU[0].rungs[r], Old.CPU[2].rungs[r]) |*value, first, last| {
        value.* = @max(first, last);
    };
    break :blk out;
};
pub const CPU = Old.CPU ++ [_]Old.Entry{.{ .family = .cpu_single, .rungs = &SINGLE }};
pub const TRUTH = Old.TRUTH;
pub fn cpuStructure(family: Canon.Family, rung: u32, flags: u32) ![32]u8 {
    for (CPU) |entry| if (entry.family == family) {
        if (rung >= entry.rungs.len) return error.NativeChainNotStrict;
        return Canon.cpuStructureV2(family, rung, entry.rungs[rung], flags);
    };
    return error.NativeChainNotStrict;
}
pub fn cpuRung(family: Canon.Family, vector: Canon.CpuVector) ?u32 {
    for (CPU) |entry| if (entry.family == family) return if (Canon.strictRung(entry.rungs, vector)) |r| @intCast(r) else null;
    return null;
}
test "native GKR cpu single has a complete strict first and last envelope" {
    for (SINGLE, 0..) |vector, r| {
        try std.testing.expect(Canon.dominates(vector, Old.CPU[0].rungs[r]));
        try std.testing.expect(Canon.dominates(vector, Old.CPU[2].rungs[r]));
        try std.testing.expect(vector[13] > 5 and vector[14] > 5);
        try std.testing.expectEqual(@as(?u32, @intCast(r)), cpuRung(.cpu_single, vector));
        const single = try cpuStructure(.cpu_single, @intCast(r), 0);
        const first = try cpuStructure(.cpu_first, @intCast(r), 0);
        try std.testing.expect(!std.mem.eql(u8, &single, &first));
    }
}

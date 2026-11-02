//! Concrete MAIN70 storage and affine virtual coordinates for the shared LS authority.
const std = @import("std");
const Specs = @import("../../memory_constraints.zig");
const E = @import("../../evaluation.zig");
pub const LOGICAL_MAIN = 79;
/// Retired logical columns, each an exact affine expression of stored ones.
/// 73 (b_low) = b0 - 256*b_high; both bytes keep their U8 memberships.
pub const REMOVED = [_]usize{ 1, 3, 4, 44, 45, 46, 47, 48, 73 };
pub const STORED = blk: {
    @setEvalBranchQuota(100000);
    var stored: [LOGICAL_MAIN - REMOVED.len]usize = undefined;
    var at: usize = 0;
    for (0..LOGICAL_MAIN) |logical| {
        var removed = false;
        for (REMOVED) |c| removed = removed or logical == c;
        if (!removed) {
            stored[at] = logical;
            at += 1;
        }
    }
    std.debug.assert(at == stored.len);
    break :blk stored;
};
pub const MAIN = STORED.len;
pub fn column(logical: usize) usize {
    for (STORED, 0..) |c, physical| if (c == logical) return physical;
    unreachable;
}
pub fn columns(comptime logical: []const usize) [logical.len]usize {
    @setEvalBranchQuota(100000);
    var result: [logical.len]usize = undefined;
    for (logical, &result) |c, *physical| physical.* = column(c);
    return result;
}
pub fn projectFor(comptime F: type, logical: []const F) [MAIN]F {
    std.debug.assert(logical.len == LOGICAL_MAIN);
    var physical: [MAIN]F = undefined;
    for (STORED, &physical) |c, *v| v.* = logical[c];
    return physical;
}
pub fn expandFor(comptime F: type, physical: []const F) [LOGICAL_MAIN]F {
    std.debug.assert(physical.len == MAIN);
    var logical: [LOGICAL_MAIN]F = undefined;
    for (STORED, physical) |c, v| logical[c] = v;
    var write = F.zero();
    var opcode = F.zero();
    inline for (Specs.load_specs ++ Specs.store_specs, 0..) |spec, index| {
        const flag = logical[49 + index];
        if (index >= Specs.load_specs.len) write = write.add(flag);
        opcode = opcode.add(flag.mul(q(F, @intFromEnum(spec.opcode))));
    }
    logical[1] = write;
    logical[3] = logical[12].add(logical[13].mul(q(F, 65536)));
    logical[4] = logical[68].mul(q(F, 8));
    var offset = F.zero();
    for (0..8) |j| offset = offset.add(logical[60 + j].mul(q(F, @intCast(j))));
    logical[44] = logical[4].add(offset);
    for (1..4) |j| logical[44 + j] = logical[4 + j];
    logical[48] = opcode;
    // b_low: the U8 query ranges this affine expression directly.
    logical[73] = logical[36].sub(logical[74].mul(q(F, 256)));
    return logical;
}

fn q(comptime F: type, value: u32) F {
    if (F == @import("stwo_core").fields.m31.M31) return F.fromCanonical(value);
    return E.qFor(F, value);
}

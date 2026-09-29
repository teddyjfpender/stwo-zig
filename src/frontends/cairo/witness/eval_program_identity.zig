//! Strong identity for authenticated CPU AIR kernels. Independent of execution.
const std = @import("std");
const eval = @import("eval_program.zig");

/// Hash typed fields explicitly, never padding or the 64-bit semantic selector.
/// Domain size is rebound by the claim planner and is checked by validateRange.
pub fn identity(program: eval.Program) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-cairo-cpu-air-abi-v1");
    inline for (std.meta.fields(eval.Header)) |field| {
        if (comptime !std.mem.eql(u8, field.name, "domain_log_size") and
            !std.mem.eql(u8, field.name, "semantic_hash"))
            hashValue(&hash, @field(program.header, field.name));
    }
    hashValue(&hash, program.base_consts.len);
    for (program.base_consts) |value| hashValue(&hash, value);
    hashValue(&hash, program.ext_consts.len);
    for (program.ext_consts) |value| for (value) |coordinate| hashValue(&hash, coordinate);
    hashValue(&hash, program.base_insts.len);
    for (program.base_insts) |inst| inline for (std.meta.fields(eval.BaseInst)) |field|
        hashValue(&hash, @field(inst, field.name));
    hashValue(&hash, program.ext_insts.len);
    for (program.ext_insts) |inst| inline for (std.meta.fields(eval.ExtInst)) |field|
        hashValue(&hash, @field(inst, field.name));
    hashValue(&hash, program.constraint_roots.len);
    for (program.constraint_roots) |value| hashValue(&hash, value);
    return hash.finalResult();
}
fn hashValue(hash: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    const encoded: u64 = switch (@typeInfo(@TypeOf(value))) {
        .@"enum" => @intFromEnum(value),
        .int => |info| if (info.signedness == .signed) @as(u64, @bitCast(@as(i64, value))) else @intCast(value),
        else => unreachable,
    };
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, encoded, .little);
    hash.update(&bytes);
}

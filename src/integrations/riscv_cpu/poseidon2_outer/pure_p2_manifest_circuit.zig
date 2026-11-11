//! Constrained counterpart of the new nine-limb OP manifest.
//! Entries must come from checked child circuits + receiver-owned authority.
const C = @import("full_p2_common.zig");
const M = @import("pure_p2_manifest.zig");
const F = @import("full_p2_frame.zig");
pub fn digest(ctx: *C.Context, execution: anytype, entries: anytype) !C.Hash {
    var writer = try @import("full_p2_child.zig").ReceiptWriter.init(ctx);
    try M.emit(execution, entries, &writer);
    return writer.finish();
}
pub fn drawShared(ctx: *C.Context, manifest: C.Hash) !F.Shared {
    var channel = try C.Channel.init(ctx);
    try channel.mixConstU32s(ctx, &M.DOMAIN);
    try channel.mixRoot(ctx, manifest);
    var draw = F.Draw{ .ctx = ctx, .channel = &channel };
    draw.mixU32s(&.{ 0x52414d31, 14 });
    var ram: @FieldType(F.Shared, "ram") = undefined;
    ram.offset = draw.drawSecureFelt();
    for (&ram.coefficients) |*coefficient| coefficient.* = draw.drawSecureFelt();
    draw.mixU32s(&.{ 0x4b494f31, 11 });
    const kio = @FieldType(F.Shared, "kio").draw(&draw);
    draw.mixU32s(&.{ 0x53574952, 35 });
    const wire = @FieldType(F.Shared, "wire").draw(&draw);
    try draw.finish();
    return .{ .ram = ram, .kio = kio, .wire = wire };
}

//! Finite all-external native envelope, not an invented ordinary instruction.
//! Callers still prove every retirement and the global receiver separately
//! closes PC/state, all32 registers, ROM requests, and terminal first-halt RAM.
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Frame = @import("block_v5_native_frame_v1.zig");
pub const Kind = enum(u32) { ordinary, external_with_clocks, external_frame };
pub const TAG: u32 = 0x4237424e; // B7BN
pub const VERSION: u32 = 1;
pub fn classify(shape: *const Shape, external: u32) !Kind {
    try shape.validateBlake3ExecutionWithExternal(external);
    if (shape.localZeroCustody()) return error.UnqualifiedV7NativeGeometry;
    if (shape.n_components != 0) return .ordinary;
    if (external == 0 or external != shape.total_steps or shape.public_data.clock != shape.total_steps) return error.InvalidV7ExternalNativeEnvelope;
    if (Frame.required(shape)) {
        _ = try Frame.expected(shape, external);
        return .external_frame;
    }
    for (shape.infra_descs[0..shape.n_infra]) |desc| {
        if (desc.kind != .clock_update or desc.n_rows == 0 or desc.n_columns != @import("../air/clock_update_interaction.zig").N_MAIN_COLUMNS) return error.InvalidV7ExternalNativeEnvelope;
    }
    return .external_with_clocks;
}
/// Ordinary opcode geometry needs no extra envelope discriminator. The source
/// protocol separately binds its versioned relation-layout identity.
/// External envelope classes receive their own explicit source tag.
pub fn mix(channel: anytype, kind: Kind) void {
    if (kind != .ordinary) channel.mixU32s(&.{ TAG, VERSION, @intFromEnum(kind) });
}

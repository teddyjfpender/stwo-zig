//! Stable admitted opcode support from the entire expected immutable program.
//! Observed execution census is diagnostic and cannot choose an omitted field.
const base = @import("setup.zig");
const profile = @import("../../execution_profile.zig");
const isa = @import("../../decode.zig");
/// Indexed by the RV64IM opcode domain of the full AIR (`L.fixed.OPCODES`).
/// An admitted opcode outside that domain (Zbb BINARY) has no full-AIR
/// selector, so the policy fails closed instead of indexing out of range.
pub fn derive(program: base.Program, execution: profile.Profile) ![isa.BASE_OPCODE_COUNT]bool {
    try program.validate();
    var result: [isa.BASE_OPCODE_COUNT]bool = @splat(false);
    for (program.words) |raw| {
        const instruction = profile.decode(execution, raw) catch continue;
        if (!profile.admitted(execution, instruction.opcode)) continue;
        if (!isa.isBase(instruction.opcode)) return error.UnsupportedFullAirOpcode;
        result[@intFromEnum(instruction.opcode)] = true;
    }
    return result;
}

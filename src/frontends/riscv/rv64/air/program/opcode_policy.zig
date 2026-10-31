//! Stable admitted opcode support from the entire expected immutable program.
//! Observed execution census is diagnostic and cannot choose an omitted field.
const base = @import("setup.zig");
const profile = @import("../../execution_profile.zig");
pub fn derive(program: base.Program, execution: profile.Profile) ![65]bool {
    try program.validate();
    var result: [65]bool = @splat(false);
    for (program.words) |raw| {
        const instruction = profile.decode(execution, raw) catch continue;
        if (profile.admitted(execution, instruction.opcode)) result[@intFromEnum(instruction.opcode)] = true;
    }
    return result;
}

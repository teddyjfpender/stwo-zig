//! Package-root executable boundary for the reviewed P-002 profile command.

pub fn main() void {
    @import("stwo_riscv_air_lang").modules.static_profile_registry_command.main();
}

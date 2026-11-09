//! Package-root executable boundary for the typed-AIR manifest command.

pub fn main() void {
    @import("stwo_riscv_air_lang").modules.compat_manifest_command.main();
}

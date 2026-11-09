//! Package-root executable boundary for the H-009 frontier command.

pub fn main() void {
    @import("stwo_riscv_air_lang").modules.materialization_frontier_command.main();
}

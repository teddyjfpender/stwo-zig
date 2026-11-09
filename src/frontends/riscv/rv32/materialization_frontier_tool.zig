//! Package-root executable boundary for the H-009 frontier command.

pub fn main() void {
    @import("stwo_riscv_frontend").modules.air_lang_materialization_frontier_command.main();
}

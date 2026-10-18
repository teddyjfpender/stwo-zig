//! Standalone consumer: regenerate native Tree 0 from the admitted leaf key
//! before reading any proof bytes.
pub fn main() !void {
    const recursion = @import("stwo_riscv_frontend").recursion;
    const Engine = recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
    return recursion.detached_segment_command_v1.mainWithNativeRoot(Engine);
}

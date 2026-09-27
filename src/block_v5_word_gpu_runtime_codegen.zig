//! Object-only ABI/codegen gate; functions are retained but never invoked.
//! The offline AOT tool compiles this owner without linking a GPU runtime.
const std = @import("std");
const secure = @import("backends/metal/runtime/secure_polynomial_v1.zig");
const witness = @import("frontends/riscv/prover/block_v5_word_gpu_witness_v1.zig");
const Metal = struct {
    pub const runtime = @import("backends/metal/runtime.zig");
    pub const Runtime = runtime.Runtime;
    pub const secure_polynomial_v1 = secure;
};
export fn stwo_word_gpu_runtime_codegen_gate() void {
    inline for (.{
        &secure.installAot,
        &secure.RangeInverseTable.init,
        &secure.RangeInverseTable.require,
        &secure.RangeInverseTable.deinit,
        &secure.EquationPlan.init,
        &secure.EquationPlan.prepare,
        &secure.EquationPlan.evaluate,
        &secure.EquationPlan.deinit,
        &secure.FractionPlan.init,
        &secure.FractionPlan.prepare,
        &secure.FractionPlan.generate,
        &secure.FractionPlan.deinit,
        &secure.generateWitness,
        &secure.WitnessResult.deinit,
        &witness.ForMetal(Metal).wordWitness,
        &witness.ForMetal(Metal).rangeWitness,
    }) |function| std.mem.doNotOptimizeAway(function);
}

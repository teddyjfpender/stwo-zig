test {
    _ = @import("prover/block_v5_memory_source_page_transition_test_v1.zig");
}
test "source PAGE transition: actual original program composite PAGE lane range and memory hook bodies retained" {
    const std = @import("std");
    const Recipe = @import("prover/block_v5_execution_recipe_v1.zig");
    try std.testing.expectEqual(@as(Recipe.Recipe, @enumFromInt(@import("root").BLOCK_V5_EXECUTION_RECIPE)), Recipe.canonical);
    stwo_memory_source_page_transition_body_gate();
}
pub export fn stwo_memory_source_page_transition_body_gate() void {
    const Receiver = @import("prover/block_v5_memory_source_page_transition_receiver_v1.zig");
    const Stack = @import("prover/block_v5_native_receiver_stack_v1.zig").ForCapacity(true);
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const Memory = @import("prover/block_v5_word_memory_join_impl_v1.zig").ForStack(Stack);
    const Engine = Memory.ForBackend(Cpu);
    inline for (.{ &Receiver.verify, &Receiver.Open.deinit, &Memory.admitPins, &Engine.init, &Engine.onFusedNative, &Engine.onFusedPrecompile, &Engine.finish, &Engine.deinit }) |function| @import("std").mem.doNotOptimizeAway(function);
}

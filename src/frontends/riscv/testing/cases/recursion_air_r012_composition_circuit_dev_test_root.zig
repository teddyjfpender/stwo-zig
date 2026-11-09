test {
    _ = @import("stwo_riscv_rv32").modules.recursion_air_composition_circuit;
    _ = @import("stwo_riscv_rv32").modules.recursion_air_composition_graph_recorder;
    _ = @import("recursion/air/tests/vm_air_composition_input_test.zig");
}

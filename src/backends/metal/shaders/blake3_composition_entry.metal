kernel void stwo_zig_framework_poly_v1_f17154cc136988c312ad7d9d4186fe35eee1a7e865ae0b967791e1f43e643372(
    device const uint *tree0 [[buffer(0)]],
    device const uint *tree1 [[buffer(1)]],
    device const uint *tree2 [[buffer(2)]],
    device const ulong *column_offsets [[buffer(3)]],
    device const uint *profile_parameters [[buffer(4)]],
    device const uint *relation_parameters [[buffer(5)]],
    device const uint *powers [[buffer(6)]],
    device uint *output [[buffer(7)]],
    constant uint &row_count [[buffer(8)]],
    constant uint *denominator_inverses [[buffer(9)]],
    constant uint &denominator_count [[buffer(10)]],
    uint row [[thread_position_in_grid]]) {
    if (row >= row_count) return;
    uint previous_row = riscv_previous_circle_row(row, row_count, denominator_count);
    RiscvQm31 folded = { 0u, 0u, 0u, 0u };

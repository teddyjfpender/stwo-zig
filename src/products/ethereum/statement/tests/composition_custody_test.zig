const std = @import("std");
const native = @import("stwo_riscv_frontend").recursion;
const product = @import("ethereum_frontend_component").recursion;

test "composition boundary: product preparation uses canonical native source and views" {
    try std.testing.expect(product.vm_composition_preparation.Source == native.vm_composition_preparation.Source);
    try std.testing.expect(product.vm_composition_preparation.View == native.vm_composition_preparation.View);
    try std.testing.expect(product.vm_composition_preparation.CircuitView == native.vm_composition_preparation.CircuitView);
    const Prepared = native.statement_arithmetic_preparation.Prepared;
    const PolicyPrepared = product.ethereum_statement_arithmetic_v4.Prepared;
    try std.testing.expect(@typeInfo(Prepared) == .@"opaque");
    try std.testing.expect(@typeInfo(PolicyPrepared) == .@"opaque");
    try std.testing.expect(@TypeOf(&PolicyPrepared.source) == *const fn (*const PolicyPrepared) *const Prepared);
}

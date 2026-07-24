const std = @import("std");
const exact = @import("stwo_under_test")
    .integrations
    .native_cuda
    .plonk_logup;

test {
    std.testing.refAllDecls(exact);
}

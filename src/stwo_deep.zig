const std = @import("std");
const stwo = @import("stwo.zig");

test {
    std.testing.refAllDecls(stwo);
    std.testing.refAllDeclsRecursive(stwo.core);
    std.testing.refAllDeclsRecursive(stwo.prover);
    std.testing.refAllDeclsRecursive(stwo.examples);
    std.testing.refAllDeclsRecursive(stwo.interop);
    std.testing.refAllDeclsRecursive(stwo.tracing);
}

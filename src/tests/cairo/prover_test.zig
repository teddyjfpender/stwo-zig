const std = @import("std");
const prover = @import("stwo_cairo_frontend").prover;
const rust_oracle = @import("stwo_cairo_frontend").rust_oracle;
const semantic_pack = @import("stwo_cairo_frontend").witness.semantic_pack;

test {
    std.testing.refAllDecls(prover);
    std.testing.refAllDecls(rust_oracle);
    std.testing.refAllDecls(semantic_pack);
}

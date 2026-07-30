const std = @import("std");
const source_semantic_pack = @import("stwo_cairo_frontend").witness.source_semantic_pack;

test {
    std.testing.refAllDecls(source_semantic_pack);
}

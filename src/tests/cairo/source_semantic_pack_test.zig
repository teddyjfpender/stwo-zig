const std = @import("std");
const source_semantic_pack = @import("../../frontends/cairo/witness/source_semantic_pack.zig");

test {
    std.testing.refAllDecls(source_semantic_pack);
}

pub const program = @import("program.zig");
pub const compiler = @import("compiler.zig");
pub const relation = @import("relation.zig");
pub const relation_compiler = @import("relation_compiler.zig");
pub const canonical = @import("canonical.zig");

test {
    _ = program;
    _ = compiler;
    _ = relation;
    _ = relation_compiler;
    _ = canonical;
}

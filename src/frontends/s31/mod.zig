pub const program = @import("program.zig");
pub const compiler = @import("compiler.zig");
pub const relation = @import("relation.zig");
pub const relation_compiler = @import("relation_compiler.zig");
pub const sha256d = @import("sha256d.zig");
pub const sha_chip_plan = @import("sha_chip_plan.zig");
pub const bitcoin_target = @import("bitcoin_target.zig");
pub const canonical = @import("canonical.zig");

test {
    _ = program;
    _ = compiler;
    _ = relation;
    _ = relation_compiler;
    _ = sha256d;
    _ = sha_chip_plan;
    _ = bitcoin_target;
    _ = canonical;
}

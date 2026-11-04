//! M5 rootverify: receiver VK table, root-only tree digest and policy refusals.
test {
    _ = @import("rv64_recursion/root_verify.zig");
    _ = @import("rv64_recursion/root_verify_main.zig");
}

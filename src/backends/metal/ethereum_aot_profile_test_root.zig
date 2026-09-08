test {
    _ = @import("core_aot.zig");
    _ = @import("shaders/aot_profile.zig");
    _ = @import("shared_runtime.zig");
    _ = @import("shaders/runtime_initialization_contract_test.zig");
}

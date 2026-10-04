comptime {
    _ = @import("air/guest_precompile/tests/sha256_memory_caller_test.zig");
    _ = @import("isa/sha256_compression_v1.zig");
    _ = @import("runner/guest_precompile/tests/sha256_compression_v1_test.zig");
    _ = @import("air/lang/tests/access_schedule_memory_test.zig");
    _ = @import("air/lang/tests/effects_test.zig");
}

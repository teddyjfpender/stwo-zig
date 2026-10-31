comptime {
    @import("std").testing.refAllDeclsRecursive(@import("pcs/streaming_batch_parity_test.zig"));
    @import("std").testing.refAllDeclsRecursive(@import("pcs/coefficient_storage_test.zig"));
}

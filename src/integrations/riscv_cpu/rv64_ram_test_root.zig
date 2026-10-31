test {
    _ = @import("tests/rv64_ram_diagnostic_test.zig");
    _ = @import("tests/rv64_authenticated_execution_test.zig");
    _ = @import("tests/rv64_ram_private_test.zig");
    _ = @import("tests/rv64_ram_private_hash_test.zig");
    _ = @import("tests/rv64_ram_context_test.zig");
    _ = @import("tests/rv64_ram_hash_proof_test.zig");
}

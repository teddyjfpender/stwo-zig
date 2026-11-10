//! Deliberately narrow terminal-only iteration root. Production dependencies
//! remain real; unrelated dense/pairing/leaf fixture test roots are not imported.
//! Keep the old complete OP test root and its qualification scope unchanged.
test {
    _ = @import("poseidon2_outer/native_group/terminal_blake/proof_test.zig");
    _ = @import("poseidon2_outer/native_group/terminal_blake/actual_test.zig");
    _ = @import("poseidon2_outer/native_group/terminal_blake/actual_r7_test.zig");
    _ = @import("poseidon2_outer/native_group/terminal_blake/fresh_r7_test.zig");
    _ = @import("poseidon2_outer/native_group/terminal_blake/path_preflight.zig");
}

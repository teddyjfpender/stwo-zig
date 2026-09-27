//! Focused source/ABI authority checks without compiling a prover.
comptime {
    _ = @import("shaders/abi_contract.zig");
    _ = @import("shaders/runtime_initialization_contract_test.zig");
}

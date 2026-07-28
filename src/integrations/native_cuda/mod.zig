//! Zig-owned Native CUDA frontend/backend integrations.

pub const blake = @import("blake/mod.zig");
pub const common = @import("common/mod.zig");
pub const plonk = @import("plonk/mod.zig");
pub const plonk_logup = @import("plonk_logup/mod.zig");
pub const poseidon = @import("poseidon/mod.zig");
pub const state_machine = @import("state_machine/mod.zig");
pub const wide_fibonacci = @import("wide_fibonacci/mod.zig");
pub const xor = @import("xor/mod.zig");

test "api signature: Native CUDA exposes an owned request and driver boundary" {
    comptime {
        if (@typeInfo(wide_fibonacci.request.Request) != .@"struct") {
            @compileError("wide-Fibonacci CUDA request must remain a struct");
        }
        if (@typeInfo(wide_fibonacci.NativeDriver) != .@"struct") {
            @compileError("wide-Fibonacci CUDA driver must remain a concrete type");
        }
    }
}

test {
    _ = blake;
    _ = common;
    _ = plonk;
    _ = plonk_logup;
    _ = poseidon;
    _ = state_machine;
    _ = wide_fibonacci;
    _ = xor;
}

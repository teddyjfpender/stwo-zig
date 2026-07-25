const builtin = @import("builtin");

pub const blake = @import("blake.zig");
pub const plonk = @import("plonk.zig");
pub const plonk_logup = @import("plonk_logup.zig");
pub const poseidon = @import("poseidon.zig");
pub const state_machine = @import("state_machine.zig");
pub const wide_fibonacci = @import("wide_fibonacci.zig");
pub const xor = @import("xor.zig");

comptime {
    if (builtin.is_test) {
        _ = @import("blake/session_test.zig");
        _ = @import("common/prover_transaction_test.zig");
        _ = @import("plonk/session_test.zig");
        _ = @import("poseidon/session_test.zig");
        _ = @import("state_machine/session_test.zig");
        _ = @import("wide_fibonacci/session_test.zig");
        _ = @import("xor/session_test.zig");
    }
}

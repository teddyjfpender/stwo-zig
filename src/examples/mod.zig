pub const blake = @import("blake.zig");
pub const plonk = @import("plonk.zig");
pub const plonk_logup = @import("plonk_logup.zig");
pub const poseidon = @import("poseidon.zig");
pub const state_machine = @import("state_machine.zig");
pub const wide_fibonacci = @import("wide_fibonacci.zig");
pub const xor = @import("xor.zig");

/// Narrow implementation hooks consumed by concrete accelerator integrations.
/// Public application APIs remain the seven modules above; backend packages
/// depend on these named hooks instead of reaching through owner-relative paths.
pub const backend_support = struct {
    pub const plonk = struct {
        pub const input = @import("plonk/input.zig");
    };
    pub const plonk_logup = struct {
        pub const component = @import("plonk_logup/component.zig");
        pub const input = @import("plonk_logup/input.zig");
        pub const interaction = @import("plonk_logup/interaction.zig");
    };
    pub const poseidon = struct {
        pub const component = @import("poseidon/component.zig");
        pub const input = @import("poseidon/input.zig");
        pub const interaction = @import("poseidon/interaction.zig");
    };
    pub const state_machine = struct {
        pub const input = @import("state_machine/input.zig");
        pub const statement = @import("state_machine/statement.zig");
    };
    pub const wide_fibonacci = struct {
        pub const trace = @import("wide_fibonacci/trace.zig");
    };
    pub const xor = struct {
        pub const component = @import("xor/component.zig");
        pub const input = @import("xor/input.zig");
        pub const interaction = @import("xor/interaction.zig");
    };
};

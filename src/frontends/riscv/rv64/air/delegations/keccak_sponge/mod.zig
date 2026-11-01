//! Admitted Keccak-256 sponge service (tag 0x0003_0130, ethereum_services_v3).
//!
//! Two bridge components live inside the issuing CPU proof:
//! - `call`: one row per ECALL. Consumes the CPU OWNER19 ECALL tuple, reads the
//!   four packet words, reads and writes the 25 state words through RAM14,
//!   links the old state to the first permutation and consumes the last
//!   permutation's output (IO11), and emits one local OWNER token.
//! - `perm`: one row per permutation, a contiguous run per call. Reads the
//!   message words (any alignment) through RAM14, XORs the masked and padded
//!   block into the rate lanes (byte AND table), and consumes the permutation's
//!   IO11 input and the previous output (or the call's link).
//! The permutations themselves are proven by the unchanged Keccak-f truth AIR.
//! Soundness argument: design/riscv-proving-stack/rv64-keccak-sponge-service.md.
pub const types = @import("types.zig");
pub const layout = @import("layout.zig");
pub const equations = @import("equations.zig");
pub const source = @import("source.zig");
pub const interaction = @import("interaction.zig");
pub const component = @import("component.zig");

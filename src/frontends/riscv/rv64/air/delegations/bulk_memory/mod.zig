//! Admitted bulk-memory services (memcpy with any source alignment, memset, memcmp).
//!
//! Three bridge components live inside the issuing CPU proof:
//! - `desc`: one row per ECALL. Consumes the CPU OWNER19 ECALL tuple, reads the
//!   three packet words through RAM14 and emits one local OWNER-relation token.
//! - `copy`: one row per copied word (src read + dst write, same CPU tick).
//! - `set`: one row per filled word (dst write).
//! Soundness argument: design/riscv-proving-stack/rv64-bulk-memory-service.md.
pub const types = @import("types.zig");
pub const layout = @import("layout.zig");
pub const equations = @import("equations.zig");
pub const source = @import("source.zig");
pub const interaction = @import("interaction.zig");
pub const component = @import("component.zig");

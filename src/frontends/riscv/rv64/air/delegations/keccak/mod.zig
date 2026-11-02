//! Concrete permutation-only RV64 crypto provider. CPU/RAM service bridge is separate.
pub const layout = @import("layout.zig");
pub const equations = @import("equations.zig");
pub const trace = @import("trace.zig");
pub const interaction = @import("interaction.zig");
pub const component = @import("component.zig");
pub const parallel = @import("parallel.zig");
pub const tables = @import("tables.zig");
/// Throughput-v1 (2^21/2^16 RV32 tables) multiplicities; selected by BatchPolicy.throughput_v1.
pub const throughput_counts = @import("throughput_counts.zig");
pub const batch_policy = @import("batch_policy.zig");
/// Shared semantic authority and RV32 throughput table schema (reused, not copied).
pub const authority = @import("../../../../air/guest_precompile/keccakf_authority.zig");
pub const throughput_tables = @import("../../../../air/guest_precompile/keccakf_throughput_tables_v1.zig");
pub const bridge = struct {
    pub const layout = @import("bridge/layout.zig");
    pub const equations = @import("bridge/equations.zig");
    pub const trace = @import("bridge/trace.zig");
    pub const component = @import("bridge/component.zig");
};
pub const cpu_bus = @import("cpu_bus.zig");

/// Explicit inactive adapter; legacy component links only static triple kernels.
pub const quartet_component = @import("quartet_component.zig");

pub const word16_bridge = @import("word16_bridge/mod.zig");

/// Explicit standalone prototype; no default or shared-services activation.
pub const pair2n = @import("pair2n/mod.zig");

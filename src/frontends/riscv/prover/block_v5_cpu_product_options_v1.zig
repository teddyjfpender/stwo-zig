//! Shared explicit resource/security policy. Legacy API remains typed.
pub const ForCapacity = @import("block_v5_cpu_product_options_common_v1.zig").ForCapacity;
pub const options = ForCapacity(false).options;

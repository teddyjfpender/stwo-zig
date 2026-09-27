//! Genuine capacity producer and receiver resource/security policy.
pub const options = @import("block_v5_cpu_product_options_common_v1.zig").ForCapacity(true).options;
pub const optionsWithRecursiveCompletion = @import("block_v5_cpu_product_options_common_v1.zig").ForCapacity(true).optionsWithRecursiveCompletion;

//! One installed CPU block stack. Old proof files are not relabeled.
pub const Driver = @import("block_v5_cpu_capacity_driver_v1.zig");
pub const ProductOptions = @import("block_v5_cpu_capacity_product_options_v1.zig");
pub const Detached = @import("block_v5_cpu_capacity_detached_receive_v1.zig");
pub const NativeProtocol = @import("block_v5_native_capacity_protocol_v1.zig");
pub const FusedProtocol = @import("block_v5_native_capacity_fused_proof_v1.zig");
pub const ARCHITECTURE = "block-v5-native-capacity-v1-fused-capacity-v1-open-exact-streaming";
pub const REPORT_VERSION: u32 = 2;

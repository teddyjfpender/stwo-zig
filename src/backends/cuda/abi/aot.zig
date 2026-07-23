//! Strict AOT-only module and function boundary.

const types = @import("types.zig");

pub const Stats = types.NativeAotStats;
pub const FunctionReceipt = types.NativeAotFunctionReceipt;

pub extern "c" fn stwo_native_aot_loader_create(
    exec_context: *anyopaque,
    out_loader: *?*anyopaque,
) c_int;
pub extern "c" fn stwo_native_aot_loader_destroy(loader: *anyopaque) c_int;
pub extern "c" fn stwo_native_aot_loader_stats(
    loader: *anyopaque,
    out_stats: *Stats,
) c_int;

pub extern "c" fn stwo_native_aot_function_bind(
    loader: *anyopaque,
    cache_key: u64,
    kernel_name: [*:0]const u8,
    grid: *const [3]u32,
    block: *const [3]u32,
    dynamic_shared_bytes: u32,
    argument_count: u32,
    out_function: *?*anyopaque,
    out_receipt: *FunctionReceipt,
) c_int;
pub extern "c" fn stwo_native_aot_function_launch(
    function: *anyopaque,
    arguments: [*]const ?*anyopaque,
    argument_count: u32,
) c_int;
pub extern "c" fn stwo_native_aot_function_destroy(function: *anyopaque) c_int;

//! Strict AOT-only module and function boundary.

const types = @import("types.zig");

pub const Stats = types.NativeAotStats;
pub const VerificationReceipt = types.NativeAotVerificationReceipt;
pub const FunctionReceipt = types.NativeAotFunctionReceipt;
pub const ModuleGlobalsReceipt = types.NativeAotModuleGlobalsReceipt;

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
    abi_schema: u32,
    kernel_name: [*:0]const u8,
    grid: *const [3]u32,
    block: *const [3]u32,
    dynamic_shared_bytes: u32,
    argument_count: u32,
    out_function: *?*anyopaque,
    out_receipt: *FunctionReceipt,
) c_int;
pub extern "c" fn stwo_native_aot_function_bind_with_globals(
    loader: *anyopaque,
    cache_key: u64,
    abi_schema: u32,
    expected_module_globals: u32,
    kernel_name: [*:0]const u8,
    grid: *const [3]u32,
    block: *const [3]u32,
    dynamic_shared_bytes: u32,
    argument_count: u32,
    out_function: *?*anyopaque,
    out_receipt: *FunctionReceipt,
) c_int;
pub extern "c" fn stwo_native_aot_function_publish_pedersen_w18(
    function: *anyopaque,
    columns: *const [56]u64,
    row_count: u32,
    table_identity: *const [32]u8,
    out_receipt: *ModuleGlobalsReceipt,
) c_int;
pub extern "c" fn stwo_native_aot_function_launch(
    function: *anyopaque,
    arguments: [*]const ?*anyopaque,
    argument_count: u32,
) c_int;
pub extern "c" fn stwo_native_aot_function_destroy(function: *anyopaque) c_int;

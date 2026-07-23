//! Exact resident-runtime C ABI used by repository-owned Zig code.

const types = @import("types.zig");

pub extern "c" fn stwo_static_cuda_module_build_identity(out: *[32]u8) c_int;
pub extern "c" fn stwo_zig_cuda_aot_entry_count() usize;
pub extern "c" fn stwo_cuda_device_snapshot(
    out_count: *u32,
    out_current: *u32,
    out_sm_major: *u32,
    out_sm_minor: *u32,
) c_int;

pub extern "c" fn stwo_exec_context_create(out_handle: *?*anyopaque) c_int;
pub extern "c" fn stwo_exec_context_destroy(handle: *anyopaque) c_int;
pub extern "c" fn stwo_exec_context_sync(handle: *anyopaque) c_int;
pub extern "c" fn stwo_exec_context_pool_current(
    handle: *anyopaque,
    used_current: *usize,
    reserved_current: *usize,
) c_int;
pub extern "c" fn stwo_exec_context_stream(
    handle: *anyopaque,
    out_stream: *?*anyopaque,
) c_int;
pub extern "c" fn stwo_exec_context_device(
    handle: *anyopaque,
    out_device: *c_int,
) c_int;
pub extern "c" fn stwo_exec_context_lane_count(
    handle: *anyopaque,
    out_count: *u32,
) c_int;
pub extern "c" fn stwo_exec_context_join_all_lanes(handle: *anyopaque) c_int;

pub extern "c" fn stwo_exec_context_alloc_u32(
    handle: *anyopaque,
    count: usize,
    out_ptr: *?[*]u32,
) c_int;
pub extern "c" fn stwo_exec_context_free_u32(
    handle: *anyopaque,
    ptr: [*]u32,
) c_int;
pub extern "c" fn stwo_exec_context_memset_async(
    handle: *anyopaque,
    dst: *anyopaque,
    value: c_int,
    bytes: usize,
) c_int;
pub extern "c" fn stwo_exec_context_fill_u32_async(
    handle: *anyopaque,
    dst: [*]u32,
    value: u32,
    count: usize,
) c_int;
pub extern "c" fn stwo_exec_context_memcpy_d2d_async(
    handle: *anyopaque,
    dst: *anyopaque,
    src: *const anyopaque,
    bytes: usize,
) c_int;
pub extern "c" fn stwo_exec_context_memcpy_h2d_async(
    handle: *anyopaque,
    dst: *anyopaque,
    src: *const anyopaque,
    bytes: usize,
) c_int;
pub extern "c" fn stwo_exec_context_memcpy_d2h_async(
    handle: *anyopaque,
    dst: *anyopaque,
    src: *const anyopaque,
    bytes: usize,
) c_int;

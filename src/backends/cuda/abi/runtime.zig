//! Exact resident-runtime C ABI used by repository-owned Zig code.

const types = @import("types.zig");

pub extern "c" fn stwo_static_cuda_module_build_identity(out: *[32]u8) c_int;
pub extern "c" fn stwo_zig_cuda_aot_entry_count() usize;
pub extern "c" fn stwo_cuda_execution_provider() u32;
pub extern "c" fn stwo_cuda_device_snapshot(
    out_count: *u32,
    out_current: *u32,
    out_sm_major: *u32,
    out_sm_minor: *u32,
) c_int;
pub extern "c" fn stwo_cuda_platform_snapshot(
    out: *types.PlatformSnapshot,
) c_int;

pub const context_options_version: u32 = 1;
pub const max_context_lanes: u32 = 4;
pub const max_context_dependencies: u32 = 64;
pub const current_device: u32 = @import("std").math.maxInt(u32);

pub const ContextOptions = extern struct {
    version: u32 = context_options_version,
    device_ordinal: u32 = current_device,
    lane_count: u32 = 1,
    dependency_capacity: u32 = 0,

    pub fn validate(self: ContextOptions) error{ InvalidState, InvalidExecutionLaneCount }!void {
        if (self.version != context_options_version) return error.InvalidState;
        if (self.lane_count == 0 or self.lane_count > max_context_lanes or self.dependency_capacity > max_context_dependencies)
            return error.InvalidExecutionLaneCount;
    }
};

pub const DependencyToken = extern struct {
    context_identity: u64,
    generation: u64,
    slot: u32,
    producer_lane: u32,
};

comptime {
    if (@sizeOf(ContextOptions) != 16 or @offsetOf(ContextOptions, "version") != 0 or @offsetOf(ContextOptions, "device_ordinal") != 4 or @offsetOf(ContextOptions, "lane_count") != 8 or @offsetOf(ContextOptions, "dependency_capacity") != 12)
        @compileError("CUDA context options ABI mismatch");
    if (@sizeOf(DependencyToken) != 24 or @offsetOf(DependencyToken, "context_identity") != 0 or @offsetOf(DependencyToken, "generation") != 8 or @offsetOf(DependencyToken, "slot") != 16 or @offsetOf(DependencyToken, "producer_lane") != 20)
        @compileError("CUDA dependency token ABI mismatch");
}

// On cleanup failure, a non-null out_handle is a teardown-only owner even
// when status is nonzero. Context.openOptions retains this typed outcome.
pub extern "c" fn stwo_exec_context_create_options(options: *const ContextOptions, out_handle: *?*anyopaque) c_int;
pub extern "c" fn stwo_exec_context_identity(handle: *anyopaque, out_identity: *u64) c_int;
pub extern "c" fn stwo_exec_context_lane_stream(handle: *anyopaque, lane: u32, out_stream: *?*anyopaque) c_int;
pub extern "c" fn stwo_exec_context_dependency_record(handle: *anyopaque, lane: u32, slot: u32, out_token: *DependencyToken) c_int;
pub extern "c" fn stwo_exec_context_dependency_wait(handle: *anyopaque, lane: u32, token: *const DependencyToken) c_int;
pub extern "c" fn stwo_exec_context_dependency_release(handle: *anyopaque, token: *const DependencyToken) c_int;
pub extern "c" fn stwo_exec_context_dependencies_reset(handle: *anyopaque) c_int;

pub extern "c" fn stwo_exec_context_create(out_handle: *?*anyopaque) c_int;
pub extern "c" fn stwo_exec_context_destroy(handle: *anyopaque) c_int;
pub extern "c" fn stwo_exec_context_sync(handle: *anyopaque) c_int;
pub extern "c" fn stwo_exec_context_memory_info(
    handle: *anyopaque,
    free_bytes: *usize,
    total_bytes: *usize,
) c_int;
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
pub extern "c" fn stwo_exec_context_timing_begin(
    handle: *anyopaque,
    out_interval_capacity: *u32,
) c_int;
pub extern "c" fn stwo_exec_context_timing_mark(handle: *anyopaque) c_int;
pub extern "c" fn stwo_exec_context_timing_elapsed(
    handle: *anyopaque,
    out_elapsed_ms: [*]f32,
    capacity: u32,
    out_count: *u32,
) c_int;
pub extern "c" fn stwo_exec_context_nvtx_push(
    handle: *anyopaque,
    label: [*:0]const u8,
) c_int;
pub extern "c" fn stwo_exec_context_nvtx_pop(handle: *anyopaque) c_int;
pub extern "c" fn stwo_graph_capture_begin(handle: *anyopaque) c_int;
pub extern "c" fn stwo_graph_capture_end(
    handle: *anyopaque,
    out_exec: *?*anyopaque,
    out_kernel_nodes: *u64,
) c_int;
pub extern "c" fn stwo_graph_capture_abort(handle: *anyopaque) c_int;
pub extern "c" fn stwo_graph_launch(
    exec_handle: *anyopaque,
    context_handle: *anyopaque,
) c_int;
pub extern "c" fn stwo_graph_destroy(exec_handle: *anyopaque) c_int;

pub extern "c" fn stwo_exec_context_alloc_u32(
    handle: *anyopaque,
    count: usize,
    out_ptr: *?[*]u32,
) c_int;
pub extern "c" fn stwo_exec_context_free_u32(
    handle: *anyopaque,
    ptr: [*]u32,
) c_int;
pub extern "c" fn stwo_exec_context_validate_allocation(
    handle: *anyopaque,
    pointer: *const anyopaque,
    required_bytes: usize,
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

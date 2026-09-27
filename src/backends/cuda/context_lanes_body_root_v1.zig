//! SEMANTIC / OBJECT ONLY. Retains real native ABI paths; never execute exports.
const Context = @import("runtime/context.zig").NativeContext;
const Options = @import("abi/runtime.zig").ContextOptions;

pub export fn stwo_cuda_lane_context_open_body_gate(options: *const Options) void {
    var construction = Context.openOptions(options.*);
    construction.deinit() catch return;
}

pub export fn stwo_cuda_lane_context_dependency_body_gate(owner: *Context, producer: u32, consumer: u32, slot: u32) void {
    const producer_lane = owner.lane(producer) catch return;
    const consumer_lane = owner.lane(consumer) catch return;
    var dependency = owner.recordDependency(producer_lane, slot) catch return;
    owner.waitDependency(consumer_lane, dependency) catch return;
    owner.releaseDependency(&dependency) catch return;
}

pub export fn stwo_cuda_lane_context_teardown_body_gate(owner: *Context) void {
    owner.abortProof() catch return;
    owner.joinLanes() catch return;
    owner.close() catch return;
}

pub export fn stwo_cuda_lane_context_legacy_body_gate() void {
    var owner = Context.open() catch return;
    owner.close() catch return;
}

pub export fn stwo_cuda_lane_context_guard_body_gate(owner: *Context, lane: *const Context.Lane, token: *const Context.Dependency) bool {
    owner.validateLane(lane.*) catch return false;
    owner.validateDependency(token.*) catch return false;
    return true;
}

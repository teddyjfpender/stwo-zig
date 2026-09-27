//! Real default/capacity base+Complete+detached Complete bodies retained.
//! Nothing is invoked. This is codegen qualification, never proof validation.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const V3 = @import("prover/block_v5_global_receiver_v1.zig");
const Capacity = @import("prover/block_v5_capacity_global_receiver_v1.zig");
const FileLoader = struct {
    bytes: []const u8,
    pub fn load(self: @This(), a: std.mem.Allocator) ![]u8 {
        return a.dupe(u8, self.bytes);
    }
};
fn Bodies(comptime Module: type) type {
    return struct {
        const Api = Module.ForBackend(Cpu);
        fn globals(a: std.mem.Allocator, pins: Module.Pins, inputs: Module.Inputs) anyerror!Module.VerifiedGlobals {
            return Api.verifyGlobals(a, pins, inputs);
        }
        fn complete(a: std.mem.Allocator, pins: Module.Pins, inputs: Module.Inputs, recursive: Module.RecursivePins, loader: FileLoader) anyerror!Module.CompleteBundle {
            return Api.verifyComplete(a, pins, inputs, recursive, loader);
        }
        fn detached(a: std.mem.Allocator, pins: Module.Pins, inputs: Module.Inputs, recursive: Module.RecursivePins, files: Module.DetachedForest) anyerror!Module.CompleteBundle {
            return Api.verifyCompleteDetached(a, pins, inputs, recursive, files);
        }
    };
}
fn JoinBodies(comptime Stack: type) type {
    return struct {
        const Memory = @import("prover/block_v5_word_memory_join_impl_v1.zig").ForStack(Stack).ForBackend(Cpu);
        const Tables = @import("prover/block_v5_native_table_join_impl_v1.zig").ForStack(Stack).ForBackend(Cpu);
        fn memorySeparate(self: *Memory, a: std.mem.Allocator, index: u32, pin: Stack.Programs.InstancePin, fresh: *const Stack.Native.OpenReceipt) anyerror!void {
            try self.onNative(a, index, pin, fresh);
        }
        fn tableSeparate(self: *Tables, a: std.mem.Allocator, index: u32, pin: Stack.Programs.InstancePin, fresh: *const Stack.Native.OpenReceipt) anyerror!void {
            try self.onNative(a, index, pin, fresh);
        }
    };
}
export fn stwo_capacity_global_body_gate() void {
    inline for (.{ V3, Capacity }) |Module| {
        const Gate = Bodies(Module);
        inline for (.{ &Gate.globals, &Gate.complete, &Gate.detached, &Module.CompleteBundle.deinit }) |function| std.mem.doNotOptimizeAway(function);
    }
    inline for (.{ false, true }) |capacity| {
        const Stack = @import("prover/block_v5_native_receiver_stack_v1.zig").ForCapacity(capacity);
        const Joins = JoinBodies(Stack);
        inline for (.{ &Joins.memorySeparate, &Joins.tableSeparate }) |function| std.mem.doNotOptimizeAway(function);
    }
}

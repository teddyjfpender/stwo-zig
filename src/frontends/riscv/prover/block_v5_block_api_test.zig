//! Compile the concrete producer and fresh receiver paths without generating
//! an extra proof. Real family gates qualify their components separately.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Producer = @import("block_v5_block_producer_v1.zig").ForBackend(Cpu);
const Receiver = @import("block_v5_block_receiver_v1.zig").ForBackend(Cpu);
const Programs = @import("block_v5_program_native_batch_receiver_v1.zig").ForBackend(Cpu);
const LightweightProducer = @import("block_v5_block_producer_v1.zig").ForLightweightBackend(Cpu);
const LightweightReceiver = @import("block_v5_block_receiver_v1.zig").ForLightweightBackend(Cpu);

test "block-v5 concrete producer and open receiver entrypoints compile" {
    const producer: *const @TypeOf(Producer.prove) = &Producer.prove;
    const receiver: *const @TypeOf(Receiver.verifyOpen) = &Receiver.verifyOpen;
    const programs: *const @TypeOf(Programs.verifyWithExtensions) = &Programs.verifyWithExtensions;
    std.mem.doNotOptimizeAway(producer);
    std.mem.doNotOptimizeAway(receiver);
    std.mem.doNotOptimizeAway(programs);
    const lightweight_producer: *const @TypeOf(LightweightProducer.prove) = &LightweightProducer.prove;
    const lightweight_receiver: *const @TypeOf(LightweightReceiver.verifyGlobals) = &LightweightReceiver.verifyGlobals;
    std.mem.doNotOptimizeAway(lightweight_producer);
    std.mem.doNotOptimizeAway(lightweight_receiver);
    const native_hooks: *const @TypeOf(LightweightProducer.proveWithHooks) = &LightweightProducer.proveWithHooks;
    const Callers = @import("block_v5_precompile_batch_v1.zig").ForBackend(Cpu);
    const caller_hooks: *const @TypeOf(Callers.proveWithHooks) = &Callers.proveWithHooks;
    std.mem.doNotOptimizeAway(native_hooks);
    std.mem.doNotOptimizeAway(caller_hooks);
    const CallerStage = @import("block_v5_precompile_lookup_stage_v1.zig").ForBackend(Cpu);
    const caller_stage_hooks: *const @TypeOf(CallerStage.hooks) = &CallerStage.hooks;
    std.mem.doNotOptimizeAway(caller_stage_hooks);
    try std.testing.expect(!@hasDecl(Receiver, "verifyComplete"));
    const complete: *const @TypeOf(compileComplete) = &compileComplete;
    std.mem.doNotOptimizeAway(complete);
    try std.testing.expect(@hasDecl(LightweightReceiver, "verifyComplete"));
    const detached: *const @TypeOf(LightweightReceiver.verifyCompleteDetached) = &LightweightReceiver.verifyCompleteDetached;
    std.mem.doNotOptimizeAway(detached);
    const PackedReplay = @import("block_v5_word_memory_replay_v1.zig").ForBackend(Cpu);
    const replay_collect: *const @TypeOf(PackedReplay.collect) = &PackedReplay.collect;
    const replay_prove: *const @TypeOf(PackedReplay.prove) = &PackedReplay.prove;
    std.mem.doNotOptimizeAway(replay_collect);
    std.mem.doNotOptimizeAway(replay_prove);
}

const Global = @import("block_v5_global_receiver_v1.zig");
const CompileLoader = struct {
    pub fn load(_: @This(), _: std.mem.Allocator) ![]u8 {
        return error.MissingCompileOnlyOuterProof;
    }
};
fn compileComplete(a: std.mem.Allocator, pins: Global.Pins, inputs: Global.Inputs, recursive: Global.RecursivePins) !Global.CompleteBundle {
    return LightweightReceiver.verifyComplete(a, pins, inputs, recursive, CompileLoader{});
}

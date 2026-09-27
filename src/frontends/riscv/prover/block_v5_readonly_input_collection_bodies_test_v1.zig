//! Actual typed bodies are retained; no function below is invoked by fixtures.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Codec = @import("block_v5_cpu_stark_codec_v1.zig");
const Store = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(true);
fn saveNative(store: *Store.Store, index: u32, proof: *Codec.ProofFor(.native_readonly)) !void {
    return store.put(.native_readonly, index, proof);
}
fn saveCaller(store: *Store.Store, index: u32, proof: *Codec.ProofFor(.caller_readonly)) !void {
    return store.put(.caller_readonly, index, proof);
}
fn encodeNative(a: std.mem.Allocator, proof: *const Codec.ProofFor(.native_readonly), expected: Codec.Expected, limits: Codec.Limits) ![]u8 {
    return Codec.encode(.native_readonly, a, proof, expected, limits);
}
fn decodeNative(a: std.mem.Allocator, bytes: []const u8, expected: Codec.Expected, limits: Codec.Limits) !Codec.ProofFor(.native_readonly) {
    return Codec.decode(.native_readonly, a, bytes, expected, limits);
}
fn encodeCaller(a: std.mem.Allocator, proof: *const Codec.ProofFor(.caller_readonly), expected: Codec.Expected, limits: Codec.Limits) ![]u8 {
    return Codec.encode(.caller_readonly, a, proof, expected, limits);
}
fn decodeCaller(a: std.mem.Allocator, bytes: []const u8, expected: Codec.Expected, limits: Codec.Limits) !Codec.ProofFor(.caller_readonly) {
    return Codec.decode(.caller_readonly, a, bytes, expected, limits);
}
test "readonly collection: actual canonical collection staged replay fresh closure and transport bodies retained" {
    const Native = @import("block_v5_native_capacity_readonly_stage_v1.zig").ForBackend(Cpu);
    const Caller = @import("block_v5_caller_pipeline_v1.zig").ForBackend(Cpu);
    const Global = @import("block_v5_capacity_global_receiver_v1.zig").ForBackend(Cpu);
    inline for (.{
        @import("block_v5_cpu_collect_v1.zig").ForCapacity(true).collect,
        @import("block_v5_cpu_collect_v1.zig").ForCapacity(false).collect,
        @import("block_v5_cpu_assembly_v1.zig").ForCapacity(true).assemble,
        @import("block_v5_cpu_assembly_v1.zig").ForCapacity(false).assemble,
        Native.collect,
        Native.prove,
        Caller.collectSegmentWithStaging,
        Caller.proveStaged,
        Global.verifyCompleteDetached,
        @import("block_v5_readonly_input_receiver_v1.zig").ForCapacity(true).ForBackend(Cpu).verifyNativeOwned,
        @import("block_v5_readonly_input_receiver_v1.zig").ForBackend(Cpu).verifyNativeOwned,
        @import("block_v5_cpu_bundle_policy_v1.zig").ForCapacity(true).collect,
        saveNative,
        saveCaller,
        encodeNative,
        decodeNative,
        encodeCaller,
        decodeCaller,
    }) |body| {
        const pointer: *const @TypeOf(body) = &body;
        std.mem.doNotOptimizeAway(pointer);
    }
}

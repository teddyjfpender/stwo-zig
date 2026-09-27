//! Metadata and retained production bodies only; no positive proof fixtures.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Stack = @import("block_v5_native_receiver_stack_v1.zig").ForCapacity(true);
const Memory = @import("block_v5_word_memory_join_impl_v1.zig").ForStack(Stack);
const PageMemory = @import("block_v5_memory_source_page_memory_init_v1.zig");
const Admission = @import("block_v5_memory_source_page_transition_admission_v1.zig");
test "PAGE global receive: actual public input length and digest remain independently bound" {
    const input = [_]u8{ 0, 255, 128, 42 };
    const digest = @import("block_v5_initial_sources_v1.zig").sha256(&input);
    try Admission.requirePublicInput(input.len, digest, &input);
    try std.testing.expectError(error.UntrustedV5PublicInput, Admission.requirePublicInput(input.len - 1, digest, &input));
    var altered = input;
    altered[2] ^= 1;
    try std.testing.expectError(error.UntrustedV5PublicInput, Admission.requirePublicInput(input.len, digest, &altered));
    var altered_digest = digest;
    altered_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5PublicInput, Admission.requirePublicInput(input.len, altered_digest, &input));
    try Admission.requirePublicInput(0, @import("block_v5_initial_sources_v1.zig").sha256(""), "");
}
test "PAGE global receive: legacy memory rejected before source owner allocator or proofs" {
    var pins: Memory.Pins = undefined;
    pins.memory = .{ .word = undefined };
    var denied = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.NoncanonicalSourcePageTransitionMemory, PageMemory.ForStack(Stack).init(Cpu, denied.allocator(), pins, undefined, undefined, undefined, undefined));
    try std.testing.expectEqual(@as(usize, 0), denied.alloc_index);
}
test "PAGE global receive: real source selected original global accounting and detached forest bodies retained" {
    const Global = @import("block_v5_capacity_global_receiver_v1.zig").ForBackend(Cpu);
    const Legacy = @import("block_v5_global_receiver_v1.zig").ForBackend(Cpu);
    inline for (.{ &Global.verifyGlobals, &Global.verifyGlobalsWithSourcePages, &Global.verifyCompleteDetached, &Global.verifyCompleteDetachedWithSourcePages, &Legacy.verifyGlobals, &Legacy.verifyCompleteDetached }) |body| std.mem.doNotOptimizeAway(body);
}

const std = @import("std");
const Packet = @import("integrations/riscv_cuda/resident_parent_child_packet_v1.zig");
test "resident child packet full typed codegen" {
    std.mem.doNotOptimizeAway(&Packet.Routes.init);
    std.mem.doNotOptimizeAway(&Packet.Owned.initNative);
    std.mem.doNotOptimizeAway(&Packet.Bindings.composition);
    std.mem.doNotOptimizeAway(&Packet.Bindings.deep);
    std.mem.doNotOptimizeAway(&Packet.Bindings.fri);
}
test "resident child packet preserves untrusted values module" {
    _ = Packet;
}

test "resident child transcript full typed codegen" {
    std.mem.doNotOptimizeAway(&@import("integrations/riscv_cuda/resident_parent_child_transcript_v1.zig").Owned.initNative);
}

test "resident child frames full typed codegen" {
    std.mem.doNotOptimizeAway(&@import("integrations/riscv_cuda/resident_parent_child_frames_v1.zig").Owned.init);
}

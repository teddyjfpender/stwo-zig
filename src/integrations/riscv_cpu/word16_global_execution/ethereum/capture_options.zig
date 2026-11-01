//! Producer-only operational choices. No field enters proof/statement identity.
const std = @import("std");
const Capture = @import("capture.zig");
const Pool = @import("stwo_prover_engine").work_pool.WorkPool;
pub const Options = struct {
    max_inflight_packets: u8 = 1,
    packet_heap_bytes: usize = 512 << 20,
    max_inflight_packet_heap_bytes: usize = 1 << 30,
    max_inflight_wire_bytes: u64 = 1 << 30,
    pub fn validate(self: Options) !void {
        if ((self.max_inflight_packets != 1 and self.max_inflight_packets != 2) or self.packet_heap_bytes == 0 or self.packet_heap_bytes > self.max_inflight_packet_heap_bytes or self.max_inflight_wire_bytes == 0) return error.InvalidEthereumCaptureOptions;
    }
    pub fn isDefault(self: Options) bool {
        return std.meta.eql(self, Options{});
    }
    pub fn forPool(self: Options, pool: *Pool) Capture.Options {
        return .{ .pool = pool, .max_inflight_packets = self.max_inflight_packets, .packet_heap_bytes = self.packet_heap_bytes, .max_inflight_packet_heap_bytes = self.max_inflight_packet_heap_bytes, .max_inflight_wire_bytes = self.max_inflight_wire_bytes };
    }
};

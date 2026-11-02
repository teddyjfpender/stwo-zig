//! Explicit owned-payload inventory, not RSS or a process admission bound.
//! Immutable program/setup is borrowed and intentionally excluded.
const std = @import("std");
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Advice = @import("../services/collector.zig").Advice;
fn bytes(values: anytype) usize {
    return std.mem.sliceAsBytes(values).len;
}
pub const NativePayload = struct {
    cpu_metadata: usize = 0,
    cpu_main_and_interaction: usize = 0,
    cpu_counts: usize = 0,
    cpu_capture_records_capacity: usize = 0,
    family_facts: usize = 0,
    jalr_payload: usize = 0,
    pub fn total(self: NativePayload) usize {
        return self.cpu_metadata + self.cpu_main_and_interaction + self.cpu_counts + self.cpu_capture_records_capacity + self.family_facts + self.jalr_payload;
    }
};
pub fn native(p: *const Native) NativePayload {
    var result = NativePayload{};
    if (p.cpu) |cpu| {
        result.cpu_metadata = bytes(cpu.metadata);
        result.cpu_main_and_interaction = bytes(cpu.main) + bytes(cpu.interaction);
        result.cpu_counts = bytes(cpu.rom_counts) + bytes(cpu.counts16) + bytes(cpu.counts8);
        result.cpu_capture_records_capacity = cpu.functions.capacity * @sizeOf(@TypeOf(cpu.functions.items[0])) + cpu.memory.capacity * @sizeOf(@TypeOf(cpu.memory.items[0])) + cpu.services.capacity * @sizeOf(@TypeOf(cpu.services.items[0]));
    }
    result.family_facts = bytes(p.alu.facts) + bytes(p.alu.weights) + bytes(p.binary.facts) + bytes(p.binary.weights) + bytes(p.shift) + bytes(p.shift_weights) + bytes(p.division) + bytes(p.multiplication);
    if (p.jalr) |j| result.jalr_payload = bytes(j.facts) + bytes(j.fixed) + bytes(j.main) + bytes(j.interaction);
    return result;
}
pub const AdvicePayload = struct {
    ordinary_events: usize = 0,
    service_calls: usize = 0,
    public_cells: usize = 0,
    outer_slice_headers: usize = 0,
    pub fn total(self: AdvicePayload) usize {
        return self.ordinary_events + self.service_calls + self.public_cells + self.outer_slice_headers;
    }
};
pub fn advice(a: *const Advice) AdvicePayload {
    var result = AdvicePayload{ .public_cells = bytes(a.initial) + bytes(a.terminal), .outer_slice_headers = bytes(a.events) + bytes(a.keccak) + bytes(a.secp) };
    for (a.events) |events| result.ordinary_events += bytes(events);
    for (a.keccak) |calls| result.service_calls += bytes(calls);
    for (a.secp) |families| for (families) |calls| {
        result.service_calls += bytes(calls);
    };
    return result;
}

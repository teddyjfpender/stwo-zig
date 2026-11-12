//! Canonical nominal types and callable signatures consumed across owners.
const std = @import("std");
const api = @import("../mod.zig");

test "C3 canonical API identity: ISA machine and host types" {
    try std.testing.expect(api.machine.cpu.Cpu == @import("../runner/cpu.zig").Cpu);
    try std.testing.expect(api.machine.memory.Memory == @import("../runner/memory.zig").Memory);
    try std.testing.expect(api.machine.trace_row.TraceRow == @import("../runner/trace_row.zig").TraceRow);
    try std.testing.expect(api.host.interface.HostInterface == @import("../host/interface.zig").HostInterface);
}

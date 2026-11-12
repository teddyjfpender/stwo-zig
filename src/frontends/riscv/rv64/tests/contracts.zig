//! Canonical nominal types and callable signatures consumed across owners.
const std = @import("std");
const api = @import("../mod.zig");

test "C3 canonical API identity: RV64 machine memory and session types" {
    try std.testing.expect(api.machine.Cpu == @import("../machine.zig").Cpu);
    try std.testing.expect(api.memory.Memory == @import("../memory.zig").Memory);
    try std.testing.expect(api.session.Session == @import("../session.zig").Session);
}

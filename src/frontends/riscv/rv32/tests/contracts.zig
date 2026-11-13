//! Canonical nominal types and callable signatures consumed across owners.
const std = @import("std");
const api = @import("../mod.zig");

test "C3 canonical API identity: native results and statement types" {
    try std.testing.expect(api.execution.base_result.RunResult == @import("../runner/base_result.zig").RunResult);
    try std.testing.expect(api.air.statement.RiscVStatement == @import("../air/statement.zig").RiscVStatement);
}

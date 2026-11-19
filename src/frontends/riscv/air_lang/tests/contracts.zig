//! Canonical nominal types and callable signatures consumed across owners.
const std = @import("std");
const api = @import("../mod.zig");

test "C3 canonical API identity: authoring IR and source types" {
    try std.testing.expect(api.ir.Arena == @import("../ir/ir.zig").Arena);
    try std.testing.expect(api.source.SourceSpan == @import("../ir/source.zig").SourceSpan);
    try std.testing.expect(api.framework.control_row.Row == @import("../framework/control_row.zig").Row);
}

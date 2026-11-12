//! Canonical nominal types and callable signatures consumed across owners.
const std = @import("std");
const api = @import("../mod.zig");

test "C3 canonical API identity: native sample-layout type" {
    const exported = api.vm_composition_graph_support.ForExtension(null);
    const owned = @import("../vm_composition_graph_support.zig").ForExtension(null);
    try std.testing.expect(exported.SampleLayoutV2 == owned.SampleLayoutV2);
}

//! Parent PCS geometry is reconstructed from its independently admitted key.
const std = @import("std");
const components = @import("../blake3_native_parent_components.zig");
const shared = @import("blake3_execution_deep.zig");
pub fn prepare(a: std.mem.Allocator, admission: anytype, capture: *const @import("../blake3_native_parent_verifier.zig").Verified) !shared.Prepared {
    try capture.validate(admission, admission.expected_id);
    const owner = try components.Owned.init(a, admission);
    defer owner.deinit();
    try owner.bind(capture.relations, capture.claims);
    const logs = [3][]const u32{ owner.columns[0].items, owner.columns[1].items, owner.columns[2].items };
    return shared.prepareComponents(a, owner.admitted(), logs, try admission.config(), &capture.capture);
}

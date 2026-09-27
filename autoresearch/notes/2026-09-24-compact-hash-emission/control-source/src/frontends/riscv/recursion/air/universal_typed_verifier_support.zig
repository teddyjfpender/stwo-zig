//! Compatibility exports for the shared core-only point helpers.
pub const sampledSecure = @import("../../air/component_point_support.zig").sampledSecure;
pub const secureAt = @import("../../air/component_point_support.zig").secureAt;
pub const emptyOrFilledLogs = @import("../../air/component_point_support.zig").emptyOrFilledLogs;
pub const currentPointColumns = @import("../../air/component_point_support.zig").currentPointColumns;
pub const freePointColumns = @import("../../air/component_point_support.zig").freePointColumns;
pub const checkedEnd = @import("../../air/component_point_support.zig").checkedEnd;

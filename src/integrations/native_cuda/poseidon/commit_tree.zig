//! Compatibility export for the shared resident commitment builder.

const common = @import("../common/commit_tree.zig");

pub const BuilderFor = common.BuilderFor;
pub const Error = common.Error;
pub const validateLayout = common.validateLayout;

//! Backend-independent Cairo product command and lifecycle support.

pub const application = @import("application.zig");
pub const cli = @import("cli.zig");
pub const execution_adapter = @import("execution_adapter.zig");
pub const identity = @import("identity.zig");
pub const preprocessed_cache = @import("preprocessed_cache.zig");
pub const profile = @import("profile.zig");

test {
    _ = application;
    _ = cli;
    _ = execution_adapter;
    _ = identity;
    _ = preprocessed_cache;
    _ = profile;
}

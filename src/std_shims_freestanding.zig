//! Freestanding std-shims entrypoint.
const shims = @import("std_shims/mod.zig");

pub const verifier_profile = shims.verifier_profile;

test {
    @import("std").testing.refAllDecls(@This());
}

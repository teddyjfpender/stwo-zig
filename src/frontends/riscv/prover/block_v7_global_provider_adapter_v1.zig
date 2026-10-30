//! Original ROM/lookup equations under the explicit v7 whole-execution epoch.
//! No v5 seal or receipt is manufactured. Returned claims remain open until
//! actual native/caller sources and every v7 provider close in the receiver.
pub const Program = @import("block_v7_program_provider_v1.zig");
pub const Lookup = @import("block_v7_lookup_provider_v1.zig");
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const Program = @import("block_v7_program_provider_v1.zig").ForBackend(Backend);
        pub const Lookup = @import("block_v7_lookup_provider_v1.zig").ForBackend(Backend);
    };
}

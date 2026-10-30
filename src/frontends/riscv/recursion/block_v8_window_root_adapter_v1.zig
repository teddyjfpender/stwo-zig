//! Exact verifier machine for an independently admitted closed B8 window root.
pub const PUBLIC_PARENT = true;
pub const Profile = @import("block_v8_window_root_profile_v1.zig");
pub const Original = struct {
    pub const VerifiedCapture = Profile.Capture;
};
pub const Composition = @import("air/block_v8_window_root_composition_v1.zig");
pub const Transcript = @import("air/block_v8_window_root_transcript_v1.zig");
pub const PcsProfile = @import("block_v8_endpoint_recursive_pcs_profile_v1.zig").With(@This());
pub const Pcs = @import("block_v8_endpoint_recursive_pcs_preparation_v1.zig").With(@This());
pub const Public = @import("block_v8_endpoint_recursive_public_v1.zig").With(@This());
pub const Preparation = @import("block_v8_endpoint_recursive_preparation_v1.zig").With(@This());
pub const Fixed = @import("block_v8_endpoint_recursive_fixed_roster_v1.zig").With(@This());
pub const IDENTITY_TAG = 0x42385749;
pub const SCHEDULE_TAG = 0x42385744;
pub fn firstRoots(_: *const Profile.Owned) usize {
    return 2;
}
pub fn epoch(p: *const Profile.Owned) struct { config: @import("stwo_core").pcs.PcsConfig } {
    return .{ .config = p.shape.config };
}

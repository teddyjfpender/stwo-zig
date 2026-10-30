//! Original five-commitment B5CF shape authenticated from independent policy.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("block_v6_caller_fused_fixed_v1.zig");
const Admission = @import("../prover/block_v5_caller_fused_recursive_admission_v1.zig");
pub const Profile = struct {
    pub const commitment_trees = 5;
    pub const fixed_setup_only = true;
    native: *const Native.Owned,
    admitted: *const Admission.Prepared,
    claims: Native.Claims,
    limits: Native.Limits,
    columns: [5][]const u32,
    widths: []const u32,
    config: core.pcs.PcsConfig,
    lifting_log: u32,
    seal: [32]u8,
    pub fn derive(native: *const Native.Owned, admitted: *const Admission.Prepared, claims: Native.Claims, limits: Native.Limits) !Profile {
        try native.validateAgainst(admitted, claims, limits);
        if (native.shape.columns.len != 5) return error.InvalidCallerFusedFixedGeometry;
        var columns: [5][]const u32 = undefined;
        for (&columns, native.shape.columns) |*out, logs| out.* = logs;
        return .{ .native = native, .admitted = admitted, .claims = claims, .limits = limits, .columns = columns, .widths = native.shape.widths, .config = admitted.config, .lifting_log = native.shape.lifting_log, .seal = identity(native) };
    }
    pub fn deepProfile(self: *const Profile) @import("air/pcs_deep_circuit.zig").Profile {
        return self.native.shape.deepProfile();
    }
    pub fn friProfile(self: *const Profile) @import("air/fri_verifier_circuit.zig").Profile {
        return self.native.shape.friProfile();
    }
    pub fn validate(self: *const Profile) !void {
        try self.native.validateAgainst(self.admitted, self.claims, self.limits);
        if (self.native.shape.columns.len != 5 or !std.mem.eql(u32, self.widths, self.native.shape.widths) or
            !std.meta.eql(self.config, self.admitted.config) or self.lifting_log != self.native.shape.lifting_log or
            !std.meta.eql(self.seal, identity(self.native))) return error.UntrustedCallerFusedFixedGeometry;
        for (self.columns, self.native.shape.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.UntrustedCallerFusedFixedGeometry;
    }
    fn identity(native: *const Native.Owned) [32]u8 {
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42364350, 1, 5 });
        channel.mixRoot(native.template_id);
        channel.mixRoot(native.shape.deepProfile().identityDigest());
        channel.mixRoot(native.shape.friProfile().identityDigest());
        return channel.digestBytes();
    }
};

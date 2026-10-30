//! Strategy-based shared parent verifier; no original equations duplicated.
const Family = @import("block_v8_endpoint_recursive_source_v1.zig").Family;
pub fn For(comptime family: Family) type {
    return With(@import("block_v8_endpoint_recursive_adapter_v1.zig").For(family));
}
pub fn With(comptime Adapter: type) type {
    return struct {
        // Borrowed compiler view of independently reconstructed union PCS geometry.
        // No proof capture or proposed verifier key participates in this view.
        const std = @import("std");
        const core = @import("stwo_core");
        const Profile = Adapter.Profile;
        pub const View = struct {
            original: *const Profile.Owned,
            columns: []const []const u32,
            config: core.pcs.PcsConfig,
            widths: []const u32,
            lifting_log: u32,
            seal: [32]u8,
            relation_pairs: usize,
            initial_roots: usize,
            pub fn init(original: *const Profile.Owned) !View {
                try original.validate();
                return .{ .original = original, .columns = original.shape.columns, .config = original.shape.config, .widths = original.shape.widths, .lifting_log = original.shape.lifting_log, .seal = original.seal, .relation_pairs = Profile.RELATION_PAIRS, .initial_roots = Adapter.firstRoots(original) };
            }
            pub fn validate(self: *const View) !void {
                try self.original.validate();
                if (!std.meta.eql(self.seal, self.original.seal) or !std.meta.eql(self.config, self.original.shape.config) or self.columns.len != self.original.shape.columns.len or self.lifting_log != self.original.shape.lifting_log or self.widths.len != self.original.shape.widths.len or self.initial_roots != Adapter.firstRoots(self.original) or self.relation_pairs != Profile.RELATION_PAIRS) return error.UntrustedEndpointPcsProfile;
                for (self.columns, self.original.shape.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.UntrustedEndpointPcsProfile;
                if (!std.mem.eql(u32, self.widths, self.original.shape.widths)) return error.UntrustedEndpointPcsProfile;
            }
            pub fn deepProfile(self: *const View) @import("air/pcs_deep_circuit.zig").Profile {
                return self.original.shape.deepProfile();
            }
            pub fn friProfile(self: *const View) @import("air/fri_verifier_circuit.zig").Profile {
                return self.original.shape.friProfile();
            }
        };
    };
}

//! Exact original optional-access geometry for fixed PCS compilers.
//! All borrowed metadata is rederived from original admission; no proof exists.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("block_v6_partitioned_recursive_fixed_v1.zig");
const Admission = @import("../prover/block_v6_partitioned_recursive_admission_v1.zig");
const Claims = @import("block_v6_partitioned_public_bus_v1.zig").Claims;
pub fn ForCommitments(comptime N: usize) type {
    if (N != 4 and N != 5) @compileError("partitioned native has four/five commitments");
    return struct {
        const Self = @This();
        pub const commitment_trees = N;
        pub const fixed_setup_only = true;
        native: *const Native.Owned,
        admitted: *const Admission.Prepared,
        claims: Claims,
        limits: Native.Limits,
        columns: [N][]const u32,
        widths: []const u32,
        config: core.pcs.PcsConfig,
        lifting_log: u32,
        seal: [32]u8,
        pub fn derive(native: *const Native.Owned, admitted: *const Admission.Prepared, claims: Claims, limits: Native.Limits) !Self {
            try native.validateAgainst(admitted, claims, limits);
            if (admitted.tree_count + 1 != N or native.columns.len != N) return error.InvalidPartitionedFixedGeometry;
            var columns: [N][]const u32 = undefined;
            for (&columns, native.columns) |*out, logs| out.* = logs;
            return .{ .native = native, .admitted = admitted, .claims = claims, .limits = limits, .columns = columns, .widths = native.widths, .config = native.config, .lifting_log = native.lifting_log, .seal = identity(native) };
        }
        pub fn deepProfile(self: *const Self) @import("air/pcs_deep_circuit.zig").Profile {
            return self.native.deepProfile();
        }
        pub fn friProfile(self: *const Self) @import("air/fri_verifier_circuit.zig").Profile {
            return self.native.friProfile();
        }
        pub fn validate(self: *const Self) !void {
            try self.native.validateAgainst(self.admitted, self.claims, self.limits);
            if (self.admitted.tree_count + 1 != N or self.native.columns.len != N or !std.mem.eql(u32, self.widths, self.native.widths) or !std.meta.eql(self.config, self.admitted.config) or self.lifting_log != self.native.lifting_log or !std.meta.eql(self.seal, identity(self.native))) return error.UntrustedPartitionedFixedGeometry;
            for (self.columns, self.native.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.UntrustedPartitionedFixedGeometry;
        }
        fn identity(native: *const Native.Owned) [32]u8 {
            var channel = core.channel.blake3.Channel{};
            channel.mixU32s(&.{ 0x42365050, 1, N });
            channel.mixRoot(native.template_id);
            channel.mixRoot(native.deepProfile().identityDigest());
            channel.mixRoot(native.friProfile().identityDigest());
            return channel.digestBytes();
        }
    };
}

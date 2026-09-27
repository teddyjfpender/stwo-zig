//! Synchronous, independently admitted native PCS ports. These borrow the
//! original fixed owner and policy; neither may mutate or release during use.
//! This is shape authority only, never a verifier-success or expected-key token.
const std = @import("std");
const core = @import("stwo_core");
const Word = @import("block_v5_word_recursive_fixed_v1.zig");
const Page = @import("block_v5_memory_source_page_recursive_fixed_v1.zig");
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Deep = @import("air/pcs_deep_circuit.zig");
const Fri = @import("air/fri_verifier_circuit.zig");
pub fn ForWord(comptime family: @import("air/block_v5_word_recursive_shape_composition_v1.zig").Family) type {
    const Native = Word.ForFamily(family);
    const Admitted = if (family == .ram_lanes) @import("../prover/block_v5_ram_lanes_recursive_admission_v1.zig").Prepared else @import("../prover/block_v5_range16_recursive_admission_v1.zig").Prepared;
    return struct {
        const Self = @This();
        pub const commitment_trees = 4;
        pub const fixed_setup_only = true;
        native: *const Native.Owned,
        admitted: *const Admitted,
        expected: [32]u8,
        columns: [4][]const u32,
        widths: []const u32,
        config: core.pcs.PcsConfig,
        lifting_log: u32,
        seal: [32]u8,
        pub fn derive(native: *const Native.Owned, admitted: *const Admitted, expected: [32]u8) !Self {
            try native.validateAgainst(admitted, expected);
            var columns: [4][]const u32 = undefined;
            for (native.shape.columns, &columns) |logs, *out| out.* = logs;
            return .{ .native = native, .admitted = admitted, .expected = expected, .columns = columns, .widths = native.shape.widths, .config = native.shape.config, .lifting_log = native.shape.lifting_log, .seal = native.shape.seal };
        }
        pub fn deepProfile(self: *const Self) Deep.Profile {
            return self.native.shape.deepProfile();
        }
        pub fn friProfile(self: *const Self) Fri.Profile {
            return self.native.shape.friProfile();
        }
        pub fn validate(self: *const Self) !void {
            try self.native.validateAgainst(self.admitted, self.expected);
            try exactColumns(4, self.columns, self.native.shape.columns);
            if (self.widths.ptr != self.native.shape.widths.ptr or self.widths.len != self.native.shape.widths.len or !std.meta.eql(self.config, self.admitted.config) or self.lifting_log != self.native.shape.lifting_log or !std.meta.eql(self.seal, self.native.shape.seal)) return error.UntrustedNativeFixedPcsProfile;
        }
    };
}
pub fn ForPage(comptime kind: Semantic.Kind) type {
    const Native = Page.ForKind(kind);
    const Admitted = @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig").ForKind(kind).Prepared;
    return struct {
        const Self = @This();
        pub const commitment_trees = 10;
        pub const fixed_setup_only = true;
        native: *const Native.Owned,
        admitted: *const Admitted,
        expected: [32]u8,
        public_claims: Semantic.Claims,
        columns: [10][]const u32,
        widths: []const u32,
        config: core.pcs.PcsConfig,
        lifting_log: u32,
        seal: [32]u8,
        pub fn derive(native: *const Native.Owned, admitted: *const Admitted, expected: [32]u8, public_claims: Semantic.Claims) !Self {
            try native.validateAgainst(admitted, expected, public_claims);
            var columns: [10][]const u32 = undefined;
            for (native.profile.columns, &columns) |logs, *out| out.* = logs;
            return .{ .native = native, .admitted = admitted, .expected = expected, .public_claims = public_claims, .columns = columns, .widths = native.profile.widths, .config = native.profile.config, .lifting_log = native.profile.lifting_log, .seal = identity(native, expected) };
        }
        pub fn deepProfile(self: *const Self) Deep.Profile {
            return self.native.profile.deepProfile();
        }
        pub fn friProfile(self: *const Self) Fri.Profile {
            return self.native.profile.friProfile();
        }
        pub fn validate(self: *const Self) !void {
            try self.native.validateAgainst(self.admitted, self.expected, self.public_claims);
            try exactColumns(10, self.columns, self.native.profile.columns);
            if (self.widths.ptr != self.native.profile.widths.ptr or self.widths.len != self.native.profile.widths.len or !std.meta.eql(self.config, self.admitted.config) or self.lifting_log != self.native.profile.lifting_log or !std.meta.eql(self.seal, identity(self.native, self.expected))) return error.UntrustedNativeFixedPcsProfile;
        }
        fn identity(native: *const Native.Owned, expected: [32]u8) [32]u8 {
            var channel = core.channel.blake3.Channel{};
            channel.mixU32s(&.{ 0x42355050, 1, @intFromEnum(kind), 10 });
            channel.mixRoot(expected);
            channel.mixRoot(native.profile.deepProfile().identityDigest());
            channel.mixRoot(native.profile.friProfile().identityDigest());
            return channel.digestBytes();
        }
    };
}
fn exactColumns(comptime N: usize, actual: [N][]const u32, expected: [N][]u32) !void {
    for (actual, expected) |a, e| if (a.ptr != e.ptr or a.len != e.len) return error.UntrustedNativeFixedPcsProfile;
}

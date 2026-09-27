//! Shared compact-provider admission for typed execution extension profiles.
//! The original extension certificate bounds its original requests; this layer
//! separately bounds all additional compact-provider byte requests.
const std = @import("std");
const core = @import("stwo_core");
const geometry = @import("../recursion/air/compact_range_geometry.zig");
const wire = @import("compact_range_codec.zig");
const base = @import("blake3_execution_protocol.zig");
const native_mod = @import("../air/statement.zig");
const Pin = @import("blake3_commitment_plan.zig").Admission;
pub fn ForProfile(comptime Profile: type) type {
    return struct {
        native: *const native_mod.Blake3ExecutionStatement,
        extension: *const Profile.admission.Statement,
        ranges: geometry.Plan,
        pub fn validate(self: @This(), pin: Pin, logs: Profile.admission.HashLogs) !u64 {
            try (@import("compact_execution_contract.zig").Contract{ .native = self.native, .ranges = self.ranges }).validate(Profile.externalCount(self.extension));
            try Profile.admission.validate(self.extension, self.native, pin, logs);
            const index = @intFromEnum(@import("../air/lookups/tables/schema.zig").Kind.range_check_8_8);
            return self.ranges.extendByteBound(self.extension.admission.extended_fixed_table_bounds[index]);
        }
        pub fn mix(self: @This(), channel: anytype, config: core.pcs.PcsConfig, pin: Pin, logs: Profile.admission.HashLogs) !void {
            const byte_bound = try self.validate(pin, logs);
            try base.validateConfig(config);
            const range_id = try self.ranges.identity();
            // Profile's existing transcript includes its disjoint domain and
            // authenticated extension. Validate first so rejection is atomic.
            channel.mixU32s(&.{ 0x42334358, 1, Profile.receipt_domain }); // B3CX
            try Profile.protocol.mix(channel, config, self.native, self.extension, pin, logs);
            try wire.mixAdmitted(channel, self.ranges, range_id);
            channel.mixU64(byte_bound);
        }
        pub fn identity(self: @This(), config: core.pcs.PcsConfig, pin: Pin, logs: Profile.admission.HashLogs, root: [32]u8) ![32]u8 {
            const bound = try self.validate(pin, logs);
            const original = try Profile.protocol.identity(config, self.native, self.extension, pin, logs, root);
            var channel = core.channel.blake3.Channel{};
            channel.mixU32s(&.{ 0x4233434b, 1, Profile.receipt_domain }); // B3CK
            base.mixDigest(&channel, original);
            try wire.mixAdmitted(&channel, self.ranges, try self.ranges.identity());
            channel.mixU64(bound);
            return channel.digestBytes();
        }
    };
}

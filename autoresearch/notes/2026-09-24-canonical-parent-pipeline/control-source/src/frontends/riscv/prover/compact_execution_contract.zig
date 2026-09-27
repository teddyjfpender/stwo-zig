//! Complete native/compact geometry contract for experimental execution joining.
//! This is not yet selected by the released execution artifact envelope.
const std = @import("std");
const core = @import("stwo_core");
const statement = @import("../air/statement.zig");
const protocol = @import("blake3_execution_protocol.zig");
const admission = @import("blake3_commitment_plan.zig");
const geometry = @import("../recursion/air/compact_range_geometry.zig");
const roster = @import("../recursion/air/compact_range_roster.zig").Roster;
const wire = @import("compact_range_codec.zig");
pub const VERSION: u32 = 1;
pub const Contract = struct {
    native: *const statement.Blake3ExecutionStatement,
    ranges: geometry.Plan,
    pub fn validate(self: Contract, external_retirements: u32) !void {
        try self.native.validateBlake3ExecutionWithExternal(external_retirements);
        try self.ranges.validate();
        // Never prove both full-table and compact providers for the same domain.
        for (self.native.infra_descs[0..self.native.n_infra]) |desc| switch (desc.kind) {
            .range_check_20, .range_check_8_11, .range_check_8_8_4 => return error.DuplicateCompactRangeProvider,
            else => {},
        };
    }
    /// Caller must independently admit any extension represented by the external
    /// retirement count. Geometry validation does not authorize extension semantics.
    pub fn mix(self: Contract, channel: anytype, config: core.pcs.PcsConfig, pin: admission.Admission, external_retirements: u32) !void {
        try self.validate(external_retirements);
        try protocol.validateConfig(config);
        try pin.validatePublic(&self.native.public_data);
        const id = try self.ranges.identity();
        channel.mixU32s(&.{ 0x42334352, VERSION, external_retirements }); // B3CR
        protocol.mixAdmittedStatement(channel, config, self.native, pin);
        try wire.mixAdmitted(channel, self.ranges, id);
    }
    /// Native, compact, then hash components: independent of witness buffers.
    pub fn columnLogs(self: Contract, a: std.mem.Allocator, hash_logs: [@import("blake3_commitment_components.zig").Airs.len]u32, comptime tree: protocol.ColumnTree, external_retirements: u32) ![]u32 {
        try self.validate(external_retirements);
        const base = try protocol.columnLogsWithExternal(a, self.native, hash_logs, tree, external_retirements);
        defer a.free(base);
        const prefix: usize = if (tree == .main) self.native.nMainColumns() else self.native.nInteractionColumns();
        var extra: usize = 0;
        inline for (roster.Airs) |Air| extra += if (tree == .main) Air.PHYSICAL_MAIN_COLUMN_COUNT else Air.INTERACTION_COLUMN_COUNT;
        const result = try a.alloc(u32, try std.math.add(usize, base.len, extra));
        @memcpy(result[0..prefix], base[0..prefix]);
        var at = prefix;
        inline for (roster.Airs, 0..) |Air, i| {
            const count = if (tree == .main) Air.PHYSICAL_MAIN_COLUMN_COUNT else Air.INTERACTION_COLUMN_COUNT;
            @memset(result[at..][0..count], self.ranges.shapes[i].log_size);
            at += count;
        }
        @memcpy(result[at..], base[prefix..]);
        return result;
    }
    pub fn mixClaims(self: Contract, channel: anytype, claims: *const statement.RiscVInteractionClaim, ranges: [3]core.fields.qm31.QM31, hashes: []const core.fields.qm31.QM31, external_retirements: u32) !void {
        try self.validate(external_retirements);
        // Validate all fallible shape conditions before changing the transcript.
        if (claims.n_components != self.native.n_components or claims.n_infra != self.native.n_infra or hashes.len != @import("blake3_commitment_components.zig").Airs.len) return error.InvalidInteractionClaim;
        channel.mixU32s(&.{ 0x42334343, VERSION }); // B3CC
        try protocol.mixClaims(channel, self.native, claims, hashes);
        channel.mixFelts(&ranges);
    }
};

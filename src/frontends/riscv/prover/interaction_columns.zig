//! Owned interaction-column prefix with failure-atomic reservation and transfer.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const guest_interaction = @import("../air/guest_precompile/interaction.zig");

/// The committed column array, filled strictly front to back.
///
/// A prefix counter is enough here (unlike Tree 1, which writes two disjoint
/// regions) because interaction columns are appended in declaration order and
/// never addressed absolutely.
pub const Columns = struct {
    values: []prover_pcs.ColumnEvaluation,
    filled: usize,
    moved: bool,

    pub fn init(allocator: std.mem.Allocator, n_interaction: usize) !Columns {
        return .{
            .values = try allocator.alloc(prover_pcs.ColumnEvaluation, n_interaction),
            .filled = 0,
            .moved = false,
        };
    }

    pub fn append(self: *Columns, log_size: u32, values: []M31) void {
        self.values[self.filled] = .{ .log_size = log_size, .values = values };
        self.filled += 1;
    }

    /// Transfers one complete generated interaction block into the
    /// declaration-ordered commitment. The caller retains ownership
    /// only when validation fails before the first append.
    pub fn appendGenerated(
        self: *Columns,
        log_size: u32,
        generated: []const []M31,
    ) !void {
        if (self.filled > self.values.len or
            generated.len > self.values.len - self.filled)
        {
            return error.InvalidTraceShape;
        }
        for (generated) |values| self.append(log_size, values);
    }

    pub fn reserveGuest(
        self: *Columns,
        allocator: std.mem.Allocator,
        log_size: u32,
    ) !guest_interaction.Destinations {
        const count = guest_interaction.total_column_count;
        if (self.filled > self.values.len or count > self.values.len - self.filled or
            log_size >= @bitSizeOf(usize))
        {
            return error.InvalidTraceShape;
        }
        const start = self.filled;
        const domain_size = @as(usize, 1) << @intCast(log_size);
        var initialized: usize = 0;
        errdefer {
            for (self.values[start .. start + initialized]) |column| {
                allocator.free(@constCast(column.values));
            }
            self.filled = start;
        }
        while (initialized < count) : (initialized += 1) {
            self.values[start + initialized] = .{
                .log_size = log_size,
                .values = try allocator.alloc(M31, domain_size),
            };
            self.filled += 1;
        }
        var result: guest_interaction.Destinations = undefined;
        for (&result.caller, 0..) |*destination, index| {
            destination.* = @constCast(self.values[start + index].values);
        }
        const provider_start = start + guest_interaction.caller_column_count;
        for (&result.provider, 0..) |*destination, index| {
            destination.* = @constCast(self.values[provider_start + index].values);
        }
        return result;
    }

    /// Releases the filled prefix only while this array still owns it: after
    /// `moved` the commitment scheme does.
    pub fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
        if (self.moved) return;
        for (self.values[0..self.filled]) |column| allocator.free(@constCast(column.values));
        allocator.free(self.values);
    }
};

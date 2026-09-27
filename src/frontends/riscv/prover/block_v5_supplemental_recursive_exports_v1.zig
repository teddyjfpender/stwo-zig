//! Final artifact copies made before releasing genuine fused captures. This
//! module owns only public claim/range arrays; cloning confers no proof or
//! native-receipt authority. Original fresh verifiers remain mandatory.
const std = @import("std");
const Caller = @import("block_v5_caller_fused_proof_v1.zig");
const Native = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Range = @import("block_execution_byte_range_v2.zig");
pub const CallerCopies = struct {
    claims: Caller.ClaimFrames,
    range_claims: []Range.Claims,
    pub fn clone(a: std.mem.Allocator, claims: Caller.ClaimFrames, ranges: []const Range.Claims) !CallerCopies {
        var copied = try Caller.ClaimFrames.clone(a, claims);
        errdefer copied.deinit(a);
        return .{ .claims = copied, .range_claims = try a.dupe(Range.Claims, ranges) };
    }
    pub fn deinit(self: *CallerCopies, a: std.mem.Allocator) void {
        self.claims.deinit(a);
        a.free(self.range_claims);
        self.* = undefined;
    }
};
pub const NativeCopies = struct {
    projection_claims: []Native.Claim,
    memory_claims: []Memory.Claim,
    /// Null retains the original typed absent-access case. An empty present
    /// vector is distinct from absence, even though it needs no allocation.
    range_claims: ?[]Range.Claims,
    pub fn clone(a: std.mem.Allocator, projections: []const Native.Claim, memory: []const Memory.Claim, ranges: ?[]const Range.Claims) !NativeCopies {
        const copied_projections = try a.dupe(Native.Claim, projections);
        errdefer a.free(copied_projections);
        const copied_memory = try a.dupe(Memory.Claim, memory);
        errdefer a.free(copied_memory);
        const copied_ranges = if (ranges) |present| try a.dupe(Range.Claims, present) else null;
        return .{ .projection_claims = copied_projections, .memory_claims = copied_memory, .range_claims = copied_ranges };
    }
    pub fn deinit(self: *NativeCopies, a: std.mem.Allocator) void {
        a.free(self.projection_claims);
        a.free(self.memory_claims);
        if (self.range_claims) |ranges| a.free(ranges);
        self.* = undefined;
    }
};

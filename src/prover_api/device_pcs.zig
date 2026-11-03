//! Per-proof native OM31 PCS offload. No process-global callback or fallback.
//! The caller keeps coefficient/point owners live for this synchronous boundary.
const std = @import("std");
const core = @import("stwo_core");
pub const O = core.fields.om31.OM31;
pub const M = core.fields.m31.M31;
pub const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const Channel = core.channel.raw_mod_m31.Om31Channel;
pub const P = core.pcs.ForField(O);
pub const Point = core.circle.CirclePoint(O);
/// Device columns are borrowed; the stage must validate their owner, statement
/// scope, generation and exact length before enqueue. They are never CPU slices.
pub const DeviceCoefficients = struct { words: [*]const u32, count: u64, context_token: u64, generation: u64 };
pub const Column = struct { log_size: u32, coefficients: []const M = &.{}, device: ?DeviceCoefficients = null };
pub const Tree = struct { root: H.Hash, columns: []const Column };
pub const Scope = struct { statement: [32]u8, fixed: [32]u8, main: [32]u8, ordinal: u32 };
pub const Request = struct {
    scope: ?Scope = null,
    config: core.pcs.PcsConfig,
    lifting_log_size: u32,
    trees: []const Tree,
    points: core.pcs.TreeVec([][]Point),
};
pub const Stage = struct {
    context: *anyopaque,
    /// Returns owned native containers. Updates only the supplied channel copy;
    /// an error is terminal and must never silently execute the CPU path.
    prove: *const fn (*anyopaque, std.mem.Allocator, Request, *Channel) anyerror!P.ExtendedCommitmentSchemeProof(H),
};

/// Native authority chooses the exact column roster and geometry. The device
/// may consume either base evaluations or coefficients; these are distinct
/// encodings, never interchangeable host polynomial placeholders.
pub const TraceEncoding = enum { evaluations, coefficients };
pub const TraceColumn = struct {
    log_size: u32,
    encoding: TraceEncoding,
    host: []const M = &.{},
    device: ?DeviceCoefficients = null,
    pub fn validate(self: TraceColumn) !void {
        if (self.log_size < 3 or self.log_size > 28) return error.InvalidDeviceTraceColumn;
        const count = @as(u64, 1) << @intCast(self.log_size);
        if (self.device) |value| {
            if (self.host.len != 0 or value.count != count or value.context_token == 0 or value.generation == 0) return error.InvalidDeviceTraceColumn;
        } else if (self.host.len != count) return error.InvalidDeviceTraceColumn;
    }
};
pub const TraceCommitRequest = struct {
    /// MAIN uses main=zero before its commitment exists. The successful device
    /// owner promotes its leases to the same scope with main=result.root.
    /// INTER already carries the final authenticated MAIN scope.
    scope: Scope,
    tree_index: u32,
    config: core.pcs.PcsConfig,
    columns: []const TraceColumn,
};
pub const TraceCommitStage = struct {
    context: *anyopaque,
    /// Synchronous: all writes/commitment status join before returning. Returned
    /// device coefficients stay owned until PCS completion or proof failure.
    commit: *const fn (*anyopaque, std.mem.Allocator, TraceCommitRequest) anyerror!Tree,
};

//! Per-proof native OM31 PCS offload. No process-global callback or fallback.
//! The caller keeps coefficient/point owners live for this synchronous boundary.
const std = @import("std");
const core = @import("stwo_core");
pub const TraceColumnError = error{InvalidDeviceTraceColumn};
pub const RetirementScopeError = error{InvalidTraceInputRetirementScope};
pub const ReplayError = error{ DeviceMainReplayRootMismatch, DeviceTraceHostColumn, DeviceMainReplayNotAdmitted, InvalidDeviceTraceTree };
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
/// Diagnostic classification supplied by the semantic caller. It is not part
/// of the statement, lease scope, transcript, wire format or admission policy.
pub const AllocationObserverDomain = enum(u32) { recursion_node = 1, native_packet = 2 };
pub const Request = struct {
    scope: ?Scope = null,
    allocation_observer_domain: AllocationObserverDomain = .native_packet,
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
    pub fn validate(self: TraceColumn) TraceColumnError!void {
        if (self.log_size < 3 or self.log_size > 28) return error.InvalidDeviceTraceColumn;
        const count = @as(u64, 1) << @intCast(self.log_size);
        if (self.device) |value| {
            if (self.host.len != 0 or value.count != count or value.context_token == 0 or value.generation == 0) return error.InvalidDeviceTraceColumn;
        } else if (self.host.len != count) return error.InvalidDeviceTraceColumn;
    }
    pub fn validateDiagnosed(self: TraceColumn, failure: ?*?@import("error_codes.zig").DeviceFailure) TraceColumnError!void {
        if (failure) |sink| sink.* = null;
        self.validate() catch |err| {
            @import("error_codes.zig").recordDeviceAdmission(failure, err);
            return err;
        };
    }
};
/// Optional owner-thread custody transfer after joined coefficient ingress.
/// Only consumed evaluation buffers may be retired; returned coefficients have
/// independent ownership. Failure leaves all remaining source custody with its
/// original owner and the commitment cleans up its untransferred coefficients.
pub const TraceInputRetirement = struct {
    context: *anyopaque,
    scope: Scope,
    retire: *const fn (*anyopaque, *anyopaque, u64, Scope) anyerror!void,
    pub fn invoke(self: @This(), native_context: *anyopaque, token: u64, expected: Scope) !void {
        return self.invokeDiagnosed(native_context, token, expected, null);
    }
    pub fn validateScope(self: @This(), token: u64, expected: Scope) RetirementScopeError!void {
        if (token == 0 or !std.meta.eql(self.scope, expected)) return error.InvalidTraceInputRetirementScope;
    }
    pub fn invokeDiagnosed(self: @This(), native_context: *anyopaque, token: u64, expected: Scope, failure: ?*?@import("error_codes.zig").DeviceFailure) !void {
        if (failure) |sink| sink.* = null;
        self.validateScope(token, expected) catch |err| {
            @import("error_codes.zig").recordDeviceAdmission(failure, err);
            return err;
        };
        try self.retire(self.context, native_context, token, expected);
    }
};
pub const TraceCommitRequest = struct {
    /// Borrowed for this synchronous call only. Pure admission writes on the
    /// coordinator; never retained or included in Scope/protocol identity.
    diagnostic: ?*?@import("error_codes.zig").DeviceFailure = null,
    /// MAIN uses main=zero before its commitment exists. The successful device
    /// owner promotes its leases to the same scope with main=result.root.
    /// INTER already carries the final authenticated MAIN scope.
    scope: Scope,
    tree_index: u32,
    config: core.pcs.PcsConfig,
    columns: []const TraceColumn,
    /// Bounded device replay after the manifest barrier. MAIN stays bound to
    /// this already committed root; no second transcript mix is performed.
    expected_main_root: ?H.Hash = null,
    /// INTER only. Called once after all ingress copies have joined and before
    /// allocating LDE/tree scratch. The callback must preserve column headers.
    retire_input: ?TraceInputRetirement = null,
};
pub const TraceCommitStage = struct {
    context: *anyopaque,
    /// Synchronous: all writes/commitment status join before returning. Returned
    /// device coefficients stay owned until PCS completion or proof failure.
    commit: *const fn (*anyopaque, std.mem.Allocator, TraceCommitRequest) anyerror!Tree,
};

/// Deterministic replay may replace storage, never the commitment, shape or
/// context authority. Exact scope/generation liveness is checked at enqueue.
pub fn validateMainReplay(original: Tree, replay: Tree) ReplayError!void {
    if (!std.mem.eql(u8, &original.root, &replay.root) or replay.columns.len == 0 or replay.columns.len != original.columns.len) return error.DeviceMainReplayRootMismatch;
    for (replay.columns, original.columns) |column, old| {
        const device = column.device orelse return error.DeviceTraceHostColumn;
        const previous = old.device orelse return error.DeviceMainReplayNotAdmitted;
        if (column.coefficients.len != 0 or old.coefficients.len != 0 or column.log_size != old.log_size or column.log_size < 3 or column.log_size > 28 or device.count != @as(u64, 1) << @intCast(column.log_size) or device.context_token == 0 or device.context_token != previous.context_token or device.generation == 0) return error.InvalidDeviceTraceTree;
    }
}
pub fn validateMainReplayDiagnosed(original: Tree, replay: Tree, failure: ?*?@import("error_codes.zig").DeviceFailure) ReplayError!void {
    if (failure) |sink| sink.* = null;
    validateMainReplay(original, replay) catch |err| {
        @import("error_codes.zig").recordDeviceAdmission(failure, err);
        return err;
    };
}

test "MAIN replay preserves root shape and device authority" {
    const device = DeviceCoefficients{ .words = @ptrFromInt(4096), .count = 32, .context_token = 7, .generation = 1 };
    const old = [_]Column{.{ .log_size = 5, .device = device }};
    var next = old;
    next[0].device.?.words = @ptrFromInt(8192);
    next[0].device.?.generation = 2;
    const original = Tree{ .root = @splat(1), .columns = &old };
    var replay = Tree{ .root = original.root, .columns = &next };
    try validateMainReplay(original, replay);
    replay.root[0] ^= 1;
    try std.testing.expectError(error.DeviceMainReplayRootMismatch, validateMainReplay(original, replay));
    replay.root = original.root;
    replay.columns = &.{};
    try std.testing.expectError(error.DeviceMainReplayRootMismatch, validateMainReplay(original, replay));
    replay.columns = &next;
    next[0].log_size = 6;
    try std.testing.expectError(error.InvalidDeviceTraceTree, validateMainReplay(original, replay));
    next = old;
    next[0].device.?.count = 31;
    try std.testing.expectError(error.InvalidDeviceTraceTree, validateMainReplay(original, replay));
    next = old;
    next[0].device.?.context_token = 8;
    try std.testing.expectError(error.InvalidDeviceTraceTree, validateMainReplay(original, replay));
    next = old;
    next[0].device.?.generation = 0;
    try std.testing.expectError(error.InvalidDeviceTraceTree, validateMainReplay(original, replay));
    next = old;
    next[0].coefficients = &.{M.zero()};
    try std.testing.expectError(error.InvalidDeviceTraceTree, validateMainReplay(original, replay));
    next = old;
    next[0].device = null;
    try std.testing.expectError(error.DeviceTraceHostColumn, validateMainReplay(original, replay));
}

test "device admission diagnosed validators reset scope and preserve foreign retire callback" {
    const codes = @import("error_codes.zig");
    var detail: ?codes.DeviceFailure = null;
    const invalid = TraceColumn{ .log_size = 2, .encoding = .coefficients };
    try std.testing.expectError(error.InvalidDeviceTraceColumn, invalid.validateDiagnosed(&detail));
    try std.testing.expectEqual(@as(u16, 0x3501), detail.?.entry.code);
    const device = DeviceCoefficients{ .words = @ptrFromInt(4096), .count = 32, .context_token = 7, .generation = 1 };
    const good = TraceColumn{ .log_size = 5, .encoding = .coefficients, .device = device };
    try good.validateDiagnosed(&detail);
    try std.testing.expect(detail == null);
    const scope = Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 4 };
    const Foreign = struct {
        fn retire(_: *anyopaque, _: *anyopaque, _: u64, _: Scope) anyerror!void {
            return error.InvalidTraceInputRetirementScope;
        }
    };
    var context: u8 = 0;
    const retirement = TraceInputRetirement{ .context = &context, .scope = scope, .retire = Foreign.retire };
    try std.testing.expectError(error.InvalidTraceInputRetirementScope, retirement.invokeDiagnosed(&context, 0, scope, &detail));
    try std.testing.expectEqual(@as(u16, 0x3502), detail.?.entry.code);
    try std.testing.expectError(error.InvalidTraceInputRetirementScope, retirement.invokeDiagnosed(&context, 7, scope, &detail));
    try std.testing.expect(detail == null);
    var second: ?codes.DeviceFailure = null;
    const first_request = TraceCommitRequest{ .scope = scope, .tree_index = 1, .config = .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 3) }, .columns = &.{good}, .diagnostic = &detail };
    var second_request = first_request;
    second_request.diagnostic = &second;
    try std.testing.expect(first_request.diagnostic != second_request.diagnostic);
    try std.testing.expect(std.meta.eql(first_request.scope, second_request.scope));
    try std.testing.expectEqualDeep(first_request.columns, second_request.columns);
}

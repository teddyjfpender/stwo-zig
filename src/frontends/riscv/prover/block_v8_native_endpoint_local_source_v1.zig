//! One experimental local native source: typed native AIR + complete RAM
//! projections + ordered endpoints + their own range16 provider. Global WORD,
//! ROM, byte-pair and remaining native table providers are deliberately OPEN.
//! No production route selects this module. No proof authority comes from its
//! pure closure helpers; all physical claims require original authentication.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Native = @import("block_v8_native_endpoint_components_v1.zig");
const Closure = @import("block_v8_native_endpoint_closure_v1.zig");
const Endpoint = @import("block_v8_ram_endpoint_component_v1.zig");
const Kernel = @import("block_v8_ram_endpoint_kernel_v1.zig");
const Range = @import("block_v8_endpoint_range_provider_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const Placement = @import("block_v7_heterogeneous_components_v1.zig");
const Joint = @import("block_v6_joint_components_v1.zig");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Column = engine.pcs.ColumnEvaluation;
const Q = R.Q;
const M = R.M;
const EndpointAdapter = @import("block_v5_word_quotient_adapter_v1.zig").For(Endpoint.Spec);
const RangeAdapter = @import("block_v5_word_quotient_adapter_v1.zig").For(Range.Spec);
pub const production_active = false;
pub const maps = .{ [_]usize{ 0, 1, 4 }, [_]usize{ 0, 2, 5 }, [_]usize{ 0, 3, 6 } };
pub fn endpointLog(count: u32) !u32 {
    _ = try Range.requests(count);
    if (count > 1 << 24) return error.EndpointLocalSourceResourceLimit;
    return @max(@as(u32, 4), std.math.log2_int_ceil(u32, @max(count, 1)));
}
pub const Owner = struct {
    a: std.mem.Allocator,
    scope: Closure.Scope,
    native: *Native.Owner,
    endpoint: EndpointAdapter,
    range: RangeAdapter,
    endpoint_log: u32,
    endpoint_main_logs: [Endpoint.Spec.MAIN_COUNT]u32,
    endpoint_interaction_logs: [Endpoint.Spec.INTERACTION_COUNT]u32,
    range_main_logs: [Range.Spec.MAIN_COUNT]u32,
    range_interaction_logs: [Range.Spec.INTERACTION_COUNT]u32,
    pub fn init(a: std.mem.Allocator, shape: *const Shape, scope: Closure.Scope, native_claims: []const Native.Claim, endpoint_sums: [Endpoint.PLANES]Q, range_sums: [Range.Spec.PLANES]Q, drawn: *const Epoch.Drawn) !*Owner {
        try scope.admit(shape, 0);
        const log = try endpointLog(scope.endpoint_count);
        for (endpoint_sums) |sum| try canonical(sum);
        for (range_sums) |sum| try canonical(sum);
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        const native = if (scope.native_profile.isDirect()) try Native.Owner.initDirectRamV3(a, shape, native_claims, drawn, scope.halt orelse return error.MissingDirectRamHaltPolicy) else try Native.Owner.initWithHalt(a, shape, native_claims, drawn, scope.halt);
        errdefer native.deinit();
        self.* = .{ .a = a, .scope = scope, .native = native, .endpoint_log = log, .endpoint = .{ .log_size = log, .spec = .{ .policy = scope.policy, .challenges = Endpoint.fromEpoch(drawn.*), .sums = endpoint_sums } }, .range = .{ .log_size = 16, .spec = .{ .challenges = drawn.memory, .sums = range_sums } }, .endpoint_main_logs = @splat(log), .endpoint_interaction_logs = @splat(log), .range_main_logs = @splat(16), .range_interaction_logs = @splat(16) };
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const a = self.a;
        self.native.deinit();
        a.destroy(self);
    }
    pub fn proving(self: *const Owner) !Bundle(true) {
        return Bundle(true).init(self);
    }
    pub fn verifying(self: *const Owner) !Bundle(false) {
        return Bundle(false).init(self);
    }
};
pub fn Bundle(comptime proving: bool) type {
    const H = if (proving) engine.air.component_prover.ComponentProver else core.air.components.Component;
    return struct {
        native: Joint.Combined(proving),
        placement: Placement.For(maps, 7, proving),
        handles: []H,
        pub fn init(owner: *const Owner) !@This() {
            var native = if (proving) try owner.native.proving() else try owner.native.verifying();
            errdefer native.deinit(owner.a);
            const endpoint = if (proving) owner.endpoint.asProverComponent() else owner.endpoint.asVerifierComponent();
            const range = if (proving) owner.range.asProverComponent() else owner.range.asVerifierComponent();
            const placement = try Placement.For(maps, 7, proving).init(owner.a, .{ native.handles, &.{endpoint}, &.{range} }, .{ owner.native.fixed.len, Endpoint.Spec.FIXED_COUNT, Range.Spec.FIXED_COUNT });
            return .{ .native = native, .placement = placement, .handles = placement.handles };
        }
        pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
            self.placement.deinit(a);
            self.native.deinit(a);
            self.* = undefined;
        }
    };
}
pub const Fixed = struct {
    a: std.mem.Allocator,
    columns: []Column,
    pub fn deinit(self: *Fixed) void {
        for (self.columns) |column| self.a.free(column.values);
        self.a.free(self.columns);
        self.* = undefined;
    }
};
/// Reconstruct every fixed value solely from independently admitted geometry.
/// Private endpoint values and range multiplicities never enter this builder.
pub fn fixedColumns(a: std.mem.Allocator, shape: *const Shape, endpoint_count: u32) !Fixed {
    const log = try endpointLog(endpoint_count);
    var out: std.ArrayList(Column) = .empty;
    errdefer {
        for (out.items) |column| a.free(column.values);
        out.deinit(a);
    }
    try @import("blake3_execution_protocol.zig").nativePreprocessedWithExternal(a, shape, 0, &out);
    const endpoint_rows = @as(usize, 1) << @intCast(log);
    for (0..2) |kind| {
        const values = try a.alloc(M, endpoint_rows);
        errdefer a.free(values);
        @memset(values, M.zero());
        for (0..endpoint_rows) |row| {
            const physical = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(row, log), log);
            values[physical] = if (kind == 0) M.fromCanonical(@intFromBool(row < endpoint_count)) else M.fromCanonical(@intFromBool(row == 0));
        }
        try out.append(a, .{ .log_size = log, .values = values });
    }
    for (0..2) |kind| {
        const values = try a.alloc(M, 65536);
        errdefer a.free(values);
        for (0..65536) |row| {
            const physical = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(row, 16), 16);
            values[physical] = if (kind == 0) M.one() else M.fromCanonical(@intCast(row));
        }
        try out.append(a, .{ .log_size = 16, .values = values });
    }
    return .{ .a = a, .columns = try out.toOwnedSlice(a) };
}
pub const EndpointContext = struct {
    policy: Kernel.Policy,
    challenges: Endpoint.Challenges(Q),
    pub fn termsAt(self: @This(), matrix: T.Matrix, row: usize) ![Endpoint.PLANES]R.Term(Q) {
        return Endpoint.terms(Q, self.policy, self.challenges, Q.fromBase(matrix.get(0, row)), matrix.row(Endpoint.Spec.MAIN_COUNT, Endpoint.Spec.FIXED_COUNT, row));
    }
};
pub fn endpointInteractions(a: std.mem.Allocator, matrix: T.Matrix, scope: Closure.Scope, drawn: *const Epoch.Drawn, max_bytes: usize) !T.Generated(Endpoint.PLANES) {
    if (matrix.log != try endpointLog(scope.endpoint_count) or matrix.columns.len != Endpoint.Spec.FIXED_COUNT + Endpoint.Spec.MAIN_COUNT) return error.InvalidEndpointLocalSourceGeometry;
    return T.interactions(Endpoint.PLANES, a, matrix, EndpointContext{ .policy = scope.policy, .challenges = Endpoint.fromEpoch(drawn.*) }, max_bytes);
}
/// No aggregated transcript shortcut: all native, endpoint and range16
/// physical planes are committed before any interaction tree is absorbed.
pub fn recordClaims(channel: anytype, layout: [32]u8, native_claims: []const Native.Claim, endpoint_sums: [Endpoint.PLANES]Q, range_sums: [Range.Spec.PLANES]Q) !void {
    channel.mixU32s(&.{ 0x42384c53, 1, Endpoint.PLANES, Range.Spec.PLANES });
    try Native.recordClaims(channel, layout, native_claims);
    for (endpoint_sums) |sum| {
        try canonical(sum);
        channel.mixFelts(&.{sum});
    }
    for (range_sums) |sum| {
        try canonical(sum);
        channel.mixFelts(&.{sum});
    }
}
pub const Open = struct {
    scope: Closure.Scope,
    global_transition_sum: Q,
    byte_pair_sum: Q,
    program_sum: Q,
    fetch_count: u64,
    table_requests: [@import("../air/lookups/tables/schema.zig").KIND_COUNT]Q,
};
/// Invoke only AFTER original/fresh recursive authentication. The returned
/// claims still require independently authenticated global/ROM/byte/table
/// providers; this does not accept a complete execution or Ethereum block.
pub fn close(a: std.mem.Allocator, shape: *const Shape, owner: *const Owner, native_claims: []const Native.Claim, drawn: *const Epoch.Drawn) !Open {
    var gap_sum = Q.zero();
    for (native_claims[owner.native.layout.slots.len..]) |claim| {
        try canonical(claim.sum);
        gap_sum = gap_sum.add(claim.sum);
    }
    try Range.closeRangeClaimsWithExtra(owner.scope.endpoint_count, owner.endpoint.spec.sums, owner.range.spec.sums, try @import("block_v8_native_endpoint_profile_v1.zig").gapRequests(shape, owner.scope.native_profile), gap_sum);
    const parts = try Closure.extractProfile(a, shape, 0, owner.native.layout.slots, native_claims[0..owner.native.layout.slots.len], owner.scope.native_profile);
    const open = try Closure.closeNative(shape, 0, owner.scope, parts, .{ .scope = owner.scope, .sums = owner.endpoint.spec.sums }, &drawn.word.universal_prefix);
    return .{ .scope = open.scope, .global_transition_sum = open.global_transition_sum, .byte_pair_sum = open.byte_pair_sum, .program_sum = open.program_sum, .fetch_count = open.fetch_count, .table_requests = open.table_requests };
}
fn canonical(value: Q) !void {
    for (value.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidEndpointLocalSourceClaim;
}

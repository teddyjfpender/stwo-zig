//! Pure experimental native/endpoint accounting. This verifies NO proof and
//! grants NO authority. Every physical claim, exact layout and endpoint policy
//! must first be authenticated by an original or exact recursive verifier.
//! Source-local equations are checked before global/provider sums are exposed;
//! the caller must not add unrelated source residuals and test only the total.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Projection = @import("block_v5_native_projection_fused_proof_v1.zig");
const Layout = @import("block_v8_native_endpoint_layout_v1.zig");
const Endpoint = @import("block_v8_ram_endpoint_kernel_v1.zig");
const Component = @import("block_v8_ram_endpoint_component_v1.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
const Elements = @import("../recursion/air/universal_challenges.zig");
pub const production_active = false;
pub const Scope = struct {
    native_index: u32,
    native_profile: @import("block_v8_native_endpoint_profile_v1.zig").Profile = .endpoint_v2,
    execution_profile: @import("../runner/elf_loader.zig").ExecutionProfile,
    native_identity: [32]u8,
    endpoint_count: u32,
    policy: Endpoint.Policy,
    halt: ?@import("block_v8_native_halt_policy_v1.zig").Policy = null,
    pub fn admit(self: Scope, shape: *const Shape, external_retirements: u32) !void {
        try @import("block_v8_native_endpoint_profile_v1.zig").requireShape(shape, self.native_profile);
        if (self.native_profile.isDirect() and self.halt == null) return error.MissingDirectRamHaltPolicy;
        if (external_retirements != 0) return error.UnsupportedEndpointCallerInterleaving;
        try shape.validateBlake3ExecutionWithExternal(0);
        try self.policy.validate();
        if (self.halt) |halt| try halt.validate();
        if (std.mem.allEqual(u8, &self.native_identity, 0) or self.policy.source_ordinal != self.native_index or
            shape.public_data.clock == 0 or self.policy.max_local_clock != try maxLocalClock(shape.public_data.clock))
            return error.InvalidEndpointNativeScope;
        var memory_rows: u64 = 0;
        for (shape.component_descs[0..shape.n_components]) |desc| {
            if (desc.family == .load_store) memory_rows = try std.math.add(u64, memory_rows, desc.n_rows);
        }
        if (self.endpoint_count > memory_rows) return error.InvalidEndpointNativeCensus;
    }
};
pub fn maxLocalClock(cycles: u32) !u32 {
    if (cycles == 0) return error.InvalidEndpointNativeScope;
    return std.math.sub(u32, try std.math.mul(u32, cycles, 4), 1);
}
pub const Partitions = struct {
    program_sum: Q = Q.zero(),
    fetch_count: u64 = 0,
    table_requests: [Schema.KIND_COUNT]Q = @splat(Q.zero()),
    state_sum: Q = Q.zero(),
    register_sum: Q = Q.zero(),
    register_clock_sum: Q = Q.zero(),
    ordinary_ram_sum: Q = Q.zero(),
    ram_clock_sum: Q = Q.zero(),
};
/// The proof verifier must use this same independently reconstructed layout.
/// In particular it must absorb *all* physical `Claim.sum` and `row_count`
/// values before committing its interaction tree, not just these partitions.
pub fn extract(a: std.mem.Allocator, shape: *const Shape, external_retirements: u32, actual: []const Source.Slot, claims: []const Projection.Claim) !Partitions {
    return extractProfile(a, shape, external_retirements, actual, claims, .endpoint_v2);
}
pub fn extractProfile(a: std.mem.Allocator, shape: *const Shape, external_retirements: u32, actual: []const Source.Slot, claims: []const Projection.Claim, profile: @import("block_v8_native_endpoint_profile_v1.zig").Profile) !Partitions {
    if (profile == .endpoint_v2) try Layout.requireCoverage(a, shape, external_retirements, actual) else {
        if (external_retirements != 0) return error.UnsupportedDirectRamClockProfile;
        try @import("block_v8_native_endpoint_layout_v3.zig").requireCoverage(a, shape, actual);
    }
    if (actual.len != claims.len) return error.InvalidEndpointNativeClaims;
    var out = Partitions{};
    for (actual, claims) |slot, claim| {
        try canonical(claim.sum);
        if (claim.row_count != slot.n_rows) return error.InvalidEndpointNativeClaims;
        switch (slot.kind) {
            .program => {
                out.program_sum = out.program_sum.add(claim.sum);
                out.fetch_count = try std.math.add(u64, out.fetch_count, claim.row_count);
            },
            .lookup => |lookup| switch (lookup.partition) {
                .registers_state => out.state_sum = out.state_sum.add(claim.sum),
                .register_memory_access => out.register_sum = out.register_sum.add(claim.sum),
                .register_clock_memory_access => out.register_clock_sum = out.register_clock_sum.add(claim.sum),
                .ordinary_memory_access => out.ordinary_ram_sum = out.ordinary_ram_sum.add(claim.sum),
                .clock_memory_access => out.ram_clock_sum = out.ram_clock_sum.add(claim.sum),
                else => {
                    const index = @intFromEnum(lookup.partition);
                    if (index >= Schema.KIND_COUNT) return error.InvalidEndpointNativeClaims;
                    out.table_requests[index] = out.table_requests[index].add(claim.sum);
                },
            },
        }
    }
    return out;
}
pub const EndpointClaims = struct {
    scope: Scope,
    sums: [Component.PLANES]Q,
};
/// Open claims are NOT a complete execution theorem. ROM, lookup, global
/// endpoint RAM and all nine endpoint range/byte planes still require closure.
pub const Open = struct {
    scope: Scope,
    global_transition_sum: Q,
    range16_sum: Q,
    byte_pair_sum: Q,
    program_sum: Q,
    fetch_count: u64,
    table_requests: [Schema.KIND_COUNT]Q,
};
pub fn closeNative(shape: *const Shape, external_retirements: u32, scope: Scope, parts: Partitions, endpoints: EndpointClaims, prefix: *const Elements.UniversalRelations) !Open {
    try scope.admit(shape, external_retirements);
    if (!std.meta.eql(scope, endpoints.scope)) return error.UntrustedEndpointSource;
    inline for (.{ "program_sum", "state_sum", "register_sum", "register_clock_sum", "ordinary_ram_sum", "ram_clock_sum" }) |name| try canonical(@field(parts, name));
    for (parts.table_requests) |sum| try canonical(sum);
    for (endpoints.sums) |sum| try canonical(sum);
    const shared = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(prefix);
    const Public = @import("../air/public_logup_arithmetic.zig");
    const state = (try Public.registersStateSumFor(Q, &shape.public_data, &shared.native)).add(parts.state_sum);
    const registers = (try Public.registerMemoryAccessSumFor(Q, &shape.public_data, &shared.native)).add(parts.register_sum).add(parts.register_clock_sum);
    try closeLocal(parts, endpoints.sums[0], state, registers);
    // Clock-gap edges are indispensable here. V7's zero RAM-clock residual
    // followed from omitting that projection; that convention is not valid
    // when endpoint closure replaces the per-access global WORD argument.
    const boundary = try @import("block_v5_program_boundary_v1.zig").deriveFromPinnedNativePublic(scope.execution_profile, &shape.public_data, prefix);
    var range = Q.zero();
    for (endpoints.sums[2..9]) |sum| range = range.add(sum);
    return .{ .scope = scope, .global_transition_sum = endpoints.sums[1], .range16_sum = range, .byte_pair_sum = endpoints.sums[9].add(endpoints.sums[10]), .program_sum = parts.program_sum.add(boundary.sum), .fetch_count = try std.math.add(u64, parts.fetch_count, boundary.fetch_count), .table_requests = parts.table_requests };
}
/// Algebra-only per-source obligation. Callers must never sum residuals
/// across sources before invoking it; swapped endpoints can cancel globally.
pub fn closeLocal(parts: Partitions, endpoint_local: Q, state_residual: Q, register_residual: Q) !void {
    try canonical(endpoint_local);
    try canonical(parts.ordinary_ram_sum);
    try canonical(parts.ram_clock_sum);
    try canonical(state_residual);
    try canonical(register_residual);
    if (!state_residual.isZero() or !register_residual.isZero()) return error.UnclosedEndpointNativeRegisters;
    if (!parts.ordinary_ram_sum.add(parts.ram_clock_sum).add(endpoint_local).isZero()) return error.UnclosedEndpointLocalRam;
}
fn canonical(value: Q) !void {
    for (value.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidEndpointNativeClaims;
}

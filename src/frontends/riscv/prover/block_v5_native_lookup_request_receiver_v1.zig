//! Fresh native-v3 table projection and field-safe provider group closure.
//! No program, memory, public compensation or complete block authority.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Admission = @import("block_v5_native_public_admission_v1.zig").Admission;
const Catalog = @import("block_v5_native_template_catalog_v1.zig");
const Projection = @import("block_v5_native_lookup_request_proof_v1.zig");
const Source = @import("block_v5_native_lookup_request_source_v1.zig");
const Providers = @import("block_v5_native_lookup_proof_v1.zig");
const Batch = @import("block_v5_native_lookup_batch_v1.zig");
const Planning = @import("block_v5_native_lookup_plan_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Shape = @import("../air/statement.zig");
const Profile = @import("../isa/execution_profile.zig").ExecutionProfile;
const schema = @import("../air/lookups/tables/schema.zig");
const Q = core.fields.qm31.QM31;
const Shared = @import("../recursion/air/universal_provider_relations.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");

pub const Instance = struct {
    shape: *const Shape.Blake3ExecutionStatement,
    admission: Admission,
    template: Native.Template,
    template_id: [32]u8,
    profile: Profile,
};
pub const Pins = struct {
    seal: Seal.Pins,
    expected_seal_digest: [32]u8,
    roster: []const Seal.Entry,
    catalog: Catalog.Admission,
    instances: []const Instance,
    providers: []const Batch.Record,
};
pub const Loader = struct {
    context: *anyopaque,
    take_native: *const fn (*anyopaque, u32) anyerror!Native.Proof,
    take_projection: *const fn (*anyopaque, u32) anyerror!Projection.Proof,
    take_provider: *const fn (*anyopaque, u32) anyerror!Providers.Proof,
};
pub const ClosedNativeTables = struct {
    execution_count: u32,
    group_count: u32,
    seal_digest: [32]u8,
    provider_sum: Q,
    native_table_sum: Q,
    caller_table_sum: Q = Q.zero(),
    /// Authenticated auxiliary local-clock bus; never real packed events.
    /// This is reported open for the enclosing native residual equation.
    auxiliary_clock_memory_sum: Q,
    register_compensation_sum: Q = Q.zero(),
};

pub fn validate(a: std.mem.Allocator, pins: Pins) !Seal.Sealed {
    const sealed = try Seal.seal(pins.seal, pins.roster);
    if (!std.meta.eql(sealed.digest, pins.expected_seal_digest) or
        !std.meta.eql(try pins.catalog.digest(), pins.seal.native_template_catalog_digest) or
        pins.instances.len != sealed.execution_instance_count or
        pins.providers.len != pins.seal.counts[@intFromEnum(Seal.Family.native_lookup) - 1])
        return error.UntrustedV5NativeLookupInputs;
    const plans = try a.alloc(Planning.Plan, pins.providers.len);
    defer a.free(plans);
    for (pins.providers, plans) |provider, *plan| plan.* = provider.plan;
    const demands = try a.alloc([schema.KIND_COUNT]u64, pins.instances.len);
    defer a.free(demands);
    for (pins.instances, demands, 0..) |pin, *demand, index| {
        try pin.admission.require(pins.seal, &pin.shape.public_data);
        if (pin.template.external_retirements != 0)
            return error.V5CallerStateProjectionRequired;
        try pins.catalog.admit(pins.seal, sealed, @intCast(index), pin.template, pin.template_id);
        demand.* = try Planning.nativeDemand(pin.shape, pin.template.external_retirements);
    }
    try Planning.validateDemandRoster(plans, demands);
    return sealed;
}

pub fn verify(comptime Backend: type, a: std.mem.Allocator, pins: Pins, loader: Loader) !ClosedNativeTables {
    const sealed = try validate(a, pins);
    var channel = sealed.sharedChannel();
    const relations = try Shared.SharedProviderRelations.init(&(try Universal.UniversalRelations.draw(a, &channel)));
    const ProviderApi = Providers.ForBackend(Backend);
    var basis = try ProviderApi.FixedBasis.init(a, pins.seal.config);
    defer basis.deinit(a);
    var auxiliary_clock_memory_sum = Q.zero();
    var provider_sum = Q.zero();
    var native_table_sum = Q.zero();
    for (pins.providers) |record| {
        const provider = try ProviderApi.verifyOwnedWithBasis(a, try loader.take_provider(loader.context, record.plan.index), record.plan, record.roots, sealed, pins.seal, pins.roster, &basis);
        var consumers: [schema.KIND_COUNT]Q = @splat(Q.zero());
        const end = @as(usize, record.plan.first_execution) + record.plan.execution_count;
        for (pins.instances[record.plan.first_execution..end], record.plan.first_execution..) |pin, index| {
            const ordinal: u32 = @intCast(index);
            const native = try Native.ForBackend(Backend).verifyOwnedWithCatalog(a, try loader.take_native(loader.context, ordinal), pin.shape, pin.admission, pin.template, pin.template_id, pin.profile, ordinal, sealed, pins.seal, pins.roster, pins.catalog);
            const slots = try Source.slotsFromShape(a, pin.shape, pin.template.external_retirements);
            defer a.free(slots);
            // A fresh native shape with no table consumers needs no synthetic
            // projection STARK or proof-carried zero claim.
            const public_state = try @import("../air/public_logup_arithmetic.zig").registersStateSumFor(Q, &pin.shape.public_data, &relations.native);
            if (slots.len == 0) {
                if (!public_state.isZero()) return error.UnclosedV5NativePublicState;
                continue;
            }
            const fixed_logs = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .fixed);
            defer a.free(fixed_logs);
            const main_logs = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .main);
            defer a.free(main_logs);
            const request = try Projection.ForBackend(Backend).verifyOwned(a, try loader.take_projection(loader.context, ordinal), sealed, ordinal, pin.template_id, native.instance_id, slots, fixed_logs, main_logs, native.first_roots, native.first_roots, pins.seal.config);
            if (!request.registers_state_sum.add(public_state).isZero())
                return error.UnclosedV5NativePublicState;
            auxiliary_clock_memory_sum = auxiliary_clock_memory_sum.add(request.auxiliary_clock_memory_sum);
            for (&consumers, request.claims) |*sum, claim| sum.* = sum.add(claim);
        }
        try requireClosedGroup(provider.claims, consumers);
        for (provider.claims, consumers) |supply, demand| {
            provider_sum = provider_sum.add(supply);
            native_table_sum = native_table_sum.add(demand);
        }
    }
    return .{ .execution_count = sealed.execution_instance_count, .group_count = @intCast(pins.providers.len), .seal_digest = sealed.digest, .auxiliary_clock_memory_sum = auxiliary_clock_memory_sum, .provider_sum = provider_sum, .native_table_sum = native_table_sum };
}

fn requireClosedGroup(providers: [schema.KIND_COUNT]Q, consumers: [schema.KIND_COUNT]Q) !void {
    for (providers, consumers) |provider, consumer|
        if (!provider.add(consumer).isZero()) return error.UnclosedV5NativeLookupGroup;
}

test "block-v5 native table groups cannot hide opposite residuals in a block total" {
    var left: [schema.KIND_COUNT]Q = @splat(Q.zero());
    var right: [schema.KIND_COUNT]Q = @splat(Q.zero());
    left[0] = Q.one();
    right[0] = Q.one().neg();
    try std.testing.expect(left[0].add(right[0]).isZero());
    try std.testing.expectError(error.UnclosedV5NativeLookupGroup, requireClosedGroup(left, @splat(Q.zero())));
    try std.testing.expectError(error.UnclosedV5NativeLookupGroup, requireClosedGroup(right, @splat(Q.zero())));
}

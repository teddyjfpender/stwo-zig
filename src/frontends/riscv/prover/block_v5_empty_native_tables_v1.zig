//! No lookup STARK exists for a genuinely empty native opcode/infra roster.
//! This derivation is internal fresh-hook bookkeeping, never proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Admission = @import("block_v5_native_public_admission_v1.zig").Admission;
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Catalog = @import("block_v5_native_template_catalog_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Planning = @import("block_v5_native_lookup_plan_v1.zig");
const Source = @import("block_v5_native_lookup_request_source_v1.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
const Shared = @import("../recursion/air/universal_provider_relations.zig");
pub const VERSION: u32 = 1;
pub const Partition = struct {
    claims: [Schema.KIND_COUNT]Q,
    public_state_sum: Q,
    auxiliary_clock_memory_sum: Q,
};
pub const Pins = struct {
    shape: *const Shape,
    admission: Admission,
    template: Native.Template,
    template_id: [32]u8,
    catalog: Catalog.Admission,
};

/// Producer and receiver must agree on this exact empty geometry. In
/// particular, zero ordinary opcodes never licenses dropping clock-update
/// requests: any infrastructure requires the existing nonempty projection.
pub fn validateShape(a: std.mem.Allocator, shape: *const Shape, external_retirements: u32) !void {
    try @import("block_v5_empty_program_request_v1.zig").validateShape(shape, external_retirements);
    if (shape.n_infra != 0 or shape.nPreprocessedColumns() != 0 or shape.nMainColumns() != 0 or shape.nInteractionColumns() != 0)
        return error.NonemptyV5NativeLookupGeometry;
    for (try Planning.nativeDemand(shape, external_retirements)) |count| if (count != 0) return error.NonemptyV5NativeLookupCensus;
    const slots = try Source.slotsFromShape(a, shape, external_retirements);
    defer a.free(slots);
    if (slots.len != 0) return error.NonemptyV5NativeLookupGeometry;
}

/// Called only after the enclosing receiver freshly verifies native-v3. No
/// proof-carried zero scalar, arbitrary empty wire or caller receipt is used.
/// The public PC/clock compensation is retained; real caller retirements must
/// still cancel it in the enclosing per-leaf state join.
pub fn fromFresh(a: std.mem.Allocator, independent: Pins, fresh: *const Native.OpenReceipt, index: u32, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry) !Partition {
    try sealed.require(pins, roster);
    try validateShape(a, independent.shape, independent.template.external_retirements);
    try independent.admission.require(pins, &independent.shape.public_data);
    try independent.template.admit(independent.shape, independent.template_id);
    try independent.catalog.admit(pins, sealed, index, independent.template, independent.template_id);
    if (index >= sealed.execution_instance_count or independent.admission.context.execution_index != index or
        !std.meta.eql(independent.template.config, pins.config) or
        !std.meta.eql(fresh.template_id, independent.template_id) or
        !std.meta.eql(fresh.first_roots[0], independent.template.fixed_root) or
        !std.meta.eql(fresh.sealed_digest, sealed.digest) or
        !std.meta.eql(fresh.instance_id, try Template.instanceId(independent.template_id, independent.shape, independent.admission, fresh.first_roots, index)))
        return error.UntrustedV5EmptyNativeTables;
    var found = false;
    for (roster) |entry| if (entry.family == .execution and entry.index == index) {
        if (!std.meta.eql(entry.instance_id, fresh.instance_id) or !std.meta.eql(entry.roots, fresh.first_roots)) return error.UntrustedV5EmptyNativeTables;
        found = true;
    };
    if (!found) return error.MissingV5EmptyNativeTables;
    var channel = sealed.sharedChannel();
    const universal = try Universal.UniversalRelations.draw(a, &channel);
    const relations = try Shared.SharedProviderRelations.init(&universal);
    const public_state_sum = try @import("../air/public_logup_arithmetic.zig").registersStateSumFor(Q, &independent.shape.public_data, &relations.native);
    if (!fresh.open_sum.eql(public_state_sum)) return error.UntrustedV5EmptyNativeOpenClaim;
    return .{ .claims = @splat(Q.zero()), .public_state_sum = public_state_sum, .auxiliary_clock_memory_sum = Q.zero() };
}

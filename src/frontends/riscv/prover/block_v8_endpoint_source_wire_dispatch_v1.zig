//! Explicit Local/Mixed schema AND envelope dispatch. No parser fallback or
//! source-provided receipt. Returned CPU/source fields follow fresh original
//! verification and own no pointer into released metadata/proof workspaces.
const std = @import("std");
const Local = @import("block_v8_endpoint_local_scope_v1.zig");
const LocalMetadata = @import("block_v8_endpoint_local_statement_wire_v1.zig");
const LocalCodec = @import("block_v8_endpoint_local_codec_v1.zig");
const MixedMetadata = @import("block_v8_endpoint_mixed_statement_wire_v1.zig");
const MixedCodec = @import("block_v8_endpoint_mixed_codec_v1.zig");
pub const production_active = false;
pub const Kind = enum { local_complete, local_sparse, mixed_complete, mixed_sparse, local_direct_complete, local_direct_sparse, local_wide_complete, local_wide_sparse };
pub const Limits = struct { metadata: LocalMetadata.Limits = .{}, local: LocalCodec.Limits = .{}, mixed_metadata: MixedMetadata.Limits = .{}, mixed: MixedCodec.Limits = .{} };
pub const Verified = struct {
    kind: Kind,
    source: Local.Source,
    cycles: u32,
    external_retirements: u32,
    logical_ram_accesses: u64,
    program_fetches: u64,
    cohort_ordinal: u32,
    initial_pc: u32,
    final_pc: u32,
    initial_regs: [32]u32,
    final_regs: [32]u32,
};
pub fn identify(a: std.mem.Allocator, metadata: []const u8, proof: []const u8, maximum: usize) !Kind {
    if (maximum == 0 or metadata.len > maximum or proof.len < 8) return error.InvalidEndpointSourceTransport;
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.createRetainingParent(a, @max(1 << 20, try std.math.mul(usize, maximum, 4)));
    defer budget.destroy();
    const parsed = try std.json.parseFromSlice(struct { schema: []const u8 }, budget.allocator(), metadata, .{ .ignore_unknown_fields = true, .max_value_len = maximum });
    defer parsed.deinit();
    const schema = parsed.value.schema;
    const kind: Kind = if (std.mem.eql(u8, schema, "stwo-v8-local-native-endpoint-metadata-v1")) .local_complete else if (std.mem.eql(u8, schema, LocalMetadata.SPARSE_SCHEMA)) .local_sparse else if (std.mem.eql(u8, schema, LocalMetadata.DIRECT_SCHEMA)) .local_direct_complete else if (std.mem.eql(u8, schema, LocalMetadata.SPARSE_DIRECT_SCHEMA)) .local_direct_sparse else if (std.mem.eql(u8, schema, LocalMetadata.WIDE_SCHEMA)) .local_wide_complete else if (std.mem.eql(u8, schema, LocalMetadata.SPARSE_WIDE_SCHEMA)) .local_wide_sparse else if (std.mem.eql(u8, schema, MixedMetadata.SCHEMA)) .mixed_complete else if (std.mem.eql(u8, schema, MixedMetadata.SPARSE_SCHEMA)) .mixed_sparse else return error.UnknownEndpointSourceSchema;
    const expected: []const u8 = switch (kind) {
        .local_complete => LocalCodec.MAGIC,
        .local_sparse => LocalCodec.SPARSE_MAGIC,
        .local_direct_complete => LocalCodec.DIRECT_MAGIC,
        .local_direct_sparse => LocalCodec.SPARSE_DIRECT_MAGIC,
        .local_wide_complete => LocalCodec.WIDE_MAGIC,
        .local_wide_sparse => LocalCodec.SPARSE_WIDE_MAGIC,
        .mixed_complete => MixedCodec.MAGIC,
        .mixed_sparse => MixedCodec.SPARSE_MAGIC,
    };
    if (!std.mem.eql(u8, proof[0..8], expected)) return error.EndpointSourceSchemaMagicMismatch;
    return kind;
}
pub fn verifyBytes(a: std.mem.Allocator, metadata: []const u8, proof: []const u8, trusted: Local.Trusted, limits: Limits) !Verified {
    const kind = try identify(a, metadata, proof, @max(limits.metadata.bytes, limits.mixed_metadata.bytes));
    switch (kind) {
        .local_complete, .local_sparse, .local_direct_complete, .local_direct_sparse, .local_wide_complete, .local_wide_sparse => {
            const statement = try LocalMetadata.decode(a, metadata, trusted, limits.metadata);
            defer statement.deinit();
            const checked = try LocalCodec.verifyBytes(a, proof, statement.trusted, statement.input, limits.local);
            const data = statement.input.shape.public_data;
            return .{ .kind = kind, .source = checked.source, .cycles = checked.cycles, .external_retirements = 0, .logical_ram_accesses = checked.logical_ram_accesses, .program_fetches = checked.program_fetches, .cohort_ordinal = statement.input.cohort_ordinal, .initial_pc = data.initial_pc, .final_pc = data.final_pc, .initial_regs = data.initial_regs, .final_regs = data.final_regs };
        },
        .mixed_complete, .mixed_sparse => {
            const statement = try MixedMetadata.decode(a, metadata, trusted, limits.mixed_metadata);
            defer statement.deinit();
            const checked = try MixedCodec.verifyBytes(a, proof, statement.trusted, statement.input, limits.mixed);
            const data = statement.input.shape.public_data;
            if (checked.external_retirements == 0 or checked.external_retirements > checked.cycles) return error.InvalidEndpointMixedRetirements;
            return .{ .kind = kind, .source = checked.source, .cycles = checked.cycles, .external_retirements = checked.external_retirements, .logical_ram_accesses = checked.logical_ram_accesses, .program_fetches = checked.program_fetches, .cohort_ordinal = statement.input.cohort_ordinal, .initial_pc = data.initial_pc, .final_pc = data.final_pc, .initial_regs = data.initial_regs, .final_regs = data.final_regs };
        },
    }
}

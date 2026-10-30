//! V7 native-source admission and pure ledger extraction. Original native,
//! projection and packed-access AIRs are reused without a fabricated v5 seal.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const E = @import("block_v7_execution_epoch_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const Selection = @import("block_v7_native_layout_selection_v1.zig");
pub const Layout = Selection.Layout;
pub const LayoutMode = Selection.Mode;
const Batch = @import("block_execution_sidecar_batch_v2.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
pub const Pin = struct {
    index: u32,
    shape: *const Shape,
    frame: @import("../air/block/memory_event.zig").Frame,
    template: Template.Template,
    roots: [2][32]u8,
    access_root: [32]u8,
    expected_events: u64,
    /// Independently admitted protocol choice; never inferred from proof claims.
    layout_mode: LayoutMode = .canonical_v1,
    pub fn layout(self: Pin, a: std.mem.Allocator) !Layout {
        return Selection.derive(a, self.shape, self.template.external_retirements, self.layout_mode);
    }
    pub fn validate(self: Pin) !void {
        try self.template.admit(self.shape, try self.template.identity());
        const data = &self.shape.public_data;
        _ = try @import("block_v7_native_geometry_v1.zig").classify(self.shape, self.template.external_retirements);
        if (self.frame.clock_frame != .leaf_local or self.frame.global_first_cycle == 0 or self.frame.cycle_count != data.clock or
            !std.meta.eql(self.roots[0], self.template.fixed_root) or data.initial_rw_root != null or data.final_rw_root != null or
            data.io_entries.input_len != 0 or data.io_entries.input_words.len != 0 or data.io_entries.output_len != 0 or data.io_entries.output_words.len != 0 or
            self.expected_events >= core.fields.m31.Modulus) return error.InvalidV7NativeSource;
    }
    pub fn entry(self: Pin, a: std.mem.Allocator) !E.Entry {
        try self.validate();
        var relation_layout = try self.layout(a);
        defer relation_layout.deinit();
        const slots = try Batch.slotsFromStatementForMode(a, self.shape, self.frame, 1);
        defer a.free(slots);
        if ((slots.len == 0 and (self.expected_events != 0 or !std.mem.allEqual(u8, &self.access_root, 0))) or (slots.len != 0 and std.mem.allEqual(u8, &self.access_root, 0))) return error.InvalidV7NativeAccessRoot;
        var ch = suite.Channel{};
        ch.mixU32s(&.{ 0x42374e53, 1, self.index, 1 });
        const Geometry = @import("block_v7_native_geometry_v1.zig");
        Geometry.mix(&ch, try Geometry.classify(self.shape, self.template.external_retirements));
        ch.mixRoot(try self.template.identity());
        ch.mixRoot(relation_layout.digest);
        self.shape.public_data.mixInto(&ch);
        self.shape.mixShardManifest(&ch);
        ch.mixU64(self.frame.global_first_cycle);
        ch.mixU32s(&.{self.frame.cycle_count});
        ch.mixU64(self.expected_events);
        Batch.mixRoster(&ch, self.index, try self.template.identity(), slots);
        const roots = self.roots ++ .{self.access_root};
        return E.Entry.init(.native, self.index, ch.digestBytes(), roots[0..if (slots.len == 0) @as(usize, 2) else 3]);
    }
};
pub const Exports = struct {
    program_sum: Q,
    fetch_count: u64,
    table_requests: [Schema.KIND_COUNT]Q,
    state_residual: Q,
    register_residual: Q,
    auxiliary_clock_memory: Q,
    ordinary_memory_residual: Q,
    transition_sum: Q,
    event_count: u64,
    byte_requests: Q,
};
/// Call only after fresh original verification. These values are open until
/// global providers and every individual register/state window are closed.
pub fn exports(a: std.mem.Allocator, pin: Pin, proof: *const Fused.Proof, drawn: *const E.Drawn) !Exports {
    return exportsFromClaims(a, pin, proof.claims, proof.memory_claims, drawn);
}
/// Extract only after the original proof or its exact recursive verifier has
/// authenticated these physical claims. This function confers no authority.
pub fn exportsFromClaims(a: std.mem.Allocator, pin: Pin, claims: []const Fused.Claim, memory_claims: []const Memory.Claim, drawn: *const E.Drawn) !Exports {
    var layout = try pin.layout(a);
    defer layout.deinit();
    if (claims.len != layout.slots.len) return error.InvalidV7NativeClaims;
    const shared = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&drawn.word.universal_prefix);
    var partitions: [Source.PARTITION_COUNT]Q = @splat(Q.zero());
    var program = Q.zero();
    var fetches: u64 = 0;
    for (layout.slots, claims) |slot, claim| switch (slot.kind) {
        .program => {
            program = program.add(claim.sum);
            fetches = try std.math.add(u64, fetches, claim.row_count);
        },
        .lookup => |lookup| {
            partitions[@intFromEnum(lookup.partition)] = partitions[@intFromEnum(lookup.partition)].add(claim.sum);
        },
    };
    const boundary = try @import("block_v5_program_boundary_v1.zig").deriveFromPinnedNativePublic(pin.template.execution_profile, &pin.shape.public_data, &drawn.word.universal_prefix);
    program = program.add(boundary.sum);
    fetches = try std.math.add(u64, fetches, boundary.fetch_count);
    const Public = @import("../air/public_logup_arithmetic.zig");
    const Partition = @import("block_v5_native_lookup_request_source_v1.zig").Partition;
    var out = Exports{ .program_sum = program, .fetch_count = fetches, .table_requests = partitions[0..Schema.KIND_COUNT].*, .state_residual = (try Public.registersStateSumFor(Q, &pin.shape.public_data, &shared.native)).add(partitions[@intFromEnum(Partition.registers_state)]), .register_residual = (try Public.registerMemoryAccessSumFor(Q, &pin.shape.public_data, &shared.native)).add(partitions[@intFromEnum(Partition.register_memory_access)]).add(partitions[@intFromEnum(Partition.register_clock_memory_access)]), .auxiliary_clock_memory = partitions[@intFromEnum(Partition.clock_memory_access)], .ordinary_memory_residual = partitions[@intFromEnum(Partition.ordinary_memory_access)], .transition_sum = Q.zero(), .event_count = 0, .byte_requests = Q.zero() };
    for (memory_claims) |claim| {
        out.transition_sum = out.transition_sum.add(claim.transition_sum);
        out.ordinary_memory_residual = out.ordinary_memory_residual.add(claim.universal_sum);
        out.event_count = try std.math.add(u64, out.event_count, claim.active_count);
        for (claim.range_claims) |sum| out.byte_requests = out.byte_requests.add(sum);
    }
    if (out.event_count != pin.expected_events) return error.UntrustedV7NativeCensus;
    return out;
}

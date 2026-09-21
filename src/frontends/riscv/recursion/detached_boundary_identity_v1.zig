//! Detached boundary identity operations; shared by the canonical preparation owner.
const recorder = @import("air/composition_graph_recorder.zig");
const S = recorder.Scalar;
const recursion = struct {
    const segment_statement_v2 = @import("segment_statement_v2.zig");
    const span_statement = @import("span_statement.zig");
};
const wire_layout = recursion.segment_statement_v2.fixed_layout;
const span_layout = recursion.span_statement.canonical_layout;
const BASE = wire_layout.base_statement;
const SectionV1 = @import("detached_section_profile_v1.zig").SectionV1;
const graph = @import("detached_boundary_graph_v1.zig");
const U32 = graph.U32;
const base = graph.base;
const GraphCalls = graph.GraphCalls;
const GraphSponge = graph.GraphSponge;
const identity_preimage = recursion.segment_statement_v2.identity_preimage;
const riscv_air = struct {
    const public_data_v2 = @import("../air/public_data_v2.zig");
};

pub fn identityOffset(phase: identity_preimage.Phase) usize {
    return switch (phase) {
        .job => wire_layout.job_id,
        .base_statement => wire_layout.base_statement_id,
        .position => wire_layout.position_id,
        .entry_lineage => wire_layout.entry_lineage_id,
        .exit_lineage => wire_layout.exit_lineage_id,
        .lineage => wire_layout.lineage_id,
    };
}
pub fn embeddedIdentityInputs(view: *const recursion.segment_statement_v2.CanonicalWireViewV2, metadata: *const riscv_air.public_data_v2.Metadata) ![6]identity_preimage.Input {
    const statement = &view.statement;
    const span = try statement.base();
    return .{
        .{ .job = &statement.base_statement_words },
        .{ .base_statement = &statement.base_statement_words },
        .{ .position = .{
            .session_id = statement.session_id,
            .job_id = statement.job_id,
            .segment_index = metadata.segment_index,
            .segment_count = metadata.segment_count,
            .range = .{ .start = metadata.global_cycle_start, .end = metadata.global_cycle_end },
            .slots = span.slots,
        } },
        .{ .entry_lineage = .{
            .session_id = statement.session_id,
            .job_id = statement.job_id,
            .boundary_index = metadata.segment_index,
            .cycle = metadata.global_cycle_start,
            .machine_words = statement.base_statement_words[span_layout.entry_state_start..][0..recursion.span_statement.MACHINE_STATE_CANONICAL_WORDS],
            .snapshot = .{ .id = statement.entry_snapshot_id, .count = statement.entry_snapshot_count, .root = statement.entry_continuation_root },
            .register_clocks = statement.entry_register_clocks,
            .memory_clock_id = statement.entry_memory_clock_id,
            .memory_clock_count = statement.entry_memory_clock_count,
        } },
        .{ .exit_lineage = .{
            .session_id = statement.session_id,
            .job_id = statement.job_id,
            .boundary_index = metadata.segment_index + 1,
            .cycle = metadata.global_cycle_end,
            .machine_words = statement.base_statement_words[span_layout.exit_state_start..][0..recursion.span_statement.MACHINE_STATE_CANONICAL_WORDS],
            .snapshot = .{ .id = statement.exit_snapshot_id, .count = statement.exit_snapshot_count, .root = statement.exit_continuation_root },
            .register_clocks = statement.exit_register_clocks,
            .memory_clock_id = statement.exit_memory_clock_id,
            .memory_clock_count = statement.exit_memory_clock_count,
        } },
        .{ .lineage = .{
            .session_id = statement.session_id,
            .job_id = statement.job_id,
            .position_id = statement.position_id,
            .entry_lineage_id = statement.entry_lineage_id,
            .exit_lineage_id = statement.exit_lineage_id,
            .base_statement_id = statement.base_statement_id,
        } },
    };
}
pub const SymbolicSlots = struct {
    first: [4]S,
    height: S,
    node_index: [4]S,
    pub fn nodeIndex(self: SymbolicSlots) [4]S {
        return self.node_index;
    }
};
pub fn bindIdentity(comptime phase: identity_preimage.Phase, calls: *GraphCalls, wire: []const S, input: anytype) !void {
    var hash = GraphSponge.init(calls, identity_preimage.domain(phase));
    identity_preimage.emitPhase(phase, &hash, input);
    const digest = hash.finish();
    for (digest, wire[identityOffset(phase)..][0..8]) |actual, expected| try calls.builder.constrainZero(actual.sub(expected));
}
pub fn recordEmbeddedIdentities(calls: *GraphCalls, wire: []const S, index: U32, next: U32, count: U32, start: U32, end: U32) !void {
    const span = wire[BASE..][0..recursion.span_statement.SPAN_STATEMENT_CANONICAL_WORDS];
    try bindIdentity(.job, calls, wire, span);
    try bindIdentity(.base_statement, calls, wire, span);
    const node_index = span[span_layout.slot_node_index_start..][0..4].*;
    const height = span[span_layout.slot_height];
    try calls.builder.constrainZero(height);
    const first = [4]S{ index.limbs[0], index.limbs[1], S.zero(), S.zero() };
    for (node_index, first) |actual, expected| try calls.builder.constrainZero(actual.sub(expected));
    try bindIdentity(.position, calls, wire, .{
        .session_id = wire[wire_layout.session_id..][0..8].*,
        .job_id = wire[wire_layout.job_id..][0..8].*,
        .segment_index = index,
        .segment_count = count,
        .range = .{ .start = start, .end = end },
        .slots = SymbolicSlots{ .first = first, .height = height, .node_index = node_index },
    });
    inline for (.{ identity_preimage.Phase.entry_lineage, identity_preimage.Phase.exit_lineage }, 0..) |phase, side| {
        const snapshot = if (side == 0) wire_layout.entry_snapshot_id else wire_layout.exit_snapshot_id;
        const root = if (side == 0) wire_layout.entry_continuation_root else wire_layout.exit_continuation_root;
        const clocks = if (side == 0) wire_layout.entry_register_clocks else wire_layout.exit_register_clocks;
        const clock_id = if (side == 0) wire_layout.entry_memory_clock_id else wire_layout.exit_memory_clock_id;
        const machine = if (side == 0) span_layout.entry_state_start else span_layout.exit_state_start;
        var register_clocks: [32]U32 = undefined;
        for (&register_clocks, 0..) |*clock, register| clock.* = .{ .limbs = wire[clocks + register * 2 ..][0..2].* };
        try bindIdentity(phase, calls, wire, .{
            .session_id = wire[wire_layout.session_id..][0..8].*,
            .job_id = wire[wire_layout.job_id..][0..8].*,
            .boundary_index = if (side == 0) index else next,
            .cycle = if (side == 0) start else end,
            .machine_words = span[machine..][0..recursion.span_statement.MACHINE_STATE_CANONICAL_WORDS],
            .snapshot = .{ .id = wire[snapshot..][0..8].*, .count = U32{ .limbs = wire[snapshot + 8 ..][0..2].* }, .root = (U32{ .limbs = wire[root..][0..2].* }).value() },
            .register_clocks = register_clocks,
            .memory_clock_id = wire[clock_id..][0..8].*,
            .memory_clock_count = U32{ .limbs = wire[clock_id + 8 ..][0..2].* },
        });
        // The Span's RW-memory commitment names this retained snapshot.
        const rw = machine + span_layout.machine_state_rw_digest_start_offset;
        for (span[rw..][0..8], wire[snapshot..][0..8]) |actual, expected| try calls.builder.constrainZero(actual.sub(expected));
    }
    try bindIdentity(.lineage, calls, wire, .{
        .session_id = wire[wire_layout.session_id..][0..8].*,
        .job_id = wire[wire_layout.job_id..][0..8].*,
        .position_id = wire[wire_layout.position_id..][0..8].*,
        .entry_lineage_id = wire[wire_layout.entry_lineage_id..][0..8].*,
        .exit_lineage_id = wire[wire_layout.exit_lineage_id..][0..8].*,
        .base_statement_id = wire[wire_layout.base_statement_id..][0..8].*,
    });
}
pub fn recordRetainedIdentities(calls: *GraphCalls, wire: []const S, sections: [4]SectionV1) !void {
    for (sections) |section| {
        try calls.builder.constrainZero(wire[section.header_start].sub(base(@intFromEnum(section.tag))));
        for (0..2) |limb| {
            const expected = base((section.count >> @as(u5, @intCast(16 * limb))) & 65535);
            try calls.builder.constrainZero(wire[section.header_start + 1 + limb].sub(expected));
            try calls.builder.constrainZero(wire[section.count_offset + limb].sub(expected));
        }
        var hash = GraphSponge.init(calls, section.domain);
        identity_preimage.emitRetainedSection(&hash, section.count, wire[section.payload_start..][0..section.payloadWords()]);
        const digest = hash.finish();
        for (digest, wire[section.digest_offset..][0..8]) |actual, expected| try calls.builder.constrainZero(actual.sub(expected));
    }
}

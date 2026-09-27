//! Sealed block-v4 statement from streamed first-round roots and counters.
//! All borrowed roots must have been committed before challenge draw.
const std = @import("std");
const batch = @import("block_memory_batch_verify_v2.zig");
const producer = @import("block_memory_batch_produce_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const source_mod = @import("block_v4_public_source_assembly.zig");
const execution = @import("block_v4_cpu_streaming_first_round.zig");
const tables = @import("block_v4_cpu_streaming_tables.zig");
const trusted_mod = @import("block_v4_cpu_multi_segment_assembly.zig");

pub const Bound = struct {
    a: std.mem.Allocator,
    value: batch.PinnedStatement,
    memory_pins: []batch.MemoryPin,
    native_roots: []batch.Roots,
    opcode_roots: []batch.Roots,
    opcode_counts: []u64,
    external_counts: []u64,
    external_roots: []seal_mod.FirstRoundEntry,

    pub fn deinit(self: *Bound) void {
        self.a.free(self.external_roots);
        self.a.free(self.external_counts);
        self.a.free(self.opcode_counts);
        self.a.free(self.opcode_roots);
        self.a.free(self.native_roots);
        self.a.free(self.memory_pins);
        self.* = undefined;
    }
};

pub fn bind(a: std.mem.Allocator, trusted: trusted_mod.Trusted, first: *const execution.FirstRound, memory_first: *const producer.FirstPass, public: *const source_mod.Prepared, opcode_tables: *const tables.Tables, external_tables: ?*const tables.Tables) !Bound {
    if (first.entries.len != trusted.native_key_ids.len or
        @as(usize, trusted.job.segment_count) != first.entries.len or
        @as(usize, trusted.base_seal.instance_count) != first.entries.len or
        opcode_tables.plan != &first.opcode_plan or
        (external_tables != null) != (first.external_events != 0))
        return error.InvalidStreamingBlockStatementInput;
    if (external_tables) |value| if (value.plan != &first.external_plan)
        return error.InvalidStreamingBlockStatementInput;
    const memory_pins = try a.alloc(batch.MemoryPin, memory_first.claims.len);
    errdefer a.free(memory_pins);
    for (memory_pins, memory_first.claims, memory_first.memory_roots) |*pin, claim, roots|
        pin.* = .{ .claim = claim, .roots = roots };
    const native_roots = try a.alloc(batch.Roots, first.entries.len);
    errdefer a.free(native_roots);
    const opcode_roots = try a.alloc(batch.Roots, first.entries.len);
    errdefer a.free(opcode_roots);
    const opcode_counts = try a.alloc(u64, first.entries.len);
    errdefer a.free(opcode_counts);
    const external_counts = try a.alloc(u64, first.entries.len);
    errdefer a.free(external_counts);
    var external_root_count: usize = 0;
    for (first.entries) |entry| external_root_count += @intFromBool(entry.external_witness_root != null);
    const external_roots = try a.alloc(seal_mod.FirstRoundEntry, external_root_count);
    errdefer a.free(external_roots);
    var next_external: usize = 0;
    for (first.entries, native_roots, opcode_roots, opcode_counts, external_counts, 0..) |entry, *native, *opcode, *opcode_count, *external_count, index| {
        if (!std.mem.eql(u8, &entry.hash_pin.key_id, &trusted.native_key_ids[index]) or
            (entry.external_witness_root == null) != (entry.external_events == 0))
            return error.InvalidStreamingBlockExecutionRoster;
        native.* = entry.native_roots;
        opcode.* = .{ entry.opcode_witness_root, @splat(0) };
        opcode_count.* = entry.opcode_events;
        external_count.* = entry.external_events;
        if (entry.external_witness_root) |root| {
            external_roots[next_external] = .{ .family = .execution_extension_witness, .index = @intCast(index), .roots = .{ root, @splat(0) } };
            next_external += 1;
        }
    }
    var value = batch.PinnedStatement{
        .seal = try seal_mod.SourceSeal.init(trusted.base_seal, public.register_mask, public.digest),
        .expected_events = first.event_count,
        .memory_instances = memory_pins,
        .range_table_roots = memory_first.table_roots,
        .execution_roots = native_roots,
        .execution_sidecar_roots = opcode_roots,
        .execution_active_counts = opcode_counts,
        .execution_range_table_roots = opcode_tables.roots,
        .execution_extension_roots = external_roots,
        .execution_extension_active_counts = if (external_tables == null) &.{} else external_counts,
        .execution_extension_range_table_roots = if (external_tables) |item| item.roots else &.{},
        .provider_roots = &.{},
        .complete_pins = .{ .expected_job = trusted.job, .initial_rw_anchor = public.pin.initial_rw_root.bytes, .program_root = trusted.job.complete.program.bytes, .outer_recursive_key_id = trusted.outer_key_id, .forest_roster_digest = trusted.forest_roster_digest },
    };
    const first_digest = try value.firstRoundDigest(a);
    value.seal = if (external_tables != null)
        try seal_mod.SourceSeal.initBoundWithExtension(trusted.base_seal, public.register_mask, public.digest, @intCast(first.entries.len), @intCast(memory_pins.len), memory_first.plan.digest, first_digest, first.external_plan.digest)
    else
        try seal_mod.SourceSeal.initBound(trusted.base_seal, public.register_mask, public.digest, @intCast(first.entries.len), @intCast(memory_pins.len), memory_first.plan.digest, first_digest);
    return .{ .a = a, .value = value, .memory_pins = memory_pins, .native_roots = native_roots, .opcode_roots = opcode_roots, .opcode_counts = opcode_counts, .external_counts = external_counts, .external_roots = external_roots };
}

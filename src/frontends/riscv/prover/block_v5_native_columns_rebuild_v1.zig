//! Shared base native owner reconstruction for exact-row and capacity stages.
//! Stored cells have no proof authority. Counters/public fields are rebuilt;
//! the selected typed stage must recommit and compare independent roots.
const std = @import("std");
const core = @import("stwo_core");
const Store = @import("block_v5_witness_columns_store_v1.zig");
const Native = @import("blake3_execution_trace.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Trace = @import("../runner/trace.zig");
const Columns = @import("opcode_trace.zig").Columns;
const Tables = @import("../air/lookups/tables/counter.zig");
const Ingest = @import("../air/lookups/tables/source_ingest.zig");
const Clock = @import("../air/clock_update_interaction.zig");
const Infra = @import("../infra_trace.zig");
pub const Limits = struct {
    columns: Store.Limits,
    max_public_words: usize,
    max_public_bytes: usize,
};
pub const Pin = Store.Pin;

pub fn requirePublicLimits(shape: *const Shape, limits: Limits) !void {
    const io = shape.public_data.io_entries;
    const words = try std.math.add(usize, io.input_words.len, io.output_words.len);
    const bytes = try std.math.add(usize, try std.math.mul(usize, io.input_words.len, @sizeOf(u32)), try std.math.mul(usize, io.output_words.len, @sizeOf(@import("../air/public_data.zig").OutputWord)));
    if (words > limits.max_public_words or bytes > limits.max_public_bytes) return error.V5StagedNativePublicLimit;
}

pub fn logs(a: std.mem.Allocator, shape: *const Shape) ![]u32 {
    const result = try a.alloc(u32, shape.nMainColumns());
    errdefer a.free(result);
    var at: usize = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| {
        @memset(result[at..][0..desc.n_columns], desc.log_size);
        at += desc.n_columns;
    }
    for (shape.infra_descs[0..shape.n_infra]) |desc| {
        if (desc.kind != .clock_update or desc.n_columns != Infra.CLOCK_UPDATE_COLS) return error.InvalidV5StagedNativeShape;
        @memset(result[at..][0..desc.n_columns], desc.log_size);
        at += desc.n_columns;
    }
    if (at != result.len) return error.InvalidV5StagedNativeShape;
    return result;
}

/// Owns all main/public/fixed storage in one segment arena. Every opcode/clock
/// slice aliases the exact loaded main cells; counters are regenerated from
/// those cells rather than accepted as file-supplied scalar claims.
pub fn rebuild(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, shape: *const Shape, external_retirements: u32, expected_scope: Store.Scope, pin: Pin, limits: Limits) !*Native.Owner {
    try shape.validateBlake3ExecutionWithExternal(external_retirements);
    try requirePublicLimits(shape, limits);
    if (expected_scope.kind != .native or expected_scope.cycle_count != shape.total_steps or expected_scope.first_cycle == 0) return error.InvalidV5StagedNativeShape;
    const owner = try a.create(Native.Owner);
    owner.* = .{ .allocator = a, .arena = std.heap.ArenaAllocator.init(a), .statement = shape.*, .opcode_columns = undefined, .external_retirements = external_retirements };
    errdefer owner.deinit();
    const arena = owner.arena.allocator();
    owner.claims.initZeroInto();
    const io = &owner.statement.public_data.io_entries;
    io.input_words = try arena.dupe(u32, io.input_words);
    io.output_words = try arena.dupe(@import("../air/public_data.zig").OutputWord, io.output_words);
    const expected_logs = try logs(arena, &owner.statement);
    const loaded = try Store.load(arena, dir, name, expected_scope, expected_logs, pin, limits.columns);
    try owner.main.appendSlice(arena, loaded.columns);
    owner.opcode_columns = Columns{ .components = undefined, .lookup_counters = try Tables.Set.init(arena), .counter_set_merges = 0, .direct_semantic_audit_performed = false };
    for (&owner.opcode_columns.components) |*component| component.* = .{ .columns = @splat(&.{}), .n_columns = 0, .n_real_rows = 0 };
    var at: usize = 0;
    for (owner.statement.component_descs[0..owner.statement.n_components], 0..) |desc, index| {
        if (desc.n_columns != (if (owner.statement.localZeroCustody()) try @import("../air/x0_native_envelope_v1.zig").mainColumnCount(desc.family) else Trace.nColumnsForFamily(desc.family))) return error.InvalidV5StagedNativeShape;
        const component = &owner.opcode_columns.components[index];
        component.n_columns = desc.n_columns;
        component.n_real_rows = desc.n_rows;
        // Store.load allocated mutable buffers in this owner arena. PCS's
        // ColumnEvaluation exposes a const view; these are owned aliases.
        for (component.columns[0..desc.n_columns], loaded.columns[at..][0..desc.n_columns]) |*values, column| values.* = @constCast(column.values);
        at += desc.n_columns;
        for (0..desc.n_rows) |row| {
            const physical = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(row, desc.log_size), desc.log_size);
            if (owner.statement.localZeroCustody()) {
                var values: [Trace.MAX_FAMILY_COLUMNS]core.fields.qm31.QM31 = undefined;
                for (component.columns[0..desc.n_columns], values[0..desc.n_columns]) |column, *value| value.* = core.fields.qm31.QM31.fromBase(column[physical]);
                try owner.opcode_columns.lookup_counters.?.registerList(try @import("../air/x0_native_envelope_v1.zig").Builder(core.fields.qm31.QM31).lookups(desc.family, values[0..desc.n_columns]));
            } else try Ingest.registerGeneratedCommittedRow(desc.family, &component.columns, physical, &owner.opcode_columns.lookup_counters.?);
        }
    }
    for (owner.statement.infra_descs[0..owner.statement.n_infra]) |desc| {
        // Native protocol admits at most the canonical single clock component.
        if (desc.kind != .clock_update or desc.n_columns != owner.clock_main.len) return error.InvalidV5StagedNativeShape;
        for (&owner.clock_main, loaded.columns[at..][0..desc.n_columns]) |*values, column| values.* = @constCast(column.values);
        at += desc.n_columns;
        try Clock.registerRangeCheckCounters(&owner.opcode_columns.lookup_counters.?, &owner.clock_main);
    }
    if (at != loaded.columns.len) return error.InvalidV5StagedNativeShape;
    try owner.sealNativeOnly();
    return owner;
}

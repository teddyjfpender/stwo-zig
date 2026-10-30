//! Original global table projections for one shared Keccak inventory.
//! Register claims deliberately remain in the per-window control components.
const std = @import("std");
const core = @import("stwo_core");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const Q = core.fields.qm31.QM31;
const Source = @import("block_v5_precompile_lookup_source_v1.zig");
const Algebra = @import("block_v5_precompile_lookup_algebra_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Keccak = @import("../air/guest_precompile/keccakf_trace.zig");
const Matrix = @import("block_v7_memory_trace_v1.zig").Matrix;
pub const Component = @import("block_v5_caller_fused_component_v1.zig").Tables;
pub const SLOT_COUNT = 28;
pub const Generated = struct {
    matrix: Matrix,
    claims: [SLOT_COUNT]Algebra.Claim,
    /// Unauthenticated arithmetic summary until all physical claims are
    /// bound by the original STARK; never a standalone verification receipt.
    totals: [@import("../air/lookups/tables/schema.zig").KIND_COUNT]Q,
    pub fn deinit(self: *Generated) void {
        self.matrix.deinit();
        self.* = undefined;
    }
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    source: *Source.Owner,
    slots: []Source.Slot,
    pub fn init(a: std.mem.Allocator, log: u32, fixed_offset: usize, main_offset: usize, x0_version: u32) !Owned {
        const local = true;
        if (log < Keccak.minimum_log_size or log > Keccak.maximum_log_size or x0_version != @intFromBool(local)) return error.InvalidKeccakSharedLookupGeometry;
        const owner = try Source.Owner.initKeccakForRecipe(a, local);
        errdefer owner.destroy(a);
        var slots: std.ArrayList(Source.Slot) = .empty;
        errdefer slots.deinit(a);
        try Source.appendGenericCallerSlots(a, &slots, .keccak, .{
            .log_size = log,
            .preprocessed_columns = Keccak.Layout.preprocessed_columns,
            .main_columns = @intCast(Keccak.Layout.main_columns + @as(usize, @intFromBool(local)) * 2),
            .interaction_columns = @import("../air/guest_precompile/keccakf_interaction_plan.zig").interaction_column_count,
        }, fixed_offset, main_offset, false);
        // The selected original event equations use the same explicit local
        // zero recipe as the mandatory Keccak AIR, independently of legacy.
        for (slots.items) |*slot| slot.width = @import("../air/guest_precompile/keccakf_caller_local_zero_v1.zig").Layout.main_columns;
        if (slots.items.len != SLOT_COUNT) return error.InvalidKeccakSharedLookupGeometry;
        return .{ .allocator = a, .source = owner, .slots = try slots.toOwnedSlice(a) };
    }
    pub fn deinit(self: *Owned) void {
        self.source.destroy(self.allocator);
        self.allocator.free(self.slots);
        self.* = undefined;
    }
    pub fn generate(self: *const Owned, a: std.mem.Allocator, fixed: []const Column, main: []const Column, relations: *const Profile.Relations, max_bytes: usize) !Generated {
        try Algebra.validateSlots(self.slots, main);
        var out = Generated{ .matrix = try Matrix.init(a, self.slots[0].log_size, SLOT_COUNT * 4, max_bytes), .claims = undefined, .totals = @splat(Q.zero()) };
        errdefer out.deinit();
        for (self.slots, &out.claims, 0..) |slot, *claim, i| {
            const generated = try Algebra.generate(a, fixed, main, slot, relations, self.source);
            defer for (generated.columns) |column| a.free(column);
            claim.* = .{ .sum = generated.claim, .row_count = slot.n_rows };
            out.totals[@intFromEnum(slot.table)] = out.totals[@intFromEnum(slot.table)].add(generated.claim);
            for (generated.columns, 0..) |values, j| @memcpy(@constCast(out.matrix.columns[i * 4 + j].values), values);
        }
        return out;
    }
    /// These components borrow the owner, relations, claim values and logs.
    /// The shared memory partition declares the full fixed/main inventories.
    pub fn components(self: *const Owned, a: std.mem.Allocator, fixed_logs: []const u32, main_logs: []const u32, interaction_logs: []const u32, interaction_offset: usize, claims: [SLOT_COUNT]Algebra.Claim, relations: *const Profile.Relations) ![]Component {
        const out = try a.alloc(Component, SLOT_COUNT);
        errdefer a.free(out);
        for (out, self.slots, claims, 0..) |*component, slot, claim, i| {
            if (claim.row_count != slot.n_rows) return error.InvalidKeccakSharedLookupClaim;
            component.* = try (Component{ .composition_split = 2, .inner = .{
                .slot = slot,
                .fixed_logs = fixed_logs,
                .main_logs = main_logs,
                .root_owner = false,
                .interaction_offset = try std.math.add(usize, interaction_offset, i * 4),
                .interaction_logs = interaction_logs,
                .claim = claim.sum,
                .relations = relations,
                .source_owner = self.source,
                .composition_split = 2,
            } }).init();
        }
        return out;
    }
};
test "Keccak shared lookup projects each original global event exactly once" {
    const local = true;
    var owner = try Owned.init(std.testing.allocator, 5, 0, 0, @intFromBool(local));
    defer owner.deinit();
    var selected: [160]bool = @splat(false);
    var count: usize = 0;
    for (owner.slots) |slot| {
        try std.testing.expect(slot.table != .register_memory);
        for (slot.entries[0..slot.entry_count]) |event| {
            try std.testing.expect(!selected[event]);
            selected[event] = true;
            count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 53), count);
    try std.testing.expect(selected[5]);
    for (0..50) |word| try std.testing.expect(selected[8 + 3 * word]);
    try std.testing.expect(selected[156] and selected[157]);
    for (0..5) |control| try std.testing.expect(!selected[control]);
}

test "Keccak shared lookup explicitly uses local zero pointer-gap equation" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidKeccakSharedLookupGeometry, Owned.init(a, 5, 0, 0, 0));
    var owner = try Owned.init(a, 5, 0, 0, 1);
    defer owner.deinit();
    const Local = @import("../air/guest_precompile/keccakf_caller_local_zero_v1.zig");
    const Base = @import("../air/guest_precompile/keccakf_caller.zig");
    const row = try Local.fill(.{ .execution_clock = 1, .pc = 1024, .state_ptr = 0, .pointer_register = 0, .pointer_previous_clock = 0, .input = @splat(0), .output = @splat(0), .memory_previous_clocks = @splat(0) });
    var main: [Local.Layout.main_columns]Q = undefined;
    for (&main, row) |*v, x| v.* = Q.fromBase(x);
    var ch = core.proof_suites.Blake3.Channel{};
    const word = try @import("block_v5_word_memory_protocol_v1.zig").Challenges.drawFromChannel(a, &ch);
    const relations = try Profile.Relations.drawAfterVm(a, &ch, word.universal_prefix);
    const zeros: [@import("../air/guest_precompile/keccakf_witness.zig").state_cell_count]Q = @splat(Q.zero());
    const original = try Local.coreEvents(Q, &main, &zeros, &zeros, &relations.ethereum.keccak);
    const legacy = Base.coreEvents(Q, main[0..Base.Layout.main_columns], &zeros, &zeros, &relations.ethereum.keccak);
    try std.testing.expect(!legacy[5].n1.isZero());
    try std.testing.expect(original[5].n1.isZero());
    const slot = owner.slots[0];
    try std.testing.expectEqual(@as(u8, 5), slot.entries[0]);
    const pair = try owner.source.pair(slot, &.{}, &main, &relations);
    try std.testing.expectEqualDeep(original[5].n1, pair.n1);
    try std.testing.expectEqualDeep(original[5].d1, pair.d1);
    try std.testing.expectEqualDeep(original[8].n1, pair.n2);
    try std.testing.expectEqualDeep(original[8].d1, pair.d2);
}

/// Exact finite recipe counter registration. The original local-zero caller
/// suppresses its x0 pointer-gap request as well as register memory effects.
pub fn register(a: std.mem.Allocator, records: []const @import("../runner/guest_precompile/keccakf_call_buffer.zig").Record, counters: *@import("../air/lookups/tables/counter.zig").Set) !void {
    _ = a;
    try (@import("../air/guest_precompile/ethereum_lookup_registration.zig").Context{ .keccak = records, .recovery = &.{} }).registerForKeccakRecipe(counters, true);
}

test "Keccak shared x0 counter omits the pointer gap before range validation" {
    const a = std.testing.allocator;
    var counters = try @import("../air/lookups/tables/counter.zig").Set.init(a);
    defer counters.deinit(a);
    const Record = @import("../runner/guest_precompile/keccakf_call_buffer.zig").Record;
    const clock: u32 = (1 << 18) + 1;
    const records = [_]Record{.{ .execution_clock = clock, .pc = 1024, .state_ptr = 0, .pointer_register = 0, .pointer_previous_clock = 0, .input = @splat(0), .output = @splat(0), .memory_previous_clocks = @splat((clock - 1) * 4 + 1) }};
    const original = @import("../air/guest_precompile/ethereum_lookup_registration.zig").Context{ .keccak = &records, .recovery = &.{} };
    try std.testing.expectError(error.ClockGapOutOfRange, original.register(&counters));
    for (counters.get(.range_check_20).values) |v| try std.testing.expect(v.isZero());
    try register(a, &records, &counters);
    try std.testing.expectEqualDeep(core.fields.m31.M31.zero().sub(core.fields.m31.M31.fromCanonical(50)), counters.get(.range_check_20).values[0]);
    for (counters.get(.range_check_20).values[1..]) |v| try std.testing.expect(v.isZero());
}

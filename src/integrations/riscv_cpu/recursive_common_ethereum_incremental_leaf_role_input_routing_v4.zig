//! Admitted arithmetic-input routes. Private inputs here have pointwise graph
//! constraints; every external claim input consumes its canonical source tuple.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const M31 = core.fields.m31.M31;
const air = frontend.recursion.air;
const sums = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4.zig");
pub const Air = air.ethereum_public_logup_input_v1;
pub const Row = Air.Relation.Row;
const ClaimUse = struct { word: u32, lane: u2 };
const Route = struct { row: Row, claim: ?ClaimUse = null };

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    rows: []Row,
    claims: []ClaimUse,

    pub fn init(allocator: std.mem.Allocator, view: anytype) !Prepared {
        var row_count: usize = 0;
        var claim_count: usize = 0;
        for (view.bindings, 0..) |source, node| if (try route(source, view.values[node], view.use_counts[node], @intCast(node))) |item| {
            row_count += 1;
            claim_count += @intFromBool(item.claim != null);
        };
        const rows = try allocator.alloc(Row, row_count);
        errdefer allocator.free(rows);
        const claims = try allocator.alloc(ClaimUse, claim_count);
        errdefer allocator.free(claims);
        var at: usize = 0;
        var claim_at: usize = 0;
        for (view.bindings, 0..) |source, node| if (try route(source, view.values[node], view.use_counts[node], @intCast(node))) |item| {
            rows[at] = item.row;
            at += 1;
            if (item.claim) |claim| {
                claims[claim_at] = claim;
                claim_at += 1;
            }
        };
        return .{ .allocator = allocator, .rows = rows, .claims = claims };
    }

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.claims);
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validate(self: *const Prepared, view: anytype) !void {
        var at: usize = 0;
        var claim_at: usize = 0;
        for (view.bindings, 0..) |source, node| if (try route(source, view.values[node], view.use_counts[node], @intCast(node))) |item| {
            if (at >= self.rows.len or !std.meta.eql(item.row, self.rows[at])) return error.InvalidEthereumRoleInputRouting;
            at += 1;
            if (item.claim) |claim| {
                if (claim_at >= self.claims.len or !std.meta.eql(claim, self.claims[claim_at])) return error.InvalidEthereumRoleInputRouting;
                claim_at += 1;
            }
        };
        if (at != self.rows.len or claim_at != self.claims.len) return error.InvalidEthereumRoleInputRouting;
    }

    /// One source consumption per input row, independent of arithmetic fanout.
    pub fn claimUses(self: *const Prepared, word: u32) [3]u32 {
        var uses = [_]u32{0} ** 3;
        for (self.claims) |claim| if (claim.word == word) {
            uses[claim.lane] += 1;
        };
        return uses;
    }

    pub fn hashInto(self: *const Prepared, hash: anytype) void {
        var bytes: [4]u8 = undefined;
        for (self.rows) |row| for (row) |word| {
            std.mem.writeInt(u32, &bytes, word.toU32(), .little);
            hash.update(&bytes);
        };
    }
};

fn route(source: sums.InputSourceV4, value: core.fields.qm31.QM31, use_count: u32, node: u32) !?Route {
    switch (source) {
        .role_io_word, .tuple_selector, .role_source, .clock_aux, .global_statement_word, .global_aux, .completion_opening_word => {},
        else => return null,
    }
    const limbs = value.toM31Array();
    if (!limbs[1].isZero() or !limbs[2].isZero() or !limbs[3].isZero() or use_count >= core.fields.m31.Modulus)
        return error.InvalidEthereumRoleInputRouting;
    var original = [_]M31{M31.zero()} ** air.vm_public_logup_input.LOGICAL_INPUT_COUNT;
    original[0] = M31.one();
    original[1] = limbs[0];
    original[2] = M31.one(); // row mask, all source masks initially zero
    original[8] = M31.fromCanonical(sums.CIRCUIT_ID);
    original[9] = M31.fromCanonical(node);
    original[10] = M31.fromCanonical(use_count);
    original[13] = M31.one(); // segment parameter
    const claim_scope = air.vm_public_claim_input.VM_PUBLIC_LOGUP_SCOPE;
    original[14] = M31.fromCanonical(claim_scope);
    original[15] = M31.fromCanonical(air.control_slice_witness.SEGMENT_VERIFIER_ID);
    original[16] = M31.fromCanonical(air.relation_challenge_witness.VM_PUBLIC_LOGUP_CHALLENGE_SCOPE);
    original[17] = M31.fromCanonical(@intFromEnum(air.transcript_payload.VerifierInputKind.claimed_sum));
    var source_scope: u32 = claim_scope;
    var output_scope: u32 = 1100;
    var output_index: ?u32 = null;
    var claim: ?ClaimUse = null;
    var header_index: ?u32 = null;
    switch (source) {
        .role_io_word => |index| {
            output_index = index;
            header_index = switch (index) {
                3 => 94,
                4 => 95,
                else => null,
            };
        },
        .tuple_selector => {}, // Boolean, one-hot and exact role graph constraints.
        .clock_aux => {}, // Private bits joined pointwise to raw clocks/span by the sums graph.
        .global_aux => {}, // Private range/carry/inverse witnesses constrained by the global projection.
        .completion_opening_word => {}, // Same base-field value consumed by the fixed-root completion graph.
        .global_statement_word => |index| {
            output_scope = 1101;
            output_index = index;
        },
        .role_source => |role| switch (role) {
            .claim_word => |index| {
                original[3] = M31.one();
                original[11] = M31.fromCanonical(index);
                claim = .{ .word = index, .lane = 0 };
            },
            .claim_byte => |coordinate| {
                original[4] = M31.one();
                original[11] = M31.fromCanonical(coordinate.word_index);
                original[12] = M31.fromCanonical(coordinate.byte_index);
                claim = .{ .word = coordinate.word_index, .lane = @as(u2, coordinate.byte_index) + 1 };
            },
            .completion_word => |limb| {
                original[3] = M31.one();
                source_scope = 1115;
                original[11] = M31.fromCanonical(42 + @as(u32, limb));
            },
            .completion_policy_word => |part| {
                original[3] = M31.one();
                source_scope = 1115;
                original[11] = M31.fromCanonical(switch (part) {
                    0 => 41,
                    1 => 46,
                    2 => 47,
                    3 => return error.InvalidEthereumRoleInputRouting,
                });
            },
            .completion_decoded_word => |limb| {
                output_scope = 1102;
                output_index = 49 + @as(u32, limb);
            },
            .limb_bit, .input_carry, .nonfinal_inverse, .terminal_reserved => {},
        },
        else => unreachable,
    }
    return .{ .row = Air.logicalRow(original, output_scope, output_index, source_scope, header_index), .claim = claim };
}

test "Ethereum global publication routes the graph value through public and hash boundaries" {
    const QM31 = core.fields.qm31.QM31;
    const publication = @import("recursive_common_ethereum_incremental_leaf_publication_words_v4.zig");
    const PublicAir = air.ethereum_publication_control_v1;
    const input_row = (try route(.{ .global_statement_word = 220 }, QM31.fromBase(M31.fromCanonical(5)), 3, 1000)).?.row;
    const public_row = try publication.statementWordRow(true, 220, M31.fromCanonical(5));
    var input_definition = try Air.build(std.testing.allocator);
    defer input_definition.deinit();
    const input_plan = try Air.Relation.authenticate(&input_definition);
    var public_definition = try PublicAir.build(std.testing.allocator);
    defer public_definition.deinit();
    const public_plan = try PublicAir.Relation.authenticate(&public_definition);
    const input_entries = input_plan.preparedEntries(input_row);
    const public_entries = public_plan.preparedEntries(public_row);
    var found = false;
    for (input_entries) |entry| if (entry.domain == public_entries[12].domain and !entry.numerator.isZero() and entry.arity == 3 and entry.values[0].eql(QM31.fromBase(M31.fromCanonical(1101)))) {
        try std.testing.expect(entry.numerator.eql(public_entries[12].numerator.neg()));
        try std.testing.expectEqualSlices(QM31, entry.values[0..3], public_entries[12].values[0..3]);
        found = true;
    };
    try std.testing.expect(found);
    // Claim-source consume, statement hash emit, output hash emit and public
    // boundary emit all contain exactly the same main.value.
    for ([_]usize{ 2, 3, 5, 12 }) |event| try std.testing.expect(public_entries[event].values[2].eql(QM31.fromBase(M31.fromCanonical(5))));
    const changed = public_plan.preparedEntries(try publication.statementWordRow(true, 220, M31.fromCanonical(6)));
    try std.testing.expect(!std.meta.eql(public_entries[12].values, changed[12].values));
    const legacy = public_plan.preparedEntries(try publication.statementWordRow(false, 220, M31.fromCanonical(5)));
    try std.testing.expect(legacy[12].numerator.isZero());
    try std.testing.expect(!legacy[1].numerator.isZero());
}

test "Ethereum role input routing counts only genuine claim consumers and shares publication values" {
    const sources = [_]sums.InputSourceV4{
        .{ .role_io_word = 3 },
        .{ .role_source = .{ .claim_word = 123 } },
        .{ .role_source = .{ .claim_word = 123 } },
        .{ .role_source = .{ .claim_byte = .{ .word_index = 123, .byte_index = 1 } } },
        .{ .role_source = .{ .completion_word = 2 } },
        .{ .role_source = .{ .completion_decoded_word = 1 } },
        .{ .role_source = .{ .limb_bit = .{ .slot = 0, .limb = 0, .bit = 0 } } },
        .{ .statement_word = 0 },
    };
    const values = [_]core.fields.qm31.QM31{core.fields.qm31.QM31.one()} ** sources.len;
    const uses = [_]u32{7} ** sources.len;
    const view = .{ .bindings = &sources, .values = &values, .use_counts = &uses };
    var prepared = try Prepared.init(std.testing.allocator, view);
    defer prepared.deinit();
    try prepared.validate(view);
    try std.testing.expectEqual(@as(usize, 7), prepared.rows.len);
    try std.testing.expectEqualDeep([3]u32{ 2, 0, 1 }, prepared.claimUses(123));
    try std.testing.expectEqualDeep([3]u32{ 0, 0, 0 }, prepared.claimUses(124));
    // Main.value feeds the unchanged wire relation and both publication routes.
    try std.testing.expectEqual(@as(u32, 1), prepared.rows[0][1].toU32());
    try std.testing.expectEqual(@as(u32, 7), prepared.rows[0][10].toU32());
    const extra = air.vm_public_logup_input.PHYSICAL_MAIN_COLUMN_COUNT + air.vm_public_logup_input.PREPROCESSED_COLUMN_COUNT;
    try std.testing.expectEqual(@as(u32, 1100), prepared.rows[0][extra + 1].toU32());
    try std.testing.expectEqual(@as(u32, 94), prepared.rows[0][extra + 5].toU32());
    try std.testing.expectEqual(@as(u32, 1115), prepared.rows[4][extra + 3].toU32());
    try std.testing.expectEqual(@as(u32, 44), prepared.rows[4][11].toU32());
    try std.testing.expectEqual(@as(u32, 1102), prepared.rows[5][extra + 1].toU32());
    try std.testing.expectEqual(@as(u32, 50), prepared.rows[5][extra + 2].toU32());
    prepared.rows[5][1] = M31.fromCanonical(2);
    try std.testing.expectError(error.InvalidEthereumRoleInputRouting, prepared.validate(view));
}

test "Ethereum completion policy routes consume exact native relay values" {
    const expected = [_]u32{ 41, 46, 47 };
    const words = [_]u32{ 3, 0, 0 };
    for (expected, words, 0..) |source_index, value, part| {
        const sources = [_]sums.InputSourceV4{.{ .role_source = .{ .completion_policy_word = @intCast(part) } }};
        var values = [_]core.fields.qm31.QM31{core.fields.qm31.QM31.fromBase(M31.fromCanonical(value))};
        const uses = [_]u32{1};
        const view = .{ .bindings = &sources, .values = &values, .use_counts = &uses };
        var prepared = try Prepared.init(std.testing.allocator, view);
        defer prepared.deinit();
        try prepared.validate(view);
        const row = prepared.rows[0];
        try std.testing.expectEqual(@as(u32, 1), row[3].toU32());
        try std.testing.expectEqual(source_index, row[11].toU32());
        try std.testing.expectEqual(@as(u32, 1115), row[16].toU32());
        try std.testing.expectEqual(value, row[1].toU32());
        try std.testing.expectEqual(@as(usize, 0), prepared.claims.len);
        values[0] = values[0].add(core.fields.qm31.QM31.one());
        try std.testing.expectError(error.InvalidEthereumRoleInputRouting, prepared.validate(view));
        values[0] = core.fields.qm31.QM31.fromBase(M31.fromCanonical(value));
        prepared.rows[0][11] = M31.fromCanonical(source_index + 1);
        try std.testing.expectError(error.InvalidEthereumRoleInputRouting, prepared.validate(view));
    }
    try std.testing.expectError(error.InvalidEthereumRoleInputRouting, route(.{ .role_source = .{ .completion_policy_word = 3 } }, core.fields.qm31.QM31.zero(), 1, 0));
}

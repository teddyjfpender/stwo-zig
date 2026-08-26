const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const air_v2 = @import("segment_leaf_outer_air_v2.zig");
const authority = @import("segment_leaf_outer_authority_v2.zig");
const source_v2 = @import("segment_leaf_authority_v2.zig");
const public_data_v2 = @import("../air/public_data_v2.zig");
const native_relations = @import("../air/relation_challenges.zig");
const statement_v1 = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const support = @import("../air/public_data_v2_test_support.zig");
const relation = @import("../air/lang/relation.zig");
const framework = @import("air/framework_interaction.zig");
const universal = @import("air/universal_challenges.zig");

// Shared fixtures and mutation helpers for this conformance suite.

pub const OwnedTraces = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    statement_preprocessed: [air_v2.Statement.PREPROCESSED_COLUMN_COUNT][]M31,
    statement_main: [air_v2.Statement.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    statement_interaction: [air_v2.Statement.INTERACTION_COLUMN_COUNT][]M31,
    public_logup_preprocessed: [air_v2.PublicLogUp.PREPROCESSED_COLUMN_COUNT][]M31,
    public_logup_main: [air_v2.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    public_logup_interaction: [air_v2.PublicLogUp.INTERACTION_COLUMN_COUNT][]M31,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const authority.OuterManifestV2,
    ) !OwnedTraces {
        const statement_rows: usize = manifest.components[0].trace_rows;
        const logup_rows: usize = manifest.components[1].trace_rows;
        const statement_columns =
            air_v2.Statement.PREPROCESSED_COLUMN_COUNT +
            air_v2.Statement.PHYSICAL_MAIN_COLUMN_COUNT +
            air_v2.Statement.INTERACTION_COLUMN_COUNT;
        const logup_columns =
            air_v2.PublicLogUp.PREPROCESSED_COLUMN_COUNT +
            air_v2.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT +
            air_v2.PublicLogUp.INTERACTION_COLUMN_COUNT;
        const statement_words = try std.math.mul(
            usize,
            statement_rows,
            statement_columns,
        );
        const logup_words = try std.math.mul(usize, logup_rows, logup_columns);
        const storage = try allocator.alloc(
            M31,
            try std.math.add(usize, statement_words, logup_words),
        );
        var at: usize = 0;
        var statement_preprocessed: [air_v2.Statement.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&statement_preprocessed) |*column| {
            column.* = storage[at..][0..statement_rows];
            at += statement_rows;
        }
        var statement_main: [air_v2.Statement.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&statement_main) |*column| {
            column.* = storage[at..][0..statement_rows];
            at += statement_rows;
        }
        var statement_interaction: [air_v2.Statement.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&statement_interaction) |*column| {
            column.* = storage[at..][0..statement_rows];
            at += statement_rows;
        }
        var public_logup_preprocessed: [air_v2.PublicLogUp.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&public_logup_preprocessed) |*column| {
            column.* = storage[at..][0..logup_rows];
            at += logup_rows;
        }
        var public_logup_main: [air_v2.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&public_logup_main) |*column| {
            column.* = storage[at..][0..logup_rows];
            at += logup_rows;
        }
        var public_logup_interaction: [air_v2.PublicLogUp.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&public_logup_interaction) |*column| {
            column.* = storage[at..][0..logup_rows];
            at += logup_rows;
        }
        std.debug.assert(at == storage.len);
        return .{
            .allocator = allocator,
            .storage = storage,
            .statement_preprocessed = statement_preprocessed,
            .statement_main = statement_main,
            .statement_interaction = statement_interaction,
            .public_logup_preprocessed = public_logup_preprocessed,
            .public_logup_main = public_logup_main,
            .public_logup_interaction = public_logup_interaction,
        };
    }

    pub fn deinit(self: *OwnedTraces) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn fill(self: *OwnedTraces, value: M31) void {
        @memset(self.storage, value);
    }

    pub fn traces(self: *OwnedTraces) authority.TracesV2 {
        return .{
            .statement = .{
                .preprocessed = self.statement_preprocessed,
                .main = self.statement_main,
                .interaction = self.statement_interaction,
            },
            .public_logup = .{
                .preprocessed = self.public_logup_preprocessed,
                .main = self.public_logup_main,
                .interaction = self.public_logup_interaction,
            },
        };
    }
};

pub fn expectedStatementClaim(
    prepared: *const authority.PreparedOuterAuthorityV2,
    data: *const public_data_v2.PublicDataV2,
    outer: *const universal.UniversalRelations,
) !QM31 {
    const event_count: usize = prepared.statement_event_count;
    const events = try std.testing.allocator.alloc(
        source_v2.StatementRelationEventV2,
        event_count,
    );
    defer std.testing.allocator.free(events);
    try source_v2.writeStatementRelationEventsInto(
        &prepared.source,
        events,
        data,
    );
    var result = QM31.zero();
    const challenge = outer.get(.recursion_statement_word);
    for (events) |event| {
        const denominator = try challenge.combineBase(&event.tuple);
        result = result.add(try denominator.inv());
    }
    return result;
}

pub fn expectedPublicLogUpClaim(
    prepared: *const authority.PreparedOuterAuthorityV2,
    outer: *const universal.UniversalRelations,
) !QM31 {
    return (try expectedVerifierInputClaim(prepared, outer)).add(
        try expectedPublicationBridgeClaim(prepared, outer),
    );
}

pub fn expectedVerifierInputClaim(
    prepared: *const authority.PreparedOuterAuthorityV2,
    outer: *const universal.UniversalRelations,
) !QM31 {
    var events: [source_v2.LOGUP_PUBLICATION_WORD_COUNT]source_v2.VerifierInputEventV2 =
        undefined;
    try source_v2.writeVerifierInputEventsInto(&prepared.public_logup, &events);
    var result = QM31.zero();
    const verifier_input_challenge = outer.get(.recursion_verifier_input_word);
    for (events) |event| {
        const denominator = try verifier_input_challenge.combineBase(&event.tuple);
        result = result.sub(try denominator.inv());
    }
    return result;
}

pub fn expectedPublicationBridgeClaim(
    prepared: *const authority.PreparedOuterAuthorityV2,
    outer: *const universal.UniversalRelations,
) !QM31 {
    var result = QM31.zero();
    const wire_challenge = outer.get(.recursion_wire);
    const words = try prepared.public_logup.canonicalWords();
    for (words, 0..) |word, index| {
        const tuple = [_]M31{
            M31.fromCanonical(source_v2.PUBLICATION_BRIDGE_CIRCUIT_ID),
            M31.fromCanonical(@intCast(index)),
            word,
            M31.zero(),
            M31.zero(),
            M31.zero(),
        };
        const denominator = try wire_challenge.combineBase(&tuple);
        result = result.add(try denominator.inv());
    }
    return result;
}

pub fn expectSecureBase(expected: u32, actual: QM31) !void {
    try std.testing.expect(actual.eql(QM31.fromBase(M31.fromCanonical(expected))));
}

pub fn expectStatementRow(
    trace: authority.StatementTraceV2,
    log_size: u8,
    logical_row: usize,
    scope: u32,
    index: usize,
    value: M31,
) !void {
    const row = framework.committedRow(logical_row, log_size);
    try expectM31(1, trace.preprocessed[0][row]);
    try expectM31(scope, trace.preprocessed[1][row]);
    try expectM31(index, trace.preprocessed[2][row]);
    try std.testing.expect(value.eql(trace.main[0][row]));
}

pub fn expectM31(expected: anytype, actual: M31) !void {
    try std.testing.expectEqual(@as(u32, @intCast(expected)), actual.toU32());
}

pub fn sentinel() M31 {
    return M31.fromCanonical(0x1234_5678);
}

pub fn relationBit(domain: relation.Domain) u64 {
    return @as(u64, 1) << @as(u6, @intCast(@intFromEnum(domain)));
}

//! Padded committed-word witness for the native ProgramV2 preimage or the
//! 39-row outer shared-provider envelope. The same pinned typed AIR proves
//! `main.value == preprocessed.expected` and emits one scoped lookup per word.
//! A wrapper must still admit this source into its cohort and prove its hash.

const std = @import("std");
const core = @import("stwo_core");
const source = @import("air/transcript_program_v2_field_source_v1.zig");
const universal = @import("air/universal_challenges.zig");

const M31 = core.fields.m31.M31;

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const Row = source.Row;
pub const Interaction = source.Runtime.Interaction;

pub const WordsV1 = struct {
    allocator: std.mem.Allocator,
    scope: u32,
    word_count: usize,
    log_size: u32,
    rows: []Row,

    pub fn init(allocator: std.mem.Allocator, words: []const M31, scope: u32) !WordsV1 {
        if (scope != source.PROGRAM_WORD_SCOPE and scope != source.PROVIDER_WORD_SCOPE)
            return error.InvalidFieldWordScope;
        if (words.len == 0 or words.len >= core.fields.m31.Modulus)
            return error.InvalidFieldWordCount;
        const size = std.math.ceilPowerOfTwo(usize, @max(words.len, 16)) catch
            return error.InvalidFieldWordCount;
        if (size > (@as(usize, 1) << 30)) return error.InvalidFieldWordCount;
        const rows = try allocator.alloc(Row, size);
        errdefer allocator.free(rows);
        for (words, 0..) |word, index| {
            if (word.toU32() >= core.fields.m31.Modulus)
                return error.NonCanonicalFieldWord;
            rows[index] = source.logicalRowScoped(
                word,
                1,
                word,
                scope,
                @intCast(index),
            );
        }
        for (rows[words.len..]) |*row|
            row.* = source.logicalRowScoped(M31.zero(), 0, M31.zero(), scope, 0);
        return .{
            .allocator = allocator,
            .scope = scope,
            .word_count = words.len,
            .log_size = std.math.log2_int(usize, size),
            .rows = rows,
        };
    }

    pub fn deinit(self: *WordsV1) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const WordsV1, words: []const M31, scope: u32) !void {
        if (self.scope != scope or self.word_count != words.len or
            self.log_size < 4 or self.log_size > 30 or
            self.rows.len != (@as(usize, 1) << @intCast(self.log_size)))
            return error.InvalidFieldWordWitness;
        var expected = try WordsV1.init(self.allocator, words, scope);
        defer expected.deinit();
        if (self.log_size != expected.log_size) return error.InvalidFieldWordWitness;
        for (self.rows, expected.rows) |actual, wanted| {
            for (actual, wanted) |got, want| if (!got.eql(want))
                return error.InvalidFieldWordWitness;
        }
    }

    /// Generates the exact typed lookup contribution under the wrapper's
    /// transcript-derived 47-relation challenge bundle. Cancellation and
    /// commitment remain responsibilities of the wrapper transaction.
    pub fn generateInteraction(
        self: *const WordsV1,
        allocator: std.mem.Allocator,
        relations: *const universal.UniversalRelations,
    ) !Interaction {
        var definition = try source.build(allocator);
        defer definition.deinit();
        const plan = try source.authenticate(&definition);
        return plan.generateInteraction(
            allocator,
            &definition.arena,
            try source.computeSemanticDigest(allocator),
            definition.events,
            self.rows,
            self.log_size,
            relations,
        );
    }
};

test "field word witness pads canonically and rejects altered lookup rows" {
    const allocator = std.testing.allocator;
    const words = [_]M31{ M31.one(), M31.fromCanonical(17), M31.fromCanonical(65535) };
    var witness = try WordsV1.init(allocator, &words, source.PROGRAM_WORD_SCOPE);
    defer witness.deinit();
    try std.testing.expectEqual(@as(usize, 16), witness.rows.len);
    try witness.validateAgainst(&words, source.PROGRAM_WORD_SCOPE);
    const relations = universal.UniversalRelations.dummy();
    var interaction = try witness.generateInteraction(allocator, &relations);
    defer interaction.deinit(allocator);
    witness.rows[1][0] = witness.rows[1][0].add(M31.one());
    try std.testing.expectError(
        error.InvalidFieldWordWitness,
        witness.validateAgainst(&words, source.PROGRAM_WORD_SCOPE),
    );
}

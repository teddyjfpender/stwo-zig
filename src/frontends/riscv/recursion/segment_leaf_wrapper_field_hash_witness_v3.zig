//! Canonical Poseidon row witness for staged V3 ProgramV2/provider identities.
//! It consumes the scoped word-source tuples and emits one verifier-input
//! digest. The enclosing wrapper must commit these rows and close its lookups.

const std = @import("std");
const core = @import("stwo_core");
const hash_air = @import("air/vm_public_claim_hash.zig");
const hash_witness = @import("air/vm_public_claim_hash_witness.zig");
const hash_relation = @import("air/vm_public_claim_hash_relation.zig");
const universal = @import("air/universal_challenges.zig");
const channel = @import("poseidon2_channel.zig");

const M31 = core.fields.m31.M31;

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const PROGRAM_STEP_BASE: u32 = 1024;
pub const PROVIDER_STEP_BASE: u32 = 2048;
pub const PROVIDER_FIELD_DIGEST_KIND: u32 = 0x5046_4431; // PFD1
pub const VERIFIER_ID: u32 = 0;
pub const Interaction = hash_relation.Interaction;

pub const HashV1 = struct {
    allocator: std.mem.Allocator,
    domain: u32,
    scope: u32,
    digest_kind: u32,
    step_base: u32,
    word_count: usize,
    log_size: u32,
    digest: channel.Digest,
    preprocessed: []hash_witness.PreprocessedRow,
    main: []hash_witness.MainRow,
    calls: []hash_witness.PoseidonCall,

    pub fn init(
        allocator: std.mem.Allocator,
        words: []const M31,
        domain: u32,
        scope: u32,
        digest_kind: u32,
        step_base: u32,
        digest: channel.Digest,
    ) !HashV1 {
        if (words.len == 0 or words.len >= core.fields.m31.Modulus or
            domain >= core.fields.m31.Modulus or
            scope >= core.fields.m31.Modulus or
            digest_kind >= core.fields.m31.Modulus)
            return error.InvalidFieldHashShape;
        const row_count = std.math.divCeil(usize, words.len + 1, hash_witness.RATE) catch
            return error.InvalidFieldHashShape;
        if (row_count == 0 or row_count + step_base >= core.fields.m31.Modulus)
            return error.InvalidFieldHashShape;
        const preprocessed = try allocator.alloc(hash_witness.PreprocessedRow, row_count);
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc(hash_witness.MainRow, row_count);
        errdefer allocator.free(main);
        const calls = try allocator.alloc(hash_witness.PoseidonCall, row_count);
        errdefer allocator.free(calls);
        var state = [_]M31{M31.zero()} ** hash_witness.STATE_WIDTH;
        state[hash_witness.STATE_WIDTH - 1] = M31.fromCanonical(domain);
        for (preprocessed, main, calls, 0..) |*pp, *row, *call, index| {
            pp.* = try hash_witness.expectedRow(words.len, row_count, index);
            pp.step += step_base;
            row.* = hash_witness.materialize(pp.*, words, state);
            call.* = hash_witness.callFor(row.*);
            state = row.output;
        }
        for (digest, state[0..digest.len]) |expected, actual|
            if (expected >= core.fields.m31.Modulus or expected != actual.toU32())
                return error.FieldHashDigestMismatch;
        return .{
            .allocator = allocator,
            .domain = domain,
            .scope = scope,
            .digest_kind = digest_kind,
            .step_base = step_base,
            .word_count = words.len,
            .log_size = try hash_witness.traceLogSize(row_count),
            .digest = digest,
            .preprocessed = preprocessed,
            .main = main,
            .calls = calls,
        };
    }

    pub fn deinit(self: *HashV1) void {
        self.allocator.free(self.calls);
        self.allocator.free(self.main);
        self.allocator.free(self.preprocessed);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const HashV1,
        words: []const M31,
        domain: u32,
        scope: u32,
        digest_kind: u32,
        step_base: u32,
        digest: channel.Digest,
    ) !void {
        var expected = try HashV1.init(
            self.allocator,
            words,
            domain,
            scope,
            digest_kind,
            step_base,
            digest,
        );
        defer expected.deinit();
        if (self.domain != domain or self.scope != scope or
            self.digest_kind != digest_kind or self.step_base != step_base or
            self.word_count != expected.word_count or self.log_size != expected.log_size or
            !std.meta.eql(self.digest, expected.digest) or
            !sliceEqual(hash_witness.PreprocessedRow, self.preprocessed, expected.preprocessed) or
            !sliceEqual(hash_witness.MainRow, self.main, expected.main) or
            !sliceEqual(hash_witness.PoseidonCall, self.calls, expected.calls))
            return error.FieldHashWitnessMismatch;
    }

    pub fn logicalRow(self: *const HashV1, index: usize) ![hash_air.LOGICAL_INPUT_COUNT]M31 {
        if (index >= self.main.len) return error.FieldHashWitnessMismatch;
        return self.main[index].values() ++ self.preprocessed[index].values() ++ .{
            M31.one(),
            M31.fromCanonical(self.domain),
            M31.fromCanonical(self.scope),
            M31.fromCanonical(VERIFIER_ID),
            M31.fromCanonical(self.digest_kind),
        };
    }

    /// The hash row consumes source words, uses the shared Poseidon relation,
    /// and emits the resulting verifier-input digest under fixed parameters.
    pub fn generateInteraction(
        self: *const HashV1,
        allocator: std.mem.Allocator,
        relations: *const universal.UniversalRelations,
    ) !Interaction {
        var definition = try hash_air.build(allocator);
        defer definition.deinit();
        const plan = try hash_relation.authenticate(&definition);
        const size = @as(usize, 1) << @intCast(self.log_size);
        const rows = try allocator.alloc(hash_relation.Row, size);
        defer allocator.free(rows);
        for (rows, 0..) |*row, index| {
            row.* = if (index < self.main.len)
                try self.logicalRow(index)
            else
                [_]M31{M31.zero()} ** hash_air.LOGICAL_INPUT_COUNT;
        }
        return plan.generateInteraction(
            allocator,
            &definition.arena,
            hash_air.SEMANTIC_DIGEST,
            definition.events,
            rows,
            self.log_size,
            relations,
        );
    }
};

fn sliceEqual(comptime T: type, left: []const T, right: []const T) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}

test "field hash consumes exact canonical words and rejects wrong digest" {
    const words = [_]M31{ M31.one(), M31.fromCanonical(17), M31.fromCanonical(65535) };
    const domain: u32 = 0x5350_4631;
    const scope: u32 = 0x5350_5731;
    const digest = channel.hashCanonicalWords(&words, domain);
    var witness = try HashV1.init(
        std.testing.allocator,
        &words,
        domain,
        scope,
        PROVIDER_FIELD_DIGEST_KIND,
        PROVIDER_STEP_BASE,
        digest,
    );
    defer witness.deinit();
    try witness.validateAgainst(
        &words,
        domain,
        scope,
        PROVIDER_FIELD_DIGEST_KIND,
        PROVIDER_STEP_BASE,
        digest,
    );
    const row = try witness.logicalRow(0);
    try std.testing.expectEqual(scope, row[hash_air.LOGICAL_INPUT_COUNT - 3].toU32());
    var definition = try hash_air.build(std.testing.allocator);
    defer definition.deinit();
    const support = @import("air/test_support.zig");
    const lang = @import("../air/lang/mod.zig");
    const evaluated = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(evaluated);
    for (definition.arena.constraintsView()) |constraint|
        try std.testing.expect(evaluated[lang.types.idIndex(constraint.root)].isZero());
    const padding = [_]M31{M31.zero()} ** hash_air.LOGICAL_INPUT_COUNT;
    const padded_values = try support.evaluateArena(std.testing.allocator, &definition.arena, &padding);
    defer std.testing.allocator.free(padded_values);
    for (definition.arena.constraintsView()) |constraint|
        try std.testing.expect(padded_values[lang.types.idIndex(constraint.root)].isZero());
    const relations = universal.UniversalRelations.dummy();
    var interaction = try witness.generateInteraction(std.testing.allocator, &relations);
    defer interaction.deinit(std.testing.allocator);
    var bad = digest;
    bad[0] ^= 1;
    try std.testing.expectError(
        error.FieldHashDigestMismatch,
        HashV1.init(
            std.testing.allocator,
            &words,
            domain,
            scope,
            PROVIDER_FIELD_DIGEST_KIND,
            PROVIDER_STEP_BASE,
            bad,
        ),
    );
}

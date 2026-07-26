//! Active claim-phase transcript helpers for the sharded RISC-V frontend.

const std = @import("std");
const component_order = @import("air/component_order.zig");
const lookup_table_schema = @import("air/lookups/tables/schema.zig");
const program_commitment = @import("air/program/commitment.zig");
const public_data = @import("air/public_data.zig");
const relation_challenges = @import("air/relation_challenges.zig");
const statement_mod = @import("air/statement.zig");
const transcript = @import("air/transcript/mod.zig");
const statement_validation = @import("prover/statement_validation.zig");
const trace_mod = @import("runner/trace.zig");

pub const ProverRelations = struct {
    interaction_pow: u64,
    relations: relation_challenges.Relations,
};

pub fn proveToRelations(
    allocator: std.mem.Allocator,
    channel: anytype,
    statement: *const statement_mod.RiscVStatement,
) !ProverRelations {
    const main_claim = statement.canonicalMainClaim();
    main_claim.mixInto(channel);
    statement.mixShardManifest(channel);
    const nonce = channel.grind(transcript.INTERACTION_POW_BITS);
    channel.mixU64(nonce);
    return .{
        .interaction_pow = nonce,
        .relations = try relation_challenges.Relations.draw(allocator, channel),
    };
}

pub fn verifyToRelations(
    allocator: std.mem.Allocator,
    channel: anytype,
    statement: *const statement_mod.RiscVStatement,
    interaction_pow: u64,
) !relation_challenges.Relations {
    const main_claim = statement.canonicalMainClaim();
    main_claim.mixInto(channel);
    statement.mixShardManifest(channel);
    if (!channel.verifyPowNonce(transcript.INTERACTION_POW_BITS, interaction_pow))
        return transcript.PrefixError.InvalidInteractionProofOfWork;
    channel.mixU64(interaction_pow);
    return relation_challenges.Relations.draw(allocator, channel);
}

pub fn mixInteractionClaim(
    channel: anytype,
    statement: *const statement_mod.RiscVStatement,
    claim: *const statement_mod.RiscVInteractionClaim,
) !void {
    const canonical = try claim.canonical(statement);
    const view = canonical.view();
    view.mixInto(channel);
}

const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const Blake2sMerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const TraceTag = enum(u8) {
    mix_u32s,
    mix_u64,
    mix_felts,
    interaction_pow,
    relation_pair,
    commitment_root,
};

const DrawOrder = enum { canonical, reverse_pairs };

/// Test-only byte recorder around the production channel. Every event contains
/// the exact input bytes followed by the resulting digest and draw counter.
const EventTraceChannel = struct {
    inner: Blake2sChannel = .{},
    draw_order: DrawOrder = .canonical,
    bytes: [32 * 1024]u8 = undefined,
    bytes_len: usize = 0,
    tags: [1024]TraceTag = undefined,
    tags_len: usize = 0,
    relation_pair_index: u32 = 0,

    pub fn mixU32s(self: *EventTraceChannel, values: []const u32) void {
        self.inner.mixU32s(values);
        self.begin(.mix_u32s, 4 + values.len * @sizeOf(u32));
        self.appendU32(@intCast(values.len));
        for (values) |value| self.appendU32(value);
        self.finish();
    }

    pub fn mixU64(self: *EventTraceChannel, value: u64) void {
        self.inner.mixU64(value);
        self.begin(.mix_u64, @sizeOf(u64));
        self.appendU64(value);
        self.finish();
    }

    pub fn mixFelts(self: *EventTraceChannel, values: []const QM31) void {
        self.inner.mixFelts(values);
        self.begin(.mix_felts, 4 + values.len * 4 * @sizeOf(u32));
        self.appendU32(@intCast(values.len));
        for (values) |value| self.appendFelt(value);
        self.finish();
    }

    pub fn grind(self: *EventTraceChannel, bits: u32) u64 {
        const nonce = self.inner.grind(bits);
        self.recordPow(bits, nonce);
        return nonce;
    }

    pub fn verifyPowNonce(self: *EventTraceChannel, bits: u32, nonce: u64) bool {
        const valid = self.inner.verifyPowNonce(bits, nonce);
        self.recordPow(bits, nonce);
        return valid;
    }

    pub fn drawSecureFelts(
        self: *EventTraceChannel,
        allocator: std.mem.Allocator,
        n_felts: usize,
    ) ![]QM31 {
        const values = try allocator.alloc(QM31, n_felts);
        errdefer allocator.free(values);
        var produced: usize = 0;
        while (produced < n_felts) {
            const pair_len = @min(@as(usize, 2), n_felts - produced);
            const pair = try self.inner.drawSecureFelts(allocator, pair_len);
            defer allocator.free(pair);
            if (self.draw_order == .reverse_pairs and pair_len == 2) {
                values[produced] = pair[1];
                values[produced + 1] = pair[0];
            } else {
                @memcpy(values[produced..][0..pair_len], pair);
            }
            self.begin(.relation_pair, 8 + pair_len * @as(usize, 4 * @sizeOf(u32)));
            self.appendU32(self.relation_pair_index);
            self.appendU32(@intCast(pair_len));
            for (values[produced..][0..pair_len]) |value| self.appendFelt(value);
            self.finish();
            self.relation_pair_index += 1;
            produced += pair_len;
        }
        return values;
    }

    fn digestBytes(self: EventTraceChannel) [32]u8 {
        return self.inner.digestBytes();
    }

    fn recordRoot(self: *EventTraceChannel, root: [32]u8) void {
        self.begin(.commitment_root, root.len);
        self.appendBytes(&root);
        self.finish();
    }

    fn recordPow(self: *EventTraceChannel, bits: u32, nonce: u64) void {
        self.begin(.interaction_pow, @sizeOf(u32) + @sizeOf(u64));
        self.appendU32(bits);
        self.appendU64(nonce);
        self.finish();
    }

    fn begin(self: *EventTraceChannel, tag: TraceTag, payload_len: usize) void {
        std.debug.assert(self.tags_len < self.tags.len);
        self.tags[self.tags_len] = tag;
        self.tags_len += 1;
        self.appendByte(@intFromEnum(tag));
        self.appendU32(@intCast(payload_len));
    }

    fn finish(self: *EventTraceChannel) void {
        self.appendBytes(&self.inner.digestBytes());
        self.appendU32(self.inner.n_draws);
    }

    fn appendFelt(self: *EventTraceChannel, value: QM31) void {
        for (value.toM31Array()) |limb| self.appendU32(limb.toU32());
    }

    fn appendU64(self: *EventTraceChannel, value: u64) void {
        self.appendU32(@truncate(value));
        self.appendU32(@truncate(value >> 32));
    }

    fn appendU32(self: *EventTraceChannel, value: u32) void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .little);
        self.appendBytes(&bytes);
    }

    fn appendByte(self: *EventTraceChannel, value: u8) void {
        std.debug.assert(self.bytes_len < self.bytes.len);
        self.bytes[self.bytes_len] = value;
        self.bytes_len += 1;
    }

    fn appendBytes(self: *EventTraceChannel, values: []const u8) void {
        std.debug.assert(self.bytes_len + values.len <= self.bytes.len);
        @memcpy(self.bytes[self.bytes_len..][0..values.len], values);
        self.bytes_len += values.len;
    }

    fn count(self: *const EventTraceChannel, tag: TraceTag) usize {
        var result: usize = 0;
        for (self.tags[0..self.tags_len]) |actual| result += @intFromBool(actual == tag);
        return result;
    }
};

const EventTraceMerkleChannel = struct {
    fn mixRoot(channel: *EventTraceChannel, root: [32]u8) void {
        Blake2sMerkleChannel.mixRoot(&channel.inner, root);
        channel.recordRoot(root);
    }
};

const ClaimPhaseCheckpoints = struct {
    offsets: [6]usize,
};

fn traceCommittedPrefix(
    channel: *EventTraceChannel,
    statement: *const statement_mod.RiscVStatement,
    preprocessed_root: [32]u8,
    main_root: [32]u8,
) [3]usize {
    statement.public_data.mixInto(channel);
    const after_statement = channel.bytes_len;
    EventTraceMerkleChannel.mixRoot(channel, preprocessed_root);
    const after_preprocessed = channel.bytes_len;
    EventTraceMerkleChannel.mixRoot(channel, main_root);
    return .{ after_statement, after_preprocessed, channel.bytes_len };
}

fn finishTracedClaimPhase(
    channel: *EventTraceChannel,
    statement: *const statement_mod.RiscVStatement,
    claim: *const statement_mod.RiscVInteractionClaim,
    interaction_root: [32]u8,
    prefix: [3]usize,
    after_relations: usize,
) !ClaimPhaseCheckpoints {
    try mixInteractionClaim(channel, statement, claim);
    const after_claim = channel.bytes_len;
    EventTraceMerkleChannel.mixRoot(channel, interaction_root);
    return .{ .offsets = .{
        prefix[0],
        prefix[1],
        prefix[2],
        after_relations,
        after_claim,
        channel.bytes_len,
    } };
}

fn fixtureStatement() statement_mod.RiscVStatement {
    const input_words = &[_]u32{0x0403_0201};
    const output_words = &[_]public_data.OutputWord{
        .{ .addr = 0x0010_0004, .value = 4, .clock = 12 },
        .{ .addr = 0x0010_0008, .value = 0x0807_0605, .clock = 13 },
    };
    var final_regs = [_]u32{1} ** 32;
    final_regs[0] = 0;
    var statement: statement_mod.RiscVStatement = undefined;
    statement.n_components = 2;
    statement.component_descs[0] = .{
        .family = .base_alu_imm,
        .log_size = 16,
        .n_rows = 1 << 16,
        .n_columns = trace_mod.nColumnsForFamily(.base_alu_imm),
    };
    statement.component_descs[1] = .{
        .family = .base_alu_imm,
        .log_size = 4,
        .n_rows = 5,
        .n_columns = trace_mod.nColumnsForFamily(.base_alu_imm),
    };
    statement.initial_pc = 0x1000;
    statement.final_pc = 0x1040;
    statement.total_steps = (1 << 16) + 5;
    statement.public_data = .{
        .initial_pc = statement.initial_pc,
        .final_pc = statement.final_pc,
        .clock = statement.total_steps,
        .initial_regs = .{0} ** 32,
        .final_regs = final_regs,
        .reg_last_clock = .{2} ** 32,
        .program_root = 101,
        .initial_rw_root = 202,
        .final_rw_root = 303,
        .completion = public_data.Completion.canonicalSelfLoop(statement.final_pc),
        .io_entries = .{
            .input_start = 0x0018_0000,
            .input_len = 4,
            .input_words = input_words,
            .output_len = 4,
            .output_len_addr = 0x0010_0004,
            .output_data_addr = 0x0010_0008,
            .output_words = output_words,
        },
    };
    statement.n_infra = 0;
    statement.infra_descs[statement.n_infra] = .{
        .kind = .program,
        .log_size = statement_validation.computeLogSize(20),
        .n_rows = 20,
        .n_columns = program_commitment.N_MAIN_COLUMNS,
    };
    statement.n_infra += 1;
    statement.infra_descs[statement.n_infra] = .{
        .kind = .memory,
        .log_size = 5,
        .n_rows = 18,
        .n_columns = 8,
    };
    statement.n_infra += 1;
    statement.infra_descs[statement.n_infra] = .{
        .kind = .merkle,
        .log_size = 4,
        .n_rows = 16,
        .n_columns = 10,
    };
    statement.n_infra += 1;
    statement.infra_descs[statement.n_infra] = .{
        .kind = .poseidon2,
        .log_size = 4,
        .n_rows = 16,
        .n_columns = 445,
    };
    statement.n_infra += 1;
    statement.infra_descs[statement.n_infra] = .{
        .kind = .clock_update,
        .log_size = 4,
        .n_rows = 1,
        .n_columns = 8,
    };
    statement.n_infra += 1;
    for (component_order.lookupTables()) |kind| {
        statement.infra_descs[statement.n_infra] = .{
            .kind = statement_mod.infraKindForTable(kind),
            .log_size = lookup_table_schema.logSize(kind),
            .n_rows = @intCast(lookup_table_schema.size(kind)),
            .n_columns = 1,
        };
        statement.n_infra += 1;
    }
    return statement;
}

fn fixtureInteractionClaim(statement: *const statement_mod.RiscVStatement) statement_mod.RiscVInteractionClaim {
    var claim = statement_mod.RiscVInteractionClaim.initZero();
    claim.n_components = statement.n_components;
    claim.n_infra = statement.n_infra;
    claim.opcode_claims[0][0] = QM31.fromU32Unchecked(1, 2, 3, 4);
    claim.opcode_claims[1][0] = QM31.fromU32Unchecked(5, 6, 7, 8);
    claim.program_claims[0][0] = QM31.fromU32Unchecked(9, 10, 11, 12);
    claim.memory_claims[1][0] = QM31.fromU32Unchecked(13, 14, 15, 16);
    return claim;
}

fn expectMutationRejectedOrDivergent(
    statement: *const statement_mod.RiscVStatement,
    prefix_channel: EventTraceChannel,
    mutated_nonce: u64,
    mutated_relations: relation_challenges.Relations,
) !void {
    var canonical = prefix_channel;
    const result = verifyToRelations(
        std.testing.allocator,
        &canonical,
        statement,
        mutated_nonce,
    );
    if (result) |relations| {
        try std.testing.expect(!relations.registers_state.z.eql(mutated_relations.registers_state.z) or
            !relations.registers_state.alpha.eql(mutated_relations.registers_state.alpha));
    } else |err| {
        try std.testing.expectEqual(transcript.PrefixError.InvalidInteractionProofOfWork, err);
    }
}

test "active RISC-V transcript claim phase is byte-symmetric at every event" {
    const allocator = std.testing.allocator;
    const statement = fixtureStatement();
    try statement_validation.validate(statement, .proof);
    const claim = fixtureInteractionClaim(&statement);
    const preprocessed_root = [_]u8{0x11} ** 32;
    const main_root = [_]u8{0x22} ** 32;
    const interaction_root = [_]u8{0x33} ** 32;

    var prover = EventTraceChannel{};
    const prover_prefix = traceCommittedPrefix(&prover, &statement, preprocessed_root, main_root);
    const prover_relations = try proveToRelations(allocator, &prover, &statement);
    const prover_checkpoints = try finishTracedClaimPhase(
        &prover,
        &statement,
        &claim,
        interaction_root,
        prover_prefix,
        prover.bytes_len,
    );

    var verifier = EventTraceChannel{};
    const verifier_prefix = traceCommittedPrefix(&verifier, &statement, preprocessed_root, main_root);
    const verifier_relations = try verifyToRelations(
        allocator,
        &verifier,
        &statement,
        prover_relations.interaction_pow,
    );
    const verifier_checkpoints = try finishTracedClaimPhase(
        &verifier,
        &statement,
        &claim,
        interaction_root,
        verifier_prefix,
        verifier.bytes_len,
    );

    try std.testing.expect(prover_relations.relations.registers_state.z.eql(
        verifier_relations.registers_state.z,
    ));
    try std.testing.expectEqual(prover_checkpoints.offsets, verifier_checkpoints.offsets);
    for (prover_checkpoints.offsets) |offset| {
        try std.testing.expectEqualSlices(u8, prover.bytes[0..offset], verifier.bytes[0..offset]);
    }
    try std.testing.expectEqualSlices(
        TraceTag,
        prover.tags[0..prover.tags_len],
        verifier.tags[0..verifier.tags_len],
    );
    try std.testing.expectEqual(@as(usize, 3), prover.count(.commitment_root));
    try std.testing.expectEqual(@as(usize, 1), prover.count(.interaction_pow));
    try std.testing.expectEqual(relation_challenges.RELATION_COUNT, prover.count(.relation_pair));
    try std.testing.expectEqual(
        @as(u32, @intCast(relation_challenges.RELATION_COUNT)),
        prover.relation_pair_index,
    );
    try std.testing.expectEqual(prover.digestBytes(), verifier.digestBytes());
}

test "active RISC-V transcript rejects reversed main-claim and shard-manifest mix" {
    const allocator = std.testing.allocator;
    const statement = fixtureStatement();
    try statement_validation.validate(statement, .proof);
    const preprocessed_root = [_]u8{0x11} ** 32;
    const main_root = [_]u8{0x22} ** 32;

    var canonical_prefix = EventTraceChannel{};
    _ = traceCommittedPrefix(&canonical_prefix, &statement, preprocessed_root, main_root);
    var mutated = canonical_prefix;
    statement.mixShardManifest(&mutated);
    const main_claim = statement.canonicalMainClaim();
    main_claim.mixInto(&mutated);
    const nonce = mutated.grind(transcript.INTERACTION_POW_BITS);
    mutated.mixU64(nonce);
    const relations = try relation_challenges.Relations.draw(allocator, &mutated);

    try expectMutationRejectedOrDivergent(&statement, canonical_prefix, nonce, relations);
}

test "active RISC-V transcript detects reversed relation-pair draws" {
    const allocator = std.testing.allocator;
    const statement = fixtureStatement();
    try statement_validation.validate(statement, .proof);
    const preprocessed_root = [_]u8{0x11} ** 32;
    const main_root = [_]u8{0x22} ** 32;

    var canonical = EventTraceChannel{};
    _ = traceCommittedPrefix(&canonical, &statement, preprocessed_root, main_root);
    const canonical_result = try proveToRelations(allocator, &canonical, &statement);
    var reversed = EventTraceChannel{ .draw_order = .reverse_pairs };
    _ = traceCommittedPrefix(&reversed, &statement, preprocessed_root, main_root);
    const reversed_result = try proveToRelations(allocator, &reversed, &statement);

    try std.testing.expectEqual(canonical_result.interaction_pow, reversed_result.interaction_pow);
    try std.testing.expect(canonical_result.relations.registers_state.z.eql(
        reversed_result.relations.registers_state.alpha,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        canonical.bytes[0..canonical.bytes_len],
        reversed.bytes[0..reversed.bytes_len],
    ));
    try std.testing.expectEqual(canonical.digestBytes(), reversed.digestBytes());
}

test "active RISC-V transcript binds shard order before relation draws" {
    const allocator = std.testing.allocator;
    const statement = fixtureStatement();
    try statement_validation.validate(statement, .proof);
    var reversed_statement = statement;
    std.mem.swap(
        statement_mod.FamilyComponentDesc,
        &reversed_statement.component_descs[0],
        &reversed_statement.component_descs[1],
    );
    try std.testing.expectError(
        error.InvalidStatement,
        statement_validation.validate(reversed_statement, .proof),
    );
    const canonical_claim = statement.canonicalMainClaim();
    const reversed_claim = reversed_statement.canonicalMainClaim();
    try std.testing.expectEqual(canonical_claim.log_sizes, reversed_claim.log_sizes);

    const preprocessed_root = [_]u8{0x11} ** 32;
    const main_root = [_]u8{0x22} ** 32;
    var canonical_prefix = EventTraceChannel{};
    _ = traceCommittedPrefix(&canonical_prefix, &statement, preprocessed_root, main_root);
    var reversed = EventTraceChannel{};
    _ = traceCommittedPrefix(&reversed, &reversed_statement, preprocessed_root, main_root);
    const reversed_result = try proveToRelations(allocator, &reversed, &reversed_statement);

    try expectMutationRejectedOrDivergent(
        &statement,
        canonical_prefix,
        reversed_result.interaction_pow,
        reversed_result.relations,
    );
}

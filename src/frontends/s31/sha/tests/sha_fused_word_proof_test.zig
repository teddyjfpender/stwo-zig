//! Native three-call proof of the fused SHA schedule and shift-register AIR.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_circuit_cpu_integration");
const sha = @import("s31_sha_provider").compression;
const plan_mod = @import("../config/sha_chip_plan.zig");
const air = @import("../air/sha_fused_air.zig");
const word = @import("../air/sha_fused_word_logup.zig");
const bus = @import("../air/sha_fused_word_bus.zig");
const native = @import("../verification/sha_fused_word_native_verifier.zig");
const postcard = @import("interop_postcard");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Engine = cpu.prove.Internal.Engine;
const Column = prover.pcs.ColumnEvaluation;

fn cloneColumns(allocator: std.mem.Allocator, columns: []const Column) ![]Column {
    const owned = try allocator.alloc(Column, columns.len);
    var ready: usize = 0;
    errdefer {
        for (owned[0..ready]) |column| allocator.free(column.values);
        allocator.free(owned);
    }
    for (columns, owned) |source, *target| {
        target.* = .{ .log_size = source.log_size, .values = try allocator.dupe(M31, source.values) };
        ready += 1;
    }
    return owned;
}
fn commit(scheme: *Engine.Scheme, allocator: std.mem.Allocator, columns: []const Column, channel: *MC.Channel) !void {
    try Engine.commit(scheme, allocator, try cloneColumns(allocator, columns), null, channel);
    try Engine.flushPendingCommit(scheme, allocator, channel);
}

fn statementsFor(header: [80]u8) !air.Statements {
    const plan = plan_mod.prepare(header);
    var statements: air.Statements = undefined;
    for (plan.calls, &statements) |call, *statement| {
        const reference = sha.witness(call.state, call.block);
        if (!std.meta.eql(reference.output_state, call.output)) return error.InvalidShaFusedPlan;
        statement.* = .{ .initial = call.state, .final = reference.states[64], .schedule = reference.schedule };
    }
    var first: [32]u8 = undefined;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&header, &first, .{});
    std.crypto.hash.sha2.Sha256.hash(&first, &digest, .{});
    if (!std.mem.eql(u8, &digest, &plan.digest)) return error.InvalidShaFusedDigest;
    return statements;
}

fn bitWord(main: []const Column, logical: usize, first_bit: usize) u32 {
    const storage = air.storageIndex(logical);
    var value: u32 = 0;
    for (0..32) |bit| value |= main[first_bit + bit].values[storage].toU32() << @intCast(bit);
    return value;
}

fn checkRows(main: []const Column, statements: air.Statements) !void {
    for (statements, 0..) |statement, call| {
        const base = call * air.segment_rows;
        var state = statement.initial;
        for (0..65) |t| {
            const row = base + 3 + t;
            const got = sha.State{
                bitWord(main, row, 0),  bitWord(main, row - 1, 0),  bitWord(main, row - 2, 0),  bitWord(main, row - 3, 0),
                bitWord(main, row, 32), bitWord(main, row - 1, 32), bitWord(main, row - 2, 32), bitWord(main, row - 3, 32),
            };
            try std.testing.expectEqualDeep(state, got);
            if (t < 64) {
                try std.testing.expectEqual(statement.schedule[t], bitWord(main, row, 76));
                state = sha.round(state, statement.schedule[t], sha.round_constants[t]);
            }
        }
        try std.testing.expectEqualDeep(statement.final, state);
    }
}

fn checkMutations(allocator: std.mem.Allocator, statements: air.Statements, first_call_id: u32) !void {
    var fixed = try air.writeFixed(allocator, first_call_id);
    defer fixed.deinit();
    var main = try air.writeMain(allocator, statements);
    defer main.deinit();
    try air.validateCommittedTrace(fixed.values, main.values);
    try checkRows(main.values, statements);
    const changes = [_]struct { row: usize, col: usize }{
        .{ .row = 0, .col = 0 }, // first call initial d bit
        .{ .row = 68 + 1, .col = 32 }, // second call g history
        .{ .row = 136 + 18, .col = 76 }, // third call W[15], recurrence predecessor
        .{ .row = 3 + 20, .col = 76 }, // first call W[20]
        .{ .row = 68 + 3 + 44, .col = 65 }, // second call round carry
        .{ .row = 136 + 3 + 18, .col = 108 }, // third call schedule carry
        .{ .row = 136 + 67, .col = 0 }, // third final a
        .{ .row = 204, .col = 0 }, // padding
        .{ .row = 68 + 67, .col = 76 }, // terminal W must be zero
    };
    for (changes) |change| {
        const at = air.storageIndex(change.row);
        const old = main.values[change.col].values[at];
        @constCast(main.values[change.col].values)[at] = M31.one().sub(old);
        if (air.validateCommittedTrace(fixed.values, main.values)) |_| {
            std.debug.print("accepted fused mutation row={d} col={d}\n", .{ change.row, change.col });
            return error.FusedMutationAccepted;
        } else |err| try std.testing.expectEqual(error.InvalidShaFusedConstraint, err);
        @constCast(main.values[change.col].values)[at] = old;
    }
    const k_at = air.storageIndex(3 + 9);
    const old_k = fixed.values[6].values[k_at];
    @constCast(fixed.values[6].values)[k_at] = old_k.add(M31.one());
    try std.testing.expectError(error.InvalidShaFusedConstraint, air.validateCommittedTrace(fixed.values, main.values));
    @constCast(fixed.values[6].values)[k_at] = old_k;
    const recurrence_with_carry = blk: {
        for (16..64) |t| {
            const row = 68 + 3 + t;
            const at = air.storageIndex(row);
            for (108..112) |column| if (!main.values[column].values[at].isZero()) break :blk row;
        }
        return error.MissingScheduleCarryForSelectorTest;
    };
    const selectors = [_]struct { row: usize, col: usize }{
        .{ .row = recurrence_with_carry, .col = 1 }, // removing recurrence forces a nonzero carry to zero
        .{ .row = 136 + 3 + 9, .col = 0 }, // round active
        .{ .row = 68 + 3, .col = 5 }, // padding selector on nonzero active state
    };
    for (selectors) |change| {
        const at = air.storageIndex(change.row);
        const old = fixed.values[change.col].values[at];
        @constCast(fixed.values[change.col].values)[at] = M31.one().sub(old);
        if (air.validateCommittedTrace(fixed.values, main.values)) |_| {
            std.debug.print("accepted fused selector mutation row={d} col={d}\n", .{ change.row, change.col });
            return error.FusedSelectorMutationAccepted;
        } else |err| try std.testing.expectEqual(error.InvalidShaFusedConstraint, err);
        @constCast(fixed.values[change.col].values)[at] = old;
    }
    const elements = bus.Elements.init(QM31.fromU32Unchecked(17, 3, 5, 7), QM31.fromU32Unchecked(11, 13, 19, 23));
    var interaction = try word.writeInteraction(allocator, fixed.values, main.values, elements);
    defer interaction.deinit();
    const expected = try native.expectedClaim(statements, first_call_id, elements);
    try std.testing.expect(interaction.claimed_sum.eql(expected));
    const component = word.Component{ .elements = elements, .claimed_sum = expected };
    try word.validateCommittedTrace(&component, fixed.values, main.values, interaction.columns);
    const interaction_at = air.storageIndex(68 + 3);
    const old_interaction = interaction.columns[0].values[interaction_at];
    @constCast(interaction.columns[0].values)[interaction_at] = old_interaction.add(M31.one());
    try std.testing.expectError(error.InvalidShaFusedWordConstraint, word.validateCommittedTrace(&component, fixed.values, main.values, interaction.columns));
    @constCast(interaction.columns[0].values)[interaction_at] = old_interaction;
    const addr_at = air.storageIndex(68 + 66);
    const old_addr = fixed.values[10].values[addr_at];
    @constCast(fixed.values[10].values)[addr_at] = old_addr.add(M31.one());
    try std.testing.expectError(error.InvalidShaFusedWordConstraint, word.validateCommittedTrace(&component, fixed.values, main.values, interaction.columns));
    @constCast(fixed.values[10].values)[addr_at] = old_addr;
    const id_at = air.storageIndex(136 + 3);
    const old_id = fixed.values[9].values[id_at];
    @constCast(fixed.values[9].values)[id_at] = old_id.add(M31.one());
    try std.testing.expectError(error.InvalidShaFusedWordConstraint, word.validateCommittedTrace(&component, fixed.values, main.values, interaction.columns));
}

test "fused three-call SHA schedule/round AIR proves and natively verifies exact Bitcoin header" {
    const allocator = std.testing.allocator;
    var header: [80]u8 = undefined;
    for (&header, 0..) |*byte, i| byte.* = @truncate(29 + 47 * i);
    const statements = try statementsFor(header);
    const first_call_id: u32 = 41;
    try checkMutations(allocator, statements, first_call_id);
    var invalid_terminal = statements;
    invalid_terminal[0].final[0] ^= 1;
    try std.testing.expectError(error.InvalidShaFusedTerminal, air.writeMain(allocator, invalid_terminal));
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, air.log_size);
    var fixed = try air.writeFixed(allocator, first_call_id);
    defer fixed.deinit();
    var main = try air.writeMain(allocator, statements);
    defer main.deinit();
    const canonical_root = try native.canonicalFixedRoot(allocator, statements, first_call_id, pcs);
    var channel = MC.Channel{};
    native.mixStatement(&channel, statements, first_call_id, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try commit(&scheme, allocator, fixed.values, &channel);
    try std.testing.expectEqualDeep(canonical_root, scheme.trees.items[0].commitment.root());
    try commit(&scheme, allocator, main.values, &channel);
    const challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const elements = bus.Elements.init(challenge.z, challenge.alpha);
    var interaction = try word.writeInteraction(allocator, fixed.values, main.values, elements);
    defer interaction.deinit();
    const expected = try native.expectedClaim(statements, first_call_id, elements);
    try std.testing.expect(interaction.claimed_sum.eql(expected));
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &.{expected});
    try commit(&scheme, allocator, interaction.columns, &channel);
    const air_component = air.Component{};
    const word_component = word.Component{ .elements = elements, .claimed_sum = expected };
    const handles = [_]prover.air.component_prover.ComponentProver{ air_component.asProverComponent(), word_component.asProverComponent() };
    scheme_owned = false;
    var timer = try std.time.Timer.start();
    var proof = try Engine.prove(allocator, &handles, &channel, scheme, .{ .include_all_preprocessed_columns = true });
    const prove_ns = timer.read();
    defer proof.deinit(allocator);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try postcard.serializeProof(H, bytes.writer(allocator), proof.proof);
    timer.reset();
    try native.verifyBytes(allocator, statements, first_call_id, pcs, bytes.items);
    const verify_ns = timer.read();
    std.debug.print("S31_SHA_FUSED_ISOLATED native_verified=true calls=3 rows={d} fixed={d} main={d} interaction={d} constraints={d}+{d} oods_main_openings=496 prove_ms={d} verify_ms={d} proof_bytes={d} fri_pow_bits=0 queries=12\n", .{
        air.rows,                      air.fixed_width,                air.main_width,  word.interaction_width, air.n_constraints, word.n_constraints,
        prove_ns / std.time.ns_per_ms, verify_ns / std.time.ns_per_ms, bytes.items.len,
    });
    var changed = statements;
    changed[1].schedule[0] ^= 1;
    if (native.verifyBytes(allocator, changed, first_call_id, pcs, bytes.items)) |_| return error.ChangedFusedScheduleAccepted else |_| {}
    changed = statements;
    changed[0].initial[0] ^= 1;
    if (native.verifyBytes(allocator, changed, first_call_id, pcs, bytes.items)) |_| return error.ChangedFusedInitialAccepted else |_| {}
    if (native.verifyBytes(allocator, statements, first_call_id + 1, pcs, bytes.items)) |_| return error.ChangedFusedCallIdAccepted else |_| {}
    if (native.verifyBytes(allocator, statements, first_call_id, pcs, bytes.items[0 .. bytes.items.len - 1])) |_| return error.TruncatedFusedProofAccepted else |_| {}
    const altered = try allocator.dupe(u8, bytes.items);
    defer allocator.free(altered);
    altered[0] ^= 0x80;
    if (native.verifyBytes(allocator, statements, first_call_id, pcs, altered)) |_| return error.AlteredFusedProofAccepted else |_| {}
}

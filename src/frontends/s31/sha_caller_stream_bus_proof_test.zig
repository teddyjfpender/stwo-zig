//! One native STARK proof of caller equations and Gate/word lookup fractions.
//! The public claims are intentionally open: circuit and the other direct
//! SHA components must close them in the final joined proof.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_circuit_cpu_integration");
const postcard = @import("interop_postcard");
const plan = @import("sha_chip_plan.zig");
const caller = @import("sha_caller_stream_air.zig");
const bus = @import("sha_caller_stream_bus.zig");
const word_bus = @import("sha_direct_word_bus.zig");
const native = @import("sha_caller_stream_bus_native_verifier.zig");
const gate_relation_id = @import("stwo_circuit_frontend").common.component_list.GATE_RELATION_ID;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Engine = cpu.prove.Internal.Engine;
const Column = prover.pcs.ColumnEvaluation;

fn config() @import("sha_caller_stream_equations.zig").Config {
    var addresses: [56]u32 = undefined;
    for (&addresses, 0..) |*value, i| value.* = @intCast(3 + i);
    return .{ .gate_addresses = addresses, .first_call_id = 17 };
}
fn header() [80]u8 {
    var value: [80]u8 = undefined;
    for (&value, 0..) |*byte, i| byte.* = @truncate(19 + 41 * i);
    return value;
}
fn statement(bytes: [80]u8) caller.Statement {
    return .{ .digest = plan.prepare(bytes).digest, .config = config() };
}
fn commit(scheme: *Engine.Scheme, allocator: std.mem.Allocator, columns: []const Column, channel: *MC.Channel) !void {
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
    try Engine.commit(scheme, allocator, owned, null, channel);
    try Engine.flushPendingCommit(scheme, allocator, channel);
}
fn joinedFixed(allocator: std.mem.Allocator, first: []const Column, second: []const Column) ![]Column {
    const values = try allocator.alloc(Column, first.len + second.len);
    @memcpy(values[0..first.len], first);
    @memcpy(values[first.len..], second);
    return values;
}

fn independentClaims(main: []const Column, s: caller.Statement, gate: word_bus.Elements, word: word_bus.Elements) !native.Claims {
    var claims = native.Claims{ .gate = QM31.zero(), .word = QM31.zero() };
    for (0..caller.active_rows) |logical| {
        const row = try caller.rowAt(main, logical);
        for (caller.gateBusEvents(M31, row, logical, s.config)) |maybe_gate| if (maybe_gate) |event| {
            const tuple: [6]M31 = .{
                M31.fromCanonical(gate_relation_id), M31.fromCanonical(event.address), event.value,
                M31.zero(),                          M31.zero(),                       M31.zero(),
            };
            claims.gate = claims.gate.add(try gate.denominator(M31, tuple).inv());
        };
        for (caller.wordBusEvents(M31, row, logical, s.config)) |maybe_word| if (maybe_word) |event| {
            const inverse = try word.denominator(M31, event.tuple).inv();
            if (event.weight < 0) claims.word = claims.word.sub(inverse) else {
                for (0..@as(usize, @intCast(event.weight))) |_| claims.word = claims.word.add(inverse);
            }
        };
    }
    return claims;
}

test "one native proof shares caller main columns across local equations and two independent LogUps" {
    const allocator = std.testing.allocator;
    const bytes = header();
    const s = statement(bytes);
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, caller.log_size);
    var caller_fixed = try caller.writeFixed(allocator, s);
    defer caller_fixed.deinit();
    var bus_fixed = try bus.writeFixed(allocator, s.config);
    defer bus_fixed.deinit();
    const fixed = try joinedFixed(allocator, caller_fixed.values, bus_fixed.values);
    defer allocator.free(fixed);
    var main = try caller.writeMain(allocator, bytes);
    defer main.deinit();
    try caller.validateCommittedTrace(s, caller_fixed.values, main.values);

    var channel = MC.Channel{};
    native.mixStatement(&channel, s, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try commit(&scheme, allocator, fixed, &channel);
    const fixed_root = scheme.trees.items[0].commitment.root();
    try commit(&scheme, allocator, main.values, &channel);
    const gate_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const word_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const gate_elements = word_bus.Elements.init(gate_challenge.z, gate_challenge.alpha);
    const word_elements = word_bus.Elements.init(word_challenge.z, word_challenge.alpha);
    try std.testing.expect(!gate_challenge.z.eql(word_challenge.z));
    var interaction = try bus.writeInteraction(allocator, bus_fixed.values, main.values, s.config, gate_elements, word_elements);
    defer interaction.deinit();
    const expected = try independentClaims(main.values, s, gate_elements, word_elements);
    try std.testing.expect(interaction.gate_claimed_sum.eql(expected.gate));
    try std.testing.expect(interaction.word_claimed_sum.eql(expected.word));
    const claims = native.Claims{ .gate = interaction.gate_claimed_sum, .word = interaction.word_claimed_sum };
    const caller_component = caller.Component{ .statement = s };
    const bus_component = bus.Component{
        .config = s.config,
        .fixed_offset = caller.fixed_width,
        .gate_elements = gate_elements,
        .word_elements = word_elements,
        .gate_claimed_sum = claims.gate,
        .word_claimed_sum = claims.word,
    };
    try bus.validateCommittedTrace(&bus_component, bus_fixed.values, main.values, interaction.columns);
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &.{ claims.gate, claims.word });
    try commit(&scheme, allocator, interaction.columns, &channel);
    const handles = [_]prover.air.component_prover.ComponentProver{ caller_component.asProverComponent(), bus_component.asProverComponent() };
    scheme_owned = false;
    var timer = try std.time.Timer.start();
    var proof = try Engine.prove(allocator, &handles, &channel, scheme, .{ .include_all_preprocessed_columns = true });
    const prove_ns = timer.read();
    defer proof.deinit(allocator);
    var envelope: std.ArrayList(u8) = .empty;
    defer envelope.deinit(allocator);
    try envelope.appendSlice(allocator, &native.statementTag(s, pcs, claims));
    try postcard.serializeProof(H, envelope.writer(allocator), proof.proof);
    timer.reset();
    try native.verifyBytes(allocator, s, pcs, fixed_root, claims, envelope.items);
    const verify_ns = timer.read();
    std.debug.print("S31_SHA_CALLER_STREAM_BUS verified=true rows={d} fixed={d} main={d} interaction={d} constraints={d}+{d} prove_ms={d} verify_ms={d} proof_bytes={d} fri_pow_bits=0 queries=12\n", .{
        caller.rows,          caller.fixed_width + bus.fixed_width, caller.main_width,             bus.interaction_width,
        caller.n_constraints, bus.n_constraints,                    prove_ns / std.time.ns_per_ms, verify_ns / std.time.ns_per_ms,
        envelope.items.len,
    });
    var changed = claims;
    changed.gate = changed.gate.add(QM31.one());
    try std.testing.expectError(error.WrongShaCallerBusStatementTag, native.verifyBytes(allocator, s, pcs, fixed_root, changed, envelope.items));
    changed = claims;
    changed.word = changed.word.add(QM31.one());
    try std.testing.expectError(error.WrongShaCallerBusStatementTag, native.verifyBytes(allocator, s, pcs, fixed_root, changed, envelope.items));
    var changed_statement = s;
    changed_statement.config.first_call_id += 1;
    try std.testing.expectError(error.WrongShaCallerBusStatementTag, native.verifyBytes(allocator, changed_statement, pcs, fixed_root, claims, envelope.items));
    try std.testing.expectError(error.NoncanonicalShaCallerBusFixedRoot, native.verifyBytes(allocator, s, pcs, [_]u8{0} ** 32, claims, envelope.items));
}

test "bus metadata pins all 56 Gate and 96 weighted word uses across 80 rows" {
    const s = statement(header());
    var gates: usize = 0;
    var words: usize = 0;
    var state_weight: usize = 0;
    var output_weight: usize = 0;
    for (0..caller.rows) |logical| {
        const meta = bus.metadataAt(logical, s.config);
        if (meta[0].eql(M31.one())) gates += 2;
        for ([_]usize{ 3, 7 }) |base| if (meta[base].eql(M31.one())) {
            words += 1;
            const address = meta[base + 2].toU32();
            if (address < 8) {
                try std.testing.expect(meta[base + 3].eql(M31.fromCanonical(2)));
                state_weight += 2;
            } else if (address < 24) try std.testing.expect(meta[base + 3].eql(M31.one())) else {
                try std.testing.expect(meta[base + 3].eql(M31.one().neg()));
                output_weight += 1;
            }
        };
    }
    try std.testing.expectEqual(@as(usize, 56), gates);
    try std.testing.expectEqual(@as(usize, 96), words);
    try std.testing.expectEqual(@as(usize, 48), state_weight);
    try std.testing.expectEqual(@as(usize, 24), output_weight);
}

test "locally valid private header substitution changes both open bus claims" {
    const allocator = std.testing.allocator;
    const bytes = header();
    const s = statement(bytes);
    var caller_fixed = try caller.writeFixed(allocator, s);
    defer caller_fixed.deinit();
    var bus_fixed = try bus.writeFixed(allocator, s.config);
    defer bus_fixed.deinit();
    var main = try caller.writeMain(allocator, bytes);
    defer main.deinit();
    const gate_elements = word_bus.Elements.init(QM31.fromU32Unchecked(17, 3, 5, 7), QM31.fromU32Unchecked(11, 13, 19, 23));
    const word_elements = word_bus.Elements.init(QM31.fromU32Unchecked(29, 31, 37, 41), QM31.fromU32Unchecked(43, 47, 53, 59));
    var honest = try bus.writeInteraction(allocator, bus_fixed.values, main.values, s.config, gate_elements, word_elements);
    defer honest.deinit();
    const honest_component = bus.Component{
        .config = s.config,
        .fixed_offset = caller.fixed_width,
        .gate_elements = gate_elements,
        .word_elements = word_elements,
        .gate_claimed_sum = honest.gate_claimed_sum,
        .word_claimed_sum = honest.word_claimed_sum,
    };
    try bus.validateCommittedTrace(&honest_component, bus_fixed.values, main.values, honest.columns);
    @constCast(honest.columns[0].values)[caller.storageIndex(0)] = honest.columns[0].values[caller.storageIndex(0)].add(M31.one());
    try std.testing.expectError(error.InvalidShaCallerBusConstraint, bus.validateCommittedTrace(&honest_component, bus_fixed.values, main.values, honest.columns));

    // Header byte 0 has low bit one. Changing it to zero and updating its
    // Gate limb and SHA big-endian high half preserves every caller equation.
    // Without joint closure, both claimed lookup sums can simply move.
    const storage = caller.storageIndex(0);
    try std.testing.expect(main.values[6].values[storage].eql(M31.one()));
    @constCast(main.values[6].values)[storage] = M31.zero();
    @constCast(main.values[0].values)[storage] = main.values[0].values[storage].sub(M31.one());
    @constCast(main.values[3].values)[storage] = main.values[3].values[storage].sub(M31.fromCanonical(256));
    try caller.validateCommittedTrace(s, caller_fixed.values, main.values);
    var altered = try bus.writeInteraction(allocator, bus_fixed.values, main.values, s.config, gate_elements, word_elements);
    defer altered.deinit();
    try std.testing.expect(!altered.gate_claimed_sum.eql(honest.gate_claimed_sum));
    try std.testing.expect(!altered.word_claimed_sum.eql(honest.word_claimed_sum));
    const altered_component = bus.Component{
        .config = s.config,
        .fixed_offset = caller.fixed_width,
        .gate_elements = gate_elements,
        .word_elements = word_elements,
        .gate_claimed_sum = altered.gate_claimed_sum,
        .word_claimed_sum = altered.word_claimed_sum,
    };
    try bus.validateCommittedTrace(&altered_component, bus_fixed.values, main.values, altered.columns);

    const weight = &@constCast(bus_fixed.values[6].values)[caller.storageIndex(44)];
    weight.* = weight.*.add(M31.one());
    try std.testing.expectError(error.InvalidShaCallerBusFixed, bus.validateCommittedTrace(&altered_component, bus_fixed.values, main.values, altered.columns));
}

test "committed Gate lookup accumulator mutation fails native prover constraints" {
    const allocator = std.testing.allocator;
    const bytes = header();
    const s = statement(bytes);
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, caller.log_size);
    var caller_fixed = try caller.writeFixed(allocator, s);
    defer caller_fixed.deinit();
    var bus_fixed = try bus.writeFixed(allocator, s.config);
    defer bus_fixed.deinit();
    const fixed = try joinedFixed(allocator, caller_fixed.values, bus_fixed.values);
    defer allocator.free(fixed);
    var main = try caller.writeMain(allocator, bytes);
    defer main.deinit();
    var channel = MC.Channel{};
    native.mixStatement(&channel, s, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try commit(&scheme, allocator, fixed, &channel);
    try commit(&scheme, allocator, main.values, &channel);
    const gate_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const word_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const gate_elements = word_bus.Elements.init(gate_challenge.z, gate_challenge.alpha);
    const word_elements = word_bus.Elements.init(word_challenge.z, word_challenge.alpha);
    var interaction = try bus.writeInteraction(allocator, bus_fixed.values, main.values, s.config, gate_elements, word_elements);
    defer interaction.deinit();
    const claims = native.Claims{ .gate = interaction.gate_claimed_sum, .word = interaction.word_claimed_sum };
    const caller_component = caller.Component{ .statement = s };
    const bus_component = bus.Component{
        .config = s.config,
        .fixed_offset = caller.fixed_width,
        .gate_elements = gate_elements,
        .word_elements = word_elements,
        .gate_claimed_sum = claims.gate,
        .word_claimed_sum = claims.word,
    };
    @constCast(interaction.columns[0].values)[caller.storageIndex(0)] = interaction.columns[0].values[caller.storageIndex(0)].add(M31.one());
    try std.testing.expectError(error.InvalidShaCallerBusConstraint, bus.validateCommittedTrace(&bus_component, bus_fixed.values, main.values, interaction.columns));
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &.{ claims.gate, claims.word });
    try commit(&scheme, allocator, interaction.columns, &channel);
    const handles = [_]prover.air.component_prover.ComponentProver{ caller_component.asProverComponent(), bus_component.asProverComponent() };
    scheme_owned = false;
    if (Engine.prove(allocator, &handles, &channel, scheme, .{ .include_all_preprocessed_columns = true })) |proof_result| {
        var proof = proof_result;
        proof.deinit(allocator);
        return error.MutatedCallerBusInteractionProved;
    } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
}

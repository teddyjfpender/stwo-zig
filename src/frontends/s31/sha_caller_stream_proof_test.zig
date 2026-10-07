//! Native, serialized proof tests for the isolated streamed caller AIR.
//! They do not substitute for the still-missing joint Gate/word LogUps.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_circuit_cpu_integration");
const plan = @import("sha_chip_plan.zig");
const air = @import("sha_caller_stream_air.zig");
const native = @import("sha_caller_stream_native_verifier.zig");
const postcard = @import("interop_postcard");

const M31 = core.fields.m31.M31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Engine = cpu.prove.Internal.Engine;
const Column = prover.pcs.ColumnEvaluation;

fn config() @import("sha_caller_stream_equations.zig").Config {
    var addresses: [56]u32 = undefined;
    for (&addresses, 0..) |*address, i| address.* = @intCast(i + 3);
    return .{ .gate_addresses = addresses, .first_call_id = 17 };
}

fn header() [80]u8 {
    var bytes: [80]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @truncate(17 + 73 * i);
    return bytes;
}

fn statement(bytes: [80]u8) air.Statement {
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

fn fixedRoot(allocator: std.mem.Allocator, s: air.Statement, pcs: core.pcs.config_v2.PcsConfigV2) ![32]u8 {
    var fixed = try air.writeFixed(allocator, s);
    defer fixed.deinit();
    var channel = MC.Channel{};
    native.mixStatement(&channel, s, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    defer Engine.deinit(&scheme, allocator);
    try commit(&scheme, allocator, fixed.values, &channel);
    return scheme.trees.items[0].commitment.root();
}

fn rejects(allocator: std.mem.Allocator, s: air.Statement, pcs: core.pcs.config_v2.PcsConfigV2, root: [32]u8, bytes: []const u8) !void {
    if (native.verifyBytes(allocator, s, pcs, root, bytes)) |_| return error.MutatedShaCallerAccepted else |_| {}
}

test "80-row private caller proof pins digest and namespace in a native verifier" {
    const allocator = std.testing.allocator;
    const bytes = header();
    const s = statement(bytes);
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, air.log_size);
    const key_root = try fixedRoot(allocator, s, pcs);
    var fixed = try air.writeFixed(allocator, s);
    defer fixed.deinit();
    var main = try air.writeMain(allocator, bytes);
    defer main.deinit();
    try air.validateCommittedTrace(s, fixed.values, main.values);

    var channel = MC.Channel{};
    native.mixStatement(&channel, s, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try commit(&scheme, allocator, fixed.values, &channel);
    try std.testing.expectEqualDeep(key_root, scheme.trees.items[0].commitment.root());
    try commit(&scheme, allocator, main.values, &channel);
    const component = air.Component{ .statement = s };
    const handles = [_]prover.air.component_prover.ComponentProver{component.asProverComponent()};
    scheme_owned = false;
    var timer = try std.time.Timer.start();
    var proof = try Engine.prove(allocator, &handles, &channel, scheme, .{ .include_all_preprocessed_columns = true });
    const prove_ns = timer.read();
    defer proof.deinit(allocator);
    const roots = proof.proof.commitment_scheme_proof.commitments.items;
    try std.testing.expectEqual(@as(usize, 3), roots.len);
    try std.testing.expectEqualDeep(key_root, roots[0]);
    var envelope: std.ArrayList(u8) = .empty;
    defer envelope.deinit(allocator);
    try envelope.appendSlice(allocator, &native.statementTag(s, pcs));
    try postcard.serializeProof(H, envelope.writer(allocator), proof.proof);
    timer.reset();
    try native.verifyBytes(allocator, s, pcs, key_root, envelope.items);
    const verify_ns = timer.read();
    std.debug.print("S31_SHA_CALLER_STREAM verified=true active_rows={d} rows={d} fixed={d} main={d} constraints={d} prove_ms={d} verify_ms={d} proof_bytes={d} fri_pow_bits=0 queries=12\n", .{
        air.active_rows,               air.rows,                       air.fixed_width,    air.main_width, air.n_constraints,
        prove_ns / std.time.ns_per_ms, verify_ns / std.time.ns_per_ms, envelope.items.len,
    });

    var changed = s;
    changed.digest[0] ^= 1;
    const wrong_digest_root = try fixedRoot(allocator, changed, pcs);
    try std.testing.expect(!std.mem.eql(u8, &key_root, &wrong_digest_root));
    try std.testing.expectError(error.WrongShaCallerStatementTag, native.verifyBytes(allocator, changed, pcs, wrong_digest_root, envelope.items));
    try std.testing.expectError(error.WrongShaCallerFixedRoot, native.verifyBytes(allocator, s, pcs, wrong_digest_root, envelope.items));
    changed = s;
    changed.config.first_call_id += 1;
    try std.testing.expectError(error.WrongShaCallerStatementTag, native.verifyBytes(allocator, changed, pcs, key_root, envelope.items));
    changed = s;
    changed.config.gate_addresses[0] += 100;
    try std.testing.expectError(error.WrongShaCallerStatementTag, native.verifyBytes(allocator, changed, pcs, key_root, envelope.items));
    try rejects(allocator, s, pcs, key_root, envelope.items[0 .. envelope.items.len - 1]);
}

test "caller trace rejects field alias, changed header/digest, chain, row role, and padding" {
    const allocator = std.testing.allocator;
    const bytes = header();
    const s = statement(bytes);
    var fixed = try air.writeFixed(allocator, s);
    defer fixed.deinit();
    var main = try air.writeMain(allocator, bytes);
    defer main.deinit();
    try air.validateCommittedTrace(s, fixed.values, main.values);

    const bit0 = &@constCast(main.values[6].values)[air.storageIndex(0)];
    const bit8 = &@constCast(main.values[14].values)[air.storageIndex(0)];
    const high = &@constCast(main.values[3].values)[air.storageIndex(0)];
    const save = .{ bit0.*, bit8.*, high.* };
    const inverse = try M31.fromCanonical(65535).inv();
    bit0.* = bit0.*.add(inverse.mul(M31.fromCanonical(256)));
    bit8.* = bit8.*.sub(inverse);
    high.* = high.*.add(M31.one());
    try std.testing.expectError(error.InvalidShaCallerConstraint, air.validateCommittedTrace(s, fixed.values, main.values));
    bit0.* = save[0];
    bit8.* = save[1];
    high.* = save[2];

    const mutations = [_]struct { column: usize, row: usize }{
        .{ .column = 0, .row = 0 }, // header Gate byte
        .{ .column = 2, .row = 20 }, // public digest word
        .{ .column = 4, .row = 28 }, // chained state duplicate
        .{ .column = 2, .row = 60 }, // SHA padding
        .{ .column = 6, .row = 60 }, // unused serialized bit
        .{ .column = 2, .row = 100 }, // zero padding row
    };
    for (mutations) |m| {
        const value = &@constCast(main.values[m.column].values)[air.storageIndex(m.row)];
        const original = value.*;
        value.* = value.*.add(M31.one());
        try std.testing.expectError(error.InvalidShaCallerConstraint, air.validateCommittedTrace(s, fixed.values, main.values));
        value.* = original;
    }
    const role = &@constCast(fixed.values[2].values)[air.storageIndex(60)];
    role.* = M31.zero();
    try std.testing.expectError(error.InvalidShaCallerFixedColumn, air.validateCommittedTrace(s, fixed.values, main.values));
}

test "caller committed-row event roster has 56 Gate limbs and 96 weighted SHA words" {
    const allocator = std.testing.allocator;
    const bytes = header();
    const s = statement(bytes);
    var main = try air.writeMain(allocator, bytes);
    defer main.deinit();
    var gate_count: usize = 0;
    var word_count: usize = 0;
    var total_weight: i32 = 0;
    var seen: [3][32]bool = @splat(@splat(false));
    for (0..air.active_rows) |logical| {
        const row = try air.rowAt(main.values, logical);
        for (air.gateBusEvents(M31, row, logical, s.config)) |maybe_gate| if (maybe_gate) |event| {
            try std.testing.expectEqual(s.config.gate_addresses[gate_count], event.address);
            gate_count += 1;
        };
        for (air.wordBusEvents(M31, row, logical, s.config)) |maybe_word| if (maybe_word) |event| {
            const call_id = event.tuple[1].toU32();
            const address = event.tuple[2].toU32();
            try std.testing.expectEqual(air.word_relation_id, event.tuple[0].toU32());
            try std.testing.expect(!seen[call_id - s.config.first_call_id][address]);
            seen[call_id - s.config.first_call_id][address] = true;
            const expected: i8 = if (address < 8) 2 else if (address < 24) 1 else -1;
            try std.testing.expectEqual(expected, event.weight);
            total_weight += event.weight;
            word_count += 1;
        };
    }
    try std.testing.expectEqual(@as(usize, 56), gate_count);
    try std.testing.expectEqual(@as(usize, 96), word_count);
    try std.testing.expectEqual(@as(i32, 72), total_weight);
    for (seen) |call| for (call) |present| try std.testing.expect(present);
}

test "committed field-alias witness fails the caller AIR quotient" {
    const allocator = std.testing.allocator;
    const bytes = header();
    const s = statement(bytes);
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, air.log_size);
    var fixed = try air.writeFixed(allocator, s);
    defer fixed.deinit();
    var main = try air.writeMain(allocator, bytes);
    defer main.deinit();
    const storage = air.storageIndex(0);
    const inverse = try M31.fromCanonical(65535).inv();
    @constCast(main.values[6].values)[storage] = main.values[6].values[storage].add(inverse.mul(M31.fromCanonical(256)));
    @constCast(main.values[14].values)[storage] = main.values[14].values[storage].sub(inverse);
    @constCast(main.values[3].values)[storage] = main.values[3].values[storage].add(M31.one());
    try std.testing.expectError(error.InvalidShaCallerConstraint, air.validateCommittedTrace(s, fixed.values, main.values));

    var channel = MC.Channel{};
    native.mixStatement(&channel, s, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try commit(&scheme, allocator, fixed.values, &channel);
    try commit(&scheme, allocator, main.values, &channel);
    const component = air.Component{ .statement = s };
    const handles = [_]prover.air.component_prover.ComponentProver{component.asProverComponent()};
    scheme_owned = false;
    if (Engine.prove(allocator, &handles, &channel, scheme, .{ .include_all_preprocessed_columns = true })) |proof_result| {
        var proof = proof_result;
        proof.deinit(allocator);
        return error.FieldAliasAcceptedByCallerAir;
    } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
}

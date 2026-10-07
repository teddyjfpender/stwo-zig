//! Isolated native proof harness for the 64-word SHA-256 schedule.
//! First 16 block words are verifier-owned. Private caller join is pending.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_circuit_cpu_integration");
const sha = @import("s31_sha_provider").compression;
const postcard = @import("interop_postcard");
const air = @import("../air/sha_schedule_direct_air.zig");
const native = @import("../verification/sha_schedule_direct_native_verifier.zig");
const equations = @import("../air/sha_schedule_direct_equations.zig");

const M31 = core.fields.m31.M31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Engine = cpu.prove.Internal.Engine;
const Column = prover.pcs.ColumnEvaluation;

fn fromBlock(block: [64]u8) air.Statement {
    var first: [16]u32 = undefined;
    for (&first, 0..) |*word, t| word.* = std.mem.readInt(u32, block[4 * t ..][0..4], .big);
    return .{ .first_words = first };
}

fn padded(message: []const u8) [64]u8 {
    std.debug.assert(message.len <= 55);
    var block = [_]u8{0} ** 64;
    @memcpy(block[0..message.len], message);
    block[message.len] = 0x80;
    std.mem.writeInt(u64, block[56..64], @as(u64, @intCast(message.len)) * 8, .big);
    return block;
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

fn fixedRoot(allocator: std.mem.Allocator, statement: air.Statement, pcs: core.pcs.config_v2.PcsConfigV2) ![32]u8 {
    var fixed = try air.writeFixed(allocator, statement);
    defer fixed.deinit();
    var channel = MC.Channel{};
    native.mixStatement(&channel, statement, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    defer Engine.deinit(&scheme, allocator);
    try commit(&scheme, allocator, fixed.values, &channel);
    return scheme.trees.items[0].commitment.root();
}

fn proveAndVerify(allocator: std.mem.Allocator, statement: air.Statement, pcs: core.pcs.config_v2.PcsConfigV2) !void {
    const key_root = try fixedRoot(allocator, statement, pcs);
    var fixed = try air.writeFixed(allocator, statement);
    defer fixed.deinit();
    var main = try air.writeMain(allocator, statement);
    defer main.deinit();
    try air.validateCommittedTrace(fixed.values, main.values);
    var channel = MC.Channel{};
    native.mixStatement(&channel, statement, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try commit(&scheme, allocator, fixed.values, &channel);
    try std.testing.expectEqualDeep(key_root, scheme.trees.items[0].commitment.root());
    try commit(&scheme, allocator, main.values, &channel);
    const component = air.Component{};
    const handles = [_]prover.air.component_prover.ComponentProver{component.asProverComponent()};
    scheme_owned = false;
    var timer = try std.time.Timer.start();
    var proof = try Engine.prove(allocator, &handles, &channel, scheme, .{ .include_all_preprocessed_columns = true });
    const prove_ns = timer.read();
    defer proof.deinit(allocator);
    const roots = proof.proof.commitment_scheme_proof.commitments.items;
    try std.testing.expectEqual(@as(usize, 3), roots.len);
    try std.testing.expectEqualDeep(key_root, roots[0]);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try postcard.serializeProof(H, bytes.writer(allocator), proof.proof);
    timer.reset();
    try native.verifyBytes(allocator, statement, pcs, key_root, bytes.items);
    const verify_ns = timer.read();
    std.debug.print("S31_SHA_SCHEDULE_DIRECT verified=true first={x} rows={d} fixed={d} main={d} constraints={d} prove_ms={d} verify_ms={d} proof_bytes={d} fri_pow_bits=0 queries=12\n", .{ statement.first_words[0], air.rows, air.fixed_width, air.main_width, air.n_constraints, prove_ns / std.time.ns_per_ms, verify_ns / std.time.ns_per_ms, bytes.items.len });

    var changed = statement;
    changed.first_words[0] ^= 1;
    if (native.verifyBytes(allocator, changed, pcs, key_root, bytes.items)) |_| return error.ChangedShaScheduleInputAccepted else |_| {}
    const changed_root = try fixedRoot(allocator, changed, pcs);
    try std.testing.expect(!std.mem.eql(u8, &changed_root, &key_root));
    try std.testing.expectError(error.WrongShaScheduleFixedRoot, native.verifyBytes(allocator, changed, pcs, changed_root, bytes.items));
    if (native.verifyBytes(allocator, statement, pcs, key_root, bytes.items[0 .. bytes.items.len - 1])) |_| return error.TruncatedShaScheduleProofAccepted else |_| {}
}

fn provePrivateAndVerify(allocator: std.mem.Allocator, private_inputs: air.Statement, pcs: core.pcs.config_v2.PcsConfigV2) !void {
    var fixed = try air.writeFixedPrivate(allocator);
    defer fixed.deinit();
    var main = try air.writeMain(allocator, private_inputs);
    defer main.deinit();
    try air.validateCommittedTraceMode(.private_input, fixed.values, main.values);
    try std.testing.expectError(error.InvalidShaScheduleConstraint, air.validateCommittedTrace(fixed.values, main.values));
    var channel = MC.Channel{};
    native.mixPrivateStatement(&channel, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try commit(&scheme, allocator, fixed.values, &channel);
    const fixed_root = scheme.trees.items[0].commitment.root();
    try std.testing.expectEqualDeep(try native.expectedPrivateFixedRoot(allocator, pcs), fixed_root);
    try commit(&scheme, allocator, main.values, &channel);
    const component = air.Component{ .boundary_mode = .private_input };
    const handles = [_]prover.air.component_prover.ComponentProver{component.asProverComponent()};
    scheme_owned = false;
    var proof = try Engine.prove(allocator, &handles, &channel, scheme, .{ .include_all_preprocessed_columns = true });
    defer proof.deinit(allocator);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try postcard.serializeProof(H, bytes.writer(allocator), proof.proof);
    try native.verifyPrivateBytes(allocator, pcs, bytes.items);
    if (native.verifyBytes(allocator, private_inputs, pcs, try fixedRoot(allocator, private_inputs, pcs), bytes.items)) |_| return error.PrivateScheduleAcceptedAsPublic else |_| {}
    if (native.verifyPrivateBytes(allocator, pcs, bytes.items[0 .. bytes.items.len - 1])) |_| return error.TruncatedPrivateScheduleProofAccepted else |_| {}
    std.debug.print("S31_SHA_SCHEDULE_PRIVATE verified=true rows={d} fixed={d} main={d} constraints={d} proof_bytes={d} fri_pow_bits=0 queries=12 custody=unjoined\n", .{ air.rows, air.fixed_width, air.main_width, air.n_constraints, bytes.items.len });
}

test "SHA schedule direct AIR proves and natively verifies independent blocks" {
    const allocator = std.testing.allocator;
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, air.log_size);
    for ([_][]const u8{ "", "abc" }) |message| {
        const block = padded(message);
        const statement = fromBlock(block);
        const expected = sha.witness(sha.initial_state, block).schedule;
        const actual = equations.referenceWords(statement.first_words);
        try std.testing.expectEqualDeep(expected, actual);
        if (std.mem.eql(u8, message, "abc"))
            try std.testing.expectEqualSlices(u32, &.{ 0x61626380, 0x000f0000, 0x7da86405, 0x600003c6 }, actual[16..20]);
        try proveAndVerify(allocator, statement, pcs);
    }
    var block: [64]u8 = undefined;
    for (&block, 0..) |*byte, i| byte.* = @truncate(73 * i + 19);
    const random_statement = fromBlock(block);
    try std.testing.expectEqualDeep(sha.witness(sha.initial_state, block).schedule, equations.referenceWords(random_statement.first_words));
    try proveAndVerify(allocator, random_statement, pcs);
}

test "SHA schedule AIR binds predecessor windows, carry range, and first words" {
    const allocator = std.testing.allocator;
    const statement = fromBlock(padded("abc"));
    var fixed = try air.writeFixed(allocator, statement);
    defer fixed.deinit();
    var main = try air.writeMain(allocator, statement);
    defer main.deinit();
    try air.validateCommittedTrace(fixed.values, main.values);
    const cases = [_]struct { column: usize, row: usize, value: M31 }{
        .{ .column = 0, .row = 0, .value = M31.zero() },
        .{ .column = 0, .row = 1, .value = M31.one() },
        .{ .column = 0, .row = 9, .value = M31.one() },
        .{ .column = 0, .row = 14, .value = M31.one() },
        .{ .column = 0, .row = 16, .value = M31.one() },
        .{ .column = 0, .row = 63, .value = M31.one() },
        .{ .column = 0, .row = 120, .value = M31.one() },
        .{ .column = 32, .row = 17, .value = M31.fromCanonical(2) },
        .{ .column = 34, .row = 20, .value = M31.fromCanonical(2) },
    };
    for (cases) |case| {
        const index = air.storageIndex(case.row);
        const old = main.values[case.column].values[index];
        @constCast(main.values[case.column].values)[index] = case.value;
        if (case.value.eql(old)) @constCast(main.values[case.column].values)[index] = old.add(M31.one());
        try std.testing.expectError(error.InvalidShaScheduleConstraint, air.validateCommittedTrace(fixed.values, main.values));
        @constCast(main.values[case.column].values)[index] = old;
    }
    const fixed_index = air.storageIndex(7);
    @constCast(fixed.values[2].values)[fixed_index] = fixed.values[2].values[fixed_index].add(M31.one());
    try std.testing.expectError(error.InvalidShaScheduleConstraint, air.validateCommittedTrace(fixed.values, main.values));
}

test "private schedule fixed root excludes the sixteen witness words" {
    const allocator = std.testing.allocator;
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, air.log_size);
    const a = fromBlock(padded("abc"));
    const b = fromBlock(padded(""));
    var fixed = try air.writeFixedPrivate(allocator);
    defer fixed.deinit();
    var main_a = try air.writeMain(allocator, a);
    defer main_a.deinit();
    var main_b = try air.writeMain(allocator, b);
    defer main_b.deinit();
    try air.validateCommittedTraceMode(.private_input, fixed.values, main_a.values);
    try air.validateCommittedTraceMode(.private_input, fixed.values, main_b.values);
    try std.testing.expect(!main_a.values[24].values[air.storageIndex(0)].eql(main_b.values[24].values[air.storageIndex(0)]));
    for (0..air.rows) |t| {
        const i = air.storageIndex(t);
        try std.testing.expectEqual(@as(u32, @intCast(t)), fixed.values[4].values[i].toU32());
        try std.testing.expect(fixed.values[2].values[i].isZero());
        try std.testing.expect(fixed.values[3].values[i].isZero());
    }
    try provePrivateAndVerify(allocator, a, pcs);
}

test "SHA schedule OODS mask points match quotient-domain predecessor indices" {
    const allocator = std.testing.allocator;
    const component = air.Component{};
    const eval_log = air.max_constraint_log_degree;
    const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
    for (0..domain.size()) |i| {
        const base = domain.at(core.utils.bitReverseIndex(i, eval_log));
        const point: core.circle.CirclePointQM31 = .{ .x = core.fields.qm31.QM31.fromBase(base.x), .y = core.fields.qm31.QM31.fromBase(base.y) };
        var mask = try component.maskPoints(allocator, point, eval_log);
        defer mask.deinitDeep(allocator);
        for ([_]isize{ 0, -2, -7, -15, -16 }, 0..) |offset, k| {
            const j = core.utils.offsetBitReversedCircleDomainIndex(i, air.log_size, eval_log, offset);
            const expected = domain.at(core.utils.bitReverseIndex(j, eval_log));
            const got = mask.items[1][0][k];
            if (!got.eql(.{ .x = core.fields.qm31.QM31.fromBase(expected.x), .y = core.fields.qm31.QM31.fromBase(expected.y) })) {
                std.debug.print("mask mismatch i={d} offset={d} j={d}\n", .{ i, offset, j });
                return error.InvalidShaScheduleMask;
            }
        }
    }
}

test "SHA schedule quotient denominator is constant in bit-reversed blocks" {
    const eval_log = air.max_constraint_log_degree;
    const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
    const trace_coset = core.poly.circle.canonic.CanonicCoset.new(air.log_size).coset();
    const groups = domain.size() / air.rows;
    for (0..groups) |group| {
        const representative = group * air.rows;
        const expected = domain.at(core.utils.bitReverseIndex(representative, eval_log));
        const lookup = domain.at(core.utils.bitReverseIndex(group, eval_log - air.log_size));
        try std.testing.expect(core.constraints.cosetVanishing(M31, trace_coset, expected).eql(core.constraints.cosetVanishing(M31, trace_coset, lookup)));
    }
    for (0..domain.size()) |i| {
        const representative = (i >> @intCast(air.log_size)) << @intCast(air.log_size);
        const point = domain.at(core.utils.bitReverseIndex(i, eval_log));
        const base = domain.at(core.utils.bitReverseIndex(representative, eval_log));
        const actual = core.constraints.cosetVanishing(M31, trace_coset, point);
        const assumed = core.constraints.cosetVanishing(M31, trace_coset, base);
        if (!actual.eql(assumed)) return error.InvalidShaScheduleQuotientDenominator;
    }
}

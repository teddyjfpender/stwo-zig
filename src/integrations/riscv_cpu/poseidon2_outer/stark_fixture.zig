//! Real scoped STARK for the new P2 row and an exact source/public port
//! adapter. This is not the general five-roster Var-bus prover or Ethereum.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const L = @import("layout.zig");
const Row = @import("row.zig");
const M = Core.fields.m31.M31;
pub const S = Core.fields.om31.OM31;
const Point = Core.circle.CirclePoint(S);
const PC = Engine.air.component_prover.ForField(S);
const Domain = Engine.air.accumulation.ForField(S);
const Air = Core.air.components.ForField(S);
const Acc = Core.air.accumulation.ForField(S);
const CP = Core.pcs.ForField(S);
const MC = Core.vcs_lifted.poseidon2_profile.Om31;
const H = MC.MerkleHasher;
const Channel = MC.Channel;
pub const E = Engine.engine.ForField(S).ProverEngine(@import("stwo_cpu_backend").CpuBackend, H, MC, Channel);
pub const Wire = @import("stwo_proof_wire").ForHasher(S, H);
pub const LOG = 4;
pub const ROWS = 1 << LOG;
pub const FIXED = L.FIXED_COLUMNS + 1;
pub const LAST = L.FIXED_COLUMNS;
pub const PORT_BASE = L.MAIN_COLUMNS;
pub const MAIN = PORT_BASE + L.PORTS * 5;
pub const ROOTS = L.CONSTRAINTS + L.PORTS * 5 + 24 + 9;
pub const Mutation = enum { none, x2, x5, port_address, port_extension, fixed_id };
pub const Statement = struct {
    base: [24]M,
    output: [9]M,
    pub fn fixture() Statement {
        var base: [24]M = undefined;
        for (&base, 0..) |*value, i| value.* = M.fromCanonical(@intCast(13 + i * 7));
        var state = base;
        for (&state) |*value| value.* = value.add(M.fromCanonical(ROWS - 1));
        Core.crypto.poseidon2_m31_w24.permute(&state);
        return .{ .base = base, .output = state[0..9].* };
    }
};
pub fn config() !CP.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try Core.fri.ForField(S).FriConfig.init(0, 1, 24) };
}
pub fn fixtureIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/rv64/p2-dedicated-row-public-port-fixture/v1\x00");
    hash.update(&Row.sourceIdentity());
    hash.update(&MC.identity());
    hash.update(@embedFile("stark_fixture.zig"));
    return hash.finalResult();
}
fn mix(channel: *Channel, statement: Statement) !void {
    var words: [32 / 4]u32 = undefined;
    const id = fixtureIdentity();
    for (&words, 0..) |*value, i| value.* = std.mem.readInt(u32, id[4 * i ..][0..4], .little);
    channel.mixU32s(&.{ 0x50325257, 1, LOG, FIXED, MAIN, ROOTS });
    channel.mixU32s(&words);
    for (statement.base) |value| channel.mixU32s(&.{value.v});
    for (statement.output) |value| channel.mixU32s(&.{value.v});
}
const Columns = struct {
    a: std.mem.Allocator,
    values: []Engine.pcs.ColumnEvaluation,
    fn init(a: std.mem.Allocator, count: usize) !Columns {
        const values = try a.alloc(Engine.pcs.ColumnEvaluation, count);
        errdefer a.free(values);
        var made: usize = 0;
        errdefer for (values[0..made]) |v| a.free(v.values);
        for (values) |*value| {
            const data = try a.alloc(M, ROWS);
            @memset(data, M.zero());
            value.* = .{ .log_size = LOG, .values = data };
            made += 1;
        }
        return .{ .a = a, .values = values };
    }
    fn deinit(self: *Columns) void {
        for (self.values) |v| self.a.free(v.values);
        self.a.free(self.values);
        self.* = undefined;
    }
};
fn fixedColumns(a: std.mem.Allocator) !Columns {
    var out = try Columns.init(a, FIXED);
    errdefer out.deinit();
    var counts: [2 + ROWS * 48]u32 = @splat(1);
    counts[0] = 0;
    counts[1] = 0;
    const usage = try L.validateUsage(.{ .counts = &counts, .max_per_wire = 1, .max_total = ROWS * 48 });
    for (0..ROWS) |r| {
        var gate: L.Gate = undefined;
        for (&gate.inputs, &gate.outputs, 0..) |*input, *output, i| {
            input.* = @intCast(2 + 48 * r + i);
            output.* = @intCast(2 + 48 * r + 24 + i);
        }
        const row = try L.fixedForValidated(gate, usage);
        for (row, out.values[0..L.FIXED_COLUMNS]) |value, *column| @constCast(column.values)[r] = value;
        @constCast(out.values[LAST].values)[r] = M.fromCanonical(@intFromBool(r == ROWS - 1));
    }
    return out;
}
fn mainColumns(a: std.mem.Allocator, statement: Statement, fixed: Columns) !Columns {
    var out = try Columns.init(a, MAIN);
    errdefer out.deinit();
    for (0..ROWS) |r| {
        var input = statement.base;
        for (&input) |*v| v.* = v.add(M.fromCanonical(@intCast(r)));
        const row = try Row.fill(input);
        for (row, out.values[0..L.MAIN_COLUMNS]) |value, *column| @constCast(column.values)[r] = value;
        for (0..L.PORTS) |port| {
            @constCast(out.values[PORT_BASE + 5 * port].values)[r] = fixed.values[if (port < 24) L.INPUT_ID + port else L.OUTPUT_ID + port - 24].values[r];
            @constCast(out.values[PORT_BASE + 5 * port + 1].values)[r] = row[if (port < 24) L.INPUT + port else L.OUTPUT + port - 24];
        }
    }
    return out;
}
const Spec = struct {
    statement: Statement,
    const Adapter = Core.air.derive.ForField(S).ComponentAdapter(@This(), PC.ComponentProver, PC.Trace, Domain.DomainEvaluationAccumulator);
    pub fn nConstraints(_: *const @This()) usize {
        return ROOTS;
    }
    // Cubic roots divided by the trace vanishing polynomial have degree<2N.
    pub fn maxConstraintLogDegreeBound(_: *const @This()) u32 {
        return LOG + 1;
    }
    pub fn traceLogDegreeBounds(_: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        const trees = try a.alloc([]u32, 2);
        errdefer a.free(trees);
        trees[0] = try a.alloc(u32, FIXED);
        errdefer a.free(trees[0]);
        trees[1] = try a.alloc(u32, MAIN);
        @memset(trees[0], LOG);
        @memset(trees[1], LOG);
        return Air.TraceLogDegreeBounds.initOwned(trees);
    }
    pub fn preprocessedColumnIndices(_: *const @This(), a: std.mem.Allocator) ![]usize {
        const ids = try a.alloc(usize, FIXED);
        for (ids, 0..) |*id, i| id.* = i;
        return ids;
    }
    pub fn maskPoints(_: *const @This(), a: std.mem.Allocator, point: Point, _: u32) !Air.MaskPoints {
        const trees = try a.alloc([][]Point, 2);
        var made: usize = 0;
        errdefer {
            for (trees[0..made]) |tree| {
                for (tree) |p| a.free(p);
                a.free(tree);
            }
            a.free(trees);
        }
        for (trees, [_]usize{ FIXED, MAIN }) |*tree, count| {
            tree.* = try a.alloc([]Point, count);
            var inner: usize = 0;
            errdefer {
                for (tree.*[0..inner]) |p| a.free(p);
                a.free(tree.*);
            }
            for (tree.*) |*p| {
                p.* = try a.dupe(Point, &.{point});
                inner += 1;
            }
            made += 1;
        }
        return Air.MaskPoints.initOwned(trees);
    }
    fn roots(self: *const @This(), main: *const [MAIN]S, fixed: *const [FIXED]S) ![ROOTS]S {
        var out: [ROOTS]S = undefined;
        out[0..L.CONSTRAINTS].* = try Row.evaluateFor(S, main[0..L.MAIN_COLUMNS]);
        var n: usize = L.CONSTRAINTS;
        for (0..L.PORTS) |port| {
            out[n] = main[PORT_BASE + 5 * port].sub(fixed[if (port < 24) L.INPUT_ID + port else L.OUTPUT_ID + port - 24]);
            n += 1;
            out[n] = main[PORT_BASE + 5 * port + 1].sub(main[if (port < 24) L.INPUT + port else L.OUTPUT + port - 24]);
            n += 1;
            for (2..5) |coordinate| {
                out[n] = main[PORT_BASE + 5 * port + coordinate];
                n += 1;
            }
        }
        const inv = try M.fromCanonical(48).inv();
        for (self.statement.base, 0..) |base, i| {
            const ordinal = fixed[L.INPUT_ID + i].sub(S.fromBase(M.fromCanonical(@intCast(2 + i)))).mulM31(inv);
            out[n] = main[L.INPUT + i].sub(S.fromBase(base).add(ordinal));
            n += 1;
        }
        for (self.statement.output, 0..) |expected, i| {
            out[n] = fixed[LAST].mul(main[L.OUTPUT + i].sub(S.fromBase(expected)));
            n += 1;
        }
        std.debug.assert(n == ROOTS);
        return out;
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const Air.MaskValues, acc: *Acc.PointEvaluationAccumulator, max_log: u32) !void {
        if (max_log < LOG or mask.items.len < 2 or mask.items[0].len != FIXED or mask.items[1].len != MAIN) return error.InvalidPoseidonFixtureMask;
        var main: [MAIN]S = undefined;
        var fixed: [FIXED]S = undefined;
        for (&fixed, mask.items[0]) |*value, column| {
            if (column.len != 1) return error.InvalidPoseidonFixtureMask;
            value.* = column[0];
        }
        for (&main, mask.items[1]) |*value, column| {
            if (column.len != 1) return error.InvalidPoseidonFixtureMask;
            value.* = column[0];
        }
        const inv = try Core.constraints.cosetVanishing(S, Core.poly.circle.canonic.CanonicCoset.new(LOG).coset(), point.repeatedDouble(max_log - LOG)).inv();
        for (try self.roots(&main, &fixed)) |root| acc.accumulate(root.mul(inv));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const PC.Trace, acc: *Domain.DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len < 2 or trace.polys.items[0].len != FIXED or trace.polys.items[1].len != MAIN) return error.InvalidPoseidonFixtureTrace;
        const log = LOG + 1;
        const domain = Core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
        const slots = try acc.columns(acc.allocator, &.{.{ .log_size = log, .n_cols = ROOTS }});
        defer acc.allocator.free(slots);
        const output = &slots[0];
        for (0..domain.size()) |r| {
            var main: [MAIN]S = undefined;
            var fixed: [FIXED]S = undefined;
            for (&fixed, trace.polys.items[0]) |*v, poly| v.* = S.fromBase(try poly.valueAtLiftingPosition(log, r));
            for (&main, trace.polys.items[1]) |*v, poly| v.* = S.fromBase(try poly.valueAtLiftingPosition(log, r));
            const point = domain.at(Core.utils.bitReverseIndex(r, log));
            const inv = try Core.constraints.cosetVanishing(S, Core.poly.circle.canonic.CanonicCoset.new(LOG).coset(), .{ .x = S.fromBase(point.x), .y = S.fromBase(point.y) }).inv();
            var value = S.zero();
            for (try self.roots(&main, &fixed), 0..) |root, i| value = value.add(root.mul(output.random_coeff_powers[ROOTS - 1 - i]));
            output.accumulate(r, value.mul(inv));
        }
    }
};
pub fn trustedFixedRoot(a: std.mem.Allocator, statement: Statement) !H.Hash {
    var fixed = try fixedColumns(a);
    defer fixed.deinit();
    const cfg = try config();
    var channel = Channel.init();
    cfg.mixInto(&channel);
    try mix(&channel, statement);
    var scheme = try E.init(a, cfg);
    defer scheme.deinit(a);
    try scheme.commit(a, fixed.values, &channel);
    return scheme.trees.items[0].root();
}
pub fn produce(a: std.mem.Allocator, mutation: Mutation) !E.ExtendedProof {
    const statement = Statement.fixture();
    var fixed = try fixedColumns(a);
    defer fixed.deinit();
    var main = try mainColumns(a, statement, fixed);
    defer main.deinit();
    switch (mutation) {
        .none => {},
        .x2 => @constCast(main.values[L.TEMPORARY].values)[3] = main.values[L.TEMPORARY].values[3].add(M.one()),
        .x5 => @constCast(main.values[L.TEMPORARY + 1].values)[3] = main.values[L.TEMPORARY + 1].values[3].add(M.one()),
        .port_address => @constCast(main.values[PORT_BASE + 5 * 7].values)[3] = main.values[PORT_BASE + 5 * 7].values[3].add(M.one()),
        .port_extension => @constCast(main.values[PORT_BASE + 5 * 31 + 2].values)[3] = M.one(),
        .fixed_id => @constCast(fixed.values[L.INPUT_ID].values)[3] = fixed.values[L.INPUT_ID].values[3].add(M.one()),
    }
    const cfg = try config();
    var channel = Channel.init();
    cfg.mixInto(&channel);
    try mix(&channel, statement);
    var scheme = try E.init(a, cfg);
    var owned = true;
    errdefer if (owned) scheme.deinit(a);
    try scheme.commit(a, fixed.values, &channel);
    try scheme.commit(a, main.values, &channel);
    const spec = Spec{ .statement = statement };
    const components = [_]PC.ComponentProver{Spec.Adapter.asProverComponent(&spec)};
    owned = false;
    return E.prove(a, &components, &channel, scheme, .{});
}
/// Proof ownership is consumed on both success and error, just like the core
/// receiver. All geometry, source FIXED and statement are independently pinned.
pub fn verify(a: std.mem.Allocator, proof: Core.proof.ForField(S).StarkProof(H), statement: Statement) !void {
    var owned = proof;
    var owns = true;
    defer if (owns) owned.deinit(a);
    if (proof.commitment_scheme_proof.commitments.items.len != 3) return error.InvalidPoseidonFixtureShape;
    const expected = try trustedFixedRoot(a, statement);
    if (!std.mem.eql(u8, &expected, &proof.commitment_scheme_proof.commitments.items[0])) return error.UntrustedPoseidonFixedCommitment;
    const cfg = try config();
    var channel = Channel.init();
    cfg.mixInto(&channel);
    try mix(&channel, statement);
    var receiver = try CP.verifier.CommitmentSchemeVerifier(H, MC).init(a, cfg);
    defer receiver.deinit(a);
    const fixed_logs = [_]u32{LOG} ** FIXED;
    const main_logs = [_]u32{LOG} ** MAIN;
    try receiver.commit(a, proof.commitment_scheme_proof.commitments.items[0], &fixed_logs, &channel);
    try receiver.commit(a, proof.commitment_scheme_proof.commitments.items[1], &main_logs, &channel);
    const spec = Spec{ .statement = statement };
    owns = false;
    try Core.verifier.ForField(S).verify(H, MC, a, &.{Spec.Adapter.asVerifierComponent(&spec)}, &channel, &receiver, proof);
}
test "dedicated Poseidon row and exact public port adapter has real OM31 PCS FRI proof" {
    const a = std.testing.allocator;
    var proof = produce(a, .none) catch |err| {
        std.debug.print("P2_ROW_PRODUCER_ERROR {s}\n", .{@errorName(err)});
        return err;
    };
    defer proof.deinit(a);
    const bytes = try Wire.encodeProofBytesBinary(a, proof.proof);
    defer a.free(bytes);
    verify(a, try Wire.decodeProofBytesBinary(a, bytes), Statement.fixture()) catch |err| {
        std.debug.print("P2_ROW_RECEIVER_ERROR {s}\n", .{@errorName(err)});
        return err;
    };
    std.debug.print("\nP2_DEDICATED_REAL_STARK rows={} main={} fixed={} roots={} bytes={} fresh_scope=false\n", .{ ROWS, MAIN, FIXED, ROOTS, bytes.len });
}

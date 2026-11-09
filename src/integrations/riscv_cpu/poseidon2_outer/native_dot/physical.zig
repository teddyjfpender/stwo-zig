//! Standalone physical dot gate only. The receiver closes Var debt against an
//! independently supplied typed external statement, never against this MAIN.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const A = @import("../authority.zig");
const K = @import("physical_key.zig");
const R = @import("row.zig");
const W = @import("witness.zig");
const C = @import("component.zig");
const M = A.M;
const Q = A.Q;
const O = A.O;
const Wire = @import("stwo_proof_wire").ForHasher(O, A.H);
const Air = Core.air.components.ForField(O);
const PC = Engine.air.component_prover.ForField(O);
const LogUp = Engine.air.logup_columns.ForField(O);
const MAGIC = "OPDOTP01";
const HEADER = 104;
pub const CLAIM_OFFSET = 72;
pub const Mutation = enum { none, accumulator, empty_result, prefix, auxiliary };
fn begin(key: *const K.Key) A.MC.Channel {
    var channel = A.MC.Channel.init();
    key.profile.config().mixInto(&channel);
    var words: [16]u32 = undefined;
    for (words[0..8], 0..) |*v, i| v.* = std.mem.readInt(u32, key.identity[4 * i ..][0..4], .little);
    for (words[8..16], 0..) |*v, i| v.* = std.mem.readInt(u32, key.statement[4 * i ..][0..4], .little);
    channel.mixU32s(&.{ 0x444f5431, R.MAIN, R.FIXED, R.INTER, key.dot_log, key.auxiliary_log });
    channel.mixU32s(&words);
    return channel;
}
pub fn expectedDebt(key: *const K.Key, elements: C.Elements) !O {
    var sum = O.zero();
    for (key.external) |entry| {
        const coordinates = entry.binding.value.toM31Array();
        const port = R.PortFor(M){ .numerator = if (entry.count < 0) M.fromCanonical(@intCast(-entry.count)).neg() else M.fromCanonical(@intCast(entry.count)), .tuple = .{ M.fromCanonical(@import("stwo_circuit_frontend").common.component_list.GATE_RELATION_ID), M.fromCanonical(entry.binding.id), coordinates[0], coordinates[1], coordinates[2], coordinates[3] } };
        const denominator = R.denominator(O, .{ .numerator = O.fromBase(port.numerator), .tuple = blk: {
            var tuple: [6]O = undefined;
            for (&tuple, port.tuple) |*v, f| v.* = O.fromBase(f);
            break :blk tuple;
        } }, elements.z, elements.powers);
        sum = sum.add(O.fromBase(port.numerator).mul(try denominator.inv()));
    }
    return sum;
}
fn makeMain(a: std.mem.Allocator, key: *const K.Key, variables: []const Q) !A.Columns {
    var iterator = try W.Iterator.init(&key.source, variables);
    var columns = try K.columns(a, 1, key.dot_log, key.auxiliary_log);
    errdefer columns.deinit();
    var i: usize = 0;
    while (try iterator.next()) |row| : (i += 1) {
        for (row, 0..) |v, j| columns.put(j, K.physical(i, key.dot_log), v);
    }
    for (0..@as(usize, 1) << @intCast(key.auxiliary_log)) |r| columns.put(R.MAIN, K.physical(r, key.auxiliary_log), K.auxiliaryValue(r));
    return columns;
}
const Fractions = struct {
    main: []const A.Col,
    fixed: []const A.Col,
    elements: C.Elements,
    fn fill(self: @This(), row: usize, out: []LogUp.Fraction) !void {
        var main: [R.MAIN]M = undefined;
        var fixed: [R.FIXED]M = undefined;
        for (&main, self.main[0..R.MAIN]) |*v, c| v.* = c.values[row];
        for (&fixed, self.fixed[0..R.FIXED]) |*v, c| v.* = c.values[row];
        const ports = R.portsFor(M, &main, &fixed);
        for (out, 0..) |*fraction, i| {
            const p = ports[2 * i];
            const q = ports[2 * i + 1];
            var a: O = self.elements.z.neg();
            var b = a;
            for (p.tuple, q.tuple, self.elements.powers) |x, y, power| {
                a = a.add(power.mulM31(x));
                b = b.add(power.mulM31(y));
            }
            fraction.* = .{ .numerator = b.mulM31(p.numerator).add(a.mulM31(q.numerator)), .denominator = a.mul(b) };
        }
    }
};
pub fn prove(a: std.mem.Allocator, key: *const K.Key, variables: []const Q, mutation: Mutation) ![]u8 {
    if (!Engine.host_budget_allocator.SharedHostBudget.isAllocator(a)) return error.NativeDotPhysicalBudgetRequired;
    var main = try makeMain(a, key, variables);
    defer main.deinit();
    if (mutation == .accumulator) main.put(R.ACC + 3, K.physical(1, key.dot_log), main.values[R.ACC + 3].values[K.physical(1, key.dot_log)].add(M.one()));
    if (mutation == .empty_result) main.put(R.ACC + 3, K.physical(2, key.dot_log), main.values[R.ACC + 3].values[K.physical(2, key.dot_log)].add(M.one()));
    if (mutation == .auxiliary) main.put(R.MAIN, 1, main.values[R.MAIN].values[1].add(M.one()));
    var channel = begin(key);
    var scheme = try A.E.init(a, key.profile.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(1);
    try scheme.trees.ensureUnusedCapacity(a, 1);
    scheme.trees.appendAssumeCapacity(key.fixed_tree.retainShared());
    A.MC.mixRoot(&channel, key.fixed_root);
    try scheme.commitBorrowedStreamingWithRecorder(a, main.values, 64, null, &channel);
    const elements = C.Elements.init(channel.drawSecureFelt(), channel.drawSecureFelt());
    var interaction = try LogUp.build(a, key.dot_log, 3, Fractions{ .main = main.values, .fixed = key.fixed.values, .elements = elements }, Fractions.fill);
    defer @import("stwo_circuit_frontend").witness.trace.freeColumns(a, interaction.columns);
    // Local fraction generation was the last raw MAIN consumer. The compact
    // PCS already owns coefficients; do not carry the wide input into proving.
    main.deinit();
    main = .{ .allocator = a, .values = &.{} };
    if (mutation == .empty_result and !interaction.claimed_sum.eql(try expectedDebt(key, elements))) return error.NativeDotMutationDebtNotClosed;
    if (mutation == .prefix) @constCast(interaction.columns[16].values)[K.physical(2, key.dot_log)] = interaction.columns[16].values[K.physical(2, key.dot_log)].add(M.one());
    channel.mixFelts(&.{interaction.claimed_sum});
    try scheme.commitBorrowedStreamingWithRecorder(a, interaction.columns, 64, null, &channel);
    @import("stwo_circuit_frontend").witness.trace.freeColumns(a, interaction.columns);
    interaction.columns = &.{};
    const dot = C.Component{ .key = key, .elements = elements, .claim = interaction.claimed_sum, .mode = .dot };
    const auxiliary = C.Component{ .key = key, .elements = elements, .claim = O.zero(), .mode = .auxiliary };
    const components = [_]PC.ComponentProver{ C.Component.Adapter.asProverComponent(&dot), C.Component.Adapter.asProverComponent(&auxiliary) };
    owns = false;
    var produced = try A.E.prove(a, &components, &channel, scheme, .{});
    defer produced.deinit(a);
    const body = try Wire.encodeProofBytesBinary(a, produced.proof);
    defer a.free(body);
    const bytes = try a.alloc(u8, HEADER + body.len);
    @memcpy(bytes[0..8], MAGIC);
    @memcpy(bytes[8..40], &key.identity);
    @memcpy(bytes[40..72], &key.statement);
    for (interaction.claimed_sum.toM31Array(), 0..) |v, i| std.mem.writeInt(u32, bytes[CLAIM_OFFSET + 4 * i ..][0..4], v.v, .little);
    @memcpy(bytes[HEADER..], body);
    return bytes;
}
pub const PendingDebt = struct { external_var_debt_closed: bool = false };
/// Falsification control only: establishes the fragment's PCS/AIR validity,
/// explicitly leaves debt pending, and cannot run in a production build.
pub fn checkStarkFragmentForTest(a: std.mem.Allocator, key: *const K.Key, encoded: []const u8) !PendingDebt {
    if (!@import("builtin").is_test) return error.NativeDotTestOnly;
    try verifyImpl(a, key, encoded, false);
    return .{};
}
pub fn verify(a: std.mem.Allocator, key: *const K.Key, encoded: []const u8) !void {
    return verifyImpl(a, key, encoded, true);
}
fn verifyImpl(a: std.mem.Allocator, key: *const K.Key, encoded: []const u8, require_external_debt: bool) !void {
    if (!Engine.host_budget_allocator.SharedHostBudget.isAllocator(a)) return error.NativeDotPhysicalBudgetRequired;
    if (encoded.len <= HEADER or !std.mem.eql(u8, encoded[0..8], MAGIC)) return error.NativeDotPhysicalEnvelope;
    if (!std.mem.eql(u8, encoded[8..40], &key.identity)) return error.NativeDotPhysicalAuthority;
    if (!std.mem.eql(u8, encoded[40..72], &key.statement)) return error.NativeDotPhysicalStatement;
    var coordinates: [8]M = undefined;
    for (&coordinates, 0..) |*v, i| {
        const raw = std.mem.readInt(u32, encoded[CLAIM_OFFSET + 4 * i ..][0..4], .little);
        if (raw >= Core.fields.m31.Modulus) return error.NativeDotNoncanonicalClaim;
        v.* = M.fromCanonical(raw);
    }
    const claim = O.fromM31Array(coordinates);
    var proof = try Wire.decodeProofBytesBinary(a, encoded[HEADER..]);
    var owned = true;
    defer if (owned) proof.deinit(a);
    const pcs = &proof.commitment_scheme_proof;
    if (pcs.commitments.items.len != 4 or pcs.revision_config != null or !std.meta.eql(pcs.config, key.profile.config())) return error.NativeDotPhysicalShape;
    if (!std.mem.eql(u8, &pcs.commitments.items[0], &key.fixed_root)) return error.NativeDotPhysicalFixedRoot;
    var channel = begin(key);
    var receiver = try Core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(A.H, A.MC).init(a, key.profile.config());
    defer receiver.deinit(a);
    const fixed_logs = try key.treeLogs(a, 0);
    defer a.free(fixed_logs);
    const main_logs = try key.treeLogs(a, 1);
    defer a.free(main_logs);
    const inter_logs = try key.treeLogs(a, 2);
    defer a.free(inter_logs);
    try receiver.commit(a, key.fixed_root, fixed_logs, &channel);
    try receiver.commit(a, pcs.commitments.items[1], main_logs, &channel);
    const elements = C.Elements.init(channel.drawSecureFelt(), channel.drawSecureFelt());
    if (require_external_debt and !claim.eql(try expectedDebt(key, elements))) return error.NativeDotExternalVarDebt;
    channel.mixFelts(&.{claim});
    try receiver.commit(a, pcs.commitments.items[2], inter_logs, &channel);
    const dot = C.Component{ .key = key, .elements = elements, .claim = claim, .mode = .dot };
    const auxiliary = C.Component{ .key = key, .elements = elements, .claim = O.zero(), .mode = .auxiliary };
    const components = [_]Air.Component{ C.Component.Adapter.asVerifierComponent(&dot), C.Component.Adapter.asVerifierComponent(&auxiliary) };
    owned = false;
    try Core.verifier.ForField(O).verify(A.H, A.MC, a, &components, &channel, &receiver, proof);
}

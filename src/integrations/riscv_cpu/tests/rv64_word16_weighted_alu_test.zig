//! Complete weighted truth source inside the unchanged closed CPU verifier.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const CPU = @import("../word16/cpu.zig");
const F = @import("../word16/weighted_alu_fixture.zig");
const Sources = @import("../word16/cpu_sources.zig");
const Protocol = @import("../word16/cpu_protocol.zig");
const Components = @import("../word16/cpu_components.zig").Components;
const A = front.rv64_air.word16_v1.alu_experiment;
const physical = front.rv64_air.witness.physical;
const T = @import("../rv64_distributed_v1/manifest.zig").T;
const Backend = @import("stwo_cpu_backend").CpuBackend;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
fn materials(alu_log: u32) !CPU.Materials {
    return CPU.Materials.init(a, .{ .base = F.BASE, .words = &F.WORDS }, F.geometry(7, alu_log));
}
test "weighted ALU one EQ fact serves 127 native BEQs and fresh unchanged verifier" {
    const public = try F.expected(7);
    const records = try F.capture(a, public);
    defer a.free(records);
    var small = try materials(5);
    defer small.deinit();
    var source = try Sources.Source.initDeduplicated(a, &small, public, records);
    defer source.deinit();
    try std.testing.expectEqual(@as(usize, 1), source.alu.?.fact_count);
    try std.testing.expectEqual(public.steps, source.alu.?.function_mass);
    try std.testing.expectEqual(@as(u32, 127), source.alu.?.metadata[0].multiplicity());
    var range_mass: u64 = 0;
    for (source.alu.?.range16_counts) |count| range_mass += count;
    try std.testing.expectEqual(@as(u64, 20 * 32), range_mass);
    var weighted = try CPU.produceDeduplicated(a, &small, public, records, false);
    defer weighted.deinit(a);
    var scalar = try CPU.produceDeduplicated(a, &small, public, records, true);
    defer scalar.deinit(a);
    try std.testing.expectEqualSlices(u8, weighted.bytes, scalar.bytes);
    var independent = try materials(5);
    defer independent.deinit();
    try CPU.verifyClosed(a, &independent, public, weighted);
    var baseline = try materials(7);
    defer baseline.deinit();
    var unit = try CPU.produce(a, &baseline, public, records, false);
    defer unit.deinit(a);
    try CPU.verifyClosed(a, &baseline, public, unit);
    var wrong = public;
    wrong.final_registers[1] = 1;
    if (CPU.verifyClosed(a, &independent, wrong, weighted)) |_| return error.AcceptedWrongWeightedBoundary else |_| {}
}
const Attack = enum { multiplicity, missing_fact, balanced_range_debt };
fn falseProof(setup: *const CPU.Materials, public: CPU.Public, records: []const front.rv64.machine.Retirement, attack: Attack) !void {
    var source = try Sources.Source.initDeduplicated(a, setup, public, records);
    defer source.deinit();
    const n = source.alu.?.size();
    const first = physical(0, setup.geometry.alu_log);
    if (attack == .multiplicity) source.alu.?.main[(A.lookup.MAIN - 1) * n + first] = M.fromCanonical(public.steps - 1);
    if (attack == .missing_fact) {
        const padding = physical(1, setup.geometry.alu_log);
        for (0..A.lookup.MAIN) |column| source.alu.?.main[column * n + first] = source.alu.?.main[column * n + padding];
    }
    var scheme = try T.Scheme.init(a, Protocol.P.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = Protocol.P.Channel{};
    try Protocol.mixLocal(&channel, setup, public);
    try setup.appendFixed(a, &scheme, &channel);
    const main = try source.columns(a, 1);
    defer a.free(main);
    try scheme.commitBorrowedStreaming(a, main, 8, &channel);
    source.releaseMain();
    const draw = Protocol.drawProfile(&channel, null, .alu_binary_v2);
    var claims = try source.generate(draw.cpu, draw.and_);
    var alu = source.alu_claims.?;
    if (attack == .balanced_range_debt) {
        claims.cpu.range16 = claims.cpu.range16.add(Q.one());
        alu.range16 = alu.range16.sub(Q.one());
    }
    try claims.validateProfile(.local_binary, .alu_binary_v2, alu);
    Protocol.mixClaimsProfile(&channel, claims, .alu_binary_v2, alu);
    const interaction = try source.columns(a, 2);
    defer a.free(interaction);
    try scheme.commitBorrowedStreaming(a, interaction, 8, &channel);
    var components = try Components.initWithAlu(setup, public, draw, claims, alu, false);
    const handles = try components.provers(a);
    defer a.free(handles);
    owns = false;
    var proof = try engine.prove.prove(Backend, T.P.Hasher, T.P.MerkleChannel, a, handles, &channel, scheme);
    defer proof.deinit(a);
}
test "weighted ALU physical engine rejects wrong multiplicity missing fact and balanced RANGE debt" {
    const public = try F.expected(7);
    const records = try F.capture(a, public);
    defer a.free(records);
    var setup = try materials(5);
    defer setup.deinit();
    for (std.enums.values(Attack)) |attack| try std.testing.expectError(error.ConstraintsNotSatisfied, falseProof(&setup, public, records, attack));
}
test "weighted ALU native wrong weight fails closure and copied weights remain phase owned" {
    const public = try F.expected(7);
    const records = try F.capture(a, public);
    defer a.free(records);
    var setup = try materials(5);
    defer setup.deinit();
    var source = try Sources.Source.initDeduplicated(a, &setup, public, records);
    defer source.deinit();
    source.alu.?.function_mass -= 1;
    source.alu.?.metadata[0].multiplicity_words[0] -= 1;
    source.releaseMain();
    var channel = Protocol.P.Channel{};
    try Protocol.mixLocal(&channel, &setup, public);
    const draw = Protocol.drawProfile(&channel, null, .alu_binary_v2);
    try std.testing.expectError(error.UnclosedThinCpuFunction, source.generate(draw.cpu, draw.and_));
}

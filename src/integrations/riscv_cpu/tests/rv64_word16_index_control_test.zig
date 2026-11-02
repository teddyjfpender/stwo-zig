//! Indexed PC execution proof. All register/function/range obligations close.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const front = @import("stwo_riscv_frontend");
const air = front.rv64_air;
const I = air.word16_index_control;
const W = air.word16_cpu;
const P = @import("../word16_index/proof.zig");
const Native = @import("../word16/alu_cpu_fixture_data.zig");
const T = @import("../rv64_distributed_v1/manifest.zig").T;
const Backend = @import("stwo_cpu_backend").CpuBackend;
const M = core.fields.m31.M31;
const Q = air.evaluation.Q;
const a = std.testing.allocator;
fn materials(native: *const Native.Fixture) !P.Materials {
    return P.Materials.init(a, .{ .base = 4096, .words = native.words.items }, .{ .cpu_log = 6, .alu_log = 6, .binary_log = 5 });
}
fn pairsFor(m: *const P.Materials, state: W.public.Public) [2]P.Pair {
    return .{ .{ .id = m.authority.idForPc(state.initial_pc) catch unreachable, .pc = state.initial_pc }, .{ .id = m.authority.idForPc(state.final_pc) catch unreachable, .pc = state.final_pc } };
}
fn reject(m: *const P.Materials, state: W.public.Public, pairs: []const P.Pair, proof: P.Encoded) !void {
    if (P.verify(a, m, state, pairs, proof)) |_| return error.ExpectedIndexProofRejection else |_| {}
}
test "indexed40 CPU closes real ALU binary branches REG and two ROM projections" {
    var native = try Native.Fixture.init(a);
    defer native.deinit();
    var m = try materials(&native);
    defer m.deinit();
    const pairs = pairsFor(&m, native.public);
    var source = try P.Sources.Source.init(a, &m, native.public, native.records.items, &pairs);
    defer source.deinit();
    try std.testing.expectEqual(@as(usize, 0), source.cpu.base.main.len);
    try std.testing.expectEqual(@as(usize, 40 * 64), source.cpu.main.len);
    var proof = try P.produce(a, &m, native.public, native.records.items, &pairs);
    defer proof.deinit(a);
    var receiver = try materials(&native);
    defer receiver.deinit();
    try P.verify(a, &receiver, native.public, &pairs, proof);
    var forged = proof;
    forged.claims.map = forged.claims.map.add(Q.one());
    forged.claims.known_map = forged.claims.known_map.sub(Q.one());
    try reject(&receiver, native.public, &pairs, forged);
    forged = proof;
    forged.claims.base.cpu.rom = forged.claims.base.cpu.rom.add(Q.one());
    forged.claims.base.rom = forged.claims.base.rom.sub(Q.one());
    try reject(&receiver, native.public, &pairs, forged);
}
const Attack = enum { none, current_id, next_id, operand, false_map, padded_map };
fn attempt(m: *const P.Materials, native: *const Native.Fixture, pairs: []const P.Pair, attack: Attack) !P.Encoded {
    var source = try P.Sources.Source.init(a, m, native.public, native.records.items, pairs);
    defer source.deinit();
    const n = source.cpu.base.size();
    const pos = W.layout.physical(0, m.geometry.cpu_log);
    switch (attack) {
        .current_id => source.cpu.main[pos] = M.fromCanonical(@intCast(m.authority.addresses.len)),
        .next_id => source.cpu.main[n + pos] = M.fromCanonical(@intCast(m.authority.addresses.len)),
        .operand => source.cpu.main[(W.layout.main.a - 6) * n + pos] = source.cpu.main[(W.layout.main.a - 6) * n + pos].add(M.one()),
        .false_map => {
            const at = W.layout.physical(0, 5);
            for (1..5) |c| source.map_main[c * 32 + at] = M.zero();
        },
        .padded_map => {
            const size = @as(usize, 1) << @intCast(m.authority.log_size);
            try std.testing.expect(m.authority.edges.len < size);
            const first = W.layout.physical(m.authority.first_rows[@intCast(pairs[0].id)], m.authority.log_size);
            const pad = W.layout.physical(size - 1, m.authority.log_size);
            const value = source.map_counts[first];
            source.map_counts[first] = 0;
            source.map_counts[pad] += value;
            source.rom.main[size + first] = M.zero();
            source.rom.main[size + pad] = M.fromCanonical(@intCast(value));
        },
        .none => {},
    }
    var scheme = try T.Scheme.init(a, T.P.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = T.P.Channel{};
    try P.Protocol.mix(&channel, m, native.public, pairs);
    try m.appendFixed(a, &scheme, &channel);
    const main = try source.columns(a, 1);
    defer a.free(main);
    try scheme.commitBorrowedStreaming(a, main, 8, &channel);
    source.releaseMain();
    const ch = P.Protocol.draw(&channel);
    const claims = try source.generate(ch);
    if (attack == .false_map) {
        // Coherently change the public query pin AND recompute its exact wrong
        // inverse/prefix. Keep the balanced physical claim: membership is false,
        // so the prefix boundary must fail even for this colluding producer.
        for (1..5) |c| source.map_roster[0][c] = M.zero();
        var sum = Q.zero();
        const fc = P.Sources.mapFunction(ch.map);
        for (source.map_roster, 0..) |row, logical| {
            var d = fc.offset;
            for (fc.coefficients, row[0..13]) |coefficient, value| d = d.sub(coefficient.mulM31(value));
            const inverse = try d.inv();
            sum = sum.add(inverse.mulM31(row[13]));
            const at = W.layout.physical(logical, 5);
            for (inverse.toM31Array(), 0..) |value, c| source.map_interaction[c * 32 + at] = value;
            for (sum.toM31Array(), 0..) |value, c| source.map_interaction[(4 + c) * 32 + at] = value;
        }
        for (sum.toM31Array(), 0..) |value, c| for (0..32) |row| {
            source.map_interaction[(4 + c) * 32 + row] = source.map_interaction[(4 + c) * 32 + row].sub(value);
        };
    }
    P.Protocol.mixClaims(&channel, claims);
    const inter = try source.columns(a, 2);
    defer a.free(inter);
    try scheme.commitBorrowedStreaming(a, inter, 8, &channel);
    var components = try P.Components.init(m, source.cpu.public, ch, claims, &source.map_roster);
    const handles = try components.provers(a);
    defer a.free(handles);
    owns = false;
    var proof = try engine.prove.prove(Backend, T.P.Hasher, T.P.MerkleChannel, a, handles, &channel, scheme);
    defer proof.deinit(a);
    return .{ .bytes = try wire.encodeProofBytesBinary(a, proof), .claims = claims };
}
test "indexed physical proving rejects wrong IDs operands and first PC padded map alias" {
    var native = try Native.Fixture.init(a);
    defer native.deinit();
    var m = try materials(&native);
    defer m.deinit();
    const pairs = pairsFor(&m, native.public);
    for ([_]Attack{ .current_id, .next_id, .operand, .false_map }) |attack| try std.testing.expectError(error.ConstraintsNotSatisfied, attempt(&m, &native, &pairs, attack));
    var padded = try attempt(&m, &native, &pairs, .padded_map);
    defer padded.deinit(a);
    try P.verify(a, &m, native.public, &pairs, padded);
}
fn oneStep(memory: *front.rv64.memory.Memory, pc: u64) !struct { state: W.public.Public, record: front.rv64.machine.Retirement } {
    var cpu = front.rv64.machine.Cpu.init(pc, 0);
    cpu.regs[1] = 0xffff000180007fff;
    cpu.regs[2] = 0x7fffffff8000ffff;
    const before = cpu.regs;
    const record = try cpu.step(memory);
    var clocks: [32]u32 = @splat(0);
    for ([_]u5{ record.rs1, record.rs2, record.rd }, 0..) |id, slot| if (id != 0) {
        clocks[id] = @intCast(slot + 1);
    };
    return .{ .state = .{ .steps = 1, .initial_pc = pc, .final_pc = cpu.pc, .initial_registers = before, .final_registers = cpu.regs, .register_clocks = clocks }, .record = record };
}
test "indexed proof preserves sparse high64 PCs and binds even invalid raw program bytes" {
    const high: u64 = 0x8000000000000404;
    const word = Native.reg(7, 3, 1, 2, false, false);
    const words = [_]u32{ 0, word, word };
    const addresses = [_]u64{ 1024, 1028, high };
    var memory = front.rv64.memory.Memory.init(a, .{});
    defer memory.deinit();
    for (addresses, words) |pc, raw| {
        try memory.map(.{ .start = pc, .size = 4, .permissions = .{ .read = true, .execute = true } });
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, raw, .little);
        try memory.initialize(pc, &bytes);
    }
    const native = try oneStep(&memory, high);
    var m = try P.Materials.init(a, .{ .base = 1024, .words = &words, .addresses = &addresses }, .{ .cpu_log = 5 });
    defer m.deinit();
    const pairs = [_]P.Pair{ .{ .id = try m.authority.idForPc(1024), .pc = 1024 }, .{ .id = try m.authority.idForPc(high), .pc = high } };
    var proof = try P.produce(a, &m, native.state, &.{native.record}, &pairs);
    defer proof.deinit(a);
    try P.verify(a, &m, native.state, &pairs, proof);
    var wrong = native.state;
    wrong.initial_pc = high & 0x0000ffffffffffff;
    wrong.final_pc = wrong.initial_pc + 4;
    try reject(&m, wrong, &pairs, proof);
    var altered = words;
    altered[0] = 0xffffffff;
    var other = try P.Materials.init(a, .{ .base = 1024, .words = &altered, .addresses = &addresses }, .{ .cpu_log = 5 });
    defer other.deinit();
    try std.testing.expectEqualSlices(u8, &m.fixed_root.value, &other.fixed_root.value);
    try std.testing.expect(!std.mem.eql(u8, &m.authority.identity, &other.authority.identity));
    try reject(&other, native.state, &pairs, proof);
}
test "indexed IDs above u16 and full64 wrapping static exits physically verify" {
    const words = try a.alloc(u32, 65538);
    defer a.free(words);
    @memset(words, 0);
    words[words.len - 1] = Native.reg(7, 3, 1, 2, false, false);
    const pc: u64 = 1024 + 4 * (words.len - 1);
    var memory = front.rv64.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 1024, .size = words.len * 4, .permissions = .{ .read = true, .execute = true } });
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, words[words.len - 1], .little);
    try memory.initialize(pc, &bytes);
    const native = try oneStep(&memory, pc);
    var m = try P.Materials.init(a, .{ .base = 1024, .words = words }, .{ .cpu_log = 5 });
    defer m.deinit();
    try std.testing.expect((try m.authority.idForPc(pc)) > 65535);
    var proof = try P.produce(a, &m, native.state, &.{native.record}, &.{});
    defer proof.deinit(a);
    try P.verify(a, &m, native.state, &.{}, proof);
    const top = std.math.maxInt(u64) - 3;
    try memory.map(.{ .start = top, .size = 4, .permissions = .{ .read = true, .execute = true } });
    try memory.initialize(top, &bytes);
    const wrap = try oneStep(&memory, top);
    var top_m = try P.Materials.init(a, .{ .base = top, .words = &.{words[words.len - 1]} }, .{ .cpu_log = 5 });
    defer top_m.deinit();
    try std.testing.expectEqual(@as(u64, 0), wrap.state.final_pc);
    var top_proof = try P.produce(a, &top_m, wrap.state, &.{wrap.record}, &.{});
    defer top_proof.deinit(a);
    try P.verify(a, &top_m, wrap.state, &.{}, top_proof);
    try std.testing.expectError(error.NonfetchableIndexAddress, top_m.authority.executableId(0));
    var unmapped = wrap.state;
    unmapped.final_pc = 0x1234567800000000;
    try std.testing.expectError(error.UnknownIndexAddress, P.verify(a, &top_m, unmapped, &.{}, top_proof));
}
fn dense(x: u32) Q {
    return Q.fromPartialEvals(.{ air.evaluation.q(x), air.evaluation.q(x + 1), air.evaluation.q(x + 3), air.evaluation.q(x + 7) });
}
fn fill(out: []Q, t: Q, seed: u32) void {
    for (out, 0..) |*v, i| v.* = dense(seed + @as(u32, @intCast(2 * i))).add(t.mul(dense(seed + @as(u32, @intCast(2 * i + 1)))));
}
test "indexed CPU49 and dual ROM7 polynomials are dense QM31 degree at most three" {
    var native = try Native.Fixture.init(a);
    defer native.deinit();
    var m = try materials(&native);
    defer m.deinit();
    const public = try I.equations.resolve(&m.authority, native.public, 6);
    var channel = T.P.Channel{};
    const ch = P.Protocol.draw(&channel);
    const claims = W.public.Claims{ .register = dense(1), .function = dense(2), .rom = dense(3), .range16 = dense(4), .range8 = dense(5) };
    var cpu_samples: [5][49]Q = undefined;
    var rom_samples: [5][7]Q = undefined;
    var fixed: [3]Q = undefined;
    var main: [40]Q = undefined;
    var prior_main: [40]Q = undefined;
    var current: [56]Q = undefined;
    var previous: [56]Q = undefined;
    var rom_fixed: [23]Q = undefined;
    var rom_main: [2]Q = undefined;
    var rom_current: [16]Q = undefined;
    var rom_previous: [16]Q = undefined;
    for (0..5) |i| {
        const t = air.evaluation.q(@intCast(i));
        fill(&fixed, t, 1);
        fill(&main, t, 100);
        fill(&prior_main, t, 200);
        fill(&current, t, 300);
        fill(&previous, t, 400);
        fill(&rom_fixed, t, 500);
        fill(&rom_main, t, 600);
        fill(&rom_current, t, 700);
        fill(&rom_previous, t, 800);
        var sink = air.evaluation.Sink{ .values = &cpu_samples[i] };
        I.equations.emitFor(Q, &fixed, &main, &prior_main, &current, &previous, public, claims, ch.data, ch.rom, &sink);
        try std.testing.expectEqual(@as(usize, 49), sink.count);
        var rom_sink = air.evaluation.Sink{ .values = &rom_samples[i] };
        I.equations.emitRomFor(Q, &rom_fixed, &rom_main, &rom_current, &rom_previous, .{ dense(8), dense(9) }, ch.rom, ch.map, &rom_sink);
        try std.testing.expectEqual(@as(usize, 7), rom_sink.count);
    }
    for (0..49) |i| try std.testing.expect(cpu_samples[4][i].sub(cpu_samples[3][i].mul(air.evaluation.q(4))).add(cpu_samples[2][i].mul(air.evaluation.q(6))).sub(cpu_samples[1][i].mul(air.evaluation.q(4))).add(cpu_samples[0][i]).isZero());
    for (0..7) |i| try std.testing.expect(rom_samples[4][i].sub(rom_samples[3][i].mul(air.evaluation.q(4))).add(rom_samples[2][i].mul(air.evaluation.q(6))).sub(rom_samples[1][i].mul(air.evaluation.q(4))).add(rom_samples[0][i]).isZero());
}
fn allocationCase(allocator: std.mem.Allocator, m: *const P.Materials, native: *const Native.Fixture, pairs: []const P.Pair) !void {
    var source = try P.Sources.Source.init(allocator, m, native.public, native.records.items, pairs);
    defer source.deinit();
}
test "indexed40 composite source unwinds every allocation failure" {
    var native = try Native.Fixture.init(a);
    defer native.deinit();
    var m = try materials(&native);
    defer m.deinit();
    const pairs = pairsFor(&m, native.public);
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{ &m, &native, &pairs });
}

fn withPool(m: *const P.Materials, native: *const Native.Fixture, pairs: []const P.Pair, workers: usize, reference: bool) !P.Encoded {
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 256 * 1024 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    return if (reference) P.produceReference(a, m, native.public, native.records.items, pairs) else P.produce(a, m, native.public, native.records.items, pairs);
}
test "indexed packed16 and scalar oracle exact proof bytes match pooled disjoint ranges" {
    var native = try Native.Fixture.init(a);
    defer native.deinit();
    // 8192 evaluation rows force two real row jobs on the four-worker pool;
    // this is not the small-domain serial fast path.
    var m = try P.Materials.init(a, .{ .base = 4096, .words = native.words.items }, .{ .cpu_log = 12, .alu_log = 6, .binary_log = 5 });
    defer m.deinit();
    const pairs = pairsFor(&m, native.public);
    var scalar = try withPool(&m, &native, &pairs, 1, true);
    defer scalar.deinit(a);
    var serial = try withPool(&m, &native, &pairs, 1, false);
    defer serial.deinit(a);
    var parallel = try withPool(&m, &native, &pairs, 4, false);
    defer parallel.deinit(a);
    try std.testing.expectEqualSlices(u8, scalar.bytes, serial.bytes);
    try std.testing.expectEqualSlices(u8, serial.bytes, parallel.bytes);
    try P.verify(a, &m, native.public, &pairs, parallel);
}
fn packedFields(comptime F: type, comptime n: usize, scalar: *[16][n]Q, seed: u32) [n]F {
    var out: [n]F = undefined;
    for (0..n) |column| {
        var lanes: [16]Q = undefined;
        for (0..16) |lane| {
            const value: u32 = @intCast((@as(u64, seed) + column * 103 + lane * 997) % core.fields.m31.Modulus);
            if (F == air.evaluation.PackedBase) {
                const base = M.fromCanonical(if (lane == 0) core.fields.m31.Modulus - 1 else value);
                lanes[lane] = Q.fromBase(base);
            } else lanes[lane] = dense(value + 7);
            scalar[lane][column] = lanes[lane];
        }
        if (F == air.evaluation.PackedBase) {
            var bases: [16]M = undefined;
            for (lanes, &bases) |v, *b| b.* = v.toM31Array()[0];
            out[column] = F.fromLanes(bases);
        } else out[column] = F.fromLanes(lanes);
    }
    return out;
}
test "indexed all CPU and map residuals match sixteen base and extension scalar lanes" {
    var native = try Native.Fixture.init(a);
    defer native.deinit();
    var m = try materials(&native);
    defer m.deinit();
    const public = try I.equations.resolve(&m.authority, native.public, 6);
    var channel = T.P.Channel{};
    const ch = P.Protocol.draw(&channel);
    const claims = W.public.Claims{ .register = dense(1), .function = dense(2), .rom = dense(3), .range16 = dense(4), .range8 = dense(5) };
    inline for (.{ air.evaluation.PackedBase, air.evaluation.PackedSecure }) |F| {
        var sf: [16][3]Q = undefined;
        var sm: [16][40]Q = undefined;
        var spm: [16][40]Q = undefined;
        var sc: [16][56]Q = undefined;
        var sp: [16][56]Q = undefined;
        const fixed = packedFields(F, 3, &sf, 1);
        const main = packedFields(F, 40, &sm, 100);
        const prior = packedFields(F, 40, &spm, 200);
        const current = packedFields(F, 56, &sc, 300);
        const previous = packedFields(F, 56, &sp, 400);
        var packed_values: [49]air.evaluation.PackedSecure = undefined;
        var sink = air.evaluation.PackedSink{ .values = &packed_values };
        I.equations.emitFor(F, &fixed, &main, &prior, &current, &previous, public, claims, ch.data, ch.rom, &sink);
        try std.testing.expectEqual(@as(usize, 49), sink.count);
        for (0..16) |lane| {
            var reference: [49]Q = undefined;
            var scalar = air.evaluation.Sink{ .values = &reference };
            I.equations.emitFor(Q, &sf[lane], &sm[lane], &spm[lane], &sc[lane], &sp[lane], public, claims, ch.data, ch.rom, &scalar);
            for (packed_values, reference) |actual, expected| try std.testing.expect(actual.lane(lane).eql(expected));
        }
        var srf: [16][23]Q = undefined;
        var srm: [16][2]Q = undefined;
        var src: [16][16]Q = undefined;
        var srp: [16][16]Q = undefined;
        const rf = packedFields(F, 23, &srf, 500);
        const rm = packedFields(F, 2, &srm, 600);
        const rc = packedFields(F, 16, &src, 700);
        const rp = packedFields(F, 16, &srp, 800);
        var residuals: [7]air.evaluation.PackedSecure = undefined;
        var rs = air.evaluation.PackedSink{ .values = &residuals };
        I.equations.emitRomFor(F, &rf, &rm, &rc, &rp, .{ dense(8), dense(9) }, ch.rom, ch.map, &rs);
        for (0..16) |lane| {
            var reference: [7]Q = undefined;
            var scalar = air.evaluation.Sink{ .values = &reference };
            I.equations.emitRomFor(Q, &srf[lane], &srm[lane], &src[lane], &srp[lane], .{ dense(8), dense(9) }, ch.rom, ch.map, &scalar);
            for (residuals, reference) |actual, expected| try std.testing.expect(actual.lane(lane).eql(expected));
        }
    }
}

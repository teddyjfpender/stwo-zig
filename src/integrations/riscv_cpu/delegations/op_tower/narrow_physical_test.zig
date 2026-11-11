//! Closed-admission composite narrow Miller-line correctness fixture. The input
//! frontier and32-step arithmetic DAG share one PCS/proof and one SSA closure.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const Backend = @import("stwo_cpu_backend").CpuBackend;
fn Qualification(comptime Q: type) type {
    return struct {
        const T = front.rv64_air.crypto.bn254_tower;
        const N = T.narrow;
        const S = N.source;
        const Eq = N.equations;
        const LF = Eq.LayoutForField(.frontier, Q);
        const LA = Eq.LayoutForField(.arithmetic, Q);
        const M = core.fields.m31.M31;

        const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
        const MC = if (Q == core.fields.qm31.QM31) core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel else @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig").MC;
        const Channel = if (Q == core.fields.qm31.QM31) core.channel.blake2s.Blake2sChannel else @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig").Channel;
        const Scheme = engine.pcs.ForField(Q).CommitmentSchemeProver(Backend, H, MC);
        const Verifier = core.pcs.ForField(Q).verifier.CommitmentSchemeVerifier(H, MC);
        const wire = @import("stwo_proof_wire").ForField(Q);
        const a = std.testing.allocator;
        const FL = 8;
        const AL = 15;
        const FIRST_ID = 7;
        const degree = front.rv64_air.evaluation.extensionDegree(Q);
        const CLAIM_BYTES = 4 * degree;
        const FRAME_BYTES = 4 * CLAIM_BYTES;
        const CONFIG = core.pcs.ForField(Q).PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 12 } };
        const CF = N.ForField(Q).Component(.frontier);
        const CA = N.ForField(Q).Component(.arithmetic);
        fn mix(channel: *Channel) void {
            CONFIG.mixInto(channel);
            channel.mixU32s(&.{ 0x4f50544e, 1, @intCast(T.execution.TAG), FL, AL, FIRST_ID, 1, LF.MAIN, LA.MAIN, LF.INTERACTION, LA.INTERACTION, LF.CONSTRAINTS, LA.CONSTRAINTS, N.micro.G.carry_bits, @intCast(N.micro.G.carry_offset) });
        }
        fn draw(channel: *Channel) Eq.ChallengesFor(Q) {
            return .{ .bytes = channel.drawSecureFelt(), .carries = channel.drawSecureFelt(), .ssa = front.rv64_air.crypto.curves.equations.WireFor(Q).draw(channel), .wire = front.rv64_air.crypto.curves.equations.WireFor(Q).draw(channel) };
        }
        fn columns(storage: []const M, log: u32, out: []engine.pcs.ColumnEvaluation) void {
            const n = @as(usize, 1) << @intCast(log);
            for (out, 0..) |*column, index| column.* = .{ .log_size = log, .values = storage[index * n ..][0..n] };
        }
        fn logs(comptime left: usize, comptime right: usize) [left + right]u32 {
            return ([_]u32{FL} ** left) ++ ([_]u32{AL} ** right);
        }
        fn input() N.trace.Input {
            var out: N.trace.Input = @splat(0);
            for (0..12) |index| out[index] = (@as(u256, 1) << 240) + @as(u256, 0x102030405060708) * (index + 1);
            out[12] = 1;
            out[18] = 1;
            out[19] = 1;
            return out;
        }
        fn externalTuple(kind: u32, id: u32, label: usize, bytes: [32]u8) [35]Q {
            var tuple: [35]Q = undefined;
            tuple[0] = Q.fromBase(M.fromCanonical(kind));
            tuple[1] = Q.fromBase(M.fromCanonical(id));
            tuple[2] = Q.fromBase(M.fromCanonical(@intCast(label)));
            for (tuple[3..], bytes) |*value, byte| value.* = Q.fromBase(M.fromCanonical(byte));
            return tuple;
        }
        fn expected(ch: Eq.ChallengesFor(Q), packet: *const N.trace.Input, id: u32, corrupt: bool) !Q {
            var total = Q.zero();
            for (0..20) |coord| {
                var bytes: [32]u8 = undefined;
                std.mem.writeInt(u256, &bytes, packet[coord], .little);
                total = total.sub(try ch.wire.denominator(&externalTuple(12, id, coord, bytes)).inv());
            }
            // A*1=A, independent of the narrow/wide arithmetic implementations.
            for (0..12) |coord| {
                var bytes: [32]u8 = undefined;
                std.mem.writeInt(u256, &bytes, packet[coord], .little);
                if (corrupt and coord == 0) bytes[0] ^= 1;
                total = total.add(try ch.wire.denominator(&externalTuple(12, id, 20 + coord, bytes)).inv());
            }
            return total;
        }
        fn componentF(ch: Eq.ChallengesFor(Q), claim: Eq.ClaimsFor(Q)) CF {
            return .{ .log_size = FL, .public = .{ .calls = 1, .first_id = FIRST_ID }, .claims = claim, .challenges = ch };
        }
        fn componentA(ch: Eq.ChallengesFor(Q), claim: Eq.ClaimsFor(Q)) CA {
            return .{ .log_size = AL, .public = .{ .calls = 1, .first_id = FIRST_ID }, .claims = claim, .challenges = ch, .offsets = .{ S.FIXED, LF.MAIN, LF.INTERACTION } };
        }
        fn encodeClaim(destination: []u8, q: Q) void {
            for (q.toM31Array(), 0..) |value, index| std.mem.writeInt(u32, destination[4 * index ..][0..4], value.v, .little);
        }
        fn decodeClaim(source: []const u8) !Q {
            var values: [degree]M = undefined;
            for (&values, 0..) |*value, index| {
                const integer = std.mem.readInt(u32, source[4 * index ..][0..4], .little);
                if (integer >= core.fields.m31.Modulus) return error.NoncanonicalTowerClaim;
                value.* = M.fromCanonical(integer);
            }
            return Q.fromM31Array(values);
        }
        fn receive(encoded: []const u8, packet: *const N.trace.Input, mutation: u8) !void {
            if (encoded.len < FRAME_BYTES) return error.InvalidTowerFrame;
            const claims = [_]Q{ try decodeClaim(encoded[0..CLAIM_BYTES]), try decodeClaim(encoded[CLAIM_BYTES .. 2 * CLAIM_BYTES]), try decodeClaim(encoded[2 * CLAIM_BYTES .. 3 * CLAIM_BYTES]), try decodeClaim(encoded[3 * CLAIM_BYTES .. 4 * CLAIM_BYTES]) };
            if (!claims[0].add(claims[2]).isZero()) return error.TowerSsaNotClosed;
            var proof = try wire.decodeProofBytesBinary(a, encoded[FRAME_BYTES..]);
            var owns = true;
            defer if (owns) proof.deinit(a);
            const roots = proof.commitment_scheme_proof.commitments.items;
            if (roots.len != 4) return error.InvalidTowerProofShape;
            const ff = try N.trace.fixed(a, .frontier, FL);
            defer a.free(ff);
            const af = try N.trace.fixed(a, .arithmetic, AL);
            defer a.free(af);
            var fixed_columns: [2 * S.FIXED]engine.pcs.ColumnEvaluation = undefined;
            columns(ff, FL, fixed_columns[0..S.FIXED]);
            columns(af, AL, fixed_columns[S.FIXED..]);
            var setup = try Scheme.init(a, CONFIG);
            defer setup.deinit(a);
            var scratch = if (Q == core.fields.qm31.QM31) Channel{} else Channel.init();
            try setup.commit(a, &fixed_columns, &scratch);
            var fresh = try setup.roots(a);
            defer fresh.deinit(a);
            if (!std.mem.eql(u8, &roots[0], &fresh.items[0])) return error.InvalidTowerFixedRoot;
            var verifier = try Verifier.init(a, CONFIG);
            defer verifier.deinit(a);
            var channel = if (Q == core.fields.qm31.QM31) Channel{} else Channel.init();
            mix(&channel);
            try verifier.commit(a, roots[0], &logs(S.FIXED, S.FIXED), &channel);
            try verifier.commit(a, roots[1], &logs(LF.MAIN, LA.MAIN), &channel);
            const ch = draw(&channel);
            if (!claims[1].add(claims[3]).eql(try expected(ch, packet, if (mutation == 1) FIRST_ID + 1 else FIRST_ID, mutation == 2))) return error.TowerWireNotClosed;
            channel.mixFelts(&claims);
            try verifier.commit(a, roots[2], &logs(LF.INTERACTION, LA.INTERACTION), &channel);
            if (mutation == 3) proof.commitment_scheme_proof.sampled_values.items[1][LF.MAIN + N.micro.RESULT][0] = proof.commitment_scheme_proof.sampled_values.items[1][LF.MAIN + N.micro.RESULT][0].add(Q.one());
            const f = componentF(ch, .{ .ssa = claims[0], .wire = claims[1] });
            const ar = componentA(ch, .{ .ssa = claims[2], .wire = claims[3] });
            const components = [_]core.air.components.ForField(Q).Component{ f.asVerifierComponent(), ar.asVerifierComponent() };
            owns = false;
            try core.verifier.ForField(Q).verify(H, MC, a, &components, &channel, &verifier, proof);
        }
        pub fn run() !void {
            const packet = input();
            var fs = try N.trace.SourceForField(.frontier, Q).init(a, &.{packet}, FIRST_ID, FL);
            defer fs.deinit();
            var ars = try N.trace.SourceForField(.arithmetic, Q).init(a, &.{packet}, FIRST_ID, AL);
            defer ars.deinit();
            var fixed_columns: [2 * S.FIXED]engine.pcs.ColumnEvaluation = undefined;
            var main_columns: [LF.MAIN + LA.MAIN]engine.pcs.ColumnEvaluation = undefined;
            var inter_columns: [LF.INTERACTION + LA.INTERACTION]engine.pcs.ColumnEvaluation = undefined;
            columns(fs.fixed, FL, fixed_columns[0..S.FIXED]);
            columns(ars.fixed, AL, fixed_columns[S.FIXED..]);
            columns(fs.main, FL, main_columns[0..LF.MAIN]);
            columns(ars.main, AL, main_columns[LF.MAIN..]);
            var scheme = try Scheme.init(a, CONFIG);
            var owns = true;
            defer if (owns) scheme.deinit(a);
            var channel = if (Q == core.fields.qm31.QM31) Channel{} else Channel.init();
            mix(&channel);
            try scheme.commit(a, &fixed_columns, &channel);
            try scheme.commit(a, &main_columns, &channel);
            const ch = draw(&channel);
            const fc = try fs.generateInteraction(ch);
            const ac = try ars.generateInteraction(ch);
            try std.testing.expect(fc.ssa.add(ac.ssa).isZero());
            try std.testing.expect(fc.wire.add(ac.wire).eql(try expected(ch, &packet, FIRST_ID, false)));
            const claims = [_]Q{ fc.ssa, fc.wire, ac.ssa, ac.wire };
            channel.mixFelts(&claims);
            columns(fs.interaction, FL, inter_columns[0..LF.INTERACTION]);
            columns(ars.interaction, AL, inter_columns[LF.INTERACTION..]);
            try scheme.commit(a, &inter_columns, &channel);
            const f = componentF(ch, fc);
            const ar = componentA(ch, ac);
            const components = [_]engine.air.component_prover.ForField(Q).ComponentProver{ f.asProverComponent(), ar.asProverComponent() };
            owns = false;
            var proof = try engine.prove.ForField(Q).prove(Backend, H, MC, a, &components, &channel, scheme);
            defer proof.deinit(a);
            const bytes = try wire.encodeProofBytesBinary(a, proof);
            defer a.free(bytes);
            const framed = try a.alloc(u8, FRAME_BYTES + bytes.len);
            defer a.free(framed);
            for (claims, 0..) |claim, index| encodeClaim(framed[CLAIM_BYTES * index ..][0..CLAIM_BYTES], claim);
            @memcpy(framed[FRAME_BYTES..], bytes);
            try receive(framed, &packet, 0);
            for (1..4) |mutation| try std.testing.expect(std.meta.isError(receive(framed, &packet, @intCast(mutation))));
            framed[0] ^= 1;
            try std.testing.expectError(error.TowerSsaNotClosed, receive(framed, &packet, 0));
            std.debug.print("OP_TOWER_NARROW_PHYSICAL toy_profile=true field_degree={} proof_bytes={} arithmetic={}/{} frontier={}/{} degree=3\n", .{ degree, framed.len, LA.MAIN, LA.INTERACTION, LF.MAIN, LF.INTERACTION });
        }
    };
}
test "narrow OP Miller-line composite proof closes SSA and fresh Wire authority" {
    try Qualification(core.fields.qm31.QM31).run();
}
test "narrow OP Miller-line OM31 composite proof closes SSA and fresh Wire authority" {
    try Qualification(core.fields.om31.OM31).run();
}

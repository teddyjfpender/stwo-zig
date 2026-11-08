//! Full PCS/FRI qualification for the experimental named Poseidon2 profile.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
pub fn ForField(comptime Secure: type) type {
    return ForFieldVersion(Secure, 1);
}
pub fn ForFieldVersion(comptime Secure: type, comptime version: u8) type {
    return struct {
        const S = Secure;
        const M = core.fields.m31.M31;
        const Point = core.circle.CirclePoint(S);
        const A = std.testing.allocator;
        const P = engine.air.component_prover.ForField(S);
        const D = engine.air.accumulation.ForField(S);
        const K = core.air.components.ForField(S);
        const Acc = core.air.accumulation.ForField(S);
        const PCS = engine.pcs.ForField(S);
        const CP = core.pcs.ForField(S);
        const CPU = @import("stwo_cpu_backend").CpuBackend;
        const MC = if (version == 1) core.vcs_lifted.poseidon2_profile.ForField(S) else core.vcs_lifted.poseidon2_profile.ForFieldV2(S);
        const H = MC.MerkleHasher;
        const C = MC.Channel;
        const E = engine.engine.ForField(S).ProverEngine(CPU, H, MC, C);
        const Air = struct {
            log: u32 = 4,
            main_index: usize = 0,
            const Adapter = core.air.derive.ForField(S).ComponentAdapter(@This(), P.ComponentProver, P.Trace, D.DomainEvaluationAccumulator);
            pub fn nConstraints(_: *const @This()) usize {
                return 2;
            }
            pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
                return self.log + 1;
            }
            pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !K.TraceLogDegreeBounds {
                const trees = try a.alloc([]u32, 2);
                errdefer a.free(trees);
                trees[0] = try a.alloc(u32, 0);
                errdefer a.free(trees[0]);
                trees[1] = try a.dupe(u32, &.{self.log});
                return K.TraceLogDegreeBounds.initOwned(trees);
            }
            pub fn maskPoints(_: *const @This(), a: std.mem.Allocator, point: Point, _: u32) !K.MaskPoints {
                const trees = try a.alloc([][]Point, 2);
                errdefer a.free(trees);
                trees[0] = try a.alloc([]Point, 0);
                errdefer a.free(trees[0]);
                trees[1] = try a.alloc([]Point, 1);
                errdefer a.free(trees[1]);
                trees[1][0] = try a.dupe(Point, &.{point});
                return K.MaskPoints.initOwned(trees);
            }
            pub fn preprocessedColumnIndices(_: *const @This(), a: std.mem.Allocator) ![]usize {
                return a.alloc(usize, 0);
            }
            fn quotient(self: *const @This(), point: Point, v: S) !S {
                const z = core.constraints.cosetVanishing(S, core.poly.circle.canonic.CanonicCoset.new(self.log).coset(), point);
                return v.mul(v.sub(S.one())).div(z);
            }
            pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const K.MaskValues, acc: *Acc.PointEvaluationAccumulator, max_log: u32) !void {
                if (max_log < self.log) return error.InvalidStructure;
                const native_point = point.repeatedDouble(max_log - self.log);
                const q = try self.quotient(native_point, mask.items[1][self.main_index][0]);
                acc.accumulate(q);
                acc.accumulate(q);
            }
            pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const P.Trace, acc: *D.DomainEvaluationAccumulator) !void {
                const poly = trace.polys.items[1][self.main_index].coefficients orelse return error.MissingCoefficients;
                const log = self.log + 1;
                const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
                var col = try engine.secure_column.SecureColumnByCoordsFor(S).uninitialized(acc.allocator, domain.size());
                defer col.deinit(acc.allocator);
                for (0..domain.size()) |i| {
                    const p = domain.at(core.utils.bitReverseIndex(i, log));
                    const point = Point{ .x = S.fromBase(p.x), .y = S.fromBase(p.y) };
                    col.set(i, try self.quotient(point, poly.evalAtPointFor(S, point)));
                }
                try acc.accumulateColumn(log, &col);
                try acc.accumulateColumn(log, &col);
            }
        };
        fn configWithFold(fold: u32) !CP.PcsConfig {
            var c = CP.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.ForField(S).FriConfig.init(0, 1, 12) };
            c.fri_config.fold_step = fold;
            return c;
        }
        fn produce(a: std.mem.Allocator) !E.ExtendedProof {
            return produceTrace(a, false);
        }
        fn produceTrace(a: std.mem.Allocator, invalid: bool) !E.ExtendedProof {
            return produceTraceWithFold(a, invalid, 1);
        }
        pub fn produceTraceWithFold(a: std.mem.Allocator, invalid: bool, fold: u32) !E.ExtendedProof {
            return produceTraceWithStorage(a, invalid, fold, false, null);
        }
        pub fn produceTraceWithStorage(a: std.mem.Allocator, invalid: bool, fold: u32, compact: bool, byte_limit: ?usize) !E.ExtendedProof {
            const cfg = try configWithFold(fold);
            var channel = C.init();
            cfg.mixInto(&channel);
            var scheme = try E.init(a, cfg);
            scheme.compact_polynomial_storage = compact;
            scheme.compact_polynomial_min_log_size = 0;
            scheme.wide_quotient_group_byte_limit = byte_limit;
            var owns = true;
            errdefer if (owns) scheme.deinit(a);
            try scheme.commit(a, &.{}, &channel);
            var values: [16]M = undefined;
            for (&values, 0..) |*v, i| v.* = M.fromCanonical(@intCast((i * i + i / 3) & 1));
            if (invalid) values[3] = M.fromCanonical(2);
            try scheme.commit(a, &.{.{ .log_size = 4, .values = &values }}, &channel);
            const air = Air{};
            const components = [_]P.ComponentProver{Air.Adapter.asProverComponent(&air)};
            owns = false;
            return E.prove(a, &components, &channel, scheme, .{});
        }
        fn verify(a: std.mem.Allocator, proof: core.proof.ForField(S).StarkProof(H)) !void {
            return verifyFold(a, proof, 1);
        }
        pub fn verifyFold(a: std.mem.Allocator, proof: core.proof.ForField(S).StarkProof(H), fold: u32) !void {
            var owned = proof;
            var owns = true;
            defer if (owns) owned.deinit(a);
            if (proof.commitment_scheme_proof.commitments.items.len != 3) return error.InvalidStructure;
            const cfg = try configWithFold(fold);
            var channel = C.init();
            cfg.mixInto(&channel);
            var receiver = try CP.verifier.CommitmentSchemeVerifier(H, MC).init(a, cfg);
            defer receiver.deinit(a);
            try receiver.commit(a, proof.commitment_scheme_proof.commitments.items[0], &.{}, &channel);
            try receiver.commit(a, proof.commitment_scheme_proof.commitments.items[1], &.{4}, &channel);
            const air = Air{};
            const component = Air.Adapter.asVerifierComponent(&air);
            owns = false;
            try core.verifier.ForField(S).verify(H, MC, a, &.{component}, &channel, &receiver, proof);
        }

        const Wire = @import("stwo_proof_wire").ForHasher(S, H);
        test "Poseidon2 field-selected real STARK roundtrips through new binary and JSON receivers" {
            for ([_]u32{ 1, 4 }) |fold| {
                var p = try produceTraceWithFold(A, false, fold);
                defer p.deinit(A);
                for ([_]bool{ false, true }) |binary| {
                    const bytes = if (binary) try Wire.encodeProofBytesBinary(A, p.proof) else try Wire.encodeProofBytes(A, p.proof);
                    defer A.free(bytes);
                    const decoded = if (binary) try Wire.decodeProofBytesBinary(A, bytes) else try Wire.decodeProofBytes(A, bytes);
                    try verifyFold(A, decoded, fold);
                    std.debug.print("P2_REAL_STARK version={d} degree={d} fold={d} binary={} bytes={d} accepted\n", .{ version, @typeInfo(@TypeOf(S.zero().toM31Array())).array.len, fold, binary, bytes.len });
                }
                const encoded = try Wire.encodeProofBytesBinary(A, p.proof);
                defer A.free(encoded);
                try std.testing.expectError(error.UnsupportedBinaryVersion, @import("stwo_proof_wire").ForField(S).decodeProofBytesBinary(A, encoded));
                const Other = if (version == 1) core.vcs_lifted.poseidon2_profile.ForFieldV2(S) else core.vcs_lifted.poseidon2_profile.ForField(S);
                try std.testing.expectError(error.UnsupportedBinaryVersion, @import("stwo_proof_wire").ForHasher(S, Other.MerkleHasher).decodeProofBytesBinary(A, encoded));
                var arena = std.heap.ArenaAllocator.init(A);
                defer arena.deinit();
                var wire = try Wire.proofToWire(arena.allocator(), p.proof);
                std.mem.writeInt(u32, wire.commitments[1][0..4], core.fields.m31.Modulus, .little);
                try std.testing.expectError(error.NonCanonicalPoseidonDigest, Wire.wireToProof(A, wire));
            }
        }
        test "Poseidon2 field-selected fresh receiver rejects altered canonical root and opening" {
            for ([_]bool{ false, true }) |root| {
                var p = try produce(A);
                defer p.aux.deinit(A);
                if (root) {
                    p.proof.commitment_scheme_proof.commitments.items[1][0] ^= 1;
                } else {
                    const v = &p.proof.commitment_scheme_proof.queried_values.items[1][0][0];
                    v.* = v.add(M.one());
                }
                verify(A, p.proof) catch |err| {
                    std.debug.print("P2_REAL_REJECT root={} {s}\n", .{ root, @errorName(err) });
                    continue;
                };
                return error.ExpectedRejection;
            }
        }
    };
}
test {
    _ = ForField(core.fields.qm31.QM31);
    _ = ForField(core.fields.om31.OM31);
    _ = ForFieldVersion(core.fields.qm31.QM31, 2);
    _ = ForFieldVersion(core.fields.om31.OM31, 2);
}

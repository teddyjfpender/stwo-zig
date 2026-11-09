//! Closed BYTE-local GKR physical gate. All public inputs/output expectations,
//! instance dimensions and source scope come from receiver-owned parameters.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = A.crypto.bn254_dense;
const N = @import("native.zig");
const C = @import("component.zig");
const Proj = @import("projection.zig");
const Q = N.Q;
const M = N.M;
const Backend = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const Protocol = @import("../../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const MC = Protocol.MC;
const Channel = Protocol.Channel;
const Scheme = engine.pcs.ForField(Q).CommitmentSchemeProver(Backend, H, MC);
const Verifier = core.pcs.ForField(Q).verifier.CommitmentSchemeVerifier(H, MC);
const Wire = @import("stwo_proof_wire").ForField(Q);
const CONFIG = core.pcs.ForField(Q).PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 12 } };
fn mixReceipt(channel: *Channel, digest: core.crypto.poseidon2_m31_sponge.Digest) void {
    var words: [9]u32 = undefined;
    for (&words, 0..) |*x, i| x.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
fn columns(data: []const M, out: []engine.pcs.ColumnEvaluation) void {
    for (out, 0..) |*v, i| v.* = .{ .log_size = 8, .values = data[i * 256 ..][0..256] };
}
fn Qualification(comptime kind: D.spec.Kind) type {
    return struct {
        const R = D.row.Layout(kind);
        const Trace = D.fixture_trace.Trace(kind);
        const Component = C.Component(kind);
        const INPUT = blk: {
            var a: [D.spec.inputs(kind)]u256 = undefined;
            for (&a, 0..) |*x, i| x.* = if (i % 3 == 0) std.math.maxInt(u256) else if (i % 3 == 1) D.spec.B.BN254_P - 1 else 19 * i + 3;
            break :blk a;
        };
        fn expected() [12]u256 {
            return D.reference(INPUT[0..12].*, if (kind == .square) INPUT[0..12].* else INPUT[12..24].*);
        }
        fn mix(channel: *Channel, input: *const [D.spec.inputs(kind)]u256, out: [12]u256) void {
            CONFIG.mixInto(channel);
            channel.mixU32s(&.{ 0x444c474b, 1, @intFromEnum(kind), 8, 12, R.MAIN, 24, 17, 355 });
            var words: [8]u32 = undefined;
            const id = N.statement(kind, input, out);
            for (&words, 0..) |*x, i| x.* = std.mem.readInt(u32, id[4 * i ..][0..4], .little);
            channel.mixU32s(&words);
        }
        fn scope(input: *const [D.spec.inputs(kind)]u256, out: [12]u256, fixed: [32]u8, main: [32]u8) N.Scope {
            return .{ .statement = N.statement(kind, input, out), .fixed = fixed, .main = main };
        }
        fn receive(a: std.mem.Allocator, child_bytes: []const u8, proof_bytes: []const u8, input: *const [D.spec.inputs(kind)]u256, out: [12]u256, mutation: u8) !void {
            if (proof_bytes.len > 16 * 1024 * 1024) return error.DenseProofCap;
            var proof = try Wire.decodeProofBytesBinary(a, proof_bytes);
            var owns = true;
            defer if (owns) proof.deinit(a);
            const roots = proof.commitment_scheme_proof.commitments.items;
            if (roots.len != 4) return error.DenseProofShape;
            const fixed = try Trace.fixedAlloc(a);
            defer a.free(fixed);
            var fixed_columns: [D.air.FIXED]engine.pcs.ColumnEvaluation = undefined;
            columns(fixed, &fixed_columns);
            var setup = try Scheme.init(a, CONFIG);
            defer setup.deinit(a);
            setup.setCompactPolynomialStorage(1);
            var scratch = Channel.init();
            try setup.commit(a, &fixed_columns, &scratch);
            var fresh = try setup.roots(a);
            defer fresh.deinit(a);
            if (!std.mem.eql(u8, &fresh.items[0], &roots[0])) return error.DenseFixedAuthority;
            var verifier = try Verifier.init(a, CONFIG);
            defer verifier.deinit(a);
            var channel = Channel.init();
            mix(&channel, input, out);
            try verifier.commit(a, roots[0], &([_]u32{8} ** D.air.FIXED), &channel);
            try verifier.commit(a, roots[1], &([_]u32{8} ** R.MAIN), &channel);
            const wire = A.crypto.curves.equations.WireFor(Q).draw(&channel);
            var encoded = try N.decode(a, child_bytes);
            defer encoded.deinit();
            var pending = try N.verify(a, scope(input, out, roots[0], roots[1]), &encoded.proof);
            defer pending.deinit(a);
            var data = try Proj.Data.init(a, &pending.artifact, pending.beta, pending.eta);
            defer data.deinit();
            const claim = try Trace.expectedClaim(.{ .byte = pending.beta, .wire = wire }, out);
            mixReceipt(&channel, pending.digest);
            channel.mixFelts(&.{claim});
            try verifier.commit(a, roots[2], &([_]u32{8} ** 24), &channel);
            if (mutation != 0) {
                const col: usize = switch (mutation) {
                    1 => 0,
                    2 => 8,
                    else => 16,
                };
                proof.commitment_scheme_proof.sampled_values.items[2][col][0] = proof.commitment_scheme_proof.sampled_values.items[2][col][0].add(Q.one());
            }
            const component = Component{ .input = input, .data = &data, .wire = wire, .claim = claim };
            const components = [_]core.air.components.ForField(Q).Component{component.asVerifierComponent()};
            owns = false;
            try core.verifier.ForField(Q).verify(H, MC, a, &components, &channel, &verifier, proof);
        }
        pub fn run() !void {
            const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 2 << 30);
            defer budget.destroy();
            const a = budget.allocator();
            var trace = try Trace.initMainOnly(a, &INPUT);
            defer trace.deinit();
            try std.testing.expectEqual(@as(usize, 0), trace.inter.len);
            var fixed: [D.air.FIXED]engine.pcs.ColumnEvaluation = undefined;
            var main: [R.MAIN]engine.pcs.ColumnEvaluation = undefined;
            columns(trace.fixed, &fixed);
            columns(trace.main, &main);
            var scheme = try Scheme.init(a, CONFIG);
            var owns = true;
            defer if (owns) scheme.deinit(a);
            scheme.setCompactPolynomialStorage(1);
            var channel = Channel.init();
            mix(&channel, &INPUT, expected());
            try scheme.commit(a, &fixed, &channel);
            try scheme.commit(a, &main, &channel);
            const wire = A.crypto.curves.equations.WireFor(Q).draw(&channel);
            const scoped = scope(&INPUT, expected(), scheme.trees.items[0].root(), scheme.trees.items[1].root());
            var child = try N.prove(kind, a, scoped, &trace);
            defer child.deinit(a);
            const child_bytes = try N.encode(a, &child.result.proof);
            defer a.free(child_bytes);
            var pending = try N.verify(a, scoped, &child.result.proof);
            defer pending.deinit(a);
            try std.testing.expectEqual(child.digest, pending.digest);
            var data = try Proj.Data.init(a, &pending.artifact, pending.beta, pending.eta);
            defer data.deinit();
            const binding = try Proj.witness(kind, a, &trace, &data);
            defer a.free(binding);
            const global = try Proj.globalWitness(kind, a, &trace, wire, expected());
            defer a.free(global.columns);
            var inter: [24]engine.pcs.ColumnEvaluation = undefined;
            columns(binding, inter[0..16]);
            columns(global.columns, inter[16..]);
            mixReceipt(&channel, pending.digest);
            channel.mixFelts(&.{global.claim});
            try scheme.commit(a, &inter, &channel);
            const component = Component{ .input = &INPUT, .data = &data, .wire = wire, .claim = global.claim };
            const components = [_]engine.air.component_prover.ForField(Q).ComponentProver{component.asProverComponent()};
            owns = false;
            var proof = try engine.prove.ForField(Q).prove(Backend, H, MC, a, &components, &channel, scheme);
            defer proof.deinit(a);
            const bytes = try Wire.encodeProofBytesBinary(a, proof);
            defer a.free(bytes);
            if (std.process.getEnvVarOwned(a, "STWO_DENSE_LOCAL_OUT")) |path| {
                defer a.free(path);
                var dir = try std.fs.cwd().makeOpenPath(path, .{});
                defer dir.close();
                const f = try dir.createFile(@tagName(kind) ++ ".proof.bin", .{ .exclusive = true });
                defer f.close();
                try f.writeAll(bytes);
                const g = try dir.createFile(@tagName(kind) ++ ".gkr.bin", .{ .exclusive = true });
                defer g.close();
                try g.writeAll(child_bytes);
            } else |err| if (err != error.EnvironmentVariableNotFound) return err;
            try receive(a, child_bytes, bytes, &INPUT, expected(), 0);
            for (1..4) |m| try std.testing.expect(std.meta.isError(receive(a, child_bytes, bytes, &INPUT, expected(), @intCast(m))));
            var wrong = INPUT;
            wrong[0] ^= 1;
            try std.testing.expect(std.meta.isError(receive(a, child_bytes, bytes, &wrong, expected(), 0)));
            const changed = try a.dupe(u8, child_bytes);
            defer a.free(changed);
            changed[changed.len - 1] ^= 1;
            try std.testing.expect(std.meta.isError(receive(a, changed, bytes, &INPUT, expected(), 0)));
            std.debug.print("OP_DENSE_LOCAL_PHYSICAL correctness_only=true kind={s} main={d} inter=24 native_bytes={d} child_bytes={d}\n", .{ @tagName(kind), R.MAIN, bytes.len, child_bytes.len });
        }
    };
}
test "direct dense multiply source-bound BYTE GKR physical fresh receiver" {
    try Qualification(.multiply).run();
}
test "direct dense square source-bound BYTE GKR physical fresh receiver" {
    try Qualification(.square).run();
}

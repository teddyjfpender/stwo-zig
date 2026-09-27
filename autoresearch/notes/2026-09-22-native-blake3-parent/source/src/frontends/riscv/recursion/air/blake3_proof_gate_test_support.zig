//! Shared real-proof gate for canonical compression and complete hash graphs.
//! Callers use an arena for fixture storage; core verification consumes proofs.
pub const run = ForBackend(@import("blake3_proof_fixture.zig").Cpu).run;
pub const runFor = ForBackend(@import("blake3_proof_fixture.zig").Cpu).runFor;
pub const runForParameters = ForBackend(@import("blake3_proof_fixture.zig").Cpu).runForParameters;
pub const runForParametersObserved = ForBackend(@import("blake3_proof_fixture.zig").Cpu).runForParametersObserved;

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const std = @import("std");
        const f = @import("blake3_proof_fixture.zig").ForBackend(Backend);
        const core = f.core;
        const M31 = f.M31;
        const QM31 = f.QM31;
        pub fn run(a: std.mem.Allocator, rows: anytype, logs: [3]u32, trusted_pp: []const f.Column, false_pp: []const f.Column) !void {
            return @This().runFor(@import("blake3_fixture_roster.zig").Fixture(false), a, rows, logs, trusted_pp, false_pp);
        }
        pub fn runFor(comptime F: type, a: std.mem.Allocator, rows: anytype, logs: [F.Airs.len]u32, trusted_pp: []const f.Column, false_pp: []const f.Column) !void {
            const parameters: [F.Airs.len][0]M31 = @splat(.{});
            return @This().runForParameters(F, a, rows, logs, trusted_pp, false_pp, parameters);
        }
        pub fn runForParameters(comptime F: type, a: std.mem.Allocator, rows: anytype, logs: [F.Airs.len]u32, trusted_pp: []const f.Column, false_pp: []const f.Column, parameters: anytype) !void {
            return @This().runForParametersObserved(F, a, rows, logs, trusted_pp, false_pp, parameters, void);
        }
        pub fn runForParametersObserved(comptime F: type, a: std.mem.Allocator, rows: anytype, logs: [F.Airs.len]u32, trusted_pp: []const f.Column, false_pp: []const f.Column, parameters: anytype, comptime Observer: type) !void {
            var definitions: F.Tuple(.definition) = undefined;
            var plans: F.Tuple(.plan) = undefined;
            inline for (F.Airs, 0..) |Air, i| {
                definitions[i] = if (@hasDecl(Air, "Location")) try Air.build(a, .generated) else try Air.build(a);
                plans[i] = try f.binding.Binding(Air).authenticate(&definitions[i]);
            }
            var pp: std.ArrayList(f.Column) = .empty;
            var main: std.ArrayList(f.Column) = .empty;
            var interaction: std.ArrayList(f.Column) = .empty;
            var counters = [2]f.Counter{ try f.Counter.init(a, .bitwise), try f.Counter.init(a, .range_check_8_8) };
            inline for (F.Airs, 0..) |Air, i| {
                const log = logs[i];
                try f.project(Air, a, rows[i], log, 0, &pp);
                try f.project(Air, a, rows[i], log, 1, &main);
                try f.register(Air, &plans[i], rows[i], &counters);
            }
            var table_pp: [2]usize = undefined;
            const table_main = main.items.len;
            for (f.kinds, &counters, &table_pp) |kind, *counter, *offset| {
                offset.* = pp.items.len;
                try f.tablePreprocessed(a, kind, &pp);
                try main.append(a, .{ .log_size = f.schema.logSize(kind), .values = try counter.committedColumn(a) });
            }
            // Reconstruct fixed columns from the statement and canonical SSA schedule,
            // independently of private round witnesses. Compare before trusting a root.
            try std.testing.expectEqual(pp.items.len, trusted_pp.len);
            for (pp.items, trusted_pp) |actual, trusted| {
                try std.testing.expectEqual(actual.log_size, trusted.log_size);
                try std.testing.expectEqualSlices(M31, trusted.values, actual.values);
            }
            const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
            var channel = f.Channel{};
            channel.mixU32s(&.{ 0x42334350, 1 });
            var scheme = try f.Scheme.init(a, config);
            try scheme.commit(a, pp.items, &channel);
            try scheme.commit(a, main.items, &channel);
            const relations = try f.universal.UniversalRelations.draw(a, &channel);
            const providers = try @import("universal_provider_relations.zig").SharedProviderRelations.init(&relations);
            var claims: [F.Airs.len + 2]QM31 = undefined;
            inline for (F.Airs, 0..) |Air, i| {
                const log = logs[i];
                const generated = try f.framework.Runtime(f.binding.Binding(Air).Runtime).generatePrepared(a, &plans[i], rows[i], log, &relations);
                claims[i] = generated.claimed_sum;
                for (generated.columns) |column| try interaction.append(a, .{ .log_size = log, .values = column });
            }
            const table_interaction = interaction.items.len;
            for (&counters, f.kinds, F.Airs.len..) |*counter, kind, i| {
                const generated = try f.table_interaction.generate(a, counter, &providers.native);
                claims[i] = generated.claim;
                for (generated.columns) |column| try interaction.append(a, .{ .log_size = f.schema.logSize(kind), .values = column });
            }
            var total = QM31.zero();
            for (claims) |claim| total = total.add(claim);
            try std.testing.expect(total.isZero());
            f.mixClaims(&channel, &claims);
            try scheme.commit(a, interaction.items, &channel);
            const manifest = F.Manifest{ .log_sizes = logs };
            var components: F.Tuple(.component) = undefined;
            inline for (F.Airs, 0..) |Air, i| components[i] = try F.Component(Air).init(&definitions[i], plans[i], &manifest, @enumFromInt(i), logs[i], parameters[i], &relations, claims[i]);
            var tables: [2]f.Table = undefined;
            for (&tables, f.kinds, table_pp, 0..) |*table, kind, offset, i| {
                var tuple: [f.schema.MAX_ARITY]usize = undefined;
                for (tuple[0..f.schema.arity(kind)], 0..) |*index, j| index.* = offset + 1 + j;
                table.* = try f.Table.initProver(kind, offset, tuple[0..f.schema.arity(kind)], table_main + i, table_interaction + 4 * i, &providers.native, claims[F.Airs.len + i]);
            }
            var provers: [F.Airs.len + 2]f.prover.air.component_prover.ComponentProver = undefined;
            inline for (F.Airs, 0..) |_, i| provers[i] = components[i].asProverComponent();
            for (&tables, 0..) |*table, i| provers[F.Airs.len + i] = table.asProverComponent();
            var proof = try f.prover.prove.prove(f.Cpu, f.Hasher, f.MerkleChannel, a, &provers, &channel, scheme);
            var owns_proof = true;
            defer if (owns_proof) proof.deinit(a);
            var verifier_channel = f.Channel{};
            verifier_channel.mixU32s(&.{ 0x42334350, 1 });
            var fixed_scheme = try f.Scheme.init(a, config);
            defer fixed_scheme.deinit(a);
            try fixed_scheme.commit(a, trusted_pp, &verifier_channel);
            const roots = try fixed_scheme.roots(a);
            try f.admitPreprocessedRoot(roots.items[0], proof.commitment_scheme_proof.commitments.items[0]);
            var substituted = proof.commitment_scheme_proof.commitments.items[0];
            substituted[31] ^= 0x80;
            try std.testing.expectError(error.UntrustedBlake3Preprocessing, f.admitPreprocessedRoot(roots.items[0], substituted));
            var false_scheme = try f.Scheme.init(a, config);
            defer false_scheme.deinit(a);
            var false_channel = f.Channel{};
            try false_scheme.commit(a, false_pp, &false_channel);
            const false_roots = try false_scheme.roots(a);
            try std.testing.expectError(error.UntrustedBlake3Preprocessing, f.admitPreprocessedRoot(false_roots.items[0], proof.commitment_scheme_proof.commitments.items[0]));
            var verifier = try f.Verifier.init(a, config);
            defer verifier.deinit(a);
            // Replay from the start: commit checks and challenge draws must match exactly.
            verifier_channel = f.Channel{};
            verifier_channel.mixU32s(&.{ 0x42334350, 1 });
            try verifier.commit(a, roots.items[0], try f.columnLogs(a, trusted_pp), &verifier_channel);
            try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[1], try f.columnLogs(a, main.items), &verifier_channel);
            const verifier_relations = try f.universal.UniversalRelations.draw(a, &verifier_channel);
            try std.testing.expect(std.meta.eql(relations, verifier_relations));
            f.mixClaims(&verifier_channel, &claims);
            try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[2], try f.columnLogs(a, interaction.items), &verifier_channel);
            var verifiers: [F.Airs.len + 2]core.air.components.Component = undefined;
            inline for (F.Airs, 0..) |_, i| verifiers[i] = components[i].asVerifierComponent();
            for (&tables, 0..) |*table, i| verifiers[F.Airs.len + i] = table.asVerifierComponent();
            owns_proof = false; // Core verification consumes the proof on every path.
            if (Observer == void) {
                try core.verifier.verify(f.Hasher, f.MerkleChannel, a, &verifiers, &verifier_channel, &verifier, proof);
            } else {
                var capture: core.verifier.ProofCapture(f.Hasher) = undefined;
                try core.verifier.verifyWithProofCapture(f.Hasher, f.MerkleChannel, a, &verifiers, &verifier_channel, &verifier, proof, &capture);
                defer capture.deinit(a);
                try Observer.check(F, a, &capture, &components, &tables, &verifiers, &relations, &claims, config);
            }
            try std.testing.expectEqualSlices(u8, &channel.digestBytes(), &verifier_channel.digestBytes());
        }
    };
}

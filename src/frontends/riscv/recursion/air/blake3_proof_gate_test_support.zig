//! Shared real-proof gate for canonical compression and complete hash graphs.
//! Callers use an arena for fixture storage; core verification consumes proofs.
pub const run = ForBackend(@import("blake3_proof_fixture.zig").Cpu).run;
pub const runFor = ForBackend(@import("blake3_proof_fixture.zig").Cpu).runFor;
pub const runForParameters = ForBackend(@import("blake3_proof_fixture.zig").Cpu).runForParameters;
pub const runForParametersObserved = ForBackend(@import("blake3_proof_fixture.zig").Cpu).runForParametersObserved;

pub fn ForBackend(comptime Backend: type) type {
    return ForBackendWithTables(Backend, @import("blake3_proof_fixture.zig").kinds);
}
pub fn ForBackendWithTables(comptime Backend: type, comptime kinds: anytype) type {
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
            return @This().runForParametersProtocol(F, a, rows, logs, trusted_pp, false_pp, parameters, DefaultProtocol{}, Observer);
        }
        fn register(comptime Air: type, plan: *const f.binding.Binding(Air).Plan, rows: []const Air.Row, counters: *[kinds.len]f.Counter) !void {
            const Visitor = struct {
                counters: *[kinds.len]f.Counter,
                pub fn accepts(_: *@This(), id: anytype) bool {
                    inline for (kinds) |kind| if (id == @import("../../air/lang/relation.zig").id(@field(@import("../../air/lang/relation.zig").Domain, @tagName(kind)))) return true;
                    return false;
                }
                pub fn visit(self: *@This(), id: anytype, numerator: M31, tuple: []const M31) !void {
                    inline for (kinds, 0..) |kind, i| if (id == @import("../../air/lang/relation.zig").id(@field(@import("../../air/lang/relation.zig").Domain, @tagName(kind)))) {
                        try self.counters[i].registerBase(numerator, tuple);
                        return;
                    };
                    return error.UnexpectedLookupProvider;
                }
            };
            var visitor = Visitor{ .counters = counters };
            for (rows) |row| try plan.visitPreparedBaseEntries(row, &visitor);
        }
        const DefaultProtocol = struct {
            pub fn config(_: @This()) !core.pcs.PcsConfig {
                return .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
            }
            pub fn mix(_: @This(), channel: *f.Channel) !void {
                channel.mixU32s(&.{ 0x42334350, 1 });
            }
            pub fn admitRoot(_: @This(), _: f.Hasher.Hash) !void {}
            pub fn mixClaims(_: @This(), channel: *f.Channel, claims: []const QM31) !void {
                f.mixClaims(channel, claims);
            }
        };
        pub fn runForParametersProtocol(comptime F: type, a: std.mem.Allocator, rows: anytype, logs: [F.Airs.len]u32, trusted_pp: []const f.Column, false_pp: []const f.Column, parameters: anytype, protocol: anytype, comptime Observer: type) !void {
            var definitions: F.Tuple(.definition) = undefined;
            var plans: F.Tuple(.plan) = undefined;
            inline for (F.Airs, 0..) |Air, i| {
                definitions[i] = if (@hasDecl(Air, "Location")) try Air.build(a, .generated) else try Air.build(a);
                plans[i] = try f.binding.Binding(Air).authenticate(&definitions[i]);
            }
            var pp: std.ArrayList(f.Column) = .empty;
            var main: std.ArrayList(f.Column) = .empty;
            var interaction: std.ArrayList(f.Column) = .empty;
            var counters: [kinds.len]f.Counter = undefined;
            for (&counters, kinds) |*counter, kind| counter.* = try f.Counter.init(a, kind);
            inline for (F.Airs, 0..) |Air, i| {
                const log = logs[i];
                try f.project(Air, a, rows[i], log, 0, &pp);
                try f.project(Air, a, rows[i], log, 1, &main);
                if (!@hasDecl(@TypeOf(protocol), "registerLookups")) try register(Air, &plans[i], rows[i], &counters);
            }
            if (@hasDecl(@TypeOf(protocol), "appendExtraFixed")) try protocol.appendExtraFixed(a, &pp);
            if (@hasDecl(@TypeOf(protocol), "registerLookups")) try protocol.registerLookups(a, &counters);
            var table_pp: [kinds.len]usize = undefined;
            const table_main = main.items.len;
            for (kinds, &counters, &table_pp) |kind, *counter, *offset| {
                offset.* = pp.items.len;
                try f.tablePreprocessed(a, kind, &pp);
                try main.append(a, .{ .log_size = f.schema.logSize(kind), .values = try counter.committedColumn(a) });
            }
            if (@hasDecl(@TypeOf(protocol), "appendExtraMain")) try protocol.appendExtraMain(a, &main);
            // Reconstruct fixed columns from the statement and canonical SSA schedule,
            // independently of private round witnesses. Compare before trusting a root.
            try std.testing.expectEqual(pp.items.len, trusted_pp.len);
            for (pp.items, trusted_pp) |actual, trusted| {
                try std.testing.expectEqual(actual.log_size, trusted.log_size);
                try std.testing.expectEqualSlices(M31, trusted.values, actual.values);
            }
            const config = try protocol.config();
            var channel = f.Channel{};
            if (!@hasDecl(@TypeOf(protocol), "bindFirstRound")) try protocol.mix(&channel);
            var scheme = try f.Scheme.init(a, config);
            try scheme.commit(a, pp.items, &channel);
            try scheme.commit(a, main.items, &channel);
            if (@hasDecl(@TypeOf(protocol), "bindFirstRound")) {
                var first_round_roots = try scheme.roots(a);
                defer first_round_roots.deinit(a);
                try protocol.bindFirstRound(first_round_roots.items[0], first_round_roots.items[1]);
                channel = f.Channel{};
                try protocol.mix(&channel);
                f.MerkleChannel.mixRoot(&channel, first_round_roots.items[0]);
                f.MerkleChannel.mixRoot(&channel, first_round_roots.items[1]);
            }
            const relations = if (@hasDecl(@TypeOf(protocol), "drawRelations")) try protocol.drawRelations(a, &channel) else try f.universal.UniversalRelations.draw(a, &channel);
            const providers = try @import("universal_provider_relations.zig").SharedProviderRelations.init(&relations);
            var claims: [F.Airs.len + kinds.len]QM31 = undefined;
            inline for (F.Airs, 0..) |Air, i| {
                const log = logs[i];
                const generated = try f.framework.Runtime(f.binding.Binding(Air).Runtime).generatePrepared(a, &plans[i], rows[i], log, &relations);
                claims[i] = generated.claimed_sum;
                for (generated.columns) |column| try interaction.append(a, .{ .log_size = log, .values = column });
            }
            const table_interaction = interaction.items.len;
            for (&counters, kinds, F.Airs.len..) |*counter, kind, i| {
                const generated = try f.table_interaction.generate(a, counter, &providers.native);
                claims[i] = generated.claim;
                for (generated.columns) |column| try interaction.append(a, .{ .log_size = f.schema.logSize(kind), .values = column });
            }
            if (@hasDecl(@TypeOf(protocol), "appendExtraInteraction")) try protocol.appendExtraInteraction(a, &interaction);
            var total = QM31.zero();
            for (claims) |claim| total = total.add(claim);
            try std.testing.expect(total.isZero());
            try protocol.mixClaims(&channel, &claims);
            if (@hasDecl(@TypeOf(protocol), "mixExtraClaims")) try protocol.mixExtraClaims(&channel);
            try scheme.commit(a, interaction.items, &channel);
            const manifest = F.Manifest{ .log_sizes = logs };
            const component_owner = try @import("universal_component_owner.zig").ForRoster(F).initPrepared(a, &manifest, &definitions, &plans, parameters, relations, claims[0..F.Airs.len].*);
            defer component_owner.deinit();
            var tables: [kinds.len]f.Table = undefined;
            for (&tables, kinds, table_pp, 0..) |*table, kind, offset, i| {
                var tuple: [f.schema.MAX_ARITY]usize = undefined;
                for (tuple[0..f.schema.arity(kind)], 0..) |*index, j| index.* = offset + 1 + j;
                table.* = try f.Table.initProver(kind, offset, tuple[0..f.schema.arity(kind)], table_main + i, table_interaction + 4 * i, &providers.native, claims[F.Airs.len + i]);
            }
            const extra_count: usize = if (@hasDecl(@TypeOf(protocol), "EXTRA_COMPONENT_COUNT")) @TypeOf(protocol).EXTRA_COMPONENT_COUNT else 0;
            var provers: [F.Airs.len + kinds.len + extra_count]f.prover.air.component_prover.ComponentProver = undefined;
            @memcpy(provers[0..F.Airs.len], &(try component_owner.proverHandles()));
            for (&tables, 0..) |*table, i| provers[F.Airs.len + i] = try @import("roster_composition_geometry.zig").ForAirs(F.Airs).table(table.asProverComponent());
            if (comptime extra_count != 0 and @hasDecl(@TypeOf(protocol), "EXTRA_COMPOSITION_LOG_SPLIT")) {
                const intrinsic = @import("roster_composition_geometry.zig").ForAirs(F.Airs).quotient_log_blowup;
                const target = @TypeOf(protocol).EXTRA_COMPOSITION_LOG_SPLIT;
                if (target < intrinsic) return error.InvalidExtraCompositionGeometry;
                if (target > intrinsic) {
                    for (provers[0 .. F.Airs.len + kinds.len]) |*handle| handle.* = try handle.withCompositionGeometryOverrideV1(.{
                        .max_constraint_log_degree_bound_delta = target - intrinsic,
                        .composition_log_split = target,
                    });
                }
            }
            if (comptime extra_count != 0) @memcpy(provers[F.Airs.len + kinds.len ..], &protocol.extraProverHandles());
            var timer = try std.time.Timer.start();
            var extended = try f.prover.prove.proveExWithExecution(f.Cpu, f.Hasher, f.MerkleChannel, a, &provers, &channel, scheme, false, null, null, null);
            const prove_ns = timer.lap();
            const proof_value = extended.proof;
            extended.aux.deinit(a);
            var proof = proof_value;
            var owns_proof = true;
            defer if (owns_proof) proof.deinit(a);
            if (@hasDecl(@TypeOf(protocol), "observeProof")) try protocol.observeProof(a, &proof, prove_ns);
            _ = timer.lap();
            var verifier_channel = f.Channel{};
            try protocol.mix(&verifier_channel);
            var fixed_scheme = try f.Scheme.init(a, config);
            defer fixed_scheme.deinit(a);
            try fixed_scheme.commit(a, trusted_pp, &verifier_channel);
            const roots = try fixed_scheme.roots(a);
            try protocol.admitRoot(roots.items[0]);
            try protocol.admitRoot(proof.commitment_scheme_proof.commitments.items[0]);
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
            try protocol.mix(&verifier_channel);
            try verifier.commit(a, roots.items[0], try f.columnLogs(a, trusted_pp), &verifier_channel);
            try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[1], try f.columnLogs(a, main.items), &verifier_channel);
            const verifier_relations = if (@hasDecl(@TypeOf(protocol), "drawRelations")) try protocol.drawRelations(a, &verifier_channel) else try f.universal.UniversalRelations.draw(a, &verifier_channel);
            try std.testing.expect(std.meta.eql(relations, verifier_relations));
            try protocol.mixClaims(&verifier_channel, &claims);
            if (@hasDecl(@TypeOf(protocol), "mixExtraClaims")) try protocol.mixExtraClaims(&verifier_channel);
            try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[2], try f.columnLogs(a, interaction.items), &verifier_channel);
            var verifiers: [F.Airs.len + kinds.len + extra_count]core.air.components.Component = undefined;
            @memcpy(verifiers[0..F.Airs.len], &(try component_owner.verifierHandles()));
            for (&tables, 0..) |*table, i| verifiers[F.Airs.len + i] = try @import("roster_composition_geometry.zig").ForAirs(F.Airs).table(table.asVerifierComponent());
            if (comptime extra_count != 0 and @hasDecl(@TypeOf(protocol), "EXTRA_COMPOSITION_LOG_SPLIT")) {
                const intrinsic = @import("roster_composition_geometry.zig").ForAirs(F.Airs).quotient_log_blowup;
                const target = @TypeOf(protocol).EXTRA_COMPOSITION_LOG_SPLIT;
                if (target > intrinsic) {
                    for (verifiers[0 .. F.Airs.len + kinds.len]) |*handle| handle.* = try handle.withCompositionGeometryOverrideV1(.{
                        .max_constraint_log_degree_bound_delta = target - intrinsic,
                        .composition_log_split = target,
                    });
                }
            }
            if (comptime extra_count != 0) @memcpy(verifiers[F.Airs.len + kinds.len ..], &protocol.extraVerifierHandles());
            owns_proof = false; // Core verification consumes the proof on every path.
            if (@hasDecl(@TypeOf(protocol), "verifyOwned")) {
                verifier_channel = try protocol.verifyOwned(a, proof, claims);
            } else if (Observer == void) {
                try core.verifier.verify(f.Hasher, f.MerkleChannel, a, &verifiers, &verifier_channel, &verifier, proof);
            } else {
                var capture: core.verifier.ProofCapture(f.Hasher) = undefined;
                try core.verifier.verifyWithProofCapture(f.Hasher, f.MerkleChannel, a, &verifiers, &verifier_channel, &verifier, proof, &capture);
                defer capture.deinit(a);
                try Observer.check(F, a, &capture, &component_owner.components, &tables, &verifiers, &relations, &claims, config);
            }
            try std.testing.expectEqualSlices(u8, &channel.digestBytes(), &verifier_channel.digestBytes());
            if (@hasDecl(@TypeOf(protocol), "observeVerified")) try protocol.observeVerified(timer.lap());
        }
    };
}

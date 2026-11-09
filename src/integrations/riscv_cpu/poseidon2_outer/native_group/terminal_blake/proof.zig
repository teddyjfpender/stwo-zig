//! Terminal-only hash/codec orchestration around original backend witnesses,
//! source-owned component emitters and the same generic STARK engine.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const A = @import("../../authority.zig");
const Context = @import("../../context.zig").Context;
const Kind = @import("arithmetic.zig").Kind;
pub const R6 = ForArithmetic(.r6);
pub const R7 = ForArithmetic(.r7);
pub const Wire = R6.Wire;
pub const MAGIC = R6.MAGIC;
pub const MAX_PROOF_BYTES = R6.MAX_PROOF_BYTES;
pub const prove = R6.prove;
pub const proveProfiled = R6.proveProfiled;
pub const proveBalancedClaimsForTest = R6.proveBalancedClaimsForTest;
pub const verify = R6.verify;
pub fn ForArithmetic(comptime kind: Kind) type {
    const Arith = @import("arithmetic.zig").For(kind);
    const Suite = @import("profile.zig").ForArithmetic(kind);
    const K = @import("authority.zig").ForArithmetic(kind);
    const W = Arith.W;
    const O = Suite.O;
    const Q = A.Q;
    const H = Suite.H;
    const MC = Suite.MC;
    const Channel = Suite.Channel;
    return struct {
        const Self = @This();
        pub const Wire = @import("stwo_proof_wire").ForHasher(O, H);
        pub const MAGIC = if (kind == .r6) "STB26G01" else "STB28G01";
        pub const MAX_PROOF_BYTES = 2 << 20;
        const HEADER = 8 + 32 + Arith.COUNT * 8 * 4;
        fn begin(a: std.mem.Allocator, key: *const K.Key, outputs: []const Q) !Channel {
            if (outputs.len != Arith.base(&key.inner).n_outputs) return error.TerminalBlakeOutputCount;
            var channel = Channel.init();
            const domain = [_]u32{ 0x4f505442, if (kind == .r6) 1 else 2, Arith.COUNT, 8, 32 };
            channel.mixU32s(&domain);
            Suite.fri_policy.config().mixInto(&channel);
            const words = try a.alloc(u32, 9 + 4 * outputs.len);
            defer a.free(words);
            for (0..8) |i| words[i] = std.mem.readInt(u32, key.identity[4 * i ..][0..4], .little);
            words[8] = @intCast(outputs.len);
            for (outputs, 0..) |output, i| {
                for (output.toM31Array(), 0..) |v, j| words[9 + 4 * i + j] = v.v;
            }
            channel.mixU32s(words);
            return channel;
        }
        pub fn prove(a: std.mem.Allocator, ctx: *const Context, key: *const K.Key, outputs: []const Q) ![]u8 {
            return Self.proveProfiled(a, ctx, key, outputs, null);
        }
        pub fn proveProfiled(a: std.mem.Allocator, ctx: *const Context, key: *const K.Key, outputs: []const Q, recorder: ?*Engine.stage_profile.Recorder) ![]u8 {
            return Self.proveRecorded(a, ctx, key, outputs, recorder, .none);
        }
        /// Coherent transcript falsification only; no mutation flag enters a receiver.
        pub fn proveBalancedClaimsForTest(a: std.mem.Allocator, ctx: *const Context, key: *const K.Key, outputs: []const Q) ![]u8 {
            if (!@import("builtin").is_test) return error.TerminalBlakeTestOnly;
            return Self.proveRecorded(a, ctx, key, outputs, null, .balanced_claims);
        }
        pub fn proveMutationForTest(a: std.mem.Allocator, ctx: *const Context, key: *const K.Key, outputs: []const Q, mutation: @import("arithmetic.zig").Mutation) ![]u8 {
            if (!@import("builtin").is_test) return error.TerminalBlakeTestOnly;
            return Self.proveRecorded(a, ctx, key, outputs, null, mutation);
        }
        fn proveRecorded(a: std.mem.Allocator, ctx: *const Context, key: *const K.Key, outputs: []const Q, recorder: ?*Engine.stage_profile.Recorder, mutation: @import("arithmetic.zig").Mutation) ![]u8 {
            if (kind == .r7 and !Engine.host_budget_allocator.SharedHostBudget.isAllocator(a)) return error.NativeDotR7BudgetRequired;
            if (key.fixed_tree == null or Arith.base(&key.inner).fixed.values.len != Arith.FIXED_COUNT or Arith.base(&key.inner).usage.len == 0) return error.TerminalBlakeProverDataRetired;
            var main = blk: {
                var span = try Engine.stage_profile.StageScope.begin(recorder, "terminal_blake.main_generation", "Terminal MAIN generation");
                defer span.end();
                break :blk try W.main(a, ctx, &key.inner);
            };
            defer main.deinit();
            if (mutation != .none) try Arith.mutateMainForTest(&main, &key.inner, mutation);
            var channel = try Self.begin(a, key, outputs);
            var scheme = try Suite.E.init(a, Suite.fri_policy.config());
            scheme.reuse_bounded_merkle_tail = true;
            scheme.setCompactPolynomialStorage(1);
            var owned = true;
            defer if (owned) scheme.deinit(a);
            {
                var tree = key.fixed_tree.?.retainShared();
                errdefer tree.deinit(a);
                try scheme.appendCommittedTree(a, tree, &channel);
            }
            {
                var span = try Engine.stage_profile.StageScope.begin(recorder, "terminal_blake.main_commit", "Terminal Blake MAIN commitment");
                defer span.end();
                try scheme.commitBorrowedStreamingWithRecorder(a, main.values, 64, recorder, &channel);
            }
            const elements = W.Elements.init(channel.drawSecureFelt(), channel.drawSecureFelt());
            var inter = blk: {
                var span = try Engine.stage_profile.StageScope.begin(recorder, "terminal_blake.interaction_generation", "Terminal interaction generation");
                defer span.end();
                break :blk try W.interaction(a, &key.inner, main.values, outputs, &elements);
            };
            defer inter.deinit();
            main.deinit();
            main = .{ .allocator = a, .values = &.{} };
            if (mutation == .balanced_claims) {
                inter.claims[0] = inter.claims[0].add(O.one());
                inter.claims[Arith.COUNT - 1] = inter.claims[Arith.COUNT - 1].sub(O.one());
                if (!(try W.closure(outputs, inter.claims, &elements)).isZero()) return error.TerminalBlakeMutationNotBalanced;
            }
            channel.mixFelts(&inter.claims);
            {
                var span = try Engine.stage_profile.StageScope.begin(recorder, "terminal_blake.interaction_commit", "Terminal Blake interaction commitment");
                defer span.end();
                try scheme.commitBorrowedStreamingWithRecorder(a, inter.columns, 64, recorder, &channel);
            }
            @import("stwo_circuit_frontend").witness.trace.freeColumns(a, inter.columns);
            inter.columns = &.{};
            const logs = try key.inner.treeLogs(a, 0);
            defer a.free(logs);
            const bundle = try Arith.Components.init(a, &key.inner, elements, inter.claims, logs);
            const components = bundle.provers();
            owned = false;
            var produced = try Suite.E.prove(a, &components, &channel, scheme, .{ .recorder = recorder });
            defer produced.deinit(a);
            const body = try Self.Wire.encodeProofBytesBinary(a, produced.proof);
            defer a.free(body);
            if (body.len > Self.MAX_PROOF_BYTES - HEADER) return error.TerminalBlakeProofSize;
            const out = try a.alloc(u8, HEADER + body.len);
            @memcpy(out[0..8], Self.MAGIC);
            @memcpy(out[8..40], &key.identity);
            for (inter.claims, 0..) |claim, i| for (claim.toM31Array(), 0..) |v, j| std.mem.writeInt(u32, out[40 + 32 * i + 4 * j ..][0..4], v.v, .little);
            @memcpy(out[HEADER..], body);
            return out;
        }
        pub fn verify(a: std.mem.Allocator, key: *const K.Key, outputs: []const Q, encoded: []const u8) !void {
            if (encoded.len > Self.MAX_PROOF_BYTES) return error.TerminalBlakeProofSize;
            if (encoded.len < HEADER or !std.mem.eql(u8, encoded[0..8], Self.MAGIC)) return error.TerminalBlakeWire;
            if (!std.mem.eql(u8, encoded[8..40], &key.identity)) return error.TerminalBlakeAuthority;
            var claims: W.Claims = undefined;
            for (&claims, 0..) |*claim, i| {
                var limbs: [8]A.M = undefined;
                for (&limbs, 0..) |*limb, j| {
                    const value = std.mem.readInt(u32, encoded[40 + 32 * i + 4 * j ..][0..4], .little);
                    if (value >= Core.fields.m31.Modulus) return error.TerminalBlakeNoncanonicalClaim;
                    limb.* = A.M.fromCanonical(value);
                }
                claim.* = O.fromM31Array(limbs);
            }
            var proof = try Self.Wire.decodeProofBytesBinary(a, encoded[HEADER..]);
            var owned = true;
            defer if (owned) proof.deinit(a);
            const pcs = &proof.commitment_scheme_proof;
            if (pcs.commitments.items.len != 4 or pcs.revision_config != null or !std.meta.eql(pcs.config, Suite.fri_policy.config())) return error.TerminalBlakeShape;
            if (!std.mem.eql(u8, &pcs.commitments.items[0], &key.fixed_root)) return error.TerminalBlakeFixedAuthority;
            var channel = try Self.begin(a, key, outputs);
            var receiver = try Core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(H, MC).init(a, Suite.fri_policy.config());
            defer receiver.deinit(a);
            const fixed = try key.inner.treeLogs(a, 0);
            defer a.free(fixed);
            const main = try key.inner.treeLogs(a, 1);
            defer a.free(main);
            const inter = try key.inner.treeLogs(a, 2);
            defer a.free(inter);
            try receiver.commit(a, key.fixed_root, fixed, &channel);
            try receiver.commit(a, pcs.commitments.items[1], main, &channel);
            const elements = W.Elements.init(channel.drawSecureFelt(), channel.drawSecureFelt());
            if (!(try W.closure(outputs, claims, &elements)).isZero()) return error.TerminalBlakeGlobalLookup;
            channel.mixFelts(&claims);
            try receiver.commit(a, pcs.commitments.items[2], inter, &channel);
            const bundle = try Arith.Components.init(a, &key.inner, elements, claims, fixed);
            const components = bundle.verifiers();
            owned = false;
            try Core.verifier.ForField(O).verify(H, MC, a, &components, &channel, &receiver, proof);
        }
    };
}

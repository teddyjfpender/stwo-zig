//! Complete opt-in native-parent circuit leaf: original prefix, 47 relation
//! pairs, ALL 25 physical claims, canonical 23 AIRs + two lookup tables,
//! dynamic exact public supply, four-tree BLAKE3 PCS, PoW26 and q70 FRI.
//! This module never accepts a native-parent successful verification receipt.
const std = @import("std");
const core = @import("stwo_core");
const b = @import("stwo_circuit_frontend").builder;
const channel = @import("stwo_circuit_frontend").builder.blake3_channel_reuse_v1;
const pcs = @import("stwo_circuit_frontend").builder.blake3_pcs_reuse_v1;
const Lower = @import("stwo_circuit_frontend").builder.riscv_composition_lowering_v1;
const Statement = @import("stwo_circuit_frontend").statements.riscv_native_parent_v1;
const Authority = @import("authority_v1.zig");
const Material = @import("proof_material_v1.zig");
const Q = core.fields.qm31.QM31;
const W = b.wrappers.U32Wrapper(b.Var);
pub const production_active = false;
pub const OUTPUTS: usize = 8;
pub const Result = struct { digest: channel.Digest, statement: Statement.Wires, pcs_result: pcs.Result };

pub fn build(comptime V: type, ctx: *b.Context(V), authority: *const Authority.Owned, material: *const Material.Owned) !Result {
    try authority.validate();
    const proof = try material.allocate(V, ctx, authority.geometry);
    const statement = try Statement.allocate(V, ctx, authority.statement);
    // These are actual root variables used again in every PCS opening.
    try requireRoot(V, ctx, proof.proof.roots[0], authority.profile.fixed_root);
    try requireRoot(V, ctx, proof.proof.roots[1], authority.profile.main_root);
    var transcript = try channel.Channel(V).init(ctx);
    const prefix = try Prefix(V).allocate(ctx, &authority.profile.admission.prefix);
    try prefix.replay(ctx, &transcript, &authority.profile.admission.prefix);
    try transcript.mixRoot(ctx, proof.proof.roots[0]);
    try transcript.mixRoot(ctx, proof.proof.roots[1]);
    var challenges: [94]b.Var = undefined;
    for (0..47) |i| {
        const pair = try transcript.drawSecurePair(ctx, 1);
        challenges[2 * i] = pair[0];
        challenges[2 * i + 1] = pair[1];
    }
    var claim_header: [3]W = undefined;
    for (&claim_header, [_]u32{ authority.profile.admission.claim_tag, 1, 25 }) |*word, value| word.* = try b.wrappers.constU32(V, ctx, value);
    try transcript.mixU32s(ctx, &claim_header);
    // Exactly the same claim variables are consumed by the equation compiler.
    try transcript.mixFelts(ctx, &proof.claims);
    try transcript.mixRoot(ctx, proof.proof.roots[2]);
    const alpha = try transcript.drawSecureFelt(ctx, 1);
    try transcript.mixRoot(ctx, proof.proof.roots[3]);
    const oods = try pcs.drawOods(V, ctx, &transcript);
    const inputs = try ctx.scratch().alloc(b.Var, authority.composition.sources.len);
    const live = try Lower.liveness(ctx.scratch(), &authority.composition.circuit);
    var live_challenges: [94]bool = @splat(false);
    for (authority.composition.sources, live.inputs) |source, used| if (source == .challenge and used) {
        live_challenges[source.challenge] = true;
    };
    // The universal protocol draws every registry domain. Only the derived
    // secure draw results of structurally unused domains are discarded here;
    // all raw sampling/rejection constraints remain, and no proof input is marked.
    for (challenges, live_challenges) |challenge, used| if (!used) try ctx.markAsUnused(challenge);
    var supply = try Supply(V).init(ctx, prefix);
    for (inputs, authority.composition.sources) |*input, source| {
        input.* = switch (source) {
            .sample => |i| try checkedAt(proof.proof.sampled_values, i),
            .claim => |i| try checkedAt(&proof.claims, i),
            .challenge => |i| try checkedAt(&challenges, i),
            .composition => alpha,
            .oods => oods.seed,
            .packed_public_input => |i| blk: {
                if (i / 4 >= authority.terms.len) return error.InvalidRiscCircuitPublicReference;
                break :blk (try supply.coordinates(ctx, authority.terms[i / 4]))[i % 4];
            },
            .public_input => return error.UnsupportedRiscCircuitLegacySpan,
        };
    }
    // Shared native equation authority includes split-composition equality AND
    // claimed-sum + exact public-supply closure. There is no host sum shortcut.
    Lower.constrain(V, ctx, &authority.composition.circuit, inputs) catch |err| switch (err) {
        // Diagnostic stage identity for hostile-proof qualification. It changes
        // no constraints and exposes no mode that skips typed AIR verification.
        error.EqFailedOnEval => return error.RiscCircuitTypedCompositionRejected,
        else => return err,
    };
    const opening = try pcs.verifyAfterOods(V, ctx, authority.geometry, &transcript, proof.proof, oods);
    const digest = try statement.digest(V, ctx);
    var outputs: [OUTPUTS]b.Var = undefined;
    for (&outputs, digest) |*output, word| output.* = word.get();
    try ctx.setOutputs(&outputs);
    return .{ .digest = digest, .statement = statement, .pcs_result = opening };
}

fn checkedAt(values: []const b.Var, index: usize) !b.Var {
    if (index >= values.len) return error.InvalidRiscCircuitCompositionInputs;
    return values[index];
}
fn requireRoot(comptime V: type, ctx: *b.Context(V), actual: channel.Digest, expected: [32]u8) !void {
    for (actual, 0..) |word, i| try ctx.eq(word.get(), (try b.wrappers.constU32(V, ctx, std.mem.readInt(u32, expected[4 * i ..][0..4], .little))).get());
}

fn Prefix(comptime V: type) type {
    return struct {
        words: []const W,
        felts: []const b.Var,
        fn allocate(ctx: *b.Context(V), frame: anytype) !@This() {
            const words = try ctx.scratch().alloc(W, frame.words.len);
            const felts = try ctx.scratch().alloc(b.Var, frame.felts.len);
            for (words, frame.words) |*wire, value| {
                wire.* = try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, value));
                try ctx.eq(wire.get(), (try b.wrappers.constU32(V, ctx, value)).get());
            }
            for (felts, frame.felts) |*wire, value| {
                wire.* = try ctx.guess(b.ivalue.fromQm31(V, value));
                try ctx.eq(wire.*, try ctx.constant(value));
            }
            return .{ .words = words, .felts = felts };
        }
        fn replay(v: @This(), ctx: *b.Context(V), transcript: *channel.Channel(V), frame: anytype) !void {
            for (frame.first) |step| switch (step) {
                .words => |span| try transcript.mixU32s(ctx, try spanAt(W, v.words, span.first, span.len)),
                .felts => |span| try transcript.mixFelts(ctx, try spanAt(b.Var, v.felts, span.first, span.len)),
                .root => |offset| try transcript.mixRoot(ctx, (try spanAt(W, v.words, offset, 8))[0..8].*),
                .integer => |offset| try transcript.mixU64(ctx, (try spanAt(W, v.words, offset, 2))[0..2].*),
            };
        }
    };
}
fn spanAt(comptime T: type, all: []const T, first: usize, len: usize) ![]const T {
    if (first > all.len or len > all.len - first) return error.InvalidRiscCircuitPrefix;
    return all[first..][0..len];
}

/// Shares both field-coordinate unpacking and byte decompositions across ALL
/// occurrences. The returned variables are derived from transcript operands,
/// never independently guessed duplicate values matched by a host equality.
fn Supply(comptime V: type) type {
    return struct {
        prefix: Prefix(V),
        word_bytes: []?[4]b.Var,
        felt_words: []?[4]W,
        felt_bytes: []?[4]b.Var,
        felt_coordinates: []?[4]b.Var,
        fn init(ctx: *b.Context(V), prefix: Prefix(V)) !@This() {
            const a = ctx.scratch();
            const word_bytes = try a.alloc(?[4]b.Var, prefix.words.len);
            const felt_words = try a.alloc(?[4]W, prefix.felts.len);
            const felt_bytes = try a.alloc(?[4]b.Var, 4 * prefix.felts.len);
            const felt_coordinates = try a.alloc(?[4]b.Var, prefix.felts.len);
            @memset(word_bytes, null);
            @memset(felt_words, null);
            @memset(felt_bytes, null);
            @memset(felt_coordinates, null);
            return .{ .prefix = prefix, .word_bytes = word_bytes, .felt_words = felt_words, .felt_bytes = felt_bytes, .felt_coordinates = felt_coordinates };
        }
        fn coordinates(v: *@This(), ctx: *b.Context(V), reference: Authority.TermRef) ![4]b.Var {
            switch (reference) {
                .raw_word => |i| {
                    if (i >= v.prefix.words.len) return error.InvalidRiscCircuitPublicReference;
                    if (v.word_bytes[i] == null) v.word_bytes[i] = try bytes(V, ctx, v.prefix.words[i]);
                    return v.word_bytes[i].?;
                },
                .felt_word => |i| {
                    if (i.field >= v.prefix.felts.len) return error.InvalidRiscCircuitPublicReference;
                    if (v.felt_words[i.field] == null) {
                        const unpacked = try b.blake.unpackQm31sToU32Words(V, ctx, &.{v.prefix.felts[i.field]});
                        v.felt_words[i.field] = unpacked[0..4].*;
                    }
                    const index = 4 * i.field + @as(usize, i.coordinate);
                    if (v.felt_bytes[index] == null) v.felt_bytes[index] = try bytes(V, ctx, v.felt_words[i.field].?[i.coordinate]);
                    return v.felt_bytes[index].?;
                },
                .qm31 => |i| {
                    if (i >= v.prefix.felts.len) return error.InvalidRiscCircuitPublicReference;
                    if (v.felt_coordinates[i] == null) {
                        var coordinates_: [4]b.Var = undefined;
                        for (&coordinates_, 0..) |*coordinate, j| coordinate.* = try b.simd.unpackIdx(V, ctx, b.simd.Simd.fromPacked(&.{v.prefix.felts[i]}, 4), j);
                        v.felt_coordinates[i] = coordinates_;
                    }
                    return v.felt_coordinates[i].?;
                },
            }
        }
    };
}
fn bytes(comptime V: type, ctx: *b.Context(V), word: W) ![4]b.Var {
    const value = b.ivalue.unpackU32(V, ctx.get(word.get()));
    var result: [4]b.Var = undefined;
    for (&result, 0..) |*byte, i| byte.* = (try b.wrappers.guessU16(V, ctx, .newUnsafe(b.ivalue.fromQm31(V, Q.fromU32Unchecked((value >> @as(u5, @intCast(8 * i))) & 255, 0, 0, 0))))).get();
    // The guesses above are U16; this tightens all four byte values to U8.
    for (result) |byte| _ = try b.extract_bits.extractBits(V, ctx, b.simd.Simd.fromPacked(&.{byte}, 1), 8);
    const limbs = b.simd.Simd.fromPacked(&.{word.get()}, 2);
    const scale = try ctx.constant(Q.fromU32Unchecked(256, 0, 0, 0));
    try ctx.eq(try b.simd.unpackIdx(V, ctx, limbs, 0), try ctx.add(result[0], try ctx.mul(scale, result[1])));
    try ctx.eq(try b.simd.unpackIdx(V, ctx, limbs, 1), try ctx.add(result[2], try ctx.mul(scale, result[3])));
    return result;
}

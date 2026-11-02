//! Bounded synthetic LogUp matrix probe. Counts requested live allocator bytes,
//! not RSS; proving inputs remain owned and unchanged for later binding.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const G = @import("gkr_prover.zig").ForField(O);
const V = @import("gkr_verifier.zig").ForField(O);
const Mle = @import("mle.zig");
const Kernel = @import("verifier_kernel.zig");
const Budget = @import("../host_budget_allocator.zig").HostBudgetAllocator;
fn word(hash: *std.crypto.hash.blake2.Blake2s256, n: usize) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(n), .little);
    hash.update(&bytes);
}
fn inputHash(n: []const M, d: []const O) [32]u8 {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    for (n) |v| h.update(&v.toBytesLe());
    for (d) |v| h.update(&v.toBytesLe());
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}
fn proofHash(p: *const V.GkrBatchProof) [32]u8 {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    word(&h, p.sumcheck_proofs.len);
    for (p.sumcheck_proofs) |s| {
        word(&h, s.round_polys.len);
        for (s.round_polys) |poly| {
            word(&h, poly.coeffsSlice().len);
            for (poly.coeffsSlice()) |v| h.update(&v.toBytesLe());
        }
    }
    word(&h, p.layer_masks_by_instance.len);
    for (p.layer_masks_by_instance) |masks| {
        word(&h, masks.len);
        for (masks) |mask| {
            word(&h, mask.columns.len);
            for (mask.columns) |pair| for (pair) |v| {
                h.update(&v.toBytesLe());
            };
        }
    }
    word(&h, p.output_claims_by_instance.len);
    for (p.output_claims_by_instance) |claims| {
        word(&h, claims.len);
        for (claims) |v| h.update(&v.toBytesLe());
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}
pub fn main() !void {
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);
    const row_log: u32 = if (args.len > 1) try std.fmt.parseInt(u32, args[1], 10) else 14;
    if (row_log < 5 or row_log > 18) return error.ProbeSizeOutsideBound;
    const n = @as(usize, 1) << @intCast(row_log + 4);
    var meter = Budget.init(std.heap.page_allocator, std.math.maxInt(usize));
    const a = meter.allocator();
    var proof_hex: [64]u8 = undefined;
    var transcript_hex: [64]u8 = undefined;
    var report: struct { row_log: u32, lanes: u32 = 16, input_bytes: usize, prove_peak_live_bytes: usize, after_prove_live_bytes: usize, verify_peak_live_bytes: usize, final_live_bytes: usize, inputs_unchanged: bool, proof_hash: []const u8, transcript: []const u8 } = undefined;
    {
        const numerators = try a.alloc(M, n);
        defer a.free(numerators);
        const denominators = try a.alloc(O, n);
        defer a.free(denominators);
        for (numerators, denominators, 0..) |*num, *den, i| {
            num.* = switch (i % 3) {
                0 => M.one(),
                1 => M.zero(),
                else => M.one().neg(),
            };
            var coordinates: [8]M = undefined;
            for (&coordinates, 0..) |*v, k| v.* = M.fromCanonical(@intCast(1 + (i * 17 + k * 31) % 1000003));
            den.* = O.fromM31Array(coordinates);
        }
        const layer = G.Layer{ .LogUpMultiplicities = .{ .numerators = try Mle.MleFor(O, M).initOwned(numerators), .denominators = try Mle.MleFor(O, O).initOwned(denominators) } };
        const original = inputHash(numerators, denominators);
        const input_bytes = meter.live_bytes;
        var channel = core.channel.raw_mod_m31.Om31Channel.init();
        var result = try G.proveBatch(a, &channel, &.{layer});
        defer result.deinit(a);
        const peak = meter.peak_live_bytes;
        const live = meter.live_bytes;
        const unchanged = std.mem.eql(u8, &original, &inputHash(numerators, denominators));
        if (!unchanged) return error.InputsMutated;
        const digest = proofHash(&result.proof);
        meter.peak_live_bytes = meter.live_bytes;
        var receiver = core.channel.raw_mod_m31.Om31Channel.init();
        var artifact = try V.partiallyVerifyBatch(a, &.{.LogUp}, &result.proof, &receiver);
        defer artifact.deinit(a);
        const expected = [_]O{ try layer.LogUpMultiplicities.numerators.evalAtPoint(a, artifact.ood_point), try layer.LogUpMultiplicities.denominators.evalAtPoint(a, artifact.ood_point) };
        const inputs = [_][]const O{&expected};
        try Kernel.verifyTerminalInputs(O, &artifact, &inputs, V.NativeChecks{});
        proof_hex = std.fmt.bytesToHex(digest, .lower);
        transcript_hex = std.fmt.bytesToHex(channel.digestBytes(), .lower);
        report = .{ .row_log = row_log, .input_bytes = input_bytes, .prove_peak_live_bytes = peak, .after_prove_live_bytes = live, .verify_peak_live_bytes = meter.peak_live_bytes, .final_live_bytes = 0, .inputs_unchanged = unchanged, .proof_hash = &proof_hex, .transcript = &transcript_hex };
    }
    report.final_live_bytes = meter.live_bytes;
    if (meter.live_bytes != 0) return error.LiveOwnersRemain;
    const json = try std.json.Stringify.valueAlloc(std.heap.page_allocator, report, .{});
    defer std.heap.page_allocator.free(json);
    std.debug.print("{s}\n", .{json});
}

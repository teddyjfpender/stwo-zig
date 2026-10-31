const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const F = @import("fixture.zig");
const R = @import("roster.zig");
const P = @import("protocol.zig");
const E = @import("execution.zig");
const G = @import("../protocol.zig");
const a = std.testing.allocator;
fn generate(src: *R.TruthSource, ch: P.TruthDraw) ![3]G.Q {
    return switch (src.*) {
        .keccak => |*s| .{ try A.crypto.keccak.interaction.generate(&s.permutation, ch.keccak), try s.chi.generateInteraction(ch.keccak), try s.xor5.generateInteraction(ch.keccak) },
        .secp => |*s| .{ try s.batch.product.generateInteraction(ch.secp), try s.batch.linear.generateInteraction(ch.secp), try s.bytes.generateInteraction(ch.secp.bytes) },
    };
}
fn setAllocator(src: *R.TruthSource, allocator: std.mem.Allocator) void {
    switch (src.*) {
        .keccak => |*v| {
            v.permutation.allocator = allocator;
            v.chi.allocator = allocator;
            v.xor5.allocator = allocator;
        },
        .secp => |*v| {
            v.batch.product.allocator = allocator;
            v.batch.linear.allocator = allocator;
            v.bytes.allocator = allocator;
        },
    }
}
fn proveMode(c: *const F.Case, advice: *const @import("collector.zig").Advice, index: usize, store: *@import("../retained_main_store.zig").Store, owned: bool) ![]u8 {
    const truth = c.truths()[index];
    var src = try R.TruthSource.init(a, truth, advice);
    defer src.deinit();
    var scheme = try G.T.Scheme.init(a, G.T.P.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = G.T.P.Channel{};
    P.beginTruth(&channel, truth, c.expected(), index);
    try truth.key().append(a, &scheme, &channel);
    if (owned) {
        const main = try src.takeMain();
        try scheme.commitOwnedStreamingWithRecorderAndBacking(a, main.columns, main.backings, 8, null, &channel);
    } else {
        const main = try src.columns(a, 1);
        defer a.free(main);
        try scheme.commitBorrowedStreaming(a, main, 8, &channel);
        try src.releaseMain();
    }
    _ = try store.spill(a, &scheme.trees.items[1]);
    try std.testing.expectEqualSlices(u8, &scheme.trees.items[1].root(), &c.bundle.manifest.roots[2 + index].main.bytes);
    const ch = try P.drawTruth(&channel, &c.bundle.manifest, truth, index);
    const claims = try generate(&src, ch);
    try std.testing.expectEqualDeep(c.bundle.truths[index].claims, claims);
    channel.mixFelts(&claims);
    if (owned) {
        // Both descriptor-allocation failure positions must leave every original
        // interaction owner available for the successful retry below.
        const before = try src.columns(a, 2);
        defer a.free(before);
        for (0..2) |fail_index| {
            var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = fail_index });
            setAllocator(&src, failing.allocator());
            const attempt = src.takeInteraction();
            setAllocator(&src, a);
            try std.testing.expectError(error.OutOfMemory, attempt);
            const after = try src.columns(a, 2);
            defer a.free(after);
            for (before, after) |x, y| try std.testing.expectEqual(x.values.ptr, y.values.ptr);
        }
        const inter = try src.takeInteraction();
        try scheme.commitOwnedStreamingWithRecorderAndBacking(a, inter.columns, inter.backings, 8, null, &channel);
    } else {
        const inter = try src.columns(a, 2);
        defer a.free(inter);
        try scheme.commitBorrowedStreaming(a, inter, 8, &channel);
    }
    if (truth == .keccak) {
        var components = @import("../keccak/shared/execution.zig").truthComponents(truth.keccak.setup, truth.first(), truth.count(), ch.keccak, claims);
        const handles = [_]engine.air.component_prover.ComponentProver{ components[0].asProverComponent(), components[1].asProverComponent(), components[2].asProverComponent() };
        owns = false;
        var proof = try engine.prove.prove(Backend, G.T.P.Hasher, G.T.P.MerkleChannel, a, &handles, &channel, scheme);
        defer proof.deinit(a);
        return wire.encodeProofBytesBinary(a, proof);
    } else {
        var components = @import("../secp/execution.zig").TruthComponents.initSpan(truth.secp.setup, truth.first(), truth.count(), ch.secp, claims);
        const handles = components.provers();
        owns = false;
        var proof = try engine.prove.prove(Backend, G.T.P.Hasher, G.T.P.MerkleChannel, a, &handles, &channel, scheme);
        defer proof.deinit(a);
        return wire.encodeProofBytesBinary(a, proof);
    }
}
fn allocationTake(alloc: std.mem.Allocator, truth: R.Truth, advice: *const @import("collector.zig").Advice) !void {
    var src = try R.TruthSource.init(alloc, truth, advice);
    defer src.deinit();
    const transferred = try src.takeMain();
    defer transferred.deinit(alloc);
}
test "Owned K ADD DOUBLE truth MAIN INTER and mapped coefficients preserve complete expected proofs" {
    var c = try F.Case.init(a);
    defer c.deinit();
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try @import("../retained_main_store.zig").Store.init(path, 64 << 20);
    defer store.deinit();
    for (0..3) |index| {
        const bytes = try proveMode(&c, &captured.advice, index, &store, true);
        defer a.free(bytes);
        try std.testing.expectEqualSlices(u8, c.bundle.truths[index].bytes, bytes);
        const borrowed = try proveMode(&c, &captured.advice, index, &store, false);
        defer a.free(borrowed);
        try std.testing.expectEqualSlices(u8, bytes, borrowed);
        var candidate = c.bundle;
        var tt = c.bundle.truths[0..3].*;
        tt[index].bytes = bytes;
        candidate.truths = &tt;
        try E.verify(a, &c.keys(), &c.truths(), c.expected(), &candidate);
        try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    }
}
test "Truth ownership transfer allocation failure borrowed phase and aliased buffers leave ownership intact" {
    var c = try F.Case.init(a);
    defer c.deinit();
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    for (c.truths()) |truth| {
        try std.testing.checkAllAllocationFailures(a, allocationTake, .{ truth, &captured.advice });
        var src = try R.TruthSource.init(a, truth, &captured.advice);
        defer src.deinit();
        switch (src) {
            .keccak => |*s| {
                s.permutation.owns_main = false;
                try std.testing.expectError(error.InvalidTruthBufferOwner, src.takeMain());
                s.permutation.owns_main = true;
                const saved = s.xor5.main;
                s.xor5.main = s.chi.main[0..saved.len];
                try std.testing.expectError(error.AliasedTruthBuffers, src.takeMain());
                s.xor5.main = saved;
            },
            .secp => |*s| {
                s.batch.product.owns_main = false;
                try std.testing.expectError(error.InvalidTruthBufferOwner, src.takeMain());
                s.batch.product.owns_main = true;
                const saved = s.bytes.main;
                s.bytes.main = s.batch.product.main[0..saved.len];
                try std.testing.expectError(error.AliasedTruthBuffers, src.takeMain());
                s.bytes.main = saved;
            },
        }
        const main = try src.takeMain();
        defer main.deinit(a);
        try std.testing.expectError(error.InvalidTruthBufferOwner, src.takeMain());
        try std.testing.expectError(error.InvalidTruthBufferPhase, src.takeInteraction());
    }
}

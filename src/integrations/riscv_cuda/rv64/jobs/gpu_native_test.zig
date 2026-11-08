const std = @import("std");
const testing = std.testing;
const api = @import("api.zig");
const G = @import("gpu_native.zig");

fn sampleProofs() [6]G.ProofSpec {
    return .{
        .{ .id = .{ .kind = .request, .ordinal = 0 }, .device = 0, .max_encoded_bytes = 0 },
        .{ .id = .{ .kind = .native_segment, .ordinal = 0 }, .device = 0, .max_encoded_bytes = 1001 },
        .{ .id = .{ .kind = .native_segment, .ordinal = 1 }, .device = 1, .max_encoded_bytes = 4096 },
        .{ .id = .{ .kind = .truth, .ordinal = 0 }, .device = 1, .max_encoded_bytes = 64 },
        .{ .id = .{ .kind = .leaf, .ordinal = 0 }, .device = 0, .max_encoded_bytes = 128, .extra_checks = &.{.root_match} },
        .{ .id = .{ .kind = .root, .ordinal = 0 }, .device = 0, .max_encoded_bytes = 256 },
    };
}

const exchange = G.Exchange{ .segments = 2, .claims_per_segment = 3, .devices = 2 };

test "request layout: regions aligned, disjoint, every proof once" {
    const proofs = sampleProofs();
    var l = try G.RequestLayout.build(testing.allocator, 2, &proofs, exchange);
    defer l.deinit();
    try testing.expectEqual(@as(usize, 2), l.segments.len);
    try testing.expectEqual(@as(usize, 4), l.segments[0].entries.len);
    try testing.expectEqual(@as(usize, 2), l.segments[1].entries.len);
    for (l.segments) |s| {
        try testing.expect(s.status_offset % G.region_align == 0);
        try testing.expect(s.exchange_offset % G.region_align == 0);
        try testing.expect(s.encoded_offset % G.region_align == 0);
        // Exchange at a fixed offset right after the header, then directory, status, encoded.
        try testing.expectEqual(@as(usize, G.region_align), s.exchange_offset);
        try testing.expect(s.directory_offset >= s.exchange_offset + s.exchange_words);
        try testing.expect(s.status_offset >= s.directory_offset + s.entries.len * G.entry_words);
        try testing.expect(s.encoded_offset >= s.status_offset + s.status_words);
        try testing.expectEqual(exchange.words(), s.exchange_words);
        var prev_end: usize = s.encoded_offset;
        for (s.entries) |e| {
            try testing.expect(e.encoded_offset >= prev_end);
            prev_end = e.encoded_offset + 1 + e.encoded_capacity_words;
        }
        try testing.expect(prev_end <= s.words);
    }
    // the leaf carries its extra check after the required ones
    const leaf = G.ProofId{ .kind = .leaf, .ordinal = 0 };
    _ = try l.segments[0].statusWord(leaf, .root_match);
    _ = try l.segments[0].statusWord(leaf, .lookup_sum);
    try testing.expectError(error.GpuNativeUnknownCheck, l.segments[0].statusWord(leaf, .public_claims));
    try testing.expectError(error.GpuNativeUnknownProof, l.segments[1].statusWord(leaf, .lookup_sum));
    // 1001 bytes -> 251 words
    const seg0 = l.segments[0].entries[l.segments[0].find(.{ .kind = .native_segment, .ordinal = 0 }).?];
    try testing.expectEqual(@as(u32, 251), seg0.encoded_capacity_words);
}

test "request layout refuses duplicates and bad devices" {
    var proofs = sampleProofs();
    proofs[3].id = proofs[2].id;
    try testing.expectError(error.GpuNativeDuplicateProof, G.RequestLayout.build(testing.allocator, 2, &proofs, exchange));
    proofs = sampleProofs();
    proofs[5].device = 2;
    try testing.expectError(error.GpuNativeProofDeviceOutOfRange, G.RequestLayout.build(testing.allocator, 2, &proofs, exchange));
    proofs = sampleProofs();
    proofs[4].extra_checks = &.{.lookup_sum};
    try testing.expectError(error.GpuNativeDuplicateCheck, G.RequestLayout.build(testing.allocator, 2, &proofs, exchange));
}

/// Host model of the device side: prefix upload, unset memset, checks and
/// encoders writing their words.
const completion: u32 = 0x77;

fn fill(a: std.mem.Allocator, l: *const G.RequestLayout, request: u64) ![][]u32 {
    const mirrors = try a.alloc([]u32, l.segments.len);
    for (l.segments, mirrors) |*s, *m| {
        m.* = try a.alloc(u32, s.words);
        @memset(m.*, 0xdead_beef);
        try s.prefix(m.*, request);
        m.*[G.header_completion_word] = completion;
        @memset(m.*[s.status_offset..][0..s.status_words], G.Verdict.unset);
        for (s.entries) |e| {
            for (0..e.status_count) |k| m.*[e.status_first + k] = G.Verdict.accepted;
            const bytes: u32 = @min(e.encoded_capacity_words * 4, 7 + e.ordinal);
            m.*[e.encoded_offset] = bytes;
            const body = std.mem.sliceAsBytes(m.*[e.encoded_offset + 1 ..][0..e.encoded_capacity_words]);
            for (body[0..bytes], 0..) |*b, i| b.* = @truncate(i ^ e.kind);
        }
    }
    return mirrors;
}

fn freeMirrors(a: std.mem.Allocator, m: [][]u32) void {
    for (m) |x| a.free(x);
    a.free(m);
}

test "publish: all accepted -> every proof sliced; any bad word refuses the request" {
    const a = testing.allocator;
    const proofs = sampleProofs();
    var l = try G.RequestLayout.build(a, 2, &proofs, exchange);
    defer l.deinit();
    const m = try fill(a, &l, 9);
    defer freeMirrors(a, m);
    const views = [2][]const u32{ m[0], m[1] };
    const out = try G.publish(a, &l, 9, completion, &views, null);
    defer a.free(out);
    try testing.expectEqual(@as(usize, 6), out.len);
    for (out) |p| if (p.id.kind == .native_segment and p.id.ordinal == 1) try testing.expectEqual(@as(usize, 8), p.bytes.len);

    // an unset word (check never ran) rejects
    const s1 = &l.segments[1];
    const w = try s1.statusWord(.{ .kind = .truth, .ordinal = 0 }, .truth_status);
    m[1][w] = G.Verdict.unset;
    var why: G.Rejection = undefined;
    try testing.expectError(error.GpuNativeProofRejected, G.publish(a, &l, 9, completion, &views, &why));
    try testing.expectEqual(G.Check.truth_status, why.check);
    // a reject code names its check
    m[1][w] = G.Verdict.reject(.truth_status, 3);
    try testing.expectEqual(G.Check.truth_status, G.Verdict.checkOf(m[1][w]).?);
    try testing.expectError(error.GpuNativeProofRejected, G.publish(a, &l, 9, completion, &views, null));
    m[1][w] = G.Verdict.accepted;
    // an encoder overrun rejects
    const e = s1.entries[0];
    m[1][e.encoded_offset] = e.encoded_capacity_words * 4 + 1;
    try testing.expectError(error.GpuNativeEncodedOverrun, G.publish(a, &l, 9, completion, &views, null));
    // an empty proof (length never written) rejects, naming encode_bounds
    m[1][e.encoded_offset] = 0;
    try testing.expectError(error.GpuNativeEncodedEmpty, G.publish(a, &l, 9, completion, &views, &why));
    try testing.expectEqual(G.Check.encode_bounds, why.check);
    m[1][e.encoded_offset] = 4;
    // a mirror whose D2H never landed (completion word not this request's) rejects
    m[0][G.header_completion_word] = completion - 1;
    try testing.expectError(error.GpuNativeSlabNotCompleted, G.publish(a, &l, 9, completion, &views, null));
    m[0][G.header_completion_word] = completion;
    // a stale request id rejects
    try testing.expectError(error.GpuNativeSlabHeaderMismatch, G.publish(a, &l, 10, completion, &views, null));
    const again = try G.publish(a, &l, 9, completion, &views, null);
    a.free(again);
}

test "verdict encoding never collides with accepted/unset" {
    inline for (std.meta.fields(G.Check)) |f| {
        const c: G.Check = @enumFromInt(f.value);
        const r = G.Verdict.reject(c, 0);
        try testing.expect(r != G.Verdict.accepted and r != G.Verdict.unset);
        try testing.expectEqual(c, G.Verdict.checkOf(r).?);
    }
}

test "exchange slots are disjoint and flags distinct" {
    const x = G.Exchange{ .segments = 7, .claims_per_segment = 5, .devices = 2 };
    const used = try testing.allocator.alloc(bool, x.words());
    defer testing.allocator.free(used);
    @memset(used, false);
    var slots: std.ArrayListUnmanaged(G.Exchange.Slot) = .empty;
    defer slots.deinit(testing.allocator);
    for (0..7) |s| {
        try slots.append(testing.allocator, try x.root(@intCast(s)));
        try slots.append(testing.allocator, try x.claims(@intCast(s)));
    }
    for (0..2) |d| try slots.append(testing.allocator, try x.partial(@intCast(d)));
    try slots.append(testing.allocator, x.seal());
    for (slots.items) |s| {
        for (used[s.offset..][0..s.words]) |*u| {
            try testing.expect(!u.*);
            u.* = true;
        }
        try testing.expect(!used[s.flag]);
        used[s.flag] = true;
    }
    // Every flag of the request is in the contiguous prefix [0, flagWords).
    for (slots.items) |sl| try testing.expect(sl.flag < x.flagWords());
    try testing.expectEqual(slots.items.len, x.flagWords());
    try testing.expectError(error.GpuNativeExchangeSlot, x.root(7));
}

test "exchange: offsets come from install capacities; a request never moves a flag onto data" {
    const cap = G.Exchange{ .segments = 8, .claims_per_segment = 4, .devices = 2 };
    const small = G.Exchange{ .segments = 2, .claims_per_segment = 1, .devices = 2, .capacity_segments = 8, .capacity_claims = 4 };
    const big = G.Exchange{ .segments = 7, .claims_per_segment = 3, .devices = 2, .capacity_segments = 8, .capacity_claims = 4 };
    try testing.expectEqual(cap.words(), small.words());
    try testing.expectEqual(cap.words(), big.words());
    try testing.expectEqual(cap.flagCapacity(), big.flagCapacity());
    // Data slots of one request never overlap the flag capacity of any other.
    for ([_]G.Exchange{ small, big }) |x| {
        for (0..x.segments) |sg| {
            try testing.expect((try x.root(@intCast(sg))).offset >= cap.flagCapacity());
            try testing.expect((try x.claims(@intCast(sg))).offset >= cap.flagCapacity());
            try testing.expect((try x.claims(@intCast(sg))).flag < cap.flagCapacity());
        }
        try testing.expect(x.seal().offset + G.Exchange.seal_words <= x.words());
    }
    // Same slot, same data offset in both requests (fixed per service).
    try testing.expectEqual((try small.root(1)).offset, (try big.root(1)).offset);
    try testing.expectEqual((try small.claims(1)).offset, (try big.claims(1)).offset);
    try testing.expectError(error.GpuNativeExchangeExceedsCapacity, (G.Exchange{ .segments = 9, .claims_per_segment = 1, .devices = 2, .capacity_segments = 8, .capacity_claims = 4 }).validate());
}

test "exchange: a GPU without segments owns no partial; the request's flags stay contiguous" {
    const x = G.Exchange{ .segments = 1, .claims_per_segment = 1, .devices = 2, .capacity_segments = 4, .capacity_claims = 1, .partial_mask = 0b01 };
    try x.validate();
    try testing.expect(x.hasPartial(0) and !x.hasPartial(1));
    try testing.expectError(error.GpuNativeExchangeNoPartial, x.partial(1));
    // seal + 1 partial + root + claims
    try testing.expectEqual(@as(usize, 4), x.flagWords());
    var seen = [_]bool{false} ** 4;
    for ([_]G.Exchange.Slot{ x.seal(), try x.partial(0), try x.root(0), try x.claims(0) }) |sl| {
        try testing.expect(!seen[sl.flag]);
        seen[sl.flag] = true;
    }
    try testing.expectError(error.GpuNativeExchangeDevices, (G.Exchange{ .segments = 1, .claims_per_segment = 1, .devices = 2, .partial_mask = 0b100 }).validate());
}

test "flat exchange keeps every produced flag contiguous without partial slots" {
    const x = G.Exchange{ .segments = 2, .claims_per_segment = 4, .devices = 2, .partials_enabled = false, .truths = 1, .receipts = true, .child_wire_words = 16 };
    try x.validate();
    try testing.expectEqual(@as(usize, 0), x.partials());
    try testing.expectError(error.GpuNativeExchangeNoPartial, x.partial(0));
    const slots = [_]G.Exchange.Slot{ x.seal(), try x.root(0), try x.claims(0), try x.root(1), try x.claims(1), try x.truthRoot(0), try x.receipt(0), try x.receipt(1), try x.childWire(0), try x.childWire(1) };
    try testing.expectEqual(slots.len, x.flagWords());
    var seen: [slots.len]bool = @splat(false);
    for (slots) |s| {
        try testing.expect(s.flag < seen.len);
        try testing.expect(!seen[s.flag]);
        try testing.expect(s.offset + s.words <= x.words());
        seen[s.flag] = true;
    }
    for (seen) |flag| try testing.expect(flag);
}

const Built = struct {
    var destroyed: u32 = 0;
    fn destroy(_: *anyopaque) void {
        destroyed += 1;
    }
    fn build(_: *anyopaque, _: std.mem.Allocator, key: G.ClassKey) anyerror!G.ClassEntry {
        return .{ .key = key, .plan = @ptrFromInt(0x1000), .destroy = destroy, .max_encoded_bytes = 77 };
    }
};

test "class cache: built once at warm, a request-path miss fails closed" {
    var c = G.ClassCache.init(testing.allocator);
    Built.destroyed = 0;
    var dummy: u8 = 0;
    const b = G.ClassCache.Builder{ .ctx = &dummy, .build = Built.build };
    const k1: G.ClassKey = @splat(1);
    const k2: G.ClassKey = @splat(2);
    const e1 = try c.warm(k1, b);
    try testing.expectEqual(e1, try c.warm(k1, b));
    try testing.expectEqual(@as(u64, 1), c.builds);
    c.seal();
    try testing.expectEqual(e1, try c.get(k1));
    try testing.expectError(error.GpuNativeClassNotWarmed, c.get(k2));
    try testing.expectError(error.GpuNativeClassBuildOnRequestPath, c.warm(k2, b));
    try testing.expectEqual(@as(u64, 2), c.request_misses);
    c.deinit();
    try testing.expectEqual(@as(u32, 1), Built.destroyed);
}

test "memory plan: regions tile the device, validation" {
    var p = G.MemoryPlan{ .device = 0, .capacity_words = 1000 };
    try testing.expectError(error.GpuNativeMemoryPlanNoArena, p.validate());
    p.set(.class_cache, 100);
    p.set(.main_resident, 300);
    p.set(.arena, 400);
    p.set(.exchange_slab, 50);
    p.set(.truth, 100);
    try p.validate();
    try testing.expectEqual(@as(u64, 100), p.offset(.graph_exec));
    try testing.expectEqual(@as(u64, 400), p.offset(.arena));
    p.set(.reserve, 51);
    try testing.expectError(error.GpuNativeMemoryPlanExceedsDevice, p.validate());
}

test "required checks: no duplicates per kind" {
    inline for (std.meta.fields(G.ProofKind)) |f| {
        const r = G.requiredChecks(@enumFromInt(f.value));
        for (r, 0..) |c, i| for (r[0..i]) |p| try testing.expect(p != c);
    }
}

test "device check / encoder resolve their slab words" {
    const proofs = sampleProofs();
    var l = try G.RequestLayout.build(testing.allocator, 2, &proofs, exchange);
    defer l.deinit();
    const backing = try testing.allocator.alloc(u32, l.segments[0].words);
    defer testing.allocator.free(backing);
    const seg = api.DeviceBuffer{ .ptr = backing.ptr, .words = backing.len };
    const id = G.ProofId{ .kind = .native_segment, .ordinal = 0 };
    const w = try l.segments[0].statusBuffer(seg, id, .oods_constraint);
    try testing.expectEqual(@as(usize, 1), w.words);
    const r = try l.segments[0].encodedBuffer(seg, id);
    try testing.expectEqual(@as(usize, 1 + 251), r.words);
    _ = try l.segments[0].exchangeBuffer(seg);
}

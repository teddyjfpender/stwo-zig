//! Host transcript/layout oracle and semantic-negative regression owner.
const Schema = @import("native_device_stage2.zig");
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const C = @import("native_commit.zig");
const JP = @import("../joined_parameters.zig");
const NO = @import("native_encode_oods.zig");
const Blake = std.crypto.hash.blake2.Blake2s256;
const CPU = @import("stwo_riscv_cpu_integration");
const Manifest = CPU.rv64_gkr_manifest;

/// Host mirror of the device seal (exactly the kernel's word streams), used to
/// pin the constants against the manifest authority without a GPU.
pub fn hostChi(constants: Schema.SealConstants, entries: []const Schema.SealEntry, roots: []const [8]u32) [8]u32 {
    const H2 = struct {
        fn h(tag: [8]u32, words: []const u32) [8]u32 {
            var b = Blake.init(.{});
            b.update(std.mem.sliceAsBytes(&tag));
            b.update(std.mem.sliceAsBytes(words));
            var out: [32]u8 = undefined;
            b.final(&out);
            return Schema.words8(out);
        }
    };
    var m = constants.m0;
    for (entries, 0..) |e, k| {
        var pre: [18]u32 = @splat(0);
        pre[0..8].* = if (e.root_offset == std.math.maxInt(u32)) e.main_const else roots[k];
        const rho = H2.h(constants.rho_tag, &pre);
        var step: [51]u32 = undefined;
        step[0..8].* = m;
        step[8] = e.k;
        step[9] = e.family;
        step[10] = e.rung;
        step[11..19].* = e.vkhash;
        step[19..27].* = e.stmt;
        step[27..35].* = e.s_in;
        step[35..43].* = e.s_out;
        step[43..51].* = rho;
        m = H2.h(constants.seg_tag, &step);
    }
    var fin: [16]u32 = undefined;
    fin[0..8].* = constants.execution;
    fin[8..16].* = m;
    return H2.h(constants.chi_tag, &fin);
}

pub fn testRoster(seed: u8, n: usize, roster: []Schema.RosterEntry, workers: []Manifest.ExpectedWorker, stages: []Manifest.StageOne) void {
    for (0..n) |k| {
        const b: u8 = seed +% @as(u8, @intCast(k)) *% 7;
        roster[k] = .{ .family = @intCast(k % 3), .rung = @intCast(k % 2), .vkhash = @splat(b +% 1), .stmt = @splat(b +% 2), .s_in = @splat(b +% 3), .s_out = @splat(b +% 4), .segment = @intCast(k), .root = @splat(b +% 5) };
        const kind: Manifest.Kind = if (k == 0) .cpu else .cpu;
        workers[k] = .{ .kind = kind, .global_relations = .{ .ram = true, .kio = false, .wire = false }, .mass = .{ .ram = 0, .kio = 0, .wire = 0 }, .ordinal = @intCast(k), .statement = roster[k].stmt, .fixed = @splat(9), .local_instances = null, .chain = .{ .family = roster[k].family, .rung = roster[k].rung, .vkhash = roster[k].vkhash, .stmt = roster[k].stmt, .s_in = roster[k].s_in, .s_out = roster[k].s_out } };
        stages[k] = .{ .main = roster[k].root, .local = null };
    }
}

test "device seal word streams reproduce the manifest chi chain (m6_v2_gkr) and drawShared inputs" {
    const a = std.testing.allocator;
    const Chain = CPU.rv64_gkr_chain;
    const identity = try Chain.versionIdentity(.m6_v2_gkr);
    const execution: [32]u8 = @splat(0x42);
    var roster: [5]Schema.RosterEntry = undefined;
    var workers: [5]Manifest.ExpectedWorker = undefined;
    var stages: [5]Manifest.StageOne = undefined;
    testRoster(3, 5, &roster, &workers, &stages);
    var pending = try Manifest.verifyAndSealFor(.m6_v2_gkr, a, execution, &workers, &stages);
    defer pending.deinit(a);
    const ex = G.Exchange{ .segments = 5, .claims_per_segment = 2, .devices = 2 };
    const entries = try Schema.sealEntries(a, &roster, ex);
    defer a.free(entries);
    var roots: [5][8]u32 = undefined;
    for (&roots, roster) |*r, e| r.* = Schema.words8(e.root);
    const k = Schema.sealConstants(identity, execution, 5, 1);
    try std.testing.expectEqualSlices(u32, &Schema.words8(pending.digest), &hostChi(k, entries, &roots));
    // drawShared layout: the shared namespace order of the joined parameters.
    try std.testing.expectEqual(@as(u32, 15), k.ram_draws);
    try std.testing.expectEqual(JP.kio - JP.ram, k.ram_draws);
    try std.testing.expectEqual(JP.wire - JP.kio, k.kio_draws);
    try std.testing.expectEqual(JP.claims - JP.wire, k.wire_draws);
    const shared = Manifest.drawShared(pending.digest);
    try std.testing.expectEqual(@as(usize, k.kio_draws - 1), shared.kio.coefficients.len);
    try std.testing.expectEqual(@as(usize, k.wire_draws - 1), shared.wire.coefficients.len);
    // Root slots point into the exchange data, flags at the slot's flag word.
    for (entries, 0..) |e, s| {
        const slot = try ex.root(@intCast(s));
        try std.testing.expectEqual(@as(u32, @intCast(slot.offset)), e.root_offset);
        try std.testing.expectEqual(@as(u32, @intCast(slot.flag)), e.flag_offset);
    }
}

test "handoff names are distinct per kind and segment; patch sources partition the namespaces" {
    try std.testing.expect(!std.mem.eql(u8, &Schema.handoffName(.checkpoint, 1), &Schema.handoffName(.binding, 1)));
    try std.testing.expect(!std.mem.eql(u8, &Schema.handoffName(.checkpoint, 1), &Schema.handoffName(.checkpoint, 2)));
    try std.testing.expectEqual(Schema.Source.shared, Schema.sourceOf(JP.ram).?.source);
    try std.testing.expectEqual(@as(u32, Schema.shared_felts - 1), Schema.sourceOf(JP.claims - 1).?.index);
    try std.testing.expect(Schema.sourceOf(JP.claims) == null);
    // Per-segment statement values are patched from the public input.
    try std.testing.expectEqual(Schema.Source.public, Schema.sourceOf(JP.cpu_steps).?.source);
    try std.testing.expectEqual(@as(u32, JP.local - 1), Schema.sourceOf(JP.local - 1).?.index);
    for (0..JP.claims) |slot| try std.testing.expect(Schema.sourceOf(@intCast(slot)) != null);
    try std.testing.expectEqual(Schema.Source.semantic, Schema.sourceOf(JP.local).?.source);
    try std.testing.expectEqual(Schema.semantic_felts - 1, Schema.sourceOf(JP.eta + 3).?.index);
    const a = std.testing.allocator;
    var dst: std.ArrayListUnmanaged(u32) = .empty;
    var idx: std.ArrayListUnmanaged(u32) = .empty;
    try Schema.appendSlots(a, &dst, &idx, &.{ JP.cpu_steps, JP.ram + 2, JP.local + 1, JP.wire }, 40, .shared);
    var p = try Schema.patchOf(a, &dst, &idx);
    defer p.deinit(a);
    try std.testing.expectEqualSlices(u32, &.{ 40 + 8, 40 + 24 }, p.dst);
    try std.testing.expectEqualSlices(u32, &.{ 2, JP.wire - JP.ram }, p.index);
    try Schema.appendSlots(a, &dst, &idx, &.{ JP.cpu_steps, JP.ram + 2, JP.first_id }, 0, .public);
    var q = try Schema.patchOf(a, &dst, &idx);
    defer q.deinit(a);
    try std.testing.expectEqualSlices(u32, &.{ 0, 16 }, q.dst);
    try std.testing.expectEqualSlices(u32, &.{ JP.cpu_steps, JP.first_id }, q.index);
}

test "patch tables fail closed on an out-of-range source felt or target word" {
    var dst = [_]u32{ 0, 16 };
    var idx = [_]u32{ 1, Schema.shared_felts - 1 };
    const p = Schema.Patch{ .dst = &dst, .index = &idx };
    try p.check(Schema.shared_felts, 24);
    try std.testing.expectError(error.NativeStage2PatchTable, p.check(Schema.shared_felts, 23));
    try std.testing.expectError(error.NativeStage2PatchTable, p.check(Schema.shared_felts - 1, 24));
    // hc rows beyond the namespace felts are in range only when the class
    // declares them in semantic_words.
    var hdst = [_]u32{0};
    var hidx = [_]u32{Schema.semantic_felts + 3};
    const set = Schema.PatchSet{ .semantic = .{ .dst = &hdst, .index = &hidx } };
    try std.testing.expectError(error.NativeStage2PatchTable, set.check(8 * @as(usize, Schema.semantic_felts), 8));
    try set.check(8 * (@as(usize, Schema.semantic_felts) + 4), 8);
}

test "class image and views agree on the per-set, per-source table layout" {
    const a = std.testing.allocator;
    var prog = [_]u32{ 1, 2, 3 };
    var d0 = [_]u32{ 8, 16 };
    var x0 = [_]u32{ 4, 5 };
    var d1 = [_]u32{24};
    var x1 = [_]u32{6};
    var d2 = [_]u32{ 32, 40, 48 };
    var x2 = [_]u32{ 7, 8, 9 };
    var globals = [_]Schema.PatchSet{.{ .shared = .{ .dst = &d0, .index = &x0 }, .public = .{ .dst = &d1, .index = &x1 } }};
    var fr: Schema.ClassFraming = undefined;
    fr.program = .{ .a = a, .words = &prog, .max_encoded_bytes = 0, .pcs_words = 0 };
    fr.global_patches = &globals;
    fr.comp_patches = .{ .semantic = .{ .dst = &d2, .index = &x2 } };
    fr.oods = null;
    const img = try fr.image(a);
    defer a.free(img);
    try std.testing.expectEqual(fr.deviceWords(), img.len);
    const v = try fr.views(a, .{ .ptr = img.ptr, .words = img.len });
    defer a.free(v.globals);
    const at = struct {
        fn f(b: api.DeviceBuffer) []const u32 {
            return b.ptr[0..b.words];
        }
    }.f;
    try std.testing.expectEqualSlices(u32, &prog, at(v.program));
    try std.testing.expectEqualSlices(u32, &d0, at(v.globals[0][0].dst));
    try std.testing.expectEqualSlices(u32, &x0, at(v.globals[0][0].index));
    try std.testing.expectEqual(@as(usize, 0), v.globals[0][1].dst.words);
    try std.testing.expectEqualSlices(u32, &d1, at(v.globals[0][2].dst));
    try std.testing.expectEqualSlices(u32, &x1, at(v.globals[0][2].index));
    try std.testing.expectEqualSlices(u32, &d2, at(v.composition[1].dst));
    try std.testing.expectEqualSlices(u32, &x2, at(v.composition[1].index));
    try std.testing.expectEqual(@as(usize, 0), v.composition[0].dst.words);
}

test "seal frames two-stage truth roots from Exchange.truthRoot (after the seal slot) like segment roots" {
    const a = std.testing.allocator;
    const Chain = CPU.rv64_gkr_chain;
    const identity = try Chain.versionIdentity(.m6_v2_gkr);
    const execution: [32]u8 = @splat(0x24);
    var roster: [6]Schema.RosterEntry = undefined;
    var workers: [6]Manifest.ExpectedWorker = undefined;
    var stages: [6]Manifest.StageOne = undefined;
    testRoster(5, 6, &roster, &workers, &stages);
    // Entries 4 and 5 are truths 0 and 1 (manifest ordinal = cpu count + t),
    // produced on GPU 1 and 0.
    roster[4].segment = null;
    roster[4].truth = 0;
    roster[4].truth_device = 1;
    roster[5].segment = null;
    roster[5].truth = 1;
    var pending = try Manifest.verifyAndSealFor(.m6_v2_gkr, a, execution, &workers, &stages);
    defer pending.deinit(a);
    const ex = G.Exchange{ .segments = 4, .claims_per_segment = 2, .devices = 2, .truths = 2 };
    try ex.validate();
    const entries = try Schema.sealEntries(a, &roster, ex);
    defer a.free(entries);
    const seal = ex.seal();
    for (entries[4..], 0..) |e, t| {
        const slot = try ex.truthRoot(@intCast(t));
        try std.testing.expectEqual(@as(u32, @intCast(slot.offset)), e.root_offset);
        try std.testing.expectEqual(@as(u32, @intCast(slot.flag)), e.flag_offset);
        // Laid out after the seal slot: the kernel's tail custody range.
        try std.testing.expect(e.root_offset >= seal.offset + seal.words and e.root_offset + 8 <= ex.words());
        try std.testing.expect(e.flag_offset < seal.offset);
    }
    var roots: [6][8]u32 = undefined;
    for (&roots, roster) |*r, e| r.* = Schema.words8(e.root);
    const k = Schema.sealConstants(identity, execution, 6, 3);
    try std.testing.expectEqualSlices(u32, &Schema.words8(pending.digest), &hostChi(k, entries, &roots));
    // The seal awaits each truth slot from its producer.
    const awaits = try Schema.truthAwaits(a, &roster, ex, 2);
    defer a.free(awaits);
    try std.testing.expectEqual(@as(usize, 2), awaits.len);
    try std.testing.expectEqual(@as(u32, 1), awaits[0].device);
    try std.testing.expectEqual((try ex.truthRoot(1)).offset, awaits[1].slot.offset);
    try std.testing.expectError(error.GpuNativeSealDeviceOutOfRange, Schema.truthAwaits(a, &roster, ex, 1));
    // A truth slot the exchange has no capacity for, or a doubly-rooted entry, fails closed.
    const ex1 = G.Exchange{ .segments = 4, .claims_per_segment = 2, .devices = 2, .truths = 1 };
    try std.testing.expectError(error.GpuNativeExchangeSlot, Schema.sealEntries(a, &roster, ex1));
    var both = roster;
    both[4].segment = 0;
    try std.testing.expectError(error.NativeSealRosterRootAmbiguous, Schema.sealEntries(a, &both, ex));
}

test "class image carries the OODS program after the patch tables" {
    const a = std.testing.allocator;
    var prog = [_]u32{ 1, 2 };
    var d0 = [_]u32{8};
    var x0 = [_]u32{4};
    const od = [_]u32{ 9, 8, 7, 6 };
    var fr: Schema.ClassFraming = undefined;
    fr.program = .{ .a = a, .words = &prog, .max_encoded_bytes = 0, .pcs_words = 0 };
    fr.global_patches = &.{};
    fr.comp_patches = .{ .shared = .{ .dst = &d0, .index = &x0 } };
    fr.oods = &od;
    const img = try fr.image(a);
    defer a.free(img);
    try std.testing.expectEqual(fr.deviceWords(), img.len);
    const v = try fr.views(a, .{ .ptr = img.ptr, .words = img.len });
    defer a.free(v.globals);
    try std.testing.expectEqualSlices(u32, &od, v.oods.?.ptr[0..v.oods.?.words]);
    fr.oods = null;
    try std.testing.expectEqual(img.len - od.len, fr.deviceWords());
}

test {
    _ = NO;
}

test "flat seal script reproduces manifest.emitCanonical (v1-flat digest) from exchange slots; faults refuse" {
    const a = std.testing.allocator;
    const OM = @import("stwo_core").fields.om31.OM31;
    const Mm = @import("stwo_core").fields.m31.M31;
    const ex = G.Exchange{ .segments = 3, .claims_per_segment = 4, .devices = 2, .truths = 1, .receipts = true };
    try ex.validate();
    // Slots stay disjoint with receipts (after the truth roots); flags distinct.
    {
        const used = try a.alloc(bool, ex.words());
        defer a.free(used);
        @memset(used, false);
        var slots: std.ArrayListUnmanaged(G.Exchange.Slot) = .empty;
        defer slots.deinit(a);
        for (0..3) |sg| {
            try slots.append(a, try ex.root(@intCast(sg)));
            try slots.append(a, try ex.claims(@intCast(sg)));
            try slots.append(a, try ex.receipt(@intCast(sg)));
        }
        try slots.append(a, try ex.truthRoot(0));
        for (0..2) |dv| try slots.append(a, try ex.partial(@intCast(dv)));
        try slots.append(a, ex.seal());
        for (slots.items) |sl| {
            for (used[sl.offset..][0..sl.words]) |*u| {
                try std.testing.expect(!u.*);
                u.* = true;
            }
            try std.testing.expect(!used[sl.flag] and sl.flag < ex.flagWords());
            used[sl.flag] = true;
        }
        try std.testing.expectEqual(slots.items.len, ex.flagWords());
        try std.testing.expectError(error.GpuNativeExchangeSlot, (G.Exchange{ .segments = 3, .claims_per_segment = 4, .devices = 2 }).receipt(0));
    }
    const tag: u32 = 77;
    var x = try a.alloc(u32, ex.words());
    defer a.free(x);
    @memset(x, 0);
    var prng = std.Random.DefaultPrng.init(42);
    const rng = prng.random();
    var mains: [5][32]u8 = undefined;
    var receipts: [3][32]u8 = undefined;
    var marg: [3][2][2]OM = undefined;
    for (&mains) |*m| rng.bytes(m);
    for (&receipts) |*r| rng.bytes(r);
    for (0..3) |sg| {
        const root = try ex.root(@intCast(sg));
        x[root.flag] = tag;
        @memcpy(x[root.offset..][0..8], &Schema.words8(mains[sg]));
        const rc_ = try ex.receipt(@intCast(sg));
        x[rc_.flag] = tag;
        @memcpy(x[rc_.offset..][0..8], &Schema.words8(receipts[sg]));
        const cl = try ex.claims(@intCast(sg));
        x[cl.flag] = tag;
        for (0..2) |i| for (0..2) |j| {
            var limbs: [8]Mm = undefined;
            for (&limbs) |*l| l.* = Mm.fromCanonical(rng.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus));
            marg[sg][i][j] = OM.fromM31Array(limbs);
            for (limbs, 0..) |l, k| x[cl.offset + 16 * i + 8 * j + k] = l.toU32();
        };
    }
    const tr = try ex.truthRoot(0);
    x[tr.flag] = tag;
    @memcpy(x[tr.offset..][0..8], &Schema.words8(mains[3]));
    var stmts: [5][32]u8 = undefined;
    var fixeds: [5][32]u8 = undefined;
    for (&stmts) |*v| rng.bytes(v);
    for (&fixeds) |*v| rng.bytes(v);
    const kinds = [5]Manifest.Kind{ .cpu, .cpu, .cpu, .keccak, .secp_add };
    var flat: [5]Schema.FlatEntry = undefined;
    for (&flat, 0..) |*e, k| e.* = .{ .kind = @intFromEnum(kinds[k]), .relations = @intCast(k % 8), .mass = .{ k, 2 * k, 3 * k + 1 }, .ordinal = @intCast(k), .statement = stmts[k], .fixed = fixeds[k] };
    flat[0].segment = 0;
    flat[0].local_instances = 2;
    flat[1].segment = 1;
    flat[1].local_instances = 2;
    flat[2].segment = 2;
    flat[3].truth = 0;
    flat[4].main = mains[4];
    const execution: [32]u8 = @splat(0x5a);
    var script = try Schema.FlatScript.build(a, Manifest.PROFILE, execution, &flat, ex);
    defer script.deinit();
    // Reference: manifest.emitCanonical over equivalent entries.
    const L = struct { digest: [32]u8, claims_to_verify_by_instance: []const []const OM };
    const E = struct { kind: Manifest.Kind, global_relations: Manifest.Relations, mass: Manifest.Mass, scope: struct { ordinal: u32, statement: [32]u8, fixed: [32]u8, main: [32]u8 }, local: ?L };
    var slices: [3][2][]const OM = undefined;
    for (0..3) |sg| for (0..2) |i| {
        slices[sg][i] = &marg[sg][i];
    };
    var ref: [5]E = undefined;
    for (&ref, 0..) |*e, k| {
        const bits: u32 = @intCast(k % 8);
        e.* = .{ .kind = kinds[k], .global_relations = .{ .ram = bits & 1 != 0, .kio = bits & 2 != 0, .wire = bits & 4 != 0 }, .mass = .{ .ram = k, .kio = 2 * k, .wire = 3 * k + 1 }, .scope = .{ .ordinal = @intCast(k), .statement = stmts[k], .fixed = fixeds[k], .main = mains[k] }, .local = null };
    }
    ref[0].local = .{ .digest = receipts[0], .claims_to_verify_by_instance = &slices[0] };
    ref[1].local = .{ .digest = receipts[1], .claims_to_verify_by_instance = &slices[1] };
    const Wr = struct {
        hash: Blake = .init(.{}),
        pub fn bytes(self: *@This(), v: []const u8) void {
            self.hash.update(v);
        }
        pub fn integer(self: *@This(), v: anytype) void {
            var e: [8]u8 = undefined;
            std.mem.writeInt(u64, &e, @intCast(v), .little);
            self.hash.update(&e);
        }
        pub fn field(self: *@This(), v: OM) !void {
            for (v.toM31Array()) |c| {
                var e: [4]u8 = undefined;
                std.mem.writeInt(u32, &e, c.v, .little);
                self.hash.update(&e);
            }
        }
    };
    var w = Wr{};
    try Manifest.emitCanonical(execution, &ref, &w);
    var expected: [32]u8 = undefined;
    w.hash.final(&expected);
    switch (script.hostDigest(x, tag)) {
        .digest => |d| try std.testing.expectEqualSlices(u8, &expected, &d),
        .refuse => return error.TestUnexpectedResult,
    }
    // An unlanded receipt slot and a non-canonical marginal refuse.
    const rf = (try ex.receipt(1)).flag;
    x[rf] = tag + 1;
    try std.testing.expectEqual(@as(u16, 1), script.hostDigest(x, tag).refuse);
    x[rf] = tag;
    const cl = try ex.claims(2);
    _ = cl;
    const c0 = try ex.claims(0);
    x[c0.offset + 5] = @import("stwo_core").fields.m31.Modulus;
    try std.testing.expectEqual(Schema.flat_noncanonical, script.hostDigest(x, tag).refuse);
    // Local without a segment root is refused at build.
    var bad = flat;
    bad[3].local_instances = 1;
    try std.testing.expectError(error.NativeSealFlatLocalWithoutSegment, Schema.FlatScript.build(a, Manifest.PROFILE, execution, &bad, ex));
}
test "resident Stage2 columns follow the producer's sorted coefficient layout" {
    const a = std.testing.allocator;
    var fixed = try C.CommitPlan.init(a, &.{ .{ .log_size = 5, .encoding = .coefficients }, .{ .log_size = 3, .encoding = .coefficients }, .{ .log_size = 4, .encoding = .coefficients }, .{ .log_size = 3, .encoding = .coefficients } }, 1);
    defer fixed.deinit();
    var main = try C.CommitPlan.init(a, &.{ .{ .log_size = 4, .encoding = .evaluations }, .{ .log_size = 5, .encoding = .evaluations }, .{ .log_size = 3, .encoding = .evaluations } }, 1);
    defer main.deinit();
    const legacy_fixed = [_]usize{ 0, 32, 40, 56 };
    const legacy_main = [_]usize{ 0, 16, 48 };
    var framing: Schema.ClassFraming = undefined;
    framing.fixed_offsets = &legacy_fixed;
    framing.main_offsets = &legacy_main;
    framing.fixed_words = 64;
    framing.main_words = 56;
    try framing.adoptResidentColumns(&fixed, &main);
    try std.testing.expectEqualSlices(usize, &.{ 32, 0, 16, 8 }, framing.fixed_offsets);
    try std.testing.expectEqualSlices(usize, &.{ 8, 24, 0 }, framing.main_offsets);
    var image: [64]u32 = undefined;
    for (fixed.shapes, fixed.offsets, 0..) |shape, at, i| @memset(image[at..][0 .. @as(usize, 1) << @intCast(shape.log_size)], @intCast(i + 1));
    // Reading by the old framing aliases a different original column.
    try std.testing.expect(image[legacy_fixed[0]] != 1);
    for (framing.fixed_offsets, 0..) |at, i| try std.testing.expectEqual(@as(u32, @intCast(i + 1)), image[at]);
    framing.main_words += 1;
    try std.testing.expectError(error.NativeStage2ResidentColumnsShape, framing.adoptResidentColumns(&fixed, &main));
}

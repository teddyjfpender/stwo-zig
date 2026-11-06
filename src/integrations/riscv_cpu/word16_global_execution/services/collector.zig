//! One chronological hint ledger for ordinary LS and all three service kinds.
//! Neither captured sidecar values nor this ledger grant acceptance authority.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const LS = A.memory.load_store_v2;
const K = A.crypto.keccak.word16_bridge;
const S = A.crypto.secp256k1.word16_bridge;
const BM = A.crypto.bulk_memory;
const Sponge = @import("sponge_collector.zig");
pub const SpongeShard = Sponge.Shard;
/// Admitted bulk-memory calls of one CPU proof (chronological) and the RAM
/// predecessors of every touched data word, concatenated in call order.
pub const BulkShard = struct {
    calls: []BM.types.Call = &.{},
    words: []BM.types.Word = &.{},
    pub fn counts(self: BulkShard) @import("types.zig").BulkCounts {
        var out = @import("types.zig").BulkCounts{};
        for (self.calls) |c| switch (c.body()) {
            .copy => out.copy_words += c.entries(),
            .set => out.set_words += c.entries(),
            .ucopy => out.ucopy_rows += c.entries(),
            .cmp => out.cmp_words += c.entries(),
            .jscan => out.jump_rows += c.bodyRows(),
            .desc, .cdesc, .jdesc, .jtab => unreachable,
        };
        for (self.calls) |c| switch (c.op) {
            .cmp => out.cmp_calls += 1,
            .jumpdest => out.jump_calls += 1,
            else => out.calls += 1,
        };
        return out;
    }
    fn deinit(self: BulkShard, a: std.mem.Allocator) void {
        a.free(self.calls);
        a.free(self.words);
    }
};
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const TT = @import("types.zig");
const CurveCalls = [TT.CURVES][]S.types.Call;
const Old = @import("../collector.zig");
const Cell = A.memory.closed_ram.types.Cell;
pub const Advice = struct {
    allocator: std.mem.Allocator,
    events: [][]LS.native.Event,
    keccak: [][]K.types.Call,
    secp: [][2][]S.types.Call,
    /// Admitted v3 SHA-256 packets per shard (empty for v2 tapes).
    sha256: [][]S.types.Call,
    /// Admitted v3 arith256_mod packets per shard (empty for v2 tapes).
    arith256_mod: [][]S.types.Call,
    /// Admitted v3 curve/field packets per shard, per op (curves.Op order).
    curves: []CurveCalls,
    bulk: []BulkShard,
    /// Admitted Keccak-sponge calls per shard (empty unless v3).
    sponge: []SpongeShard,
    initial: []Cell,
    terminal: []Cell,
    /// Explicit destructive owner seam. No source may borrow this ordinal's
    /// events when called; service calls and public cell owners are untouched.
    /// Emptying the slot before freeing makes later owner cleanup idempotent.
    pub fn retireEvents(self: *const Advice, ordinal: usize) !usize {
        if (ordinal >= self.events.len) return error.InvalidCombinedOrdinal;
        const events = self.events[ordinal];
        const bytes = std.mem.sliceAsBytes(events).len;
        self.events[ordinal] = &.{};
        self.allocator.free(events);
        return bytes;
    }
    pub fn deinit(self: *Advice) void {
        const a = self.allocator;
        for (self.bulk) |b| b.deinit(a);
        a.free(self.bulk);
        for (self.sponge) |b| b.deinit(a);
        a.free(self.sponge);
        for (self.events) |e| a.free(e);
        for (self.keccak) |c| a.free(c);
        for (self.secp) |cc| for (cc) |c| a.free(c);
        for (self.sha256) |c| a.free(c);
        for (self.arith256_mod) |c| a.free(c);
        for (self.curves) |cc| for (cc) |c| a.free(c);
        a.free(self.events);
        a.free(self.keccak);
        a.free(self.secp);
        a.free(self.sha256);
        a.free(self.arith256_mod);
        a.free(self.curves);
        a.free(self.initial);
        a.free(self.terminal);
    }
};
/// Append one packet, then release its tape. A failed append poisons this
/// builder: discard it rather than retrying a partially updated RAM ledger.
pub const Builder = struct {
    allocator: std.mem.Allocator,
    ledger: Old.Ledger,
    shards: std.ArrayList(Shard) = .{},
    failed: bool = false,
    finished: bool = false,
    pub fn init(a: std.mem.Allocator, image: @import("../../word16_execution/memory/statement.zig").Image) Builder {
        return .{ .allocator = a, .ledger = Old.Ledger.init(a, image) };
    }
    pub fn deinit(self: *Builder) void {
        if (!self.finished) for (self.shards.items) |shard| shard.deinit(self.allocator);
        self.shards.deinit(self.allocator);
        self.ledger.deinit();
    }
    pub fn append(self: *Builder, native: *Native, tape: *const front.rv64.compact_tape.Tape) !void {
        var none: ?[]LS.native.Event = null;
        return self.appendWithEvents(native, tape, &none);
    }
    /// `append` with an optional caller-prepared LS event array (see
    /// `prepareEvents`): taken (set to null) once the shard owns it; left for
    /// the caller to free if the append fails before taking it. Its contents
    /// are fully overwritten, so outputs are identical to `append`.
    pub fn appendWithEvents(self: *Builder, native: *Native, tape: *const front.rv64.compact_tape.Tape, events: *?[]LS.native.Event) !void {
        if (self.failed or self.finished) return error.InvalidServiceCollectorPhase;
        errdefer self.failed = true;
        if (self.shards.items.len >= 65535) return error.InvalidCombinedServiceRoster;
        try self.shards.ensureUnusedCapacity(self.allocator, 1);
        var profile: Profile = .{};
        const profiling = profileEnabled();
        first_touch_profile = profiling;
        const start = if (profiling) std.time.Instant.now() catch null else null;
        const shard = try one(self.allocator, &self.ledger, native, tape, self.shards.items.len, if (profiling) &profile else null, events);
        self.shards.appendAssumeCapacity(shard);
        if (start) |t0| if (std.time.Instant.now()) |t1| profile.report(self.shards.items.len - 1, t1.since(t0), &self.ledger) else |_| {};
    }
    /// LS events of the shard appended last (borrowed until `finish`
    /// transfers them into `Advice`, which keeps the same allocation).
    pub fn lastEvents(self: *const Builder) []const LS.native.Event {
        if (self.shards.items.len == 0) return &.{};
        return self.shards.items[self.shards.items.len - 1].events;
    }
    /// Borrowed slice owners are stable through finish/Advice destruction;
    /// the Shard header itself is returned by value, never a pointer into the
    /// builder's resizable array.
    pub fn lastShard(self: *const Builder) !Shard {
        if (self.shards.items.len == 0) return error.InvalidServiceCollectorPhase;
        return self.shards.items[self.shards.items.len - 1];
    }
    /// M8 two-phase ledger, phase 2 (ordered thread): merge a segment built
    /// off this thread by `prepareLocal`, touching only its first-touched
    /// addresses, then patch the placeholder predecessor clocks in its shard.
    /// Takes ownership of `local`. Any disagreement with the global ledger
    /// (value or rights of a first-touched word, a non-adjacent index, a
    /// lookup failure) discards `local` and runs the serial `append` for this
    /// segment from the unchanged global ledger, so outputs and errors are
    /// exactly the serial ones. `events` is passed through to that fallback.
    pub fn appendLocal(self: *Builder, local: *Local, native: *Native, tape: *const front.rv64.compact_tape.Tape, events: *?[]LS.native.Event) !void {
        if (self.failed or self.finished) {
            local.deinit(self.allocator);
            return error.InvalidServiceCollectorPhase;
        }
        if (self.shards.items.len >= 65535) {
            local.deinit(self.allocator);
            return error.InvalidCombinedServiceRoster;
        }
        self.shards.ensureUnusedCapacity(self.allocator, 1) catch |err| {
            local.deinit(self.allocator);
            self.failed = true;
            return err;
        };
        if (self.mergeLocal(local) catch false) {
            self.shards.appendAssumeCapacity(local.shard);
            local.shard = undefined;
            local.ledger.deinit();
            local_stats.merged += 1;
            return;
        }
        local.deinit(self.allocator);
        local_stats.fallbacks += 1;
        return self.appendWithEvents(native, tape, events);
    }
    /// True once `local` is merged into the global ledger (its shard patched
    /// and ready to append); false (global ledger untouched) to fall back.
    fn mergeLocal(self: *Builder, local: *Local) !bool {
        const a = self.allocator;
        if (local.index != self.shards.items.len) return false;
        if (local.index == 0) {
            // Segment 0 ran the serial code on an empty ledger with the same
            // image and first-touch source: adopt it wholesale.
            if (self.ledger.states.count() != 0 or self.ledger.initial.items.len != 0) return false;
            std.mem.swap(Old.StateTable, &self.ledger.states, &local.ledger.states);
            std.mem.swap(std.ArrayList(Cell), &self.ledger.initial, &local.ledger.initial);
            return true;
        }
        const touched = local.ledger.initial.items;
        if (touched.len >= std.math.maxInt(u24)) return false;
        const resolved_at = std.time.Instant.now() catch null;
        // Pass A, read only: the global state each first touch stands for.
        const global = try a.alloc(A.memory.closed_ram.types.State, touched.len);
        defer a.free(global);
        const fresh = try a.alloc(bool, touched.len);
        defer a.free(fresh);
        for (touched, global, fresh, 0..) |cell, *g, *f, i| {
            if (cell.state.epoch != 0 or cell.state.tick != i + 1) return false;
            if (self.ledger.states.get(cell.address)) |state| {
                g.* = state;
                f.* = false;
            } else {
                const fast = if (self.ledger.pages) |*pages| pages.lookup(cell.address) else null;
                g.* = fast orelse .{ .value = try self.ledger.image.initialWord(cell.address), .rights = try self.ledger.image.wordRights(cell.address) };
                f.* = true;
            }
            if (g.value != cell.state.value or g.rights != cell.state.rights) return false;
        }
        // Pass B: global exit states (first-touch order, as the serial ledger
        // appends new INITIAL cells), then the placeholder clocks.
        try self.ledger.initial.ensureUnusedCapacity(a, touched.len);
        for (touched, global, fresh) |cell, g, f| {
            const exit = local.ledger.states.get(cell.address) orelse return error.InvalidServiceCollectorPhase;
            const entry = try self.ledger.states.getOrPut(a, cell.address);
            if (f) {
                if (entry.found_existing) return error.InvalidServiceCollectorPhase;
                self.ledger.initial.appendAssumeCapacity(.{ .address = cell.address, .state = g });
            }
            // An exit with epoch 0 was never written by this segment.
            entry.value_ptr.* = if (exit.epoch == 0) g else exit;
        }
        const patch_at = std.time.Instant.now() catch null;
        patchShard(&local.shard, global);
        if (patch_at) |t1| if (std.time.Instant.now()) |t2| {
            local_stats.patch_ns += t2.since(t1);
            if (resolved_at) |t0| local_stats.resolve_ns += t1.since(t0);
        } else |_| {};
        local_stats.touched += touched.len;
        return true;
    }
    pub fn finish(self: *Builder) !Advice {
        if (self.failed or self.finished or self.shards.items.len == 0) return error.InvalidServiceCollectorPhase;
        const a = self.allocator;
        // Allocate every output header and both boundaries before transferring
        // any shard arrays. A finish failure remains safely retryable.
        const events = try a.alloc([]LS.native.Event, self.shards.items.len);
        errdefer a.free(events);
        const keccak = try a.alloc([]K.types.Call, self.shards.items.len);
        errdefer a.free(keccak);
        const secp = try a.alloc([2][]S.types.Call, self.shards.items.len);
        errdefer a.free(secp);
        const sha256 = try a.alloc([]S.types.Call, self.shards.items.len);
        errdefer a.free(sha256);
        const arith = try a.alloc([]S.types.Call, self.shards.items.len);
        errdefer a.free(arith);
        const curves = try a.alloc(CurveCalls, self.shards.items.len);
        errdefer a.free(curves);
        const bulk = try a.alloc(BulkShard, self.shards.items.len);
        errdefer a.free(bulk);
        const sponge = try a.alloc(SpongeShard, self.shards.items.len);
        errdefer a.free(sponge);
        const boundaries = try self.ledger.boundaries();
        for (self.shards.items, events, keccak, secp, sha256, arith, curves, bulk, sponge) |shard, *e, *k, *s, *h, *r, *c, *b, *z| {
            z.* = shard.sponge;
            r.* = shard.arith256_mod;
            c.* = shard.curves;
            e.* = shard.events;
            k.* = shard.keccak;
            s.* = shard.secp;
            h.* = shard.sha256;
            b.* = shard.bulk;
        }
        self.finished = true;
        return .{ .allocator = a, .events = events, .keccak = keccak, .secp = secp, .sha256 = sha256, .arith256_mod = arith, .curves = curves, .bulk = bulk, .sponge = sponge, .initial = boundaries.initial, .terminal = boundaries.terminal };
    }
};
pub fn collect(a: std.mem.Allocator, prepared: []const *Native, tapes: []const *const front.rv64.compact_tape.Tape, image: @import("../../word16_execution/memory/statement.zig").Image) !Advice {
    if (prepared.len == 0 or prepared.len != tapes.len or prepared.len > 65535) return error.InvalidCombinedServiceRoster;
    var builder = Builder.init(a, image);
    defer builder.deinit();
    for (prepared, tapes) |native, tape| try builder.append(native, tape);
    return builder.finish();
}
/// Report-only ledger cost attribution (STWO_RV64_CAPTURE_LEDGER_PROFILE=1):
/// per service family, calls and wall ns spent inside the serial ledger.
/// Never enters an output; stderr only.
const Profile = struct {
    const names = [_][]const u8{ "keccak", "secp", "sha256", "arith256", "sponge", "curves", "bulk", "jumpdest", "alloc" };
    calls: [names.len]u64 = @splat(0),
    ns: [names.len]u64 = @splat(0),
    ls: u64 = 0,
    fn add(self: ?*Profile, kind: usize, start: ?std.time.Instant) void {
        const p = self orelse return;
        const t0 = start orelse return;
        const t1 = std.time.Instant.now() catch return;
        p.calls[kind] += 1;
        p.ns[kind] += t1.since(t0);
    }
    fn report(self: *const Profile, index: usize, total_ns: u64, ledger: *const Old.Ledger) void {
        var services: u64 = 0;
        for (self.ns) |n| services += n;
        std.debug.print("CAPTURE_LEDGER_PROFILE shard={d} total_ns={d} ls_records={d} ls_and_dispatch_ns={d} table_words={d} table_bytes={d} first_touch={d}/{d}ns", .{ index, total_ns, self.ls, total_ns -| services, ledger.states.count(), ledger.states.storageBytes(), first_touch_count, first_touch_ns });
        first_touch_count = 0;
        first_touch_ns = 0;
        for (names, self.calls, self.ns) |name, c, n| std.debug.print(" {s}={d}/{d}ns", .{ name, c, n });
        std.debug.print("\n", .{});
    }
};
fn profileEnabled() bool {
    const value = std.posix.getenv("STWO_RV64_CAPTURE_LEDGER_PROFILE") orelse return false;
    return value.len != 0 and value[0] != '0';
}
fn mark(profile: ?*Profile) ?std.time.Instant {
    if (profile == null) return null;
    return std.time.Instant.now() catch null;
}
pub const Shard = struct {
    events: []LS.native.Event,
    keccak: []K.types.Call,
    secp: [2][]S.types.Call,
    sha256: []S.types.Call,
    arith256_mod: []S.types.Call,
    curves: CurveCalls,
    bulk: BulkShard = .{},
    sponge: SpongeShard = .{},
    fn deinit(self: Shard, a: std.mem.Allocator) void {
        a.free(self.events);
        a.free(self.keccak);
        for (self.secp) |calls| a.free(calls);
        a.free(self.sha256);
        a.free(self.arith256_mod);
        for (self.curves) |c| a.free(c);
        self.bulk.deinit(a);
        self.sponge.deinit(a);
    }
};
/// Non-owning one-segment source view for local class/MAIN construction.
/// Keep this header in a stable owner through all consumers; never deinit the
/// returned Advice (the original ordered collector owns its payload slices).
pub const OneShardView = struct {
    events: [1][]LS.native.Event,
    keccak: [1][]K.types.Call,
    secp: [1][2][]S.types.Call,
    sha256: [1][]S.types.Call,
    arith256_mod: [1][]S.types.Call,
    curves: [1]CurveCalls,
    bulk: [1]BulkShard,
    sponge: [1]SpongeShard,
    pub fn init(shard: Shard) OneShardView {
        return .{ .events = .{shard.events}, .keccak = .{shard.keccak}, .secp = .{shard.secp}, .sha256 = .{shard.sha256}, .arith256_mod = .{shard.arith256_mod}, .curves = .{shard.curves}, .bulk = .{shard.bulk}, .sponge = .{shard.sponge} };
    }
    pub fn advice(self: *OneShardView, a: std.mem.Allocator, initial: []Cell, terminal: []Cell) Advice {
        return .{ .allocator = a, .events = &self.events, .keccak = &self.keccak, .secp = &self.secp, .sha256 = &self.sha256, .arith256_mod = &self.arith256_mod, .curves = &self.curves, .bulk = &self.bulk, .sponge = &self.sponge, .initial = initial, .terminal = terminal };
    }
};
/// Allocates the LS event array one CPU proof's shard will fill, already
/// backed by memory: every page is touched (huge pages only where
/// `hugePageAdvice` allows), so the serial ledger never takes first-touch faults on it. Call it
/// off the ordered thread (e.g. on the capture job that produced `native`).
/// Producer scheduling only; the contents are undefined until the ledger
/// writes every element.
pub fn prepareEvents(a: std.mem.Allocator, native: *const Native) ![]LS.native.Event {
    const cpu = native.cpu orelse return error.PreparedExecutionConsumed;
    const events = try a.alloc(LS.native.Event, cpu.memory.items.len);
    prefault(std.mem.sliceAsBytes(events));
    return events;
}
/// Whether `prefault` may request transparent huge pages. `MADV_HUGEPAGE`
/// makes a first-touch fault compact memory synchronously whenever the
/// kernel's THP defrag mode is `always`, `madvise` or `defer+madvise`; on a
/// fragmented host that stalled capture (24697070: 5.7 -> 12.1 s, M4). So by
/// default advise only where it cannot stall: defrag `defer` or `never`.
/// `STWO_RV64_CAPTURE_THP=1` forces the advice, `=0` disables it.
/// Producer scheduling only (page backing, never contents).
pub fn hugePageAdvice() bool {
    const cached = thp_policy.load(.monotonic);
    if (cached != 0) return cached == 2;
    const allowed = thpAllowed();
    thp_policy.store(if (allowed) 2 else 1, .monotonic);
    return allowed;
}
var thp_policy = std.atomic.Value(u8).init(0);
fn thpAllowed() bool {
    if (std.posix.getenv("STWO_RV64_CAPTURE_THP")) |value| {
        if (value.len != 0 and value[0] == '1') return true;
        if (value.len != 0 and value[0] == '0') return false;
    }
    if (@import("builtin").os.tag != .linux) return false;
    var buffer: [256]u8 = undefined;
    const file = std.fs.openFileAbsolute("/sys/kernel/mm/transparent_hugepage/defrag", .{}) catch return false;
    defer file.close();
    const n = file.readAll(&buffer) catch return false;
    return defragAllowsAdvice(buffer[0..n]);
}
/// `text` is the sysfs defrag line, e.g. "always defer defer+madvise [madvise] never".
pub fn defragAllowsAdvice(text: []const u8) bool {
    const open = std.mem.indexOfScalar(u8, text, '[') orelse return false;
    const close = std.mem.indexOfScalarPos(u8, text, open, ']') orelse return false;
    const mode = text[open + 1 .. close];
    return std.mem.eql(u8, mode, "defer") or std.mem.eql(u8, mode, "never");
}
test "THP advice only where the defrag mode never compacts synchronously" {
    try std.testing.expect(!defragAllowsAdvice("always defer defer+madvise [madvise] never\n"));
    try std.testing.expect(!defragAllowsAdvice("[always] defer defer+madvise madvise never\n"));
    try std.testing.expect(!defragAllowsAdvice("always defer [defer+madvise] madvise never\n"));
    try std.testing.expect(defragAllowsAdvice("always [defer] defer+madvise madvise never\n"));
    try std.testing.expect(defragAllowsAdvice("always defer defer+madvise madvise [never]\n"));
    try std.testing.expect(!defragAllowsAdvice(""));
}
fn prefault(bytes: []u8) void {
    const page = 4096;
    if (bytes.len == 0) return;
    if (@import("builtin").os.tag == .linux and bytes.len >= 4 << 20) {
        const start = std.mem.alignForward(usize, @intFromPtr(bytes.ptr), page);
        const end = std.mem.alignBackward(usize, @intFromPtr(bytes.ptr) + bytes.len, page);
        if (end > start and hugePageAdvice()) {
            const ptr: [*]align(page) u8 = @ptrFromInt(start);
            // Advisory only: failure leaves ordinary 4 KiB pages.
            std.posix.madvise(ptr, end - start, std.posix.MADV.HUGEPAGE) catch {};
        }
    }
    var i: usize = 0;
    while (i < bytes.len) : (i += page) @as(*volatile u8, &bytes[i]).* = 0;
    @as(*volatile u8, &bytes[bytes.len - 1]).* = 0;
}
fn one(a: std.mem.Allocator, ledger: *Old.Ledger, native: *Native, tape: *const front.rv64.compact_tape.Tape, index: usize, profile: ?*Profile, prepared: *?[]LS.native.Event) !Shard {
    const cpu = native.cpu orelse return error.PreparedExecutionConsumed;
    if (cpu.capture_records_retired) return error.MissingPreparedMemoryRecords;
    // v3 is v2 plus SHA-256 and bulk memory; a v2 tape can never carry a v3 record.
    // Bulk calls have no tape payload (the ECALL step is the call), so they are
    // counted from the CPU's own service records.
    const v3 = front.rv64.execution_profile.isV3(tape.execution_profile);
    var bulk_records: usize = 0;
    if (v3) for (cpu.services.items) |rec| {
        bulk_records += @intFromBool(isBulkTag(rec.tag) or rec.tag == Sponge.TAG);
    };
    if ((tape.execution_profile != .ethereum_services_v2 and !v3) or cpu.epoch != index + 1 or cpu.services.items.len != tape.serviceCount() + bulk_records) return error.InvalidCombinedServiceRoster;
    var bulk_calls: std.ArrayList(BM.types.Call) = .empty;
    errdefer bulk_calls.deinit(a);
    var bulk_words: std.ArrayList(BM.types.Word) = .empty;
    errdefer bulk_words.deinit(a);
    var sponge: Sponge.Builder = .{};
    defer sponge.deinit(a);
    var sizes: [2]usize = @splat(0);
    for (tape.secp_calls.items) |call| sizes[@intFromEnum(call.kind) - 1] += 1;
    const alloc_start = mark(profile);
    const ee = take: {
        if (prepared.*) |events| {
            prepared.* = null;
            if (events.len == cpu.memory.items.len) break :take events;
            a.free(events);
        }
        break :take try a.alloc(LS.native.Event, cpu.memory.items.len);
    };
    errdefer a.free(ee);
    Profile.add(profile, 8, alloc_start);
    if (profile) |p| p.ls = ee.len;
    // The ledger's paged state table allocates pages on demand: no capacity
    // hint (the former hash map grew and rehashed here once per shard).
    const kk = try a.alloc(K.types.Call, tape.service_calls.items.len);
    errdefer a.free(kk);
    const aa = try a.alloc(S.types.Call, sizes[0]);
    errdefer a.free(aa);
    const dd = try a.alloc(S.types.Call, sizes[1]);
    errdefer a.free(dd);
    const ss = [2][]S.types.Call{ aa, dd };
    const hh = try a.alloc(S.types.Call, tape.sha256_calls.items.len);
    errdefer a.free(hh);
    var hi: usize = 0;
    const rr = try a.alloc(S.types.Call, tape.arith256_mod_calls.items.len);
    errdefer a.free(rr);
    var ri: usize = 0;
    var curve_sizes: [TT.CURVES]usize = @splat(0);
    for (tape.curve_calls.items) |call| curve_sizes[TT.curveIndex(call.op)] += 1;
    var cc: CurveCalls = @splat(&.{});
    var cc_made: usize = 0;
    errdefer for (cc[0..cc_made]) |c| a.free(c);
    for (&cc, curve_sizes) |*c, n| {
        c.* = try a.alloc(S.types.Call, n);
        cc_made += 1;
    }
    var curve_next: [TT.CURVES]usize = @splat(0);
    var ui: usize = 0;
    var next: [2]usize = @splat(0);
    var mi: usize = 0;
    var ci: usize = 0;
    var ki: usize = 0;
    var si: usize = 0;
    var previous: u24 = 0;
    // OWNER tick stride of this CPU's encoding (4, or 1 under the wide clock).
    const stride: u32 = A.word16_execution.layout.ramStride(cpu.log_size);
    while (mi < ee.len or ci < cpu.services.items.len) {
        const mt = if (mi < ee.len) cpu.memory.items[mi].tick else std.math.maxInt(u24);
        const ct = if (ci < cpu.services.items.len) cpu.services.items[ci].tick else std.math.maxInt(u24);
        if (mt == ct or @min(mt, ct) <= previous) return error.InvalidCombinedServiceChronology;
        previous = @min(mt, ct);
        if (mt < ct) {
            const rec = cpu.memory.items[mi];
            const desc = try LS.native.describe(rec.opcode);
            const ea = rec.a +% rec.immediate;
            const address = ea & ~@as(u64, 7);
            if (rec.epoch != cpu.epoch or rec.tick % stride != 0 or rec.effect.address.toInt() != ea or rec.effect.width != desc.width or rec.effect.write != desc.write) return error.InvalidMemoryRecordEffect;
            // One lookup: no other ledger insert happens before the write.
            const state = try slot(ledger, address);
            const before = state.*;
            if (before.value != rec.effect.before_word.toInt()) return error.InconsistentCapturedMemoryBefore;
            const after = A.memory.closed_ram.types.State{ .value = rec.effect.after_word.toInt(), .epoch = cpu.epoch, .tick = rec.tick, .rights = before.rights };
            ee[mi] = .{ .opcode = rec.opcode, .a = rec.a, .b = rec.b, .c = rec.c, .immediate = rec.immediate, .epoch = cpu.epoch, .tick = rec.tick, .before = before, .after = after };
            try LS.native.validate(ee[mi]);
            state.* = after;
            mi += 1;
        } else {
            const rec = cpu.services.items[ci];
            const service_start = mark(profile);
            defer Profile.add(profile, serviceKind(v3, rec.tag), service_start);
            if (rec.epoch != cpu.epoch or rec.tick % stride != 0) return error.InvalidCombinedServiceOwner;
            if (rec.tag == 0x10001) {
                if (ki >= kk.len) return error.InvalidCombinedServiceOwner;
                const captured = tape.service_calls.items[ki];
                if (rec.pointer & 7 != 0 or rec.pointer > std.math.maxInt(u64) - 199) return error.InvalidCombinedServiceOwner;
                try owner(rec.pointer, rec.tick, stride, tape, captured.pointer, captured.clock);
                var call: K.types.Call = .{ .pointer = rec.pointer, .epoch = cpu.epoch, .tick = rec.tick, .before = captured.before, .after = captured.after, .predecessors = undefined };
                for (0..25) |lane| call.predecessors[lane] = try get(ledger, rec.pointer + 8 * lane);
                try K.source.validate(call);
                for (0..25) |lane| ledger.states.getPtr(rec.pointer + 8 * lane).?.* = .{ .value = call.after[lane], .epoch = call.epoch, .tick = call.tick, .rights = call.predecessors[lane].rights };
                kk[ki] = call;
                ki += 1;
            } else if (rec.tag == 0x20011 or rec.tag == 0x20012) {
                if (si >= tape.secp_calls.items.len) return error.InvalidCombinedServiceOwner;
                const captured = tape.secp_calls.items[si];
                if (rec.pointer & 31 != 0 or rec.pointer > std.math.maxInt(u64) - (8 * captured.wordCount() - 1)) return error.InvalidCombinedServiceOwner;
                if (captured.packet_format != .little_endian_words_v2 or captured.tag() != rec.tag) return error.InvalidCombinedServiceOwner;
                try owner(rec.pointer, rec.tick, stride, tape, captured.pointer, captured.clock);
                var call: S.types.Call = .{ .pointer = rec.pointer, .epoch = cpu.epoch, .tick = rec.tick, .before = captured.before, .after = captured.after, .predecessors = @splat(.{ .value = 0, .rights = 0 }) };
                for (0..captured.wordCount()) |lane| call.predecessors[lane] = try get(ledger, rec.pointer + 8 * lane);
                try S.source.validate(S.types.kindOf(captured.kind), call);
                for (0..captured.wordCount()) |lane| ledger.states.getPtr(rec.pointer + 8 * lane).?.* = .{ .value = call.after[lane], .epoch = call.epoch, .tick = call.tick, .rights = call.predecessors[lane].rights };
                const family = @intFromEnum(captured.kind) - 1;
                ss[family][next[family]] = call;
                next[family] += 1;
                si += 1;
            } else if (v3 and rec.tag == 0x30010) {
                if (hi >= hh.len) return error.InvalidCombinedServiceOwner;
                const captured = tape.sha256_calls.items[hi];
                const words = @TypeOf(captured).WORDS;
                if (rec.pointer & 31 != 0 or rec.pointer > std.math.maxInt(u64) - (8 * words - 1)) return error.InvalidCombinedServiceOwner;
                try owner(rec.pointer, rec.tick, stride, tape, captured.pointer, captured.clock);
                var call: S.types.Call = .{ .pointer = rec.pointer, .epoch = cpu.epoch, .tick = rec.tick, .before = @splat(0), .after = @splat(0), .predecessors = @splat(.{ .value = 0, .rights = 0 }) };
                call.before[0..words].* = captured.before;
                call.after[0..words].* = captured.after;
                for (0..words) |lane| call.predecessors[lane] = try get(ledger, rec.pointer + 8 * lane);
                try S.source.validate(.sha256, call);
                for (0..words) |lane| ledger.states.getPtr(rec.pointer + 8 * lane).?.* = .{ .value = call.after[lane], .epoch = call.epoch, .tick = call.tick, .rights = call.predecessors[lane].rights };
                hh[hi] = call;
                hi += 1;
            } else if (v3 and rec.tag == 0x30021) {
                if (ri >= rr.len) return error.InvalidCombinedServiceOwner;
                const captured = tape.arith256_mod_calls.items[ri];
                const words = @TypeOf(captured).WORDS;
                if (rec.pointer & 31 != 0 or rec.pointer > std.math.maxInt(u64) - (8 * words - 1)) return error.InvalidCombinedServiceOwner;
                try owner(rec.pointer, rec.tick, stride, tape, captured.pointer, captured.clock);
                var call: S.types.Call = .{ .pointer = rec.pointer, .epoch = cpu.epoch, .tick = rec.tick, .before = @splat(0), .after = @splat(0), .predecessors = @splat(.{ .value = 0, .rights = 0 }) };
                call.before[0..words].* = captured.before;
                call.after[0..words].* = captured.after;
                for (0..words) |lane| call.predecessors[lane] = try get(ledger, rec.pointer + 8 * lane);
                try S.source.validate(.arith256_mod, call);
                for (0..words) |lane| ledger.states.getPtr(rec.pointer + 8 * lane).?.* = .{ .value = call.after[lane], .epoch = call.epoch, .tick = call.tick, .rights = call.predecessors[lane].rights };
                rr[ri] = call;
                ri += 1;
            } else if (v3 and rec.tag == Sponge.TAG) {
                try sponge.replay(a, ledger, rec.pointer, cpu.epoch, rec.tick, get);
            } else if (v3 and TT.curveOpOfTag(rec.tag) != null) {
                if (ui >= tape.curve_calls.items.len) return error.InvalidCombinedServiceOwner;
                const captured = tape.curve_calls.items[ui];
                const words = captured.wordCount();
                if (captured.tag() != rec.tag or rec.pointer & 31 != 0 or rec.pointer > std.math.maxInt(u64) - (8 * words - 1)) return error.InvalidCombinedServiceOwner;
                try owner(rec.pointer, rec.tick, stride, tape, captured.pointer, captured.clock);
                var call: S.types.Call = .{ .pointer = rec.pointer, .epoch = cpu.epoch, .tick = rec.tick, .before = captured.before, .after = captured.after, .predecessors = @splat(.{ .value = 0, .rights = 0 }) };
                for (0..words) |lane| call.predecessors[lane] = try get(ledger, rec.pointer + 8 * lane);
                try S.source.validate(S.types.curveKind(captured.op), call);
                for (0..words) |lane| ledger.states.getPtr(rec.pointer + 8 * lane).?.* = .{ .value = call.after[lane], .epoch = call.epoch, .tick = call.tick, .rights = call.predecessors[lane].rights };
                const k = TT.curveIndex(captured.op);
                cc[k][curve_next[k]] = call;
                curve_next[k] += 1;
                ui += 1;
            } else if (v3 and isBulkTag(rec.tag)) {
                try bulkCall(a, ledger, rec.pointer, rec.tag, cpu.epoch, rec.tick, &bulk_calls, &bulk_words);
            } else return error.UnqualifiedCombinedServiceTag;
            ci += 1;
        }
    }
    if (ki != kk.len or si != tape.secp_calls.items.len or hi != hh.len or ri != rr.len or ui != tape.curve_calls.items.len) return error.InvalidCombinedServiceRoster;
    const owned_words = try bulk_words.toOwnedSlice(a);
    errdefer a.free(owned_words);
    const bulk = BulkShard{ .calls = try bulk_calls.toOwnedSlice(a), .words = owned_words };
    errdefer bulk.deinit(a);
    const sponge_shard = try sponge.finish(a);
    return .{ .sponge = sponge_shard, .events = ee, .keccak = kk, .secp = ss, .sha256 = hh, .arith256_mod = rr, .curves = cc, .bulk = bulk };
}
fn serviceKind(v3: bool, tag: u64) usize {
    if (tag == 0x10001) return 0;
    if (tag == 0x20011 or tag == 0x20012) return 1;
    if (v3 and tag == 0x30010) return 2;
    if (v3 and tag == 0x30021) return 3;
    if (v3 and tag == Sponge.TAG) return 4;
    if (v3 and TT.curveOpOfTag(tag) != null) return 5;
    if (tag == BM.types.JUMPDEST_TAG) return 7;
    return 6;
}
fn isBulkTag(tag: u64) bool {
    return tag == BM.types.MEMCPY_TAG or tag == BM.types.MEMSET_TAG or tag == BM.types.MEMCMP_TAG or tag == BM.types.JUMPDEST_TAG;
}
/// Replays one admitted bulk call on the ledger at the CPU step's tick: the
/// packet words are read, then the data words. memcpy reads the source words
/// holding a copied byte (`len/8` aligned, `len/8 + 1` at a byte shift) and
/// writes every destination word; memset writes the destination words;
/// memcmp reads word pairs up to and including the first differing pair (or
/// all) and writes the result -1/0/1 to packet word 3. Values come only from
/// the ledger; BM.types.validateCall rejects aliasing, misalignment, bad
/// lengths, missing rights and a wrong result before any ledger update.
fn bulkCall(a: std.mem.Allocator, ledger: *Old.Ledger, pointer: u64, tag: u64, epoch: u16, tick: u24, calls: *std.ArrayList(BM.types.Call), words: *std.ArrayList(BM.types.Word)) !void {
    if (tag == BM.types.JUMPDEST_TAG) {
        if (pointer & 7 != 0 or pointer > std.math.maxInt(u64) - 23) return error.InvalidCombinedServiceOwner;
        return jumpdestCall(a, ledger, pointer, epoch, tick, calls, words);
    }
    const op: BM.types.Op = switch (tag) {
        BM.types.MEMCPY_TAG => .copy,
        BM.types.MEMSET_TAG => .set,
        BM.types.MEMCMP_TAG => .cmp,
        else => return error.UnqualifiedCombinedServiceTag,
    };
    const packet_words: usize = if (op == .cmp) 4 else 3;
    if (pointer & 7 != 0 or pointer > std.math.maxInt(u64) - (8 * packet_words - 1)) return error.InvalidCombinedServiceOwner;
    var call = BM.types.Call{ .op = op, .pointer = pointer, .epoch = epoch, .tick = tick, .dst = undefined, .word1 = undefined, .len = undefined, .packet = @splat(.{ .value = 0, .rights = 0 }) };
    for (0..packet_words) |k| call.packet[k] = try get(ledger, pointer + 8 * k);
    call.dst = call.packet[0].value;
    call.word1 = call.packet[1].value;
    call.len = call.packet[2].value;
    if (call.len == 0 or call.len % 8 != 0 or call.len > BM.types.MAX_BYTES) return error.InvalidBulkMemoryLength;
    if (call.dst & 7 != 0 or (op == .cmp and call.word1 & 7 != 0)) return error.InvalidBulkMemoryRange;
    const start = words.items.len;
    errdefer words.shrinkRetainingCapacity(start);
    try calls.ensureUnusedCapacity(a, 1);
    const n = call.count();
    const base = call.word1 & ~@as(u64, 7);
    switch (op) {
        .set => for (0..n) |j| try words.append(a, .{ .dst = try get(ledger, call.dst +% 8 * j) }),
        .copy => if (call.shift() == 0) {
            for (0..n) |j| try words.append(a, .{ .dst = try get(ledger, call.dst +% 8 * j), .src = try get(ledger, call.word1 +% 8 * j) });
        } else {
            // Row r reads source word r and (r >= 1) writes destination word r - 1.
            for (0..n + 1) |r| try words.append(a, .{ .dst = if (r == 0) .{ .value = 0, .rights = 0 } else try get(ledger, call.dst +% 8 * (r - 1)), .src = try get(ledger, base +% 8 * r) });
        },
        .cmp => {
            var j: usize = 0;
            while (j < n) : (j += 1) {
                const w = BM.types.Word{ .dst = try get(ledger, call.dst +% 8 * j), .src = try get(ledger, call.word1 +% 8 * j) };
                try words.append(a, w);
                call.result = BM.types.compareWords(w.dst.value, w.src.value);
                if (call.result != 0) break;
            }
            call.examined = @intCast(words.items.len - start);
        },
        .jumpdest => unreachable, // jumpdestCall
    }
    const body = words.items[start..];
    try BM.types.validateCall(call, body);
    for (0..packet_words) |k| {
        const value: u64 = if (k == 3) @bitCast(@as(i64, call.result)) else call.packet[k].value;
        ledger.states.getPtr(pointer + 8 * k).?.* = .{ .value = value, .epoch = epoch, .tick = tick, .rights = call.packet[k].rights };
    }
    for (body, 0..) |w, j| {
        const at = BM.types.State{ .value = 0, .epoch = epoch, .tick = tick, .rights = 0 };
        switch (op) {
            .set => ledger.states.getPtr(call.dst + 8 * j).?.* = withValue(at, @as(u64, call.fill()) * 0x0101010101010101, w.dst.rights),
            .copy => if (call.shift() == 0) {
                ledger.states.getPtr(call.word1 + 8 * j).?.* = withValue(at, w.src.value, w.src.rights);
                ledger.states.getPtr(call.dst + 8 * j).?.* = withValue(at, w.src.value, w.dst.rights);
            } else {
                ledger.states.getPtr(base + 8 * j).?.* = withValue(at, w.src.value, w.src.rights);
                if (j != 0) ledger.states.getPtr(call.dst + 8 * (j - 1)).?.* = withValue(at, BM.types.shifted(body[j - 1].src.value, w.src.value, call.shift()), w.dst.rights);
            },
            .cmp => {
                ledger.states.getPtr(call.dst + 8 * j).?.* = withValue(at, w.dst.value, w.dst.rights);
                ledger.states.getPtr(call.word1 + 8 * j).?.* = withValue(at, w.src.value, w.src.rights);
            },
            .jumpdest => unreachable,
        }
    }
    calls.appendAssumeCapacity(call);
}
/// Replays one admitted JUMPDEST analysis on the ledger: packet `code, len,
/// bitmap`; the code words are read and the bitmap words written with the
/// canonical analysis of the ledger's code values. Entries: code word
/// predecessors (`src`), then bitmap word predecessors (`dst`).
fn jumpdestCall(a: std.mem.Allocator, ledger: *Old.Ledger, pointer: u64, epoch: u16, tick: u24, calls: *std.ArrayList(BM.types.Call), words: *std.ArrayList(BM.types.Word)) !void {
    var call = BM.types.Call{ .op = .jumpdest, .pointer = pointer, .epoch = epoch, .tick = tick, .dst = undefined, .word1 = undefined, .len = undefined, .packet = @splat(.{ .value = 0, .rights = 0 }) };
    for (0..3) |k| call.packet[k] = try get(ledger, pointer + 8 * k);
    call.dst = call.packet[0].value;
    call.len = call.packet[1].value;
    call.word1 = call.packet[2].value;
    if (call.len == 0 or call.len % 8 != 0 or call.len > BM.types.MAX_BYTES) return error.InvalidBulkMemoryLength;
    const n = call.count();
    const rows = call.bitmapWords();
    const start = words.items.len;
    try words.ensureUnusedCapacity(a, n + rows);
    try calls.ensureUnusedCapacity(a, 1);
    errdefer words.shrinkRetainingCapacity(start);
    for (0..n) |j| words.appendAssumeCapacity(.{ .dst = .{ .value = 0, .rights = 0 }, .src = try get(ledger, call.dst +% 8 * j) });
    for (0..rows) |r| words.appendAssumeCapacity(.{ .dst = try get(ledger, call.word1 +% 8 * r) });
    try BM.types.validateCall(call, words.items[start..]);
    const code = try a.alloc(u64, n);
    defer a.free(code);
    for (code, words.items[start..][0..n]) |*v, w| v.* = w.src.value;
    const pending = try a.alloc(u8, rows);
    defer a.free(pending);
    const bitmap = try a.alloc(u64, rows);
    defer a.free(bitmap);
    BM.types.analyzeWords(code, pending, bitmap);
    for (0..3) |k| ledger.states.getPtr(pointer + 8 * k).?.* = .{ .value = call.packet[k].value, .epoch = epoch, .tick = tick, .rights = call.packet[k].rights };
    for (words.items[start..][0..n], 0..) |w, j| ledger.states.getPtr(call.dst + 8 * j).?.* = .{ .value = w.src.value, .epoch = epoch, .tick = tick, .rights = w.src.rights };
    for (words.items[start + n ..][0..rows], 0..) |w, r| ledger.states.getPtr(call.word1 + 8 * r).?.* = .{ .value = bitmap[r], .epoch = epoch, .tick = tick, .rights = w.dst.rights };
    calls.appendAssumeCapacity(call);
}
fn withValue(clock: BM.types.State, value: u64, rights: u2) BM.types.State {
    return .{ .value = value, .epoch = clock.epoch, .tick = clock.tick, .rights = rights };
}
fn owner(pointer: u64, tick: u24, stride: u32, tape: *const front.rv64.compact_tape.Tape, captured_pointer: u64, clock: u64) !void {
    if (pointer != captured_pointer or clock <= tape.initial_clock or clock - tape.initial_clock > tape.len or stride * (clock - tape.initial_clock) != tick) return error.InvalidCombinedServiceOwner;
}
/// Report-only first-touch census (`STWO_RV64_CAPTURE_LEDGER_PROFILE`): the
/// ledger runs on one thread, so plain counters suffice.
var first_touch_profile: bool = false;
var first_touch_count: u64 = 0;
var first_touch_ns: u64 = 0;
fn slot(ledger: *Old.Ledger, address: u64) !*A.memory.closed_ram.types.State {
    const entry = try ledger.states.getOrPut(ledger.allocator, address);
    if (!entry.found_existing) {
        const t0 = if (first_touch_profile) std.time.Instant.now() catch null else null;
        defer if (t0) |start| if (std.time.Instant.now()) |t1| {
            first_touch_count += 1;
            first_touch_ns += t1.since(start);
        } else |_| {};
        const fast = if (ledger.pages) |*pages| pages.lookup(address) else null;
        entry.value_ptr.* = fast orelse .{ .value = try ledger.image.initialWord(address), .rights = try ledger.image.wordRights(address) };
        if (local_start) |start| {
            // Phase 1 placeholder (see `Local`): the starting image's word and
            // the first-touch ordinal; the image lookup above keeps its errors.
            const ordinal = ledger.initial.items.len;
            if (ordinal + 1 >= std.math.maxInt(u24)) return error.LocalLedgerOverflow;
            entry.value_ptr.* = .{ .value = startWord(start, address), .rights = entry.value_ptr.rights, .epoch = 0, .tick = @intCast(ordinal + 1) };
        }
        try ledger.initial.append(ledger.allocator, .{ .address = address, .state = entry.value_ptr.* });
    }
    return entry.value_ptr;
}
fn get(ledger: *Old.Ledger, address: u64) !A.memory.closed_ram.types.State {
    return (try slot(ledger, address)).*;
}
/// M8 two-phase ledger (`STWO_RV64_M8_CAPTURE_LOCAL_LEDGER=1`, default off).
/// Producer scheduling only: outputs are byte-identical to the serial ledger.
pub fn localLedgerEnabled() bool {
    const value = std.posix.getenv("STWO_RV64_M8_CAPTURE_LOCAL_LEDGER") orelse return false;
    return std.mem.eql(u8, value, "1");
}
/// Report-only counters of `Builder.appendLocal` (ordered thread only).
pub var local_stats: struct { merged: u64 = 0, fallbacks: u64 = 0, touched: u64 = 0, resolve_ns: u64 = 0, patch_ns: u64 = 0 } = .{};
/// Phase 1 output: one segment's shard computed on a segment-local ledger.
/// Every state the segment read before writing it is a placeholder
/// `{value, rights, epoch 0, tick k + 1}`, where `value` is the word in the
/// segment's starting memory image, `rights` the image rights and `k` the
/// ordinal of the address in `ledger.initial` (first-touch order). Genuine
/// ledger states never have epoch 0 and tick != 0 (INITIAL cells have tick 0,
/// written states the CPU's epoch >= 1), so placeholders are unambiguous.
/// Every validator only orders a predecessor clock against the current
/// call (epoch >= 1), which epoch 0 and any earlier real epoch satisfy alike.
pub const Local = struct {
    index: usize,
    ledger: Old.Ledger,
    shard: Shard,
    pub fn deinit(self: *Local, a: std.mem.Allocator) void {
        self.shard.deinit(a);
        self.ledger.deinit();
        self.* = undefined;
    }
};
const Checkpoint = front.rv64.checkpoint.Checkpoint;
threadlocal var local_start: ?*const Checkpoint = null;
/// Phase 1 (any thread): `one` for segment `index` on a fresh ledger over the
/// same image. Segment 0 uses the serial first-touch source (the global ledger
/// is empty then) and is adopted whole. `start` is the memory image before
/// this segment (the first pass checkpoint); it is only read. `prepared` is
/// taken as in `appendWithEvents`. `a` must be thread-safe.
pub fn prepareLocal(a: std.mem.Allocator, image: @import("../../word16_execution/memory/statement.zig").Image, pages: Old.OwnerPages, native: *Native, tape: *const front.rv64.compact_tape.Tape, index: usize, prepared: *?[]LS.native.Event, start: *const Checkpoint) !Local {
    var ledger = Old.Ledger.init(a, image);
    errdefer ledger.deinit();
    ledger.pages = pages;
    local_start = if (index == 0) null else start;
    defer local_start = null;
    const shard = try one(a, &ledger, native, tape, index, null, prepared);
    return .{ .index = index, .ledger = ledger, .shard = shard };
}
/// The little-endian u64 at `address` in a checkpoint image (absent pages
/// read as zero, as an unallocated guest page does).
fn startWord(cp: *const Checkpoint, address: u64) u64 {
    const P: u64 = front.rv64.memory.PAGE_SIZE;
    var bytes: [8]u8 = undefined;
    if (address % P <= P - 8) {
        const page = cp.find(address / P) orelse return 0;
        const offset: usize = @intCast(address % P);
        return std.mem.readInt(u64, page[offset..][0..8], .little);
    }
    for (&bytes, 0..) |*byte, i| {
        const at = address +% i;
        byte.* = if (cp.find(at / P)) |page| page[@intCast(at % P)] else 0;
    }
    return std.mem.readInt(u64, &bytes, .little);
}
fn containsState(comptime T: type) bool {
    if (T == A.memory.closed_ram.types.State) return true;
    return switch (@typeInfo(T)) {
        .@"struct" => |info| blk: {
            inline for (info.fields) |field| if (containsState(field.type)) break :blk true;
            break :blk false;
        },
        .array => |info| containsState(info.child),
        .pointer => |info| info.size == .slice and containsState(info.child),
        else => false,
    };
}
fn patchValue(comptime T: type, value: *T, global: []const A.memory.closed_ram.types.State) void {
    if (comptime !containsState(T)) return;
    if (T == A.memory.closed_ram.types.State) {
        if (value.epoch == 0 and value.tick != 0) {
            const g = global[value.tick - 1];
            value.epoch = g.epoch;
            value.tick = g.tick;
        }
        return;
    }
    switch (@typeInfo(T)) {
        .@"struct" => |info| inline for (info.fields) |field| patchValue(field.type, &@field(value, field.name), global),
        .array => |info| for (value) |*item| patchValue(info.child, item, global),
        .pointer => |info| for (value.*) |*item| patchValue(info.child, item, global),
        else => {},
    }
}
/// Replaces every placeholder clock in `shard` (every `State` field, found by
/// reflection) with the clock of the global state it stands for.
fn patchShard(shard: *Shard, global: []const A.memory.closed_ram.types.State) void {
    patchValue(Shard, shard, global);
}
test "M8 two-phase ledger: placeholder clocks patch every State field and nothing else" {
    const a = std.testing.allocator;
    const St = A.memory.closed_ram.types.State;
    const global = [_]St{ .{ .value = 7, .epoch = 3, .tick = 40, .rights = 3 }, .{ .value = 9, .rights = 1 } };
    const events = try a.alloc(LS.native.Event, 2);
    events[0] = .{ .opcode = .LD, .immediate = 0, .a = 8, .epoch = 5, .tick = 4, .before = .{ .value = 7, .tick = 1, .rights = 3 }, .after = .{ .value = 7, .epoch = 5, .tick = 4, .rights = 3 } };
    events[1] = .{ .opcode = .LD, .immediate = 0, .a = 8, .epoch = 5, .tick = 8, .before = events[0].after, .after = .{ .value = 7, .epoch = 5, .tick = 8, .rights = 3 } };
    const keccak = try a.alloc(K.types.Call, 1);
    keccak[0] = .{ .pointer = 0, .epoch = 5, .tick = 12, .before = @splat(0), .after = @splat(0), .predecessors = @splat(.{ .value = 9, .tick = 2, .rights = 1 }) };
    keccak[0].predecessors[3] = .{ .value = 0, .rights = 0 };
    const words = try a.alloc(BM.types.Word, 1);
    words[0] = .{ .dst = .{ .value = 9, .tick = 2, .rights = 1 } };
    const sponge_words = try a.alloc(St, 1);
    sponge_words[0] = .{ .value = 7, .tick = 1, .rights = 3 };
    var shard = Shard{ .events = events, .keccak = keccak, .secp = .{ try a.alloc(S.types.Call, 0), try a.alloc(S.types.Call, 0) }, .sha256 = try a.alloc(S.types.Call, 0), .arith256_mod = try a.alloc(S.types.Call, 0), .curves = undefined, .bulk = .{ .calls = try a.alloc(BM.types.Call, 0), .words = words }, .sponge = .{ .calls = try a.alloc(A.crypto.keccak_sponge.types.Call, 0), .words = sponge_words, .inputs = try a.alloc([25]u64, 0) } };
    for (&shard.curves) |*c| c.* = try a.alloc(S.types.Call, 0);
    defer shard.deinit(a);
    patchShard(&shard, &global);
    try std.testing.expectEqualDeep(St{ .value = 7, .epoch = 3, .tick = 40, .rights = 3 }, shard.events[0].before);
    try std.testing.expectEqualDeep(St{ .value = 7, .epoch = 5, .tick = 4, .rights = 3 }, shard.events[1].before);
    try std.testing.expectEqualDeep(St{ .value = 7, .epoch = 5, .tick = 8, .rights = 3 }, shard.events[1].after);
    try std.testing.expectEqualDeep(St{ .value = 9, .epoch = 0, .tick = 0, .rights = 1 }, shard.keccak[0].predecessors[0]);
    try std.testing.expectEqualDeep(St{ .value = 0, .rights = 0 }, shard.keccak[0].predecessors[3]);
    try std.testing.expectEqualDeep(St{ .value = 9, .rights = 1 }, shard.bulk.words[0].dst);
    try std.testing.expectEqualDeep(St{ .value = 0, .rights = 0 }, shard.bulk.words[0].src);
    try std.testing.expectEqualDeep(St{ .value = 7, .epoch = 3, .tick = 40, .rights = 3 }, shard.sponge.words[0]);
}
test "M8 two-phase ledger: starting-image words, page-crossing and absent pages" {
    const P: usize = front.rv64.memory.PAGE_SIZE;
    var page0: [front.rv64.memory.PAGE_SIZE]u8 = @splat(0);
    var page1: [front.rv64.memory.PAGE_SIZE]u8 = @splat(0);
    std.mem.writeInt(u64, page0[16..24], 0x1122334455667788, .little);
    page0[P - 2] = 0xaa;
    page0[P - 1] = 0xbb;
    page1[0] = 0xcc;
    const entries = [_]front.rv64.checkpoint.Entry{ .{ .index = 4, .page = &page0 }, .{ .index = 5, .page = &page1 } };
    const cp = Checkpoint{ .cpu = undefined, .counters = .{}, .pages = &entries, .written = &.{} };
    try std.testing.expectEqual(@as(u64, 0x1122334455667788), startWord(&cp, 4 * P + 16));
    try std.testing.expectEqual(@as(u64, 0xccbbaa), startWord(&cp, 5 * P - 2));
    try std.testing.expectEqual(@as(u64, 0), startWord(&cp, 9 * P + 8));
}

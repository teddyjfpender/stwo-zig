//! Compact bulk/sponge service records -> GPU MAIN and shared range ledgers.
//! No CPU row materialization and no multiplicity readback.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const A = @import("stwo_riscv_frontend").rv64_air.crypto;
const B = A.bulk_memory;
const S = A.keccak_sponge;
const D = CPU.rv64_device_pcs;
const Stage = CPU.rv64_device_source_stage;
const Assembly = @import("device_source.zig");
const Core = @import("core_witness.zig");
const Service = @import("pcs_native.zig");
const Native = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
pub const State = extern struct { value: u64, tick: u32, epoch: u16, rights: u8, reserved: u8 = 0 };
pub const BulkCall = extern struct { pointer: u64, dst: u64, word1: u64, len: u64, epoch: u32, tick: u32, op: u32, examined: u32, result: i32, first_word: u32, first_scan: u32, reserved: u32 = 0, packet: [4]State };
pub const Word = extern struct { dst: State, src: State };
pub const Row = extern struct { call: u32, word: u32, index: u32, reserved: u32 = 0 };
pub const SpongeCall = extern struct { pointer: u64, epoch: u32, tick: u32, first_word: u32, first_perm: u32, packet: [4]State, state: [25]State };
const BulkJob = extern struct { calls: [*]const BulkCall, words: [*]const Word, rows: [*]const Row, pending: [*]const u32, main: [*]u32, range16: [*]u32, jump_counts: [*]u32, status: [*]u32, count: u32, log: u32, kind: u32, call_count: u32, word_count: u32, pending_count: u32 };
const SpongeJob = extern struct { calls: [*]const SpongeCall, words: [*]const State, outputs: [*]const u64, rows: [*]const Row, main: [*]u32, range16: [*]u32, range8: [*]u32, and_counts: [*]u32, status: [*]u32, count: u32, log: u32, kind: u32, first_id: u32, call_count: u32, word_count: u32, permutation_count: u32, reserved: u32 = 0 };
const BulkFn = *const fn (*anyopaque, u32, *const BulkJob) callconv(.c) c_int;
const AnalyzeFn = *const fn (*anyopaque, u32, [*]const BulkCall, u32, [*]const Word, u32, [*]u32, u32, [*]u32, [*]u32) callconv(.c) c_int;
const SpongeFn = *const fn (*anyopaque, u32, *const SpongeJob) callconv(.c) c_int;
const OutputsFn = *const fn (*anyopaque, u32, [*]const u64, [*]u64, u32, [*]u32) callconv(.c) c_int;
comptime {
    std.debug.assert(@sizeOf(State) == 16 and @sizeOf(BulkCall) == 128 and @sizeOf(SpongeCall) == 488 and @sizeOf(Row) == 16);
}
fn check(rc: c_int) !void {
    if (rc != 0) return error.CudaBulkSpongeFailed;
}
fn sym(comptime T: type, s: *Service.Context, n: [:0]const u8) !T {
    return s.library.lookup(T, n) orelse error.MissingBulkSpongeWitnessSymbol;
}
fn state(v: B.types.State) State {
    return .{ .value = v.value, .tick = v.tick, .epoch = v.epoch, .rights = v.rights };
}
pub const Context = struct {
    service: *Service.Context,
    bulk: BulkFn,
    analyze: AnalyzeFn,
    sponge: SpongeFn,
    outputs: OutputsFn,
    pub fn init(service: *Service.Context) !Context {
        return .{ .service = service, .bulk = try sym(BulkFn, service, "stwo_rv64_bulk_witness_on"), .analyze = try sym(AnalyzeFn, service, "stwo_rv64_bulk_analyze_on"), .sponge = try sym(SpongeFn, service, "stwo_rv64_sponge_witness_on"), .outputs = try sym(OutputsFn, service, "stwo_rv64_sponge_outputs_on") };
    }
    pub fn contributor(self: *Context) Assembly.Contributor {
        return .{ .context = self, .format = format };
    }
    fn format(raw: *anyopaque, a: std.mem.Allocator, request: Stage.Request, core: *Core.CoreProjection, headers: *Assembly.Headers, columns: []D.TraceColumn) !?Assembly.Owner {
        const self: *Context = @ptrCast(@alignCast(raw));
        if (!request.setup.bridges.bulk.any() and !request.setup.bridges.sponge.any()) return null;
        const owner = try a.create(Owner);
        owner.* = .{ .a = a, .backend = self, .core = core, .request = request, .headers = headers, .columns = columns };
        errdefer owner.destroy();
        const rc = self.service.submit(self.service.session, Owner.callback, owner);
        if (owner.failure) |err| return err;
        try check(rc);
        return .{ .context = owner, .release = Owner.release };
    }
};
const Owner = struct {
    a: std.mem.Allocator,
    backend: *Context,
    core: *Core.CoreProjection,
    request: Stage.Request,
    headers: *Assembly.Headers,
    columns: []D.TraceColumn,
    leases: std.ArrayList(Native.Lease) = .empty,
    failure: ?anyerror = null,
    fn release(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        self.destroy();
    }
    fn destroy(self: *Owner) void {
        _ = self.backend.service.submit(self.backend.service.session, releaseLeases, self);
        const a = self.a;
        self.leases.deinit(a);
        a.destroy(self);
    }
    fn releaseLeases(_: *anyopaque, _: u64, raw: ?*anyopaque) callconv(.c) c_int {
        const self: *Owner = @ptrCast(@alignCast(raw.?));
        var rc: c_int = 0;
        for (self.leases.items) |*l| {
            const r = self.backend.service.lease_release(self.backend.service.session, l);
            if (r != 0) rc = r;
        }
        return rc;
    }
    fn allocate(self: *Owner, ctx: *SC.Context, words: usize, kind: u32) !Native.Lease {
        var l = try ctx.allocate(@max(words, 1), kind);
        errdefer ctx.release(&l) catch {};
        try self.leases.append(self.a, l);
        return l;
    }
    fn upload(self: *Owner, ctx: *SC.Context, comptime T: type, values: []const T) !Native.Lease {
        const words: []const u32 = @alignCast(std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(values)));
        const l = try self.allocate(ctx, words.len, 0);
        if (words.len > 0) try ctx.upload(try (try ctx.borrow(l)).sub(0, words.len), words);
        return l;
    }
    fn output(self: *Owner, ctx: *SC.Context, log: u32, width: usize, offset: usize) !Native.Lease {
        const n = @as(usize, 1) << @intCast(log);
        if (offset + width > self.columns.len) return error.InvalidBulkSpongeOffset;
        const l = try self.allocate(ctx, n * width, 1);
        for (self.columns[offset..][0..width], 0..) |*c, k| c.* = .{ .log_size = log, .encoding = .evaluations, .device = .{ .words = l.words.? + k * n, .count = n, .context_token = l.context_token, .generation = l.generation } };
        return l;
    }
    fn callback(raw: *anyopaque, token: u64, arg: ?*anyopaque) callconv(.c) c_int {
        const self: *Owner = @ptrCast(@alignCast(arg.?));
        var ctx = SC.Context{ .session = self.backend.service.session, .native_context = raw, .token = token, .scope = @import("pcs_scope.zig").identity(self.request.scope), .api = &self.core.backend.api };
        defer std.debug.print("GPU_NATIVE_H2D role=bulk-sponge ordinal={} bytes={} scope=scoped-uploads-only\n", .{ self.request.ordinal, ctx.uploaded_bytes });
        self.run(&ctx) catch |err| {
            self.failure = err;
            ctx.join() catch {};
            return 1;
        };
        return 0;
    }
    fn run(self: *Owner, ctx: *SC.Context) !void {
        if (self.request.setup.bridges.bulk.any()) try self.bulk(ctx);
        if (self.request.setup.bridges.sponge.any()) try self.sponge(ctx);
        try ctx.join();
    }
    fn bulk(self: *Owner, ctx: *SC.Context) !void {
        const advice = self.request.advice.bulk[self.request.ordinal];
        const calls = try self.a.alloc(BulkCall, advice.calls.len);
        defer self.a.free(calls);
        const words = try self.a.alloc(Word, advice.words.len);
        defer self.a.free(words);
        var first_word: u32 = 0;
        var scans: u32 = 0;
        for (advice.calls, calls) |c, *out| {
            if (@as(u64, first_word) + c.entries() > advice.words.len) return error.InvalidBulkMemoryWords;
            try B.types.validateCall(c, advice.words[first_word..][0..c.entries()]);
            out.* = .{ .pointer = c.pointer, .dst = c.dst, .word1 = c.word1, .len = c.len, .epoch = c.epoch, .tick = c.tick, .op = @intFromEnum(c.op), .examined = c.examined, .result = c.result, .first_word = first_word, .first_scan = scans, .packet = undefined };
            for (c.packet, &out.packet) |v, *s| s.* = state(v);
            first_word += c.entries();
            if (c.op == .jumpdest) scans += c.bodyRows();
        }
        if (first_word != advice.words.len) return error.InvalidBulkMemoryWords;
        for (advice.words, words) |v, *w| w.* = .{ .dst = state(v.dst), .src = state(v.src) };
        const dc = try self.upload(ctx, BulkCall, calls);
        const dw = try self.upload(ctx, Word, words);
        const pending = try self.allocate(ctx, scans, 0);
        const jumps = try self.allocate(ctx, 8448, 0);
        try check(self.core.backend.memset(ctx.native_context, @ptrCast(@alignCast(jumps.words.?)), 0, 8448 * 4));
        try ctx.join();
        try check(self.backend.analyze(ctx.native_context, 1, @ptrCast(@alignCast(dc.words.?)), @intCast(calls.len), @ptrCast(@alignCast(dw.words.?)), @intCast(words.len), pending.words.?, scans, jumps.words.?, @constCast(self.core.ledgers.status.words)));
        // Analysis and witness use the same lane; no host multiplicities.
        for (Assembly.T.bulk_kinds, 0..) |kind, index| if (self.request.setup.bridges.bulk.at(kind)) |log| {
            const total = B.source.Source.rowsFor(kind, advice.calls);
            _ = try B.types.validateGeometry(kind, total, log);
            var rows: std.ArrayList(Row) = .empty;
            defer rows.deinit(self.a);
            const call_rows = try self.a.alloc(u32, advice.calls.len);
            defer self.a.free(call_rows);
            @memset(call_rows, 0);
            for (advice.calls, 0..) |c, k| {
                if (c.descriptor() == kind) {
                    call_rows[k] = @intCast(rows.items.len);
                    try rows.append(self.a, .{ .call = @intCast(k), .word = calls[k].first_word, .index = 0 });
                }
                if (c.body() == kind) {
                    call_rows[k] = @intCast(rows.items.len);
                    for (0..c.bodyRows()) |j| try rows.append(self.a, .{ .call = @intCast(k), .word = calls[k].first_word + @as(u32, @intCast(if (kind == .jscan) 0 else j)), .index = @intCast(j) });
                }
            }
            const dr = try self.upload(ctx, Row, rows.items);
            const main = try self.output(ctx, log, B.layout.main(kind), self.request.setup.bulkOffset(kind, 1));
            try ctx.join();
            const job = BulkJob{ .calls = @ptrCast(@alignCast(dc.words.?)), .words = @ptrCast(@alignCast(dw.words.?)), .rows = @ptrCast(@alignCast(dr.words.?)), .pending = pending.words.?, .main = main.words.?, .range16 = @constCast(self.core.ledgers.range16.words), .jump_counts = jumps.words.?, .status = @constCast(self.core.ledgers.status.words), .count = @intCast(total), .log = log, .kind = @intFromEnum(kind), .call_count = @intCast(calls.len), .word_count = @intCast(words.len), .pending_count = scans };
            try check(self.backend.bulk(ctx.native_context, 1, &job));
            // Narrow headers survive MAIN release; no host matrix allocation.
            var h = B.source.Source{ .allocator = self.a, .kind = kind, .log_size = log, .rows = @intCast(total), .calls = &.{}, .words = &.{}, .row_call = &.{}, .row_word = &.{}, .call_row = &.{}, .fixed = &.{}, .main = &.{}, .owns_main = false, .counts16 = &.{}, .counts8 = &.{}, .device_only = true };
            errdefer h.deinit();
            h.calls = try self.a.dupe(B.types.Call, advice.calls);
            h.words = try self.a.dupe(B.types.Word, advice.words);
            h.call_row = try self.a.dupe(u32, call_rows);
            h.row_call = try self.a.alloc(u32, rows.items.len);
            h.row_word = try self.a.alloc(u32, rows.items.len);
            for (rows.items, h.row_call, h.row_word) |r, *c, *w| {
                c.* = r.call;
                w.* = r.word;
            }
            self.headers.bulk[index] = h;
        };
    }
    fn sponge(self: *Owner, ctx: *SC.Context) !void {
        const advice = self.request.advice.sponge[self.request.ordinal];
        const calls = try self.a.alloc(SpongeCall, advice.calls.len);
        defer self.a.free(calls);
        const words = try self.a.alloc(State, advice.words.len);
        defer self.a.free(words);
        var nw: usize = 0;
        var np: usize = 0;
        for (advice.calls, calls) |c, *out| {
            if (c.first_word != nw or c.first_perm != np or nw + c.words() > advice.words.len) return error.InvalidKeccakSpongeCallOrder;
            try S.types.validateCall(c, advice.words[nw..][0..c.words()]);
            out.* = .{ .pointer = c.pointer, .epoch = c.epoch, .tick = c.tick, .first_word = c.first_word, .first_perm = c.first_perm, .packet = undefined, .state = undefined };
            for (c.packet, &out.packet) |v, *s| s.* = state(v);
            for (c.state, &out.state) |v, *s| s.* = state(v);
            nw += c.words();
            np += c.permutations();
        }
        if (nw != advice.words.len or np != advice.inputs.len) return error.InvalidKeccakSpongeWords;
        for (advice.words, words) |v, *s| s.* = state(v);
        const dc = try self.upload(ctx, SpongeCall, calls);
        const dw = try self.upload(ctx, State, words);
        const di = try self.upload(ctx, [25]u64, advice.inputs);
        const dout = try self.allocate(ctx, np * 50, 0);
        try ctx.join();
        if (np != 0) try check(self.backend.outputs(ctx.native_context, 1, @ptrCast(@alignCast(di.words.?)), @ptrCast(@alignCast(dout.words.?)), @intCast(np), @constCast(self.core.ledgers.status.words)));
        const plan = try self.a.create(S.source.Plan);
        errdefer self.a.destroy(plan);
        plan.* = .{ .calls = &.{}, .words = &.{}, .perms = &.{}, .row_call = &.{}, .device_permutations = @intCast(np) };
        errdefer plan.deinit(self.a);
        plan.calls = try self.a.dupe(S.types.Call, advice.calls);
        plan.words = try self.a.dupe(S.types.State, advice.words);
        plan.row_call = try self.a.alloc(u32, np);
        for (advice.calls, 0..) |c, k| @memset(plan.row_call[c.first_perm..][0..c.permutations()], @intCast(k));
        for (Assembly.T.sponge_kinds, 0..) |kind, index| if (self.request.setup.bridges.sponge.at(kind)) |log| {
            const count = plan.rows(kind);
            _ = try S.types.validateGeometry(kind, count, log);
            const rows = try self.a.alloc(Row, count);
            defer self.a.free(rows);
            if (kind == .call) {
                for (rows, 0..) |*r, k| r.* = .{ .call = @intCast(k), .word = 0, .index = 0 };
            } else {
                for (rows, 0..) |*r, k| {
                    const ci = plan.row_call[k];
                    r.* = .{ .call = ci, .word = 0, .index = @intCast(k - advice.calls[ci].first_perm) };
                }
            }
            const dr = try self.upload(ctx, Row, rows);
            const main = try self.output(ctx, log, S.layout.main(kind), self.request.setup.spongeOffset(kind, 1));
            try ctx.join();
            const job = SpongeJob{ .calls = @ptrCast(@alignCast(dc.words.?)), .words = @ptrCast(@alignCast(dw.words.?)), .outputs = @ptrCast(@alignCast(dout.words.?)), .rows = @ptrCast(@alignCast(dr.words.?)), .main = main.words.?, .range16 = @constCast(self.core.ledgers.range16.words), .range8 = @constCast(self.core.ledgers.range8.words), .and_counts = @constCast(self.core.ledgers.and_.words), .status = @constCast(self.core.ledgers.status.words), .count = count, .log = log, .kind = @intFromEnum(kind), .first_id = self.request.request.sponge.first_id, .call_count = @intCast(calls.len), .word_count = @intCast(words.len), .permutation_count = @intCast(np) };
            try check(self.backend.sponge(ctx.native_context, 1, &job));
            self.headers.sponge[index] = .{ .allocator = self.a, .kind = kind, .log_size = log, .rows = count, .first_id = self.request.request.sponge.first_id, .plan = plan, .fixed = &.{}, .main = &.{}, .owns_main = false, .counts16 = &.{}, .counts8 = &.{}, .counts_and = &.{} };
        };
        self.headers.sponge_plan = plan;
    }
};

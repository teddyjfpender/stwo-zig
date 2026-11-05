//! Compact service-call/RAM predecessors -> resident bridge MAIN. The native
//! polynomial authorities still authenticate OWNER/RAM/IO; this is a formatter.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak.word16_bridge;
const W = A.crypto.secp256k1.word16_bridge;
const D = CPU.rv64_device_pcs;
const Stage = CPU.rv64_device_source_stage;
const T = CPU.rv64_services_types;
const S = @import("device_source.zig");
const Core = @import("core_witness.zig");
const Native = @import("pcs_native_abi.zig");
const Service = @import("pcs_native.zig");
const SC = @import("session_context.zig");
pub const Job = extern struct {
    inputs: ?[*]const u32,
    main: [*]u32,
    range16: [*]u32,
    range8: [*]u32,
    status: [*]u32,
    input_words: u64,
    main_words: u64,
    calls: u32,
    first_id: u32,
    log: u32,
    kind: u32,
    coordinates: u32,
    write_mask: u32,
};
const Kernel = *const fn (*anyopaque, u32, *const Job) callconv(.c) c_int;
pub const Context = struct {
    service: *Service.Context,
    kernel: Kernel,
    pub fn init(service: *Service.Context) !Context {
        return .{ .service = service, .kernel = service.library.lookup(Kernel, "stwo_rv64_bridge_witness_on") orelse return error.MissingResidentBridgeSymbol };
    }
    pub fn contributor(self: *Context) S.Contributor {
        return .{ .context = self, .format = format };
    }
    fn format(raw: *anyopaque, a: std.mem.Allocator, request: Stage.Request, core: *Core.CoreProjection, headers: *S.Headers, columns: []D.TraceColumn) !?S.Owner {
        const self: *Context = @ptrCast(@alignCast(raw));
        if (self.service != core.backend.service) return error.CrossDeviceBridgeContext;
        const owner = try a.create(Owner);
        errdefer a.destroy(owner);
        owner.* = .{ .allocator = a, .service = self.service };
        errdefer owner.destroy();
        for (0..T.FAMILIES) |index| {
            const family: T.Family = @enumFromInt(index);
            const log = request.setup.bridges.at(family) orelse continue;
            const count = request.request.calls[index];
            const first = request.first_ids[index];
            const offset = request.setup.offset(family, 1);
            const width = T.widths(family)[1];
            if (offset + width > columns.len) return error.InvalidResidentBridgeColumns;
            var encoded: []u32 = undefined;
            var coordinates: usize = undefined;
            var write_mask: u32 = 0;
            if (family == .keccak) {
                const calls = request.advice.keccak[request.ordinal];
                if (calls.len != count) return error.InvalidCombinedServiceCount;
                _ = try K.types.validateGeometry(calls.len, first, log);
                for (calls, 0..) |call, i| {
                    try K.source.validate(call);
                    if (i != 0 and (call.epoch < calls[i - 1].epoch or (call.epoch == calls[i - 1].epoch and call.tick <= calls[i - 1].tick))) return error.InvalidWord16KeccakCallOrder;
                }
                encoded = try encodeKeccak(a, calls);
                errdefer a.free(encoded);
                coordinates = 25;
                headers.keccak = .{ .allocator = a, .log_size = log, .first_id = first, .calls = try a.dupe(K.types.Call, calls), .fixed = &.{}, .main = &.{}, .owns_main = true, .counts16 = &.{}, .counts8 = &.{} };
            } else {
                const kind = T.bridgeKind(family);
                const calls: []const W.types.Call = switch (family) {
                    .add => request.advice.secp[request.ordinal][0],
                    .double => request.advice.secp[request.ordinal][1],
                    .sha256 => request.advice.sha256[request.ordinal],
                    .arith256_mod => request.advice.arith256_mod[request.ordinal],
                    else => request.advice.curves[request.ordinal][index - T.FIRST_CURVE],
                };
                if (calls.len != count) return error.InvalidCombinedServiceCount;
                _ = try W.types.validateGeometry(kind, calls.len, first, log);
                for (calls, 0..) |call, i| {
                    try W.source.validate(kind, call);
                    if (i != 0 and (call.epoch < calls[i - 1].epoch or (call.epoch == calls[i - 1].epoch and call.tick <= calls[i - 1].tick))) return error.InvalidWord16SecpCallOrder;
                }
                coordinates = W.types.coordinates(kind);
                for (0..coordinates) |coord| if (W.types.isWritten(kind, coord)) {
                    write_mask |= @as(u32, 1) << @intCast(coord);
                };
                encoded = try encodeWire(a, kind, calls);
                errdefer a.free(encoded);
                const header = W.source.Source{ .allocator = a, .kind = kind, .log_size = log, .first_id = first, .calls = try a.dupe(W.types.Call, calls), .fixed = &.{}, .main = &.{}, .owns_main = true, .counts16 = &.{}, .counts8 = &.{} };
                switch (family) {
                    .add => headers.add = header,
                    .double => headers.double = header,
                    .sha256 => headers.sha256 = header,
                    .arith256_mod => headers.arith256_mod = header,
                    else => headers.curves[index - T.FIRST_CURVE] = header,
                }
            }
            defer a.free(encoded);
            var operation = Operation{ .backend = self, .owner = owner, .core = core, .words = encoded, .count = count, .first = first, .log = log, .kind = if (family == .keccak) 0 else 1, .coordinates = @intCast(coordinates), .write_mask = write_mask, .target = columns[offset..][0..width] };
            const status = self.service.submit(self.service.session, Operation.callback, &operation);
            if (operation.failure) |err| return err;
            if (status != 0) return error.CudaBridgeWitnessFailed;
        }
        return .{ .context = owner, .release = Owner.release };
    }
};
fn pair(out: []u32, value: u64) void {
    out[0] = @truncate(value);
    out[1] = @truncate(value >> 32);
}
fn packet(out: []u32, pointer: u64, epoch: u16, tick: u24) void {
    pair(out, pointer);
    out[2] = epoch;
    out[3] = tick;
}
fn ram(out: []u32, before: u64, after: u64, pred: A.memory.closed_ram.types.State) void {
    pair(out, before);
    pair(out[2..], after);
    pair(out[4..], pred.value);
    out[6] = @as(u32, pred.epoch) | (@as(u32, pred.rights) << 16);
    out[7] = pred.tick;
}
pub fn encodeKeccak(a: std.mem.Allocator, calls: []const K.types.Call) ![]u32 {
    const stride = 4 + 25 * 8;
    const out = try a.alloc(u32, try std.math.mul(usize, calls.len, stride));
    for (calls, 0..) |call, i| {
        const row = out[i * stride ..][0..stride];
        packet(row, call.pointer, call.epoch, call.tick);
        for (0..25) |j| ram(row[4 + j * 8 ..], call.before[j], call.after[j], call.predecessors[j]);
    }
    return out;
}
pub fn encodeWire(a: std.mem.Allocator, kind: W.types.Kind, calls: []const W.types.Call) ![]u32 {
    const words = 4 * W.types.coordinates(kind);
    const stride = 4 + words * 8;
    const out = try a.alloc(u32, try std.math.mul(usize, calls.len, stride));
    for (calls, 0..) |call, i| {
        const row = out[i * stride ..][0..stride];
        packet(row, call.pointer, call.epoch, call.tick);
        for (0..words) |j| ram(row[4 + j * 8 ..], call.before[j], call.after[j], call.predecessors[j]);
    }
    return out;
}
const Owner = struct {
    allocator: std.mem.Allocator,
    service: *Service.Context,
    leases: std.ArrayList(Native.Lease) = .empty,
    fn release(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        const a = self.allocator;
        self.destroy();
        a.destroy(self);
    }
    fn destroy(self: *Owner) void {
        _ = self.service.submit(self.service.session, releaseDevice, self);
        self.leases.deinit(self.allocator);
    }
    fn releaseDevice(_: *anyopaque, _: u64, raw: ?*anyopaque) callconv(.c) c_int {
        const self: *Owner = @ptrCast(@alignCast(raw.?));
        var status: c_int = 0;
        for (self.leases.items) |*lease| {
            const rc = self.service.lease_release(self.service.session, lease);
            if (rc != 0) status = rc;
        }
        return status;
    }
};
const Operation = struct {
    backend: *Context,
    owner: *Owner,
    core: *Core.CoreProjection,
    words: []const u32,
    count: u32,
    first: u32,
    log: u32,
    kind: u32,
    coordinates: u32,
    write_mask: u32,
    target: []D.TraceColumn,
    failure: ?anyerror = null,
    fn callback(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Operation = @ptrCast(@alignCast(data.?));
        self.run(raw, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn allocate(self: *Operation, ctx: *SC.Context, words: usize, kind: u32) !Native.Lease {
        var lease = try ctx.allocate(@max(words, 1), kind);
        errdefer ctx.release(&lease) catch {};
        try self.owner.leases.append(self.owner.allocator, lease);
        return lease;
    }
    fn run(self: *Operation, raw: *anyopaque, token: u64) !void {
        var ctx = SC.Context{ .session = self.backend.service.session, .native_context = raw, .token = token, .scope = @import("pcs_scope.zig").identity(self.core.scope), .api = &self.core.backend.api };
        defer std.debug.print("GPU_NATIVE_H2D role=bridge ordinal={} bytes={} scope=scoped-uploads-only\n", .{ self.core.scope.ordinal, ctx.uploaded_bytes });
        defer ctx.join() catch {};
        const input = try self.allocate(&ctx, self.words.len, 0);
        const rows = @as(usize, 1) << @intCast(self.log);
        const main = try self.allocate(&ctx, rows * self.target.len, 1);
        if (self.words.len != 0) try ctx.upload(try (try ctx.borrow(input)).sub(0, self.words.len), self.words);
        try ctx.join();
        const job = Job{ .inputs = if (self.words.len == 0) null else input.words, .main = main.words.?, .range16 = @constCast(self.core.ledgers.range16.words), .range8 = @constCast(self.core.ledgers.range8.words), .status = @constCast(self.core.ledgers.status.words), .input_words = self.words.len, .main_words = main.count, .calls = self.count, .first_id = self.first, .log = self.log, .kind = self.kind, .coordinates = self.coordinates, .write_mask = self.write_mask };
        if (self.backend.kernel(raw, 1, &job) != 0) return error.CudaBridgeWitnessFailed;
        try ctx.join();
        for (self.target, 0..) |*column, i| column.* = .{ .log_size = self.log, .encoding = .evaluations, .device = .{ .words = main.words.? + i * rows, .count = rows, .context_token = token, .generation = main.generation } };
    }
};
comptime {
    if (@sizeOf(Job) != 80) @compileError("bridge witness ABI changed");
}
test "resident bridge contributor and compact encoder are fully typed" {
    std.mem.doNotOptimizeAway(&Context.format);
    std.mem.doNotOptimizeAway(&Context.init);
}

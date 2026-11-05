//! Production outer-prefix transcript parity. Uses the existing exact rawmod
//! OM31 CUDA channel, never the generic QM31/reduced-digest transcript mode.
//! Check mode observes host authority and replays once before resident CPCS.
const std = @import("std");
const Raw = @import("stwo_core").channel.raw_mod_m31;
const Service = @import("pcs_native.zig");
const N = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const D = @import("stwo_prover_api").device_pcs;
const Core = @import("stwo_core");
const LookupParams = *const fn (*anyopaque, u32, [*]const u32, [*]u32, [*]u32) callconv(.c) c_int;
const Init = *const fn (*anyopaque, u32, [*]u32, [*]const u32, u64) callconv(.c) c_int;
const Mix = *const fn (*anyopaque, u32, [*]u32, u32, u64, u64, [*]const u32, u32, u32, [*]u32) callconv(.c) c_int;
const Draw = *const fn (*anyopaque, u32, [*]u32, u32, u64, u64, u32, [*]u32, [*]u32) callconv(.c) c_int;
const DrawRaw = *const fn ([*]u32, u32, u64, u64, [*]u32, [*]u32, [*]u32, *anyopaque) callconv(.c) c_int;
const Kind = enum { mix_words, mix_felts, draw_raw, draw_om31 };
const Op = struct { kind: Kind, first: usize, count: usize, after: Raw.Om31Checkpoint };
fn sym(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse error.MissingOuterDeviceFsSymbol;
}
fn check(code: c_int) !void {
    if (code != 0) return error.OuterDeviceFsNativeFailure;
}
pub fn create(a: std.mem.Allocator, service: *Service.Context, scope: D.Scope, class: ?[32]u8, is_leaf: bool) !?Raw.Om31Observer {
    const option = std.posix.getenv("STWO_RV64_OUTER_DEVICE_FS") orelse return null;
    if (std.mem.eql(u8, option, "0")) return null;
    if (!std.mem.eql(u8, option, "check")) return error.OuterDeviceFsModeNotQualified;
    if (@import("stwo_riscv_cpu_integration").rv64_om31_outer_wrap.hybridProfileActive()) return error.UnsupportedHybridOuterDeviceFsCheck;
    // These diagnostic allocations have no global admission model yet.
    if (service.admission != null) return error.UnmodeledOuterDeviceFsCheck;
    const addon_path = std.posix.getenv("STWO_RV64_OUTER_FS_OPS_LIBRARY") orelse return error.MissingOuterDeviceFsAddon;
    var addon = try std.DynLib.open(addon_path);
    errdefer addon.close();
    _ = try sym(LookupParams, &addon, "stwo_rv64_outer_fs_lookup_params_on");
    const self = try a.create(Recorder);
    self.* = .{ .a = a, .service = service, .scope = scope, .class = class orelse @splat(0), .is_leaf = is_leaf, .addon = addon };
    return .{ .context = self, .start = Recorder.start, .record = Recorder.record, .before_pcs = Recorder.before, .finish = Recorder.finish, .destroy = Recorder.destroy };
}
/// Actual first consumer. The observer is scoped to the calling proof; the
/// returned lease remains recorder-owned until all proof stages have joined.
pub fn interactionParameters(service: *Service.Context, scope: D.Scope) !?N.Lease {
    const observer = Raw.om31_observer orelse return null;
    if (observer.record != Recorder.record) return null;
    const r = Recorder.of(observer.context);
    if (r.service != service or !std.meta.eql(r.scope, scope)) return error.ForeignOuterDeviceFsScope;
    if (r.failure) |err| return err;
    if (r.interaction != null) return error.DuplicateOuterDeviceFsInteraction;
    const channel: *const Raw.Om31Channel = @ptrCast(@alignCast(observer.target orelse return error.MissingOuterDeviceFsTarget));
    const current = Raw.om31Checkpoint(channel);
    const last = r.ops.items[r.ops.items.len - 1].after;
    if (!std.mem.eql(u8, &last.digest, &current.digest) or last.draws != current.draws) return error.UnobservedOuterTranscriptMutation;
    var job = Job{ .recorder = r, .keep_interaction = true };
    const code = service.submit(service.session, Job.run, &job);
    if (job.failure) |err| return err;
    try check(code);
    r.inter_consumed = true;
    return r.interaction orelse error.MissingOuterDeviceFsParameters;
}
const Recorder = struct {
    a: std.mem.Allocator,
    addon: std.DynLib,
    service: *Service.Context,
    scope: D.Scope,
    class: [32]u8,
    is_leaf: bool,
    initial: ?Raw.Om31Checkpoint = null,
    ops: std.ArrayList(Op) = .empty,
    words: std.ArrayList(u32) = .empty,
    failure: ?anyerror = null,
    checked: bool = false,
    interaction: ?N.Lease = null,
    inter_consumed: bool = false,
    fn of(raw: *anyopaque) *@This() { return @ptrCast(@alignCast(raw)); }
    fn start(raw: *anyopaque, initial: Raw.Om31Checkpoint) void {
        const self = of(raw);
        if (self.initial != null) { self.failure = error.DuplicateOuterDeviceFsStart; return; }
        self.initial = initial;
    }
    fn record(raw: *anyopaque, event: Raw.Om31Event, after: Raw.Om31Checkpoint) void {
        const self = of(raw);
        if (self.failure != null) return;
        self.append(event, after) catch |err| { self.failure = err; };
    }
    fn append(self: *@This(), event: Raw.Om31Event, after: Raw.Om31Checkpoint) !void {
        if (self.initial == null or self.checked or self.ops.items.len >= 1024) return error.OuterDeviceFsRecordOrder;
        const count: usize = switch (event) { .mix_words => |v| v.len, .mix_felts => |v| try std.math.mul(usize, v.len, 8), else => 8 };
        if (count > (1 << 18) - @min(@as(usize, 1 << 18), self.words.items.len)) return error.OuterDeviceFsRecordBudget;
        const first = self.words.items.len;
        const kind: Kind = switch (event) {
            .mix_words => |v| blk: { try self.words.appendSlice(self.a, v); break :blk .mix_words; },
            .mix_felts => |values| blk: {
                for (values) |v| for (v.toM31Array()) |word| try self.words.append(self.a, word.v);
                break :blk .mix_felts;
            },
            .draw_raw => |v| blk: { try self.words.appendSlice(self.a, &v); break :blk .draw_raw; },
            .draw_om31 => |v| blk: { try self.words.appendSlice(self.a, &v); break :blk .draw_om31; },
        };
        try self.ops.append(self.a, .{ .kind = kind, .first = first, .count = count, .after = after });
    }
    fn before(raw: *anyopaque, current: Raw.Om31Checkpoint) !void {
        const self = of(raw);
        if (self.failure) |err| return err;
        if (self.checked or self.initial == null or self.ops.items.len == 0) return error.OuterDeviceFsRecordOrder;
        const last = self.ops.items[self.ops.items.len - 1].after;
        if (!std.mem.eql(u8, &last.digest, &current.digest) or last.draws != current.draws) return error.UnobservedOuterTranscriptMutation;
        var job = Job{ .recorder = self };
        const code = self.service.submit(self.service.session, Job.run, &job);
        if (job.failure) |err| return err;
        try check(code);
        self.checked = true;
    }
    fn finish(raw: *anyopaque) !void {
        const self = of(raw);
        if (self.failure) |err| return err;
        if (!self.checked or !self.inter_consumed) return error.OuterDeviceFsCheckNotConsumed;
    }
    fn destroy(raw: *anyopaque) void {
        const self = of(raw);
        if (self.interaction) |*lease| {
            const Release = struct {
                service: *Service.Context,
                lease: *N.Lease,
                fn run(_: *anyopaque, _: u64, user: ?*anyopaque) callconv(.c) c_int {
                    const job: *@This() = @ptrCast(@alignCast(user orelse return 1));
                    return job.service.lease_release(job.service.session, job.lease);
                }
            };
            var job = Release{ .service = self.service, .lease = lease };
            if (self.service.submit(self.service.session, Release.run, &job) != 0) {
                const cleanup = self.service.library.lookup(N.Submit, "stwo_rv64_gpu_session_cleanup");
                if (cleanup == null or cleanup.?(self.service.session, Release.run, &job) != 0)
                    std.log.err("outer device FS parameter cleanup deferred to terminal context destruction", .{});
            }
        }
        self.addon.close();
        self.ops.deinit(self.a);
        self.words.deinit(self.a);
        self.a.destroy(self);
    }
};
const Job = struct {
    recorder: *Recorder,
    keep_interaction: bool = false,
    failure: ?anyerror = null,
    fn run(raw: *anyopaque, token: u64, user: ?*anyopaque) callconv(.c) c_int {
        const self: *@This() = @ptrCast(@alignCast(user orelse return 1));
        self.execute(raw, token) catch |err| { self.failure = err; return 1; };
        return 0;
    }
    fn execute(self: *@This(), raw: *anyopaque, token: u64) !void {
        const r = self.recorder;
        const a = r.a;
        const service = r.service;
        const lib = &service.library;
        const api = SC.Api{ .allocate = service.lease_allocate, .release = service.lease_release, .validate_range = service.lease_validate_range, .upload = try sym(N.Upload, lib, "stwo_exec_context_memcpy_h2d_async"), .download = try sym(N.Download, lib, "stwo_exec_context_memcpy_d2h_async"), .sync = try sym(N.Sync, lib, "stwo_exec_context_sync"), .lane_stream = try sym(N.LaneStream, lib, "stwo_exec_context_lane_stream") };
        var ctx = SC.Context{ .session = service.session, .native_context = raw, .token = token, .scope = @import("pcs_scope.zig").identity(r.scope), .api = &api };
        defer ctx.active = false;
        var stream: ?*anyopaque = null;
        try check(api.lane_stream(raw, 0, &stream));
        const init = try sym(Init, lib, "stwo_rv64_channel_init_on");
        const mix = try sym(Mix, lib, "stwo_rv64_channel_mix_on");
        const draw = try sym(Draw, lib, "stwo_rv64_channel_draw_on");
        var draws: usize = 0;
        for (r.ops.items) |op| if (op.kind == .draw_raw or op.kind == .draw_om31) { draws += 1; };
        if (draws == 0) return error.OuterDeviceFsNoChallenges;
        if (self.keep_interaction and draws != 2) return error.OuterDeviceFsUnexpectedLookupDraws;
        var parameters: N.Lease = .{};
        errdefer if (parameters.words != null) ctx.release(&parameters) catch {};
        var leases: [5]N.Lease = @splat(.{});
        var made: usize = 0;
        defer {
            ctx.join() catch {};
            for (leases[0..made]) |*lease| ctx.release(lease) catch {};
        }
        const sizes = [_]usize{ 16, 9, @max(1, r.words.items.len), draws * 8, r.ops.items.len * 16 };
        for (&leases, sizes) |*lease, size| { lease.* = try ctx.allocate(size, 0); made += 1; }
        var seed: [9]u32 = undefined;
        for (0..8) |i| seed[i] = std.mem.readInt(u32, r.initial.?.digest[4*i..][0..4], .little);
        seed[8] = r.initial.?.draws;
        try check(api.upload(raw, leases[1].words.?, &seed, @sizeOf(@TypeOf(seed))));
        if (r.words.items.len != 0) try check(api.upload(raw, leases[2].words.?, r.words.items.ptr, r.words.items.len * 4));
        const chain: u64 = 0x4f4d333100000000 | @as(u64, r.scope.ordinal);
        try check(init(raw, 0, leases[0].words.?, leases[1].words.?, chain));
        var output_at: usize = 0;
        for (r.ops.items, 0..) |op, i| {
            const boundary = leases[4].words.? + i * 16;
            const previous = chain + i;
            const next = previous + 1;
            switch (op.kind) {
                .mix_words, .mix_felts => try check(mix(raw, 0, leases[0].words.?, @intCast(i), previous, next, leases[2].words.? + op.first, @intCast(op.count), @intFromBool(op.kind == .mix_felts), boundary)),
                .draw_om31 => { try check(draw(raw, 0, leases[0].words.?, @intCast(i), previous, next, 1, leases[3].words.? + output_at, boundary)); output_at += 8; },
                .draw_raw => { const draw_raw = try sym(DrawRaw, lib, "stwo_blake2s_transcript_draw_u32s_on"); try check(draw_raw(leases[0].words.?, @intCast(i), previous, next, leases[3].words.? + output_at, leases[3].words.? + output_at, boundary, stream.?)); output_at += 8; },
            }
        }
        if (self.keep_interaction) {
            parameters = try ctx.allocate(56, 0);
            const lookup = try sym(LookupParams, &r.addon, "stwo_rv64_outer_fs_lookup_params_on");
            try check(lookup(raw, 0, leases[3].words.?, parameters.words.?, leases[0].words.? + 10));
        }
        var parameter_words: [56]u32 = undefined;
        var terminal: [16]u32 = undefined;
        if (self.keep_interaction) {
            try check(api.download(raw, &parameter_words, parameters.words.?, @sizeOf(@TypeOf(parameter_words))));
            try check(api.download(raw, &terminal, leases[0].words.?, @sizeOf(@TypeOf(terminal))));
        }
        const boundaries = try a.alloc(u32, r.ops.items.len * 16);
        defer a.free(boundaries);
        const outputs = try a.alloc(u32, draws * 8);
        defer a.free(outputs);
        try check(api.download(raw, boundaries.ptr, leases[4].words.?, boundaries.len * 4));
        try check(api.download(raw, outputs.ptr, leases[3].words.?, outputs.len * 4));
        try ctx.join(); // One final parity readback after the entire batch.
        output_at = 0;
        for (r.ops.items, 0..) |op, i| {
            const actual = boundaries[i * 16..][0..16];
            var expected: [16]u32 = @splat(0);
            for (0..8) |j| expected[j] = std.mem.readInt(u32, op.after.digest[4*j..][0..4], .little);
            expected[8] = op.after.draws;
            expected[9] = @intCast(i + 1);
            expected[12] = @truncate(chain + i + 1);
            expected[13] = @truncate((chain + i + 1) >> 32);
            if (!std.mem.eql(u32, actual, &expected)) {
                std.debug.print("GPU_OUTER_DEVICE_FS mismatch ordinal={} op={} kind={s} expected={any} actual={any}\n", .{ r.scope.ordinal, i, @tagName(op.kind), expected, actual.* });
                return error.OuterDeviceFsCheckpointMismatch;
            }
            if (op.kind == .draw_raw or op.kind == .draw_om31) {
                if (!std.mem.eql(u32, outputs[output_at..][0..8], r.words.items[op.first..][0..8])) return error.OuterDeviceFsChallengeMismatch;
                output_at += 8;
            }
        }
        if (self.keep_interaction) {
            if (terminal[10] != 0) return error.InvalidOuterDeviceFsParameters;
            var z_alpha: [16]u32 = undefined;
            var at: usize = 0;
            for (r.ops.items) |op| if (op.kind == .draw_om31) {
                if (at + 8 > z_alpha.len) return error.OuterDeviceFsUnexpectedLookupDraws;
                @memcpy(z_alpha[at..][0..8], r.words.items[op.first..][0..8]);
                at += 8;
            };
            if (at != 16) return error.OuterDeviceFsUnexpectedLookupDraws;
            var expected: [56]u32 = undefined;
            @memcpy(expected[0..8], z_alpha[0..8]);
            var limbs: [8]Core.fields.m31.M31 = undefined;
            for (&limbs, z_alpha[8..16]) |*value, word| value.* = Core.fields.m31.M31.fromCanonical(word);
            const alpha = Core.fields.om31.OM31.fromM31Array(limbs);
            var power = Core.fields.om31.OM31.one();
            for (0..6) |i| {
                for (power.toM31Array(), 0..) |word, j| expected[8 + 8 * i + j] = word.v;
                power = power.mul(alpha);
            }
            if (!std.mem.eql(u32, &expected, &parameter_words)) return error.OuterDeviceFsParametersMismatch;
            r.interaction = parameters;
        }
        std.debug.print("GPU_OUTER_DEVICE_FS check_ok ordinal={} class={x} leaf={} phase={s} ops={} draw_blocks={} input_words={} checkpoint_words={} resident_consumers=inter\n", .{ r.scope.ordinal, r.class[0..8], r.is_leaf, if (self.keep_interaction) "lookup_params" else "before_pcs", r.ops.items.len, draws, r.words.items.len, boundaries.len });
    }
};

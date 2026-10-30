//! Device epoch challenge schedule from the original value-free grammar.
//! The epoch digest is an authenticated public operand supplied in a resident
//! slot; this module does not establish epoch admission or global closure.
const std = @import("std");
const core = @import("stwo_core");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const B3 = cuda.runtime.stages.blake3;
const Epoch = @import("../../frontends/riscv/prover/block_v7_execution_epoch_v1.zig");
const Fixed = @import("../../frontends/riscv/recursion/air/blake3_fixed_operation_recorder_v1.zig");
const Grammar = @import("../../frontends/riscv/recursion/air/block_v7_epoch_transcript_v1.zig");
pub const DRAW_COUNT = 106;
pub const Step = union(enum) { words: struct { first: usize, count: usize }, secure: struct { first: usize, count: usize } };
pub const Plan = struct {
    arena: std.heap.ArenaAllocator,
    words: []const u32,
    steps: []const Step,
    pub fn init(backing: std.mem.Allocator, epoch: Epoch.Epoch) !Plan {
        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const a = arena.allocator();
        var recorder = Fixed.Recorder{ .a = a, .limits = .{} };
        try Grammar.fixed(a, &recorder);
        try recorder.check();
        var words: std.ArrayList(u32) = .empty;
        var steps: std.ArrayList(Step) = .empty;
        try words.appendSlice(a, &.{ epoch.sharedTag(), Epoch.VERSION, 2 });
        var next: usize = 0;
        for (recorder.operations.items) |op| switch (op) {
            .words => |values| {
                const first = words.items.len;
                try words.appendSlice(a, values);
                try steps.append(a, .{ .words = .{ .first = first, .count = values.len } });
            },
            .secure => |draw| {
                const output = draw.output orelse return error.InvalidNativeEpochSchedule;
                const first: usize = switch (output) {
                    .universal => |relation| 2 * relation,
                    .universal_half => |part| 2 * part.relation + part.half,
                    else => return error.InvalidNativeEpochSchedule,
                };
                const count: usize = if (draw.consumption == .one) 1 else 2;
                if (first != next or first + count > DRAW_COUNT or draw.discard_output)
                    return error.InvalidNativeEpochSchedule;
                try steps.append(a, .{ .secure = .{ .first = first, .count = count } });
                next += count;
            },
            else => return error.InvalidNativeEpochSchedule,
        };
        if (next != DRAW_COUNT) return error.InvalidNativeEpochSchedule;
        return .{ .arena = arena, .words = words.items, .steps = steps.items };
    }
    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
pub const Bound = struct {
    plan: *const Plan,
    state: B3.Channels,
    static_words: common.Words,
    epoch_root: common.Words,
    draws: common.SecureFields,
    primed: bool = false,
    executed: bool = false,
    pub fn init(plan: *const Plan, state: B3.Channels, words: common.Words, epoch_root: common.Words, draws: common.SecureFields) !Bound {
        if (state.len != 1 or words.len != plan.words.len or epoch_root.len != 8 or draws.len != DRAW_COUNT)
            return error.InvalidNativeEpochBuffers;
        inline for (.{ words, epoch_root, draws }) |view| {
            if (view.owner != state.owner or view.generation != state.generation) return error.InvalidNativeEpochBuffers;
        }
        return .{ .plan = plan, .state = state, .static_words = words, .epoch_root = epoch_root, .draws = draws };
    }
    pub fn prime(self: *Bound, session: *cuda.runtime.NativeSession) !void {
        if (self.primed) return error.InvalidNativeEpochState;
        try common.requireStage(session, .ingress);
        try session.context.uploadSlice(u32, self.static_words, self.plan.words);
        self.primed = true;
    }
    pub fn execute(self: *Bound, session: *cuda.runtime.NativeSession) !void {
        if (!self.primed or self.executed) return error.InvalidNativeEpochState;
        const Ops = B3.Native;
        try Ops.channel(session, .trace_commit, self.state, try self.static_words.sub(0, 0), 0, .init, 1024);
        try Ops.channel(session, .trace_commit, self.state, try self.static_words.sub(0, 3), 3, .words, 1024);
        try Ops.channel(session, .trace_commit, self.state, self.epoch_root, 8, .root, 1024);
        for (self.plan.steps) |step| switch (step) {
            .words => |span| try Ops.channel(session, .trace_commit, self.state, try self.static_words.sub(span.first, span.count), @intCast(span.count), .words, 1024),
            .secure => |span| try Ops.channel(session, .trace_commit, self.state, try (try self.draws.sub(span.first, span.count)).cast(u32), @intCast(span.count), .secure, 1024),
        };
        self.executed = true;
    }
};

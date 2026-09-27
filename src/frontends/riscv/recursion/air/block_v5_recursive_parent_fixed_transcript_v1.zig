//! Fixed-only compiler of original bounded parent transcript operations.
//! Routed payload buffers contain only lengths: they are passed exclusively to
//! trusted emitters, which construct fixed routing and never evaluate a hash.
//! No native channel, nonce, challenge, query witness or verifier is invented.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Shape = @import("../block_v5_recursive_parent_shape_v1.zig").Shape;
const Schema = @import("../block_v5_recursive_parent_operations_v1.zig");
const plan = @import("blake3_transcript_plan.zig");
const FixedRecorder = @import("blake3_fixed_operation_recorder_v1.zig");
pub const Limits = FixedRecorder.Limits;
const Recorder = FixedRecorder.Recorder;
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: ?*Budget,
    fixed: plan.Plan,
    shape_id: [32]u8,
    pub fn init(a: std.mem.Allocator, admission: anytype, shape: *const Shape, namespace: u32, capacity: u32, limits: Limits) !Owned {
        try shape.validateAgainst(admission);
        if (capacity == 0 or limits.max_operations == 0) return error.InvalidBlake3Transcript;
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const temp = arena.allocator();
        var recorder = Recorder{ .a = temp, .limits = limits };
        if (comptime @hasDecl(@TypeOf(admission.source.*), "replayShape")) admission.source.replayShape(&recorder) else admission.source.replayPublic(&recorder);
        if (recorder.failure) |failure| return failure;
        var suffix: std.ArrayList(Schema.Operation) = .empty;
        try Schema.appendClosedSuffix(temp, &suffix, shape);
        for (suffix.items) |operation| try recorder.suffix(operation);
        const fixed = try plan.Plan.initCompact(a, .{ .namespace = namespace, .attempt_capacity = capacity }, recorder.operations.items);
        return .{ .allocator = a, .budget = lease, .fixed = fixed, .shape_id = shape.seal };
    }
    pub fn validateAgainst(self: *const Owned, shape: *const Shape) !void {
        try shape.validate();
        try self.fixed.validate();
        if (!std.meta.eql(self.shape_id, shape.seal)) return error.UntrustedRecursiveParentShape;
    }
    pub fn deinit(self: *Owned) void {
        const lease = self.budget;
        self.fixed.deinit();
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};

//! M8 request feeder glue (STWO_RV64_M8_JOBS=1; jobs/provider.zig is the
//! jobs-clean core). The resident service selects both hybrids through
//! `jobs/provider.zig Selection` and, per request, threads every job seam
//! through the feeder's publication ledger:
//!
//!   native Stage1Job   ResidentStages.numerical.prove   -> ledger .native_stage1
//!   native Stage2Job   ResidentStages.native_stage_two  -> ledger .native_stage2
//!   OuterNodeJob       Factory.whole_node (+ the precommitted FIXED's)
//!                                                       -> ledger .outer_node
//!
//! Each hybrid runs its own finish-time acceptance (Stage1 verdict +
//! native_binding.checkAuthority, Stage2 global status words +
//! native_stage2.accept, OuterNodeJob lookup status) and returns an error on
//! rejection; the wrapper records the outcome, and `seal` (before the request
//! is answered and its combined publication entry written) refuses
//! publication unless every job that ran was accepted. The wrappers change no
//! proof byte: they forward the same arguments and results.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const P = @import("jobs/provider.zig");
const Child = CPU.rv64_gkr_child;
const Dev = Outer.device_prove;
const Q = Outer.protocol.Q;

pub const Selection = P.Selection;

/// Per-kind sequence numbers: a seam may legitimately run twice for one
/// ordinal (replays), so ledger keys are attempts, not ordinals.
const Sequence = struct {
    next: std.atomic.Value(u32) = .init(0),
    fn take(self: *Sequence) u32 {
        return self.next.fetchAdd(1, .monotonic);
    }
    fn reset(self: *Sequence) void {
        self.next.store(0, .monotonic);
    }
};

pub const Feeder = struct {
    core: *P.Feeder,
    seq: [@typeInfo(P.Kind).@"enum".fields.len]Sequence = @splat(.{}),
    // native seams
    inner_numerical: ?*const Child.NumericalStage = null,
    numerical: Child.NumericalStage = undefined,
    inner_stage_two: ?StageTwo = null,
    // outer seams, one per lane (index = lane)
    lanes: [4]LaneWrap = undefined,
    lane_count: usize = 0,

    pub const NativeStageTwo = @FieldType(CPU.rv64_ethereum_gkr_main.ResidentStages, "native_stage_two");
    const StageTwo = @typeInfo(NativeStageTwo).optional.child;

    /// null unless STWO_RV64_M8_JOBS=1 (a contradictory selection fails closed).
    pub fn create(a: std.mem.Allocator) !?*Feeder {
        const chosen = try P.Selection.fromProcess();
        if (!chosen.feeder) return null;
        const core = try P.Feeder.create(a, chosen);
        errdefer core.destroy();
        const self = try a.create(Feeder);
        self.* = .{ .core = core };
        return self;
    }
    pub fn destroy(self: *Feeder) void {
        const a = self.core.a;
        self.core.destroy();
        a.destroy(self);
    }
    pub fn selection(self: *const Feeder) P.Selection {
        return self.core.selection;
    }
    pub fn beginRequest(self: *Feeder) void {
        for (&self.seq) |*s| s.reset();
        self.core.beginRequest();
    }

    fn run(self: *Feeder, kind: P.Kind, comptime T: type, result: anyerror!T) !T {
        const index = self.seq[@intFromEnum(kind)].take();
        try self.core.ledger.expect(kind, index);
        const value = result catch |err| {
            self.core.ledger.fail(kind, index, err);
            return err;
        };
        try self.core.ledger.acceptStatus(kind, index, &.{}, null);
        return value;
    }

    // ---- native: wrap what the native hybrid installed into `stages` ----

    /// Call after the native hybrid's `install(&stages)`; forwards to it.
    pub fn wrapNative(self: *Feeder, stages: anytype) !void {
        const numerical = stages.numerical orelse return error.M8FeederNativeStageMissing;
        const stage_two = stages.native_stage_two orelse return error.M8FeederNativeStageMissing;
        self.inner_numerical = numerical;
        self.numerical = numerical.*;
        self.numerical.context = self;
        self.numerical.prove = prove;
        stages.numerical = &self.numerical;
        // bind / abort / replay_binding keep the hybrid's context: rebind them.
        self.numerical.bind = if (numerical.bind != null) bind else null;
        self.numerical.abort = if (numerical.abort != null) abort else null;
        self.numerical.replay_binding = if (numerical.replay_binding != null) replay else null;
        self.inner_stage_two = stage_two;
        stages.native_stage_two = .{ .context = self, .stage_two = stageTwo };
    }
    fn of(raw: *anyopaque) *Feeder {
        return @ptrCast(@alignCast(raw));
    }
    const ProveFn = @typeInfo(@FieldType(Child.NumericalStage, "prove")).pointer.child;
    const GkrProof = @typeInfo(@typeInfo(ProveFn).@"fn".return_type.?).error_union.payload;
    const AbortFn = @typeInfo(@typeInfo(@FieldType(Child.NumericalStage, "abort")).optional.child).pointer.child;
    const Scope = @typeInfo(AbortFn).@"fn".params[1].type.?;
    fn prove(raw: *anyopaque, a: std.mem.Allocator, request: Child.NumericalStage.Request) anyerror!GkrProof {
        const self = of(raw);
        const inner = self.inner_numerical.?;
        return self.run(.native_stage1, GkrProof, inner.prove(inner.context, a, request));
    }
    fn bind(raw: *anyopaque, a: std.mem.Allocator, request: Child.DeviceBinding.Request) anyerror!Child.DeviceBinding.Owner {
        const inner = of(raw).inner_numerical.?;
        return inner.bind.?(inner.context, a, request);
    }
    fn abort(raw: *anyopaque, scope: Scope) void {
        const inner = of(raw).inner_numerical.?;
        inner.abort.?(inner.context, scope);
    }
    fn replay(raw: *anyopaque, a: std.mem.Allocator, request: Child.NumericalStage.Request, owner: *Child.DeviceBinding.Owner) anyerror!void {
        const inner = of(raw).inner_numerical.?;
        return inner.replay_binding.?(inner.context, a, request, owner);
    }
    const StageTwoFn = @typeInfo(@FieldType(StageTwo, "stage_two")).pointer.child;
    const StageTwoParams = @typeInfo(StageTwoFn).@"fn".params;
    const CpuEncoded = @typeInfo(@typeInfo(StageTwoFn).@"fn".return_type.?).error_union.payload;
    fn stageTwo(raw: *anyopaque, a: std.mem.Allocator, worker: StageTwoParams[2].type.?, pending: StageTwoParams[3].type.?, index: usize, budget: usize) anyerror!CpuEncoded {
        const self = of(raw);
        const inner = self.inner_stage_two.?;
        return self.run(.native_stage2, CpuEncoded, inner.stage_two(inner.context, a, worker, pending, index, budget));
    }

    // ---- outer: wrap each lane factory the outer hybrid installed ----

    const LaneWrap = struct {
        feeder: *Feeder,
        inner_node: Dev.WholeNode,
        inner_precommit: @FieldType(Dev.Factory, "precommit_fixed"),
        inner_context: *anyopaque,
    };

    /// Call after the outer hybrid's `install(lanes, ...)` (each lane's
    /// `factory` is then the job-backed one).
    pub fn wrapOuter(self: *Feeder, lanes: anytype) !void {
        if (lanes.len > self.lanes.len) return error.M8FeederTooManyLanes;
        for (lanes, 0..) |*lane, i| {
            const node = lane.factory.whole_node orelse return error.M8FeederOuterStageMissing;
            // The outer window and the native per-job windows share one
            // WorkerSet: recursion device work must start after native
            // completion, or their unparks would collide (fail closed here).
            if (!lane.factory.requires_native_complete) return error.M8FeederSharedSetRequiresNativeComplete;
            self.lanes[i] = .{ .feeder = self, .inner_node = node, .inner_precommit = lane.factory.precommit_fixed, .inner_context = lane.factory.context };
            lane.factory.whole_node = .{ .context = &self.lanes[i], .prove = wholeNode };
        }
        self.lane_count = lanes.len;
        // precommit_fixed returns a PrecommittedFixed whose whole_node wins
        // over the factory's: route it through the same wrapper. The factory
        // context stays the hybrid lane's, so the wrapper is per lane.
        inline for (0..4) |i| if (i < lanes.len) if (lanes[i].factory.precommit_fixed != null) {
            lanes[i].factory.precommit_fixed = precommitFor(i);
        };
    }
    fn wholeNode(raw: *anyopaque, a: std.mem.Allocator, key: *const Outer.prove.Authority, graph: *const @import("stwo_circuit_frontend").builder.Context(Q), expected: []const Q, ordinal: u32) anyerror!Outer.prove.Produced {
        const lane: *LaneWrap = @ptrCast(@alignCast(raw));
        return lane.feeder.run(.outer_node, Outer.prove.Produced, lane.inner_node.prove(lane.inner_node.context, a, key, graph, expected, ordinal));
    }
    const PP = @import("stwo_circuit_frontend").common.preprocessed.PreprocessedCircuit;
    fn precommitFor(comptime i: usize) @typeInfo(@FieldType(Dev.Factory, "precommit_fixed")).optional.child {
        return struct {
            fn f(raw: *anyopaque, a: std.mem.Allocator, pp: *const PP, ordinal: u32) anyerror!Dev.PrecommittedFixed {
                const lane = &active.?.lanes[i];
                if (raw != lane.inner_context) return error.M8FeederLaneMismatch;
                var fixed = try lane.inner_precommit.?(lane.inner_context, a, pp, ordinal);
                if (fixed.whole_node != null) fixed.whole_node = .{ .context = lane, .prove = wholeNode };
                return fixed;
            }
        }.f;
    }
    /// The one feeder of the process (the precommit wrapper keeps the hybrid's
    /// factory context, so it finds its lane through this).
    var active: ?*Feeder = null;
    pub fn activate(self: *Feeder) void {
        active = self;
    }

    /// The publication gate (before the request is answered). `out_dir`
    /// receives m8-feeder.json.
    pub fn seal(self: *Feeder, out_dir: ?[]const u8) !void {
        const Nop = struct {
            fn run(_: void) !void {}
        };
        try self.core.publish(out_dir, {}, Nop.run);
    }
};

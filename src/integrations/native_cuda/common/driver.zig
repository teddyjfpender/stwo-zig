//! AIR-independent execution of one prepared resident CUDA proof.

const std = @import("std");

/// Builds a retained proof driver from a transaction implementation and a
/// structural executor. The executor owns request admission and AIR semantics;
/// this driver owns only transaction lifetime, schedule order, graph replay,
/// and the single final proof read.
pub fn DriverFor(comptime Transaction: type, comptime Executor: type) type {
    comptime assertExecutor(Executor);
    return struct {
        const Self = @This();
        pub const PreparedProof = Executor.PreparedPlan;
        pub const Request = Executor.Request;

        allocator: std.mem.Allocator,

        pub fn prepare(
            self: Self,
            runtime: anytype,
            request: Request,
        ) !PreparedProof {
            const geometry = try Executor.admit(request);
            const target = try Executor.planTarget(runtime.planningSession());
            var prepared = try Executor.prepare(
                self.allocator,
                geometry,
                target,
            );
            errdefer prepared.deinit(self.allocator);
            const arena_plan = try prepared.instantiateArenaPlan(self.allocator);
            try runtime.prepareExecution(
                self.allocator,
                prepared.cacheKey(),
                arena_plan,
            );
            return prepared;
        }

        pub fn runRetained(
            self: Self,
            runtime: anytype,
            request: Request,
        ) !Transaction.StarkBundleOutput {
            var prepared = try self.prepare(runtime, request);
            defer prepared.deinit(self.allocator);
            return self.runPreparedRetained(runtime, request, &prepared);
        }

        pub fn runPreparedRetained(
            self: Self,
            runtime: anytype,
            request: Request,
            prepared: *PreparedProof,
        ) !Transaction.StarkBundleOutput {
            return self.runPrepared(runtime, request, prepared, .graphs);
        }

        /// Forced direct execution is the byte-parity oracle for every cached
        /// graph schedule and remains available to conformance gates.
        pub fn runPreparedRetainedDirect(
            self: Self,
            runtime: anytype,
            request: Request,
            prepared: *PreparedProof,
        ) !Transaction.StarkBundleOutput {
            return self.runPrepared(runtime, request, prepared, .direct);
        }

        const ExecutionMode = enum { graphs, direct };

        fn runPrepared(
            self: Self,
            runtime: anytype,
            request: Request,
            prepared: *PreparedProof,
            mode: ExecutionMode,
        ) !Transaction.StarkBundleOutput {
            const geometry = try Executor.admit(request);
            try Executor.validatePrepared(prepared, geometry);
            const session = try runtime.beginProof();
            var session_live = true;
            errdefer if (session_live) session.abortRetained() catch {};

            session_live = false;
            var transaction = try Transaction.openPreparedCachedRetained(
                self.allocator,
                session,
                prepared.cacheKey(),
            );
            return execute(self, &transaction, prepared, geometry, mode);
        }

        fn execute(
            self: Self,
            transaction: *Transaction,
            prepared: *PreparedProof,
            geometry: Executor.Geometry,
            mode: ExecutionMode,
        ) !Transaction.StarkBundleOutput {
            var transaction_live = true;
            errdefer if (transaction_live) transaction.abort() catch {};

            try Executor.ingress(transaction, prepared, geometry);
            try transaction.finishIngress();

            for (prepared.schedule()) |scheduled| {
                try transaction.beginStage(scheduled.stage);
                const use_graph = mode == .graphs and
                    prepared.graphsEnabled() and
                    scheduled.graph_candidate;
                if (!use_graph) {
                    try Executor.executeNode(
                        transaction,
                        prepared,
                        geometry,
                        scheduled,
                    );
                } else if (try transaction.proofSession().hasStageGraph(
                    prepared.cacheKey(),
                    scheduled.stage,
                )) {
                    try transaction.proofSession().launchStageGraph(
                        prepared.cacheKey(),
                        scheduled.stage,
                    );
                } else {
                    try transaction.proofSession().beginStageGraphCapture(
                        prepared.cacheKey(),
                        scheduled.stage,
                    );
                    Executor.executeNode(
                        transaction,
                        prepared,
                        geometry,
                        scheduled,
                    ) catch |execute_error| {
                        transaction.proofSession()
                            .abortStageGraphCapture() catch |abort_error|
                            return abort_error;
                        return execute_error;
                    };
                    try transaction.proofSession()
                        .finishStageGraphCaptureAndLaunch(
                        prepared.cacheKey(),
                        scheduled.stage,
                    );
                }
                try transaction.endStage(scheduled.stage);
            }

            const output = try transaction.assembleStarkBundleAndFinish(
                self.allocator,
                prepared.proofSlot(),
            );
            transaction_live = false;
            return output;
        }
    };
}

fn assertExecutor(comptime Executor: type) void {
    inline for (&.{
        "Request",
        "Geometry",
        "PreparedPlan",
        "admit",
        "prepare",
        "planTarget",
        "validatePrepared",
        "ingress",
        "executeNode",
    }) |name| {
        if (!@hasDecl(Executor, name))
            @compileError("Native CUDA executor is missing " ++ name);
    }
    const Prepared = Executor.PreparedPlan;
    inline for (&.{
        "deinit",
        "instantiateArenaPlan",
        "proofSlot",
        "schedule",
        "cacheKey",
        "graphsEnabled",
    }) |name| {
        if (!@hasDecl(Prepared, name))
            @compileError("Native CUDA prepared plan is missing " ++ name);
    }
}

test "generic driver admits before execution and aborts failed transactions" {
    const arena = @import("../../../backends/cuda/runtime/arena.zig");
    const execution_plan = @import(
        "../../../backends/cuda/runtime/execution_plan.zig",
    );
    const telemetry = @import(
        "../../../backends/cuda/runtime/telemetry.zig",
    );
    const TestRequest = struct { valid: bool = true };
    const TestGeometry = struct { marker: u32 };

    const Transaction = struct {
        const GraphSession = struct {
            pub fn hasStageGraph(
                _: *@This(),
                _: [32]u8,
                _: telemetry.Stage,
            ) !bool {
                return false;
            }
            pub fn launchStageGraph(
                _: *@This(),
                _: [32]u8,
                _: telemetry.Stage,
            ) !void {}
            pub fn beginStageGraphCapture(
                _: *@This(),
                _: [32]u8,
                _: telemetry.Stage,
            ) !void {}
            pub fn finishStageGraphCaptureAndLaunch(
                _: *@This(),
                _: [32]u8,
                _: telemetry.Stage,
            ) !void {}
            pub fn abortStageGraphCapture(_: *@This()) !void {}
        };
        pub const StarkBundleOutput = struct { marker: u32 };
        var graph_session: GraphSession = .{};
        var aborts: usize = 0;
        var final_reads: usize = 0;

        began: bool = false,
        ended: bool = false,

        pub fn openPreparedCachedRetained(
            _: std.mem.Allocator,
            _: anytype,
            key: [32]u8,
        ) !@This() {
            if (key[0] != 7) return error.InvalidPlan;
            return .{};
        }
        pub fn proofSession(_: *@This()) *GraphSession {
            return &graph_session;
        }
        pub fn finishIngress(_: *@This()) !void {}
        pub fn beginStage(self: *@This(), stage: telemetry.Stage) !void {
            if (stage != .pow or self.began) return error.InvalidOrder;
            self.began = true;
        }
        pub fn endStage(self: *@This(), stage: telemetry.Stage) !void {
            if (stage != .pow or !self.began or self.ended)
                return error.InvalidOrder;
            self.ended = true;
        }
        pub fn assembleStarkBundleAndFinish(
            self: *@This(),
            _: std.mem.Allocator,
            proof_slot: arena.SlotId,
        ) !StarkBundleOutput {
            if (!self.ended or proof_slot != 9) return error.InvalidOrder;
            final_reads += 1;
            return .{ .marker = 0xcada };
        }
        pub fn abort(_: *@This()) !void {
            aborts += 1;
        }
    };
    const Executor = struct {
        pub const Request = TestRequest;
        pub const Geometry = TestGeometry;
        var execute_fail = false;
        var execute_calls: usize = 0;

        pub const PreparedPlan = struct {
            arena_plan: arena.Plan,
            scheduled: [1]execution_plan.ScheduledNode,

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                self.arena_plan.deinit(allocator);
            }
            pub fn instantiateArenaPlan(
                self: *const @This(),
                allocator: std.mem.Allocator,
            ) !arena.Plan {
                return self.arena_plan.clone(allocator);
            }
            pub fn proofSlot(_: *const @This()) arena.SlotId {
                return 9;
            }
            pub fn schedule(
                self: *const @This(),
            ) []const execution_plan.ScheduledNode {
                return &self.scheduled;
            }
            pub fn cacheKey(_: *const @This()) [32]u8 {
                return [_]u8{7} ** 32;
            }
            pub fn graphsEnabled(_: *const @This()) bool {
                return false;
            }
        };

        pub fn admit(request: Request) !Geometry {
            if (!request.valid) return error.InvalidRequest;
            return .{ .marker = 11 };
        }
        pub fn planTarget(_: anytype) !u8 {
            return 5;
        }
        pub fn prepare(
            allocator: std.mem.Allocator,
            geometry: Geometry,
            target: u8,
        ) !PreparedPlan {
            if (geometry.marker != 11 or target != 5)
                return error.InvalidPlan;
            const requirements = [_]arena.Requirement{.{
                .id = 9,
                .words = 4,
                .live_from = .proof_assembly,
                .live_through = .proof_assembly,
            }};
            return .{
                .arena_plan = try arena.Plan.init(allocator, &requirements),
                .scheduled = .{.{
                    .node_id = 0,
                    .kind = .pow,
                    .stage = .pow,
                    .stream_index = 0,
                    .graph_region = 0,
                    .graph_candidate = false,
                    .dependency_count = 0,
                }},
            };
        }
        pub fn validatePrepared(
            _: *const PreparedPlan,
            geometry: Geometry,
        ) !void {
            if (geometry.marker != 11) return error.InvalidPlan;
        }
        pub fn ingress(
            _: *Transaction,
            _: *PreparedPlan,
            _: Geometry,
        ) !void {}
        pub fn executeNode(
            _: *Transaction,
            _: *PreparedPlan,
            _: Geometry,
            _: execution_plan.ScheduledNode,
        ) !void {
            execute_calls += 1;
            if (execute_fail) return error.ForcedFailure;
        }
    };
    const Session = struct {
        pub fn abortRetained(_: *@This()) !void {}
    };
    const Runtime = struct {
        session: Session = .{},
        begins: usize = 0,

        pub fn planningSession(self: *@This()) *Session {
            return &self.session;
        }
        pub fn prepareExecution(
            _: *@This(),
            allocator: std.mem.Allocator,
            key: [32]u8,
            owned_plan: arena.Plan,
        ) !void {
            var plan = owned_plan;
            defer plan.deinit(allocator);
            if (key[0] != 7 or plan.placements.len != 1)
                return error.InvalidPlan;
        }
        pub fn beginProof(self: *@This()) !*Session {
            self.begins += 1;
            return &self.session;
        }
    };

    const Driver = DriverFor(Transaction, Executor);
    const driver = Driver{ .allocator = std.testing.allocator };
    var runtime = Runtime{};
    Transaction.aborts = 0;
    Transaction.final_reads = 0;
    Executor.execute_fail = false;
    Executor.execute_calls = 0;
    const output = try driver.runRetained(&runtime, .{});
    try std.testing.expectEqual(@as(u32, 0xcada), output.marker);
    try std.testing.expectEqual(@as(usize, 1), Transaction.final_reads);
    try std.testing.expectEqual(@as(usize, 1), Executor.execute_calls);

    try std.testing.expectError(
        error.InvalidRequest,
        driver.runRetained(&runtime, .{ .valid = false }),
    );
    try std.testing.expectEqual(@as(usize, 1), runtime.begins);

    Executor.execute_fail = true;
    try std.testing.expectError(
        error.ForcedFailure,
        driver.runRetained(&runtime, .{}),
    );
    try std.testing.expectEqual(@as(usize, 1), Transaction.aborts);
    try std.testing.expectEqual(@as(usize, 1), Transaction.final_reads);
}

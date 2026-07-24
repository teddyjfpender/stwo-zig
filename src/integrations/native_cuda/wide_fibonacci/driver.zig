//! Backend-owned ordering for one resident wide-Fibonacci CUDA proof.

const std = @import("std");
const arena = @import("../../../backends/cuda/runtime/arena.zig");
const protocol = @import("protocol.zig");
const request_mod = @import("request.zig");

pub const NativeTransaction =
    @import("../../../backends/cuda/runtime/proof_transaction.zig")
        .ResidentProofTransaction;
pub const NativeRuntime =
    @import("../../../backends/cuda/runtime/process_runtime.zig").NativeRuntime;

/// Instantiates the orchestration independently from a concrete kernel binder.
/// `Executor` is the only layer allowed to translate admitted protocol
/// geometry into device capabilities. It must not expose a CPU/Metal escape.
pub fn DriverFor(comptime Transaction: type, comptime Executor: type) type {
    comptime assertExecutor(Executor);
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        accepted_sms: []const u32,

        pub fn run(
            self: Self,
            request: request_mod.Request,
        ) !Transaction.StarkBundleOutput {
            const geometry = try request_mod.admit(request);
            var prepared = try Executor.prepare(self.allocator, geometry);
            defer prepared.deinit(self.allocator);

            var transaction = try Transaction.openPrepared(
                self.allocator,
                self.accepted_sms,
                prepared.takeArenaPlan(),
            );
            return execute(self, &transaction, &prepared, geometry);
        }

        pub fn runRetained(
            self: Self,
            runtime: anytype,
            request: request_mod.Request,
        ) !Transaction.StarkBundleOutput {
            const geometry = try request_mod.admit(request);
            var prepared = try Executor.prepare(self.allocator, geometry);
            defer prepared.deinit(self.allocator);

            const session = try runtime.beginProof();
            var transaction = try Transaction.openPreparedRetained(
                self.allocator,
                session,
                prepared.takeArenaPlan(),
            );
            return execute(self, &transaction, &prepared, geometry);
        }

        fn execute(
            self: Self,
            transaction: *Transaction,
            prepared: *Executor.PreparedPlan,
            geometry: request_mod.Geometry,
        ) !Transaction.StarkBundleOutput {
            var transaction_live = true;
            errdefer if (transaction_live) transaction.abort() catch {};

            try Executor.ingress(transaction, prepared, geometry);
            try transaction.finishIngress();

            inline for (protocol.execution_stages) |stage| {
                try transaction.beginStage(stage);
                try executeStage(
                    Executor,
                    stage,
                    transaction,
                    prepared,
                    geometry,
                );
                try transaction.endStage(stage);
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

fn executeStage(
    comptime Executor: type,
    comptime stage: protocol.Stage,
    transaction: anytype,
    prepared: *Executor.PreparedPlan,
    geometry: request_mod.Geometry,
) !void {
    switch (stage) {
        .trace_generation => try Executor.traceGeneration(
            transaction,
            prepared,
            geometry,
        ),
        .trace_commit => try Executor.traceCommit(
            transaction,
            prepared,
            geometry,
        ),
        .constraint_evaluation => try Executor.constraintEvaluation(
            transaction,
            prepared,
            geometry,
        ),
        .oods => try Executor.oods(transaction, prepared, geometry),
        .quotient => try Executor.quotient(transaction, prepared, geometry),
        .fri_commit => try Executor.friCommit(transaction, prepared, geometry),
        .pow => try Executor.pow(transaction, prepared, geometry),
        .decommit => try Executor.decommit(transaction, prepared, geometry),
        .ingress, .proof_assembly => unreachable,
    }
}

fn assertExecutor(comptime Executor: type) void {
    if (!@hasDecl(Executor, "PreparedPlan"))
        @compileError("Native CUDA executor requires PreparedPlan");
    inline for (&.{
        "prepare",
        "ingress",
        "traceGeneration",
        "traceCommit",
        "constraintEvaluation",
        "oods",
        "quotient",
        "friCommit",
        "pow",
        "decommit",
    }) |name| {
        if (!@hasDecl(Executor, name))
            @compileError("Native CUDA executor is missing " ++ name);
    }
    const Prepared = Executor.PreparedPlan;
    inline for (&.{ "deinit", "requirements", "proofSlot", "takeArenaPlan" }) |name| {
        if (!@hasDecl(Prepared, name))
            @compileError("Native CUDA prepared plan is missing " ++ name);
    }
}

test "driver owns exact stage order and one final proof read" {
    const FakeTransaction = struct {
        pub const StarkBundleOutput = struct {
            marker: u32,
        };

        next_stage: usize = 0,
        final_reads: usize = 0,
        aborted: bool = false,

        pub fn openPrepared(
            allocator: std.mem.Allocator,
            accepted_sms: []const u32,
            owned_plan: arena.Plan,
        ) !@This() {
            var plan = owned_plan;
            defer plan.deinit(allocator);
            if (accepted_sms.len == 0 or plan.placements.len != 1)
                return error.InvalidPlan;
            return .{};
        }

        pub fn finishIngress(self: *@This()) !void {
            if (self.next_stage != 0) return error.InvalidOrder;
        }

        pub fn beginStage(
            self: *@This(),
            stage: protocol.Stage,
        ) !void {
            if (protocol.execution_stages[self.next_stage] != stage)
                return error.InvalidOrder;
        }

        pub fn endStage(
            self: *@This(),
            stage: protocol.Stage,
        ) !void {
            if (protocol.execution_stages[self.next_stage] != stage)
                return error.InvalidOrder;
            self.next_stage += 1;
        }

        pub fn assembleStarkBundleAndFinish(
            self: *@This(),
            _: std.mem.Allocator,
            proof_slot: arena.SlotId,
        ) !StarkBundleOutput {
            if (self.next_stage != protocol.execution_stages.len or
                proof_slot != 99 or self.final_reads != 0)
            {
                return error.InvalidOrder;
            }
            self.final_reads += 1;
            return .{ .marker = 0xcada };
        }

        pub fn abort(self: *@This()) !void {
            self.aborted = true;
        }
    };

    const FakeExecutor = struct {
        const stages = protocol.execution_stages;
        var calls: usize = 0;
        var prepare_calls: usize = 0;

        pub const PreparedPlan = struct {
            items: [1]arena.Requirement = .{.{
                .id = 99,
                .words = 8,
                .live_from = .proof_assembly,
                .live_through = .proof_assembly,
            }},
            plan: arena.Plan,
            plan_live: bool = true,

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                if (self.plan_live) self.plan.deinit(allocator);
            }
            pub fn requirements(self: *const @This()) []const arena.Requirement {
                return &self.items;
            }
            pub fn proofSlot(_: *const @This()) arena.SlotId {
                return 99;
            }
            pub fn takeArenaPlan(self: *@This()) arena.Plan {
                std.debug.assert(self.plan_live);
                self.plan_live = false;
                return self.plan;
            }
        };

        pub fn prepare(
            allocator: std.mem.Allocator,
            _: request_mod.Geometry,
        ) !PreparedPlan {
            calls = 0;
            prepare_calls += 1;
            var prepared = PreparedPlan{ .plan = undefined };
            prepared.plan = try arena.Plan.init(allocator, &prepared.items);
            return prepared;
        }

        pub fn ingress(
            _: *FakeTransaction,
            _: *PreparedPlan,
            geometry: request_mod.Geometry,
        ) !void {
            if (geometry.trace_rows != 1 << 14) return error.InvalidGeometry;
        }

        fn stage(expected: protocol.Stage) !void {
            if (stages[calls] != expected) return error.InvalidOrder;
            calls += 1;
        }

        pub fn traceGeneration(_: *FakeTransaction, _: *PreparedPlan, _: request_mod.Geometry) !void {
            try stage(.trace_generation);
        }
        pub fn traceCommit(_: *FakeTransaction, _: *PreparedPlan, _: request_mod.Geometry) !void {
            try stage(.trace_commit);
        }
        pub fn constraintEvaluation(_: *FakeTransaction, _: *PreparedPlan, _: request_mod.Geometry) !void {
            try stage(.constraint_evaluation);
        }
        pub fn oods(_: *FakeTransaction, _: *PreparedPlan, _: request_mod.Geometry) !void {
            try stage(.oods);
        }
        pub fn quotient(_: *FakeTransaction, _: *PreparedPlan, _: request_mod.Geometry) !void {
            try stage(.quotient);
        }
        pub fn friCommit(_: *FakeTransaction, _: *PreparedPlan, _: request_mod.Geometry) !void {
            try stage(.fri_commit);
        }
        pub fn pow(_: *FakeTransaction, _: *PreparedPlan, _: request_mod.Geometry) !void {
            try stage(.pow);
        }
        pub fn decommit(_: *FakeTransaction, _: *PreparedPlan, _: request_mod.Geometry) !void {
            try stage(.decommit);
        }
    };

    const Driver = DriverFor(FakeTransaction, FakeExecutor);
    const driver = Driver{
        .allocator = std.testing.allocator,
        .accepted_sms = &.{89},
    };
    const request = request_mod.Request{
        .statement = .{ .log_n_rows = 14, .sequence_len = 100 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    };
    FakeExecutor.prepare_calls = 0;
    const output = try driver.run(request);
    try std.testing.expectEqual(@as(u32, 0xcada), output.marker);
    try std.testing.expectEqual(protocol.execution_stages.len, FakeExecutor.calls);
    try std.testing.expectEqual(@as(usize, 1), FakeExecutor.prepare_calls);

    var unsupported = request;
    unsupported.protocol.pow_bits = 11;
    try std.testing.expectError(
        error.UnsupportedProtocol,
        driver.run(unsupported),
    );
    try std.testing.expectEqual(@as(usize, 1), FakeExecutor.prepare_calls);
}

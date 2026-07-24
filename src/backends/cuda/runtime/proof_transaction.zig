//! One movable owner for a complete resident CUDA proof request.

const std = @import("std");
const arena_module = @import("arena.zig");
const column = @import("column.zig");
const decommit_bundle = @import("proof_assembly/decommit_bundle.zig");
const stark_bundle = @import("proof_assembly/stark_bundle.zig");
const runtime_error = @import("error.zig");
const session_module = @import("session.zig");
const telemetry = @import("telemetry.zig");

pub const ResidentProofTransaction = TransactionFor(session_module.NativeSession);

pub fn TransactionFor(comptime Session: type) type {
    const Context = @FieldType(Session, "context");
    const Arena = arena_module.ArenaFor(Context);
    return struct {
        const Self = @This();

        pub const BundleOutput = struct {
            bundle: decommit_bundle.Bundle,
            verdict: Session.FinishVerdict,

            pub fn deinit(
                self: *@This(),
                allocator: std.mem.Allocator,
            ) void {
                self.bundle.deinit(allocator);
                self.* = undefined;
            }
        };

        pub const StarkBundleOutput = struct {
            bundle: stark_bundle.Bundle,
            verdict: Session.FinishVerdict,

            pub fn deinit(
                self: *@This(),
                allocator: std.mem.Allocator,
            ) void {
                self.bundle.deinit(allocator);
                self.* = undefined;
            }
        };

        allocator: std.mem.Allocator,
        plan: arena_module.Plan,
        session: Session,
        arena: Arena,
        arena_live: bool = true,
        state: enum { ingress, proving, finished, aborted } = .ingress,

        pub fn open(
            allocator: std.mem.Allocator,
            accepted_sms: []const u32,
            requirements: []const arena_module.Requirement,
        ) (std.mem.Allocator.Error || runtime_error.Error)!Self {
            const plan = try arena_module.Plan.init(allocator, requirements);
            return openPrepared(allocator, accepted_sms, plan);
        }

        /// Takes ownership of a validated placement plan so product adapters do
        /// not repeat lifetime placement work when opening the transaction.
        pub fn openPrepared(
            allocator: std.mem.Allocator,
            accepted_sms: []const u32,
            owned_plan: arena_module.Plan,
        ) runtime_error.Error!Self {
            var plan = owned_plan;
            errdefer plan.deinit(allocator);
            var session = try Session.open(accepted_sms);
            errdefer session.abort() catch {};
            try session.beginStage(.ingress);
            const arena = try Arena.init(&session.context, &plan);
            return .{
                .allocator = allocator,
                .plan = plan,
                .session = session,
                .arena = arena,
            };
        }

        pub fn slot(
            self: *const Self,
            id: arena_module.SlotId,
        ) runtime_error.Error!column.DeviceSlice(u32) {
            if (!self.arena_live or
                self.state == .finished or
                self.state == .aborted)
            {
                return error.InvalidState;
            }
            return self.arena.slice(id);
        }

        pub fn slotAs(
            self: *const Self,
            comptime F: type,
            id: arena_module.SlotId,
        ) runtime_error.Error!column.DeviceSlice(F) {
            if (!self.arena_live or
                self.state == .finished or
                self.state == .aborted)
            {
                return error.InvalidState;
            }
            return self.arena.sliceAs(F, id);
        }

        pub fn upload(
            self: *Self,
            comptime F: type,
            id: arena_module.SlotId,
            values: []const F,
        ) runtime_error.Error!void {
            if (self.state != .ingress) return error.InvalidState;
            const destination = try self.slotAs(F, id);
            if (destination.len != values.len) return error.SizeOverflow;
            try self.uploadResidentSlice(F, id, 0, values);
        }

        /// Uploads one exact host range into an ingress-live arena slot.
        pub fn uploadResidentSlice(
            self: *Self,
            comptime F: type,
            destination_id: arena_module.SlotId,
            first: usize,
            values: []const F,
        ) runtime_error.Error!void {
            if (self.state != .ingress) return error.InvalidState;
            const active = self.session.context.active_stage orelse
                return error.StageNotActive;
            if (active != .ingress) return error.StageOrderViolation;
            try self.requireSlotLiveAt(destination_id, .ingress);
            if (values.len == 0) return error.SizeOverflow;
            const destination = try (try self.slotAs(
                F,
                destination_id,
            )).sub(first, values.len);
            try self.session.context.uploadSlice(F, destination, values);
        }

        /// Copies one exact resident range without constructing arena-backed
        /// Buffer handles or crossing the host boundary.
        pub fn copyResidentSlice(
            self: *Self,
            comptime F: type,
            destination_id: arena_module.SlotId,
            destination_first: usize,
            source_id: arena_module.SlotId,
            source_first: usize,
            count: usize,
        ) runtime_error.Error!void {
            if (self.state != .proving) return error.InvalidState;
            const destination = try (try self.slotAs(
                F,
                destination_id,
            )).sub(destination_first, count);
            const source = try (try self.slotAs(
                F,
                source_id,
            )).sub(source_first, count);
            try self.session.context.copyDeviceSlice(F, destination, source);
        }

        /// Zeroes an exact live arena range on the active proof stage's stream.
        pub fn zeroResidentSlice(
            self: *Self,
            comptime F: type,
            stage: telemetry.Stage,
            destination_id: arena_module.SlotId,
            first: usize,
            count: usize,
        ) runtime_error.Error!void {
            switch (stage) {
                .ingress => if (self.state != .ingress)
                    return error.InvalidState,
                .proof_assembly => return error.InvalidState,
                else => if (self.state != .proving)
                    return error.InvalidState,
            }
            const active = self.session.context.active_stage orelse
                return error.StageNotActive;
            if (active != stage) return error.StageOrderViolation;
            try self.requireSlotLiveAt(destination_id, stage);
            const destination = try (try self.slotAs(
                F,
                destination_id,
            )).sub(first, count);
            try self.session.zeroResidentSlice(F, stage, destination);
        }

        pub fn finishIngress(self: *Self) runtime_error.Error!void {
            if (self.state != .ingress) return error.InvalidState;
            try self.session.endStage(.ingress);
            self.state = .proving;
        }

        pub fn beginStage(
            self: *Self,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            if (self.state != .proving or
                stage == .ingress or
                stage == .proof_assembly)
            {
                return error.InvalidState;
            }
            try self.session.beginStage(stage);
        }

        pub fn endStage(
            self: *Self,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            if (self.state != .proving or
                stage == .ingress or
                stage == .proof_assembly)
            {
                return error.InvalidState;
            }
            try self.session.endStage(stage);
        }

        /// Performs the one allowed device-to-host read, releases the proof
        /// arena in stream order, and returns authenticated residency evidence.
        pub fn assembleAndFinish(
            self: *Self,
            destination: []u32,
            proof_slot: arena_module.SlotId,
        ) runtime_error.Error!Session.FinishVerdict {
            if (self.state != .proving or !self.arena_live)
                return error.InvalidState;
            try self.session.beginStage(.proof_assembly);
            const source = try self.slot(proof_slot);
            if (source.len != destination.len) return error.SizeOverflow;
            try self.session.context.readProofSlice(u32, destination, source);
            try self.arena.deinit(&self.session.context);
            self.arena_live = false;
            try self.session.endStage(.proof_assembly);
            try self.session.markProofComplete();
            const verdict = try self.session.finish();
            self.plan.deinit(self.allocator);
            self.state = .finished;
            return verdict;
        }

        /// Allocates the sole host result, closes the GPU session, and then
        /// structurally validates the compact bundle without prover work.
        pub fn assembleBundleAndFinish(
            self: *Self,
            allocator: std.mem.Allocator,
            proof_slot: arena_module.SlotId,
        ) !BundleOutput {
            const source = try self.slot(proof_slot);
            const storage = try allocator.alloc(u32, source.len);
            const verdict = self.assembleAndFinish(
                storage,
                proof_slot,
            ) catch |err| {
                allocator.free(storage);
                return err;
            };
            return .{
                .bundle = try decommit_bundle.Bundle.decodeOwned(
                    allocator,
                    storage,
                ),
                .verdict = verdict,
            };
        }

        /// Decodes the complete STARK proof transport after the sole terminal
        /// read. The nested decommitment borrows this allocation.
        pub fn assembleStarkBundleAndFinish(
            self: *Self,
            allocator: std.mem.Allocator,
            proof_slot: arena_module.SlotId,
        ) !StarkBundleOutput {
            const source = try self.slot(proof_slot);
            const storage = try allocator.alloc(u32, source.len);
            const verdict = self.assembleAndFinish(
                storage,
                proof_slot,
            ) catch |err| {
                allocator.free(storage);
                return err;
            };
            return .{
                .bundle = try stark_bundle.Bundle.decodeOwned(
                    allocator,
                    storage,
                ),
                .verdict = verdict,
            };
        }

        /// Releases all registered device memory even when a kernel failed
        /// with an active proof stage.
        pub fn abort(self: *Self) runtime_error.Error!void {
            if (self.state == .finished or self.state == .aborted)
                return error.InvalidState;
            const abort_result = self.session.abort();
            self.arena_live = false;
            self.plan.deinit(self.allocator);
            self.state = .aborted;
            return abort_result;
        }

        fn requireSlotLiveAt(
            self: *const Self,
            id: arena_module.SlotId,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            const placement = try self.plan.placement(id);
            if (stage.index() < placement.requirement.live_from.index() or
                stage.index() > placement.requirement.live_through.index())
            {
                return error.StageOrderViolation;
            }
        }
    };
}

test "proof transaction surface exposes no intermediate host read" {
    const Transaction = ResidentProofTransaction;
    try std.testing.expect(!@hasDecl(Transaction, "download"));
    try std.testing.expect(!@hasDecl(Transaction, "read"));
    try std.testing.expect(@hasDecl(Transaction, "assembleAndFinish"));
    try std.testing.expect(@hasDecl(Transaction, "assembleStarkBundleAndFinish"));
    try std.testing.expect(@hasDecl(Transaction, "abort"));
}

test "proof transaction survives value movement and owns failure cleanup" {
    const FakeContext = struct {
        pub const Buffer = struct {
            pointer: [*]u32,
            words: usize,
            owner: usize,
            generation: u64,
        };

        var storage: [64]u32 = [_]u32{0} ** 64;
        active_stage: ?telemetry.Stage = null,
        frees: usize = 0,
        aborted: bool = false,

        pub fn allocate(self: *@This(), words: usize) runtime_error.Error!Buffer {
            if (self.active_stage != .ingress or words > storage.len)
                return error.AllocationOutsideIngress;
            return .{
                .pointer = &storage,
                .words = words,
                .owner = 1,
                .generation = 1,
            };
        }

        pub fn free(self: *@This(), buffer: *Buffer) runtime_error.Error!void {
            if (buffer.owner != 1 or buffer.generation != 1)
                return error.ContextMismatch;
            self.frees += 1;
            buffer.words = 0;
            buffer.owner = 0;
            buffer.generation = 0;
        }

        pub fn deviceSlicePointer(
            _: *@This(),
            comptime F: type,
            slice: anytype,
            minimum: usize,
        ) runtime_error.Error![*]F {
            if (slice.owner != 1 or slice.generation != 1 or
                slice.len < minimum or slice.address == 0)
            {
                return error.InvalidDeviceAddress;
            }
            return @ptrFromInt(slice.address);
        }

        pub fn uploadSlice(
            self: *@This(),
            comptime F: type,
            destination: anytype,
            source: []const F,
        ) runtime_error.Error!void {
            if (self.active_stage != .ingress)
                return error.HostWriteOutsideIngress;
            const pointer = try self.deviceSlicePointer(F, destination, source.len);
            @memcpy(pointer[0..source.len], source);
        }

        pub fn copyDeviceSlice(
            self: *@This(),
            comptime F: type,
            destination: anytype,
            source: anytype,
        ) runtime_error.Error!void {
            if (self.active_stage == null or destination.len != source.len)
                return error.InvalidState;
            const destination_pointer = try self.deviceSlicePointer(
                F,
                destination,
                destination.len,
            );
            const source_pointer = try self.deviceSlicePointer(
                F,
                source,
                source.len,
            );
            @memcpy(
                destination_pointer[0..destination.len],
                source_pointer[0..source.len],
            );
        }

        pub fn readProofSlice(
            self: *@This(),
            comptime F: type,
            destination: []F,
            source: anytype,
        ) runtime_error.Error!void {
            if (self.active_stage != .proof_assembly)
                return error.HostReadOutsideProofAssembly;
            const pointer = try self.deviceSlicePointer(F, source, destination.len);
            @memcpy(destination, pointer[0..destination.len]);
        }
    };

    const FakeSession = struct {
        pub const FinishVerdict = u8;

        context: FakeContext = .{},
        next_stage: usize = 0,
        complete: bool = false,

        pub fn open(_: []const u32) runtime_error.Error!@This() {
            return .{};
        }

        pub fn beginStage(
            self: *@This(),
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            if (self.context.active_stage != null or
                self.next_stage >= telemetry.all_stages.len or
                telemetry.all_stages[self.next_stage] != stage)
            {
                return error.StageOrderViolation;
            }
            self.context.active_stage = stage;
        }

        pub fn endStage(
            self: *@This(),
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            if (self.context.active_stage != stage)
                return error.StageOrderViolation;
            self.context.active_stage = null;
            self.next_stage += 1;
        }

        pub fn markProofComplete(self: *@This()) runtime_error.Error!void {
            if (self.next_stage != telemetry.all_stages.len)
                return error.StageOrderViolation;
            self.complete = true;
        }

        pub fn finish(self: *@This()) runtime_error.Error!FinishVerdict {
            if (!self.complete or self.context.frees != 1)
                return error.InvalidState;
            return 7;
        }

        pub fn abort(self: *@This()) runtime_error.Error!void {
            self.context.active_stage = null;
            self.context.aborted = true;
        }
    };

    const Transaction = TransactionFor(FakeSession);
    const allocator = std.testing.allocator;
    const requirements = [_]arena_module.Requirement{.{
        .id = 9,
        .words = 8,
        .live_from = .ingress,
        .live_through = .proof_assembly,
    }};
    var transaction = try Transaction.open(
        allocator,
        &.{89},
        &requirements,
    );
    try transaction.upload(u32, 9, &.{ 1, 2, 3, 4, 0, 0, 0, 0 });
    try transaction.finishIngress();
    try transaction.beginStage(.trace_generation);
    try transaction.copyResidentSlice(u32, 9, 4, 9, 0, 4);
    try transaction.endStage(.trace_generation);
    inline for (.{
        telemetry.Stage.trace_commit,
        telemetry.Stage.constraint_evaluation,
        telemetry.Stage.oods,
        telemetry.Stage.quotient,
        telemetry.Stage.fri_commit,
        telemetry.Stage.pow,
        telemetry.Stage.decommit,
    }) |stage| {
        try transaction.beginStage(stage);
        try transaction.endStage(stage);
    }
    var output: [8]u32 = undefined;
    try std.testing.expectEqual(
        @as(u8, 7),
        try transaction.assembleAndFinish(&output, 9),
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 1, 2, 3, 4, 1, 2, 3, 4 },
        &output,
    );

    var failed = try Transaction.open(allocator, &.{89}, &requirements);
    try failed.finishIngress();
    try failed.beginStage(.trace_generation);
    try failed.abort();
    try std.testing.expect(failed.session.context.aborted);
}

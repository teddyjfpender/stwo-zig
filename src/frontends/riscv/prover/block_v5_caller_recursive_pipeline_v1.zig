//! The original staged caller lifecycle with both genuine recursive children.
//! Retain one owned B5CF base proof until its arithmetic companion exists.
//! Capture each original verifier once; never regenerate witness matrices or
//! retain the caller's witness/PCS. Published children remain open equations.
const std = @import("std");
const Caller = @import("block_v5_caller_pipeline_v1.zig");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const ArithmeticAdmission = @import("block_v5_caller_arithmetic_recursive_admission_v1.zig");
const FusedAdmission = @import("block_v5_caller_fused_recursive_admission_v1.zig");
const PairModule = @import("block_v5_caller_recursive_admission_pair_v1.zig");
const ArithmeticStage = @import("block_v5_caller_arithmetic_recursive_stage_v1.zig");
const FusedStage = @import("block_v5_caller_fused_recursive_stage_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Pin = @import("block_v5_caller_fused_receiver_v1.zig").Pin;
const Staged = @import("block_v5_caller_columns_stage_v1.zig");
const Pool = @import("stwo_prover_engine").work_pool.WorkPool;

pub const Sinks = struct { arithmetic: ArithmeticStage.Sink, fused: FusedStage.Sink };
pub const Admissions = PairModule.Pair;

pub fn pinFor(bound: *const Caller.Bound, sealed: Seal.Sealed) !Pin {
    return .{ .statement = &bound.proposal.statement, .total_steps = bound.proposal.total_steps, .execution_instance_id = bound.record.execution.instance_id, .expected_key_id = bound.record.key_id, .expected_caller_instance_id = bound.record.instance_id, .roots = bound.record.roots, .witness_root = bound.proposal.witness_root, .frame = bound.proposal.frame, .expected_rw_events = try @import("block_execution_external_trace_v2.zig").expectedEventCountForMode(&bound.proposal.statement, sealed.register_custody_mode) };
}

/// Bounded ownership/order guard, not proof authority. An accepted payload is
/// only owned transport until both actual verifier captures have succeeded.
pub fn Pending(comptime Payload: type) type {
    return struct {
        index: u32,
        value: ?Payload = null,
        phase: enum { empty, holding, verifying, children_published, fused_forwarding, fused_forwarded, caller_forwarding, complete } = .empty,
        pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
            if (self.value) |*owned| owned.deinit(a);
            self.* = undefined;
        }
        pub fn take(self: *@This(), index: u32, payload: *Payload) !void {
            if (index != self.index or self.phase != .empty or self.value != null)
                return error.UnexpectedRecursiveCallerFusedProof;
            self.value = payload.*;
            payload.* = undefined;
            self.phase = .holding;
        }
        pub fn begin(self: *@This(), index: u32) !*const Payload {
            if (index != self.index or self.phase != .holding or self.value == null)
                return error.MissingRecursiveCallerFusedProof;
            self.phase = .verifying;
            return &self.value.?;
        }
        pub fn childrenPublished(self: *@This()) !void {
            if (self.phase != .verifying or self.value == null)
                return error.InvalidRecursiveCallerPublicationOrder;
            self.phase = .children_published;
        }
        pub fn forward(self: *@This(), context: *anyopaque, put: *const fn (*anyopaque, u32, *Payload) anyerror!void) !void {
            if (self.phase != .children_published or self.value == null)
                return error.InvalidRecursiveCallerPublicationOrder;
            // Error consumes nothing. Success transfers ownership once.
            self.phase = .fused_forwarding;
            put(context, self.index, &self.value.?) catch |err| {
                self.phase = .children_published;
                return err;
            };
            self.value = null;
            self.phase = .fused_forwarded;
        }
        pub fn requireCaller(self: *const @This(), index: u32) !void {
            if (index != self.index or self.phase != .fused_forwarded or self.value != null)
                return error.InvalidRecursiveCallerPublicationOrder;
        }
        pub fn beginCaller(self: *@This(), index: u32) !void {
            try self.requireCaller(index);
            self.phase = .caller_forwarding;
        }
        pub fn callerPublished(self: *@This(), index: u32) !void {
            if (index != self.index or self.phase != .caller_forwarding or self.value != null)
                return error.InvalidRecursiveCallerPublicationOrder;
            self.phase = .complete;
        }
        pub fn requireFinished(self: *const @This()) !void {
            if (self.phase != .complete or self.value != null)
                return error.IncompleteRecursiveCallerPublication;
        }
    };
}

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Pipeline = Caller.ForBackend(Backend);
        const Arithmetic = ArithmeticStage.ForBackend(Backend);
        const Projection = FusedStage.ForBackend(Backend);
        const Warm = @import("block_v5_precompile_batch_v1.zig").ForBackend(Backend).WarmCaller;
        pub const Options = struct {
            arithmetic: Arithmetic.Options,
            fused: Projection.Options,
            arithmetic_limits: ArithmeticAdmission.Limits = .{},
            fused_limits: FusedAdmission.Limits = .{},
            pub fn validate(self: @This(), config: @import("stwo_core").pcs.PcsConfig) !void {
                if (self.arithmetic.profile != self.fused.profile)
                    return error.MixedRecursiveCallerSecurity;
                try self.arithmetic.validate(config);
                try self.fused.validate(config);
            }
        };
        pub const Session = struct {
            a: std.mem.Allocator,
            admissions: *Admissions,
            owns_admissions: bool = false,
            arithmetic: *const ArithmeticAdmission.Prepared,
            fused: *const FusedAdmission.Prepared,
            pending: Pending(Fused.Proof),
            base: Caller.Sink,
            recursive: Sinks,
            options: Options,
            pub fn init(a: std.mem.Allocator, index: u32, pin: Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, base: Caller.Sink, recursive: Sinks, options: Options) !Session {
                try options.validate(pins.config);
                if (base.put_fused == null) return error.MissingV5CanonicalCallerFusionSink;
                const admissions = try Admissions.create(a, index, pin, sealed, pins, entries, .{ .arithmetic = options.arithmetic_limits, .fused = options.fused_limits });
                errdefer admissions.deinit();
                var session = try bindAdmissions(a, admissions, base, recursive, options);
                session.owns_admissions = true;
                return session;
            }
            /// The catalog remains alive through sessions, file loaders and
            /// all hierarchy workers. Destroying a session releases only its
            /// lease; it cannot invalidate the durable Prepared policies.
            pub fn initBorrowed(a: std.mem.Allocator, admissions: *Admissions, base: Caller.Sink, recursive: Sinks, options: Options) !Session {
                try admissions.require();
                return bindAdmissions(a, admissions, base, recursive, options);
            }
            fn bindAdmissions(a: std.mem.Allocator, admissions: *Admissions, base: Caller.Sink, recursive: Sinks, options: Options) !Session {
                try options.validate(admissions.fused.config);
                if (base.put_fused == null) return error.MissingV5CanonicalCallerFusionSink;
                if (!std.meta.eql(a, admissions.a) or
                    !std.meta.eql(options.arithmetic_limits, admissions.arithmetic.limits) or
                    !std.meta.eql(options.fused_limits, admissions.fused.limits))
                    return error.UntrustedRecursiveCallerAdmissionOwner;
                try admissions.acquireSession();
                return .{ .a = a, .admissions = admissions, .arithmetic = &admissions.arithmetic, .fused = &admissions.fused, .pending = .{ .index = admissions.fused.binding.execution_index }, .base = base, .recursive = recursive, .options = options };
            }
            pub fn deinit(self: *Session) void {
                self.pending.deinit(self.a);
                self.admissions.releaseSession();
                if (self.owns_admissions) self.admissions.deinit();
                self.* = undefined;
            }
            pub fn sink(self: *Session) Caller.Sink {
                return .{ .context = self, .put_caller = putCaller, .put_fused = putFused };
            }
            pub fn hooks(self: *Session) Pipeline.Hooks {
                return .{ .context = self, .on_caller_proof = proved };
            }
            pub fn requireFinished(self: *const Session) !void {
                try self.pending.requireFinished();
            }
            fn putFused(raw: *anyopaque, index: u32, proof: *Fused.Proof) !void {
                const self: *Session = @ptrCast(@alignCast(raw));
                try self.pending.take(index, proof);
            }
            fn putCaller(raw: *anyopaque, index: u32, proof: *Family.Proof) !void {
                const self: *Session = @ptrCast(@alignCast(raw));
                try self.pending.beginCaller(index);
                self.base.put_caller(self.base.context, index, proof) catch |err| {
                    self.pending.phase = .fused_forwarded;
                    return err;
                };
                try self.pending.callerPublished(index);
            }
            fn proved(raw: *anyopaque, a: std.mem.Allocator, warm: Warm, proof: *const Family.Proof) !void {
                const self: *Session = @ptrCast(@alignCast(raw));
                if (!std.meta.eql(a, self.a) or warm.record.execution.index != self.pending.index or
                    !std.meta.eql(warm.record.statement, self.arithmetic.statement) or
                    warm.record.total_steps != self.arithmetic.total_steps or
                    !std.meta.eql(warm.first.binding(warm.sealed), self.arithmetic.binding) or
                    !std.meta.eql(warm.sealed, self.arithmetic.sealed) or
                    !std.meta.eql(warm.pins, self.arithmetic.pins) or
                    !std.meta.eql(warm.entries, self.arithmetic.entries))
                    return error.UntrustedRecursiveCallerWarmLifetime;
                const fused_proof = try self.pending.begin(warm.record.execution.index);
                // The original arithmetic verifier succeeds before any fused
                // capture or publication. No proof-shaped receipt is fabricated.
                var arithmetic = try @import("block_v5_caller_arithmetic_recursive_capture_v1.zig").ForBackend(Backend).verifyBorrowed(a, proof, self.arithmetic);
                const caller_receipt = arithmetic.receipt;
                // Consuming publication releases the genuine capture after its
                // last row reader, before recursive setup/proving. The original
                // producer retains its source proof for the unchanged base sink.
                try Arithmetic.publishConsumingVerifiedCapture(a, &arithmetic, self.arithmetic, self.options.arithmetic, self.recursive.arithmetic);
                var projection = try @import("block_v5_caller_fused_recursive_capture_v1.zig").ForBackend(Backend).verifyAfterFreshCaller(a, fused_proof, &caller_receipt, self.fused);
                try Projection.publishConsumingVerifiedCapture(a, &projection, self.fused, self.options.fused, self.recursive.fused);
                try self.pending.childrenPublished();
                try self.pending.forward(self.base.context, self.base.put_fused.?);
            }
        };

        pub fn proveStaged(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, file_pin: Staged.Pin, bound: *const Caller.Bound, limits: Staged.Limits, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, pool: *Pool, base: Caller.Sink, recursive: Sinks, options: Options) !void {
            try bound.require(a);
            var session = try Session.init(a, bound.record.execution.index, try pinFor(bound, sealed), sealed, pins, entries, base, recursive, options);
            defer session.deinit();
            try Pipeline.proveStaged(a, dir, name, file_pin, bound, limits, sealed, pins, entries, pool, session.sink(), session.hooks());
            try session.requireFinished();
        }
        pub fn proveSegment(a: std.mem.Allocator, segment: *const @import("../runner/mod.zig").EthereumShaSegmentResult, bound: *const Caller.Bound, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, pool: *Pool, base: Caller.Sink, recursive: Sinks, options: Options) !void {
            try bound.require(a);
            var session = try Session.init(a, bound.record.execution.index, try pinFor(bound, sealed), sealed, pins, entries, base, recursive, options);
            defer session.deinit();
            try Pipeline.proveSegment(a, segment, bound, sealed, pins, entries, pool, session.sink(), session.hooks());
            try session.requireFinished();
        }
        fn requireAdmissionSource(a: std.mem.Allocator, bound: *const Caller.Bound, admissions: *const Admissions) !void {
            try bound.require(a);
            const pin = try pinFor(bound, admissions.fused.sealed);
            const expected = FusedAdmission.Receiver.binding(bound.record.execution.index, pin, admissions.fused.sealed);
            if (!std.meta.eql(expected, admissions.fused.binding) or
                !std.meta.eql(pin.statement.*, admissions.fused.statement) or
                pin.total_steps != admissions.fused.total_steps or
                !std.meta.eql(pin.frame, admissions.fused.frame) or
                !std.meta.eql(pin.witness_root, admissions.fused.witness_root) or
                pin.expected_rw_events != admissions.fused.expected_rw_events)
                return error.UntrustedRecursiveCallerAdmissionSource;
        }
        /// Actual staged proving with the same long-lived policies later used
        /// by durable publication and fresh hierarchy verification.
        pub fn proveStagedWithAdmissions(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, file_pin: Staged.Pin, bound: *const Caller.Bound, limits: Staged.Limits, pool: *Pool, base: Caller.Sink, recursive: Sinks, admissions: *Admissions, options: Options) !void {
            try requireAdmissionSource(a, bound, admissions);
            var session = try Session.initBorrowed(a, admissions, base, recursive, options);
            defer session.deinit();
            try Pipeline.proveStaged(a, dir, name, file_pin, bound, limits, admissions.fused.sealed, admissions.fused.pins, admissions.fused.entries, pool, session.sink(), session.hooks());
            try session.requireFinished();
        }
        pub fn proveSegmentWithAdmissions(a: std.mem.Allocator, segment: *const @import("../runner/mod.zig").EthereumShaSegmentResult, bound: *const Caller.Bound, pool: *Pool, base: Caller.Sink, recursive: Sinks, admissions: *Admissions, options: Options) !void {
            try requireAdmissionSource(a, bound, admissions);
            var session = try Session.initBorrowed(a, admissions, base, recursive, options);
            defer session.deinit();
            try Pipeline.proveSegment(a, segment, bound, admissions.fused.sealed, admissions.fused.pins, admissions.fused.entries, pool, session.sink(), session.hooks());
            try session.requireFinished();
        }
    };
}

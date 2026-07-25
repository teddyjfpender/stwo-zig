//! Complete prover transaction contract shared by native and device backends.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const proof = @import("stwo_core").proof;
const component = @import("air/component_prover.zig");
const pcs = @import("pcs/mod.zig");
const prove_mod = @import("prove.zig");
const session_mod = @import("session.zig");
const stage_profile = @import("stage_profile.zig");

pub const ProveOptions = struct {
    include_all_preprocessed_columns: bool = false,
    recorder: ?*stage_profile.Recorder = null,
};

/// Checks the transaction-level surface expected by backend-neutral frontends.
pub fn assertProverEngine(comptime Engine: type) void {
    comptime {
        if (!@hasDecl(Engine, "Scheme")) @compileError("prover engine requires Scheme");
        if (!@hasDecl(Engine, "init")) @compileError("prover engine requires init");
        if (!@hasDecl(Engine, "deinit")) @compileError("prover engine requires deinit");
        if (!@hasDecl(Engine, "commit")) @compileError("prover engine requires commit");
        if (!@hasDecl(Engine, "prove")) @compileError("prover engine requires prove");
    }
}

/// Builds a complete proving engine from a PCS backend and protocol types.
///
/// `commit` consumes its column slice and `prove` consumes the scheme. This
/// keeps ownership identical for host and resident-device implementations.
pub fn ProverEngine(
    comptime B: type,
    comptime H: type,
    comptime MC: type,
    comptime C: type,
) type {
    return struct {
        pub const Backend = B;
        pub const Hasher = H;
        pub const MerkleChannel = MC;
        pub const Channel = C;
        pub const Scheme = pcs.CommitmentSchemeProver(B, H, MC);
        pub const Session = session_mod.ProverSession;
        pub const ExtendedProof = proof.ExtendedStarkProof(H);
        pub const TelemetrySnapshot = if (@hasDecl(B, "TelemetrySnapshot")) B.TelemetrySnapshot else void;
        pub const TelemetryError = if (@hasDecl(B, "TelemetryError")) B.TelemetryError else error{};
        pub const RuntimeInitializationPolicy = if (@hasDecl(B, "RuntimeInitializationPolicy"))
            B.RuntimeInitializationPolicy
        else
            void;
        pub const RuntimeLifecycleSnapshot = if (@hasDecl(B, "RuntimeLifecycleSnapshot"))
            B.RuntimeLifecycleSnapshot
        else
            void;

        pub fn init(allocator: std.mem.Allocator, config: pcs_core.PcsConfig) !Scheme {
            return Scheme.init(allocator, config);
        }

        pub fn deinit(scheme: *Scheme, allocator: std.mem.Allocator) void {
            scheme.deinit(allocator);
        }

        pub fn initSession(
            allocator: std.mem.Allocator,
            config: pcs_core.PcsConfig,
            max_circle_log: u32,
            host_byte_budget: usize,
        ) !Session {
            return Session.init(
                allocator,
                config,
                max_circle_log,
                host_byte_budget,
            );
        }

        pub fn initWithSession(
            session: *const Session,
            config: pcs_core.PcsConfig,
            required_circle_log: u32,
        ) !Scheme {
            try session.validateRequest(config, required_circle_log);
            return Scheme.initWithTwiddleTower(config, &session.twiddle_tower);
        }

        pub fn warmup() !void {
            if (comptime @hasDecl(B, "warmup")) try B.warmup();
        }

        pub fn initializeRuntime(
            allocator: std.mem.Allocator,
            policy: RuntimeInitializationPolicy,
        ) !void {
            if (comptime @hasDecl(B, "initializeRuntime"))
                try B.initializeRuntime(allocator, policy);
        }

        pub fn runtimeLifecycleSnapshot() RuntimeLifecycleSnapshot {
            if (comptime @hasDecl(B, "runtimeLifecycleSnapshot"))
                return B.runtimeLifecycleSnapshot();
        }

        pub fn runtimePlatformIdentityAlloc(allocator: std.mem.Allocator) !?[]u8 {
            if (comptime @hasDecl(B, "runtimePlatformIdentityAlloc"))
                return try B.runtimePlatformIdentityAlloc(allocator);
            return null;
        }

        pub fn telemetrySnapshot() TelemetryError!TelemetrySnapshot {
            if (comptime @hasDecl(B, "telemetrySnapshot")) return B.telemetrySnapshot();
        }

        pub fn commit(
            scheme: *Scheme,
            allocator: std.mem.Allocator,
            columns: []pcs.ColumnEvaluation,
            recorder: ?*stage_profile.Recorder,
            channel: *C,
        ) !void {
            return scheme.commitOwnedWithRecorder(allocator, columns, recorder, channel);
        }

        pub fn commitWithBacking(
            scheme: *Scheme,
            allocator: std.mem.Allocator,
            columns: []pcs.ColumnEvaluation,
            backing_buffers: ?[][]@import("stwo_core").fields.m31.M31,
            recorder: ?*stage_profile.Recorder,
            channel: *C,
        ) !void {
            return commitPreparedWithBacking(
                scheme,
                allocator,
                columns,
                backing_buffers,
                .materialized,
                recorder,
                channel,
            );
        }

        pub fn commitPreparedWithBacking(
            scheme: *Scheme,
            allocator: std.mem.Allocator,
            columns: []pcs.ColumnEvaluation,
            backing_buffers: ?[][]@import("stwo_core").fields.m31.M31,
            source: pcs.ColumnSource,
            recorder: ?*stage_profile.Recorder,
            channel: *C,
        ) !void {
            return scheme.commitOwnedPreparedWithRecorderAndBacking(
                allocator,
                columns,
                backing_buffers,
                source,
                recorder,
                channel,
            );
        }

        pub fn flushPendingCommit(
            scheme: *Scheme,
            allocator: std.mem.Allocator,
            channel: *C,
        ) !void {
            try pcs.flushPendingCommit(MC, scheme, allocator, channel);
        }

        pub fn prove(
            allocator: std.mem.Allocator,
            components: []const component.ComponentProver,
            channel: *C,
            scheme: Scheme,
            options: ProveOptions,
        ) !ExtendedProof {
            return prove_mod.proveExWithRecorder(
                B,
                H,
                MC,
                allocator,
                components,
                channel,
                scheme,
                options.include_all_preprocessed_columns,
                options.recorder,
            );
        }
    };
}

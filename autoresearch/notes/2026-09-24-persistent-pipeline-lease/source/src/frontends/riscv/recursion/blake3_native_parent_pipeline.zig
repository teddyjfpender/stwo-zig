//! Native-child adapter for the shared bounded parent pipeline.
const std = @import("std");
const core = @import("stwo_core");
const preparation = @import("blake3_native_parent_preparation.zig");
const worker_mod = @import("blake3_native_parent_worker.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const verifier = @import("../prover/verifier.zig");
const shared = @import("blake3_parent_pipeline.zig");
pub const MAX_JOBS = shared.MAX_JOBS;
pub const PREPARATION_STACK_BYTES = shared.PREPARATION_STACK_BYTES;
pub const Sizing = shared.Sizing;
pub const Admission = shared.Admission;
pub const Interval = shared.Interval;
pub const Spans = shared.Spans;
pub const Report = shared.Report;
pub fn Job(comptime Engine: type) type {
    return struct {
        statement: *const @import("../air/statement_v2.zig").RiscVStatementV2,
        claim: *const @import("../air/statement.zig").RiscVInteractionClaim,
        capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine),
        config: core.pcs.PcsConfig,
        capacity: u32,
    };
}

pub fn admit(comptime Backend: type, policy: anytype, sizing: Sizing, count: usize) !Admission {
    return shared.admit(struct {
        pub const Worker = worker_mod.Worker(Backend);
        pub const Prepared = preparation.Prepared;
    }, policy, sizing, count);
}
pub fn run(comptime Backend: type, comptime Engine: type, a: std.mem.Allocator, policy: anytype, sizing: Sizing, worker: *worker_mod.Worker(Backend), jobs: []const Job(Engine)) !Report {
    const Input = Job(Engine);
    const Adapter = struct {
        pub const Job = Input;
        pub const Worker = worker_mod.Worker(Backend);
        pub const Prepared = preparation.Prepared;
        pub fn prepare(allocator: std.mem.Allocator, job: Input, limit: usize) !Prepared {
            return preparation.prepareBounded(Engine, allocator, job.statement, job.claim, job.capture, job.config, job.capacity, limit);
        }
        pub fn prove(target: *Worker.Lease, prepared: *const Prepared, _: Input) !artifact.Owned {
            if (!std.meta.eql(prepared.context, target.worker.plan.admission.key.context)) return error.ParentPipelineKeyMismatch;
            return target.prove(&prepared.rows);
        }
    };
    return shared.run(Adapter, a, policy, sizing, worker, jobs);
}

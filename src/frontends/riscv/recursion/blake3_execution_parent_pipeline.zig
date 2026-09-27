//! Full-width execution captures on the shared bounded preparation/proving pipeline.
const std = @import("std");
const shared = @import("blake3_parent_pipeline.zig");
const preparation = @import("blake3_execution_parent_preparation.zig");
const protocol = @import("blake3_execution_parent_protocol.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
pub const Sizing = shared.Sizing;
pub const Report = shared.Report;

/// Verifier/capture types retain the child's typed execution profile. Inputs and
/// the exclusively leased worker outlive run; outputs retain worker-budget leases.
pub fn ForBackend(comptime Backend: type, comptime Verifier: type, comptime Capture: type) type {
    return struct {
        const Self = @This();
        pub const Worker = @import("blake3_native_parent_worker.zig").WorkerForProtocol(Backend, protocol);
        pub const Job = struct {
            verifier: *const Verifier,
            capture: *const Capture,
            expected_child_id: [32]u8,
            admission: protocol.Admission,
            capacity: u32,
        };
        const Adapter = struct {
            pub const Job = Self.Job;
            pub const Worker = Self.Worker;
            pub const Prepared = preparation.Prepared;
            pub fn prepare(a: std.mem.Allocator, job: Self.Job, limit: usize) !Prepared {
                try job.admission.validate();
                var result = try preparation.prepareBounded(a, job.verifier, job.capture, job.expected_child_id, job.capacity, limit);
                errdefer result.deinit();
                try result.rows.partitionHashRows();
                if (!std.meta.eql(result.context, job.admission.key.context)) return error.ParentPipelineKeyMismatch;
                return result;
            }
            pub fn prove(worker: *Self.Worker.Lease, prepared: *Prepared, job: Self.Job) !artifact.Owned {
                if (!std.meta.eql(prepared.context, job.admission.key.context)) return error.ParentPipelineKeyMismatch;
                return worker.proveAdmittedConsuming(&prepared.rows, job.admission);
            }
        };
        pub fn admit(policy: anytype, sizing: Sizing, count: usize) !shared.Admission {
            return shared.admit(Adapter, policy, sizing, count);
        }
        pub fn run(a: std.mem.Allocator, policy: anytype, sizing: Sizing, worker: *Worker, jobs: []const Job) !Report {
            return shared.run(Adapter, a, policy, sizing, worker, jobs);
        }
    };
}

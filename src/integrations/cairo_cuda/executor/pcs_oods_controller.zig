//! Authenticated resident OODS execution for mixed-height Cairo traces.
//!
//! The OODS parameter and quotient challenge are drawn into their resident
//! destinations by the transcript controller. No method accepts host-selected
//! challenge values.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const oods_stage = @import("stwo_cuda_backend").runtime.stages.oods;
const transcript_stage = @import("stwo_cuda_backend").runtime.stages.transcript;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const shared_oods = @import(
    "../../native_cuda/common/oods_executor.zig",
);
const proof_capture = @import(
    "../../native_cuda/common/proof_assembly.zig",
);
const shared_views = @import(
    "../../native_cuda/common/resident_views.zig",
);
const bindings_module = @import("pcs_hooks_types.zig");
const topology_module = @import("pcs_oods_topology.zig");
const quotient_topology = @import("quotient/topology.zig");
const resident_plan = @import("resident_plan.zig");
const transcript_controller = @import("transcript/controller.zig");
const transcript_schedule = @import("transcript/schedule.zig");

const NativeOps = struct {
    const Oods = oods_stage.Native;
    const Transcript = transcript_stage.Native;
    const Capture = proof_capture;
};

pub const State = enum {
    prepared,
    parameter_drawn,
    poisoned,
    complete,
};

pub const Prepared = struct {
    topology: topology_module.Topology,
    bound: topology_module.Bound,
    transcript_view: transcript_controller.View,
    quotient_challenge: common.SecureFields,
    proof: shared_views.Proof,
    plan_identity: proof_ir.Digest,
    schedule: transcript_schedule.Schedule,
    identity: proof_ir.Digest,
    state: State = .prepared,

    pub fn deinit(self: *Prepared) void {
        self.bound.deinit();
        self.topology.deinit();
        self.* = undefined;
    }

    pub fn drawParameter(
        self: *Prepared,
        session: anytype,
        schedule: transcript_schedule.Schedule,
        cursor: *transcript_controller.Cursor,
    ) !void {
        return self.drawParameterWith(
            transcript_stage.Native,
            session,
            schedule,
            cursor,
        );
    }

    pub fn drawParameterWith(
        self: *Prepared,
        comptime Transcript: type,
        session: anytype,
        schedule: transcript_schedule.Schedule,
        cursor: *transcript_controller.Cursor,
    ) !void {
        try self.validate(schedule);
        if (self.state != .prepared)
            return error.InvalidOodsControllerState;
        self.state = .poisoned;
        try transcript_controller.drawSecure(
            Transcript,
            session,
            .constraint_evaluation,
            schedule,
            cursor,
            self.transcript_view,
            3,
            self.bound.oods.parameter,
        );
        self.state = .parameter_drawn;
    }

    pub fn execute(
        self: *Prepared,
        session: anytype,
        schedule: transcript_schedule.Schedule,
        cursor: *transcript_controller.Cursor,
    ) !void {
        return self.executeWith(
            NativeOps,
            session,
            schedule,
            cursor,
        );
    }

    pub fn executeWith(
        self: *Prepared,
        comptime Ops: type,
        session: anytype,
        schedule: transcript_schedule.Schedule,
        cursor: *transcript_controller.Cursor,
    ) !void {
        try self.validate(schedule);
        if (self.state != .parameter_drawn)
            return error.InvalidOodsControllerState;
        self.state = .poisoned;
        for (self.bound.batches) |batch| {
            try shared_oods.deriveBatch(
                Ops.Oods,
                session,
                batch,
                self.bound.oods,
            );
        }
        for (self.bound.batches) |batch| {
            try shared_oods.evaluateBatch(
                Ops.Oods,
                session,
                batch,
                self.bound.oods,
            );
        }
        try Ops.Capture.captureSampledValues(
            session,
            .{
                .oods = self.bound.oods,
                .proof = self.proof,
            },
        );
        try transcript_controller.mixInput(
            Ops.Transcript,
            session,
            .oods,
            schedule,
            cursor,
            self.transcript_view,
            25,
            try self.bound.oods.sampled_values.cast(u32),
        );
        try transcript_controller.drawSecure(
            Ops.Transcript,
            session,
            .oods,
            schedule,
            cursor,
            self.transcript_view,
            4,
            self.quotient_challenge,
        );
        self.state = .complete;
    }

    pub fn validate(
        self: Prepared,
        schedule: transcript_schedule.Schedule,
    ) !void {
        if (std.mem.allEqual(u8, &self.identity, 0) or
            !std.meta.eql(self.schedule, schedule) or
            !std.mem.eql(
                u8,
                &self.topology.identity,
                &self.bound.topology_identity,
            ) or
            self.bound.oods.parameter.len != 1 or
            self.quotient_challenge.len != 1 or
            !std.mem.eql(
                u8,
                &self.identity,
                &preparedIdentity(self),
            ))
        {
            return error.InvalidOodsControllerIdentity;
        }
    }
};

pub fn prepare(
    allocator: std.mem.Allocator,
    session: anytype,
    plan: *const resident_plan.Plan,
    bundle: composition.Bundle,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    bindings: bindings_module.Bindings,
    schedule: transcript_schedule.Schedule,
) !Prepared {
    const expected_schedule = try transcript_schedule.Schedule.init(
        program,
        protocol,
    );
    if (!std.mem.eql(u8, &bindings.identity, &plan.identity) or
        !std.mem.eql(
            u8,
            &schedule.schedule_identity,
            &expected_schedule.schedule_identity,
        ) or
        !std.mem.eql(
            u8,
            &schedule.executable_program_identity,
            &plan.program_identity,
        ) or
        std.mem.allEqual(u8, &plan.identity, 0))
    {
        return error.InvalidOodsControllerIdentity;
    }

    var quotient = try quotient_topology.derive(
        allocator,
        bundle,
        program,
        protocol,
    );
    defer quotient.deinit();
    if (!std.mem.eql(
        u8,
        &plan.quotient_geometry.identity,
        &quotient.identity,
    )) {
        return error.InvalidOodsControllerIdentity;
    }
    var topology = try topology_module.derive(
        allocator,
        bundle,
        program,
        protocol,
        quotient,
    );
    errdefer topology.deinit();
    var bound = try topology_module.Bound.init(
        allocator,
        topology,
        quotient,
        bindings.trees,
        bindings.oods,
    );
    errdefer bound.deinit();
    try topology.upload(session, bound.oods);
    const transcript_view = try transcript_controller.View.bind(
        bindings.transcript_storage,
    );
    var result = Prepared{
        .topology = topology,
        .bound = bound,
        .transcript_view = transcript_view,
        .quotient_challenge = bindings.quotient.challenge,
        .proof = bindings.proof,
        .plan_identity = plan.identity,
        .schedule = schedule,
        .identity = undefined,
    };
    result.identity = preparedIdentity(result);
    try result.validate(schedule);
    return result;
}

fn preparedIdentity(value: Prepared) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/oods-controller/v1\x00");
    hash.update(&value.plan_identity);
    hash.update(&value.schedule.schedule_identity);
    hash.update(&value.topology.identity);
    hash.update(&value.bound.topology_identity);
    hashView(&hash, value.transcript_view.state);
    hashView(&hash, value.transcript_view.boundary_snapshot);
    hashView(&hash, value.bound.oods.parameter);
    hashView(&hash, value.bound.oods.sampled_values);
    hashView(&hash, value.quotient_challenge);
    hashView(&hash, value.proof.sampled_values);
    hashInt(&hash, u64, value.bound.batches.len);
    for (value.bound.batches) |batch| {
        hashView(&hash, batch.coefficients.storage);
        hashInt(&hash, u64, batch.coefficients.column_stride_words);
        hashInt(&hash, u32, batch.coefficient_rows);
        hashInt(&hash, u32, batch.coefficient_log_size);
        hashInt(&hash, u64, batch.first_sample);
        hashInt(&hash, u64, batch.sample_count);
        hashInt(&hash, u64, batch.factor_first);
        hashInt(&hash, u64, batch.scratch_first);
    }
    return hash.finalResult();
}

fn hashView(hash: *std.crypto.hash.sha2.Sha256, view: anytype) void {
    hashInt(hash, u64, view.address);
    hashInt(hash, u64, view.len);
    hashInt(hash, u64, view.owner);
    hashInt(hash, u64, view.generation);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

test {
    std.testing.refAllDeclsRecursive(@This());
}

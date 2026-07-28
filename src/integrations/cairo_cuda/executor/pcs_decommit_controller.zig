//! Transcript-owned Cairo query derivation and resident opening assembly.
//!
//! The controller exposes no query input. It advances the authenticated
//! transcript through its final draw, assembles every mixed-height trace/FRI
//! record, and only then returns an identity-bound terminal route.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const common = @import(
    "../../../backends/cuda/runtime/stages/common.zig",
);
const decommit_stage = @import(
    "../../../backends/cuda/runtime/stages/decommit.zig",
);
const transcript_stage = @import(
    "../../../backends/cuda/runtime/stages/transcript.zig",
);
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const cairo_identity = @import("../identity.zig");
const proof_capture = @import(
    "../../native_cuda/common/proof_assembly.zig",
);
const bindings_module = @import("pcs_hooks_types.zig");
const topology_module = @import("pcs_decommit_topology.zig");
const resident_plan = @import("resident_plan.zig");
const transcript_controller = @import("transcript/controller.zig");
const transcript_schedule = @import("transcript/schedule.zig");

const NativeOps = struct {
    const Transcript = transcript_stage.Native;
    const Decommit = decommit_stage.Native;
    const Capture = proof_capture;
};

pub const State = enum {
    prepared,
    poisoned,
    complete,
};

pub const TerminalRoute = struct {
    protocol_identity: proof_ir.Digest,
    plan_identity: proof_ir.Digest,
    schedule_identity: proof_ir.Digest,
    schedule_semantic_identity: proof_ir.Digest,
    schedule_program_identity: proof_ir.Digest,
    schedule_operation_count: u32,
    topology_identity: proof_ir.Digest,
    controller_identity: proof_ir.Digest,
    transport: common.Words,
    expected_transport_words: usize,
    identity: proof_ir.Digest,

    pub fn validate(
        self: TerminalRoute,
        plan: *const resident_plan.Plan,
        schedule: transcript_schedule.Schedule,
        protocol: compact.CompactProtocolV1,
    ) !void {
        const protocol_identity = try cairo_identity.protocolDigest(protocol);
        if (std.mem.allEqual(u8, &self.identity, 0) or
            std.mem.allEqual(u8, &self.controller_identity, 0) or
            std.mem.allEqual(u8, &self.topology_identity, 0) or
            !std.mem.eql(
                u8,
                &self.protocol_identity,
                &protocol_identity,
            ) or
            !std.mem.eql(u8, &self.plan_identity, &plan.identity) or
            !std.mem.eql(
                u8,
                &self.schedule_identity,
                &schedule.schedule_identity,
            ) or
            !std.mem.eql(
                u8,
                &self.schedule_semantic_identity,
                &schedule.semantic_proof_identity,
            ) or
            !std.mem.eql(
                u8,
                &self.schedule_program_identity,
                &schedule.executable_program_identity,
            ) or
            self.schedule_operation_count != schedule.operation_count or
            !std.mem.eql(
                u8,
                &schedule.executable_program_identity,
                &plan.program_identity,
            ) or
            self.expected_transport_words != plan.terminal_bundle.total_words or
            self.transport.len != self.expected_transport_words or
            !std.mem.eql(u8, &self.identity, &routeIdentity(self)))
        {
            return error.InvalidTerminalRouteIdentity;
        }
    }
};

pub const Prepared = struct {
    topology: topology_module.Topology,
    transcript_view: transcript_controller.View,
    bindings: bindings_module.Bindings,
    protocol_identity: proof_ir.Digest,
    plan_identity: proof_ir.Digest,
    schedule: transcript_schedule.Schedule,
    identity: proof_ir.Digest,
    state: State = .prepared,

    pub fn deinit(self: *Prepared) void {
        self.topology.deinit();
        self.* = undefined;
    }

    pub fn execute(
        self: *Prepared,
        session: anytype,
        plan: *const resident_plan.Plan,
        protocol: compact.CompactProtocolV1,
        schedule: transcript_schedule.Schedule,
        cursor: *transcript_controller.Cursor,
    ) !TerminalRoute {
        return self.executeWith(
            NativeOps,
            session,
            plan,
            protocol,
            schedule,
            cursor,
        );
    }

    pub fn executeWith(
        self: *Prepared,
        comptime Ops: type,
        session: anytype,
        plan: *const resident_plan.Plan,
        protocol: compact.CompactProtocolV1,
        schedule: transcript_schedule.Schedule,
        cursor: *transcript_controller.Cursor,
    ) !TerminalRoute {
        try self.validate(plan, protocol, schedule);
        if (self.state != .prepared)
            return error.InvalidDecommitControllerState;
        self.state = .poisoned;
        try session.zeroResidentSlice(
            u32,
            .decommit,
            self.bindings.decommit_assembly,
        );
        try transcript_controller.drawQueries(
            Ops.Transcript,
            session,
            schedule,
            cursor,
            self.transcript_view,
            5,
            self.bindings.decommit.raw_queries,
        );
        try topology_module.normalizeWith(
            Ops.Decommit,
            session,
            self.topology,
            self.bindings.decommit,
            self.bindings.decommit_assembly,
        );
        try topology_module.openAllWith(
            Ops.Decommit,
            session,
            self.topology,
            self.bindings.trees,
            self.bindings.fri,
            self.bindings.decommit,
            self.bindings.decommit_assembly,
        );
        try Ops.Capture.captureDecommitment(
            session,
            .{ .proof = self.bindings.proof },
            self.bindings.decommit_assembly,
        );
        if (!cursor.complete(schedule))
            return error.IncompleteCairoTranscript;

        var route = TerminalRoute{
            .protocol_identity = self.protocol_identity,
            .plan_identity = self.plan_identity,
            .schedule_identity = self.schedule.schedule_identity,
            .schedule_semantic_identity = self.schedule.semantic_proof_identity,
            .schedule_program_identity = self.schedule.executable_program_identity,
            .schedule_operation_count = self.schedule.operation_count,
            .topology_identity = self.topology.identity,
            .controller_identity = self.identity,
            .transport = self.bindings.proof.bundle,
            .expected_transport_words = plan.terminal_bundle.total_words,
            .identity = undefined,
        };
        route.identity = routeIdentity(route);
        try route.validate(plan, schedule, protocol);
        self.state = .complete;
        return route;
    }

    pub fn validate(
        self: Prepared,
        plan: *const resident_plan.Plan,
        protocol: compact.CompactProtocolV1,
        schedule: transcript_schedule.Schedule,
    ) !void {
        const protocol_identity = try cairo_identity.protocolDigest(protocol);
        if (std.mem.allEqual(u8, &self.identity, 0) or
            std.mem.allEqual(u8, &self.topology.identity, 0) or
            !std.mem.eql(u8, &self.plan_identity, &plan.identity) or
            !std.mem.eql(
                u8,
                &self.protocol_identity,
                &protocol_identity,
            ) or
            !std.meta.eql(self.schedule, schedule) or
            self.topology.assembly_capacity_words !=
                self.bindings.decommit_assembly.len or
            self.bindings.decommit_assembly.len !=
                self.bindings.proof.decommitment.len or
            self.bindings.proof.bundle.len !=
                plan.terminal_bundle.total_words or
            !std.mem.eql(u8, &self.identity, &preparedIdentity(self)))
        {
            return error.InvalidDecommitControllerIdentity;
        }
    }
};

pub fn prepare(
    allocator: std.mem.Allocator,
    session: anytype,
    plan: *const resident_plan.Plan,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    bindings: bindings_module.Bindings,
    schedule: transcript_schedule.Schedule,
) !Prepared {
    const expected_schedule = try transcript_schedule.Schedule.init(
        program,
        protocol,
    );
    const protocol_identity = try cairo_identity.protocolDigest(protocol);
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
        !std.mem.eql(
            u8,
            &protocol_identity,
            &plan.protocol_identity,
        ) or
        std.mem.allEqual(u8, &plan.identity, 0))
    {
        return error.InvalidDecommitControllerIdentity;
    }
    var topology = try topology_module.derive(
        allocator,
        program,
        protocol,
    );
    errdefer topology.deinit();
    try topology.uploadColumnLogs(session, bindings.decommit);
    const transcript_view = try transcript_controller.View.bind(
        bindings.transcript_storage,
    );
    var result = Prepared{
        .topology = topology,
        .transcript_view = transcript_view,
        .bindings = bindings,
        .protocol_identity = protocol_identity,
        .plan_identity = plan.identity,
        .schedule = schedule,
        .identity = undefined,
    };
    result.identity = preparedIdentity(result);
    try result.validate(plan, protocol, schedule);
    return result;
}

fn preparedIdentity(value: Prepared) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/decommit-controller/v1\x00");
    hash.update(&value.protocol_identity);
    hash.update(&value.plan_identity);
    hash.update(&value.schedule.schedule_identity);
    hash.update(&value.topology.identity);
    hashView(&hash, value.transcript_view.state);
    hashView(&hash, value.transcript_view.boundary_snapshot);
    hashView(&hash, value.bindings.decommit.raw_queries);
    hashView(&hash, value.bindings.decommit.unique_queries);
    hashView(&hash, value.bindings.decommit_assembly);
    hashView(&hash, value.bindings.proof.decommitment);
    hashView(&hash, value.bindings.proof.bundle);
    for (value.bindings.trees.active()) |tree| {
        hashView(&hash, tree.evaluations);
        hashView(&hash, tree.merkle_hashes);
        hashView(&hash, tree.merkle_layers);
    }
    for (value.bindings.fri.activeLayers()) |layer| {
        hashView(&hash, layer.coordinates.storage);
        hashView(&hash, layer.merkle_hashes);
        hashView(&hash, layer.merkle_layers);
    }
    return hash.finalResult();
}

fn routeIdentity(value: TerminalRoute) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/terminal-route/v1\x00");
    hash.update(&value.protocol_identity);
    hash.update(&value.plan_identity);
    hash.update(&value.schedule_identity);
    hash.update(&value.schedule_semantic_identity);
    hash.update(&value.schedule_program_identity);
    hashInt(&hash, u32, value.schedule_operation_count);
    hash.update(&value.topology_identity);
    hash.update(&value.controller_identity);
    hashView(&hash, value.transport);
    hashInt(&hash, u64, value.expected_transport_words);
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

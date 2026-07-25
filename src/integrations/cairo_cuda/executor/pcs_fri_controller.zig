//! Transcript-owned resident FRI execution for Cairo CUDA proofs.
//!
//! Ingress seals the exact program inventory and uploads immutable Merkle
//! descriptors. Execution retains every coordinate and hash layer for
//! decommitment and performs no allocation, transfer, fallback, or sync.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const field = @import("../../../backends/cuda/abi/field.zig");
const common = @import(
    "../../../backends/cuda/runtime/stages/common.zig",
);
const stages = @import("../../../backends/cuda/runtime/stages/mod.zig");
const compact = @import(
    "../../../frontends/cairo/compact_verifier_interchange.zig",
);
const commit_tree = @import(
    "../../native_cuda/common/commit_tree.zig",
);
const proof_capture = @import(
    "../../native_cuda/common/proof_assembly.zig",
);
const bindings_module = @import("pcs_hooks_types.zig");
const resident_plan = @import("resident_plan.zig");
const transcript_controller = @import("transcript/controller.zig");
const transcript_schedule = @import("transcript/schedule.zig");

const first_fri_step: u32 = 20;
const packed_leaf_log: u32 = 2;

const NativeCommitment = struct {
    pub fn fri(
        session: anytype,
        evaluation_size: u32,
        coordinates: common.WordMatrix,
        hashes: common.Hashes,
        layers: []const field.MerkleLayerDescriptor,
    ) !common.Hashes {
        const Builder = commit_tree.BuilderFor(stages.commitment.Native);
        return Builder.fri(
            session,
            evaluation_size,
            0,
            coordinates,
            hashes,
            layers,
        );
    }
};

const NativeFri = struct {
    pub fn foldLayer(
        session: anytype,
        twiddles: common.Words,
        layer: Layer,
        first_is_circle: bool,
        source: common.WordMatrix,
        alpha: common.SecureFields,
        destination: common.WordMatrix,
    ) !void {
        switch (layer.fold_step) {
            1 => {
                if (first_is_circle) {
                    try session.zeroResidentSlice(
                        u32,
                        .fri_commit,
                        destination.storage,
                    );
                }
                try stages.fri.Native.fold(
                    session,
                    first_is_circle,
                    twiddles,
                    layer.twiddle_offsets[0],
                    layer.evaluation_size,
                    source,
                    alpha,
                    0,
                    destination,
                );
            },
            2 => try stages.fri.Native.foldTwo(
                session,
                twiddles,
                layer.twiddle_offsets[0..2].*,
                layer.evaluation_size,
                first_is_circle,
                source,
                alpha,
                destination,
            ),
            3 => try stages.fri.Native.foldThree(
                session,
                twiddles,
                layer.twiddle_offsets,
                layer.evaluation_size,
                first_is_circle,
                source,
                alpha,
                destination,
            ),
            else => return error.UnsupportedFriFoldStep,
        }
    }

    pub fn lastLayer(
        session: anytype,
        evaluation: common.Words,
        evaluation_stride: u32,
        log_size: u32,
        inverse_twiddles: common.Words,
        log_degree_bound: u32,
        coefficients: common.Words,
        degree_error: common.Words,
        transcript_coefficients: common.Words,
    ) !void {
        return stages.fri.Native.lastLayer(
            session,
            evaluation,
            evaluation_stride,
            log_size,
            inverse_twiddles,
            log_degree_bound,
            coefficients,
            degree_error,
            transcript_coefficients,
        );
    }
};

const NativeOps = struct {
    const Commitment = NativeCommitment;
    const Fri = NativeFri;
    const Transcript = stages.transcript.Native;
    const Capture = proof_capture;
};

pub const Layer = struct {
    tree_id: u32,
    evaluation_log_rows: u32,
    fold_step: u32,
    cumulative_fold: u32,
    log_rows_per_leaf: u32,
    evaluation_size: u32,
    merkle_first: usize,
    merkle_count: usize,
    twiddle_offsets: [3]u32,
};

pub const Topology = struct {
    allocator: std.mem.Allocator,
    layers: []Layer,
    merkle_layers: []field.MerkleLayerDescriptor,
    twiddle_words: usize,
    final_log_rows: u32,
    final_degree_log: u32,
    identity: proof_ir.Digest,

    pub fn derive(
        allocator: std.mem.Allocator,
        program: proof_ir.ProofProgram,
        protocol: compact.CompactProtocolV1,
        twiddle_words: usize,
    ) !Topology {
        try program.validate();
        try protocol.validate();
        if (program.fri_layers.len == 0 or
            program.fri_layers.len != protocol.fri_tree_count or
            program.quotient.evaluation_log_rows !=
                protocol.max_log_degree_bound or
            protocol.final_line_coefficient_count !=
                try pow2u32(protocol.log_last_layer_degree_bound))
        {
            return error.InvalidFriControllerTopology;
        }
        var descriptor_count: usize = 0;
        for (program.fri_layers) |layer| {
            descriptor_count = try add(
                descriptor_count,
                @as(usize, layer.evaluation_log_rows) + 1,
            );
        }
        const layers = try allocator.alloc(Layer, program.fri_layers.len);
        errdefer allocator.free(layers);
        const descriptor_storage = try allocator.alloc(
            field.MerkleLayerDescriptor,
            descriptor_count,
        );
        errdefer allocator.free(descriptor_storage);

        var descriptor_cursor: usize = 0;
        var cumulative: u32 = 0;
        for (program.fri_layers, layers, 0..) |
            declared,
            *layer,
            ordinal,
        | {
            if (declared.tree_id != ordinal or
                declared.cumulative_fold != cumulative or
                declared.evaluation_log_rows !=
                    protocol.max_log_degree_bound - cumulative or
                declared.fold_step == 0 or declared.fold_step > 3 or
                declared.fold_step > declared.evaluation_log_rows or
                declared.evaluation_log_rows < packed_leaf_log or
                declared.log_rows_per_leaf !=
                    declared.evaluation_log_rows - packed_leaf_log)
            {
                return error.InvalidFriControllerTopology;
            }
            if (ordinal + 1 < program.fri_layers.len and
                declared.fold_step != protocol.fri_fold_step)
            {
                return error.InvalidFriControllerTopology;
            }
            const evaluation_size = try pow2u32(
                declared.evaluation_log_rows,
            );
            const count = @as(usize, declared.evaluation_log_rows) + 1;
            try fillMerkleLayers(
                descriptor_storage[descriptor_cursor..][0..count],
                evaluation_size,
            );
            var offsets = [_]u32{0} ** 3;
            for (0..declared.fold_step) |fold| {
                const fold_u32: u32 = @intCast(fold);
                offsets[fold] = try twiddleOffset(
                    twiddle_words,
                    declared.evaluation_log_rows - fold_u32,
                    ordinal == 0 and fold == 0,
                );
            }
            layer.* = .{
                .tree_id = declared.tree_id,
                .evaluation_log_rows = declared.evaluation_log_rows,
                .fold_step = declared.fold_step,
                .cumulative_fold = declared.cumulative_fold,
                .log_rows_per_leaf = declared.log_rows_per_leaf,
                .evaluation_size = evaluation_size,
                .merkle_first = descriptor_cursor,
                .merkle_count = count,
                .twiddle_offsets = offsets,
            };
            descriptor_cursor = try add(descriptor_cursor, count);
            cumulative = std.math.add(
                u32,
                cumulative,
                declared.fold_step,
            ) catch return error.SizeOverflow;
        }
        const last = layers[layers.len - 1];
        const final_log = last.evaluation_log_rows - last.fold_step;
        if (final_log != protocol.log_last_layer_degree_bound + 1 or
            descriptor_cursor != descriptor_storage.len)
        {
            return error.InvalidFriControllerTopology;
        }
        var result = Topology{
            .allocator = allocator,
            .layers = layers,
            .merkle_layers = descriptor_storage,
            .twiddle_words = twiddle_words,
            .final_log_rows = final_log,
            .final_degree_log = protocol.log_last_layer_degree_bound,
            .identity = undefined,
        };
        result.identity = topologyIdentity(result);
        return result;
    }

    pub fn deinit(self: *Topology) void {
        self.allocator.free(self.merkle_layers);
        self.allocator.free(self.layers);
        self.* = undefined;
    }

    pub fn descriptors(
        self: Topology,
        layer: Layer,
    ) []const field.MerkleLayerDescriptor {
        return self.merkle_layers[layer.merkle_first..][0..layer.merkle_count];
    }

    pub fn upload(
        self: Topology,
        session: anytype,
        fri: @import(
            "../../native_cuda/common/resident_views.zig",
        ).Fri,
    ) !void {
        if (fri.layer_count != self.layers.len)
            return error.InvalidFriControllerBinding;
        for (self.layers, fri.activeLayers()) |layer, resident| {
            try session.context.uploadSlice(
                field.MerkleLayerDescriptor,
                resident.merkle_layers,
                self.descriptors(layer),
            );
        }
    }
};

pub const State = enum {
    prepared,
    poisoned,
    complete,
};

pub const Prepared = struct {
    topology: Topology,
    bindings: bindings_module.Bindings,
    transcript_view: transcript_controller.View,
    plan_identity: proof_ir.Digest,
    schedule_identity: proof_ir.Digest,
    identity: proof_ir.Digest,
    state: State = .prepared,

    pub fn deinit(self: *Prepared) void {
        self.topology.deinit();
        self.* = undefined;
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
        if (self.state != .prepared or
            !cursor.initialized or cursor.next_step != first_fri_step)
        {
            return error.InvalidFriControllerState;
        }
        self.state = .poisoned;
        for (self.topology.layers, 0..) |layer, ordinal| {
            const resident = self.bindings.fri.layers[ordinal];
            const root = try Ops.Commitment.fri(
                session,
                layer.evaluation_size,
                resident.coordinates,
                resident.merkle_hashes,
                self.topology.descriptors(layer),
            );
            try Ops.Capture.captureFriRoot(
                session,
                .{ .proof = self.bindings.proof },
                ordinal,
                root,
            );
            try transcript_controller.mixInput(
                Ops.Transcript,
                session,
                .fri_commit,
                schedule,
                cursor,
                self.transcript_view,
                transcript_schedule.friInputOrdinal(@intCast(ordinal)),
                try root.cast(u32),
            );
            try transcript_controller.drawSecure(
                Ops.Transcript,
                session,
                .fri_commit,
                schedule,
                cursor,
                self.transcript_view,
                transcript_schedule.friInputOrdinal(
                    @intCast(ordinal),
                ) + 1,
                self.bindings.fri.alpha,
            );
            const destination = if (ordinal + 1 < self.topology.layers.len)
                self.bindings.fri.layers[ordinal + 1].coordinates
            else
                common.WordMatrix{
                    .storage = try self.bindings.fri.last_evaluation.cast(
                        u32,
                    ),
                    .column_stride_words = @as(usize, 1) << @intCast(
                        self.topology.final_log_rows,
                    ),
                };
            try Ops.Fri.foldLayer(
                session,
                self.bindings.twiddles_inverse,
                layer,
                ordinal == 0,
                resident.coordinates,
                self.bindings.fri.alpha,
                destination,
            );
        }
        const final_rows =
            @as(u32, 1) << @intCast(self.topology.final_log_rows);
        try Ops.Fri.lastLayer(
            session,
            try self.bindings.fri.last_evaluation.cast(u32),
            final_rows,
            self.topology.final_log_rows,
            self.bindings.twiddles_inverse,
            self.topology.final_degree_log,
            try self.bindings.fri.last_coefficients.cast(u32),
            self.bindings.fri.last_degree_error,
            try self.bindings.fri.last_transcript.cast(u32),
        );
        try Ops.Capture.captureLastLayer(
            session,
            .{
                .proof = self.bindings.proof,
                .fri = self.bindings.fri,
            },
        );
        try transcript_controller.mixInput(
            Ops.Transcript,
            session,
            .fri_commit,
            schedule,
            cursor,
            self.transcript_view,
            30,
            try self.bindings.fri.last_transcript.cast(u32),
        );
        self.state = .complete;
    }

    pub fn validate(
        self: Prepared,
        schedule: transcript_schedule.Schedule,
    ) !void {
        if (std.mem.allEqual(u8, &self.identity, 0) or
            !std.mem.eql(
                u8,
                &self.schedule_identity,
                &schedule.schedule_identity,
            ) or
            !std.mem.eql(
                u8,
                &self.topology.identity,
                &topologyIdentity(self.topology),
            ) or
            !std.mem.eql(
                u8,
                &self.bindings.identity,
                &self.plan_identity,
            ))
        {
            return error.InvalidFriControllerIdentity;
        }
        try validateBindings(self.topology, self.bindings);
        if (!std.mem.eql(
            u8,
            &self.identity,
            &preparedIdentity(self),
        )) return error.InvalidFriControllerIdentity;
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
    try common.requireStage(session, .ingress);
    const expected_schedule = try transcript_schedule.Schedule.init(
        program,
        protocol,
    );
    if (std.mem.allEqual(u8, &plan.identity, 0) or
        !std.mem.eql(u8, &bindings.identity, &plan.identity) or
        !std.mem.eql(
            u8,
            &schedule.schedule_identity,
            &expected_schedule.schedule_identity,
        ) or
        !std.mem.eql(
            u8,
            &schedule.executable_program_identity,
            &plan.program_identity,
        ))
    {
        return error.InvalidFriControllerIdentity;
    }
    try bindings.requireFri();
    var topology = try Topology.derive(
        allocator,
        program,
        protocol,
        bindings.twiddles_inverse.len,
    );
    errdefer topology.deinit();
    try validateBindings(topology, bindings);
    try topology.upload(session, bindings.fri);
    var result = Prepared{
        .topology = topology,
        .bindings = bindings,
        .transcript_view = try transcript_controller.View.bind(
            bindings.transcript_storage,
        ),
        .plan_identity = plan.identity,
        .schedule_identity = schedule.schedule_identity,
        .identity = undefined,
    };
    result.identity = preparedIdentity(result);
    try result.validate(schedule);
    return result;
}

fn validateBindings(
    topology: Topology,
    bindings: bindings_module.Bindings,
) !void {
    if (bindings.fri.layer_count != topology.layers.len or
        bindings.twiddles_inverse.len != topology.twiddle_words or
        bindings.fri.alpha.len != 1)
    {
        return error.InvalidFriControllerBinding;
    }
    for (topology.layers, bindings.fri.activeLayers()) |layer, resident| {
        const rows: usize = layer.evaluation_size;
        if (resident.coordinates.column_stride_words != rows or
            resident.coordinates.storage.len != try mul(rows, 4) or
            resident.merkle_hashes.len != try fullTreeHashes(rows) or
            resident.merkle_layers.len != layer.merkle_count)
        {
            return error.InvalidFriControllerBinding;
        }
    }
    const final_rows = try pow2usize(topology.final_log_rows);
    if (bindings.fri.last_evaluation.len != final_rows or
        bindings.fri.last_coefficients.len != final_rows or
        bindings.fri.last_degree_error.len != 1 or
        bindings.fri.last_transcript.len !=
            try pow2usize(topology.final_degree_log))
    {
        return error.InvalidFriControllerBinding;
    }
}

fn fillMerkleLayers(
    output: []field.MerkleLayerDescriptor,
    leaves: u32,
) !void {
    var count: usize = leaves;
    var offset: usize = 0;
    for (output) |*layer| {
        layer.* = .{
            .offset_hashes = offset,
            .hash_count = @intCast(count),
        };
        offset = try add(offset, count);
        count = @max(count / 2, 1);
    }
    if (count != 1) return error.InvalidFriControllerTopology;
}

fn twiddleOffset(
    twiddle_words: usize,
    evaluation_log: u32,
    circle: bool,
) !u32 {
    const rows = try pow2usize(evaluation_log);
    const consumed = if (circle) rows / 2 else rows;
    if (consumed > twiddle_words)
        return error.InvalidFriControllerTopology;
    return std.math.cast(u32, twiddle_words - consumed) orelse
        error.SizeOverflow;
}

fn topologyIdentity(value: Topology) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/fri-topology/v1\x00");
    hashInt(&hash, u64, value.twiddle_words);
    hashInt(&hash, u32, value.final_log_rows);
    hashInt(&hash, u32, value.final_degree_log);
    hashInt(&hash, u64, value.layers.len);
    for (value.layers) |layer| {
        hashInt(&hash, u32, layer.tree_id);
        hashInt(&hash, u32, layer.evaluation_log_rows);
        hashInt(&hash, u32, layer.fold_step);
        hashInt(&hash, u32, layer.cumulative_fold);
        hashInt(&hash, u32, layer.log_rows_per_leaf);
        hashInt(&hash, u32, layer.evaluation_size);
        hashInt(&hash, u64, layer.merkle_first);
        hashInt(&hash, u64, layer.merkle_count);
        for (layer.twiddle_offsets) |offset|
            hashInt(&hash, u32, offset);
    }
    hashInt(&hash, u64, value.merkle_layers.len);
    hash.update(std.mem.sliceAsBytes(value.merkle_layers));
    return hash.finalResult();
}

fn preparedIdentity(value: Prepared) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/fri-controller/v1\x00");
    hash.update(&value.plan_identity);
    hash.update(&value.schedule_identity);
    hash.update(&value.topology.identity);
    hashView(&hash, value.transcript_view.state);
    hashView(&hash, value.transcript_view.boundary_snapshot);
    hashView(&hash, value.bindings.twiddles_inverse);
    hashView(&hash, value.bindings.fri.alpha);
    for (value.bindings.fri.activeLayers()) |layer| {
        hashView(&hash, layer.coordinates.storage);
        hashInt(&hash, u64, layer.coordinates.column_stride_words);
        hashView(&hash, layer.merkle_hashes);
        hashView(&hash, layer.merkle_layers);
    }
    hashView(&hash, value.bindings.fri.last_evaluation);
    hashView(&hash, value.bindings.fri.last_coefficients);
    hashView(&hash, value.bindings.fri.last_degree_error);
    hashView(&hash, value.bindings.fri.last_transcript);
    return hash.finalResult();
}

fn hashView(hash: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    hashInt(hash, u64, value.address);
    hashInt(hash, u64, value.len);
    hashInt(hash, u64, value.owner);
    hashInt(hash, u64, value.generation);
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

fn fullTreeHashes(leaves: usize) !usize {
    return std.math.sub(
        usize,
        try mul(leaves, 2),
        1,
    ) catch error.SizeOverflow;
}

fn pow2u32(log: u32) !u32 {
    if (log >= 31) return error.SizeOverflow;
    return @as(u32, 1) << @intCast(log);
}

fn pow2usize(log: u32) !usize {
    if (log >= @bitSizeOf(usize)) return error.SizeOverflow;
    return @as(usize, 1) << @intCast(log);
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.SizeOverflow;
}

fn mul(left: usize, right: usize) !usize {
    return std.math.mul(usize, left, right) catch error.SizeOverflow;
}

test {
    std.testing.refAllDeclsRecursive(@This());
}

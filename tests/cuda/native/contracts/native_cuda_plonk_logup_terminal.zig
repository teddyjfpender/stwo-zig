const std = @import("std");
const stwo = @import("stwo_under_test");
const exact = stwo.integrations.native_cuda.plonk_logup;
const RuntimeError = stwo.backends.cuda.runtime.runtime_error.Error;

test "exact terminal stages execute one ordered resident transaction" {
    const allocator = std.testing.allocator;
    const geometry = try exact.geometry.admit(
        .{ .log_n_rows = 8 },
        stwo.core.pcs.PcsConfig.default(),
    );
    var prepared = try exact.plan.PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);
    var pack = try exact.canonical_ingress.Pack.init(
        allocator,
        geometry,
    );
    defer pack.deinit(allocator);
    const provider = Provider{ .prepared = &prepared };
    var bound = try exact.resident_bindings.bind(&provider, &prepared);
    var transaction = Transaction{};
    Calls.reset();

    try exact.executor.oods.runWith(
        OodsOps,
        &transaction,
        &prepared,
        &pack,
        &bound.base,
    );
    try exact.executor.quotient.runWith(
        QuotientOps,
        &transaction,
        &prepared,
        &pack,
        &bound.base,
    );
    try exact.executor.fri.runWith(
        FriOps,
        &transaction,
        &prepared,
        &pack,
        &bound.base,
    );
    try exact.executor.pow_decommit.runPowWith(
        TailOps,
        &transaction,
        &prepared,
        &bound.base,
    );
    try exact.executor.pow_decommit.runDecommitWith(
        TailOps,
        &transaction,
        &prepared,
        &bound.base,
    );

    var expected: [22]u32 = undefined;
    for (&expected, 7..) |*step, value| step.* = @intCast(value);
    try std.testing.expectEqualSlices(
        u32,
        &expected,
        Calls.steps[0..Calls.step_count],
    );
    try std.testing.expectEqual(@as(usize, 1), Calls.oods_derivations);
    try std.testing.expectEqual(@as(usize, 6), Calls.oods_evaluations);
    try std.testing.expectEqual(@as(usize, 6), Calls.oods_stores);
    try std.testing.expectEqual(@as(usize, 5), Calls.quotient_operations);
    try std.testing.expectEqual(@as(usize, 8), Calls.fri_leaves);
    try std.testing.expectEqual(@as(usize, 8), Calls.fri_tails);
    try std.testing.expectEqual(@as(usize, 8), Calls.fri_folds);
    try std.testing.expectEqual(@as(usize, 8), Calls.fri_roots);
    try std.testing.expectEqual(@as(usize, 1), Calls.fri_last_layers);
    try std.testing.expectEqual(@as(usize, 1), Calls.fri_last_captures);
    try std.testing.expectEqual(@as(usize, 1), Calls.pow_grinds);
    try std.testing.expectEqual(@as(usize, 1), Calls.pow_captures);
    try std.testing.expectEqual(@as(usize, 1), Calls.query_normalizations);
    try std.testing.expectEqual(@as(usize, 4), Calls.trace_preparations);
    try std.testing.expectEqual(@as(usize, 4), Calls.trace_packs);
    try std.testing.expectEqual(@as(usize, 4), Calls.trace_assemblies);
    try std.testing.expectEqual(@as(usize, 8), Calls.fri_preparations);
    try std.testing.expectEqual(@as(usize, 8), Calls.fri_assemblies);
    try std.testing.expectEqual(@as(usize, 1), Calls.sample_captures);
    try std.testing.expectEqual(@as(usize, 1), Calls.zeroes);
}

test "exact terminal artifact seals four roots and 28 canonical samples" {
    const allocator = std.testing.allocator;
    var bundle = try stwo.backends.cuda.runtime.proof_assembly
        .stark_bundle.Bundle.decodeOwnedWith(
        exact.terminal_bundle.Descriptor,
        allocator,
        try makeTerminalArtifact(allocator, 8),
    );
    defer bundle.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 4), bundle.protocol.commitment_root_count);
    try std.testing.expectEqual(@as(usize, 28 * 4), bundle.sampledValues().len);
    try std.testing.expectEqual(@as(usize, 12), bundle.decommitment.trees.len);
    try std.testing.expectError(
        error.InvalidTraceOpening,
        exact.proof_decode.decodeProof(allocator, bundle),
    );

    const geometry = try exact.geometry.admit(
        .{ .log_n_rows = 8 },
        stwo.core.pcs.PcsConfig.default(),
    );
    var logical = try exact.layout.Layout.init(allocator, geometry);
    defer logical.deinit(allocator);
    var sample_count: usize = 0;
    for (logical.trace_trees) |tree| {
        for (0..tree.column_count) |column_index| {
            sample_count += try exact.proof_decode.sampleCountFor(
                tree,
                column_index,
            );
        }
    }
    try std.testing.expectEqual(@as(usize, 28), sample_count);
    const statement = try exact.terminal_output.decodeStatement(
        8,
        &.{ 1, 2, 3, 4 },
    );
    try std.testing.expectEqual(@as(u32, 8), statement.log_n_rows);
}

test "exact driver returns a typed statement and canonical proof" {
    const Driver = exact.driver.DriverFor(
        exact.driver.NativeTransaction,
        exact.executor.pipeline,
    );
    try std.testing.expect(@hasField(Driver.Output, "statement"));
    try std.testing.expect(@hasField(Driver.Output, "bundle"));
    try std.testing.expect(@hasField(Driver.Output, "verdict"));
}

test "exact finish splits one envelope into typed statement and proof" {
    const allocator = std.testing.allocator;
    var transaction = FinishTransaction{};
    var prepared = FinishPrepared{};
    var output = try exact.executor.pipeline.finish(
        &transaction,
        allocator,
        &prepared,
    );
    defer output.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), transaction.reads);
    try std.testing.expectEqual(@as(u32, 8), output.statement.log_n_rows);
    for (
        output.statement.claimed_sum.toM31Array(),
        [_]u32{ 1, 2, 3, 4 },
    ) |actual, expected| {
        try std.testing.expectEqual(expected, actual.toU32());
    }
    try std.testing.expectEqual(@as(u32, 91), output.verdict.marker);
}

test "exact CPU proof targets remain frozen for CUDA byte parity" {
    for (exact.parity_targets.targets) |target| {
        try exact.parity_targets.verify(std.testing.allocator, target);
    }
}

const FinishPrepared = struct {
    structural: struct {
        logical: struct {
            geometry: struct {
                statement: struct { log_n_rows: u32 = 8 } = .{},
            } = .{},
        } = .{},
    } = .{},

    pub fn proofSlot(_: *const FinishPrepared) exact.slots.SlotId {
        return exact.slots.proof_bundle;
    }
};

const FinishTransaction = struct {
    pub const StarkStatementBundleOutput = struct {
        statement_words: []u32,
        bundle: stwo.backends.cuda.runtime.proof_assembly
            .stark_bundle.Bundle,
        verdict: struct { marker: u32 },

        pub fn deinit(
            self: *@This(),
            allocator: std.mem.Allocator,
        ) void {
            allocator.free(self.statement_words);
            self.bundle.deinit(allocator);
            self.* = undefined;
        }
    };

    reads: usize = 0,

    pub fn assembleStarkBundleAndStatementFinishWith(
        self: *FinishTransaction,
        comptime Descriptor: type,
        allocator: std.mem.Allocator,
        slot: exact.slots.SlotId,
        statement_words: usize,
    ) !StarkStatementBundleOutput {
        if (slot != exact.slots.proof_bundle or statement_words != 4)
            return error.InvalidKernelDescriptor;
        self.reads += 1;
        return .{
            .statement_words = try allocator.dupe(
                u32,
                &.{ 1, 2, 3, 4 },
            ),
            .bundle = try stwo.backends.cuda.runtime.proof_assembly
                .stark_bundle.Bundle.decodeOwnedWith(
                Descriptor,
                allocator,
                try makeTerminalArtifact(allocator, 8),
            ),
            .verdict = .{ .marker = 91 },
        };
    }
};

fn makeTerminalArtifact(
    allocator: std.mem.Allocator,
    log_n_rows: u32,
) ![]u32 {
    const stark = stwo.backends.cuda.runtime.proof_assembly.stark_bundle;
    const decommit = stwo.backends.cuda.runtime.proof_assembly.decommit_bundle;
    const query_count: usize = 3;
    const tree_count: usize = 4 + log_n_rows;
    const nested_header = decommit.header_words +
        tree_count * decommit.tree_meta_words;
    const nested_used = nested_header + 2 * query_count +
        tree_count * query_count;
    const nested = try allocator.alloc(u32, nested_used);
    defer allocator.free(nested);
    @memset(nested, 0);
    nested[0..decommit.header_words].* = .{
        decommit.magic,
        decommit.version,
        @intCast(tree_count),
        query_count,
        query_count,
        @intCast(nested_header),
        @intCast(nested_header + query_count),
        @intCast(nested_used),
    };
    const queries = [_]u32{ 0, 1, 2 };
    @memcpy(
        nested[nested_header .. nested_header + query_count],
        &queries,
    );
    @memcpy(
        nested[nested_header + query_count ..][0..query_count],
        &queries,
    );
    var nested_cursor = nested_header + 2 * query_count;
    for (0..tree_count) |tree_index| {
        const base = decommit.header_words +
            tree_index * decommit.tree_meta_words;
        const meta = nested[base..][0..decommit.tree_meta_words];
        meta[0] = @intFromEnum(if (tree_index < 4)
            decommit.TreeKind.trace
        else
            decommit.TreeKind.fri);
        meta[1] = @intCast(tree_index);
        meta[2] = @intCast(nested_cursor);
        meta[3] = query_count;
        meta[14] = log_n_rows;
        meta[15] = query_count;
        @memcpy(nested[nested_cursor..][0..query_count], &queries);
        nested_cursor += query_count;
    }

    const lengths = [_]usize{
        4 * stark.hash_words,
        28 * stark.secure_words,
        @as(usize, log_n_rows) * stark.hash_words,
        stark.secure_words,
        stark.nonce_words,
        nested_used,
    };
    var total = stark.header_words;
    for (lengths) |length| total += length;
    const storage = try allocator.alloc(u32, total);
    @memset(storage, 0);
    storage[0..stark.fixed_header_words].* = .{
        stark.magic,
        stark.version,
        @intCast(total),
        stark.section_count,
        log_n_rows,
        0,
        10,
        1,
        0,
        query_count,
        1,
        std.math.maxInt(u32),
        4,
        log_n_rows,
        @intCast(tree_count),
        0,
    };
    var cursor = stark.header_words;
    inline for (
        std.meta.fields(stark.SectionKind),
        0..,
    ) |field, index| {
        const base = stark.fixed_header_words +
            index * stark.section_record_words;
        storage[base] = field.value;
        storage[base + 1] = @intCast(cursor);
        storage[base + 2] = @intCast(lengths[index]);
        cursor += lengths[index];
    }
    @memcpy(storage[total - nested_used ..], nested);
    return storage;
}

const Provider = struct {
    prepared: *const exact.plan.PreparedPlan,

    pub fn slot(
        self: *const Provider,
        id: exact.slots.SlotId,
    ) !stwo.backends.cuda.runtime.column.DeviceSlice(u32) {
        const placement = try self
            .prepared
            .cuda_plan
            .arena_plan
            .placement(id);
        return .{
            .address = 0x2_0000_0000 +
                placement.offset_words * @sizeOf(u32),
            .len = placement.requirement.words,
            .owner = 17,
            .generation = 23,
        };
    }
};

const Calls = struct {
    var steps: [22]u32 = undefined;
    var step_count: usize = 0;
    var oods_derivations: usize = 0;
    var oods_evaluations: usize = 0;
    var oods_stores: usize = 0;
    var quotient_operations: usize = 0;
    var fri_leaves: usize = 0;
    var fri_tails: usize = 0;
    var fri_folds: usize = 0;
    var fri_roots: usize = 0;
    var fri_last_layers: usize = 0;
    var fri_last_captures: usize = 0;
    var pow_grinds: usize = 0;
    var pow_captures: usize = 0;
    var query_normalizations: usize = 0;
    var trace_preparations: usize = 0;
    var trace_packs: usize = 0;
    var trace_assemblies: usize = 0;
    var fri_preparations: usize = 0;
    var fri_assemblies: usize = 0;
    var sample_captures: usize = 0;
    var zeroes: usize = 0;

    fn reset() void {
        inline for (std.meta.fields(@This())) |field| {
            if (field.type == usize) @field(@This(), field.name) = 0;
        }
    }

    fn recordStep(step: u32) !void {
        if (step_count == steps.len)
            return error.InvalidKernelDescriptor;
        steps[step_count] = step;
        step_count += 1;
    }
};

const Session = struct {
    pub fn zeroResidentSlice(
        _: *Session,
        comptime F: type,
        stage: anytype,
        destination: anytype,
    ) RuntimeError!void {
        if (F != u32 or stage != .fri_commit or destination.len == 0)
            return error.InvalidKernelDescriptor;
        Calls.zeroes += 1;
    }
};

const Transaction = struct {
    session: Session = .{},

    pub fn proofSession(self: *Transaction) *Session {
        return &self.session;
    }
};

const RecordedTranscript = struct {
    pub fn drawSecure(
        _: anytype,
        _: anytype,
        _: anytype,
        boundary: anytype,
        _: u32,
        _: u32,
        _: anytype,
        _: anytype,
    ) !void {
        try Calls.recordStep(boundary.expected_step);
    }

    pub fn mixWords(
        _: anytype,
        _: anytype,
        _: anytype,
        boundary: anytype,
        _: anytype,
        _: bool,
        _: anytype,
    ) !void {
        try Calls.recordStep(boundary.expected_step);
    }

    pub fn absorbPow(
        _: anytype,
        _: anytype,
        boundary: anytype,
        _: anytype,
        _: u32,
        _: anytype,
    ) !void {
        try Calls.recordStep(boundary.expected_step);
    }

    pub fn drawQueries(
        _: anytype,
        _: anytype,
        boundary: anytype,
        _: u32,
        _: anytype,
        _: anytype,
    ) !void {
        try Calls.recordStep(boundary.expected_step);
    }
};

const OodsOps = struct {
    pub const Transcript = @This().TranscriptOps;
    pub const Oods = @This().OodsStage;
    pub const Capture = @This().CaptureOps;

    const TranscriptOps = RecordedTranscript;
    const OodsStage = struct {
        pub fn derivePoints(
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
            _: u32,
            _: anytype,
            _: anytype,
            _: anytype,
        ) !void {
            Calls.oods_derivations += 1;
        }
        pub fn evaluateFirst(
            _: anytype,
            _: anytype,
            _: u32,
            _: anytype,
            _: anytype,
        ) !void {
            Calls.oods_evaluations += 1;
        }
        pub fn reduce(
            _: anytype,
            _: anytype,
            _: u32,
            _: u32,
            _: u32,
            _: u32,
            _: anytype,
            _: anytype,
        ) !void {}
        pub fn storeResults(
            _: anytype,
            _: anytype,
            _: u32,
            _: anytype,
            _: anytype,
        ) !void {
            Calls.oods_stores += 1;
        }
    };
    const CaptureOps = struct {
        pub fn captureSampledValues(_: anytype, _: anytype) !void {
            Calls.sample_captures += 1;
        }
    };
};

const QuotientOps = struct {
    pub fn prepareTerms(
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
    ) !void {
        Calls.quotient_operations += 1;
    }
    pub fn finalizeGroups(
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
    ) !void {
        Calls.quotient_operations += 1;
    }
    pub fn zeroOutputs(_: anytype, _: anytype, _: anytype) !void {
        Calls.quotient_operations += 1;
    }
    pub fn accumulate(
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
    ) !void {
        Calls.quotient_operations += 1;
    }
    pub fn combine(
        _: anytype,
        _: u32,
        _: u32,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
        _: anytype,
    ) !void {
        Calls.quotient_operations += 1;
    }
};

const FriOps = struct {
    pub const Commitment = @This().CommitmentOps;
    pub const Fri = @This().FriStage;
    pub const Transcript = @This().TranscriptOps;
    pub const Capture = @This().CaptureOps;

    const TranscriptOps = RecordedTranscript;
    const CommitmentOps = struct {
        pub fn friLeaves(
            _: anytype,
            _: anytype,
            _: u32,
            _: u32,
            _: anytype,
        ) RuntimeError!void {
            Calls.fri_leaves += 1;
        }
        pub fn layer(
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
            _: bool,
        ) RuntimeError!void {
            return error.InvalidKernelDescriptor;
        }
        pub fn contiguousTail(
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
            levels: u32,
        ) RuntimeError!void {
            if (levels < 2) return error.InvalidKernelDescriptor;
            Calls.fri_tails += 1;
        }
    };
    const FriStage = struct {
        pub fn fold(
            _: anytype,
            _: bool,
            _: anytype,
            _: u32,
            _: u32,
            _: anytype,
            _: anytype,
            _: u32,
            _: anytype,
        ) !void {
            Calls.fri_folds += 1;
        }
        pub fn lastLayer(
            _: anytype,
            _: anytype,
            _: u32,
            _: u32,
            _: anytype,
            _: u32,
            _: anytype,
            _: anytype,
            _: anytype,
        ) !void {
            Calls.fri_last_layers += 1;
        }
    };
    const CaptureOps = struct {
        pub fn validateLayout(_: anytype, _: anytype) !void {}
        pub fn captureFriRoot(
            _: anytype,
            _: anytype,
            _: usize,
            _: anytype,
        ) !void {
            Calls.fri_roots += 1;
        }
        pub fn captureLastLayer(_: anytype, _: anytype) !void {
            Calls.fri_last_captures += 1;
        }
    };
};

const TailOps = struct {
    pub const Fri = @This().FriStage;
    pub const Transcript = @This().TranscriptOps;
    pub const Decommit = @This().DecommitOps;
    pub const Capture = @This().CaptureOps;

    const TranscriptOps = RecordedTranscript;
    const FriStage = struct {
        pub fn grindPow(
            _: anytype,
            _: anytype,
            _: u32,
            _: u64,
            _: anytype,
            _: anytype,
            _: anytype,
            _: anytype,
        ) !void {
            Calls.pow_grinds += 1;
        }
    };
    const CaptureOps = struct {
        pub fn capturePowNonce(_: anytype, _: anytype) !void {
            Calls.pow_captures += 1;
        }
    };
    const DecommitOps = struct {
        pub fn normalizeQueries(
            _: anytype,
            _: anytype,
            _: u32,
            _: u32,
            _: anytype,
            _: anytype,
            _: anytype,
        ) !void {
            Calls.query_normalizations += 1;
        }
        pub fn prepareTraceQueries(
            _: anytype,
            _: anytype,
            _: anytype,
            _: u32,
            _: u32,
            _: u32,
            _: u32,
            _: anytype,
        ) !void {
            Calls.trace_preparations += 1;
        }
        pub fn packTraceGroup(
            _: anytype,
            _: usize,
            _: usize,
            _: u32,
            _: anytype,
            _: anytype,
            _: u32,
            _: anytype,
            _: anytype,
            _: anytype,
        ) !void {
            Calls.trace_packs += 1;
        }
        pub fn assembleTrace(
            _: anytype,
            _: usize,
            _: u32,
            _: u32,
            _: u32,
            _: usize,
            _: u32,
            _: anytype,
        ) !void {
            Calls.trace_assemblies += 1;
        }
        pub fn prepareFriQueries(
            _: anytype,
            _: anytype,
            _: anytype,
            _: u32,
            _: u32,
            _: u32,
            _: anytype,
        ) !void {
            Calls.fri_preparations += 1;
        }
        pub fn assembleFri(
            _: anytype,
            _: usize,
            _: u32,
            _: anytype,
        ) !void {
            Calls.fri_assemblies += 1;
        }
    };
};

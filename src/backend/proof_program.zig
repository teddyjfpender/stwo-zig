//! Immutable backend-neutral description of one proof shape.
//!
//! Frontends emit this representation. Backends compile it into their own
//! allocation and execution plans without learning workload names.

const std = @import("std");
const native_air = @import("proof_program_native_air.zig");

pub const Digest = [32]u8;
pub const NativeAirContract = native_air.Contract;
pub const NativeTraceGeometry = native_air.TraceGeometry;
pub const MaterializedHostTrace = native_air.MaterializedHostTrace;
pub const NativeStatementBinding = native_air.StatementBinding;
pub const NativeSampleMaskRecipe = native_air.SampleMaskRecipe;
pub const NativeConstraintParameterAbi = native_air.ConstraintParameterAbi;

pub const Stage = enum(u8) {
    ingress,
    trace_generation,
    trace_commit,
    constraint_evaluation,
    oods,
    quotient,
    fri_commit,
    pow,
    decommit,
    proof_assembly,

    pub fn index(self: Stage) usize {
        return @intFromEnum(self);
    }
};

pub const Frontend = enum(u8) {
    native,
    riscv,
    cairo,
};

pub const Identity = struct {
    frontend: Frontend,
    air: Digest,
    statement: Digest,
    protocol: Digest,
};

pub const ColumnRole = enum(u8) {
    preprocessed,
    main,
    interaction,
    composition,
};

pub const TraceColumn = struct {
    id: u32,
    component: u32,
    ordinal: u32,
    log_rows: u32,
    role: ColumnRole,
};

pub const ConstraintProgram = struct {
    id: u32,
    component: u32,
    expression: Digest,
    constraint_count: u32,
    max_degree_log: u32,
};

pub const CommitmentRole = enum(u8) {
    preprocessed,
    main,
    interaction,
    composition,
    fri,
};

pub const CommitmentTree = struct {
    id: u32,
    role: CommitmentRole,
    first_column: u32,
    column_count: u32,
    evaluation_log_rows: u32,
    log_rows_per_leaf: u32,
    retain_openings: bool,
};

pub const TranscriptKind = enum(u8) {
    mix,
    challenge,
    pow,
    queries,
};

pub const TranscriptBarrier = struct {
    ordinal: u32,
    node: u32,
    phase: u32,
    kind: TranscriptKind,
    value_count: u32,
};

pub const QuotientSchedule = struct {
    term_count: u32,
    group_count: u32,
    evaluation_log_rows: u32,
    composition_degree_log: u32,
};

pub const FriLayer = struct {
    tree_id: u32,
    evaluation_log_rows: u32,
    fold_step: u32,
    cumulative_fold: u32,
    log_rows_per_leaf: u32,
};

pub const StorageClass = enum(u8) {
    request_local,
    process_cache,
};

pub const Buffer = struct {
    id: u32,
    words: u64,
    alignment_words: u32,
    live_from: Stage,
    live_through: Stage,
    storage: StorageClass,
    immutable: bool,
};

pub const OperationKind = enum(u8) {
    trace_generation,
    commitment,
    constraint_evaluation,
    oods,
    quotient,
    fri_commit,
    pow,
    decommit,
};

pub const Parallelism = enum(u8) {
    coordination,
    component,
    merkle_subtree,
    quotient_chunk,
    fri_round,
};

pub const DependencySpan = struct {
    first: u32,
    count: u32,
};

pub const WorkEstimate = struct {
    bytes_read: u64,
    bytes_written: u64,
    field_operations: u64,
    hash_compressions: u64,
    minimum_launches: u32,
};

pub const Node = struct {
    id: u32,
    kind: OperationKind,
    stage: Stage,
    dependencies: DependencySpan,
    parallelism: Parallelism,
    graph_candidate: bool,
    work: WorkEstimate,
};

pub const Description = struct {
    identity: Identity,
    /// Null retains the original proof-program-v1 digest and semantics.
    native_air_contract: ?NativeAirContract = null,
    trace_columns: []const TraceColumn,
    constraints: []const ConstraintProgram,
    commitments: []const CommitmentTree,
    transcript: []const TranscriptBarrier,
    quotient: QuotientSchedule,
    fri_layers: []const FriLayer,
    buffers: []const Buffer,
    nodes: []const Node,
    dependency_ids: []const u32,
};

pub const Error = error{
    DuplicateBuffer,
    DuplicateColumn,
    EmptyCommitmentSet,
    EmptyConstraintSet,
    EmptyExecutionGraph,
    EmptyIdentity,
    EmptyTrace,
    InvalidBuffer,
    InvalidCommitment,
    InvalidConstraint,
    InvalidDependency,
    InvalidFriSchedule,
    InvalidNode,
    InvalidNativeAir,
    InvalidQuotientSchedule,
    InvalidTranscript,
};

pub const ProofProgram = struct {
    identity: Identity,
    native_air_contract: ?NativeAirContract,
    trace_columns: []TraceColumn,
    constraints: []ConstraintProgram,
    commitments: []CommitmentTree,
    transcript: []TranscriptBarrier,
    quotient: QuotientSchedule,
    fri_layers: []FriLayer,
    buffers: []Buffer,
    nodes: []Node,
    dependency_ids: []u32,
    /// Proof meaning, independent of backend scheduling and resource policy.
    semantic_digest: Digest,
    /// Complete executable identity used for backend compilation caches.
    program_digest: Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        description: Description,
    ) (std.mem.Allocator.Error || Error)!ProofProgram {
        const trace_columns = try allocator.dupe(
            TraceColumn,
            description.trace_columns,
        );
        errdefer allocator.free(trace_columns);
        const constraints = try allocator.dupe(
            ConstraintProgram,
            description.constraints,
        );
        errdefer allocator.free(constraints);
        const commitments = try allocator.dupe(
            CommitmentTree,
            description.commitments,
        );
        errdefer allocator.free(commitments);
        const transcript = try allocator.dupe(
            TranscriptBarrier,
            description.transcript,
        );
        errdefer allocator.free(transcript);
        const fri_layers = try allocator.dupe(
            FriLayer,
            description.fri_layers,
        );
        errdefer allocator.free(fri_layers);
        const buffers = try allocator.dupe(Buffer, description.buffers);
        errdefer allocator.free(buffers);
        const nodes = try allocator.dupe(Node, description.nodes);
        errdefer allocator.free(nodes);
        const dependency_ids = try allocator.dupe(
            u32,
            description.dependency_ids,
        );
        errdefer allocator.free(dependency_ids);

        var program = ProofProgram{
            .identity = description.identity,
            .native_air_contract = description.native_air_contract,
            .trace_columns = trace_columns,
            .constraints = constraints,
            .commitments = commitments,
            .transcript = transcript,
            .quotient = description.quotient,
            .fri_layers = fri_layers,
            .buffers = buffers,
            .nodes = nodes,
            .dependency_ids = dependency_ids,
            .semantic_digest = undefined,
            .program_digest = undefined,
        };
        try program.validate();
        program.semantic_digest = program.computeSemanticDigest();
        program.program_digest = program.computeDigest();
        return program;
    }

    pub fn deinit(
        self: *ProofProgram,
        allocator: std.mem.Allocator,
    ) void {
        allocator.free(self.dependency_ids);
        allocator.free(self.nodes);
        allocator.free(self.buffers);
        allocator.free(self.fri_layers);
        allocator.free(self.transcript);
        allocator.free(self.commitments);
        allocator.free(self.constraints);
        allocator.free(self.trace_columns);
        self.* = undefined;
    }

    pub fn validate(self: ProofProgram) Error!void {
        try validateIdentity(self.identity);
        if (self.native_air_contract) |contract| {
            contract.validate() catch return error.InvalidNativeAir;
            try validateNativeAir(self, contract);
        }
        if (self.trace_columns.len == 0) return error.EmptyTrace;
        if (self.constraints.len == 0) return error.EmptyConstraintSet;
        if (self.commitments.len == 0) return error.EmptyCommitmentSet;
        if (self.nodes.len == 0) return error.EmptyExecutionGraph;
        if (self.quotient.term_count == 0 or
            self.quotient.group_count == 0 or
            self.quotient.evaluation_log_rows == 0)
        {
            return error.InvalidQuotientSchedule;
        }

        for (self.trace_columns, 0..) |column, index| {
            if (column.id != index or column.log_rows == 0)
                return error.InvalidNode;
            for (self.trace_columns[0..index]) |previous| {
                if (previous.component == column.component and
                    previous.ordinal == column.ordinal)
                {
                    return error.DuplicateColumn;
                }
            }
        }
        for (self.constraints) |constraint| {
            if (constraint.constraint_count == 0 or
                constraint.max_degree_log == 0 or
                digestEmpty(constraint.expression))
            {
                return error.InvalidConstraint;
            }
        }
        for (self.commitments, 0..) |tree, index| {
            if (tree.id != index or tree.evaluation_log_rows == 0)
                return error.InvalidCommitment;
            const end = std.math.add(
                usize,
                tree.first_column,
                tree.column_count,
            ) catch return error.InvalidCommitment;
            if (end > self.trace_columns.len)
                return error.InvalidCommitment;
            if (tree.column_count == 0) {
                if (!isTraceRole(tree.role)) return error.InvalidCommitment;
                continue;
            }
        }
        for (self.transcript, 0..) |barrier, index| {
            if (barrier.ordinal != index or
                barrier.node >= self.nodes.len or
                barrier.value_count == 0)
            {
                return error.InvalidTranscript;
            }
            if (index != 0) {
                const previous = self.transcript[index - 1];
                if (previous.node > barrier.node or
                    (previous.node == barrier.node and
                        previous.phase >= barrier.phase))
                {
                    return error.InvalidTranscript;
                }
            }
        }
        for (self.fri_layers, 0..) |layer, index| {
            if (layer.tree_id != index or
                layer.evaluation_log_rows == 0 or
                layer.fold_step == 0 or
                layer.fold_step > layer.evaluation_log_rows)
            {
                return error.InvalidFriSchedule;
            }
            if (index != 0 and
                self.fri_layers[index - 1].evaluation_log_rows <=
                    layer.evaluation_log_rows)
            {
                return error.InvalidFriSchedule;
            }
        }
        for (self.buffers, 0..) |buffer, index| {
            if (buffer.words == 0 or
                buffer.alignment_words == 0 or
                !std.math.isPowerOfTwo(buffer.alignment_words) or
                buffer.live_from.index() > buffer.live_through.index())
            {
                return error.InvalidBuffer;
            }
            for (self.buffers[0..index]) |previous| {
                if (previous.id == buffer.id) return error.DuplicateBuffer;
            }
        }
        for (self.nodes, 0..) |node, index| {
            if (node.id != index or
                node.stage == .ingress or
                node.stage == .proof_assembly or
                node.work.minimum_launches == 0)
            {
                return error.InvalidNode;
            }
            const dependency_end = std.math.add(
                usize,
                node.dependencies.first,
                node.dependencies.count,
            ) catch return error.InvalidDependency;
            if (dependency_end > self.dependency_ids.len)
                return error.InvalidDependency;
            for (self.dependency_ids[node.dependencies.first..dependency_end]) |dependency| {
                if (dependency >= node.id) return error.InvalidDependency;
                if (self.nodes[dependency].stage.index() > node.stage.index())
                    return error.InvalidDependency;
            }
        }
    }

    fn computeDigest(self: ProofProgram) Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(if (self.native_air_contract == null)
            "stwo-zig-proof-program-v1"
        else
            "stwo-zig-proof-program-v2");
        hashInt(&hash, u8, @intFromEnum(self.identity.frontend));
        hash.update(&self.identity.air);
        hash.update(&self.identity.statement);
        hash.update(&self.identity.protocol);
        hashSlice(&hash, self.trace_columns);
        hashSlice(&hash, self.constraints);
        hashSlice(&hash, self.commitments);
        hashSlice(&hash, self.transcript);
        hashStruct(&hash, self.quotient);
        hashSlice(&hash, self.fri_layers);
        hashSlice(&hash, self.buffers);
        hashSlice(&hash, self.nodes);
        hashInt(&hash, u64, self.dependency_ids.len);
        for (self.dependency_ids) |dependency| {
            hashInt(&hash, u32, dependency);
        }
        if (self.native_air_contract) |contract| hashStruct(&hash, contract);
        var digest: Digest = undefined;
        hash.final(&digest);
        return digest;
    }

    fn computeSemanticDigest(self: ProofProgram) Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig-proof-program-semantic-v1");
        hashInt(&hash, u8, @intFromEnum(self.identity.frontend));
        hash.update(&self.identity.air);
        hash.update(&self.identity.statement);
        hash.update(&self.identity.protocol);
        hashSlice(&hash, self.trace_columns);
        hashSlice(&hash, self.constraints);
        hashSemanticCommitments(&hash, self.commitments);
        hashSemanticTranscript(&hash, self.transcript, self.nodes);
        hashStruct(&hash, self.quotient);
        hashSlice(&hash, self.fri_layers);
        if (self.native_air_contract) |contract| {
            hashInt(&hash, u8, 1);
            hashNativeAirSemantics(&hash, contract);
        } else {
            hashInt(&hash, u8, 0);
        }
        var digest: Digest = undefined;
        hash.final(&digest);
        return digest;
    }
};

fn hashSemanticCommitments(
    hash: *std.crypto.hash.sha2.Sha256,
    trees: []const CommitmentTree,
) void {
    hashInt(hash, u64, trees.len);
    for (trees) |tree| {
        hashInt(hash, u32, tree.id);
        hashInt(hash, u8, @intFromEnum(tree.role));
        hashInt(hash, u32, tree.first_column);
        hashInt(hash, u32, tree.column_count);
        hashInt(hash, u32, tree.evaluation_log_rows);
        hashInt(hash, u32, tree.log_rows_per_leaf);
    }
}

fn hashSemanticTranscript(
    hash: *std.crypto.hash.sha2.Sha256,
    barriers: []const TranscriptBarrier,
    nodes: []const Node,
) void {
    hashInt(hash, u64, barriers.len);
    for (barriers) |barrier| {
        const node = nodes[barrier.node];
        hashInt(hash, u32, barrier.ordinal);
        hashInt(hash, u8, @intFromEnum(barrier.kind));
        hashInt(hash, u32, barrier.value_count);
        hashInt(hash, u8, @intFromEnum(node.kind));
        hashInt(hash, u8, @intFromEnum(node.stage));
    }
}

fn hashNativeAirSemantics(
    hash: *std.crypto.hash.sha2.Sha256,
    contract: NativeAirContract,
) void {
    hashStruct(hash, contract);
}

fn validateNativeAir(
    program: ProofProgram,
    contract: NativeAirContract,
) Error!void {
    if (program.identity.frontend != .native) return error.InvalidNativeAir;
    const geometry = contract.geometry;
    var role_counts = [_]u32{0} ** 3;
    for (program.trace_columns) |column| {
        const component_end = std.math.add(
            u32,
            geometry.component,
            geometry.component_count,
        ) catch return error.InvalidNativeAir;
        if (column.component < geometry.component or
            column.component >= component_end or
            column.log_rows == 0 or
            column.log_rows > geometry.log_rows)
        {
            return error.InvalidNativeAir;
        }
        switch (column.role) {
            .preprocessed => role_counts[0] += 1,
            .main => role_counts[1] += 1,
            .interaction => role_counts[2] += 1,
            .composition => {},
        }
    }
    if (role_counts[0] != geometry.preprocessed_columns or
        role_counts[1] != geometry.main_columns or
        role_counts[2] != geometry.interaction_columns)
    {
        return error.InvalidNativeAir;
    }
    for (program.constraints) |constraint| {
        if (constraint.component < geometry.component or
            constraint.component >=
                geometry.component + geometry.component_count)
            return error.InvalidNativeAir;
    }

    const roles = [_]CommitmentRole{
        .preprocessed,
        .main,
        .interaction,
    };
    const widths = [_]u32{
        geometry.preprocessed_columns,
        geometry.main_columns,
        geometry.interaction_columns,
    };
    var first_column: u32 = 0;
    var evaluation_log_rows: ?u32 = null;
    for (roles, widths) |role, width| {
        const matching_trees = treeCount(program.commitments, role);
        if (width == 0 and matching_trees == 0) continue;
        if (matching_trees != 1) return error.InvalidNativeAir;
        const tree = uniqueTree(program.commitments, role).?;
        if (tree.first_column != first_column or tree.column_count != width)
            return error.InvalidNativeAir;
        if (evaluation_log_rows) |expected| {
            if (tree.evaluation_log_rows != expected)
                return error.InvalidNativeAir;
        } else {
            evaluation_log_rows = tree.evaluation_log_rows;
        }
        var column_index: usize = tree.first_column;
        const end = column_index + tree.column_count;
        while (column_index < end) : (column_index += 1) {
            if (columnRole(role) != program.trace_columns[column_index].role)
                return error.InvalidNativeAir;
        }
        first_column = std.math.add(u32, first_column, width) catch
            return error.InvalidNativeAir;
    }
}

fn treeCount(
    trees: []const CommitmentTree,
    role: CommitmentRole,
) usize {
    var count: usize = 0;
    for (trees) |tree| {
        if (tree.role == role) count += 1;
    }
    return count;
}

fn uniqueTree(
    trees: []const CommitmentTree,
    role: CommitmentRole,
) ?CommitmentTree {
    var result: ?CommitmentTree = null;
    for (trees) |tree| {
        if (tree.role != role) continue;
        if (result != null) return null;
        result = tree;
    }
    return result;
}

fn isTraceRole(role: CommitmentRole) bool {
    return switch (role) {
        .preprocessed, .main, .interaction => true,
        .composition, .fri => false,
    };
}

fn columnRole(role: CommitmentRole) ColumnRole {
    return switch (role) {
        .preprocessed => .preprocessed,
        .main => .main,
        .interaction => .interaction,
        .composition => .composition,
        .fri => unreachable,
    };
}

pub fn identityDigest(bytes: []const u8) Digest {
    var digest: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

fn validateIdentity(identity: Identity) Error!void {
    if (digestEmpty(identity.air) or
        digestEmpty(identity.statement) or
        digestEmpty(identity.protocol))
    {
        return error.EmptyIdentity;
    }
}

fn digestEmpty(digest: Digest) bool {
    return std.mem.allEqual(u8, &digest, 0);
}

fn hashSlice(
    hash: *std.crypto.hash.sha2.Sha256,
    values: anytype,
) void {
    hashInt(hash, u64, values.len);
    for (values) |value| hashStruct(hash, value);
}

fn hashStruct(
    hash: *std.crypto.hash.sha2.Sha256,
    value: anytype,
) void {
    inline for (std.meta.fields(@TypeOf(value))) |field| {
        const item = @field(value, field.name);
        switch (@typeInfo(field.type)) {
            .bool => hashInt(hash, u8, @intFromBool(item)),
            .int => hashInt(hash, field.type, item),
            .@"enum" => hashInt(hash, u8, @intFromEnum(item)),
            .array => hash.update(&item),
            .@"struct" => hashStruct(hash, item),
            else => @compileError("unsupported proof-program digest field"),
        }
    }
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

test "program validation rejects cycles and produces stable identity" {
    const allocator = std.testing.allocator;
    const air = identityDigest("air");
    const statement = identityDigest("statement");
    const protocol = identityDigest("protocol");
    const columns = [_]TraceColumn{.{
        .id = 0,
        .component = 0,
        .ordinal = 0,
        .log_rows = 8,
        .role = .main,
    }};
    const constraints = [_]ConstraintProgram{.{
        .id = 0,
        .component = 0,
        .expression = identityDigest("constraint"),
        .constraint_count = 1,
        .max_degree_log = 1,
    }};
    const commitments = [_]CommitmentTree{.{
        .id = 0,
        .role = .main,
        .first_column = 0,
        .column_count = 1,
        .evaluation_log_rows = 9,
        .log_rows_per_leaf = 9,
        .retain_openings = true,
    }};
    const buffers = [_]Buffer{.{
        .id = 7,
        .words = 64,
        .alignment_words = 8,
        .live_from = .trace_generation,
        .live_through = .decommit,
        .storage = .request_local,
        .immutable = false,
    }};
    const nodes = [_]Node{
        .{
            .id = 0,
            .kind = .trace_generation,
            .stage = .trace_generation,
            .dependencies = .{ .first = 0, .count = 0 },
            .parallelism = .component,
            .graph_candidate = true,
            .work = .{
                .bytes_read = 0,
                .bytes_written = 256,
                .field_operations = 64,
                .hash_compressions = 0,
                .minimum_launches = 1,
            },
        },
        .{
            .id = 1,
            .kind = .commitment,
            .stage = .trace_commit,
            .dependencies = .{ .first = 0, .count = 1 },
            .parallelism = .merkle_subtree,
            .graph_candidate = true,
            .work = .{
                .bytes_read = 256,
                .bytes_written = 256,
                .field_operations = 64,
                .hash_compressions = 32,
                .minimum_launches = 1,
            },
        },
    };
    const dependencies = [_]u32{0};
    const description = Description{
        .identity = .{
            .frontend = .native,
            .air = air,
            .statement = statement,
            .protocol = protocol,
        },
        .trace_columns = &columns,
        .constraints = &constraints,
        .commitments = &commitments,
        .transcript = &.{.{
            .ordinal = 0,
            .node = 1,
            .phase = 0,
            .kind = .challenge,
            .value_count = 1,
        }},
        .quotient = .{
            .term_count = 1,
            .group_count = 1,
            .evaluation_log_rows = 9,
            .composition_degree_log = 1,
        },
        .fri_layers = &.{.{
            .tree_id = 0,
            .evaluation_log_rows = 9,
            .fold_step = 1,
            .cumulative_fold = 0,
            .log_rows_per_leaf = 9,
        }},
        .buffers = &buffers,
        .nodes = &nodes,
        .dependency_ids = &dependencies,
    };
    var first = try ProofProgram.init(allocator, description);
    defer first.deinit(allocator);
    var second = try ProofProgram.init(allocator, description);
    defer second.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &first.program_digest,
        &second.program_digest,
    );
    var expected_v1: Digest = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_v1,
        "e3aeaa5c59c27266c6f1ac3f57d874567133b7af76547a22c8480fb282d265ff",
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_v1,
        &first.program_digest,
    );

    var invalid_nodes = nodes;
    invalid_nodes[1].dependencies = .{ .first = 0, .count = 1 };
    var invalid_dependencies = dependencies;
    invalid_dependencies[0] = 1;
    var invalid = description;
    invalid.nodes = &invalid_nodes;
    invalid.dependency_ids = &invalid_dependencies;
    try std.testing.expectError(
        error.InvalidDependency,
        ProofProgram.init(allocator, invalid),
    );
}

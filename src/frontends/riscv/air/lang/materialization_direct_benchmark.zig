//! Retained-scratch CPU interpreter for authenticated materialization programs.
//!
//! This is the common H-010 measurement implementation. It accepts an owned
//! canonical direct program, resolves every committed leaf to an explicit main
//! column once, and retains one M31 value per direct node. There is no slot
//! reuse, backend specialization, or per-row allocation. The implementation is
//! proposal/test/tool-only and is deliberately absent from `mod.zig`.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_program = @import("materialization_direct_program.zig");
const fixed = @import("materialization_fixed_direct.zig");
const types = @import("types.zig");

pub const format_version: u16 = 1;
pub const evaluator_id =
    "stwo.typed-air.poseidon2-retained-cpu-evaluator-v1";
pub const digest_domain =
    "stwo-zig/typed-air/materialization-direct-benchmark-evaluator-v1";
pub const Digest = [32]u8;

pub const ValueColumn = struct {
    value: types.ValueId,
    tree: fixed.CommitmentTree = .main,
    physical_column: u64,
};

pub const Binary = struct { lhs: u32, rhs: u32 };
pub const Instruction = union(enum) {
    constant: M31,
    column: u32,
    add: Binary,
    sub: Binary,
    neg: u32,
    mul: Binary,
};

pub const RowResult = struct {
    sink: M31,
    nonzero_roots: u32,
    first_nonzero_root: ?u32,

    pub fn allRootsZero(self: RowResult) bool {
        return self.nonzero_roots == 0;
    }
};

pub const TraceResult = struct {
    sink: M31,
    rows: u64,
    root_evaluations: u64,
    nonzero_roots: u64,
    first_nonzero_row: ?u64,
    first_nonzero_root: ?u32,

    pub fn allRootsZero(self: TraceResult) bool {
        return self.nonzero_roots == 0;
    }
};

/// Capability returned only after evaluator authentication and complete trace
/// shape validation. It deliberately owns no allocation and is valid only
/// while the evaluator and column descriptors remain unchanged. Benchmark
/// code can therefore keep authentication outside the measured row loop.
/// This is a timing capability inside a tool-only module, not an authority or
/// memory-safety boundary, and must never be exported by the production facade.
pub const PreparedTrace = struct {
    evaluator: *Evaluator,
    columns: []const []const M31,
    rows: usize,
    rows_u64: u64,
    root_evaluations: u64,

    pub fn execute(self: PreparedTrace) TraceResult {
        return self.evaluator.executePreparedTrace(self);
    }
};

pub const Error = std.mem.Allocator.Error || error{
    CountOverflow,
    CorruptEvaluator,
    DuplicateBaseBinding,
    DuplicateColumnBinding,
    InvalidDirectOperand,
    InvalidDirectRoot,
    InvalidMainColumn,
    InvalidTraceShape,
    MissingCommittedBinding,
    UnsupportedCommitmentTree,
    UnsupportedRowMask,
};

/// Immutable-after-construction retained interpreter. One instance owns one
/// scratch array and is intentionally non-reentrant; allocate one per worker.
pub const Evaluator = struct {
    allocator: std.mem.Allocator,
    program_digest: Digest,
    evaluator_digest: Digest,
    instructions: []Instruction,
    roots: []u32,
    scratch: []M31,
    main_columns: u32,

    pub fn init(
        allocator: std.mem.Allocator,
        program: *const direct_program.Program,
        base_columns: []const ValueColumn,
        main_column_count: u64,
    ) Error!Evaluator {
        const main_columns = std.math.cast(u32, main_column_count) orelse
            return error.CountOverflow;
        if (main_columns == 0) return error.InvalidMainColumn;
        try validateBaseBindings(base_columns, main_column_count);

        const nodes = program.nodes();
        if (nodes.len == 0 or nodes.len != program.counts.nodes)
            return error.InvalidDirectOperand;
        const instructions = try allocator.alloc(Instruction, nodes.len);
        errdefer allocator.free(instructions);
        const scratch = try allocator.alloc(M31, nodes.len);
        errdefer allocator.free(scratch);

        const mapped_columns = try allocator.alloc(u64, nodes.len);
        defer allocator.free(mapped_columns);
        @memset(mapped_columns, no_column);
        for (program.selectedColumns()) |binding| {
            if (binding.tree != .main) return error.UnsupportedCommitmentTree;
            if (binding.direct_node >= nodes.len or
                binding.physical_column >= main_column_count)
            {
                return error.InvalidMainColumn;
            }
            if (mapped_columns[binding.direct_node] != no_column)
                return error.DuplicateColumnBinding;
            mapped_columns[binding.direct_node] = binding.physical_column;
        }

        for (nodes, 0..) |node, index| {
            instructions[index] = switch (node.op) {
                .constant => .{ .constant = M31.fromU64(node.value) },
                .committed => blk: {
                    const mapped = mapped_columns[index];
                    if (mapped != no_column)
                        break :blk .{ .column = @intCast(mapped) };
                    const value: types.ValueId = @enumFromInt(
                        std.math.cast(u32, node.value) orelse
                            return error.MissingCommittedBinding,
                    );
                    break :blk .{ .column = try findBaseColumn(
                        base_columns,
                        value,
                        main_column_count,
                    ) };
                },
                .fixed_committed => blk: {
                    if (node.lhs != @intFromEnum(fixed.CommitmentTree.main))
                        return error.UnsupportedCommitmentTree;
                    if (node.value >= main_column_count)
                        return error.InvalidMainColumn;
                    break :blk .{ .column = @intCast(node.value) };
                },
                .row_mask => return error.UnsupportedRowMask,
                .add => .{ .add = try checkedBinary(node, index) },
                .sub => .{ .sub = try checkedBinary(node, index) },
                .neg => .{ .neg = try checkedOperand(node.lhs, index) },
                .mul => .{ .mul = try checkedBinary(node, index) },
            };
        }

        const root_uses = program.roots();
        if (root_uses.len == 0 or root_uses.len != program.counts.root_uses)
            return error.InvalidDirectRoot;
        if (root_uses.len > std.math.maxInt(u32)) return error.CountOverflow;
        const roots = try allocator.alloc(u32, root_uses.len);
        errdefer allocator.free(roots);
        for (root_uses, roots) |root, *owned| {
            if (root.node >= nodes.len) return error.InvalidDirectRoot;
            owned.* = root.node;
        }

        const program_digest = program.programDigest();
        const evaluator_digest = computeDigest(
            program_digest,
            instructions,
            roots,
            main_columns,
            base_columns,
        );
        return .{
            .allocator = allocator,
            .program_digest = program_digest,
            .evaluator_digest = evaluator_digest,
            .instructions = instructions,
            .roots = roots,
            .scratch = scratch,
            .main_columns = main_columns,
        };
    }

    pub fn deinit(self: *Evaluator) void {
        self.allocator.free(self.scratch);
        self.allocator.free(self.roots);
        self.allocator.free(self.instructions);
        self.* = undefined;
    }

    pub fn identityDigest(self: *const Evaluator) Error!Digest {
        if (self.instructions.len == 0 or
            self.instructions.len != self.scratch.len or
            self.roots.len == 0 or self.main_columns == 0)
        {
            return error.CorruptEvaluator;
        }
        const actual = computeOwnedDigest(self);
        if (!std.mem.eql(u8, &actual, &self.evaluator_digest))
            return error.CorruptEvaluator;
        return actual;
    }

    pub fn retainedScratchBytes(self: *const Evaluator) Error!u64 {
        return std.math.mul(
            u64,
            std.math.cast(u64, self.scratch.len) orelse
                return error.CountOverflow,
            @sizeOf(M31),
        ) catch error.CountOverflow;
    }

    /// Evaluates one flat main row after authenticating the owned executable.
    /// Useful for correctness and mutation diagnostics, not the timing loop.
    pub fn evaluateRow(
        self: *Evaluator,
        row: []const M31,
    ) Error!RowResult {
        _ = try self.identityDigest();
        if (row.len != self.main_columns) return error.InvalidTraceShape;
        self.executeFlat(row);
        return self.foldRow();
    }

    /// Evaluates every committed row. Shape and executable identity are checked
    /// before the first node executes; the hot loop allocates nothing.
    pub fn evaluateTrace(
        self: *Evaluator,
        columns: []const []const M31,
    ) Error!TraceResult {
        return (try self.prepareTrace(columns)).execute();
    }

    /// Authenticates this evaluator and validates the entire column-major
    /// shape. The returned capability is the only hot-loop entry point.
    pub fn prepareTrace(
        self: *Evaluator,
        columns: []const []const M31,
    ) Error!PreparedTrace {
        _ = try self.identityDigest();
        if (columns.len != self.main_columns or columns.len == 0)
            return error.InvalidTraceShape;
        const rows = columns[0].len;
        for (columns) |column| if (column.len != rows)
            return error.InvalidTraceShape;

        const rows_u64 = std.math.cast(u64, rows) orelse
            return error.CountOverflow;
        const roots_u64 = std.math.cast(u64, self.roots.len) orelse
            return error.CountOverflow;
        const root_evaluations = std.math.mul(
            u64,
            rows_u64,
            roots_u64,
        ) catch return error.CountOverflow;
        return .{
            .evaluator = self,
            .columns = columns,
            .rows = rows,
            .rows_u64 = rows_u64,
            .root_evaluations = root_evaluations,
        };
    }

    fn executePreparedTrace(
        self: *Evaluator,
        prepared: PreparedTrace,
    ) TraceResult {
        var result = TraceResult{
            .sink = M31.zero(),
            .rows = prepared.rows_u64,
            .root_evaluations = prepared.root_evaluations,
            .nonzero_roots = 0,
            .first_nonzero_row = null,
            .first_nonzero_root = null,
        };
        for (0..prepared.rows) |row| {
            self.executeTraceRow(prepared.columns, row);
            const folded = self.foldRow();
            // Preserve row order in the observable sink even for honest zero
            // roots; the multiplier is fixed protocol data, not a score.
            result.sink = result.sink.mul(sink_challenge).add(folded.sink);
            // `prepareTrace` proved that the total number of root evaluations
            // fits in u64, so this bounded subset cannot overflow.
            result.nonzero_roots += folded.nonzero_roots;
            if (folded.first_nonzero_root) |root| {
                if (result.first_nonzero_row == null) {
                    result.first_nonzero_row = @intCast(row);
                    result.first_nonzero_root = root;
                }
            }
        }
        std.mem.doNotOptimizeAway(&result.sink);
        return result;
    }

    fn executeFlat(self: *Evaluator, row: []const M31) void {
        for (self.instructions, 0..) |instruction, index|
            self.scratch[index] = evaluateInstruction(instruction, self.scratch, row);
    }

    fn executeTraceRow(
        self: *Evaluator,
        columns: []const []const M31,
        row: usize,
    ) void {
        for (self.instructions, 0..) |instruction, index|
            self.scratch[index] = evaluateTraceInstruction(
                instruction,
                self.scratch,
                columns,
                row,
            );
    }

    fn foldRow(self: *const Evaluator) RowResult {
        var result = RowResult{
            .sink = M31.zero(),
            .nonzero_roots = 0,
            .first_nonzero_root = null,
        };
        for (self.roots, 0..) |root, ordinal| {
            const value = self.scratch[root];
            result.sink = result.sink.mul(sink_challenge).add(value);
            if (value.v != 0) {
                result.nonzero_roots += 1;
                if (result.first_nonzero_root == null)
                    result.first_nonzero_root = @intCast(ordinal);
            }
        }
        return result;
    }
};

const no_column = std.math.maxInt(u64);
const sink_challenge = M31.fromCanonical(0x10001);

fn validateBaseBindings(
    bindings: []const ValueColumn,
    main_column_count: u64,
) Error!void {
    for (bindings, 0..) |binding, index| {
        if (binding.tree != .main) return error.UnsupportedCommitmentTree;
        if (binding.physical_column >= main_column_count)
            return error.InvalidMainColumn;
        for (bindings[0..index]) |prior| {
            if (prior.value == binding.value) return error.DuplicateBaseBinding;
            if (prior.physical_column == binding.physical_column)
                return error.DuplicateColumnBinding;
        }
    }
}

fn findBaseColumn(
    bindings: []const ValueColumn,
    value: types.ValueId,
    main_column_count: u64,
) Error!u32 {
    for (bindings) |binding| if (binding.value == value) {
        if (binding.tree != .main) return error.UnsupportedCommitmentTree;
        if (binding.physical_column >= main_column_count)
            return error.InvalidMainColumn;
        return @intCast(binding.physical_column);
    };
    return error.MissingCommittedBinding;
}

fn checkedOperand(raw: u32, current: usize) Error!u32 {
    if (raw >= current) return error.InvalidDirectOperand;
    return raw;
}

fn checkedBinary(node: direct_program.Node, current: usize) Error!Binary {
    return .{
        .lhs = try checkedOperand(node.lhs, current),
        .rhs = try checkedOperand(node.rhs, current),
    };
}

inline fn evaluateInstruction(
    instruction: Instruction,
    scratch: []const M31,
    row: []const M31,
) M31 {
    return switch (instruction) {
        .constant => |value| value,
        .column => |column| row[column],
        .add => |binary| scratch[binary.lhs].add(scratch[binary.rhs]),
        .sub => |binary| scratch[binary.lhs].sub(scratch[binary.rhs]),
        .neg => |operand| scratch[operand].neg(),
        .mul => |binary| scratch[binary.lhs].mul(scratch[binary.rhs]),
    };
}

inline fn evaluateTraceInstruction(
    instruction: Instruction,
    scratch: []const M31,
    columns: []const []const M31,
    row: usize,
) M31 {
    return switch (instruction) {
        .constant => |value| value,
        .column => |column| columns[column][row],
        .add => |binary| scratch[binary.lhs].add(scratch[binary.rhs]),
        .sub => |binary| scratch[binary.lhs].sub(scratch[binary.rhs]),
        .neg => |operand| scratch[operand].neg(),
        .mul => |binary| scratch[binary.lhs].mul(scratch[binary.rhs]),
    };
}

fn computeOwnedDigest(self: *const Evaluator) Digest {
    var hash = beginDigest();
    hash.update(&self.program_digest);
    hashInt(&hash, u32, self.main_columns);
    hashInstructions(&hash, self.instructions);
    hashRoots(&hash, self.roots);
    return hash.finalResult();
}

fn computeDigest(
    program_digest: Digest,
    instructions: []const Instruction,
    roots: []const u32,
    main_columns: u32,
    _: []const ValueColumn,
) Digest {
    var hash = beginDigest();
    hash.update(&program_digest);
    hashInt(&hash, u32, main_columns);
    hashInstructions(&hash, instructions);
    hashRoots(&hash, roots);
    return hash.finalResult();
}

fn beginDigest() std.crypto.hash.sha2.Sha256 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(digest_domain);
    hashInt(&hash, u16, format_version);
    hashInt(&hash, u16, evaluator_id.len);
    hash.update(evaluator_id);
    return hash;
}

fn hashInstructions(hash: anytype, instructions: []const Instruction) void {
    hashInt(hash, u32, @intCast(instructions.len));
    for (instructions) |instruction| switch (instruction) {
        .constant => |value| {
            hashInt(hash, u8, 0);
            hashInt(hash, u32, value.v);
        },
        .column => |column| {
            hashInt(hash, u8, 1);
            hashInt(hash, u32, column);
        },
        .add => |binary| hashBinary(hash, 2, binary),
        .sub => |binary| hashBinary(hash, 3, binary),
        .neg => |operand| {
            hashInt(hash, u8, 4);
            hashInt(hash, u32, operand);
        },
        .mul => |binary| hashBinary(hash, 5, binary),
    };
}

fn hashBinary(hash: anytype, tag: u8, binary: Binary) void {
    hashInt(hash, u8, tag);
    hashInt(hash, u32, binary.lhs);
    hashInt(hash, u32, binary.rhs);
}

fn hashRoots(hash: anytype, roots: []const u32) void {
    hashInt(hash, u32, @intCast(roots.len));
    for (roots) |root| hashInt(hash, u32, root);
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

//! Reusable, pinned V3 temporal row-11 preparation session.
//!
//! This is the graph/preprocessed-input side of a future proof-bearing parent.
//! A fixed circuit and its 4,096-row preprocessed binding are built once and
//! reused across a tree. Every pair still supplies fresh child/parent words;
//! no witness or proof state is retained between nodes. Parent publication is
//! impossible here: verified wrapper children, sidecar AIR and a fresh parent
//! PCS verifier must join this stage in one transaction first.
const std = @import("std");
const core = @import("stwo_core");
const graph = @import("statement_semantics_circuit_temporal_v3.zig");
const row11 = @import("air/statement_semantics_input_witness.zig");
const row11_air = @import("air/statement_semantics_input.zig");
const interval = @import("temporal_interval_v3.zig");

const QM31 = core.fields.qm31.QM31;

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const CIRCUIT_ID: u32 = 0x5633_0011; // V3 row 11, separate from legacy 11.
pub const LOG_SIZE: u32 = 12;
pub const TRACE_SIZE: usize = 1 << LOG_SIZE;
pub const PARENT_PROOF_AVAILABLE = false;
pub const PREPROCESSED_DIGEST: [32]u8 = blk: {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(
        &result,
        "efc251be69de0a37843fd8ddca7be8c10617aa6cefe517f051ddfed0dc4413ac",
    ) catch @compileError("invalid V3 temporal row-11 preprocessed digest");
    break :blk result;
};

pub const SessionV3 = struct {
    allocator: std.mem.Allocator,
    circuit: graph.Circuit,
    preprocessed: row11.Preprocessed,
    executor: row11.Executor,

    pub fn init(allocator: std.mem.Allocator) !SessionV3 {
        var circuit = try graph.build(allocator);
        errdefer circuit.deinit();
        try circuit.validate();
        var preprocessed = try row11.Preprocessed.init(
            allocator,
            CIRCUIT_ID,
            circuit.inputBindings(),
        );
        errdefer preprocessed.deinit();
        try preprocessed.validate();
        if (preprocessed.log_size != LOG_SIZE or
            preprocessed.rows.len != graph.INPUT_COUNT)
            return error.TemporalRow11GeometryMismatch;
        if (!std.mem.eql(u8, &preprocessed.authority_digest, &PREPROCESSED_DIGEST))
            return error.TemporalRow11AuthorityMismatch;
        var definition = try row11_air.build(allocator);
        defer definition.deinit();
        const binding = try row11.Binding.canonical(&definition);
        const executor = try row11.Executor.init(&definition, &binding);
        return .{
            .allocator = allocator,
            .circuit = circuit,
            .preprocessed = preprocessed,
            .executor = executor,
        };
    }

    pub fn deinit(self: *SessionV3) void {
        self.preprocessed.deinit();
        self.circuit.deinit();
        self.* = undefined;
    }

    /// Cold integrity check for a retained session before admitting a roster.
    /// The equality of every row to the pinned graph's source binding matters:
    /// a self-rehashed preprocessed array alone is not a verifier key.
    pub fn validate(self: *const SessionV3) !void {
        try self.circuit.validate();
        try self.preprocessed.validate();
        if (self.preprocessed.circuit_id != CIRCUIT_ID or
            self.preprocessed.log_size != LOG_SIZE or
            self.preprocessed.rows.len != graph.INPUT_COUNT)
            return error.TemporalRow11GeometryMismatch;
        if (!std.mem.eql(u8, &self.preprocessed.authority_digest, &PREPROCESSED_DIGEST))
            return error.TemporalRow11AuthorityMismatch;
        var expected = try row11.Preprocessed.init(
            self.allocator,
            CIRCUIT_ID,
            self.circuit.inputBindings(),
        );
        defer expected.deinit();
        if (!std.meta.eql(self.preprocessed.authority_digest, expected.authority_digest) or
            self.preprocessed.rows.len != expected.rows.len)
            return error.TemporalRow11AuthorityMismatch;
        for (self.preprocessed.rows, expected.rows) |actual, wanted| {
            if (!std.meta.eql(actual, wanted)) return error.TemporalRow11AuthorityMismatch;
        }
        var definition = try row11_air.build(self.allocator);
        defer definition.deinit();
        const binding = try row11.Binding.canonical(&definition);
        if (!std.meta.eql(self.executor.binding, binding) or
            !std.meta.eql(self.executor.binding_digest, binding.identityDigest()))
            return error.TemporalRow11AuthorityMismatch;
    }

    /// Checks the fixed graph over exact pair preimages. This remains a native
    /// diagnostic and cannot publish a recursively verified parent.
    pub fn checkPair(
        self: *const SessionV3,
        pair: *const interval.PairPreflightV3,
        left: *const interval.IntervalV3,
        right: *const interval.IntervalV3,
        workspace: *WorkspaceV3,
    ) !void {
        // A self-rehashed but altered row array must never reach the trace
        // writer, even when this long-lived session is reused across nodes.
        if (!std.mem.eql(u8, &self.preprocessed.authority_digest, &PREPROCESSED_DIGEST))
            return error.TemporalRow11AuthorityMismatch;
        try pair.validateAgainst(left, right);
        if (workspace.inputs.len != graph.INPUT_COUNT or
            workspace.values.len != graph.NODE_COUNT)
            return error.TemporalRow11WorkspaceMismatch;
        if (!try self.circuit.checkIntoAssumeValid(
            graph.Witness.forBinary(
                &pair.child_statement_words[0],
                &pair.child_statement_words[1],
                &pair.parent_statement_words,
            ),
            workspace.inputs,
            workspace.values,
        )) return error.TemporalRow11Unsatisfied;
        for (workspace.inputs, workspace.base_inputs) |input, *base| {
            if (!input.isBase()) return error.TemporalRow11NonBaseInput;
            base.* = input.c0.a;
        }
    }

    /// Materializes the actual typed row-11 preprocessed and main SoA columns
    /// at log 12. The parent prover must commit these columns in its roster;
    /// this method alone does not make them verifier-owned.
    pub fn fillTrace(
        self: *const SessionV3,
        pair: *const interval.PairPreflightV3,
        left: *const interval.IntervalV3,
        right: *const interval.IntervalV3,
        workspace: *WorkspaceV3,
        trace: *TraceV3,
    ) !void {
        try self.checkPair(pair, left, right, workspace);
        for (trace.preprocessed) |column| {
            if (column.len != TRACE_SIZE) return error.TemporalRow11TraceGeometryMismatch;
        }
        for (trace.main) |column| {
            if (column.len != TRACE_SIZE) return error.TemporalRow11TraceGeometryMismatch;
        }
        try self.executor.generatePreprocessedInto(&self.preprocessed, &trace.preprocessed);
        try self.executor.generateMainInto(
            &self.preprocessed,
            &trace.main,
            workspace.base_inputs,
            .binary_node,
        );
    }

    pub fn requireVerifiedParent(_: *const SessionV3) error{ParentProofUnavailable}!void {
        return error.ParentProofUnavailable;
    }
};

pub const WorkspaceV3 = struct {
    allocator: std.mem.Allocator,
    inputs: []QM31,
    values: []QM31,
    base_inputs: []core.fields.m31.M31,

    pub fn init(allocator: std.mem.Allocator) !WorkspaceV3 {
        const inputs = try allocator.alloc(QM31, graph.INPUT_COUNT);
        errdefer allocator.free(inputs);
        const values = try allocator.alloc(QM31, graph.NODE_COUNT);
        errdefer allocator.free(values);
        const base_inputs = try allocator.alloc(core.fields.m31.M31, graph.INPUT_COUNT);
        return .{ .allocator = allocator, .inputs = inputs, .values = values, .base_inputs = base_inputs };
    }

    pub fn deinit(self: *WorkspaceV3) void {
        self.allocator.free(self.base_inputs);
        self.allocator.free(self.values);
        self.allocator.free(self.inputs);
        self.* = undefined;
    }
};

pub const TraceV3 = struct {
    allocator: std.mem.Allocator,
    storage: []core.fields.m31.M31,
    preprocessed: [row11.PREPROCESSED_COLUMN_COUNT][]core.fields.m31.M31,
    main: [row11.MAIN_COLUMN_COUNT][]core.fields.m31.M31,

    pub fn init(allocator: std.mem.Allocator) !TraceV3 {
        const column_count = row11.PREPROCESSED_COLUMN_COUNT + row11.MAIN_COLUMN_COUNT;
        const storage = try allocator.alloc(core.fields.m31.M31, column_count * TRACE_SIZE);
        var result: TraceV3 = .{
            .allocator = allocator,
            .storage = storage,
            .preprocessed = undefined,
            .main = undefined,
        };
        var offset: usize = 0;
        for (&result.preprocessed) |*column| {
            column.* = storage[offset..][0..TRACE_SIZE];
            offset += TRACE_SIZE;
        }
        for (&result.main) |*column| {
            column.* = storage[offset..][0..TRACE_SIZE];
            offset += TRACE_SIZE;
        }
        return result;
    }

    pub fn deinit(self: *TraceV3) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};

comptime {
    if (CIRCUIT_ID >= core.fields.m31.Modulus or
        graph.INPUT_COUNT <= (TRACE_SIZE >> 1) or
        graph.INPUT_COUNT > TRACE_SIZE or PARENT_PROOF_AVAILABLE)
        @compileError("V3 temporal row-11 session geometry or proof gate drifted");
}

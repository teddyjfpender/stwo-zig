//! Bounded precompile census/replay. Only statements and roots survive B5SS;
//! each arithmetic witness and PCS scheme is released before the next call.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const family = @import("block_v5_precompile_family_proof_v1.zig");
const protocol = @import("block_v5_precompile_protocol_v1.zig");
const Witness = @import("block_v5_precompile_witness_v1.zig").Witness;
const Statement = @import("blake3_ethereum_sha_profile.zig").admission.Statement;
const seal = @import("block_v5_source_seal_v1.zig");
const Digest = [32]u8;
pub const Execution = struct { index: u32, instance_id: Digest };
pub const Source = struct {
    context: *anyopaque,
    /// Returns owned witness storage for the requested execution ordinal.
    load: *const fn (*anyopaque, u32) anyerror!Witness,
};
pub const Sink = struct {
    context: *anyopaque,
    /// Success transfers ownership; error leaves it with the producer.
    accept: *const fn (*anyopaque, u32, *family.Proof) anyerror!void,
};
pub const Record = struct {
    execution: Execution,
    total_steps: u32,
    statement: Statement,
    key_id: Digest,
    instance_id: Digest,
    roots: seal.Roots,
    pub fn entry(self: Record) seal.Entry {
        return .{ .family = .precompile, .index = self.execution.index, .instance_id = self.instance_id, .roots = self.roots };
    }
};

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Api = family.ForBackend(Backend);
        pub const WarmCaller = struct {
            record: *const Record,
            witness: *const Witness,
            first: *Api.FirstRound,
            sealed: seal.Sealed,
            pins: seal.Pins,
            entries: []const seal.Entry,
        };
        /// Same-root ROM, state, shared-table and external-memory stages run
        /// while this execution's witness/commitments are live. Inputs are
        /// borrowed, and a callback cannot consume the arithmetic proof.
        pub const Hooks = struct {
            context: *anyopaque,
            on_first_round: ?*const fn (*anyopaque, std.mem.Allocator, WarmCaller) anyerror!void = null,
            on_proof: ?*const fn (*anyopaque, std.mem.Allocator, WarmCaller, *const family.Proof) anyerror!void = null,
        };
        records: []Record,
        config: core.pcs.PcsConfig,
        pub fn deinit(self: *Self, a: std.mem.Allocator) void {
            a.free(self.records);
            self.* = undefined;
        }

        pub fn collect(a: std.mem.Allocator, source: Source, executions: []const Execution, config: core.pcs.PcsConfig) !Self {
            const records = try a.alloc(Record, executions.len);
            errdefer a.free(records);
            for (executions, records, 0..) |execution, *record, ordinal| {
                if (ordinal > 0 and execution.index <= executions[ordinal - 1].index)
                    return error.InvalidBlockV5PrecompileCensusOrder;
                var witness = try source.load(source.context, execution.index);
                defer witness.deinit();
                var first = try Api.commitFirstRound(a, &witness, witness.total_steps, config, execution.index, execution.instance_id);
                defer first.deinit(a);
                record.* = .{ .execution = execution, .total_steps = witness.total_steps, .statement = witness.statement, .key_id = first.key_id, .instance_id = first.instance_id, .roots = first.roots };
            }
            return .{ .records = records, .config = config };
        }

        pub fn prove(self: *const Self, a: std.mem.Allocator, source: Source, sink: Sink, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, pool: *engine.work_pool.WorkPool) !void {
            return self.proveWithHooks(a, source, sink, sealed, pins, entries, pool, null);
        }
        pub fn proveWithHooks(self: *const Self, a: std.mem.Allocator, source: Source, sink: Sink, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, pool: *engine.work_pool.WorkPool, hooks: ?Hooks) !void {
            try sealed.require(pins, entries);
            if (!std.meta.eql(pins.config, self.config) or
                pins.counts[@intFromEnum(seal.Family.precompile) - 1] != self.records.len)
                return error.UntrustedBlockV5PrecompileCensus;
            for (self.records) |*record| {
                var witness = try source.load(source.context, record.execution.index);
                defer witness.deinit();
                try proveWitnessWithHooks(a, record, &witness, self.config, sink, sealed, pins, entries, pool, hooks);
            }
        }
        /// Checked one-record production while the driver's segment is live.
        /// No replay callback or second arithmetic matrix is needed by hooks.
        pub fn proveWitnessWithHooks(a: std.mem.Allocator, record: *const Record, witness: *const Witness, config: core.pcs.PcsConfig, sink: Sink, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, pool: *engine.work_pool.WorkPool, hooks: ?Hooks) !void {
            try sealed.require(pins, entries);
            if (!std.meta.eql(config, pins.config) or witness.total_steps != record.total_steps or
                !std.meta.eql(witness.statement, record.statement)) return error.BlockV5PrecompileWitnessReplayMismatch;
            var first = try Api.commitFirstRound(a, witness, witness.total_steps, config, record.execution.index, record.execution.instance_id);
            defer first.deinit(a);
            try proveFirstRoundWithHooks(a, record, witness, &first, config, sink, sealed, pins, entries, pool, hooks);
        }
        /// Reuse a real staged recommit. The caller retains witness/first-round
        /// ownership; this function checks the same exact record/roots and runs
        /// the original warm proof/publish transaction without committing twice.
        pub fn proveFirstRoundWithHooks(a: std.mem.Allocator, record: *const Record, witness: *const Witness, first: *Api.FirstRound, config: core.pcs.PcsConfig, sink: Sink, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, pool: *engine.work_pool.WorkPool, hooks: ?Hooks) !void {
            try sealed.require(pins, entries);
            if (!std.meta.eql(config, pins.config) or witness.total_steps != record.total_steps or
                !std.meta.eql(witness.statement, record.statement) or first.witness != witness or !first.owns_scheme or
                !std.meta.eql(first.config, config) or first.total_steps != record.total_steps or first.index != record.execution.index or
                !std.meta.eql(first.execution_instance_id, record.execution.instance_id) or first.scheme.trees.items.len != 2)
                return error.BlockV5PrecompileWitnessReplayMismatch;
            if (!std.meta.eql(first.entry(), record.entry()) or !std.meta.eql(first.key_id, record.key_id))
                return error.BlockV5PrecompileRootReplayMismatch;
            const warm = WarmCaller{ .record = record, .witness = witness, .first = first, .sealed = sealed, .pins = pins, .entries = entries };
            if (hooks) |callbacks| if (callbacks.on_first_round) |callback| {
                try callback(callbacks.context, a, warm);
                if (!first.owns_scheme or first.scheme.trees.items.len != 2 or !std.meta.eql(first.entry(), record.entry()))
                    return error.ChangedV5BlockWarmCaller;
                var roots = try first.scheme.roots(a);
                defer roots.deinit(a);
                if (roots.items.len != 2 or !std.meta.eql(roots.items[0..2].*, record.roots)) return error.ChangedV5BlockWarmCaller;
            };
            var proof = try Api.prove(a, first, sealed, pins, entries, pool);
            errdefer proof.deinit(a);
            if (hooks) |callbacks| if (callbacks.on_proof) |callback| try callback(callbacks.context, a, warm, &proof);
            try sink.accept(sink.context, record.execution.index, &proof);
        }
    };
}

pub const ProofSource = struct {
    context: *anyopaque,
    /// Returns an owned proof. The receiver consumes it on every path.
    load: *const fn (*anyopaque, u32) anyerror!family.Proof,
};
pub const ReceiptSink = struct {
    context: *anyopaque,
    accept: *const fn (*anyopaque, family.OpenReceipt) anyerror!void,
};

/// Records must be independently admitted by the enclosing block policy, not
/// read from proof-carried metadata. Receipts remain open until global closure.
pub fn receive(comptime Backend: type, a: std.mem.Allocator, source: ProofSource, sink: ReceiptSink, records: []const Record, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !core.fields.qm31.QM31 {
    try sealed.require(pins, entries);
    if (records.len != pins.counts[@intFromEnum(seal.Family.precompile) - 1])
        return error.UntrustedBlockV5PrecompileCensus;
    var sum = core.fields.qm31.QM31.zero();
    for (records, 0..) |record, ordinal| {
        if (ordinal > 0 and record.execution.index <= records[ordinal - 1].execution.index)
            return error.InvalidBlockV5PrecompileCensusOrder;
        if (!std.meta.eql(record.key_id, try protocol.keyId(&record.statement, record.total_steps, pins.config, record.roots[0])))
            return error.UntrustedBlockV5PrecompileKey;
        const receipt = try family.ForBackend(Backend).verifyOwned(a, try source.load(source.context, record.execution.index), &record.statement, record.total_steps, record.key_id, record.execution.instance_id, record.execution.index, sealed, pins, entries);
        if (!std.meta.eql(receipt.binding.first_roots, record.roots) or
            !std.meta.eql(receipt.binding.caller_instance_id, record.instance_id))
            return error.UntrustedBlockV5PrecompileRecord;
        try sink.accept(sink.context, receipt);
        sum = sum.add(receipt.open_sum);
    }
    return sum;
}

//! One-leaf-at-a-time fresh native/opcode/extension verification. The guest is
//! reexecuted from pinned ELF/input to reconstruct its native verifier shape;
//! this is bounded but not yet succinct. Proof authority comes from fresh
//! STARK verification against independent keys and presealed roots.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const product_mod = @import("block_v4_cpu_streaming_produce.zig");
const trusted_mod = @import("block_v4_cpu_multi_segment_assembly.zig");
const execution_mod = @import("block_v4_cpu_multi_execution_assembly.zig");
const opcode_mod = @import("block_execution_sidecar_batch_v2.zig");
const opcode_receiver = @import("block_execution_batch_receiver_v2.zig").ForEthereumShaBackend(Cpu);
const external_mod = @import("block_execution_external_batch_v2.zig");
const external_receiver = @import("block_execution_external_receiver_v2.zig").ForEthereumShaBackend(Cpu);
const closure_receipt = @import("block_memory_execution_proof_v2.zig").VerifiedExecutionReceipt;
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const segment_public = @import("blake3_segment_public.zig");
const table_closure = @import("block_v4_cpu_incremental_execution_tables.zig");
const Native = @import("blake3_ethereum_sha_proof.zig").ForBackend(Cpu);
const seal_mod = @import("block_memory_source_seal_v2.zig");

/// Optional artifact staging hook. Its result never enters the core receipt;
/// a staged leaf has no authority until the block relations and forest verify.
pub const FreshLeafObserver = struct {
    context: *anyopaque,
    on_fresh_leaf: *const fn (*anyopaque, u32, []const u8, *const Native.PreparedVerifier, [32]u8, span.SpanStatement, seal_mod.SourceSeal, *const opcode_mod.VerifiedExecutionReceipt) anyerror!void,
};

pub const Verified = struct {
    opcodes: []opcode_mod.VerifiedExecutionReceipt,
    projected: []closure_receipt,
    externals: []external_mod.VerifiedReceipt,
    leaves: []span.SpanStatement,
    public_data: []segment_public.Owned,
    pub fn deinit(self: *Verified, a: std.mem.Allocator) void {
        for (self.opcodes) |*receipt| receipt.deinit(a);
        for (self.externals) |*receipt| receipt.deinit(a);
        for (self.public_data) |*data| data.deinit();
        a.free(self.opcodes);
        a.free(self.projected);
        a.free(self.externals);
        a.free(self.leaves);
        a.free(self.public_data);
        self.* = undefined;
    }
};

pub fn verify(a: std.mem.Allocator, product: product_mod.Product, trusted: trusted_mod.Trusted, config: core.pcs.PcsConfig) !Verified {
    return verifyObserved(a, product, trusted, config, null);
}

pub fn verifyObserved(a: std.mem.Allocator, product: product_mod.Product, trusted: trusted_mod.Trusted, config: core.pcs.PcsConfig, observer: ?FreshLeafObserver) !Verified {
    const statement = product.statement;
    const count = trusted.native_key_ids.len;
    if (count == 0 or count != statement.seal.execution_instance_count or
        count != product.first.entries.len or count != product.executions.entries.len or
        count != statement.execution_active_counts.len or
        count != statement.execution_sidecar_roots.len or
        count != statement.execution_roots.len)
        return error.InvalidIncrementalExecutionCensus;
    if (statement.seal.extension_rosters_bound and
        statement.execution_extension_active_counts.len != count)
        return error.InvalidIncrementalExtensionCensus;
    const opcodes = try a.alloc(opcode_mod.VerifiedExecutionReceipt, count);
    var opcode_count: usize = 0;
    errdefer {
        for (opcodes[0..opcode_count]) |*receipt| receipt.deinit(a);
        a.free(opcodes);
    }
    const projected = try a.alloc(closure_receipt, count);
    errdefer a.free(projected);
    const leaves = try a.alloc(span.SpanStatement, count);
    errdefer a.free(leaves);
    const public_data = try a.alloc(segment_public.Owned, count);
    var public_count: usize = 0;
    errdefer {
        for (public_data[0..public_count]) |*data| data.deinit();
        a.free(public_data);
    }
    const externals = try a.alloc(external_mod.VerifiedReceipt, statement.execution_extension_roots.len);
    var external_count: usize = 0;
    errdefer {
        for (externals[0..external_count]) |*receipt| receipt.deinit(a);
        a.free(externals);
    }

    var reader = try product.source.openPass(.verification);
    defer reader.deinit();
    var index: usize = 0;
    while (try reader.next()) |owned| {
        var segment = owned;
        defer segment.deinit();
        if (index >= count) return error.IncrementalExecutionOverrun;
        var prepared = try execution_mod.Execution.init(a, &segment, @intCast(index), config, trusted.native_key_ids[index]);
        defer prepared.deinit();
        try product.first.checkLeaf(index, &prepared);
        const entry = product.first.entries[index];
        if (!std.meta.eql(prepared.nativeRoots(), statement.execution_roots[index]) or
            !std.meta.eql(prepared.opcodeWitnessRoot(), statement.execution_sidecar_roots[index][0]) or
            entry.opcode_events != statement.execution_active_counts[index] or
            !std.meta.eql(entry.hash_pin.key_id, trusted.native_key_ids[index]))
            return error.UnsealedIncrementalExecutionFirstRound;
        const leaf = try v3.leaf(trusted.job, &segment.base);
        leaves[index] = leaf;
        public_data[index] = try segment_public.Owned.init(a, &segment.base);
        public_count += 1;
        public_data[index].data.program_root = prepared.prepared.native.public_data.program_root;
        public_data[index].data.initial_rw_root = prepared.prepared.native.public_data.initial_rw_root;
        public_data[index].data.final_rw_root = prepared.prepared.native.public_data.final_rw_root;
        var expected_public = core.channel.blake3.Channel{};
        var retained_public = core.channel.blake3.Channel{};
        prepared.prepared.native.public_data.mixInto(&expected_public);
        public_data[index].data.mixInto(&retained_public);
        if (!std.mem.eql(u8, &expected_public.digestBytes(), &retained_public.digestBytes()))
            return error.InconsistentIncrementalNativePublicData;
        var loaded = try product.executions.load(index);
        defer loaded.deinit();
        opcodes[index] = try opcode_receiver.verify(a, loaded.wire, prepared.prepared, trusted.native_key_ids[index], leaf, statement.seal, @intCast(index), statement.execution_sidecar_roots[index][0], config);
        opcode_count += 1;
        if (!std.meta.eql(opcodes[index].native_roots, statement.execution_roots[index]) or
            opcodes[index].event_count != entry.opcode_events or
            !std.meta.eql(opcodes[index].witness_root, entry.opcode_witness_root))
            return error.UnsealedIncrementalOpcodeReceipt;
        projected[index] = opcodes[index].closureReceipt();

        const expected_external = try prepared.externalCount();
        if (statement.seal.extension_rosters_bound) {
            if (expected_external != statement.execution_extension_active_counts[index])
                return error.UnsealedIncrementalExtensionCensus;
        } else if (expected_external != 0) return error.UnboundIncrementalExecutionExtension;
        if (expected_external == 0) {
            if (loaded.extension != null) return error.ExtraIncrementalExtensionProof;
        } else {
            if (external_count >= externals.len) return error.MissingIncrementalExtensionRoot;
            const root = statement.execution_extension_roots[external_count];
            const wire = loaded.extension orelse return error.MissingIncrementalExtensionProof;
            if (root.index != index or wire.instance_index != index or
                !std.meta.eql(root.roots[0], entry.external_witness_root.?))
                return error.UnsealedIncrementalExtensionRoot;
            externals[external_count] = try external_receiver.verifyAfterVerifiedOpcode(a, .{ .external_stark = wire.stark_bytes, .external_claims = wire.claims }, prepared.prepared, trusted.native_key_ids[index], leaf, statement.seal, @intCast(index), &opcodes[index], root.roots[0], config);
            const verified = &externals[external_count];
            external_count += 1;
            if (verified.event_count != expected_external or
                !std.meta.eql(verified.native_roots, opcodes[index].native_roots) or
                !std.meta.eql(verified.witness_root, root.roots[0]) or
                !std.meta.eql(verified.sealed_channel_digest, opcodes[index].sealed_channel_digest))
                return error.UnsealedIncrementalExtensionReceipt;
            projected[index].event_count = try std.math.add(u64, projected[index].event_count, verified.event_count);
            projected[index].transition_sum = projected[index].transition_sum.add(verified.transition_sum);
        }
        if (observer) |hook| {
            try hook.on_fresh_leaf(hook.context, @intCast(index), loaded.wire.native_artifact, prepared.prepared, trusted.native_key_ids[index], leaf, statement.seal, &opcodes[index]);
            // Recursive proving currently takes a mutable prepared pointer.
            // Recheck the public verifier shape before it leaves this scope.
            try prepared.prepared.validate(trusted.native_key_ids[index]);
            if (!std.meta.eql(prepared.nativeRoots(), statement.execution_roots[index]) or
                !std.meta.eql(opcodes[index].native_roots, statement.execution_roots[index]) or
                !std.meta.eql(opcodes[index].witness_root, statement.execution_sidecar_roots[index][0]))
                return error.ObserverChangedIncrementalLeaf;
            var after_public = core.channel.blake3.Channel{};
            prepared.prepared.native.public_data.mixInto(&after_public);
            if (!std.mem.eql(u8, &expected_public.digestBytes(), &after_public.digestBytes()))
                return error.ObserverChangedIncrementalPublicData;
        }
        index += 1;
    }
    if (index != count or external_count != externals.len)
        return error.IncompleteIncrementalExecutionProofs;
    try table_closure.verify(a, product, opcodes, externals, config);
    return .{ .opcodes = opcodes, .projected = projected, .externals = externals, .leaves = leaves, .public_data = public_data };
}

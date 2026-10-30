//! Bounded CPU execution originals -> one complete mixed root candidate.
//! The receiver independently selects policy/key and authenticates the output;
//! this producer returns no verification receipt. All original proof owners
//! remain borrowed only for this call. Returned metadata/proof are detached.
//! The shared variant changes only transcript factoring and its typed protocol.
//! Both variants produce one complete root with at most 64 original children;
//! this does not enable shared-prefix factoring across bounded direct batches.
pub fn For(comptime shared: bool) type {
    return struct {
        const std = @import("std");
        const Cpu = @import("stwo_cpu_backend").CpuBackend;
        const Original = @import("../prover/block_v7_execution_receiver_v1.zig");
        const Metadata = @import("block_v7_mixed_metadata_v1.zig");
        const Inputs = @import("block_v7_mixed_inputs_v1.zig");
        const Bus = @import("block_v7_mixed_public_v1.zig");
        const Cold = if (shared) @import("block_v7_shared_epoch_mixed_fixed_v1.zig") else @import("block_v7_mixed_fixed_v1.zig");
        const Collection = @import("block_v7_mixed_collection_v1.zig").For(shared);
        pub const Protocol = if (shared) @import("block_v7_shared_epoch_mixed_protocol_v1.zig") else @import("block_v7_mixed_protocol_v1.zig");
        const Mixed = if (shared) @import("block_v7_shared_epoch_mixed_preparation_v1.zig") else @import("block_v7_mixed_preparation_v1.zig");
        const Parent = @import("blake3_execution_parent_proof.zig");
        pub const Options = struct {
            quotient_executor: ?*const @import("stwo_prover_engine").pcs.QuotientExecutor = null,
            composition_executor: ?*const @import("blake3_parent_composition_executor_v1.zig").Executor = null,
            interaction_executor: ?*const @import("blake3_parent_interaction_executor_v1.zig").Executor = null,
            profile: @import("blake3_execution_parent_protocol.zig").Profile,
            capacity: u32 = 2,
            /// Optional common child setup/live cap, clamped by each parent.
            family_max_bytes: ?usize = null,
            reuse_native_compiler: bool = false,
            max_native_compiler_bytes: usize = 2 << 30,
            native_compiler_parallelism: usize = 1,
            parallel_preparation: usize = 1,
            original_captures: ?*Original.Captures = null,
            reuse_caller_compiler: bool = true,
            reuse_fixed_commitment: bool = true,
            max_caller_compilers: usize = Bus.MAX_CHILDREN,
            max_caller_compiler_bytes: usize = 2 << 30,
            fixed: Cold.Limits = .{},
            join: Mixed.Limits = .{},
        };
        pub const Stats = struct {
            metadata_ns: u64,
            native_compile_ns: u64,
            caller_compile_ns: u64,
            cold_key_ns: u64,
            capture_witness_join_ns: u64,
            family_preparation: Collection.Stats,
            parity_ns: u64,
            plan_ns: u64,
            proof_ns: u64,
            encoding_ns: u64,
            whole_ns: u64,
            retained_rows_bytes: usize,
            fixed_commitment_reused: bool,
        };
        pub const Output = struct {
            allocator: std.mem.Allocator,
            metadata: *Metadata.Owned,
            key: Protocol.Key,
            wires: []Bus.Wire,
            bytes: []u8,
            stats: Stats,
            pub fn deinit(self: *Output) void {
                self.allocator.free(self.bytes);
                self.allocator.free(self.wires);
                self.metadata.deinit();
                self.* = undefined;
            }
        };
        pub fn produce(a: std.mem.Allocator, trusted: Original.Trusted, originals: Original.Input, options: Options) !Output {
            try @import("block_v7_receiver_security_v1.zig").require(options.profile.config(), trusted.config, originals.epoch.config);
            if (options.capacity == 0) return error.InvalidCompleteRootCapacity;
            var whole = try std.time.Timer.start();
            var phase = try std.time.Timer.start();
            var stats: Stats = undefined;
            const metadata = try Metadata.Owned.init(a, trusted, originals);
            errdefer metadata.deinit();
            var canonical = try Inputs.Owned.init(a, metadata.input());
            defer canonical.deinit();
            stats.metadata_ns = phase.lap();
            if (options.fixed.native_compilers != null) return error.ExternalNativeCompilerNotSupported;
            if (options.fixed.caller_compilers != null or options.fixed.active_caller_compilers != null) return error.ExternalCallerCompilerNotSupported;
            var compilers = try @import("block_v7_caller_compiler_set_v1.zig").Owned.initWithTranscript(a, metadata.input(), options.max_caller_compilers, options.max_caller_compiler_bytes, options.reuse_caller_compiler, if (shared) null else options.capacity);
            defer compilers.deinit();
            stats.caller_compile_ns = phase.lap();
            var native_compilers = if (options.reuse_native_compiler) try @import("block_v7_native_compiler_set_v1.zig").Owned.initWindow(a, metadata.input(), 0, canonical.expected.len, Bus.MAX_CHILDREN, .{ .max_bytes = options.max_native_compiler_bytes, .parallel_families = options.native_compiler_parallelism }) else null;
            defer if (native_compilers) |*set| set.deinit();
            stats.native_compile_ns = phase.lap();
            const family_max_bytes = options.family_max_bytes orelse options.fixed.family_max_bytes;
            var fixed_limits = options.fixed;
            fixed_limits.family_max_bytes = family_max_bytes;
            fixed_limits.native_compilers = if (native_compilers) |*set| set.slots else null;
            fixed_limits.caller_compilers = compilers.full();
            fixed_limits.active_caller_compilers = compilers.active();
            var cold = try Cold.Owned.derive(a, metadata.input(), options.capacity, fixed_limits);
            var cold_live = true;
            defer if (cold_live) cold.deinit();
            const Fixed = @import("blake3_parent_fixed_key_v1.zig").ForBackend(Cpu);
            var committed: ?Fixed.Committed = if (options.reuse_fixed_commitment) try Fixed.deriveCommitted(a, cold.fixed, cold.context, options.profile) else null;
            defer if (committed) |*owned| owned.deinit();
            const base = if (committed) |*owned| owned.key else try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, cold.fixed, cold.context, options.profile);
            const key = try Protocol.Key.fromGeometry(base, cold.wires, cold.expected);
            stats.cold_key_ns = phase.lap();
            stats.family_preparation = .{};
            var joined = try Collection.prepareWindow(a, originals, metadata.input(), 0, canonical.expected.len, .{ .original_captures = options.original_captures, .stats = &stats.family_preparation, .parallel_preparation = options.parallel_preparation, .capacity = options.capacity, .family_max_bytes = family_max_bytes, .join = options.join, .native_compilers = if (native_compilers) |*set| set.slots else null, .caller_compilers = compilers.full(), .active_caller_compilers = compilers.active() });
            defer joined.deinit();
            if (options.original_captures) |captures| try captures.requireDrained();
            // The live composition owns its evaluation graph. Release the compiler
            // cache before commitment/proving so it does not raise the root peak.
            compilers.clear();
            if (native_compilers) |*set| set.clear();
            stats.capture_witness_join_ns = phase.lap();
            try cold.validateLive(&joined);
            try canonical.requireSame(joined.values());
            stats.retained_rows_bytes = try joined.recursive.rows.retainedBytes();
            stats.parity_ns = phase.lap();
            // Independent cold/live equality is established above; retain only the
            // authenticated commitment, not a second copy of every fixed row.
            cold.deinit();
            cold_live = false;
            const admission = try Protocol.Admission.init(key, try key.identity(), joined.wires, joined.values(), canonical.expected);
            const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
            const plan = if (committed) |*owned| try Plan.initFromFixedCommitment(a, &joined.recursive.rows, admission, owned) else try Plan.init(a, &joined.recursive.rows, admission);
            stats.fixed_commitment_reused = committed != null;
            // Plan acquired its own lease; release setup ownership before proving.
            if (committed) |*owned| owned.deinit();
            committed = null;
            defer plan.deinit();
            plan.setQuotientExecutor(options.quotient_executor);
            plan.setCompositionExecutor(options.composition_executor);
            plan.setInteractionExecutor(options.interaction_executor);
            stats.plan_ns = phase.lap();
            var proof = try plan.proveConsuming(a, &joined.recursive.rows);
            defer proof.deinit();
            stats.proof_ns = phase.lap();
            const bytes = try Parent.codec.encode(a, &proof, &admission);
            errdefer a.free(bytes);
            const wires = try a.dupe(Bus.Wire, joined.wires);
            stats.encoding_ns = phase.lap();
            stats.whole_ns = whole.read();
            return .{ .allocator = a, .metadata = metadata, .key = key, .wires = wires, .bytes = bytes, .stats = stats };
        }
    };
}

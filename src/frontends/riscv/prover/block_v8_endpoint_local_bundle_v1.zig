//! Complete ORIGINAL bundle receiver for the late-memory architecture.
//! Local execution originals are freshly verified one at a time; their public
//! CPU boundaries and exact endpoint roots define the global roster. Bridge
//! batches open those roots under ONE late challenge, and one global memory
//! original closes initialization, adjacency and externally pinned endpoints.
//! This is NOT a recursive single-root or terminal whole-block publication.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Scope = @import("block_v8_endpoint_local_scope_v1.zig");
const Metadata = @import("block_v8_endpoint_local_statement_wire_v1.zig");
const Codec = @import("block_v8_endpoint_local_codec_v1.zig");
const Window = @import("block_v7_real_window_policy_v2.zig");
const Memory = @import("block_v7_window_memory_joint_v1.zig");
const MemoryProtocol = @import("block_v7_window_memory_joint_protocol_v1.zig");
const MemoryLayout = @import("block_v7_window_memory_joint_layout_v1.zig");
const BridgeScope = @import("block_v8_endpoint_global_bridge_scope_v1.zig");
const Bridge = @import("block_v8_endpoint_global_bridge_proof_v1.zig");
const Compact = @import("block_v8_compact_ram_proof_v1.zig");
const Sources = @import("block_v8_endpoint_source_wire_dispatch_v1.zig");
pub const production_active = false;
pub const External = @import("block_v7_window_union_loader_v1.zig").External;
pub const Summary = struct {
    scope: enum { declared_window_originals_closed } = .declared_window_originals_closed,
    global_argument: enum { legacy_window, compact_endpoint } = .legacy_window,
    elf_sha256: [32]u8,
    incoming_sha256: [32]u8,
    outgoing_sha256: [32]u8,
    epoch: [32]u8,
    cycles: u64,
    cohorts: u32,
    bridge_batches: u32,
    endpoint_events: u64,
    logical_ram_accesses: u64,
    program_fetches: u64,
    external_retirements: u64 = 0,
};
pub fn For(comptime compact: bool) type {
    return struct {
        pub const Input = struct {
            cohort_count: u32,
            bridge_batches: u32,
            cohort_policy: ?Window.CohortPolicy = null,
            /// Nomination only: every value/permission is independently reconstructed
            /// from the externally pinned complete incoming snapshot and ELF.
            selected_initial_addresses: []const u32,
            global_memory: if (compact) *const Compact.Proof else *const Memory.Proof,
        };
        pub const Limits = struct {
            max_live_bytes: usize = 12 << 30,
            max_cohorts: u32 = 4096,
            max_cohort_cycles: u32 = 1 << 20,
            initial: @import("block_v7_initial_intervals_v1.zig").Limits = .{},
            metadata: Metadata.Limits = .{},
            local: Codec.Limits = .{},
            mixed_metadata: @import("block_v8_endpoint_mixed_statement_wire_v1.zig").Limits = .{},
            mixed: @import("block_v8_endpoint_mixed_codec_v1.zig").Limits = .{},
            bridge: Bridge.Limits = .{},
            memory: if (compact) Compact.Limits else Memory.Limits = .{},
        };
        /// Provider has loadLocal(a,index)->lease{metadata,proof,deinit()} and
        /// loadBridge(a,index)->lease{first,count,proof:*const Bridge.Proof,deinit()}.
        /// Each lease is released before the next is requested. Providers nominate
        /// bytes/proofs only: they return no admission receipt, key, witness or epoch.
        /// File/service implementations can bound their own read buffers with `a`.
        pub fn verify(backing: std.mem.Allocator, external: External, input: @This().Input, provider: anytype, limits: @This().Limits) !Summary {
            if (limits.max_live_bytes == 0 or input.cohort_count == 0 or input.cohort_count > @min(limits.max_cohorts, BridgeScope.MAX_SOURCES) or input.bridge_batches == 0 or input.bridge_batches > input.cohort_count or input.selected_initial_addresses.len > limits.initial.max_initialized_words)
                return error.InvalidEndpointBundleRoster;
            if (compact and input.cohort_policy == null) return error.InvalidEndpointBundleCohortPolicy;
            const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(backing, limits.max_live_bytes);
            defer budget.destroy();
            const a = budget.allocator();
            if (input.cohort_policy) |cohort_policy| {
                if (cohort_policy.cohort_count != input.cohort_count or cohort_policy.max_cohort_cycles > limits.max_cohort_cycles) return error.InvalidEndpointBundleCohortPolicy;
                try cohort_policy.validate(external.trusted.window.cycles);
            }
            var window = if (input.cohort_policy) |cohort_policy|
                if (input.selected_initial_addresses.len == 0 and external.boundary.isEmpty())
                    try Window.Owned.deriveCohorts(a, external.elf, external.incoming, external.outgoing, external.trusted, cohort_policy, limits.initial)
                else
                    try Window.Owned.deriveCohortsForAddressesWithBoundary(a, external.elf, external.incoming, external.outgoing, external.trusted, cohort_policy, input.selected_initial_addresses, external.boundary, limits.initial)
            else if (input.selected_initial_addresses.len == 0)
                try Window.Owned.derive(a, external.elf, external.incoming, external.outgoing, external.trusted, limits.initial)
            else
                try Window.Owned.deriveForAddresses(a, external.elf, external.incoming, external.outgoing, external.trusted, input.selected_initial_addresses, limits.initial);
            defer window.deinit();
            const info = window.initial.info;
            const policy = @import("block_v7_execution_policy_v1.zig").Policy{ .initialized = &window.initial, .program_root = window.program_root, .terminal = .{ .final_cycle = external.trusted.window.cycles, .halt_address = info.halt_flag, .length_address = info.output_len, .data_address = info.output_data, .output_end = info.output_end, .output = @splat(0) }, .config = external.config, .window = &window };
            try policy.validate();
            const local_trusted = Scope.Trusted{ .elf = external.elf, .elf_sha256 = external.trusted.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = external.config, .cohort_count = input.cohort_count, .terminal_cycle = if (external.boundary.terminal != null) external.trusted.window.cycles else null, .boundary_policy_id = if (external.boundary.terminal) |last| last.policy_id else @splat(0) };
            const sources = try a.alloc(BridgeScope.Source, input.cohort_count);
            defer a.free(sources);
            var registers = window.boundary.initial_cpu.regs;
            var pc = window.boundary.initial_cpu.pc;
            var cycle: u64 = 1;
            var logical: u64 = 0;
            var fetches: u64 = 0;
            var external_retirements: u64 = 0;
            var endpoint_count: u64 = 0;
            for (sources, 0..) |*source, index| {
                var lease = try provider.loadLocal(a, @as(u32, @intCast(index)));
                defer lease.deinit();
                const verified = try Sources.verifyBytes(a, lease.metadata, lease.proof, local_trusted, .{ .metadata = limits.metadata, .local = limits.local, .mixed_metadata = limits.mixed_metadata, .mixed = limits.mixed });
                if (input.cohort_policy) |cohort_policy| if (verified.cycles > cohort_policy.max_cohort_cycles) return error.UntrustedEndpointBundleCohortPolicy;
                const frame = verified.source.frame;
                if (verified.cohort_ordinal != index or verified.source.policy.source_ordinal != index or frame.clock_frame != .leaf_local or frame.global_first_cycle != cycle or frame.cycle_count != verified.cycles or verified.initial_pc != pc or !std.meta.eql(verified.initial_regs, registers))
                    return error.UntrustedEndpointBundleCpuChain;
                cycle = try std.math.add(u64, cycle, verified.cycles);
                if (cycle - 1 > external.trusted.window.cycles) return error.UntrustedEndpointBundleCpuChain;
                pc = verified.final_pc;
                registers = verified.final_regs;
                endpoint_count = try std.math.add(u64, endpoint_count, verified.source.endpoint_count);
                logical = try std.math.add(u64, logical, verified.logical_ram_accesses);
                fetches = try std.math.add(u64, fetches, verified.program_fetches);
                external_retirements = try std.math.add(u64, external_retirements, verified.external_retirements);
                source.* = .{ .local_identity = verified.source.local_identity, .local_epoch = verified.source.local_epoch, .endpoint_root = verified.source.endpoint_root, .endpoint_count = verified.source.endpoint_count, .policy = verified.source.policy };
            }
            if (cycle - 1 != external.trusted.window.cycles or pc != window.boundary.final_cpu.pc or !std.meta.eql(registers, window.boundary.final_cpu.regs)) return error.UntrustedEndpointBundleCpuChain;
            const global_policy = if (compact) Compact.Policy{ .window = &window, .config = external.config, .event_count = std.math.cast(u32, endpoint_count) orelse return error.InvalidEndpointBundleGlobalGeometry } else policy;
            const global_entry = if (compact) entry: {
                if (input.global_memory.event_count != endpoint_count) return error.InvalidEndpointBundleGlobalGeometry;
                break :entry try global_policy.entry(input.global_memory.roots);
            } else try legacyEntry(a, policy, input.global_memory, limits.memory);
            var roster = try BridgeScope.Owned.init(a, try global_policy.digest(), external.config, sources, global_entry);
            defer roster.deinit();
            var transition = core.fields.qm31.QM31.zero();
            var next: u32 = 0;
            for (0..input.bridge_batches) |index| {
                var lease = try provider.loadBridge(a, @as(u32, @intCast(index)));
                defer lease.deinit();
                if (lease.first != next or lease.count == 0 or lease.count > BridgeScope.MAX_BATCH_SOURCES or lease.count > input.cohort_count - next) return error.IncompleteEndpointBridgeCoverage;
                var batch = try roster.batch(a, lease.first, lease.count);
                defer batch.deinit();
                transition = transition.add(try Bridge.verifyConditional(a, batch, &lease.proof.stark, lease.proof.claims, limits.bridge));
                next = try std.math.add(u32, next, lease.count);
            }
            if (next != input.cohort_count) return error.IncompleteEndpointBridgeCoverage;
            const memory = if (compact) try Compact.verifyConditional(a, global_policy, roster.epoch, roster.entries, input.global_memory, limits.memory) else try Memory.For(Cpu).verify(a, policy, roster.epoch, roster.entries, input.global_memory, limits.memory);
            if (memory.event_count != roster.endpoint_count or !transition.add(memory.transition).isZero()) return error.UnclosedEndpointBundleGlobalMemory;
            return .{ .global_argument = if (compact) .compact_endpoint else .legacy_window, .elf_sha256 = external.trusted.elf_sha256, .incoming_sha256 = external.trusted.incoming_sha256, .outgoing_sha256 = external.trusted.outgoing_sha256, .epoch = roster.epoch.digest, .cycles = cycle - 1, .cohorts = input.cohort_count, .bridge_batches = input.bridge_batches, .endpoint_events = memory.event_count, .logical_ram_accesses = logical, .program_fetches = fetches, .external_retirements = external_retirements };
        }
    };
}
pub const Input = For(false).Input;
pub const Limits = For(false).Limits;
pub const CompactInput = For(true).Input;
pub const CompactLimits = For(true).Limits;
pub const verify = For(false).verify;
pub const verifyCompact = For(true).verify;

fn legacyEntry(a: std.mem.Allocator, policy: @import("block_v7_execution_policy_v1.zig").Policy, proof: *const Memory.Proof, limits: Memory.Limits) !@import("block_v7_execution_epoch_v1.zig").Entry {
    if (proof.ram.len == 0 or proof.ram.len > limits.memory.max_shards) return error.InvalidEndpointBundleGlobalGeometry;
    const geometries = try a.alloc(@import("block_v5_ram_lanes_protocol_v1.zig").Claim, proof.ram.len);
    defer a.free(geometries);
    for (geometries, proof.ram) |*geometry, claim| geometry.* = claim.geometry;
    var layout = try MemoryLayout.Layout.init(a, geometries, proof.interval_log, limits.layout);
    defer layout.deinit();
    return MemoryProtocol.entry(policy, &layout, proof.roots);
}

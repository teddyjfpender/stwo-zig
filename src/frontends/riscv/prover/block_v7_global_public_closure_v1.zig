//! Original whole-execution policy and typed algebra over canonical PUBLIC
//! operands. This module proves nothing by itself: the complete receiver must
//! first authenticate all frames with its independently keyed mixed STARK.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Inputs = @import("../recursion/block_v7_mixed_inputs_v1.zig");
const Bus = @import("../recursion/block_v7_mixed_public_v1.zig");
const Original = @import("block_v7_execution_receiver_v1.zig");
const I = @import("block_v7_initial_intervals_v1.zig");
const P = @import("block_v7_execution_policy_v1.zig");
const E = @import("block_v7_execution_epoch_v1.zig");
const LP = @import("block_v5_native_lookup_plan_v1.zig");
const CallerProfile = @import("blake3_ethereum_sha_profile.zig");
pub const Trusted = Original.Trusted;
pub const Limits = struct { initial: I.Limits = .{}, max_segments: usize = 4096, max_entries: usize = Bus.MAX_CHILDREN, memory: @import("block_v7_memory_joint_proof_v1.zig").Limits = .{}, window_memory: @import("block_v7_window_memory_joint_v1.zig").Limits = .{} };
pub const Summary = struct { statement: [32]u8, epoch: [32]u8, cycles: u64, segments: u32, ram_events: u64, program_fetches: u64, output: [43]u8, scope: Original.Scope = .complete_execution };
pub fn closePublic(a: std.mem.Allocator, trusted: Trusted, input: Inputs.Input, authenticated: Bus.Values, limits: Limits) !Summary {
    if (input.natives.len == 0 or input.natives.len > limits.max_segments or input.entries.len > limits.max_entries) return error.InvalidV7ExecutionRoster;
    var canonical = try Inputs.Owned.init(a, input);
    defer canonical.deinit();
    try canonical.requireSame(authenticated);
    return closeCanonical(a, trusted, input, limits);
}
/// The final reduction receiver calls this only AFTER its root authenticates
/// all original frames. Explicit max_entries is independent receiver policy;
/// no partial batch is required or permitted to claim global closure.
pub fn closeWholePublic(a: std.mem.Allocator, trusted: Trusted, input: Inputs.Input, authenticated: []const Bus.Child, limits: Limits) !Summary {
    if (input.natives.len == 0 or input.natives.len > limits.max_segments or input.entries.len > limits.max_entries) return error.InvalidV7ExecutionRoster;
    var canonical = try Inputs.Owned.initWhole(a, input, limits.max_entries);
    defer canonical.deinit();
    try canonical.requireSameWhole(authenticated);
    return closeCanonical(a, trusted, input, limits);
}
fn closeCanonical(a: std.mem.Allocator, trusted: Trusted, input: Inputs.Input, limits: Limits) !Summary {
    var initialized = try Original.deriveInitialization(a, trusted, limits.initial);
    defer initialized.deinit();
    var image = try @import("block_v7_program_image_v1.zig").Owned.init(a, trusted.elf, &initialized, limits.initial);
    defer image.deinit();
    const policy = P.Policy{ .initialized = &initialized, .program_root = image.root.bytes, .terminal = trusted.terminal, .config = trusted.config, .window = trusted.window };
    try input.epoch.require(try policy.digest(), trusted.config, input.epoch.counts, input.entries, limits.max_entries);
    const windows = try a.alloc(P.Native, input.natives.len);
    defer a.free(windows);
    const external = try a.alloc(u32, input.natives.len);
    defer a.free(external);
    @memset(external, 0);
    var demands: [6]u64 = @splat(0);
    inline for (.{ false, true }) |active| {
        const callers = if (active) input.active_callers else input.callers;
        for (callers, 0..) |caller, index| {
            const pin = caller.admitted.pin();
            if (trusted.profile != CallerProfile.execution_profile or pin.index != index or pin.execution_index >= input.natives.len or (index != 0 and pin.execution_index <= callers[index - 1].admitted.pin().execution_index)) return error.UntrustedV7CallerRoster;
            const native = input.natives[pin.execution_index].profile.pin;
            if (!std.meta.eql(pin.frame, native.frame) or pin.total_steps != native.frame.cycle_count or !std.meta.eql(pin.execution_identity, (try native.entry(a)).identity)) return error.UntrustedV7CallerExecution;
            _ = try pin.require(a, input.epoch, input.entries);
            external[pin.execution_index] = CallerProfile.externalCount(pin.statement);
            var schedule = try @import("block_v5_caller_fused_schedule_v1.zig").Schedule.init(a, pin.statement, pin.total_steps, pin.frame, 1);
            defer schedule.deinit();
            const demand = try @import("block_v5_memory_byte_demand_v1.zig").externalDemandForMode(pin.statement, schedule.memory, 1);
            try @import("block_v5_precompile_table_demand_v1.zig").add(a, &demands, pin.statement, pin.total_steps, trusted.config);
            try LP.addDemand(&demands, try LP.sidecarMemoryDemand(demand.event_count));
            const CallerProof = if (active) @import("block_v7_caller_active_proof_v1.zig") else @import("block_v7_caller_joint_proof_v1.zig");
            try CallerProof.ForBackend(Cpu).requireFixedRoot(a, pin);
        }
    }
    for (input.natives, windows, 0..) |native, *window, index| {
        const pin = native.profile.pin;
        if (pin.index != index or pin.template.execution_profile != trusted.profile or pin.template.external_retirements != external[index]) return error.UntrustedV7NativeRoster;
        window.* = .{ .shape = pin.shape, .frame = pin.frame, .external_retirements = external[index] };
        try LP.addDemand(&demands, try LP.nativeDemand(pin.shape, external[index]));
        try LP.addDemand(&demands, try LP.sidecarMemoryDemand(pin.expected_events));
        try @import("block_v5_native_execution_proof_v3.zig").ForBackend(Cpu).verifyFixed(a, pin.shape, pin.template, trusted.config);
    }
    try policy.validateWindows(windows);
    const expected_plan = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = @intCast(input.natives.len), .max_requests = demands };
    if (!std.meta.eql(expected_plan, input.lookup.input.policy.plan)) return error.UntrustedV7LookupDemand;
    const rom = input.program.input.policy.plan;
    if (!std.meta.eql(rom.program_root, image.root) or rom.leaves.len != image.leaves.len) return error.UntrustedV7ProgramImage;
    for (rom.leaves, image.leaves) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedV7ProgramImage;
    try @import("block_v7_program_provider_v1.zig").ForBackend(Cpu).requireFixedRoots(a, input.program.input.policy);
    try @import("block_v7_lookup_compact_proof_v1.zig").For(Cpu).requireFixedRoots(a, input.lookup.input.policy, .{});
    const memory = try closeMemory(a, policy, input, limits);
    var program_sum = input.program.input.claim;
    var transition = memory.transition;
    var table_sums = input.lookup.input.claims;
    var fetches: u64 = 0;
    var events: u64 = 0;
    const states = try a.alloc(Q, input.natives.len);
    defer a.free(states);
    const registers = try a.alloc(Q, input.natives.len);
    defer a.free(registers);
    const drawn = try input.epoch.draw(a);
    for (input.natives, 0..) |native, index| {
        const n = try @import("block_v7_native_source_v1.zig").exportsFromClaims(a, native.profile.pin, native.claims.projection, native.claims.access, &drawn);
        if (!n.ordinary_memory_residual.isZero() or !n.auxiliary_clock_memory.isZero()) return error.UnclosedV7NativeRelations;
        states[index] = n.state_residual;
        registers[index] = n.register_residual;
        program_sum = program_sum.add(n.program_sum);
        transition = transition.add(n.transition_sum);
        fetches = try std.math.add(u64, fetches, n.fetch_count);
        events = try std.math.add(u64, events, n.event_count);
        for (&table_sums, n.table_requests) |*value, request| value.* = value.add(request);
        const range = @intFromEnum(@import("../air/lookups/tables/schema.zig").Kind.range_check_8_8);
        table_sums[range] = table_sums[range].add(n.byte_requests);
    }
    inline for (.{ false, true }) |active| {
        const callers = if (active) input.active_callers else input.callers;
        for (callers) |caller| {
            const n = try @import("block_v7_caller_joint_source_v1.zig").exports(&caller.admitted.relations.schedule, &caller.arithmetic, &caller.claims);
            if (!n.internal_residual.isZero() or !n.auxiliary_clock_memory.isZero()) return error.UnclosedV7CallerRelations;
            const index = caller.admitted.pin().execution_index;
            states[index] = states[index].add(n.state_sum);
            registers[index] = registers[index].add(n.register_sum);
            program_sum = program_sum.add(n.program_sum);
            transition = transition.add(n.transition_sum);
            fetches = try std.math.add(u64, fetches, n.fetch_count);
            events = try std.math.add(u64, events, n.event_count);
            for (&table_sums, n.table_requests) |*value, request| value.* = value.add(request);
            const range = @intFromEnum(@import("../air/lookups/tables/schema.zig").Kind.range_check_8_8);
            table_sums[range] = table_sums[range].add(n.byte_requests);
        }
    }
    for (states, registers) |state, register| if (!state.isZero() or !register.isZero()) return error.UnclosedV7WindowRelations;
    if (!program_sum.isZero() or !transition.isZero() or fetches != rom.expected_fetches or events != memory.event_count) return error.UnclosedV7ExecutionRelations;
    for (table_sums) |sum| if (!sum.isZero()) return error.UnclosedV7LookupRelations;
    return .{ .statement = try policy.digest(), .epoch = input.epoch.digest, .cycles = policy.finalCycle(), .segments = @intCast(input.natives.len), .ram_events = events, .program_fetches = fetches, .output = if (trusted.window == null) trusted.terminal.output else @splat(0), .scope = if (trusted.window == null) .complete_execution else .declared_window };
}

fn closeMemory(a: std.mem.Allocator, policy: P.Policy, input: Inputs.Input, limits: Limits) !@import("block_v7_memory_claim_closure_v1.zig").Open {
    if (input.window_memory) |memory| {
        if (policy.window == null or input.memory != null or input.separate_memory != null or !std.meta.eql(try memory.input.policy.digest(), try policy.digest())) return error.UntrustedV7MemoryPolicy;
        const geometry = try a.alloc(@import("block_v5_ram_lanes_protocol_v1.zig").Claim, memory.input.claims.ram.len);
        defer a.free(geometry);
        for (geometry, memory.input.claims.ram) |*g, claim| g.* = claim.geometry;
        try @import("block_v7_window_memory_joint_v1.zig").For(Cpu).requireFixedRoot(a, policy, geometry, memory.input.interval_log, memory.input.roots[0], limits.window_memory);
        const drawn = try input.epoch.draw(a);
        return @import("block_v7_window_memory_joint_protocol_v1.zig").closeVerifiedClaims(policy, drawn.word.initial, memory.input.claims);
    }
    if (policy.window != null) return error.UntrustedV7MemoryPolicy;
    if (input.memory) |memory| {
        if (input.separate_memory != null or !std.meta.eql(try memory.input.policy.digest(), try policy.digest())) return error.UntrustedV7MemoryPolicy;
        const geometry = try a.alloc(@import("block_v5_ram_lanes_protocol_v1.zig").Claim, memory.input.claims.ram.len);
        defer a.free(geometry);
        for (geometry, memory.input.claims.ram) |*g, claim| g.* = claim.geometry;
        try @import("block_v7_memory_joint_proof_v1.zig").For(Cpu).requireFixedRoot(a, policy, geometry, memory.input.interval_log, memory.input.roots[0], limits.memory);
        return @import("block_v7_memory_claim_closure_v1.zig").close(memory.input.claims);
    }
    const separate = input.separate_memory orelse return error.InvalidV7MixedMemoryMode;
    const Memory = @import("../recursion/block_v7_memory_component_recursive_v1.zig");
    const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
    const Closure = @import("block_v7_memory_claim_closure_v1.zig");
    const cap = limits.memory.memory;
    if (separate.ram.len == 0 or separate.ram.len > cap.max_shards) return error.V7MemoryResourceLimit;
    const geometry = try a.alloc(Geometry.Claim, separate.ram.len);
    defer a.free(geometry);
    const claims = try a.alloc(Closure.RamClaim, separate.ram.len);
    defer a.free(claims);
    for (separate.ram, geometry, claims, 0..) |ram, *g, *claim, index| {
        if (ram.input.index != index or !std.meta.eql(try ram.input.policy.digest(), try policy.digest())) return error.UntrustedV7MemoryPolicy;
        g.* = ram.input.geometry orelse return error.InvalidV7MemoryComponentGeometry;
        if (g.row_log > cap.max_row_log or g.total_events > cap.max_events or @as(u64, g.total_events) * 24 >= core.fields.m31.Modulus) return error.V7MemoryResourceLimit;
        try Memory.For(.ram).Profile.requireFixedRootWithLimit(Cpu, a, ram, cap.max_matrix_bytes);
        claim.* = .{ .geometry = g.*, .sums = ram.input.sums };
    }
    try Geometry.admitSequence(geometry, geometry[0].total_events);
    inline for (.{ @import("../recursion/air/block_v7_memory_composition_v1.zig").Family.interval, .range16, .terminal }) |kind| {
        const profile = @field(separate, @tagName(kind));
        if (!std.meta.eql(try profile.input.policy.digest(), try policy.digest()) or profile.input.index != 0) return error.UntrustedV7MemoryPolicy;
        try Memory.For(kind).Profile.requireFixedRootWithLimit(Cpu, a, profile, cap.max_matrix_bytes);
    }
    return Closure.close(.{ .ram = claims, .interval = separate.interval.input.sums, .range16 = separate.range16.input.sums, .terminal = separate.terminal.input.sums });
}

//! Complete original block algebra over independently admitted, root-authenticated
//! public values. No proof authority is granted here: a mixed root receiver must
//! first verify and bind EXACTLY this complete input roster to its public supply.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Global = @import("block_v5_global_receiver_v1.zig");
const Stack = @import("block_v5_native_receiver_stack_v1.zig").ForCapacity(false);
const Memory = @import("block_v5_word_memory_join_impl_v1.zig").ForStack(Stack);
const Source = @import("block_v6_source_public_closure_v1.zig");
const NativeBus = @import("../recursion/block_v6_partitioned_public_bus_v1.zig");
const NativeAdmission = @import("block_v6_partitioned_recursive_admission_v1.zig");
const Caller = @import("block_v6_caller_public_exports_v1.zig");
const Auxiliary = @import("../recursion/block_v6_auxiliary_direct_public_v1.zig");
const Providers = @import("../recursion/block_v6_provider_batch_public_v1.zig");
const Planning = @import("block_v5_native_lookup_plan_v1.zig");
const Bytes = @import("block_v5_memory_byte_demand_v1.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
const AlgebraModule = @import("block_v5_global_join_algebra_v1.zig");
const Algebra = AlgebraModule.Algebra(Q);
pub const Execution = struct { admitted: *const NativeAdmission.Prepared, public: NativeBus.Values };
pub const Extension = struct {
    admitted: *const @import("block_v5_caller_recursive_admission_pair_v1.zig").Pair,
    arithmetic: Auxiliary.Definition(.caller_arithmetic).Bus.Values,
    fused: Auxiliary.Definition(.caller_fused).Bus.Values,
};
pub const Input = struct {
    executions: []const Execution,
    callers: []const Extension,
    program: Providers.Definition(.program_table).Bus.Values,
    lookup: []const Providers.Definition(.native_lookup).Bus.Values,
    source: Source.Input,
};
pub const Limits = struct { max_executions: usize = 1 << 20, max_setup_bytes: usize = 512 << 20, source: @import("block_v5_memory_source_page_join_owner_v1.zig").Limits = .{} };
pub const AlgebraResult = struct {
    execution_count: u32,
    caller_count: u32,
    lookup_groups: u32,
    fetch_count: u64,
    memory_events: u64,
    seal: [32]u8,
    initial_root: [32]u8,
    final_root: [32]u8,
    pub const complete_block_authority = false;
};

pub fn close(backing: std.mem.Allocator, pins: Global.Pins, context: *const @import("block_v5_memory_source_unified_page_proof_v1.zig").Context, input: Input, limits: Limits) !AlgebraResult {
    if (pins.tables.seal.register_custody_mode != 1 or pins.memory.memory != .lanes or pins.memory.readonly != null or !std.mem.allEqual(u8, &pins.tables.seal.readonly_roster_digest, 0)) return error.UnsupportedV6GlobalPublicMode;
    const n = pins.tables.executions.len;
    if (n == 0 or n > limits.max_executions or input.executions.len != n or input.callers.len != pins.tables.extensions.len or input.lookup.len != pins.tables.providers.len or limits.max_setup_bytes == 0) return error.IncompleteV6GlobalPublicRoster;
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.createRetainingParent(backing, limits.max_setup_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    const sealed = try pins.validate();
    try Memory.admitPins(a, pins.memory, sealed);
    if (!std.meta.eql(context.base.digest, sealed.digest)) return error.UntrustedV6GlobalPublicSource;
    // PAGE validation reconstructs the original fixed columns under its own
    // explicit source budget. Charge it to our caller's receiver budget, not
    // this narrower budget for global accounting metadata. Both remain bounded
    // by the enclosing receiver's total live allocation limit.
    const source = try Source.close(backing, context, pins.memory.memory.lanes, input.source, limits.source);
    var channel = sealed.sharedChannel();
    const relations = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const requests = try a.alloc([Schema.KIND_COUNT]Q, n);
    defer a.free(requests);
    const demands = try a.alloc([Schema.KIND_COUNT]u64, n);
    defer a.free(demands);
    const states = try a.alloc(Q, n);
    defer a.free(states);
    const registers = try a.alloc(Q, n);
    defer a.free(registers);
    const BytePart = struct { sum: Q = Q.zero(), event_count: u64 = 0 };
    const byte_parts = try a.alloc(BytePart, n);
    defer a.free(byte_parts);
    @memset(byte_parts, .{});
    var sums: AlgebraModule.Accounting(Q) = .{ .native_open_sum = Q.zero(), .precompile_open_sum = Q.zero(), .public_program_boundary_sum = Q.zero(), .program_provider_sum = input.program.claim, .table_provider_sum = Q.zero(), .ordinary_memory_opposite = Q.zero(), .external_memory_opposite = Q.zero(), .auxiliary_clock_memory_sum = Q.zero(), .register_compensation_sum = Q.zero() };
    var transition = Q.zero();
    var program = input.program.claim;
    var fetches: u64 = 0;
    var next_extension: usize = 0;
    for (input.executions, pins.tables.executions, 0..) |entry, pin, index| {
        const admitted = entry.admitted;
        try admitted.validate(admitted.template_id);
        if (admitted.native.index != index or !std.meta.eql(admitted.native.sealed.digest, sealed.digest) or !std.meta.eql(admitted.native.pin.expected_id, pin.admission.expected_id) or !std.meta.eql(admitted.native.expected_id, pin.template_id) or !std.meta.eql(admitted.native.template, pin.template) or !std.meta.eql(admitted.native.shape.*, pin.shape.*) or admitted.memory.expected_events != pins.tables.ordinary_events[index] or !std.meta.eql(admitted.witness_root, pins.memory.opcode_witness_roots[index])) return error.UntrustedV6GlobalPublicExecution;
        var open = try NativeBus.exportsFromValues(a, admitted, entry.public);
        defer open.deinit(a);
        const contribution = try @import("block_v6_partitioned_accounting_v1.zig").extract(a, admitted, &open, pins.tables.register_windows);
        requests[index] = contribution.table_requests;
        states[index] = contribution.state_residual;
        registers[index] = contribution.register_residual;
        sums.native_open_sum = sums.native_open_sum.add(contribution.native_open_sum);
        sums.ordinary_memory_opposite = sums.ordinary_memory_opposite.add(contribution.ordinary_memory_opposite);
        sums.auxiliary_clock_memory_sum = sums.auxiliary_clock_memory_sum.add(contribution.auxiliary_clock_memory);
        sums.register_compensation_sum = sums.register_compensation_sum.add(contribution.register_compensation);
        transition = transition.add(contribution.ordinary_transition);
        const projection = open.companion.projections orelse return error.MissingV6GlobalPublicProjection;
        const boundary = try @import("block_v5_program_boundary_v1.zig").deriveFromPinnedNativePublic(pin.profile, &pin.shape.public_data, &relations);
        program = program.add(contribution.program_request).add(boundary.sum);
        sums.public_program_boundary_sum = sums.public_program_boundary_sum.add(boundary.sum);
        fetches = try std.math.add(u64, fetches, try std.math.add(u64, projection.fetch_count, boundary.fetch_count));
        const demand = try Bytes.opcodeDemandFromShapeForMode(a, pin.shape, admitted.frame, contribution.ordinary_events, 1);
        if (open.companion.memory) |memory| byte_parts[index].sum = try Bytes.freshRequests(memory, demand, sealed.digest) else if (demand.event_count != 0) return error.MissingV6GlobalPublicMemory;
        byte_parts[index].event_count = demand.event_count;
        var expected_external: u32 = 0;
        if (next_extension < pins.tables.extensions.len and pins.tables.extensions[next_extension].execution_index == index) {
            expected_external = @import("blake3_ethereum_sha_profile.zig").externalCount(pins.tables.extensions[next_extension].statement);
            next_extension += 1;
        }
        if (Stack.Programs.externalRetirements(pin) != expected_external) return error.UntrustedV6GlobalPublicCallerCensus;
        demands[index] = try Planning.nativeDemand(pin.shape, expected_external);
    }
    for (input.callers, pins.tables.extensions, pins.memory.extensions) |entry, pin, memory_pin| {
        try entry.admitted.require();
        const admitted = &entry.admitted.fused;
        const index = pin.execution_index;
        if (index >= n or admitted.binding.execution_index != index or !std.meta.eql(admitted.sealed.digest, sealed.digest) or !std.meta.eql(admitted.statement, pin.statement.*) or admitted.total_steps != pin.total_steps or !std.meta.eql(admitted.binding.caller_key_id, pin.expected_key_id) or !std.meta.eql(admitted.binding.execution_instance_id, input.executions[index].admitted.binding.instance_id) or !std.meta.eql(admitted.witness_root, memory_pin.witness_root) or !std.meta.eql(admitted.frame, input.executions[index].admitted.frame)) return error.UntrustedV6GlobalPublicCaller;
        const arithmetic = try Caller.arithmetic(&entry.admitted.arithmetic, entry.arithmetic);
        var fused = try Caller.fused(a, admitted, entry.fused);
        defer fused.deinit(a);
        if (!std.meta.eql(arithmetic.binding, fused.state.binding) or fused.state.caller_count != Stack.Programs.externalRetirements(pins.tables.executions[index]) or fused.tables.memory_event_count != try @import("block_execution_external_trace_v2.zig").expectedEventCount(pin.statement)) return error.UntrustedV6GlobalPublicCallerCensus;
        states[index] = states[index].add(fused.state.sum);
        registers[index] = registers[index].add(fused.tables.register_memory_sum);
        for (&requests[index], fused.tables.claims) |*sum, value| sum.* = sum.add(value);
        sums.precompile_open_sum = sums.precompile_open_sum.add(arithmetic.open_sum);
        sums.auxiliary_clock_memory_sum = sums.auxiliary_clock_memory_sum.add(fused.tables.auxiliary_clock_memory_sum);
        sums.external_memory_opposite = sums.external_memory_opposite.add(fused.memory.universal_sum);
        transition = transition.add(fused.memory.transition_sum);
        program = program.add(fused.program.sum);
        fetches = try std.math.add(u64, fetches, fused.program.fetch_count);
        const demand = try Bytes.externalDemandForMode(pin.statement, admitted.schedule.memory, 1);
        byte_parts[index].sum = byte_parts[index].sum.add(try Bytes.freshRequests(fused.memory, demand, sealed.digest));
        byte_parts[index].event_count = try std.math.add(u64, byte_parts[index].event_count, demand.event_count);
        try @import("block_v5_precompile_table_demand_v1.zig").add(a, &demands[index], pin.statement, pin.total_steps, pins.tables.seal.config);
    }
    var sink = AlgebraModule.ScalarSink{};
    try Algebra.states(&sink, states);
    try Algebra.registers(&sink, 1, registers);
    var events: u64 = 0;
    for (demands, byte_parts) |*demand, bytes| {
        try Planning.addDemand(demand, try Planning.sidecarMemoryDemand(bytes.event_count));
        events = try std.math.add(u64, events, bytes.event_count);
    }
    if (events != source.events) return error.UnclosedV6GlobalPublicMemoryCensus;
    try Algebra.transition(&sink, transition, source.transition_sum);
    const plans = try a.alloc(Planning.Plan, input.lookup.len);
    defer a.free(plans);
    for (plans, pins.tables.providers) |*plan, record| plan.* = record.plan;
    try Planning.validateDemandRoster(plans, demands);
    for (input.lookup, pins.tables.providers) |value, record| {
        try value.validate();
        if (!std.meta.eql(value.plan, record.plan) or !std.meta.eql(value.roots, record.roots) or !std.meta.eql(value.sealed, sealed.digest) or !std.meta.eql(value.template, @import("block_v5_native_lookup_recursive_admission_v1.zig").templateId(pins.tables.seal.config, record.roots[0]))) return error.UntrustedV6GlobalPublicLookup;
        try @import("block_v5_native_lookup_proof_v1.zig").admit(record.plan, record.roots, sealed, pins.tables.seal, pins.tables.roster);
        const start = record.plan.first_execution;
        const end = start + record.plan.execution_count;
        const totals = try Algebra.lookupGroup(&sink, value.claims, requests[start..end], byte_parts[start..end]);
        sums.table_provider_sum = sums.table_provider_sum.add(totals.provider_sum);
    }
    const rom = input.program;
    try rom.validate();
    if (!std.meta.eql(rom.template, @import("block_v5_program_table_recursive_admission_v1.zig").templateId(pins.program.log_size, pins.tables.seal.config)) or !std.meta.eql(rom.sealed, sealed.digest) or !std.meta.eql(rom.native_roster, sealed.native_roster_digest) or !std.meta.eql(rom.plan, try pins.program.digest()) or !std.meta.eql(rom.program_root, pins.program.program_root.bytes) or !std.meta.eql(rom.roots, sealed.program_first_roots) or rom.log_size != pins.program.log_size or rom.fetch_count != pins.program.expected_fetches or fetches != rom.fetch_count) return error.UntrustedV6GlobalPublicProgram;
    try sink.zero(program, error.UnclosedProgramRelation);
    try Algebra.accounting(&sink, sums, byte_parts);
    return .{ .execution_count = @intCast(n), .caller_count = @intCast(input.callers.len), .lookup_groups = @intCast(input.lookup.len), .fetch_count = fetches, .memory_events = events, .seal = sealed.digest, .initial_root = source.initial_root, .final_root = source.final_root };
}

test "global public closure rejects mode0 before reading any claimed proof authority" {
    var pins: Global.Pins = undefined;
    pins.tables.seal.register_custody_mode = 0;
    try std.testing.expectError(error.UnsupportedV6GlobalPublicMode, close(std.testing.allocator, pins, undefined, undefined, .{}));
}

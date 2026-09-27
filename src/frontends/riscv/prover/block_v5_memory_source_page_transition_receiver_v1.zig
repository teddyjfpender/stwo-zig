//! Authentic capacity-native/caller transition consumer for the PAGE source
//! join. It accepts original proofs only: PAGE Owner.verify is called inside
//! this fresh loop, followed by original Programs composite receivers/hooks.
//! Byte/provider/register/state/accounting/public/source recursion stays OPEN.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Stack = @import("block_v5_native_receiver_stack_v1.zig").ForCapacity(true);
const Global = @import("block_v5_capacity_global_receiver_v1.zig");
const Memory = @import("block_v5_word_memory_join_impl_v1.zig").ForStack(Stack);
const Engine = Memory.ForBackend(Cpu);
const Programs = Stack.Programs;
const Native = Stack.Native;
const Fused = Stack.Fused;
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const CallerFused = @import("block_v5_caller_fused_proof_v1.zig");
const ProgramProof = @import("block_v5_program_table_proof_v1.zig");
const External = @import("block_execution_external_trace_v2.zig");
const Page = @import("block_v5_memory_source_page_join_owner_v1.zig");
const Admission = @import("block_v5_memory_source_page_transition_admission_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const Limits = struct { max_executions: usize = 8192, max_live_bytes: usize = 4 << 30 };
pub const Loader = struct {
    context: *anyopaque,
    /// Original decoded proof allocations use the supplied bounded allocator.
    /// Success transfers ownership; errors retain no allocations.
    native: *const fn (*anyopaque, std.mem.Allocator, u32) anyerror!Native.Proof,
    fused: ?*const fn (*anyopaque, std.mem.Allocator, u32) anyerror!Fused.Proof = null,
    caller: ?*const fn (*anyopaque, std.mem.Allocator, u32) anyerror!Family.Proof = null,
    caller_fused: ?*const fn (*anyopaque, std.mem.Allocator, u32) anyerror!CallerFused.Proof = null,
    program: *const fn (*anyopaque, std.mem.Allocator) anyerror!ProgramProof.Proof,
};
pub const Open = struct {
    allocation_owner: *Budget,
    source: Page.Open,
    programs: Programs.ScopedPrograms,
    bytes: []Memory.ExecutionBytes,
    ordinary_memory_opposite: Q,
    external_memory_opposite: Q,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Open) void {
        const owner = self.allocation_owner;
        owner.allocator().free(self.bytes);
        self.* = undefined;
        owner.destroy();
    }
};
/// Independent Global.Pins and PAGE Owner must be reconstructed in this
/// process. No proposed Page.Open, accepted-receipt array or setup manifest
/// enters this API. Original borrowed source/admission owners outlive this call.
pub fn verify(backing: std.mem.Allocator, pins: Global.Pins, page: *Page.Owner, page_loader: Page.Loader, loader: Loader, limits: Limits) !Open {
    if (limits.max_live_bytes == 0 or limits.max_executions == 0 or pins.memory.executions.len > limits.max_executions)
        return error.SourcePageTransitionResourceLimit;
    const budget = try Budget.createRetainingParent(backing, limits.max_live_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    const sealed = try pins.validate();
    const sorted = switch (pins.memory.memory) {
        .lanes => |value| value,
        .word => return error.NoncanonicalSourcePageTransitionMemory,
    };
    try Admission.sameMemory(sorted, page.memory);
    if (!std.meta.eql(sealed, page.context.base)) return error.UntrustedSourcePageTransitionSeal;
    try Memory.admitPins(a, pins.memory, sealed);
    const demand_count = try Admission.eventCensus(pins.memory, sealed.register_custody_mode);
    if (demand_count != sorted.expected_total_events) return error.UntrustedSourcePageTransitionCensus;
    const memory_pins = try a.alloc(Stack.FusedReceiver.MemoryPin, pins.memory.executions.len);
    defer a.free(memory_pins);
    for (pins.memory.executions, memory_pins, 0..) |pin, *memory_pin, index| memory_pin.* = .{
        .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = pin.admission.context.first_cycle, .cycle_count = pin.shape.public_data.clock },
        .expected_events = pins.memory.ordinary_events[index],
        .witness_root = pins.memory.opcode_witness_roots[index],
    };
    const caller_memory = try a.alloc(Programs.CallerMemoryPin, pins.memory.extensions.len);
    defer a.free(caller_memory);
    for (pins.memory.extensions, caller_memory) |pin, *memory_pin| memory_pin.* = .{
        .frame = memory_pins[pin.public.execution_index].frame,
        .witness_root = pin.witness_root,
        .expected_rw_events = try External.expectedEventCountForMode(pin.public.statement, sealed.register_custody_mode),
    };
    var bridge = ProofLoader{ .a = a, .loader = loader };
    const original = bridge.original();
    // This is original metadata admission, never proof authority. Reject
    // mismatched access/caller/program rosters before consuming a PAGE proof.
    try Programs.ForBackend(Cpu).admitRoster(a, pins.tables.seal, pins.tables.roster, sealed, pins.tables.catalog, pins.program, pins.tables.executions, pins.tables.extensions, memory_pins, caller_memory, original);
    const fresh = try page.verify(a, page_loader);
    try Admission.requireSource(fresh, sorted, sealed);
    const parts = try a.alloc(Memory.ExecutionBytes, pins.memory.executions.len);
    for (parts, 0..) |*part, index| part.* = .{ .index = @intCast(index), .event_count = 0, .request_count = 0, .max_requests = 0, .sum = Q.zero() };
    // This INTERNAL semantic conversion is justified by the actual PAGE/lane/
    // range proof path immediately above. It creates no legacy proof artifact
    // or virtual log; the public output preserves the distinct PAGE result.
    var engine = Engine{
        .a = a,
        .pins = pins.memory,
        .sealed = sealed,
        .loader = .{ .context = &bridge },
        .fresh_memory = .{ .transition_sum = fresh.transition_sum, .register_endpoints_verified = false, .register_endpoint_count = 0, .event_count = fresh.events, .first_touch_count = fresh.first_touches, .endpoint_count = fresh.endpoints, .range_count = fresh.range_requests, .memory_instances = fresh.memory_instances, .range_shards = fresh.range_shards, .initial_rw_root = fresh.initial_root, .final_rw_root = fresh.final_root, .sealed_digest = fresh.base_seal, .memory_plan_digest = fresh.memory_plan },
        .byte_parts = parts,
    };
    defer engine.deinit();
    var hooks = Hooks{ .engine = &engine };
    const programs = try Programs.ForBackend(Cpu).verifyWithCompositeHooks(a, pins.tables.seal, pins.tables.roster, sealed, pins.tables.catalog, pins.program, pins.tables.executions, pins.tables.extensions, memory_pins, caller_memory, original, .{
        .context = &hooks,
        .on_fused = Hooks.native,
        .on_fused_caller = Hooks.caller,
    });
    const closed = try engine.finish();
    return .{ .allocation_owner = budget, .source = fresh, .programs = programs, .bytes = closed.bytes, .ordinary_memory_opposite = closed.ordinary_memory_opposite, .external_memory_opposite = closed.external_memory_opposite };
}
const Hooks = struct {
    engine: *Engine,
    fn native(raw: *anyopaque, _: std.mem.Allocator, index: u32, pin: Programs.InstancePin, fresh: *const Native.OpenReceipt, fused: *const Fused.Verified) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        try self.engine.onFusedNative(index, pin, fresh, if (fused.memory) |*memory| memory else null);
    }
    fn caller(raw: *anyopaque, _: std.mem.Allocator, index: u32, pin: Programs.ExtensionPin, fresh: *const Family.OpenReceipt, fused: *const CallerFused.Verified) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        try self.engine.onFusedPrecompile(index, pin, fresh, &fused.memory);
    }
};
const ProofLoader = struct {
    a: std.mem.Allocator,
    loader: Loader,
    fn original(self: *@This()) Programs.Loader {
        return .{ .context = self, .take_native = native, .take_fused = if (self.loader.fused != null) fused else null, .take_table = program, .take_precompile = if (self.loader.caller != null) caller else null, .take_caller_fused = if (self.loader.caller_fused != null) callerFused else null };
    }
    fn from(raw: *anyopaque) *@This() {
        return @ptrCast(@alignCast(raw));
    }
    fn native(raw: *anyopaque, index: u32) !Native.Proof {
        const self = from(raw);
        return self.loader.native(self.loader.context, self.a, index);
    }
    fn fused(raw: *anyopaque, index: u32) !Fused.Proof {
        const self = from(raw);
        return (self.loader.fused orelse return error.MissingSourcePageTransitionFused)(self.loader.context, self.a, index);
    }
    fn caller(raw: *anyopaque, index: u32) !Family.Proof {
        const self = from(raw);
        return (self.loader.caller orelse return error.MissingSourcePageTransitionCaller)(self.loader.context, self.a, index);
    }
    fn callerFused(raw: *anyopaque, index: u32) !CallerFused.Proof {
        const self = from(raw);
        return (self.loader.caller_fused orelse return error.MissingSourcePageTransitionCaller)(self.loader.context, self.a, index);
    }
    fn program(raw: *anyopaque) !ProgramProof.Proof {
        const self = from(raw);
        return self.loader.program(self.loader.context, self.a);
    }
};
pub const testing = struct {
    pub const requireMemory = Admission.sameMemory;
    pub const requireSourceIdentity = Admission.requireSource;
    pub const exactEventCensus = Admission.eventCensus;
};

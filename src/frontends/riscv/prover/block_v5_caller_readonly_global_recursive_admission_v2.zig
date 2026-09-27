//! Independent original caller B5IC geometry. The caller binding is a link
//! proposal; a separate arithmetic recursive child must authenticate it.
const std = @import("std");
const core = @import("stwo_core");
pub const Fused = @import("block_v5_caller_readonly_global_proof_v2.zig");
pub const Receiver = @import("block_v5_caller_readonly_global_receiver_v2.zig");
pub const Profile = @import("blake3_ethereum_sha_profile.zig");
pub const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const ScheduleModule = @import("block_v5_caller_fused_schedule_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub const VERSION: u32 = 2;
pub const Limits = struct {
    max_capture_bytes: usize = 512 << 20,
    max_preparation_bytes: usize = 4 << 30,
    max_columns: usize = 32768,
    max_samples: usize = 131072,
    max_public_claims: usize = 32768,
    max_public_wires: usize = 1 << 20,
};
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    statement: Profile.admission.Statement,
    total_steps: u32,
    binding: Protocol.CallerBinding,
    frame: @import("../air/block/memory_event.zig").Frame,
    witness_root: [32]u8,
    expected_rw_events: u64,
    sealed: Seal.Sealed,
    pins: Seal.Pins,
    entries: []const Seal.Entry,
    config: core.pcs.PcsConfig,
    schedule: ScheduleModule.Schedule,
    readonly: Fused.Authority,
    plan: @import("block_v5_readonly_input_global_roster_v2.zig").BorrowedPlan,
    logs: [4][]u32,
    template_id: [32]u8,
    custody: [32]u8,
    limits: Limits,
    pub fn init(a: std.mem.Allocator, index: u32, source_pin: Receiver.Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Limits) !Prepared {
        try Receiver.admit(a, index, source_pin, sealed, pins, entries);
        if (limits.max_capture_bytes == 0 or limits.max_preparation_bytes == 0 or limits.max_samples == 0) return error.CallerReadonlyRecursiveResourceLimit;
        var schedule = try ScheduleModule.Schedule.init(a, source_pin.statement, source_pin.total_steps, source_pin.frame, sealed.register_custody_mode);
        errdefer schedule.deinit();
        var plan = try source_pin.readonly.admit(a);
        errdefer plan.deinit();
        const witness = try Fused.witnessLogs(a, &schedule);
        errdefer a.free(witness);
        const interaction = try Fused.interactionLogs(a, &schedule);
        errdefer a.free(interaction);
        const logs = [4][]u32{ schedule.fixed, schedule.main, witness, interaction };
        for (logs) |tree| if (tree.len > limits.max_columns) return error.CallerReadonlyRecursiveResourceLimit;
        const n_public = try @import("../recursion/air/block_v5_caller_readonly_global_composition_v2.zig").publicCount(schedule.program.len, schedule.tables.len, schedule.memory.len);
        if (n_public > limits.max_public_claims) return error.CallerReadonlyRecursiveResourceLimit;
        var result = Prepared{ .allocator = a, .statement = source_pin.statement.*, .total_steps = source_pin.total_steps, .binding = Receiver.binding(index, source_pin, sealed), .frame = source_pin.frame, .witness_root = source_pin.witness_root, .expected_rw_events = source_pin.expected_rw_events, .sealed = sealed, .pins = pins, .entries = entries, .config = pins.config, .schedule = schedule, .readonly = source_pin.readonly, .plan = plan, .logs = logs, .template_id = undefined, .custody = undefined, .limits = limits };
        result.template_id = result.templateId();
        result.custody = result.identity();
        return result;
    }
    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.logs[2]);
        self.allocator.free(self.logs[3]);
        self.plan.deinit();
        self.schedule.deinit();
        self.* = undefined;
    }
    pub fn pin(self: *const Prepared) Receiver.Pin {
        return .{ .statement = &self.statement, .total_steps = self.total_steps, .execution_instance_id = self.binding.execution_instance_id, .expected_key_id = self.binding.caller_key_id, .expected_caller_instance_id = self.binding.caller_instance_id, .roots = self.binding.first_roots, .witness_root = self.witness_root, .frame = self.frame, .expected_rw_events = self.expected_rw_events, .readonly = self.readonly };
    }
    pub fn templateId(self: *const Prepared) [32]u8 {
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42354a58, VERSION, Fused.TAG, Fused.VERSION, @intFromEnum(Protocol.circuit_profile), self.schedule.split, self.sealed.register_custody_mode });
        channel.mixRoot(self.binding.caller_key_id);
        // Genuine roster epoch and compact source group are independent public
        // policy. Separate grouped providers and native/global joins remain OPEN.
        channel.mixRoot(self.readonly.roster.epoch().roster_digest);
        channel.mixU32s(&.{ self.readonly.ordinal, self.readonly.group_id });
        channel.mixRoot(self.readonly.source_identity);
        channel.mixU64(self.readonly.census.all_rw);
        channel.mixU64(self.readonly.census.readonly);
        channel.mixU64(self.readonly.census.mutable);
        channel.mixRoot(self.readonly.selection.expected_digest);
        channel.mixRoot(self.readonly.plan.expected_digest);
        channel.mixRoot(self.plan.digest);
        inline for (@typeInfo(@TypeOf(self.readonly.limits)).@"struct".fields) |field| channel.mixU64(@field(self.readonly.limits, field.name));
        self.config.mixInto(&channel);
        // The original caller key pins its fixed geometry and active selectors.
        // Dynamic execution/frame/root values remain public, never setup data.
        for (self.logs) |logs| {
            channel.mixU32s(&.{@intCast(logs.len)});
            channel.mixU32s(logs);
        }
        for (self.schedule.program) |slot| channel.mixU32s(&.{ @intFromEnum(slot.kind), slot.log_size, slot.active_calls, slot.x0_local_custody_version, @intCast(slot.main_offset), @intCast(slot.main_columns), if (slot.fixed_selector_offset) |offset| @intCast(offset) else std.math.maxInt(u32) });
        for (self.schedule.tables) |slot| @import("block_v5_precompile_lookup_algebra_v1.zig").mixSlot(&channel, slot);
        for (self.schedule.memory) |slot| channel.mixU32s(&.{ @intFromEnum(slot.kind), @intCast(slot.slot), slot.log_size, @intCast(slot.fixed_offset), @intCast(slot.main_offset) });
        for (self.schedule.masks.fixed) |open| channel.mixU32s(&.{@intFromBool(open)});
        for (self.schedule.masks.main) |open| channel.mixU32s(&.{@intFromBool(open)});
        channel.mixU64(self.schedule.masks.state_offset orelse std.math.maxInt(usize));
        return channel.digestBytes();
    }
    pub fn identity(self: *const Prepared) [32]u8 {
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixRoot(self.templateId());
        @import("block_v5_precompile_family_proof_v1.zig").mixBinding(&channel, self.binding);
        channel.mixRoot(self.sealed.digest);
        channel.mixRoot(self.witness_root);
        channel.mixU32s(&.{ self.total_steps, @intFromEnum(self.frame.clock_frame), self.frame.cycle_count });
        channel.mixU64(self.frame.global_first_cycle);
        channel.mixU64(self.expected_rw_events);
        ScheduleModule.mix(&channel, &self.schedule);
        return channel.digestBytes();
    }
    pub fn validate(self: *const Prepared, expected: [32]u8) !void {
        if (!std.meta.eql(expected, self.template_id) or !std.meta.eql(self.templateId(), expected) or !std.meta.eql(self.custody, self.identity()) or !std.meta.eql(self.config, self.pins.config)) return error.UntrustedCallerReadonlyRecursiveAdmission;
        try Receiver.admit(self.allocator, self.binding.execution_index, self.pin(), self.sealed, self.pins, self.entries);
        // Reconstruct every offset, mask and schedule. A mutable checksum is not
        // independent authority for a received or host-mutated layout.
        var independently = try Prepared.init(self.allocator, self.binding.execution_index, self.pin(), self.sealed, self.pins, self.entries, self.limits);
        defer independently.deinit();
        if (self.plan.intervals.ptr != independently.plan.intervals.ptr or self.plan.intervals.len != independently.plan.intervals.len or !std.meta.eql(self.plan.digest, independently.plan.digest)) return error.UntrustedCallerReadonlyRecursiveGeometry;
        for (self.logs, independently.logs) |actual, normative| if (!std.mem.eql(u32, actual, normative)) return error.UntrustedCallerReadonlyRecursiveGeometry;
        if (!std.meta.eql(independently.template_id, expected) or !std.meta.eql(independently.custody, self.custody)) return error.UntrustedCallerReadonlyRecursiveGeometry;
    }
};

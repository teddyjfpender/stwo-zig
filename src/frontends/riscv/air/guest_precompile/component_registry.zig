//! Profile-scoped component authority for the Poseidon2 guest extension.
//!
//! The base 28-component enum remains closed. This module appends two typed
//! construction authorities only after the extension profile has been
//! admitted. All row-facing metadata is numeric and fixed-size.

const std = @import("std");
const base_claims = @import("../transcript/claims.zig");
const base_relation = @import("../lang/relation.zig");
const poseidon_identity = @import("../lang/typed_poseidon2_identity_golden.zig");
const types = @import("../lang/types.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const relation_registry = @import("relation_registry.zig");

pub const ExecutionProfile = execution_profile.ExecutionProfile;
pub const Role = base_relation.Role;
pub const Digest = [32]u8;

pub const base_component_count: usize = base_claims.COMPONENT_COUNT;
pub const extension_component_count: usize = 2;
pub const component_count: usize = base_component_count + extension_component_count;
pub const preprocessed_columns: u16 = 2;
pub const minimum_log_size: u32 = 4;
pub const guest_opcode_id: u16 = 46;
pub const provider_main_columns: u16 = 445;

pub const Slot = enum(u16) {
    caller = 28,
    provider = 29,
    _,
};

pub const Kind = enum(u32) {
    guest_poseidon2_call_v1 = 0x4750_4331,
    guest_poseidon2_provider_compat_v1 = 0x4750_5031,
    _,
};

pub const ActivePrefixPolicy = enum(u32) {
    contiguous_zero_padded_v1 = 0x4150_4631,
    _,
};

pub const caller_name = "stwo.riscv.guest_poseidon2_call.v1";
pub const provider_name = "stwo.riscv.guest_poseidon2_provider.compat-v1";
pub const component_version: u16 = 1;
pub const active_prefix_policy = ActivePrefixPolicy.contiguous_zero_padded_v1;

pub const CallerLayout = struct {
    enabler: u16,
    execution_clock: u16,
    pc: u16,
    pointer_register: u16,
    pointer_previous_clock: u16,
    pointer_bytes: u16,
    pointer_word_index: u16,
    span_end_limbs: u16,
    input_bytes: u16,
    output_bytes: u16,
    memory_previous_clocks: u16,
    canonical_materializations: u16,
    main_columns: u16,

    pub fn validate(self: CallerLayout) Error!void {
        if (!std.meta.eql(self, caller_layout)) return error.CallerLayoutMismatch;
    }

    pub fn inputByte(self: CallerLayout, lane: u8, byte: u8) u16 {
        std.debug.assert(lane < 16 and byte < 4);
        return self.input_bytes + @as(u16, lane) * 4 + byte;
    }

    pub fn outputByte(self: CallerLayout, lane: u8, byte: u8) u16 {
        std.debug.assert(lane < 16 and byte < 4);
        return self.output_bytes + @as(u16, lane) * 4 + byte;
    }

    pub fn previousClock(self: CallerLayout, lane: u8) u16 {
        std.debug.assert(lane < 16);
        return self.memory_previous_clocks + lane;
    }

    pub fn canonicalMaterialization(
        self: CallerLayout,
        output: bool,
        lane: u8,
        value: u8,
    ) u16 {
        std.debug.assert(lane < 16 and value < 4);
        const word: u16 = @as(u16, @intFromBool(output)) * 16 + lane;
        return self.canonical_materializations + 4 * word + value;
    }
};

pub const caller_layout = CallerLayout{
    .enabler = 0,
    .execution_clock = 1,
    .pc = 2,
    .pointer_register = 3,
    .pointer_previous_clock = 4,
    .pointer_bytes = 5,
    .pointer_word_index = 9,
    .span_end_limbs = 10,
    .input_bytes = 14,
    .output_bytes = 78,
    .memory_previous_clocks = 142,
    .canonical_materializations = 158,
    .main_columns = 286,
};

pub const CallerConstraintIdentity = struct {
    policy_id: u32,
    version: u16,
    maximum_constraint_degree: u8,
    lanes: u8,
    word_bytes: u8,
    address_bits: u8,
    span_words: u8,
    canonical_words: u8,
    canonical_materializations_per_word: u8,
    clock_stride: u8,
    pointer_access_ordinal: u8,
    lane_access_ordinal: u8,
    opcode_id: u16,

    pub fn canonical() CallerConstraintIdentity {
        return .{
            .policy_id = 0x4750_4350,
            .version = 1,
            .maximum_constraint_degree = 3,
            .lanes = 16,
            .word_bytes = 4,
            .address_bits = 30,
            .span_words = 16,
            .canonical_words = 32,
            .canonical_materializations_per_word = 4,
            .clock_stride = 4,
            .pointer_access_ordinal = 1,
            .lane_access_ordinal = 2,
            .opcode_id = guest_opcode_id,
        };
    }

    pub fn validate(self: CallerConstraintIdentity) Error!void {
        if (!std.meta.eql(self, CallerConstraintIdentity.canonical()))
            return error.CallerConstraintIdentityMismatch;
    }
};

pub const Projection = enum(u8) {
    program,
    state_before,
    state_after,
    pointer_consume,
    pointer_emit,
    pointer_clock_gap,
    lane_consume,
    lane_emit,
    lane_clock_gap,
    input_byte_pair,
    input_high_limb,
    output_byte_pair,
    output_high_limb,
    pointer_span_low,
    pointer_span_high,
    guest_input_output,
    provider_input,
    provider_narrow_output,
    provider_wide_output,
    provider_input_output,
};

pub const Numerator = enum(u8) {
    negative_active,
    positive_active,
    zero_in_guest_mode,
};

pub const no_index: u8 = std.math.maxInt(u8);

pub const EventPlan = struct {
    ordinal: u8,
    schema: types.RelationSchemaId,
    schema_version: u16,
    arity: u8,
    role: Role,
    access_ordinal: ?u8,
    projection: Projection,
    index: u8,
    part: u8,
    numerator: Numerator,
};

pub const BatchPlan = struct {
    ordinal: u8,
    first_event: u8,
    second_event: ?u8,
    interaction_column_start: u16,
};

pub const caller_event_count: usize = 153;
pub const caller_batch_count: usize = 77;
pub const caller_interaction_columns: u16 = 308;
pub const provider_event_count: usize = 4;
pub const provider_batch_count: usize = 2;
pub const provider_interaction_columns: u16 = 8;

pub const FixedTableDemand = [6]u16;
pub const caller_fixed_table_demand = FixedTableDemand{
    0, // bitwise
    17, // range_check_20
    0, // range_check_8_11
    1, // range_check_8_8_4
    65, // range_check_8_8
    32, // range_check_m31
};

pub const caller_events = buildCallerEvents();
pub const caller_batches = buildBatches(caller_event_count);
pub const provider_events = buildProviderEvents();
pub const provider_batches = buildBatches(provider_event_count);

pub const StaticIdentity = struct {
    slot: Slot,
    kind: Kind,
    name: []const u8,
    version: u16,
    preprocessed_columns: u16,
    main_columns: u16,
    interaction_columns: u16,
    events: u16,
    batches: u16,
};

pub const caller_identity = StaticIdentity{
    .slot = .caller,
    .kind = .guest_poseidon2_call_v1,
    .name = caller_name,
    .version = component_version,
    .preprocessed_columns = preprocessed_columns,
    .main_columns = caller_layout.main_columns,
    .interaction_columns = caller_interaction_columns,
    .events = caller_event_count,
    .batches = caller_batch_count,
};

pub const provider_identity = StaticIdentity{
    .slot = .provider,
    .kind = .guest_poseidon2_provider_compat_v1,
    .name = provider_name,
    .version = component_version,
    .preprocessed_columns = preprocessed_columns,
    .main_columns = provider_main_columns,
    .interaction_columns = provider_interaction_columns,
    .events = provider_event_count,
    .batches = provider_batch_count,
};

pub const Descriptor = struct {
    slot: Slot,
    kind: Kind,
    version: u16,
    n_rows: u32,
    log_size: u32,
    preprocessed_columns: u16,
    main_columns: u16,
    interaction_columns: u16,

    pub fn canonical(kind: Kind, n_rows: u32) Error!Descriptor {
        const identity = identityForKind(kind) orelse return error.UnknownComponent;
        return .{
            .slot = identity.slot,
            .kind = identity.kind,
            .version = identity.version,
            .n_rows = n_rows,
            .log_size = canonicalLogSize(n_rows),
            .preprocessed_columns = identity.preprocessed_columns,
            .main_columns = identity.main_columns,
            .interaction_columns = identity.interaction_columns,
        };
    }

    pub fn validate(self: Descriptor) Error!void {
        const expected = try Descriptor.canonical(self.kind, self.n_rows);
        if (self.slot != expected.slot) return error.ComponentSlotMismatch;
        if (self.version != expected.version) return error.ComponentVersionMismatch;
        if (self.log_size != expected.log_size) return error.ComponentLogSizeMismatch;
        if (self.preprocessed_columns != expected.preprocessed_columns or
            self.main_columns != expected.main_columns or
            self.interaction_columns != expected.interaction_columns)
        {
            return error.ComponentGeometryMismatch;
        }
    }
};

pub const CallerConstruction = struct {
    descriptor: Descriptor,
    constraint_identity: CallerConstraintIdentity,
    layout: *const CallerLayout,
    events: *const [caller_event_count]EventPlan,
    batches: *const [caller_batch_count]BatchPlan,
    fixed_table_demand: *const FixedTableDemand,

    pub fn validate(self: CallerConstruction) Error!void {
        try self.descriptor.validate();
        try self.constraint_identity.validate();
        if (self.descriptor.kind != .guest_poseidon2_call_v1 or
            !std.meta.eql(self.layout.*, caller_layout) or
            !std.meta.eql(self.events.*, caller_events) or
            !std.meta.eql(self.batches.*, caller_batches) or
            !std.meta.eql(self.fixed_table_demand.*, caller_fixed_table_demand))
        {
            return error.ConstructionAuthorityMismatch;
        }
    }
};

/// Thin authenticated reference to the reviewed compatibility-v1 placement.
/// The golden layout digest seals the complete 445-column mapping; retaining
/// this numeric header avoids importing the heavyweight prover implementation
/// into profile admission and verifier dispatch.
pub const ProviderCompatibilityIdentity = struct {
    format_version: u16,
    policy_id: u32,
    policy_version: u16,
    maximum_constraint_degree: u8,
    width: u16,
    materializations: u16,
    main_columns: u16,

    pub fn canonical() ProviderCompatibilityIdentity {
        return .{
            .format_version = 1,
            .policy_id = 0x5032_4331,
            .policy_version = 1,
            .maximum_constraint_degree = 3,
            .width = 16,
            .materializations = 426,
            .main_columns = provider_main_columns,
        };
    }

    pub fn validate(self: ProviderCompatibilityIdentity) Error!void {
        if (!std.meta.eql(self, ProviderCompatibilityIdentity.canonical()))
            return error.ProviderCompatibilityMismatch;
    }
};

pub const ProviderConstruction = struct {
    descriptor: Descriptor,
    compatibility_identity: ProviderCompatibilityIdentity,
    compatibility_layout_digest: Digest,
    enabled_mode: u8,
    io_mode: u8,
    wide_mode: u8,
    events: *const [provider_event_count]EventPlan,
    batches: *const [provider_batch_count]BatchPlan,

    pub fn validate(self: ProviderConstruction) Error!void {
        try self.descriptor.validate();
        try self.compatibility_identity.validate();
        if (self.descriptor.kind != .guest_poseidon2_provider_compat_v1 or
            !std.mem.eql(
                u8,
                &self.compatibility_layout_digest,
                &poseidon_identity.layout,
            ) or
            self.enabled_mode != 1 or self.io_mode != 1 or self.wide_mode != 0 or
            !std.meta.eql(self.events.*, provider_events) or
            !std.meta.eql(self.batches.*, provider_batches))
        {
            return error.ConstructionAuthorityMismatch;
        }
    }
};

pub const VerifierConstruction = union(enum) {
    caller: CallerConstruction,
    provider: ProviderConstruction,

    pub fn validate(self: VerifierConstruction) Error!void {
        return switch (self) {
            .caller => |construction| construction.validate(),
            .provider => |construction| construction.validate(),
        };
    }
};

pub const ComponentRef = union(enum) {
    base: base_claims.Component,
    extension: *const StaticIdentity,
};

pub const Registry = struct {
    profile: ExecutionProfile,

    pub fn forProfile(profile: ExecutionProfile) Registry {
        return .{ .profile = profile };
    }

    pub fn componentCount(self: Registry) usize {
        return base_component_count +
            @as(usize, @intFromBool(self.profile == .rv32im_zkvm_poseidon2_v1)) * 2;
    }

    pub fn getByIndex(self: Registry, index: usize) ?ComponentRef {
        if (index < base_component_count) {
            return .{ .base = @enumFromInt(index) };
        }
        if (self.profile != .rv32im_zkvm_poseidon2_v1) return null;
        return switch (index) {
            @intFromEnum(Slot.caller) => .{ .extension = &caller_identity },
            @intFromEnum(Slot.provider) => .{ .extension = &provider_identity },
            else => null,
        };
    }

    pub fn verifierConstruction(
        self: Registry,
        descriptor: Descriptor,
    ) Error!VerifierConstruction {
        if (self.profile != .rv32im_zkvm_poseidon2_v1)
            return error.ProfileDoesNotAdmitComponent;
        try descriptor.validate();
        return switch (descriptor.kind) {
            .guest_poseidon2_call_v1 => .{ .caller = .{
                .descriptor = descriptor,
                .constraint_identity = CallerConstraintIdentity.canonical(),
                .layout = &caller_layout,
                .events = &caller_events,
                .batches = &caller_batches,
                .fixed_table_demand = &caller_fixed_table_demand,
            } },
            .guest_poseidon2_provider_compat_v1 => .{ .provider = .{
                .descriptor = descriptor,
                .compatibility_identity = ProviderCompatibilityIdentity.canonical(),
                .compatibility_layout_digest = poseidon_identity.layout,
                .enabled_mode = 1,
                .io_mode = 1,
                .wide_mode = 0,
                .events = &provider_events,
                .batches = &provider_batches,
            } },
            _ => error.UnknownComponent,
        };
    }
};

pub const Error = error{
    CallerLayoutMismatch,
    CallerConstraintIdentityMismatch,
    ComponentGeometryMismatch,
    ComponentLogSizeMismatch,
    ComponentSlotMismatch,
    ComponentVersionMismatch,
    ConstructionAuthorityMismatch,
    ProfileDoesNotAdmitComponent,
    ProviderCompatibilityMismatch,
    UnknownComponent,
};

pub fn canonicalLogSize(n_rows: u32) u32 {
    if (n_rows <= 16) return minimum_log_size;
    return @max(minimum_log_size, std.math.log2_int_ceil(u32, n_rows));
}

pub fn identityForKind(kind: Kind) ?*const StaticIdentity {
    return switch (kind) {
        .guest_poseidon2_call_v1 => &caller_identity,
        .guest_poseidon2_provider_compat_v1 => &provider_identity,
        _ => null,
    };
}

fn baseEvent(
    ordinal: usize,
    domain: base_relation.Domain,
    role: Role,
    access_ordinal: ?u8,
    projection: Projection,
    index: u8,
    part: u8,
) EventPlan {
    const schema = base_relation.get(domain);
    return .{
        .ordinal = @intCast(ordinal),
        .schema = schema.id,
        .schema_version = schema.version,
        .arity = @intCast(schema.fields.len),
        .role = role,
        .access_ordinal = access_ordinal,
        .projection = projection,
        .index = index,
        .part = part,
        .numerator = if (role == .emit) .positive_active else .negative_active,
    };
}

fn guestEvent(
    ordinal: usize,
    role: Role,
    projection: Projection,
) EventPlan {
    return .{
        .ordinal = @intCast(ordinal),
        .schema = relation_registry.guest_schema_id,
        .schema_version = relation_registry.guest_schema_version,
        .arity = relation_registry.guest_relation_arity,
        .role = role,
        .access_ordinal = null,
        .projection = projection,
        .index = no_index,
        .part = 0,
        .numerator = if (role == .emit) .positive_active else .negative_active,
    };
}

fn buildCallerEvents() [caller_event_count]EventPlan {
    var result: [caller_event_count]EventPlan = undefined;
    var index: usize = 0;
    result[index] = baseEvent(index, .program_access, .request, null, .program, no_index, 0);
    index += 1;
    result[index] = baseEvent(index, .registers_state, .consume, null, .state_before, no_index, 0);
    index += 1;
    result[index] = baseEvent(index, .registers_state, .emit, null, .state_after, no_index, 0);
    index += 1;
    result[index] = baseEvent(index, .memory_access, .consume, 1, .pointer_consume, no_index, 0);
    index += 1;
    result[index] = baseEvent(index, .memory_access, .emit, 1, .pointer_emit, no_index, 0);
    index += 1;
    result[index] = baseEvent(index, .range_check_20, .request, 1, .pointer_clock_gap, no_index, 0);
    index += 1;

    for (0..16) |lane| {
        result[index] = baseEvent(index, .memory_access, .consume, 2, .lane_consume, @intCast(lane), 0);
        index += 1;
        result[index] = baseEvent(index, .memory_access, .emit, 2, .lane_emit, @intCast(lane), 0);
        index += 1;
        result[index] = baseEvent(index, .range_check_20, .request, 2, .lane_clock_gap, @intCast(lane), 0);
        index += 1;
    }

    for (0..2) |output| for (0..16) |lane| {
        const pair_projection: Projection = if (output == 0) .input_byte_pair else .output_byte_pair;
        const high_projection: Projection = if (output == 0) .input_high_limb else .output_high_limb;
        for (0..2) |pair| {
            result[index] = baseEvent(index, .range_check_8_8, .request, null, pair_projection, @intCast(lane), @intCast(pair));
            index += 1;
        }
        result[index] = baseEvent(index, .range_check_m31, .request, null, high_projection, @intCast(lane), 0);
        index += 1;
    };

    result[index] = baseEvent(index, .range_check_8_8, .request, null, .pointer_span_low, no_index, 0);
    index += 1;
    result[index] = baseEvent(index, .range_check_8_8_4, .request, null, .pointer_span_high, no_index, 0);
    index += 1;
    result[index] = guestEvent(index, .request, .guest_input_output);
    index += 1;
    std.debug.assert(index == result.len);
    return result;
}

fn buildProviderEvents() [provider_event_count]EventPlan {
    var result: [provider_event_count]EventPlan = undefined;
    result[0] = baseEvent(0, .poseidon2, .request, null, .provider_input, no_index, 0);
    result[0].numerator = .zero_in_guest_mode;
    result[1] = baseEvent(1, .poseidon2, .request, null, .provider_narrow_output, no_index, 0);
    result[1].numerator = .zero_in_guest_mode;
    result[2] = baseEvent(2, .poseidon2, .request, null, .provider_wide_output, no_index, 0);
    result[2].numerator = .zero_in_guest_mode;
    result[3] = guestEvent(3, .emit, .provider_input_output);
    return result;
}

fn buildBatches(comptime event_count: usize) [(event_count + 1) / 2]BatchPlan {
    var result: [(event_count + 1) / 2]BatchPlan = undefined;
    for (&result, 0..) |*batch, ordinal| {
        const first = ordinal * 2;
        batch.* = .{
            .ordinal = @intCast(ordinal),
            .first_event = @intCast(first),
            .second_event = if (first + 1 < event_count) @intCast(first + 1) else null,
            .interaction_column_start = @intCast(ordinal * 4),
        };
    }
    return result;
}

comptime {
    if (base_component_count != 28 or component_count != 30)
        @compileError("guest component registry must append to exact base 28");
    if (@intFromEnum(Slot.caller) != base_component_count or
        @intFromEnum(Slot.provider) != base_component_count + 1)
    {
        @compileError("guest component slots drifted");
    }
    if (caller_layout.main_columns != 286 or caller_interaction_columns != 308)
        @compileError("caller geometry drifted from ADR-0029");
    if (provider_main_columns != 445 or provider_interaction_columns != 8) {
        @compileError("provider compatibility geometry drifted");
    }
    if (caller_events.len != 153 or caller_batches.len != 77 or
        provider_events.len != 4 or provider_batches.len != 2)
    {
        @compileError("guest event geometry drifted");
    }
    if (caller_batches[caller_batches.len - 1].second_event != null or
        caller_batches[caller_batches.len - 1].interaction_column_start != 304)
    {
        @compileError("caller final single-event batch drifted");
    }
}

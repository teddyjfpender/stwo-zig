//! Focused C-005/C-006 registry, statement, and artifact evidence.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const base_claims = @import("../transcript/claims.zig");
const public_data = @import("../public_data.zig");
const trace = @import("../../runner/trace.zig");
const artifact = @import("artifact_identity.zig");
const components = @import("component_registry.zig");
const manifest = @import("manifest.zig");
const relation_registry = @import("relation_registry.zig");
const statement_mod = @import("statement.zig");

const FamilyDescriptor = struct {
    family: trace.OpcodeFamily,
    log_size: u32,
    n_rows: u32,
    n_columns: u32,
};

const InfraKind = enum(u32) {
    program,
    memory,
    clock_update,
    poseidon2,
    merkle,
    bitwise,
    range_check_20,
    range_check_8_11,
    range_check_8_8_4,
    range_check_8_8,
    range_check_m31,
};

const InfraDescriptor = struct {
    kind: InfraKind,
    log_size: u32,
    n_rows: u32,
    n_columns: u32,
};

const CoreFixture = struct {
    n_components: u32,
    component_descs: [4]FamilyDescriptor,
    initial_pc: u32,
    final_pc: u32,
    total_steps: u32,
    public_data: public_data.PublicData,
    n_infra: u32,
    infra_descs: [8]InfraDescriptor,
};

fn coreFixture(n_guest: u32) CoreFixture {
    const total = 3 + n_guest;
    var result: CoreFixture = undefined;
    result.n_components = 1;
    result.component_descs[0] = .{
        .family = .fence,
        .log_size = 4,
        .n_rows = 3,
        .n_columns = trace.nColumnsForFamily(.fence),
    };
    result.initial_pc = 0x1000;
    result.final_pc = 0x1000 + 4 * total;
    result.total_steps = total;
    result.public_data = .{
        .initial_pc = result.initial_pc,
        .final_pc = result.final_pc,
        .clock = total,
        .initial_regs = .{0} ** 32,
        .final_regs = .{0} ** 32,
        .reg_last_clock = .{0} ** 32,
        .program_root = 7,
        .initial_rw_root = 11,
        .final_rw_root = 13,
        .completion = null,
        .io_entries = .{
            .input_start = 0,
            .input_len = 0,
            .input_words = &.{},
            .output_len = 0,
            .output_len_addr = 0,
            .output_data_addr = 0,
            .output_words = &.{},
        },
    };
    result.n_infra = 3;
    result.infra_descs[0] = .{
        .kind = .program,
        .log_size = 3,
        .n_rows = 7,
        .n_columns = 10,
    };
    result.infra_descs[1] = .{
        .kind = .memory,
        .log_size = 4,
        .n_rows = 11,
        .n_columns = 8,
    };
    result.infra_descs[2] = .{
        .kind = .clock_update,
        .log_size = 4,
        .n_rows = 2,
        .n_columns = 10,
    };
    return result;
}

test "component registry appends exact typed slots only for extension profile" {
    const base = components.Registry.forProfile(.rv32im_zkvm_v1);
    const extension = components.Registry.forProfile(.rv32im_zkvm_poseidon2_v1);
    try std.testing.expectEqual(@as(usize, 28), base.componentCount());
    try std.testing.expectEqual(@as(usize, 30), extension.componentCount());
    for (0..base_claims.COMPONENT_COUNT) |index| {
        const base_item = base.getByIndex(index) orelse return error.MissingBaseComponent;
        const extension_item = extension.getByIndex(index) orelse return error.MissingBaseComponent;
        try std.testing.expectEqual(index, @intFromEnum(base_item.base));
        try std.testing.expectEqual(base_item.base, extension_item.base);
    }
    try std.testing.expect(base.getByIndex(28) == null);
    try std.testing.expect(base.getByIndex(29) == null);
    try std.testing.expectEqual(
        components.Kind.guest_poseidon2_call_v1,
        extension.getByIndex(28).?.extension.kind,
    );
    try std.testing.expectEqual(
        components.Kind.guest_poseidon2_provider_compat_v1,
        extension.getByIndex(29).?.extension.kind,
    );
    try std.testing.expect(extension.getByIndex(30) == null);

    const caller = try components.Descriptor.canonical(.guest_poseidon2_call_v1, 0);
    const provider = try components.Descriptor.canonical(
        .guest_poseidon2_provider_compat_v1,
        0,
    );
    try std.testing.expectEqual(@as(u32, 4), caller.log_size);
    try std.testing.expectEqual(@as(u32, 0), caller.n_rows);
    try std.testing.expectEqual(@as(u16, 286), caller.main_columns);
    try std.testing.expectEqual(@as(u16, 308), caller.interaction_columns);
    try std.testing.expectEqual(@as(u32, 4), provider.log_size);
    try std.testing.expectEqual(@as(u16, 445), provider.main_columns);
    try std.testing.expectEqual(@as(u16, 8), provider.interaction_columns);
    try std.testing.expectEqual(@as(u32, 4), components.canonicalLogSize(16));
    try std.testing.expectEqual(@as(u32, 5), components.canonicalLogSize(17));

    try std.testing.expectError(
        error.ProfileDoesNotAdmitComponent,
        base.verifierConstruction(caller),
    );
    const caller_dispatch = try extension.verifierConstruction(caller);
    try caller_dispatch.validate();
    try caller_dispatch.caller.constraint_identity.validate();
    try std.testing.expectEqual(caller, caller_dispatch.caller.descriptor);
    try std.testing.expect(caller_dispatch.caller.events == &components.caller_events);
    const provider_dispatch = try extension.verifierConstruction(provider);
    try provider_dispatch.validate();
    try std.testing.expectEqual(@as(u8, 1), provider_dispatch.provider.enabled_mode);
    try std.testing.expectEqual(@as(u8, 1), provider_dispatch.provider.io_mode);
    try std.testing.expectEqual(@as(u8, 0), provider_dispatch.provider.wide_mode);
    try std.testing.expectEqual(@as(u16, 445), provider_dispatch.provider.compatibility_identity.main_columns);

    var malformed = caller;
    malformed.slot = .provider;
    try std.testing.expectError(error.ComponentSlotMismatch, malformed.validate());
    malformed = caller;
    malformed.version += 1;
    try std.testing.expectError(error.ComponentVersionMismatch, malformed.validate());
    malformed = caller;
    malformed.main_columns -= 1;
    try std.testing.expectError(error.ComponentGeometryMismatch, malformed.validate());
    malformed = caller;
    malformed.log_size += 1;
    try std.testing.expectError(error.ComponentLogSizeMismatch, malformed.validate());
    try std.testing.expectError(
        error.UnknownComponent,
        components.Descriptor.canonical(@enumFromInt(0xffff_ffff), 1),
    );
}

test "caller layout and all 153 events close exact C-007 geometry" {
    const layout = components.caller_layout;
    try layout.validate();
    try std.testing.expectEqual(@as(u16, 0), layout.enabler);
    try std.testing.expectEqual(@as(u16, 14), layout.inputByte(0, 0));
    try std.testing.expectEqual(@as(u16, 77), layout.inputByte(15, 3));
    try std.testing.expectEqual(@as(u16, 78), layout.outputByte(0, 0));
    try std.testing.expectEqual(@as(u16, 141), layout.outputByte(15, 3));
    try std.testing.expectEqual(@as(u16, 142), layout.previousClock(0));
    try std.testing.expectEqual(@as(u16, 157), layout.previousClock(15));
    try std.testing.expectEqual(@as(u16, 158), layout.canonicalMaterialization(false, 0, 0));
    try std.testing.expectEqual(@as(u16, 285), layout.canonicalMaterialization(true, 15, 3));
    try std.testing.expectEqual(@as(u16, 286), layout.main_columns);

    var domain_counts = [_]u16{0} ** 13;
    for (components.caller_events, 0..) |event, ordinal| {
        try std.testing.expectEqual(ordinal, event.ordinal);
        domain_counts[@intFromEnum(event.schema)] += 1;
    }
    try std.testing.expectEqual(@as(u16, 2), domain_counts[0]);
    try std.testing.expectEqual(@as(u16, 34), domain_counts[1]);
    try std.testing.expectEqual(@as(u16, 1), domain_counts[2]);
    try std.testing.expectEqual(@as(u16, 17), domain_counts[7]);
    try std.testing.expectEqual(@as(u16, 1), domain_counts[9]);
    try std.testing.expectEqual(@as(u16, 65), domain_counts[10]);
    try std.testing.expectEqual(@as(u16, 32), domain_counts[11]);
    try std.testing.expectEqual(@as(u16, 1), domain_counts[12]);
    try std.testing.expectEqual(
        components.caller_fixed_table_demand,
        components.FixedTableDemand{ 0, 17, 0, 1, 65, 32 },
    );

    try std.testing.expectEqual(components.Projection.program, components.caller_events[0].projection);
    try std.testing.expectEqual(components.Role.consume, components.caller_events[1].role);
    try std.testing.expectEqual(components.Role.emit, components.caller_events[2].role);
    try std.testing.expectEqual(@as(?u8, 1), components.caller_events[3].access_ordinal);
    try std.testing.expectEqual(@as(?u8, 2), components.caller_events[6].access_ordinal);
    try std.testing.expectEqual(components.Projection.input_byte_pair, components.caller_events[54].projection);
    try std.testing.expectEqual(components.Projection.output_byte_pair, components.caller_events[102].projection);
    try std.testing.expectEqual(components.Projection.pointer_span_low, components.caller_events[150].projection);
    try std.testing.expectEqual(components.Projection.pointer_span_high, components.caller_events[151].projection);
    try std.testing.expectEqual(components.Projection.guest_input_output, components.caller_events[152].projection);
    try std.testing.expectEqual(relation_registry.guest_schema_id, components.caller_events[152].schema);
    try std.testing.expectEqual(components.Role.request, components.caller_events[152].role);

    for (components.caller_batches, 0..) |batch, ordinal| {
        try std.testing.expectEqual(ordinal, batch.ordinal);
        try std.testing.expectEqual(@as(u8, @intCast(2 * ordinal)), batch.first_event);
        try std.testing.expectEqual(@as(u16, @intCast(4 * ordinal)), batch.interaction_column_start);
    }
    try std.testing.expect(components.caller_batches[76].second_event == null);
    try std.testing.expectEqual(@as(u16, 304), components.caller_batches[76].interaction_column_start);
    try std.testing.expectEqual(@as(u16, 308), components.caller_interaction_columns);
}

test "provider dispatch retains authenticated 445 by 8 compat authority" {
    const identity = components.ProviderCompatibilityIdentity.canonical();
    try identity.validate();
    try std.testing.expectEqual(@as(u32, 0x5032_4331), identity.policy_id);
    try std.testing.expectEqual(@as(u16, 16), identity.width);
    try std.testing.expectEqual(@as(u16, 426), identity.materializations);
    try std.testing.expectEqual(@as(u16, 445), identity.main_columns);
    for (components.provider_events[0..3]) |event| {
        try std.testing.expectEqual(components.Numerator.zero_in_guest_mode, event.numerator);
    }
    const supply = components.provider_events[3];
    try std.testing.expectEqual(relation_registry.guest_schema_id, supply.schema);
    try std.testing.expectEqual(components.Role.emit, supply.role);
    try std.testing.expectEqual(components.Numerator.positive_active, supply.numerator);
    try std.testing.expectEqual(@as(u16, 0), components.provider_batches[0].interaction_column_start);
    try std.testing.expectEqual(@as(u16, 4), components.provider_batches[1].interaction_column_start);
    var malformed = identity;
    malformed.main_columns -= 1;
    try std.testing.expectError(
        error.ProviderCompatibilityMismatch,
        malformed.validate(),
    );
}

test "manifest binds every static identity class and fails closed on mutation" {
    const canonical = manifest.Identity.canonical();
    try canonical.validate();
    const first_digest = try canonical.digest();
    const second_digest = manifest.canonicalDigest();
    try std.testing.expectEqualSlices(u8, &first_digest, &second_digest);
    try std.testing.expectEqualSlices(
        u8,
        &manifest.canonical_digest_golden,
        &first_digest,
    );

    var changed = canonical;
    changed.format_version += 1;
    try std.testing.expectError(error.ManifestFormatMismatch, changed.validate());
    changed = canonical;
    changed.profile_name = "rv32im-zkvm-v1";
    try std.testing.expectError(error.ProfileMismatch, changed.validate());
    changed = canonical;
    changed.semantic_digest[0] ^= 1;
    try std.testing.expectError(error.SemanticDigestMismatch, changed.validate());
    changed = canonical;
    changed.guest_relation_version += 1;
    try std.testing.expectError(error.RelationIdentityMismatch, changed.validate());
    changed = canonical;
    const first = changed.components[0];
    changed.components[0] = changed.components[1];
    changed.components[1] = first;
    try std.testing.expectError(error.ComponentIdentityMismatch, changed.validate());
    changed = canonical;
    changed.components[0].name = "stwo.riscv.guest_poseidon2_call.v2";
    try std.testing.expectError(error.ComponentIdentityMismatch, changed.validate());
    changed = canonical;
    changed.components[1].main_columns -= 1;
    try std.testing.expectError(error.ComponentIdentityMismatch, changed.validate());
    changed = canonical;
    changed.caller_layout.output_bytes += 1;
    try std.testing.expectError(error.CallerLayoutMismatch, changed.validate());
    changed = canonical;
    changed.caller_constraint_identity.address_bits -= 1;
    try std.testing.expectError(
        error.CallerConstraintIdentityMismatch,
        changed.validate(),
    );
    changed = canonical;
    changed.caller_fixed_table_demand[4] -= 1;
    try std.testing.expectError(error.FixedTableDemandMismatch, changed.validate());
    changed = canonical;
    changed.provider_layout_digest[0] ^= 1;
    try std.testing.expectError(error.ProviderLayoutMismatch, changed.validate());
    changed = canonical;
    changed.provider_io_mode = 0;
    try std.testing.expectError(error.ProviderModeMismatch, changed.validate());
    changed = canonical;
    changed.challenge_order += 1;
    try std.testing.expectError(error.ProtocolOrderMismatch, changed.validate());
}

test "statement binds zero-call and active geometry with exact admission certificate" {
    var zero_core = coreFixture(0);
    const zero = try statement_mod.ExtensionStatement.canonical(&zero_core, 0);
    try zero.validate(&zero_core);
    try std.testing.expectEqual(@as(u32, 0), zero.counts.n_guest);
    for (zero.components) |descriptor| {
        try std.testing.expectEqual(@as(u32, 0), descriptor.n_rows);
        try std.testing.expectEqual(@as(u32, 4), descriptor.log_size);
        try std.testing.expectEqual(@as(u16, 2), descriptor.preprocessed_columns);
    }
    zero_core.public_data.initial_rw_root = null;
    zero_core.public_data.final_rw_root = null;
    _ = try statement_mod.ExtensionStatement.canonical(&zero_core, 0);

    var core = coreFixture(2);
    const statement = try statement_mod.ExtensionStatement.canonical(&core, 2);
    try statement.validateConstruction(&core, .{
        .custom_retirements = 2,
        .frozen_call_count = 2,
    });
    try std.testing.expectEqual(@as(u64, 3), statement.admission.n_base);
    try std.testing.expectEqual(@as(u64, 5), statement.admission.total_steps);
    try std.testing.expectEqual(@as(u64, 2), statement.admission.n_guest);
    try std.testing.expectEqual(@as(u64, 2), statement.admission.clock_update_rows);
    try std.testing.expectEqual(@as(u64, 11), statement.admission.memory_rows);
    try std.testing.expectEqual(@as(u64, 58), statement.admission.memory_relation_terms);
    try std.testing.expectEqual(
        [6]u64{ 0, 9, 0, 0, 31, 0 },
        statement.admission.base_fixed_table_bounds,
    );
    try std.testing.expectEqual(
        [6]u64{ 0, 43, 0, 2, 161, 64 },
        statement.admission.extended_fixed_table_bounds,
    );
    try std.testing.expectError(
        error.CallCountMismatch,
        statement.validateConstruction(&core, .{
            .custom_retirements = 1,
            .frozen_call_count = 2,
        }),
    );
}

test "statement identity, component, count, and certificate mutations reject" {
    var core = coreFixture(2);
    const canonical = try statement_mod.ExtensionStatement.canonical(&core, 2);
    var changed = canonical;
    changed.profile = .rv32im_zkvm_v1;
    try std.testing.expectError(error.ProfileMismatch, changed.validate(&core));
    changed = canonical;
    changed.abi_version += 1;
    try std.testing.expectError(error.AbiMismatch, changed.validate(&core));
    changed = canonical;
    changed.statement_version += 1;
    try std.testing.expectError(error.StatementVersionMismatch, changed.validate(&core));
    changed = canonical;
    changed.active_prefix = @enumFromInt(0xffff_ffff);
    try std.testing.expectError(error.ActivePrefixMismatch, changed.validate(&core));
    changed = canonical;
    changed.manifest_digest[0] ^= 1;
    try std.testing.expectError(error.ManifestDigestMismatch, changed.validate(&core));
    changed = canonical;
    changed.semantic_digest[0] ^= 1;
    try std.testing.expectError(error.SemanticDigestMismatch, changed.validate(&core));
    changed = canonical;
    changed.counts.frozen_call_count -= 1;
    try std.testing.expectError(error.CallCountMismatch, changed.validate(&core));
    changed = canonical;
    changed.counts = .{
        .n_guest = @intCast(statement_mod.field_modulus),
        .custom_retirements = @intCast(statement_mod.field_modulus),
        .frozen_call_count = @intCast(statement_mod.field_modulus),
    };
    try std.testing.expectError(error.GuestCardinalityExceeded, changed.validate(&core));
    changed = canonical;
    changed.components[0].kind = .guest_poseidon2_provider_compat_v1;
    try std.testing.expectError(error.ComponentOrderMismatch, changed.validate(&core));
    changed = canonical;
    changed.components[0].version += 1;
    try std.testing.expectError(error.ComponentVersionMismatch, changed.validate(&core));
    changed = canonical;
    changed.components[1].n_rows -= 1;
    try std.testing.expectError(error.CallCountMismatch, changed.validate(&core));
    changed = canonical;
    changed.admission.memory_relation_terms -= 1;
    try std.testing.expectError(error.AdmissionCertificateMismatch, changed.validate(&core));

    core.public_data.clock -= 1;
    try std.testing.expectError(error.CoreGeometryMismatch, canonical.validate(&core));
    var no_clock = coreFixture(2);
    no_clock.n_infra = 2;
    try std.testing.expectError(
        error.MissingClockUpdate,
        statement_mod.ExtensionStatement.canonical(&no_clock, 2),
    );
    var no_program = coreFixture(2);
    no_program.infra_descs[0].kind = .merkle;
    try std.testing.expectError(
        error.MissingProgramComponent,
        statement_mod.ExtensionStatement.canonical(&no_program, 2),
    );
    var duplicate_program = coreFixture(2);
    duplicate_program.infra_descs[3] = duplicate_program.infra_descs[0];
    duplicate_program.n_infra = 4;
    try std.testing.expectError(
        error.DuplicateProgramComponent,
        statement_mod.ExtensionStatement.canonical(&duplicate_program, 2),
    );
    var duplicate_clock = coreFixture(2);
    duplicate_clock.infra_descs[3] = duplicate_clock.infra_descs[2];
    duplicate_clock.n_infra = 4;
    try std.testing.expectError(
        error.DuplicateClockUpdate,
        statement_mod.ExtensionStatement.canonical(&duplicate_clock, 2),
    );
    var no_rw_root = coreFixture(2);
    no_rw_root.public_data.initial_rw_root = null;
    try std.testing.expectError(
        error.MissingRwRoot,
        statement_mod.ExtensionStatement.canonical(&no_rw_root, 2),
    );
}

test "checked admission rejects historical formula boundary and u64 overflow" {
    try std.testing.expectEqual(
        statement_mod.field_modulus - 1,
        try statement_mod.checkedMemoryRelationTerms(.{
            .total_steps = 0,
            .n_guest = 0,
            .clock_update_rows = 0,
            .memory_rows = statement_mod.field_modulus - 3,
        }),
    );
    try std.testing.expectError(
        error.CoefficientBoundExceeded,
        statement_mod.checkedMemoryRelationTerms(.{
            .total_steps = 0,
            .n_guest = 0,
            .clock_update_rows = 0,
            .memory_rows = statement_mod.field_modulus - 2,
        }),
    );
    try std.testing.expectError(
        error.ArithmeticOverflow,
        statement_mod.checkedMemoryRelationTerms(.{
            .total_steps = std.math.maxInt(u64),
            .n_guest = 0,
            .clock_update_rows = 0,
            .memory_rows = 0,
        }),
    );
    var base = [_]u64{0} ** 6;
    base[0] = statement_mod.field_modulus - 1;
    const accepted = try statement_mod.checkedExtendedFixedTableBounds(base, 0);
    try std.testing.expectEqual(statement_mod.field_modulus - 1, accepted[0]);
    base[0] = statement_mod.field_modulus;
    try std.testing.expectError(
        error.CoefficientBoundExceeded,
        statement_mod.checkedExtendedFixedTableBounds(base, 0),
    );
    base = [_]u64{0} ** 6;
    try std.testing.expectError(
        error.ArithmeticOverflow,
        statement_mod.checkedExtendedFixedTableBounds(base, std.math.maxInt(u64)),
    );
}

const RecordingChannel = struct {
    u64s: [400]u64 = undefined,
    n_u64s: usize = 0,
    u32s: [400]u32 = undefined,
    n_u32s: usize = 0,
    felts: [components.component_count]QM31 = undefined,
    n_felts: usize = 0,

    pub fn mixU64(self: *RecordingChannel, value: u64) void {
        self.u64s[self.n_u64s] = value;
        self.n_u64s += 1;
    }

    pub fn mixU32s(self: *RecordingChannel, values: []const u32) void {
        std.debug.assert(values.len <= self.u32s.len - self.n_u32s);
        @memcpy(self.u32s[self.n_u32s..][0..values.len], values);
        self.n_u32s += values.len;
    }

    pub fn mixFelts(self: *RecordingChannel, values: []const QM31) void {
        std.debug.assert(values.len <= self.felts.len - self.n_felts);
        @memcpy(self.felts[self.n_felts..][0..values.len], values);
        self.n_felts += values.len;
    }
};

test "extension claims preserve base values and append exact transcript order" {
    var core = coreFixture(2);
    const statement = try statement_mod.ExtensionStatement.canonical(&core, 2);
    var base_logs: [base_claims.COMPONENT_COUNT]u32 = undefined;
    for (&base_logs, 0..) |*value, index| value.* = @intCast(index + 1);
    const main = statement_mod.MainClaim.init(base_claims.MainClaim.init(base_logs), &statement);
    comptime std.debug.assert(@TypeOf(main.base) == base_claims.MainClaim);
    var channel = RecordingChannel{};
    main.mixInto(&channel);
    try std.testing.expectEqual(@as(usize, 30), channel.n_u64s);
    for (base_logs, channel.u64s[0..28]) |expected, actual|
        try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(@as(u64, 4), channel.u64s[28]);
    try std.testing.expectEqual(@as(u64, 4), channel.u64s[29]);

    var sums: [base_claims.COMPONENT_COUNT]QM31 = undefined;
    for (&sums, 0..) |*sum, index|
        sum.* = QM31.fromU32Unchecked(@intCast(index + 1), 0, 0, 0);
    const base_interaction = base_claims.InteractionClaim.init(sums, &.{ 7, 8 });
    const caller_sum = QM31.fromU32Unchecked(101, 0, 0, 0);
    const provider_sum = QM31.fromU32Unchecked(102, 0, 0, 0);
    const interaction = statement_mod.InteractionClaim.init(
        base_interaction,
        caller_sum,
        provider_sum,
        &statement,
    );
    channel = RecordingChannel{};
    interaction.mixInto(&channel);
    try std.testing.expectEqual(@as(usize, 30), channel.n_felts);
    for (sums, channel.felts[0..28]) |expected, actual|
        try std.testing.expect(expected.eql(actual));
    try std.testing.expect(caller_sum.eql(channel.felts[28]));
    try std.testing.expect(provider_sum.eql(channel.felts[29]));
    try std.testing.expectEqual(@as(usize, 0), channel.n_u64s);
    try std.testing.expectEqual(@as(usize, 12), channel.n_u32s);
    try std.testing.expectEqualSlices(
        u32,
        &.{
            statement_mod.interaction_claim_geometry_domain_words[0],
            statement_mod.interaction_claim_geometry_domain_words[1],
            statement_mod.interaction_claim_geometry_domain_words[2],
            statement_mod.interaction_claim_geometry_domain_words[3],
            2,
            components.caller_interaction_columns,
            4,
            components.provider_interaction_columns,
            4,
            318,
            7,
            8,
        },
        channel.u32s[0..channel.n_u32s],
    );
}

test "artifact encoding round trips and every identity digest is authoritative" {
    var core = coreFixture(2);
    const statement = try statement_mod.ExtensionStatement.canonical(&core, 2);
    const canonical = try artifact.Identity.canonical(&core, &statement);
    try canonical.validate(&core, &statement);
    const bytes = canonical.encode();
    try std.testing.expectEqual(@as(usize, 152), bytes.len);
    const decoded = try artifact.Identity.decode(&bytes);
    try std.testing.expectEqual(canonical, decoded);
    try decoded.validate(&core, &statement);

    var malformed_bytes = bytes;
    malformed_bytes[0] ^= 1;
    try std.testing.expectError(error.InvalidArtifactMagic, artifact.Identity.decode(&malformed_bytes));
    try std.testing.expectError(error.InvalidArtifactLength, artifact.Identity.decode(bytes[0 .. bytes.len - 1]));

    var changed = canonical;
    changed.profile_id = 0;
    try std.testing.expectError(error.ProfileMismatch, changed.validate(&core, &statement));
    changed = canonical;
    changed.total_components -= 1;
    try std.testing.expectError(error.RegistryGeometryMismatch, changed.validate(&core, &statement));
    changed = canonical;
    changed.manifest_digest[0] ^= 1;
    try std.testing.expectError(error.ManifestDigestMismatch, changed.validate(&core, &statement));
    changed = canonical;
    changed.semantic_digest[0] ^= 1;
    try std.testing.expectError(error.SemanticDigestMismatch, changed.validate(&core, &statement));
    changed = canonical;
    changed.provider_layout_digest[0] ^= 1;
    try std.testing.expectError(error.ProviderLayoutMismatch, changed.validate(&core, &statement));
    changed = canonical;
    changed.statement_digest[0] ^= 1;
    try std.testing.expectError(error.StatementDigestMismatch, changed.validate(&core, &statement));

    var other_core = core;
    other_core.final_pc += 4;
    other_core.public_data.final_pc = other_core.final_pc;
    const other_statement = try statement_mod.ExtensionStatement.canonical(&other_core, 2);
    const other_digest = try other_statement.digest(&other_core);
    try std.testing.expect(!std.mem.eql(u8, &canonical.statement_digest, &other_digest));
    try std.testing.expectError(
        error.StatementDigestMismatch,
        canonical.validate(&other_core, &other_statement),
    );
}

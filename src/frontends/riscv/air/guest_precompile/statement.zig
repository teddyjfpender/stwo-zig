//! Extension statement geometry, claims, and checked coefficient admission.
//!
//! The unchanged core statement remains the owner of slots 0..27. This value
//! authenticates only the appended profile and is always validated against the
//! independently supplied core statement before transcript use.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const base_claims = @import("../transcript/claims.zig");
const component_order = @import("../component_order.zig");
const opcode_entries = @import("../lookups/opcode_entries.zig");
const lookup_entry = @import("../lookups/entry.zig");
const trace = @import("../../runner/trace.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const components = @import("component_registry.zig");
const hashing = @import("identity_hash.zig");
const manifest = @import("manifest.zig");

pub const Digest = hashing.Digest;
pub const field_modulus: u64 = m31.Modulus;
pub const fixed_table_count: usize = component_order.LOOKUP_TABLE_COUNT;
pub const max_core_components: usize = 256;
pub const max_core_infrastructure: usize = 512;
pub const statement_digest_domain =
    "stwo-zig/riscv/guest-poseidon2-statement/v1";

/// Little-endian bytes `STWGICG2`, followed by the authenticated claim-order
/// version and extension component count. Runtime words encode the exact base
/// slice length and the two fixed extension runs.
pub const interaction_claim_geometry_domain_words = [4]u32{
    0x4757_5453,
    0x3247_4349,
    manifest.claim_order_version,
    components.extension_component_count,
};

pub const CountBinding = struct {
    n_guest: u32,
    custom_retirements: u32,
    frozen_call_count: u32,
};

pub const ConstructionCounts = struct {
    custom_retirements: u32,
    frozen_call_count: u32,
};

pub const MemoryAdmissionNumbers = struct {
    total_steps: u64,
    n_guest: u64,
    clock_update_rows: u64,
    memory_rows: u64,
};

pub const AdmissionCertificate = struct {
    n_base: u64,
    total_steps: u64,
    n_guest: u64,
    clock_update_rows: u64,
    memory_rows: u64,
    memory_relation_terms: u64,
    base_fixed_table_bounds: [fixed_table_count]u64,
    extended_fixed_table_bounds: [fixed_table_count]u64,
};

pub const ExtensionStatement = struct {
    profile: execution_profile.ExecutionProfile,
    abi_version: u16,
    statement_version: u16,
    active_prefix: components.ActivePrefixPolicy,
    memory_policy: manifest.MemoryAdmissionPolicy,
    manifest_digest: Digest,
    semantic_digest: Digest,
    counts: CountBinding,
    components: [components.extension_component_count]components.Descriptor,
    admission: AdmissionCertificate,

    pub fn canonical(
        core: anytype,
        n_guest: u32,
    ) Error!ExtensionStatement {
        const descriptors = [components.extension_component_count]components.Descriptor{
            try components.Descriptor.canonical(.guest_poseidon2_call_v1, n_guest),
            try components.Descriptor.canonical(
                .guest_poseidon2_provider_compat_v1,
                n_guest,
            ),
        };
        const result = ExtensionStatement{
            .profile = .rv32im_zkvm_poseidon2_v1,
            .abi_version = execution_profile.poseidon2_abi_version,
            .statement_version = manifest.statement_schema_version,
            .active_prefix = components.active_prefix_policy,
            .memory_policy = manifest.memory_admission_policy,
            .manifest_digest = manifest.canonicalDigest(),
            .semantic_digest = execution_profile.poseidon2_semantic_digest,
            .counts = .{
                .n_guest = n_guest,
                .custom_retirements = n_guest,
                .frozen_call_count = n_guest,
            },
            .components = descriptors,
            .admission = try admissionCertificate(core, n_guest),
        };
        try result.validate(core);
        return result;
    }

    pub fn validate(
        self: *const ExtensionStatement,
        core: anytype,
    ) Error!void {
        if (self.profile != .rv32im_zkvm_poseidon2_v1)
            return error.ProfileMismatch;
        if (self.abi_version != execution_profile.poseidon2_abi_version)
            return error.AbiMismatch;
        if (self.statement_version != manifest.statement_schema_version)
            return error.StatementVersionMismatch;
        if (self.active_prefix != components.active_prefix_policy)
            return error.ActivePrefixMismatch;
        if (self.memory_policy != manifest.memory_admission_policy)
            return error.MemoryPolicyMismatch;
        if (!std.mem.eql(u8, &self.manifest_digest, &manifest.canonicalDigest()))
            return error.ManifestDigestMismatch;
        if (!std.mem.eql(
            u8,
            &self.semantic_digest,
            &execution_profile.poseidon2_semantic_digest,
        )) return error.SemanticDigestMismatch;
        if (self.counts.n_guest != self.counts.custom_retirements or
            self.counts.n_guest != self.counts.frozen_call_count)
        {
            return error.CallCountMismatch;
        }
        if (@as(u64, self.counts.n_guest) >= field_modulus)
            return error.GuestCardinalityExceeded;
        if (self.components[0].slot != .caller or
            self.components[0].kind != .guest_poseidon2_call_v1 or
            self.components[1].slot != .provider or
            self.components[1].kind != .guest_poseidon2_provider_compat_v1)
        {
            return error.ComponentOrderMismatch;
        }
        for (self.components) |descriptor| try descriptor.validate();
        if (self.components[0].n_rows != self.counts.n_guest or
            self.components[1].n_rows != self.counts.n_guest)
        {
            return error.CallCountMismatch;
        }
        const expected = try admissionCertificate(core, self.counts.n_guest);
        if (!std.meta.eql(self.admission, expected))
            return error.AdmissionCertificateMismatch;
    }

    pub fn validateConstruction(
        self: *const ExtensionStatement,
        core: anytype,
        observed: ConstructionCounts,
    ) Error!void {
        try self.validate(core);
        if (observed.custom_retirements != self.counts.n_guest or
            observed.frozen_call_count != self.counts.n_guest)
        {
            return error.CallCountMismatch;
        }
    }

    pub fn digest(
        self: *const ExtensionStatement,
        core: anytype,
    ) Error!Digest {
        try self.validate(core);
        var hash = hashing.init(statement_digest_domain);
        hashCoreStatement(&hash, core);
        hashing.hashInt(&hash, u16, @intFromEnum(self.profile));
        hashing.hashInt(&hash, u16, self.abi_version);
        hashing.hashInt(&hash, u16, self.statement_version);
        hashing.hashInt(&hash, u32, @intFromEnum(self.active_prefix));
        hashing.hashInt(&hash, u32, @intFromEnum(self.memory_policy));
        hash.update(&self.manifest_digest);
        hash.update(&self.semantic_digest);
        hashing.hashInt(&hash, u32, self.counts.n_guest);
        hashing.hashInt(&hash, u32, self.counts.custom_retirements);
        hashing.hashInt(&hash, u32, self.counts.frozen_call_count);
        for (self.components) |descriptor| hashDescriptor(&hash, descriptor);
        hashAdmission(&hash, self.admission);
        return hashing.finish(&hash);
    }
};

/// A separately versioned 30-component main claim. The base value and its mix
/// implementation are reused unchanged; the two extension log sizes follow.
pub const MainClaim = struct {
    base: base_claims.MainClaim,
    extension_log_sizes: [components.extension_component_count]u32,

    pub fn init(
        base: base_claims.MainClaim,
        statement: *const ExtensionStatement,
    ) MainClaim {
        return .{
            .base = base,
            .extension_log_sizes = .{
                statement.components[0].log_size,
                statement.components[1].log_size,
            },
        };
    }

    pub fn mixInto(self: *const MainClaim, channel: anytype) void {
        self.base.mixInto(channel);
        for (self.extension_log_sizes) |log_size|
            channel.mixU64(@as(u64, log_size));
    }
};

/// Extended interaction claim order: base 28 sums, caller/provider sums, then
/// base physical-column logs and the two fixed extension column blocks.
pub const InteractionClaim = struct {
    base: base_claims.InteractionClaim,
    extension_sums: [components.extension_component_count]QM31,
    extension_log_sizes: [components.extension_component_count]u32,

    pub fn init(
        base: base_claims.InteractionClaim,
        caller_sum: QM31,
        provider_sum: QM31,
        statement: *const ExtensionStatement,
    ) InteractionClaim {
        return .{
            .base = base,
            .extension_sums = .{ caller_sum, provider_sum },
            .extension_log_sizes = .{
                statement.components[0].log_size,
                statement.components[1].log_size,
            },
        };
    }

    pub fn mixInto(self: *const InteractionClaim, channel: anytype) void {
        channel.mixFelts(&self.base.claimed_sums);
        channel.mixFelts(&self.extension_sums);
        const extension_columns = @as(u32, components.caller_interaction_columns) +
            components.provider_interaction_columns;
        channel.mixU32s(&[interaction_claim_geometry_domain_words.len + 6]u32{
            interaction_claim_geometry_domain_words[0],
            interaction_claim_geometry_domain_words[1],
            interaction_claim_geometry_domain_words[2],
            interaction_claim_geometry_domain_words[3],
            @intCast(self.base.log_sizes.len),
            components.caller_interaction_columns,
            self.extension_log_sizes[0],
            components.provider_interaction_columns,
            self.extension_log_sizes[1],
            @intCast(self.base.log_sizes.len + @as(usize, extension_columns)),
        });
        channel.mixU32s(self.base.log_sizes);
    }

    pub fn total(self: *const InteractionClaim) QM31 {
        var result = self.base.total();
        for (self.extension_sums) |sum| result = result.add(sum);
        return result;
    }
};

pub const Error = components.Error || error{
    AbiMismatch,
    ActivePrefixMismatch,
    AdmissionCertificateMismatch,
    ArithmeticOverflow,
    CallCountMismatch,
    CoefficientBoundExceeded,
    ComponentOrderMismatch,
    CoreGeometryMismatch,
    DuplicateClockUpdate,
    GuestCardinalityExceeded,
    InvalidBaseLookupPlan,
    ManifestDigestMismatch,
    MemoryPolicyMismatch,
    MissingClockUpdate,
    MissingProgramComponent,
    MissingRwRoot,
    DuplicateProgramComponent,
    ProfileMismatch,
    SemanticDigestMismatch,
    StatementVersionMismatch,
};

pub fn checkedMemoryRelationTerms(numbers: MemoryAdmissionNumbers) Error!u64 {
    var result = try checkedMul(numbers.total_steps, 3);
    result = try checkedAdd(result, try checkedMul(numbers.n_guest, 14));
    result = try checkedAdd(result, numbers.clock_update_rows);
    result = try checkedAdd(result, numbers.memory_rows);
    result = try checkedAdd(result, 2);
    if (result >= field_modulus) return error.CoefficientBoundExceeded;
    return result;
}

pub fn checkedExtendedFixedTableBounds(
    base: [fixed_table_count]u64,
    n_guest: u64,
) Error![fixed_table_count]u64 {
    var result: [fixed_table_count]u64 = undefined;
    for (&result, base, components.caller_fixed_table_demand) |*bound, base_bound, demand| {
        bound.* = try checkedAdd(base_bound, try checkedMul(n_guest, demand));
        if (bound.* >= field_modulus) return error.CoefficientBoundExceeded;
    }
    return result;
}

pub fn deriveBaseFixedTableBounds(
    core: anytype,
) Error![fixed_table_count]u64 {
    if (core.n_components > max_core_components or
        core.n_infra > max_core_infrastructure)
    {
        return error.CoreGeometryMismatch;
    }
    var result = [_]u64{0} ** fixed_table_count;
    var cached = [_]?[fixed_table_count]u8{null} ** component_order.OPCODE_FAMILY_COUNT;
    var zero_columns = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    for (core.component_descs[0..core.n_components]) |descriptor| {
        const family_index = component_order.opcodeFamilyIndex(descriptor.family);
        const demand = cached[family_index] orelse blk: {
            const count = trace.nColumnsForFamily(descriptor.family);
            const entries = opcode_entries.fromMain(
                descriptor.family,
                zero_columns[0..count],
            ) catch return error.InvalidBaseLookupPlan;
            var current = [_]u8{0} ** fixed_table_count;
            for (entries.entries[0..entries.len]) |event| {
                if (fixedTableIndex(event.domain)) |index|
                    current[index] = std.math.add(u8, current[index], 1) catch
                        return error.InvalidBaseLookupPlan;
            }
            cached[family_index] = current;
            break :blk current;
        };
        for (&result, demand) |*bound, per_row| {
            bound.* = try checkedAdd(
                bound.*,
                try checkedMul(descriptor.n_rows, per_row),
            );
        }
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| switch (descriptor.kind) {
        .program => {
            try addRows(&result[1], descriptor.n_rows, 1);
            try addRows(&result[4], descriptor.n_rows, 1);
        },
        .memory => try addRows(&result[4], descriptor.n_rows, 2),
        .clock_update => {
            try addRows(&result[1], descriptor.n_rows, 1);
            try addRows(&result[4], descriptor.n_rows, 1);
        },
        else => {},
    };
    return result;
}

fn admissionCertificate(
    core: anytype,
    n_guest: u32,
) Error!AdmissionCertificate {
    if (core.n_components > max_core_components or
        core.n_infra > max_core_infrastructure)
    {
        return error.CoreGeometryMismatch;
    }
    var n_base: u64 = 0;
    for (core.component_descs[0..core.n_components]) |descriptor|
        n_base = try checkedAdd(n_base, descriptor.n_rows);
    const total_steps = @as(u64, core.total_steps);
    if (try checkedAdd(n_base, n_guest) != total_steps)
        return error.CallCountMismatch;
    if (core.public_data.clock != core.total_steps or
        core.public_data.initial_pc != core.initial_pc or
        core.public_data.final_pc != core.final_pc or
        core.public_data.program_root == null)
    {
        return error.CoreGeometryMismatch;
    }
    if (n_guest != 0 and
        (core.public_data.initial_rw_root == null or
            core.public_data.final_rw_root == null))
    {
        return error.MissingRwRoot;
    }

    var clock_update_rows: u64 = 0;
    var saw_clock = false;
    var saw_program = false;
    var memory_rows: u64 = 0;
    for (core.infra_descs[0..core.n_infra]) |descriptor| switch (descriptor.kind) {
        .program => {
            if (saw_program) return error.DuplicateProgramComponent;
            saw_program = true;
        },
        .clock_update => {
            if (saw_clock) return error.DuplicateClockUpdate;
            saw_clock = true;
            clock_update_rows = descriptor.n_rows;
        },
        .memory => memory_rows = try checkedAdd(memory_rows, descriptor.n_rows),
        else => {},
    };
    if (!saw_program) return error.MissingProgramComponent;
    if (!saw_clock) return error.MissingClockUpdate;

    const memory_relation_terms = try checkedMemoryRelationTerms(.{
        .total_steps = total_steps,
        .n_guest = n_guest,
        .clock_update_rows = clock_update_rows,
        .memory_rows = memory_rows,
    });
    const base_bounds = try deriveBaseFixedTableBounds(core);
    const extended_bounds = try checkedExtendedFixedTableBounds(base_bounds, n_guest);
    return .{
        .n_base = n_base,
        .total_steps = total_steps,
        .n_guest = n_guest,
        .clock_update_rows = clock_update_rows,
        .memory_rows = memory_rows,
        .memory_relation_terms = memory_relation_terms,
        .base_fixed_table_bounds = base_bounds,
        .extended_fixed_table_bounds = extended_bounds,
    };
}

fn fixedTableIndex(domain: lookup_entry.Domain) ?usize {
    return switch (domain) {
        .bitwise => 0,
        .range_check_20 => 1,
        .range_check_8_11 => 2,
        .range_check_8_8_4 => 3,
        .range_check_8_8 => 4,
        .range_check_m31 => 5,
        else => null,
    };
}

fn checkedAdd(a: anytype, b: anytype) Error!u64 {
    return std.math.add(u64, @as(u64, a), @as(u64, b)) catch
        error.ArithmeticOverflow;
}

fn checkedMul(a: anytype, b: anytype) Error!u64 {
    return std.math.mul(u64, @as(u64, a), @as(u64, b)) catch
        error.ArithmeticOverflow;
}

fn addRows(bound: *u64, rows: u32, per_row: u8) Error!void {
    bound.* = try checkedAdd(bound.*, try checkedMul(rows, per_row));
}

fn hashCoreStatement(
    hash: *hashing.Sha256,
    core: anytype,
) void {
    hashing.hashInt(hash, u32, core.n_components);
    for (core.component_descs[0..core.n_components]) |descriptor| {
        hashing.hashInt(hash, u32, @intFromEnum(descriptor.family));
        hashing.hashInt(hash, u32, descriptor.log_size);
        hashing.hashInt(hash, u32, descriptor.n_rows);
        hashing.hashInt(hash, u32, descriptor.n_columns);
    }
    hashing.hashInt(hash, u32, core.initial_pc);
    hashing.hashInt(hash, u32, core.final_pc);
    hashing.hashInt(hash, u32, core.total_steps);
    var channel = hashing.U32Channel{ .hash = hash };
    core.public_data.mixInto(&channel);
    hashing.hashInt(hash, u32, core.n_infra);
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        hashing.hashInt(hash, u32, @intFromEnum(descriptor.kind));
        hashing.hashInt(hash, u32, descriptor.log_size);
        hashing.hashInt(hash, u32, descriptor.n_rows);
        hashing.hashInt(hash, u32, descriptor.n_columns);
    }
}

fn hashDescriptor(hash: *hashing.Sha256, descriptor: components.Descriptor) void {
    hashing.hashInt(hash, u16, @intFromEnum(descriptor.slot));
    hashing.hashInt(hash, u32, @intFromEnum(descriptor.kind));
    hashing.hashInt(hash, u16, descriptor.version);
    hashing.hashInt(hash, u32, descriptor.n_rows);
    hashing.hashInt(hash, u32, descriptor.log_size);
    hashing.hashInt(hash, u16, descriptor.preprocessed_columns);
    hashing.hashInt(hash, u16, descriptor.main_columns);
    hashing.hashInt(hash, u16, descriptor.interaction_columns);
}

fn hashAdmission(hash: *hashing.Sha256, admission: AdmissionCertificate) void {
    hashing.hashInt(hash, u64, admission.n_base);
    hashing.hashInt(hash, u64, admission.total_steps);
    hashing.hashInt(hash, u64, admission.n_guest);
    hashing.hashInt(hash, u64, admission.clock_update_rows);
    hashing.hashInt(hash, u64, admission.memory_rows);
    hashing.hashInt(hash, u64, admission.memory_relation_terms);
    for (admission.base_fixed_table_bounds) |bound|
        hashing.hashInt(hash, u64, bound);
    for (admission.extended_fixed_table_bounds) |bound|
        hashing.hashInt(hash, u64, bound);
}

comptime {
    if (fixed_table_count != 6 or lookup_entry.MAX_ENTRIES != 25)
        @compileError("base fixed-table or hot lookup geometry drifted");
    if (components.caller_fixed_table_demand[1] != 17 or
        components.caller_fixed_table_demand[4] != 65 or
        components.caller_fixed_table_demand[5] != 32)
    {
        @compileError("caller coefficient authority drifted");
    }
}

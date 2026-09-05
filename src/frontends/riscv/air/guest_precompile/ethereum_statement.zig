//! Versioned verifier-visible geometry for the combined Ethereum profile.
//!
//! The base statement remains byte-for-byte unchanged. This append-only value
//! binds the two successful external-retirement families, every appended AIR
//! component, and the exact coefficient headroom those callers add to shared
//! base buses.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const component_order = @import("../component_order.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const keccak_component = @import("keccakf_component.zig");
const keccak_table_component = @import("keccakf_table_component.zig");
const keccak_tables = @import("keccakf_tables.zig");
const keccak_trace = @import("keccakf_trace.zig");
const keccak_witness = @import("keccakf_witness.zig");
const secp_bundle = @import("secp256k1_component_bundle.zig");
const secp_component = @import("secp256k1_component.zig");
const secp_config = @import("secp256k1_component_config.zig");
const secp_trace = @import("secp256k1_component_trace.zig");
const poseidon_statement = @import("statement.zig");
const base_statement = @import("../statement.zig");
const statement_v2 = @import("../statement_v2.zig");

pub const schema_version: u16 = 1;
pub const component_count: usize = 14;
pub const fixed_table_count: usize = component_order.LOOKUP_TABLE_COUNT;
pub const field_modulus: u64 = m31.Modulus;
pub const profile = execution_profile.ExecutionProfile.rv32im_zkvm_ethereum_v1;

pub const Kind = enum(u8) {
    keccak_shard_v1 = 1,
    keccak_chi_table_v2 = 2,
    keccak_xor5_table_v2 = 3,
    secp_product_base_v1 = 4,
    secp_product_scalar_v1 = 5,
    secp_linear_base_v1 = 6,
    secp_linear_scalar_v1 = 7,
    secp_point_v1 = 8,
    secp_split_v1 = 9,
    secp_scalar_program_v1 = 10,
    secp_signed_table_v1 = 11,
    secp_recovery_v1 = 12,
    secp_byte_table_v1 = 13,
    secp_recovery_caller_v1 = 14,
};

pub const Descriptor = struct {
    kind: Kind,
    log_size: u32,
    n_rows: u32,
    preprocessed_columns: u32,
    main_columns: u32,
    interaction_columns: u32,

    pub fn validate(self: Descriptor) Error!void {
        if (self.log_size == 0 or self.log_size >= 31 or
            @as(u64, self.n_rows) > (@as(u64, 1) << @intCast(self.log_size)))
        {
            return error.InvalidComponentGeometry;
        }
        const expected = expectedColumnCounts(self.kind);
        if (self.preprocessed_columns != expected.preprocessed or
            self.main_columns != expected.main or
            self.interaction_columns != expected.interaction)
        {
            return error.InvalidComponentGeometry;
        }
    }
};

pub const Shape = struct { log_size: u32, n_rows: u32 };

pub const SecpShapes = struct {
    product_base: Shape,
    product_scalar: Shape,
    linear_base: Shape,
    linear_scalar: Shape,
    point: Shape,
    split: Shape,
    scalar: Shape,
    table: Shape,
    recovery: Shape,
    byte: Shape,
    recovery_caller: Shape,
};

pub const Counts = struct {
    keccak_calls: u32,
    signer_calls: u32,
    external_retirements: u32,
};

pub const Admission = struct {
    extra_memory_terms: u64,
    memory_relation_terms: u64,
    base_fixed_table_bounds: [fixed_table_count]u64,
    extended_fixed_table_bounds: [fixed_table_count]u64,
};

pub const Statement = struct {
    version: u16,
    profile_id: execution_profile.ExecutionProfile,
    abi_version: u16,
    semantic_digest: [32]u8,
    counts: Counts,
    components: [component_count]Descriptor,
    admission: Admission,

    pub fn canonical(
        core: *const base_statement.RiscVStatement,
        keccak_calls: u32,
        signer_calls: u32,
        secp: SecpShapes,
    ) Error!Statement {
        const result = try initCanonical(
            keccak_calls,
            signer_calls,
            secp,
            try canonicalAdmission(core, keccak_calls, signer_calls),
        );
        try result.validate(core);
        return result;
    }

    /// Canonical SegmentV2 extension. The exact public memory-term count is
    /// derived from the authenticated V2 wire; its V1 compatibility projection
    /// is never used as coefficient authority.
    pub fn canonicalV2(
        native: *const statement_v2.RiscVStatementV2,
        keccak_calls: u32,
        signer_calls: u32,
        secp: SecpShapes,
    ) Error!Statement {
        native.validate() catch return error.InvalidSegmentV2Boundary;
        const result = try initCanonical(
            keccak_calls,
            signer_calls,
            secp,
            try canonicalAdmissionV2(native, keccak_calls, signer_calls),
        );
        try result.validateV2(native);
        return result;
    }

    fn initCanonical(
        keccak_calls: u32,
        signer_calls: u32,
        secp: SecpShapes,
        admission: Admission,
    ) Error!Statement {
        const external = std.math.add(u32, keccak_calls, signer_calls) catch
            return error.ArithmeticOverflow;
        return .{
            .version = schema_version,
            .profile_id = profile,
            .abi_version = execution_profile.ethereum_abi_version,
            .semantic_digest = execution_profile.ethereum_semantic_digest,
            .counts = .{
                .keccak_calls = keccak_calls,
                .signer_calls = signer_calls,
                .external_retirements = external,
            },
            .components = try canonicalDescriptors(
                keccak_calls,
                signer_calls,
                secp,
            ),
            .admission = admission,
        };
    }

    pub fn validate(
        self: *const Statement,
        core: *const base_statement.RiscVStatement,
    ) Error!void {
        try self.validateStructure(core);
        const expected_admission = try canonicalAdmission(
            core,
            self.counts.keccak_calls,
            self.counts.signer_calls,
        );
        if (!std.meta.eql(self.admission, expected_admission))
            return error.AdmissionCertificateMismatch;
    }

    /// Full SegmentV2 validation, including its exact authenticated public-term
    /// coefficient authority.
    pub fn validateV2(
        self: *const Statement,
        native: *const statement_v2.RiscVStatementV2,
    ) Error!void {
        native.validate() catch return error.InvalidSegmentV2Boundary;
        try self.validateStructure(&native.core);
        const expected_admission = try canonicalAdmissionV2(
            native,
            self.counts.keccak_calls,
            self.counts.signer_calls,
        );
        if (!std.meta.eql(self.admission, expected_admission))
            return error.AdmissionCertificateMismatch;
    }

    /// Geometry-only check for internal trace/assembly helpers. Entry points
    /// must call `validate` or `validateV2` before allocation/transcript use;
    /// this function deliberately does not authenticate the boundary-specific
    /// coefficient certificate.
    pub fn validateStructure(
        self: *const Statement,
        core: *const base_statement.RiscVStatement,
    ) Error!void {
        if (self.version != schema_version) return error.StatementVersionMismatch;
        if (self.profile_id != profile) return error.ProfileMismatch;
        if (self.abi_version != execution_profile.ethereum_abi_version)
            return error.AbiMismatch;
        if (!std.mem.eql(
            u8,
            &self.semantic_digest,
            &execution_profile.ethereum_semantic_digest,
        )) return error.SemanticDigestMismatch;
        const external = std.math.add(
            u32,
            self.counts.keccak_calls,
            self.counts.signer_calls,
        ) catch return error.ArithmeticOverflow;
        if (external != self.counts.external_retirements or
            external > core.total_steps or external >= field_modulus)
        {
            return error.CallCountMismatch;
        }
        for (self.components) |descriptor| try descriptor.validate();
        inline for (componentKinds(), 0..) |kind, index| {
            if (self.components[index].kind != kind)
                return error.ComponentOrderMismatch;
        }
        try validateCountBoundGeometry(self);
        try validateEmptyGeometry(self);
        const structural_admission = try canonicalAdmissionStructure(
            core,
            self.counts.keccak_calls,
            self.counts.signer_calls,
        );
        if (self.admission.extra_memory_terms !=
            structural_admission.extra_memory_terms or
            !std.meta.eql(
                self.admission.base_fixed_table_bounds,
                structural_admission.base_fixed_table_bounds,
            ) or
            !std.meta.eql(
                self.admission.extended_fixed_table_bounds,
                structural_admission.extended_fixed_table_bounds,
            ))
        {
            return error.AdmissionCertificateMismatch;
        }
    }

    /// Domain-separated transcript frame mixed before Tree 0.
    pub fn mixInto(
        self: *const Statement,
        core: *const base_statement.RiscVStatement,
        channel: anytype,
    ) Error!void {
        try self.validate(core);
        self.mixValidatedInto(channel);
    }

    /// SegmentV2 transcript entry. Revalidation is intentional: no
    /// geometry-only helper can move a malformed V2 admission certificate into
    /// Fiat-Shamir state.
    pub fn mixIntoV2(
        self: *const Statement,
        native: *const statement_v2.RiscVStatementV2,
        channel: anytype,
    ) Error!void {
        try self.validateV2(native);
        self.mixValidatedInto(channel);
    }

    fn mixValidatedInto(self: *const Statement, channel: anytype) void {
        channel.mixU32s(&.{
            0x4757_5453, // "STWG"
            0x3148_5445, // "ETH1"
            schema_version,
            component_count,
            @intFromEnum(self.profile_id),
            self.abi_version,
            self.counts.keccak_calls,
            self.counts.signer_calls,
            self.counts.external_retirements,
        });
        var digest_words: [8]u32 = undefined;
        for (&digest_words, 0..) |*word, index| word.* = std.mem.readInt(
            u32,
            self.semantic_digest[4 * index ..][0..4],
            .little,
        );
        channel.mixU32s(&digest_words);
        for (self.components) |descriptor| channel.mixU32s(&.{
            @intFromEnum(descriptor.kind),
            descriptor.log_size,
            descriptor.n_rows,
            descriptor.preprocessed_columns,
            descriptor.main_columns,
            descriptor.interaction_columns,
        });
        channel.mixU64(self.admission.extra_memory_terms);
        channel.mixU64(self.admission.memory_relation_terms);
        for (self.admission.base_fixed_table_bounds) |value| channel.mixU64(value);
        for (self.admission.extended_fixed_table_bounds) |value| channel.mixU64(value);
    }
};

pub const Error = poseidon_statement.Error || error{
    AbiMismatch,
    AdmissionCertificateMismatch,
    ArithmeticOverflow,
    CallCountMismatch,
    ComponentOrderMismatch,
    InvalidComponentGeometry,
    InvalidSegmentV2Boundary,
    MissingClockUpdate,
    ProfileMismatch,
    SemanticDigestMismatch,
    StatementVersionMismatch,
};

pub fn componentKinds() [component_count]Kind {
    return .{
        .keccak_shard_v1,
        .keccak_chi_table_v2,
        .keccak_xor5_table_v2,
        .secp_product_base_v1,
        .secp_product_scalar_v1,
        .secp_linear_base_v1,
        .secp_linear_scalar_v1,
        .secp_point_v1,
        .secp_split_v1,
        .secp_scalar_program_v1,
        .secp_signed_table_v1,
        .secp_recovery_v1,
        .secp_byte_table_v1,
        .secp_recovery_caller_v1,
    };
}

fn canonicalDescriptors(
    keccak_calls: u32,
    signer_calls: u32,
    secp: SecpShapes,
) Error![component_count]Descriptor {
    const slots = std.math.divCeil(u32, keccak_calls, 2) catch unreachable;
    const keccak_rows = std.math.mul(u32, slots, keccak_witness.row_count) catch
        return error.ArithmeticOverflow;
    const keccak_log = if (keccak_rows == 0)
        keccak_trace.minimum_log_size
    else
        @max(
            keccak_trace.minimum_log_size,
            std.math.log2_int_ceil(u32, keccak_rows),
        );
    if (keccak_log > keccak_trace.maximum_log_size)
        return error.InvalidComponentGeometry;
    const shapes = [component_count]Shape{
        .{ .log_size = keccak_log, .n_rows = keccak_rows },
        .{ .log_size = keccak_tables.logSize(.chi), .n_rows = @intCast(keccak_tables.size(.chi)) },
        .{ .log_size = keccak_tables.logSize(.xor5), .n_rows = @intCast(keccak_tables.size(.xor5)) },
        secp.product_base,
        secp.product_scalar,
        secp.linear_base,
        secp.linear_scalar,
        secp.point,
        secp.split,
        secp.scalar,
        secp.table,
        secp.recovery,
        secp.byte,
        secp.recovery_caller,
    };
    var result: [component_count]Descriptor = undefined;
    for (&result, componentKinds(), shapes) |*descriptor, kind, shape| {
        const counts = expectedColumnCounts(kind);
        descriptor.* = .{
            .kind = kind,
            .log_size = shape.log_size,
            .n_rows = shape.n_rows,
            .preprocessed_columns = counts.preprocessed,
            .main_columns = counts.main,
            .interaction_columns = counts.interaction,
        };
        try descriptor.validate();
    }
    if (result[11].n_rows != signer_calls or
        result[13].n_rows != signer_calls)
    {
        return error.CallCountMismatch;
    }
    return result;
}

fn validateCountBoundGeometry(self: *const Statement) Error!void {
    const expected_slots = std.math.divCeil(
        u32,
        self.counts.keccak_calls,
        2,
    ) catch unreachable;
    const expected_keccak_rows = std.math.mul(
        u32,
        expected_slots,
        keccak_witness.row_count,
    ) catch return error.ArithmeticOverflow;
    if (self.components[0].n_rows != expected_keccak_rows or
        self.components[11].n_rows != self.counts.signer_calls or
        self.components[13].n_rows != self.counts.signer_calls or
        self.components[12].n_rows != 256)
    {
        return error.CallCountMismatch;
    }
}

fn validateEmptyGeometry(self: *const Statement) Error!void {
    if (self.counts.keccak_calls == 0 and
        (self.components[0].n_rows != 0 or
            self.components[0].log_size != keccak_trace.minimum_log_size))
    {
        return error.InvalidComponentGeometry;
    }
    if (self.counts.signer_calls != 0) return;
    for (self.components[3..12]) |descriptor| {
        if (descriptor.n_rows != 0 or descriptor.log_size != 1)
            return error.InvalidComponentGeometry;
    }
    if (self.components[12].n_rows != 256 or
        self.components[12].log_size != 8 or
        self.components[13].n_rows != 0 or
        self.components[13].log_size != 1)
    {
        return error.InvalidComponentGeometry;
    }
}

const ColumnCounts = struct { preprocessed: u32, main: u32, interaction: u32 };

fn expectedColumnCounts(kind: Kind) ColumnCounts {
    return switch (kind) {
        .keccak_shard_v1 => .{
            .preprocessed = keccak_component.preprocessed_column_count,
            .main = keccak_component.main_column_count,
            .interaction = keccak_component.interaction_column_count,
        },
        .keccak_chi_table_v2, .keccak_xor5_table_v2 => .{
            .preprocessed = keccak_table_component.preprocessed_column_count,
            .main = keccak_table_component.main_column_count,
            .interaction = keccak_table_component.interaction_column_count,
        },
        .secp_product_base_v1 => secpCounts(secp_bundle.ProductBase),
        .secp_product_scalar_v1 => secpCounts(secp_bundle.ProductScalar),
        .secp_linear_base_v1 => secpCounts(secp_bundle.LinearBase),
        .secp_linear_scalar_v1 => secpCounts(secp_bundle.LinearScalar),
        .secp_point_v1 => secpCounts(secp_config.Point),
        .secp_split_v1 => secpCounts(secp_config.Split),
        .secp_scalar_program_v1 => secpCounts(secp_config.ScalarProgram),
        .secp_signed_table_v1 => secpCounts(secp_config.Table),
        .secp_recovery_v1 => secpCounts(secp_config.Recovery),
        .secp_byte_table_v1 => secpCounts(secp_config.ByteTable),
        .secp_recovery_caller_v1 => secpCounts(secp_config.RecoveryCaller),
    };
}

fn secpCounts(comptime Config: type) ColumnCounts {
    return .{
        .preprocessed = secp_trace.preprocessed_column_count,
        .main = Config.main_column_count,
        .interaction = 4 * Config.batch_count,
    };
}

fn canonicalAdmission(
    core: *const base_statement.RiscVStatement,
    keccak_calls: u32,
    signer_calls: u32,
) Error!Admission {
    return canonicalAdmissionWithPublicMemoryTerms(
        core,
        keccak_calls,
        signer_calls,
        2,
    );
}

fn canonicalAdmissionV2(
    native: *const statement_v2.RiscVStatementV2,
    keccak_calls: u32,
    signer_calls: u32,
) Error!Admission {
    const public_terms = statement_v2.nativePublicTermCounts(
        &native.public_data,
    ) catch return error.InvalidSegmentV2Boundary;
    return canonicalAdmissionWithPublicMemoryTerms(
        &native.core,
        keccak_calls,
        signer_calls,
        public_terms.memory,
    );
}

fn canonicalAdmissionWithPublicMemoryTerms(
    core: *const base_statement.RiscVStatement,
    keccak_calls: u32,
    signer_calls: u32,
    public_memory_terms: u64,
) Error!Admission {
    var result = try canonicalAdmissionStructure(
        core,
        keccak_calls,
        signer_calls,
    );
    result.memory_relation_terms = try memoryRelationTerms(
        core,
        result.extra_memory_terms,
        public_memory_terms,
    );
    return result;
}

fn canonicalAdmissionStructure(
    core: *const base_statement.RiscVStatement,
    keccak_calls: u32,
    signer_calls: u32,
) Error!Admission {
    const extra_memory_terms = try checkedAdd(
        try checkedMul(keccak_calls, 48),
        try checkedMul(signer_calls, 40),
    );
    const base_bounds = try poseidon_statement.deriveBaseFixedTableBounds(core.*);
    var extended_bounds = base_bounds;
    try addDemand(&extended_bounds, .range_check_20, keccak_calls, 51);
    try addDemand(&extended_bounds, .range_check_8_8, keccak_calls, 1);
    try addDemand(&extended_bounds, .range_check_8_8_4, keccak_calls, 1);
    try addDemand(&extended_bounds, .range_check_20, signer_calls, 43);
    try addDemand(&extended_bounds, .range_check_8_8, signer_calls, 1);
    try addDemand(&extended_bounds, .range_check_8_8_4, signer_calls, 1);
    return .{
        .extra_memory_terms = extra_memory_terms,
        .memory_relation_terms = 0,
        .base_fixed_table_bounds = base_bounds,
        .extended_fixed_table_bounds = extended_bounds,
    };
}

fn memoryRelationTerms(
    core: *const base_statement.RiscVStatement,
    extra_memory_terms: u64,
    public_memory_terms: u64,
) Error!u64 {
    var memory_rows: u64 = 0;
    var clock_rows: ?u32 = null;
    for (core.infra_descs[0..core.n_infra]) |descriptor| switch (descriptor.kind) {
        .memory => memory_rows = try checkedAdd(memory_rows, descriptor.n_rows),
        .clock_update => {
            if (clock_rows != null) return error.MissingClockUpdate;
            clock_rows = descriptor.n_rows;
        },
        else => {},
    };
    const clock = clock_rows orelse return error.MissingClockUpdate;
    var terms = try checkedMul(core.total_steps, 3);
    terms = try checkedAdd(terms, extra_memory_terms);
    terms = try checkedAdd(terms, clock);
    terms = try checkedAdd(terms, memory_rows);
    terms = try checkedAdd(terms, public_memory_terms);
    if (terms >= field_modulus) return error.CoefficientBoundExceeded;
    return terms;
}

fn addDemand(
    bounds: *[fixed_table_count]u64,
    kind: @import("../lookups/tables/schema.zig").Kind,
    rows: u32,
    per_row: u32,
) Error!void {
    const index = @intFromEnum(kind);
    bounds[index] = try checkedAdd(bounds[index], try checkedMul(rows, per_row));
    if (bounds[index] >= field_modulus) return error.CoefficientBoundExceeded;
}

fn checkedAdd(left: anytype, right: anytype) Error!u64 {
    return std.math.add(u64, @intCast(left), @intCast(right)) catch
        error.ArithmeticOverflow;
}

fn checkedMul(left: anytype, right: anytype) Error!u64 {
    return std.math.mul(u64, @intCast(left), @intCast(right)) catch
        error.ArithmeticOverflow;
}

comptime {
    if (component_count != 14 or fixed_table_count != 6)
        @compileError("Ethereum extension statement geometry drifted");
}

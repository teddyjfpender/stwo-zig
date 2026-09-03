//! Heterogeneous compiler authority for universal rows 10--17.
//!
//! Rows 10--16 have one verifier-owned VM public profile even when a binary
//! node leaves their main witnesses inactive. Row 17 is different: its two
//! child control lanes must follow the independently authenticated verifier
//! schedules. This owner reconstructs both halves from typed inputs and never
//! treats a retained digest as permission to select a program.

const std = @import("std");
const digest = @import("../air/lang/digest.zig");
const schedule = @import("air/verifier_schedule.zig");
const control_v2 = @import("air/control_slice_heterogeneous_v2.zig");
const claim_input_air = @import("air/vm_public_claim_input.zig");
const claim_input_witness = @import("air/vm_public_claim_input_witness.zig");
const claim_hash_air = @import("air/vm_public_claim_hash.zig");
const claim_hash_witness = @import("air/vm_public_claim_hash_witness.zig");
const io_hash_air = @import("air/vm_public_io_hash.zig");
const io_hash_witness = @import("air/vm_public_io_hash_witness.zig");
const claim_semantics_air = @import("air/vm_public_claim_semantics_input.zig");
const claim_semantics_witness =
    @import("air/vm_public_claim_semantics_input_witness.zig");
const public_logup_air = @import("air/vm_public_logup_input.zig");
const public_logup_witness = @import("air/vm_public_logup_input_witness.zig");
const statement_input_air = @import("air/statement_input.zig");
const statement_input_witness = @import("air/statement_input_witness.zig");
const statement_semantics_air = @import("air/statement_semantics_input.zig");
const statement_semantics_witness =
    @import("air/statement_semantics_input_witness.zig");
const leaf_authority = @import("segment_leaf_authority.zig");
const statement_source = @import("segment_statement_outer_source.zig");
const public_source = @import("segment_public_outer_source.zig");
const semantics = @import("vm_public_semantics_circuit.zig");
const vm_claim = @import("vm_public_claim.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const ROW_COUNT: usize = 8;
pub const FIRST_ROW: usize = 10;
const PROGRAM_DOMAIN =
    "stwo-zig/typed-air/binary-public-rows-program/v2\x00";

pub const Error = error{
    InvalidHeterogeneousPublicRowsAuthority,
    InvalidVmPublicProfile,
    MissingClaimedSumStep,
    DuplicateClaimedSumStep,
};

/// Owned, proof-independent compiler result. All mutable preprocessing is
/// exhaustively regenerated or validated before its program identity is used.
pub const ProgramAuthorityV2 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    shape: vm_claim.Shape,
    claimed_sum_count: u32,
    leaf_preprocessing: leaf_authority.Preprocessing,
    statement: statement_source.Authority,
    claim_reference: semantics.ClaimReference,
    logup_reference: semantics.LogupReference,
    public_logup_preprocessing: public_logup_witness.Preprocessed,
    public_logup_control: control_v2.PublicLogupPreprocessedV2,
    log_sizes: [ROW_COUNT]u32,
    program_sha256: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        shape: vm_claim.Shape,
        vm: *const schedule.Plan,
        left: *const schedule.Plan,
        right: *const schedule.Plan,
    ) !ProgramAuthorityV2 {
        try validatePlansForShape(shape, vm, left, right);
        var leaf_preprocessing = try leaf_authority.Preprocessing.init(
            allocator,
            shape,
        );
        errdefer leaf_preprocessing.deinit();
        var statement = try statement_source.Authority.init(
            allocator,
            &leaf_preprocessing,
        );
        errdefer statement.deinit();
        const claimed_sum_count = try planClaimedSumCount(vm);
        var claim_reference = try semantics.ClaimReference.init(
            allocator,
            shape,
            public_source.CLAIM_CIRCUIT_ID,
        );
        errdefer claim_reference.deinit();
        var logup_reference = try semantics.LogupReference.init(
            allocator,
            shape,
            public_source.PUBLIC_LOGUP_CIRCUIT_ID,
            claimed_sum_count,
        );
        errdefer logup_reference.deinit();
        const row16_reference = try publicLogupReference(&logup_reference);
        var public_logup_preprocessing = try public_logup_witness.Preprocessed.init(
            allocator,
            row16_reference,
        );
        errdefer public_logup_preprocessing.deinit();
        var public_logup_control = try control_v2.PublicLogupPreprocessedV2.init(
            allocator,
            vm,
            left,
            right,
        );
        errdefer public_logup_control.deinit();
        var result = ProgramAuthorityV2{
            .allocator = allocator,
            .shape = shape,
            .claimed_sum_count = claimed_sum_count,
            .leaf_preprocessing = leaf_preprocessing,
            .statement = statement,
            .claim_reference = claim_reference,
            .logup_reference = logup_reference,
            .public_logup_preprocessing = public_logup_preprocessing,
            .public_logup_control = public_logup_control,
            .log_sizes = undefined,
            .program_sha256 = undefined,
        };
        result.log_sizes = result.expectedLogSizes();
        result.program_sha256 = programIdentity(&result, vm, left, right);
        try result.validateAgainst(vm, left, right);
        return result;
    }

    pub fn deinit(self: *ProgramAuthorityV2) void {
        self.public_logup_control.deinit();
        self.public_logup_preprocessing.deinit();
        self.logup_reference.deinit();
        self.claim_reference.deinit();
        self.statement.deinit();
        self.leaf_preprocessing.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const ProgramAuthorityV2,
        vm: *const schedule.Plan,
        left: *const schedule.Plan,
        right: *const schedule.Plan,
    ) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidHeterogeneousPublicRowsAuthority;
        }
        try validatePlansForShape(self.shape, vm, left, right);
        if (self.claimed_sum_count != try planClaimedSumCount(vm))
            return error.InvalidHeterogeneousPublicRowsAuthority;
        try self.leaf_preprocessing.validate();
        try self.statement.validate();
        try validateStatementLeafBinding(self);
        try self.claim_reference.validate();
        try self.logup_reference.validate();
        if (!std.meta.eql(self.claim_reference.shape, self.shape) or
            self.claim_reference.circuit_id != public_source.CLAIM_CIRCUIT_ID or
            !std.meta.eql(self.logup_reference.shape, self.shape) or
            self.logup_reference.circuit_id != public_source.PUBLIC_LOGUP_CIRCUIT_ID or
            self.logup_reference.claimed_sum_count != self.claimed_sum_count or
            self.logup_reference.public_term_count !=
                vm.spec.public_logup_term_count)
        {
            return error.InvalidHeterogeneousPublicRowsAuthority;
        }
        try self.public_logup_preprocessing.validateAgainst(
            try publicLogupReference(&self.logup_reference),
        );
        try self.public_logup_control.validateAgainst(vm, left, right);
        if (!std.meta.eql(self.log_sizes, self.expectedLogSizes()) or
            !std.mem.eql(
                u8,
                &self.program_sha256,
                &programIdentity(self, vm, left, right),
            ))
        {
            return error.InvalidHeterogeneousPublicRowsAuthority;
        }
    }

    fn expectedLogSizes(self: *const ProgramAuthorityV2) [ROW_COUNT]u32 {
        return .{
            self.statement.statement_input_preprocessing.log_size,
            self.statement.statement_semantics_preprocessing.log_size,
            self.leaf_preprocessing.claim_input.log_size,
            self.leaf_preprocessing.claim_hash.log_size,
            self.leaf_preprocessing.io_hash.log_size,
            self.claim_reference.row_preprocessing.log_size,
            self.public_logup_preprocessing.log_size,
            self.public_logup_control.log_size,
        };
    }
};

fn validatePlansForShape(
    shape: vm_claim.Shape,
    vm: *const schedule.Plan,
    left: *const schedule.Plan,
    right: *const schedule.Plan,
) !void {
    try vm.validate();
    try left.validate();
    try right.validate();
    if (vm.schema != .vm or
        vm.spec.public_logup_term_count != try semantics.publicTermCount(shape))
    {
        return error.InvalidVmPublicProfile;
    }
}

fn validateStatementLeafBinding(self: *const ProgramAuthorityV2) !void {
    const expected = &self.statement.statement_input_preprocessing;
    const actual = &self.leaf_preprocessing.statement_input;
    if (expected.log_size != actual.log_size or
        !std.mem.eql(
            u8,
            &expected.authority_digest,
            &actual.authority_digest,
        ) or expected.rows.len != actual.rows.len)
    {
        return error.InvalidHeterogeneousPublicRowsAuthority;
    }
    for (expected.rows, actual.rows) |left, right| if (!std.meta.eql(left, right))
        return error.InvalidHeterogeneousPublicRowsAuthority;
}

fn publicLogupReference(
    reference: *const semantics.LogupReference,
) !public_logup_witness.Reference {
    return public_logup_witness.Reference.seal(
        reference.circuit_id,
        reference.claim_kinds,
        reference.claimed_sum_count,
        reference.row_bindings,
    );
}

fn planClaimedSumCount(plan: *const schedule.Plan) !u32 {
    var result: ?u32 = null;
    for (plan.steps) |step| switch (step) {
        .absorb_claimed_sums => |item| {
            if (result != null) return error.DuplicateClaimedSumStep;
            result = item.count;
        },
        else => {},
    };
    return result orelse error.MissingClaimedSumStep;
}

fn programIdentity(
    value: *const ProgramAuthorityV2,
    vm: *const schedule.Plan,
    left: *const schedule.Plan,
    right: *const schedule.Plan,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PROGRAM_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.shape.max_input_words);
    hashInt(&hash, u32, value.shape.max_output_words);
    hashInt(&hash, u32, value.claimed_sum_count);
    hash.update(&statement_input_air.SEMANTIC_DIGEST);
    hash.update(&statement_input_witness.BINDING_DIGEST);
    hash.update(&statement_semantics_air.SEMANTIC_DIGEST);
    hash.update(&statement_semantics_witness.BINDING_DIGEST);
    hash.update(&claim_input_air.SEMANTIC_DIGEST);
    hash.update(&claim_input_witness.BINDING_DIGEST);
    hash.update(&claim_hash_air.SOURCE_AUTHORITY_DIGEST);
    hash.update(&claim_hash_air.SEMANTIC_DIGEST);
    hash.update(&claim_hash_witness.BINDING_DIGEST);
    hash.update(&io_hash_air.SOURCE_AUTHORITY_DIGEST);
    hash.update(&io_hash_air.SEMANTIC_DIGEST);
    hash.update(&io_hash_witness.BINDING_DIGEST);
    hash.update(&claim_semantics_air.SEMANTIC_DIGEST);
    hash.update(&public_logup_air.SEMANTIC_DIGEST);
    hash.update(&value.statement.statement_input_preprocessing.authority_digest);
    hash.update(&value.statement.statement_semantics_preprocessing.authority_digest);
    hash.update(&value.statement.circuit.identity_digest);
    hash.update(&value.leaf_preprocessing.claim_input.authority_digest);
    hash.update(&value.leaf_preprocessing.claim_hash.authority_digest);
    hash.update(&value.leaf_preprocessing.io_hash.authority_digest);
    hash.update(&value.claim_reference.authority_digest);
    hash.update(&value.logup_reference.authority_digest);
    hash.update(&value.public_logup_preprocessing.reference_digest);
    hash.update(&value.public_logup_control.authority_sha256);
    for (value.log_sizes) |log_size| hashInt(&hash, u32, log_size);
    for ([_]*const schedule.Plan{ vm, left, right }) |plan| {
        hashInt(&hash, u16, @intFromEnum(plan.schema));
        for (plan.authority_digest) |word| hashInt(&hash, u32, word);
    }
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        FIRST_ROW != 10 or ROW_COUNT != 8)
    {
        @compileError("heterogeneous public rows contract drifted");
    }
}

//! Cold-compiled child-field schedule for the recursive Ethereum leaf wrapper.
//!
//! The schedule derives the native V2 authority and receipt from the exact
//! verified child statement/context geometry, publishes their field digests,
//! forwards the local wire digest, and retains the transcript's Tree0 root.
//! It deliberately contains no ProgramV2 or provider authority: those require
//! separate canonical field-native producers before a wrapper can activate.

const std = @import("std");
const core = @import("stwo_core");

const statement_v1 = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const hash_witness = @import("air/vm_public_claim_hash_witness.zig");
const merkle_root_witness = @import("air/merkle_root_witness.zig");
const router_air = @import("air/ethereum_leaf_child_field_router_v1.zig");
const leaf_source = @import("air/ethereum_leaf_link_source_v1.zig");
const leaf_v2 = @import("segment_leaf_authority_v2.zig");
const segment_v2 = @import("segment_statement_v2.zig");
const span = @import("span_statement.zig");

const M31 = core.fields.m31.M31;
const m31 = core.fields.m31;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const AUTHORITY_PREIMAGE_SCOPE: u32 = 0x4c41_5731; // "LAW1"
pub const RECEIPT_PREIMAGE_SCOPE: u32 = 0x4c52_5731; // "LRW1"
pub const AUTHORITY_HASH_STEP_BASE: u32 = 256;
pub const RECEIPT_HASH_STEP_BASE: u32 = 512;
pub const AUTHORITY_FIXED_WORD_COUNT: usize =
    leaf_v2.AUTHORITY_HASH_FIXED_PREIMAGE_WORD_COUNT;
pub const WORDS_PER_DESCRIPTOR: usize =
    leaf_v2.AUTHORITY_HASH_WORDS_PER_DESCRIPTOR;
pub const RECEIPT_WORD_COUNT: usize = 64;
pub const DIGEST_WORD_COUNT: usize = 8;
pub const BASE_ROUTER_ROW_COUNT: usize = 90;
pub const EXTRA_TREE0_INPUT_USES: u32 = 1;
pub const COMPLETE_WRAPPER_AUTHORITY_AVAILABLE = false;

comptime {
    if (AUTHORITY_PREIMAGE_SCOPE >= m31.Modulus or
        RECEIPT_PREIMAGE_SCOPE >= m31.Modulus or
        AUTHORITY_FIXED_WORD_COUNT != 22 or WORDS_PER_DESCRIPTOR != 8 or
        RECEIPT_WORD_COUNT != 64 or
        merkle_root_witness.COMMITMENT_INPUT_KIND != 4)
    {
        @compileError("Ethereum child-field program ABI drifted");
    }
}

pub const RouterScheduleRowV1 = struct {
    active: u32 = 1,
    statement_source_mask: u32 = 0,
    verifier_source_mask: u32 = 0,
    constant_source_mask: u32 = 0,
    derived_source_mask: u32 = 0,
    raw_a_sink_mask: u32 = 0,
    raw_b_sink_mask: u32 = 0,
    verifier_sink_mask: u32 = 0,
    statement_scope: u32 = 0,
    statement_index: u32 = 0,
    source_verifier_kind: u32 = 0,
    source_index_0: u32 = 0,
    source_index_1: u32 = 0,
    constant_value: u32 = 0,
    raw_a_scope: u32 = 0,
    raw_a_index: u32 = 0,
    raw_b_scope: u32 = 0,
    raw_b_index: u32 = 0,
    sink_verifier_kind: u32 = 0,
    sink_index_0: u32 = 0,
    sink_index_1: u32 = 0,
    sink_use_count: u32 = 0,

    pub fn logical(self: RouterScheduleRowV1, value: M31) router_air.Row {
        return router_air.logicalRow(value, self.preprocessed());
    }

    pub fn preprocessed(
        self: RouterScheduleRowV1,
    ) [router_air.PREPROCESSED_COLUMN_COUNT]u32 {
        return .{
            self.active,
            self.statement_source_mask,
            self.verifier_source_mask,
            self.constant_source_mask,
            self.derived_source_mask,
            self.raw_a_sink_mask,
            self.raw_b_sink_mask,
            self.verifier_sink_mask,
            self.statement_scope,
            self.statement_index,
            self.source_verifier_kind,
            self.source_index_0,
            self.source_index_1,
            self.constant_value,
            self.raw_a_scope,
            self.raw_a_index,
            self.raw_b_scope,
            self.raw_b_index,
            self.sink_verifier_kind,
            self.sink_index_0,
            self.sink_index_1,
            self.sink_use_count,
        };
    }

    pub fn validate(self: RouterScheduleRowV1) !void {
        const masks = [_]u32{
            self.active,
            self.statement_source_mask,
            self.verifier_source_mask,
            self.constant_source_mask,
            self.derived_source_mask,
            self.raw_a_sink_mask,
            self.raw_b_sink_mask,
            self.verifier_sink_mask,
        };
        for (masks) |mask| if (mask > 1)
            return error.InvalidEthereumChildFieldProgram;
        if (self.active != 1 or
            self.statement_source_mask + self.verifier_source_mask +
                self.constant_source_mask + self.derived_source_mask != 1 or
            self.raw_a_sink_mask + self.raw_b_sink_mask +
                self.verifier_sink_mask == 0 or
            (self.derived_source_mask == 1 and self.verifier_sink_mask != 1) or
            (self.constant_source_mask == 0 and self.constant_value != 0) or
            (self.verifier_sink_mask == 0 and self.sink_use_count != 0) or
            (self.verifier_sink_mask == 1 and self.sink_use_count == 0))
        {
            return error.InvalidEthereumChildFieldProgram;
        }
        for (self.preprocessed()) |word| if (word >= m31.Modulus)
            return error.InvalidEthereumChildFieldProgram;
    }
};

pub const HashScheduleV1 = struct {
    word_count: usize,
    log_size: u32,
    step_base: u32,
    domain: u32,
    scope: u32,
    digest_kind: u32,
    rows: []hash_witness.PreprocessedRow,

    fn deinit(self: *HashScheduleV1, allocator: std.mem.Allocator) void {
        allocator.free(self.rows);
        self.* = undefined;
    }
};

pub const ProgramV1 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    component_count: u32,
    infra_count: u32,
    router_log_size: u32,
    router_rows: []RouterScheduleRowV1,
    authority_hash: HashScheduleV1,
    receipt_hash: HashScheduleV1,

    pub fn init(
        allocator: std.mem.Allocator,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) !ProgramV1 {
        var result = try buildUnchecked(allocator, component_descs, infra_descs);
        errdefer result.deinit();
        try result.validateAgainst(component_descs, infra_descs);
        return result;
    }

    pub fn deinit(self: *ProgramV1) void {
        self.receipt_hash.deinit(self.allocator);
        self.authority_hash.deinit(self.allocator);
        self.allocator.free(self.router_rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const ProgramV1,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.component_count != component_descs.len or
            self.infra_count != infra_descs.len or
            self.router_log_size != try traceLogSize(self.router_rows.len))
        {
            return error.InvalidEthereumChildFieldProgram;
        }
        for (self.router_rows) |row| try row.validate();
        var expected = try buildUnchecked(
            self.allocator,
            component_descs,
            infra_descs,
        );
        defer expected.deinit();
        if (!metaSliceEqual(
            RouterScheduleRowV1,
            self.router_rows,
            expected.router_rows,
        ) or !hashSchedulesEqual(&self.authority_hash, &expected.authority_hash) or
            !hashSchedulesEqual(&self.receipt_hash, &expected.receipt_hash))
        {
            return error.InvalidEthereumChildFieldProgram;
        }
    }

    pub fn requireCompleteWrapperAuthority(self: *const ProgramV1) !void {
        if (self.format_version != FORMAT_VERSION or
            !COMPLETE_WRAPPER_AUTHORITY_AVAILABLE)
        {
            return error.EthereumLeafWrapperAuthorityUnavailable;
        }
    }
};

fn buildUnchecked(
    allocator: std.mem.Allocator,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
) !ProgramV1 {
    if (component_descs.len > statement_v1.MAX_COMPONENTS or
        infra_descs.len > statement_v1.MAX_INFRA_COMPONENTS)
    {
        return error.InvalidEthereumChildFieldProgram;
    }
    const descriptor_count = std.math.add(
        usize,
        component_descs.len,
        infra_descs.len,
    ) catch return error.InvalidEthereumChildFieldProgram;
    const router_count = std.math.add(
        usize,
        BASE_ROUTER_ROW_COUNT,
        std.math.mul(usize, descriptor_count, WORDS_PER_DESCRIPTOR) catch
            return error.InvalidEthereumChildFieldProgram,
    ) catch return error.InvalidEthereumChildFieldProgram;
    const router_rows = try allocator.alloc(RouterScheduleRowV1, router_count);
    errdefer allocator.free(router_rows);
    fillRouterRows(router_rows, component_descs, infra_descs);

    const authority_words = authorityWordCount(descriptor_count) catch
        return error.InvalidEthereumChildFieldProgram;
    var authority_hash = try buildHashSchedule(
        allocator,
        authority_words,
        statement_v2.AUTHORITY_ID_DOMAIN,
        AUTHORITY_PREIMAGE_SCOPE,
        leaf_source.LOCAL_AUTHORITY_DIGEST_KIND,
        AUTHORITY_HASH_STEP_BASE,
    );
    errdefer authority_hash.deinit(allocator);
    var receipt_hash = try buildHashSchedule(
        allocator,
        RECEIPT_WORD_COUNT,
        statement_v2.RECEIPT_ID_DOMAIN,
        RECEIPT_PREIMAGE_SCOPE,
        leaf_source.LOCAL_RECEIPT_DIGEST_KIND,
        RECEIPT_HASH_STEP_BASE,
    );
    errdefer receipt_hash.deinit(allocator);
    return .{
        .allocator = allocator,
        .component_count = @intCast(component_descs.len),
        .infra_count = @intCast(infra_descs.len),
        .router_log_size = try traceLogSize(router_count),
        .router_rows = router_rows,
        .authority_hash = authority_hash,
        .receipt_hash = receipt_hash,
    };
}

fn fillRouterRows(
    destination: []RouterScheduleRowV1,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
) void {
    var at: usize = 0;
    // Format/schema limbs are shared by both canonical preimages.
    putSharedConstant(&destination[at], statement_v2.FORMAT_VERSION, 0, 0);
    at += 1;
    putSharedConstant(&destination[at], 0, 1, 1);
    at += 1;
    putSharedConstant(&destination[at], statement_v2.SCHEMA_VERSION, 2, 2);
    at += 1;
    putSharedConstant(&destination[at], 0, 3, 3);
    at += 1;

    // Authority-only geometry counts.
    at = putU32Constant(
        destination,
        at,
        @intCast(component_descs.len),
        AUTHORITY_PREIMAGE_SCOPE,
        4,
    );
    at = putU32Constant(
        destination,
        at,
        @intCast(infra_descs.len),
        AUTHORITY_PREIMAGE_SCOPE,
        6,
    );

    const base = segment_v2.fixed_layout.base_statement;
    const entry_pc = base + span.canonical_layout.entry_state_start +
        span.canonical_layout.machine_state_pc_start_offset;
    const exit_pc = base + span.canonical_layout.exit_state_start +
        span.canonical_layout.machine_state_pc_start_offset;
    const clock = base + span.canonical_layout.executed_cycle_count_start;
    inline for (0..2) |limb| {
        destination[at] = statementRawRow(
            leaf_v2.WIRE_SCOPE,
            entry_pc + limb,
            AUTHORITY_PREIMAGE_SCOPE,
            8 + limb,
        );
        at += 1;
    }
    inline for (0..2) |limb| {
        destination[at] = statementRawRow(
            leaf_v2.WIRE_SCOPE,
            exit_pc + limb,
            AUTHORITY_PREIMAGE_SCOPE,
            10 + limb,
        );
        at += 1;
    }
    inline for (0..2) |limb| {
        destination[at] = statementRawRow(
            leaf_v2.WIRE_SCOPE,
            clock + limb,
            AUTHORITY_PREIMAGE_SCOPE,
            12 + limb,
        );
        at += 1;
    }

    // One authenticated wire-id value feeds both hashes and the public link.
    for (0..DIGEST_WORD_COUNT) |limb| {
        destination[at] = statementTwoRawVerifierRow(
            leaf_v2.CONTEXT_SCOPE,
            leaf_v2.CONTEXT_SEGMENT_WIRE_ID_START + limb,
            AUTHORITY_PREIMAGE_SCOPE,
            14 + limb,
            RECEIPT_PREIMAGE_SCOPE,
            24 + limb,
            leaf_source.LOCAL_WIRE_DIGEST_KIND,
            limb,
            1,
        );
        at += 1;
    }

    var authority_index: usize = AUTHORITY_FIXED_WORD_COUNT;
    for (component_descs) |desc| {
        inline for (.{
            @intFromEnum(desc.family),
            desc.log_size,
            desc.n_rows,
            desc.n_columns,
        }) |value| {
            at = putU32Constant(
                destination,
                at,
                value,
                AUTHORITY_PREIMAGE_SCOPE,
                authority_index,
            );
            authority_index += 2;
        }
    }
    for (infra_descs) |desc| {
        inline for (.{
            @intFromEnum(desc.kind),
            desc.log_size,
            desc.n_rows,
            desc.n_columns,
        }) |value| {
            at = putU32Constant(
                destination,
                at,
                value,
                AUTHORITY_PREIMAGE_SCOPE,
                authority_index,
            );
            authority_index += 2;
        }
    }

    // Receipt position/range/role words are retained in the verified context.
    const receipt_context = [_]struct { source: usize, target: usize }{
        .{ .source = 5, .target = 4 },
        .{ .source = 6, .target = 5 },
        .{ .source = 7, .target = 6 },
        .{ .source = 8, .target = 7 },
        .{ .source = 9, .target = 8 },
        .{ .source = 10, .target = 9 },
        .{ .source = 11, .target = 10 },
        .{ .source = 12, .target = 11 },
        .{ .source = 13, .target = 12 },
        .{ .source = 14, .target = 14 },
    };
    for (receipt_context) |item| {
        destination[at] = statementRawRow(
            leaf_v2.CONTEXT_SCOPE,
            item.source,
            RECEIPT_PREIMAGE_SCOPE,
            item.target,
        );
        at += 1;
    }
    destination[at] = constantRawRow(0, RECEIPT_PREIMAGE_SCOPE, 13);
    at += 1;
    destination[at] = constantRawRow(0, RECEIPT_PREIMAGE_SCOPE, 15);
    at += 1;

    // The authority digest is verifier-derived by the authority hash and also
    // enters the receipt preimage and VerifiedLink projection.
    for (0..DIGEST_WORD_COUNT) |limb| {
        destination[at] = derivedRawVerifierRow(
            RECEIPT_PREIMAGE_SCOPE,
            16 + limb,
            leaf_source.LOCAL_AUTHORITY_DIGEST_KIND,
            limb,
            2,
        );
        at += 1;
    }

    const receipt_digests = [_]struct { source: usize, target: usize }{
        .{ .source = 57, .target = 32 },
        .{ .source = 65, .target = 40 },
        .{ .source = 73, .target = 48 },
        .{ .source = 97, .target = 56 },
    };
    for (receipt_digests) |item| {
        for (0..DIGEST_WORD_COUNT) |limb| {
            destination[at] = statementRawRow(
                leaf_v2.CONTEXT_SCOPE,
                item.source + limb,
                RECEIPT_PREIMAGE_SCOPE,
                item.target + limb,
            );
            at += 1;
        }
    }

    for (0..DIGEST_WORD_COUNT) |limb| {
        destination[at] = derivedVerifierRow(
            leaf_source.LOCAL_RECEIPT_DIGEST_KIND,
            limb,
            2,
        );
        at += 1;
    }
    for (0..DIGEST_WORD_COUNT) |limb| {
        destination[at] = verifierForwardRow(
            merkle_root_witness.COMMITMENT_INPUT_KIND,
            0,
            limb,
            leaf_source.PREPROCESSED_ROOT_KIND,
            0,
            limb,
        );
        at += 1;
    }
    std.debug.assert(at == destination.len);
    std.debug.assert(authority_index ==
        AUTHORITY_FIXED_WORD_COUNT +
            WORDS_PER_DESCRIPTOR * (component_descs.len + infra_descs.len));
}

fn putSharedConstant(
    destination: *RouterScheduleRowV1,
    value: u32,
    authority_index: usize,
    receipt_index: usize,
) void {
    destination.* = .{
        .constant_source_mask = 1,
        .raw_a_sink_mask = 1,
        .raw_b_sink_mask = 1,
        .constant_value = value,
        .raw_a_scope = AUTHORITY_PREIMAGE_SCOPE,
        .raw_a_index = @intCast(authority_index),
        .raw_b_scope = RECEIPT_PREIMAGE_SCOPE,
        .raw_b_index = @intCast(receipt_index),
    };
}

fn putU32Constant(
    destination: []RouterScheduleRowV1,
    start: usize,
    value: u32,
    scope: u32,
    index: usize,
) usize {
    destination[start] = constantRawRow(value & 0xffff, scope, index);
    destination[start + 1] = constantRawRow(value >> 16, scope, index + 1);
    return start + 2;
}

fn constantRawRow(value: u32, scope: u32, index: usize) RouterScheduleRowV1 {
    return .{
        .constant_source_mask = 1,
        .raw_a_sink_mask = 1,
        .constant_value = value,
        .raw_a_scope = scope,
        .raw_a_index = @intCast(index),
    };
}

fn statementRawRow(
    source_scope: u32,
    source_index: usize,
    sink_scope: u32,
    sink_index: usize,
) RouterScheduleRowV1 {
    return .{
        .statement_source_mask = 1,
        .raw_a_sink_mask = 1,
        .statement_scope = source_scope,
        .statement_index = @intCast(source_index),
        .raw_a_scope = sink_scope,
        .raw_a_index = @intCast(sink_index),
    };
}

fn statementTwoRawVerifierRow(
    source_scope: u32,
    source_index: usize,
    raw_a_scope: u32,
    raw_a_index: usize,
    raw_b_scope: u32,
    raw_b_index: usize,
    sink_kind: u32,
    sink_limb: usize,
    sink_use_count: u32,
) RouterScheduleRowV1 {
    return .{
        .statement_source_mask = 1,
        .raw_a_sink_mask = 1,
        .raw_b_sink_mask = 1,
        .verifier_sink_mask = 1,
        .statement_scope = source_scope,
        .statement_index = @intCast(source_index),
        .raw_a_scope = raw_a_scope,
        .raw_a_index = @intCast(raw_a_index),
        .raw_b_scope = raw_b_scope,
        .raw_b_index = @intCast(raw_b_index),
        .sink_verifier_kind = sink_kind,
        .sink_index_1 = @intCast(sink_limb),
        .sink_use_count = sink_use_count,
    };
}

fn derivedRawVerifierRow(
    raw_scope: u32,
    raw_index: usize,
    sink_kind: u32,
    sink_limb: usize,
    sink_use_count: u32,
) RouterScheduleRowV1 {
    return .{
        .derived_source_mask = 1,
        .raw_a_sink_mask = 1,
        .verifier_sink_mask = 1,
        .raw_a_scope = raw_scope,
        .raw_a_index = @intCast(raw_index),
        .sink_verifier_kind = sink_kind,
        .sink_index_1 = @intCast(sink_limb),
        .sink_use_count = sink_use_count,
    };
}

fn derivedVerifierRow(
    sink_kind: u32,
    sink_limb: usize,
    sink_use_count: u32,
) RouterScheduleRowV1 {
    return .{
        .derived_source_mask = 1,
        .verifier_sink_mask = 1,
        .sink_verifier_kind = sink_kind,
        .sink_index_1 = @intCast(sink_limb),
        .sink_use_count = sink_use_count,
    };
}

fn verifierForwardRow(
    source_kind: u32,
    source_index_0: usize,
    source_index_1: usize,
    sink_kind: u32,
    sink_index_0: usize,
    sink_index_1: usize,
) RouterScheduleRowV1 {
    return .{
        .verifier_source_mask = 1,
        .verifier_sink_mask = 1,
        .source_verifier_kind = source_kind,
        .source_index_0 = @intCast(source_index_0),
        .source_index_1 = @intCast(source_index_1),
        .sink_verifier_kind = sink_kind,
        .sink_index_0 = @intCast(sink_index_0),
        .sink_index_1 = @intCast(sink_index_1),
        .sink_use_count = 1,
    };
}

fn buildHashSchedule(
    allocator: std.mem.Allocator,
    word_count: usize,
    domain: u32,
    scope: u32,
    digest_kind: u32,
    step_base: u32,
) !HashScheduleV1 {
    const row_count = std.math.divCeil(usize, word_count + 1, 8) catch
        return error.InvalidEthereumChildFieldProgram;
    const rows = try allocator.alloc(hash_witness.PreprocessedRow, row_count);
    errdefer allocator.free(rows);
    for (rows, 0..) |*row, step| {
        row.* = try hash_witness.expectedRow(word_count, row_count, step);
        row.step = std.math.add(u32, step_base, row.step) catch
            return error.InvalidEthereumChildFieldProgram;
    }
    return .{
        .word_count = word_count,
        .log_size = try hash_witness.traceLogSize(row_count),
        .step_base = step_base,
        .domain = domain,
        .scope = scope,
        .digest_kind = digest_kind,
        .rows = rows,
    };
}

fn authorityWordCount(descriptor_count: usize) !usize {
    return std.math.add(
        usize,
        AUTHORITY_FIXED_WORD_COUNT,
        std.math.mul(usize, descriptor_count, WORDS_PER_DESCRIPTOR) catch
            return error.InvalidEthereumChildFieldProgram,
    ) catch return error.InvalidEthereumChildFieldProgram;
}

fn hashSchedulesEqual(left: *const HashScheduleV1, right: *const HashScheduleV1) bool {
    return left.word_count == right.word_count and
        left.log_size == right.log_size and left.step_base == right.step_base and
        left.domain == right.domain and left.scope == right.scope and
        left.digest_kind == right.digest_kind and
        metaSliceEqual(hash_witness.PreprocessedRow, left.rows, right.rows);
}

fn metaSliceEqual(comptime T: type, left: []const T, right: []const T) bool {
    if (left.len != right.len) return false;
    for (left, right) |left_value, right_value| {
        if (!std.meta.eql(left_value, right_value)) return false;
    }
    return true;
}

fn traceLogSize(row_count: usize) !u32 {
    const padded = std.math.ceilPowerOfTwo(usize, @max(row_count, 1)) catch
        return error.InvalidEthereumChildFieldProgram;
    return @max(@as(u32, 4), std.math.log2_int(usize, padded));
}

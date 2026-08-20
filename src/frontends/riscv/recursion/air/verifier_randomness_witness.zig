//! Verifier-owned schedule and prepared direct witness for universal row 9.
//!
//! Schedule admission and witness materialization are cold, linear passes.
//! The prepared executor writes final padded SoA storage directly with no hot
//! allocation, hashing, indirect dispatch, or fallible work after preflight.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const digest = @import("../../air/lang/digest.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("verifier_randomness.zig");
const proof_kind_mod = @import("proof_kind.zig");
const schedule = @import("verifier_schedule.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const SEGMENT_VERIFIER_ID: u32 = 0;
pub const LEFT_RECURSION_VERIFIER_ID: u32 = 1;
pub const RIGHT_RECURSION_VERIFIER_ID: u32 = 2;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const WORD_COUNT = component.WORD_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const Draw = [WORD_COUNT]M31;

pub const Kind = enum(u32) {
    composition_randomness = 1,
    oods_point = 2,
    deep_randomness = 3,
    fri_alpha = 4,
    raw_query = 5,

    pub fn semanticUseCount(self: Kind) u32 {
        return if (self == .oods_point) 2 else 1;
    }
};

pub const DrawDescriptor = struct {
    kind: Kind,
    item_base: u32,
    query_items: bool,
    word_count: u32,
};

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-verifier-randomness-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "f66d61438144bc2a3b971200b5ad61d48c5d4602460d5435b1cef9e505a41542";
pub const BINDING_DIGEST = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion verifier-randomness witness binding digest",
);

pub const Error = direct.Error || schedule.Error || component.ValidationError ||
    std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    BinaryDrawCountMismatch,
    BindingMismatch,
    InactiveWordNonZero,
    InvalidPreprocessedRow,
    InvalidWitnessRow,
    LogSizeOutOfRange,
    QueryBlockWidthOutOfRange,
    QueryIndexOverflow,
    RandomnessMissing,
    ScheduleAuthorityMismatch,
    SchemaMismatch,
    SegmentDrawCountMismatch,
};

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    main: [MAIN_COLUMN_COUNT]types.ValueId,
    preprocessed: [PREPROCESSED_COLUMN_COUNT]types.ValueId,
    parameters: [component.PARAMETER_COUNT]types.ValueId,

    pub fn canonical(definition: *const component.Definition) !Binding {
        try definition.validate();
        return .{
            .format_version = BINDING_FORMAT_VERSION,
            .semantic_format_version = digest.typed_effect_format_version,
            .semantic_digest = component.SEMANTIC_DIGEST,
            .main = definition.main.physical(),
            .preprocessed = definition.preprocessed.physical(),
            .parameters = definition.parameters.physical(),
        };
    }

    pub fn identityDigest(self: *const Binding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(BINDING_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hash.update(&self.semantic_digest);
        for (self.main) |value| hashInt(&hash, u32, @intFromEnum(value));
        for (self.preprocessed) |value| hashInt(&hash, u32, @intFromEnum(value));
        for (self.parameters) |value| hashInt(&hash, u32, @intFromEnum(value));
        return hash.finalResult();
    }
};

pub const PreprocessedRow = struct {
    row_mask: u32,
    segment_mask: u32,
    binary_mask: u32,
    verifier_id: u32,
    sequence: u32,
    tag: u32,
    args: [4]u32,
    kind: Kind,
    item_base: u32,
    query_items: u32,
    multiplicities: [WORD_COUNT]u32,
    draw_index: u32,

    pub fn values(self: PreprocessedRow) [PREPROCESSED_COLUMN_COUNT]M31 {
        return .{
            M31.fromU64(self.row_mask),
            M31.fromU64(self.segment_mask),
            M31.fromU64(self.binary_mask),
            M31.fromU64(self.verifier_id),
            M31.fromU64(self.sequence),
            M31.fromU64(self.tag),
            M31.fromU64(self.args[0]),
            M31.fromU64(self.args[1]),
            M31.fromU64(self.args[2]),
            M31.fromU64(self.args[3]),
            M31.fromU64(@intFromEnum(self.kind)),
            M31.fromU64(self.item_base),
            M31.fromU64(self.query_items),
        } ++ mapU32ToM31(WORD_COUNT, self.multiplicities);
    }
};

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []PreprocessedRow,
    vm_randomness_count: usize,
    recursion_randomness_count: usize,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,

    pub fn init(
        allocator: std.mem.Allocator,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!Preprocessed {
        try validatePlans(vm, recursion);
        const vm_count = try randomnessCount(vm);
        const recursion_count = try randomnessCount(recursion);
        const row_count = std.math.add(
            usize,
            vm_count,
            std.math.mul(usize, recursion_count, 2) catch
                return error.ArithmeticOverflow,
        ) catch return error.ArithmeticOverflow;
        const log_size = try traceLogSize(row_count);
        const rows = try allocator.alloc(PreprocessedRow, row_count);
        errdefer allocator.free(rows);
        var cursor: usize = 0;
        try appendRows(rows, &cursor, vm, SEGMENT_VERIFIER_ID, 1, 0);
        try appendRows(rows, &cursor, recursion, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        try appendRows(rows, &cursor, recursion, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
        std.debug.assert(cursor == rows.len);
        for (rows) |row| try validatePreprocessedRow(row);
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .vm_randomness_count = vm_count,
            .recursion_randomness_count = recursion_count,
            .vm_schedule_digest = vm.authority_digest,
            .recursion_schedule_digest = recursion.authority_digest,
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const Preprocessed,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!void {
        try validatePlans(vm, recursion);
        const vm_count = try randomnessCount(vm);
        const recursion_count = try randomnessCount(recursion);
        if (!std.meta.eql(self.vm_schedule_digest, vm.authority_digest) or
            !std.meta.eql(self.recursion_schedule_digest, recursion.authority_digest) or
            self.vm_randomness_count != vm_count or
            self.recursion_randomness_count != recursion_count)
        {
            return error.ScheduleAuthorityMismatch;
        }
        const expected_len = std.math.add(
            usize,
            vm_count,
            std.math.mul(usize, recursion_count, 2) catch
                return error.ArithmeticOverflow,
        ) catch return error.ArithmeticOverflow;
        if (self.rows.len != expected_len or
            self.log_size != try traceLogSize(expected_len))
        {
            return error.ScheduleAuthorityMismatch;
        }
        var cursor: usize = 0;
        try compareRows(self.rows, &cursor, vm, SEGMENT_VERIFIER_ID, 1, 0);
        try compareRows(self.rows, &cursor, recursion, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        try compareRows(self.rows, &cursor, recursion, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
        if (cursor != self.rows.len) return error.ScheduleAuthorityMismatch;
    }
};

pub const DrawWitness = union(enum) {
    segment_leaf: []const Draw,
    binary_node: struct {
        left: []const Draw,
        right: []const Draw,
    },
    empty_leaf,

    pub fn proofKind(self: DrawWitness) ProofKind {
        return switch (self) {
            .segment_leaf => .segment_leaf,
            .binary_node => .binary_node,
            .empty_leaf => .empty_leaf,
        };
    }
};

pub const MainRow = struct {
    enabler: u32,
    outputs: Draw,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{M31.fromU64(self.enabler)} ++ self.outputs;
    }
};

pub const MainWitness = struct {
    allocator: std.mem.Allocator,
    rows: []MainRow,
    proof_kind: ProofKind,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,

    pub fn init(
        allocator: std.mem.Allocator,
        preprocessing: *const Preprocessed,
        draws: DrawWitness,
    ) Error!MainWitness {
        try validateDrawCounts(preprocessing, draws);
        const rows = try allocator.alloc(MainRow, preprocessing.rows.len);
        errdefer allocator.free(rows);
        for (rows, preprocessing.rows) |*target, metadata| {
            const maybe_draw = drawAt(draws, metadata);
            target.* = .{
                .enabler = @intFromBool(maybe_draw != null),
                .outputs = maybe_draw orelse [_]M31{M31.zero()} ** WORD_COUNT,
            };
            try validateMainRow(target.*);
        }
        return .{
            .allocator = allocator,
            .rows = rows,
            .proof_kind = draws.proofKind(),
            .vm_schedule_digest = preprocessing.vm_schedule_digest,
            .recursion_schedule_digest = preprocessing.recursion_schedule_digest,
        };
    }

    pub fn deinit(self: *MainWitness) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const MainWitness,
        preprocessing: *const Preprocessed,
    ) Error!void {
        if (!std.meta.eql(self.vm_schedule_digest, preprocessing.vm_schedule_digest) or
            !std.meta.eql(
                self.recursion_schedule_digest,
                preprocessing.recursion_schedule_digest,
            ) or self.rows.len != preprocessing.rows.len)
        {
            return error.ScheduleAuthorityMismatch;
        }
        for (self.rows, preprocessing.rows) |row, metadata| {
            try validateMainRow(row);
            const active = switch (self.proof_kind) {
                .segment_leaf => metadata.verifier_id == SEGMENT_VERIFIER_ID,
                .binary_node => metadata.verifier_id != SEGMENT_VERIFIER_ID,
                .empty_leaf => false,
            };
            if (row.enabler != @intFromBool(active))
                return error.InvalidWitnessRow;
        }
    }
};

pub const Executor = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const component.Definition,
        supplied: *const Binding,
    ) Error!Executor {
        const expected = try Binding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*)) return error.BindingMismatch;
        const actual = supplied.identityDigest();
        if (!std.mem.eql(u8, &actual, &BINDING_DIGEST))
            return error.BindingMismatch;
        return .{ .binding = supplied.*, .binding_digest = actual };
    }

    pub fn generatePreprocessedInto(
        self: *const Executor,
        preprocessing: *const Preprocessed,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!void {
        try preprocessing.validateAgainst(vm, recursion);
        return direct.generateMainInto(
            M31,
            PreprocessedRow,
            PREPROCESSED_COLUMN_COUNT,
            columns,
            preprocessing.rows,
            preprocessing.log_size,
            M31.zero(),
            self,
            validatePreprocessedRow,
            writePreprocessedRow,
        );
    }

    pub fn generateMainInto(
        self: *const Executor,
        witness: *const MainWitness,
        preprocessing: *const Preprocessed,
        columns: *[MAIN_COLUMN_COUNT][]M31,
    ) Error!void {
        try witness.validateAgainst(preprocessing);
        return direct.generateMainInto(
            M31,
            MainRow,
            MAIN_COLUMN_COUNT,
            columns,
            witness.rows,
            preprocessing.log_size,
            M31.zero(),
            self,
            validateMainRow,
            writeMainRow,
        );
    }
};

pub fn logicalInputs(
    main: MainRow,
    preprocessing: PreprocessedRow,
    kind: ProofKind,
) [component.LOGICAL_INPUT_COUNT]M31 {
    const selectors = kind.selectors();
    return main.values() ++ preprocessing.values() ++ .{
        selectors[0],
        selectors[1],
    };
}

fn validatePlans(vm: *const schedule.Plan, recursion: *const schedule.Plan) Error!void {
    try vm.validate();
    try recursion.validate();
    if (vm.schema != .vm or recursion.schema != .recursion)
        return error.SchemaMismatch;
}

fn randomnessCount(plan: *const schedule.Plan) Error!usize {
    var count: usize = 0;
    for (plan.steps) |step| {
        if (try descriptorFor(step) != null)
            count = std.math.add(usize, count, 1) catch return error.ArithmeticOverflow;
    }
    if (count == 0) return error.RandomnessMissing;
    return count;
}

fn appendRows(
    destination: []PreprocessedRow,
    cursor: *usize,
    plan: *const schedule.Plan,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    var draw_index: u32 = 0;
    for (plan.steps, 0..) |step, sequence| {
        const descriptor = try descriptorFor(step) orelse continue;
        destination[cursor.*] = rowFor(
            step,
            @intCast(sequence),
            descriptor,
            draw_index,
            verifier_id,
            segment_mask,
            binary_mask,
        );
        cursor.* += 1;
        draw_index += 1;
    }
}

fn compareRows(
    actual: []const PreprocessedRow,
    cursor: *usize,
    plan: *const schedule.Plan,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    var draw_index: u32 = 0;
    for (plan.steps, 0..) |step, sequence| {
        const descriptor = try descriptorFor(step) orelse continue;
        const expected = rowFor(
            step,
            @intCast(sequence),
            descriptor,
            draw_index,
            verifier_id,
            segment_mask,
            binary_mask,
        );
        if (cursor.* >= actual.len or !std.meta.eql(actual[cursor.*], expected))
            return error.ScheduleAuthorityMismatch;
        cursor.* += 1;
        draw_index += 1;
    }
}

fn rowFor(
    step: schedule.VerifierStep,
    sequence: u32,
    descriptor: DrawDescriptor,
    draw_index: u32,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) PreprocessedRow {
    const encoded = step.encode();
    var multiplicities: [WORD_COUNT]u32 = undefined;
    for (&multiplicities, 0..) |*multiplicity, word| {
        multiplicity.* = descriptor.kind.semanticUseCount() *
            @intFromBool(word < descriptor.word_count);
    }
    return .{
        .row_mask = 1,
        .segment_mask = segment_mask,
        .binary_mask = binary_mask,
        .verifier_id = verifier_id,
        .sequence = sequence,
        .tag = encoded.tag,
        .args = encoded.args,
        .kind = descriptor.kind,
        .item_base = descriptor.item_base,
        .query_items = @intFromBool(descriptor.query_items),
        .multiplicities = multiplicities,
        .draw_index = draw_index,
    };
}

fn descriptorFor(step: schedule.VerifierStep) Error!?DrawDescriptor {
    const secure = struct {
        fn make(kind: Kind, item_base: u32) DrawDescriptor {
            return .{
                .kind = kind,
                .item_base = item_base,
                .query_items = false,
                .word_count = 4,
            };
        }
    }.make;
    return switch (step) {
        .draw_composition_randomness => secure(.composition_randomness, 0),
        .draw_oods_point => secure(.oods_point, 0),
        .draw_deep_randomness => secure(.deep_randomness, 0),
        .draw_fri_alpha => |draw| secure(.fri_alpha, draw.layer),
        .draw_query_block => |draw| blk: {
            if (draw.query_count == 0 or draw.query_count > WORD_COUNT)
                return error.QueryBlockWidthOutOfRange;
            _ = std.math.add(u32, draw.first_query, draw.query_count) catch
                return error.QueryIndexOverflow;
            break :blk .{
                .kind = .raw_query,
                .item_base = draw.first_query,
                .query_items = true,
                .word_count = draw.query_count,
            };
        },
        else => null,
    };
}

fn validateDrawCounts(preprocessing: *const Preprocessed, draws: DrawWitness) Error!void {
    switch (draws) {
        .segment_leaf => |segment| if (segment.len != preprocessing.vm_randomness_count)
            return error.SegmentDrawCountMismatch,
        .binary_node => |binary| if (binary.left.len != preprocessing.recursion_randomness_count or
            binary.right.len != preprocessing.recursion_randomness_count) return error.BinaryDrawCountMismatch,
        .empty_leaf => {},
    }
}

fn drawAt(draws: DrawWitness, row: PreprocessedRow) ?Draw {
    return switch (draws) {
        .segment_leaf => |segment| if (row.verifier_id == SEGMENT_VERIFIER_ID)
            segment[row.draw_index]
        else
            null,
        .binary_node => |binary| switch (row.verifier_id) {
            LEFT_RECURSION_VERIFIER_ID => binary.left[row.draw_index],
            RIGHT_RECURSION_VERIFIER_ID => binary.right[row.draw_index],
            else => null,
        },
        .empty_leaf => null,
    };
}

fn traceLogSize(row_count: usize) Error!u32 {
    const padded = std.math.ceilPowerOfTwo(usize, @max(row_count, 1)) catch
        return error.ArithmeticOverflow;
    const log_size: u32 = @max(MIN_LOG_SIZE, std.math.log2_int(usize, padded));
    if (log_size > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return log_size;
}

fn validatePreprocessedRow(row: PreprocessedRow) direct.Error!void {
    if (row.row_mask != 1 or row.segment_mask > 1 or row.binary_mask > 1 or
        row.segment_mask + row.binary_mask != 1 or row.query_items > 1 or
        row.verifier_id >= m31.Modulus or row.sequence >= m31.Modulus or
        @intFromEnum(row.kind) >= m31.Modulus or row.item_base >= m31.Modulus or
        row.tag >= m31.Modulus or row.args[0] >= m31.Modulus or
        row.args[1] >= m31.Modulus or row.args[2] >= m31.Modulus or
        row.args[3] >= m31.Modulus)
    {
        return error.InvalidTraceRow;
    }
    const expected = descriptorForStepEncoding(row) orelse return error.InvalidTraceRow;
    if (!std.meta.eql(expected, DrawDescriptor{
        .kind = row.kind,
        .item_base = row.item_base,
        .query_items = row.query_items == 1,
        .word_count = wordCount(row.multiplicities, row.kind),
    })) return error.InvalidTraceRow;
    for (row.multiplicities, 0..) |multiplicity, word| {
        const expected_multiplicity = expected.kind.semanticUseCount() *
            @intFromBool(word < expected.word_count);
        if (multiplicity != expected_multiplicity) return error.InvalidTraceRow;
    }
}

fn descriptorForStepEncoding(row: PreprocessedRow) ?DrawDescriptor {
    return switch (row.tag) {
        9 => if (allZero(row.args)) .{
            .kind = .composition_randomness,
            .item_base = 0,
            .query_items = false,
            .word_count = 4,
        } else null,
        10 => if (allZero(row.args)) .{
            .kind = .oods_point,
            .item_base = 0,
            .query_items = false,
            .word_count = 4,
        } else null,
        16 => if (allZero(row.args)) .{
            .kind = .deep_randomness,
            .item_base = 0,
            .query_items = false,
            .word_count = 4,
        } else null,
        18 => if (row.args[1] == 0 and row.args[2] == 0 and row.args[3] == 0) .{
            .kind = .fri_alpha,
            .item_base = row.args[0],
            .query_items = false,
            .word_count = 4,
        } else null,
        21 => if (row.args[2] > 0 and row.args[2] <= WORD_COUNT and row.args[3] == 0) .{
            .kind = .raw_query,
            .item_base = row.args[1],
            .query_items = true,
            .word_count = row.args[2],
        } else null,
        else => null,
    };
}

fn wordCount(multiplicities: [WORD_COUNT]u32, kind: Kind) u32 {
    var result: u32 = 0;
    const unit = kind.semanticUseCount();
    for (multiplicities) |multiplicity| {
        if (multiplicity != unit) break;
        result += 1;
    }
    return result;
}

fn allZero(values: [4]u32) bool {
    for (values) |value| if (value != 0) return false;
    return true;
}

fn mapU32ToM31(comptime count: usize, values: [count]u32) [count]M31 {
    var result: [count]M31 = undefined;
    for (&result, values) |*target, value| target.* = M31.fromU64(value);
    return result;
}

fn validateMainRow(row: MainRow) direct.Error!void {
    if (row.enabler > 1) return error.InvalidTraceRow;
    if (row.enabler == 0) for (row.outputs) |word| if (!word.isZero())
        return error.InvalidTraceRow;
}

fn writePreprocessedRow(
    columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    logical_row: usize,
    row: PreprocessedRow,
) void {
    for (columns, row.values()) |column, value| column[logical_row] = value;
}

fn writeMainRow(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    logical_row: usize,
    row: MainRow,
) void {
    for (columns, row.values()) |column, value| column[logical_row] = value;
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

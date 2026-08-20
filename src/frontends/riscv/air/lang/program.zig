//! Whole-program records stored beside the canonical expression DAG.

const std = @import("std");
const source = @import("source.zig");
const types = @import("types.zig");

pub const RangeError = error{ReferenceRangeOverflow};

/// A canonical range into one of the program's arena-owned item pools.
pub const RefRange = struct {
    start: u32,
    len: u32,

    pub fn init(start: usize, len: usize) RangeError!RefRange {
        return .{
            .start = std.math.cast(u32, start) orelse
                return error.ReferenceRangeOverflow,
            .len = std.math.cast(u32, len) orelse
                return error.ReferenceRangeOverflow,
        };
    }

    pub fn slice(
        self: RefRange,
        values: []const types.ValueId,
    ) ?[]const types.ValueId {
        const start: usize = self.start;
        const len: usize = self.len;
        const end = std.math.add(usize, start, len) catch return null;
        if (end > values.len) return null;
        return values[start..end];
    }
};

/// A canonical range into an arena-owned record pool. Unlike `RefRange`, this
/// range is intentionally untyped: the four fields of `FunctionBody` address
/// different record kinds but share one compact, wire-stable representation.
pub const ItemRange = struct {
    start: u32,
    len: u32,

    pub fn init(start: usize, len: usize) RangeError!ItemRange {
        return .{
            .start = std.math.cast(u32, start) orelse
                return error.ReferenceRangeOverflow,
            .len = std.math.cast(u32, len) orelse
                return error.ReferenceRangeOverflow,
        };
    }

    pub fn end(self: ItemRange) ?usize {
        return std.math.add(usize, self.start, self.len) catch null;
    }

    pub fn contains(self: ItemRange, index: usize) bool {
        const range_end = self.end() orelse return false;
        return index >= self.start and index < range_end;
    }
};

pub const ConstraintCategory = enum {
    semantic,
    materialization,
    type_range,
    hint_binding,
    boundary,
    transition,
    relation_transition,
};

pub const Constraint = struct {
    /// Present only for an explicitly sealed function body. Legacy/root
    /// constraints remain ownerless and retain their frozen identity bytes.
    owner: ?types.FunctionId,
    name: types.NameId,
    root: types.ValueId,
    gate: ?types.ValueId,
    category: ConstraintCategory,
    source_span: source.SourceSpan,
};

pub const HintOutput = struct {
    hint: types.HintId,
    index: u16,
};

pub const CallOutput = struct {
    call: types.CallId,
    index: u16,
};

pub const Hint = struct {
    owner: ?types.FunctionId,
    recipe: types.HintRecipeId,
    inputs: RefRange,
    outputs: RefRange,
    activation: ?types.ValueId,
    bindings: ?RefRange,
    source_span: source.SourceSpan,
};

pub const HintBindingTarget = union(enum) {
    constraint: types.ConstraintId,
    effect: types.EffectId,
};

/// A checked dataflow path from one hint output to a proof-enforced target.
/// Path values are stored output-first and end at the target root/value.
pub const HintBinding = struct {
    output_index: u16,
    target: HintBindingTarget,
    path: RefRange,
};

pub const EffectKind = enum(u8) {
    program_fetch = 0,
    register_read = 1,
    register_write = 2,
    memory_read = 3,
    memory_write = 4,
    range_request = 5,
    state_consume = 6,
    state_produce = 7,
    component_call = 8,
    public_consume = 9,
    public_produce = 10,
    /// A fixed-table bytewise operation request. Kept distinct from component
    /// calls and range requests so serialized semantics cannot disguise the
    /// relation that enforces an ALU result.
    bitwise_request = 11,
};

/// Version-pinned relation ABI carried by an authored effect.
///
/// `EffectKind` records machine meaning; this binding records the exact proof
/// relation that enforces it.  Keeping both is necessary because several
/// semantic kinds share a relation and `range_request` is schema-polymorphic.
pub const RelationBinding = struct {
    schema: types.RelationSchemaId,
    schema_version: u16,
    role: types.RelationRole,
};

pub const Effect = struct {
    owner: ?types.FunctionId,
    kind: EffectKind,
    /// Null only for non-relation effects and the explicitly provisional
    /// migration surface.  Reviewed relation constructors always populate it.
    binding: ?RelationBinding,
    values: RefRange,
    liveness: ?types.ValueId,
    access_ordinal: ?u8,
    source_span: source.SourceSpan,
};

/// The two closed control-transfer polynomials currently admitted by the
/// RISC-V program relation. `jump` uses the JAL tuple's `rs1` field as its
/// signed offset. `branch` uses the branch tuple's `operand` field and names
/// the direct constraint proving the committed decision bit.
pub const ProgramControlTargetKind = union(enum(u8)) {
    jump,
    branch: struct {
        condition: types.ValueId,
        condition_constraint: types.ConstraintId,
    },
};

/// Closed evidence for changing only the semantic type of one polynomial.
/// The target node must clone the source operation exactly; validation binds
/// the claimed type to the named proof premise rather than trusting a cast.
pub const RangeRefinementPremise = union(enum(u8)) {
    constraint_boolean: struct {
        constraint: types.ConstraintId,
    },
    fixed_table_field: struct {
        effect: types.EffectId,
        field_index: u8,
        liveness: types.ValueId,
    },
    aligned_control_target: struct {
        low: types.ValueId,
        high: types.ValueId,
        low_effect: types.EffectId,
        high_effect: types.EffectId,
        liveness: types.ValueId,
    },
    /// Zero-AIR evidence for a PC polynomial derived from fields already
    /// authenticated by the program lookup. The matching state retirement is
    /// checked separately by closed machine-use validation.
    program_control_target: struct {
        program_effect: types.EffectId,
        current_pc: types.ValueId,
        offset: types.ValueId,
        kind: ProgramControlTargetKind,
        liveness: types.ValueId,
    },
};

pub const RangeRefinement = struct {
    source: types.ValueId,
    target: types.ValueId,
    premise: RangeRefinementPremise,
    source_span: source.SourceSpan,
};

/// Zero-AIR authority for a control target that already occupies a committed
/// physical `.pc` column. The two scalar views are the compatibility
/// polynomial bindings for the physical current/target columns; the named
/// direct constraints prove the branch decision and exact gated target
/// equality. Whole-program validation restricts the physical target to the
/// adjacent state-produce event.
pub const CommittedProgramControlTargetProof = struct {
    program_effect: types.EffectId,
    current_pc: types.ValueId,
    current_pc_polynomial: types.ValueId,
    offset: types.ValueId,
    condition: types.ValueId,
    condition_constraint: types.ConstraintId,
    committed_target: types.ValueId,
    committed_target_polynomial: types.ValueId,
    target_constraint: types.ConstraintId,
    liveness: types.ValueId,
    source_span: source.SourceSpan,
};

/// Canonical ownership record for a closed preprocessed-table request. This
/// also authenticates direct, already-typed fields that need no alias node.
pub const FixedTableRequestProof = struct {
    effect: types.EffectId,
    liveness: types.ValueId,
    source_span: source.SourceSpan,
};

/// A semantic view of one existing polynomial. The target owns no column: its
/// operation is byte-for-byte identical to the source and its stronger type is
/// usable only at sites authenticated by the enclosing proof record.
pub const SemanticAlias = struct {
    source: types.ValueId,
    target: types.ValueId,
};

/// Closed authority for the production load/store component's conditional
/// three-access schedule. The exact memory-access relation is unchanged; this
/// record proves the two committed address selectors and four derived
/// clock/gap aliases used by the dynamic load/store branches.
pub const ConditionalAccessPlanProof = struct {
    first_effect: types.EffectId,
    aligned_range: types.EffectId,
    base_range: types.EffectId,
    active_source: types.ValueId,
    active: types.ValueId,
    store_source: types.ValueId,
    store_selector: types.ValueId,
    is_load: types.ValueId,
    instruction_clock: types.ValueId,
    second_clock: types.ValueId,
    memory_address: types.ValueId,
    shift_amount: types.ValueId,
    register_index: types.ValueId,
    word_source: types.ValueId,
    word_index: types.ValueId,
    base_low: types.ValueId,
    base_high: types.ValueId,
    source_address_constraint: types.ConstraintId,
    destination_address_constraint: types.ConstraintId,
    source_address: SemanticAlias,
    source_clock: SemanticAlias,
    source_gap: SemanticAlias,
    destination_address: SemanticAlias,
    destination_clock: SemanticAlias,
    destination_gap: SemanticAlias,
    source_span: source.SourceSpan,
};

/// Exact record ownership sealed by `functions.finish`. These ranges are
/// redundant with the owner IDs on records by design: validation checks both
/// directions so omission, overlap, and cross-owner mutations fail closed.
pub const FunctionBody = struct {
    constraints: ItemRange,
    effects: ItemRange,
    hints: ItemRange,
    calls: ItemRange,
};

pub const Function = struct {
    name: types.NameId,
    inputs: RefRange,
    outputs: RefRange,
    body: ?FunctionBody,
    source_span: source.SourceSpan,
    complete: bool,
};

pub const CallStrategy = enum {
    inline_expansion,
    relation_backed,
};

pub const Call = struct {
    caller: ?types.FunctionId,
    callee: types.FunctionId,
    strategy: CallStrategy,
    arguments: RefRange,
    outputs: RefRange,
    source_span: source.SourceSpan,
};

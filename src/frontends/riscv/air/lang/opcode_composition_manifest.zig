//! Fixed composition metadata compiled from the seventeen production opcode
//! authorities.
//!
//! The typed authority modules already pin execution, witness, direct-root,
//! and ordered-lookup identities.  This module projects only the facts needed
//! by component composition: canonical claim placement, mask geometry, main
//! and interaction widths, detailed-claim counts, and adapter order.  The
//! projection is pointer-free, contains no textual dispatch, and allocates
//! nothing.  Hot scalar accessors use one source-level inline family dispatch,
//! so every arm remains a compile-time constant just as in the retired tables;
//! cold consumers may borrow the enum-indexed descriptor array directly.
//!
//! This is a compatibility authority, not completion of E-022. Opcode-prefix
//! prover/verifier adapter order and placement now derive from this manifest;
//! infrastructure components and heterogeneous profile assembly still have
//! independent owners and must move before the handwritten composition layer
//! can be retired in full.

const std = @import("std");
const opcode_manifest = @import("../../opcode_manifest.zig");
const transcript_claims = @import("../transcript/claims.zig");
const typed_auipc = @import("typed_auipc_authority.zig");
const typed_base_alu_imm = @import("typed_base_alu_imm_authority.zig");
const typed_base_alu_reg = @import("typed_base_alu_reg_authority.zig");
const typed_branch_eq = @import("typed_branch_eq_authority.zig");
const typed_branch_lt = @import("typed_branch_lt_authority.zig");
const typed_div = @import("typed_div_authority.zig");
const typed_fence = @import("typed_fence_authority.zig");
const typed_jal = @import("typed_jal_authority.zig");
const typed_jalr = @import("typed_jalr_authority.zig");
const typed_load_store = @import("typed_load_store_authority.zig");
const typed_lt_imm = @import("typed_lt_imm_authority.zig");
const typed_lt_reg = @import("typed_lt_reg_authority.zig");
const typed_lui = @import("typed_lui_authority.zig");
const typed_mul = @import("typed_mul_authority.zig");
const typed_mulh = @import("typed_mulh_authority.zig");
const typed_shifts_imm = @import("typed_shifts_imm_authority.zig");
const typed_shifts_reg = @import("typed_shifts_reg_authority.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const Family = opcode_manifest.Family;
pub const TranscriptComponent = transcript_claims.Component;
pub const Digest = [32]u8;
pub const FAMILY_COUNT: usize = @typeInfo(Family).@"enum".fields.len;
pub const PREPROCESSED_COLUMNS_PER_SHARD: usize = 2;
pub const SECURE_COORDINATES_PER_CLAIM: usize = 4;
pub const ADAPTERS_PER_SHARD: usize = 2;

/// The ordinal is the commitment-tree index consumed by the component API.
pub const Tree = enum(u8) {
    preprocessed = 0,
    main = 1,
    interaction = 2,
};

pub const RowWindow = enum(u8) {
    current = 1,
    current_and_previous = 2,
};

pub const AdapterKind = enum(u8) {
    semantic = 0,
    lookup = 1,
};

pub const ADAPTER_ORDER = [ADAPTERS_PER_SHARD]AdapterKind{
    .semantic,
    .lookup,
};

/// One adapter's view of a commitment tree.  `columns == 0` is the canonical
/// empty view and still records the row-window policy expected by that adapter.
pub const TreeMask = struct {
    tree: Tree,
    /// Columns sampled by this adapter after commitment-tree alias resolution.
    columns: usize,
    /// Columns this adapter itself contributes to the PCS opening request.
    /// Lookup adapters borrow semantic main columns, so their main-tree view is
    /// nonempty while their declaration is canonically empty.
    declared_columns: usize,
    window: RowWindow,

    pub fn sampledValues(self: TreeMask) error{SampleCountOverflow}!usize {
        return std.math.mul(
            usize,
            self.columns,
            @intFromEnum(self.window),
        ) catch error.SampleCountOverflow;
    }
};

pub const AdapterMasks = struct {
    preprocessed: TreeMask,
    main: TreeMask,
    interaction: TreeMask,
};

pub const ClaimGeometry = struct {
    transcript_component: TranscriptComponent,
    /// One QM31 sum per compatibility LogUp batch.
    detailed_claims: usize,
    /// All shard-local sums fold into one canonical family claim slot.
    canonical_claim_slots: usize,
};

/// Complete fixed-shape projection of one authenticated typed authority.
pub const Descriptor = struct {
    family: Family,
    authority_digest: Digest,
    claim: ClaimGeometry,
    main_columns: usize,
    direct_constraints: usize,
    lookup_events: usize,
    lookup_batch_size: usize,
    lookup_batches: usize,
    interaction_columns: usize,
    semantic_masks: AdapterMasks,
    lookup_masks: AdapterMasks,
    adapters: [ADAPTERS_PER_SHARD]AdapterKind,
};

/// Family-enum order is the stable O(1) lookup table used by production
/// geometry consumers.  It is compiled from the pinned authority modules.
pub const BY_FAMILY: [FAMILY_COUNT]Descriptor = blk: {
    var result: [FAMILY_COUNT]Descriptor = undefined;
    for (0..FAMILY_COUNT) |index| {
        const family: Family = @enumFromInt(index);
        result[index] = descriptorFor(family);
    }
    break :blk result;
};

/// Proof-transcript order is derived from each descriptor's canonical claim
/// slot.  It deliberately differs from `Family` enum order.
pub const TRANSCRIPT_ORDER: [FAMILY_COUNT]Family = blk: {
    var result: [FAMILY_COUNT]Family = undefined;
    var occupied = [_]bool{false} ** FAMILY_COUNT;
    for (BY_FAMILY) |item| {
        const index: usize = @intFromEnum(item.claim.transcript_component);
        if (index >= FAMILY_COUNT or occupied[index])
            @compileError("typed opcode transcript placement is not a permutation");
        result[index] = item.family;
        occupied[index] = true;
    }
    for (occupied) |present| {
        if (!present)
            @compileError("typed opcode transcript placement omits a claim slot");
    }
    break :blk result;
};

pub const MAX_MAIN_COLUMNS: usize = maximumField(.main_columns);
pub const MAX_DIRECT_CONSTRAINTS: usize = maximumField(.direct_constraints);
pub const MAX_LOOKUP_EVENTS: usize = maximumField(.lookup_events);
pub const MAX_LOOKUP_BATCHES: usize = maximumField(.lookup_batches);
pub const MAX_INTERACTION_COLUMNS: usize = maximumField(.interaction_columns);

pub inline fn descriptor(family: Family) *const Descriptor {
    return &BY_FAMILY[@intFromEnum(family)];
}

pub inline fn mainColumnCount(family: Family) usize {
    return scalarField(.main_columns, family);
}

pub inline fn directConstraintCount(family: Family) usize {
    return scalarField(.direct_constraints, family);
}

pub inline fn lookupEventCount(family: Family) usize {
    return scalarField(.lookup_events, family);
}

pub inline fn lookupBatchSize(family: Family) usize {
    return scalarField(.lookup_batch_size, family);
}

pub inline fn lookupBatchCount(family: Family) usize {
    return scalarField(.lookup_batches, family);
}

pub inline fn interactionColumnCount(family: Family) usize {
    return scalarField(.interaction_columns, family);
}

pub inline fn semanticMasks(family: Family) *const AdapterMasks {
    return &BY_FAMILY[@intFromEnum(family)].semantic_masks;
}

pub inline fn lookupMasks(family: Family) *const AdapterMasks {
    return &BY_FAMILY[@intFromEnum(family)].lookup_masks;
}

pub inline fn transcriptComponent(family: Family) TranscriptComponent {
    return switch (family) {
        inline else => |comptime_family| transcriptComponentFor(comptime_family),
    };
}

pub inline fn compositionIndex(family: Family) usize {
    return @intFromEnum(transcriptComponent(family));
}

pub fn familyAtCompositionIndex(index: usize) ?Family {
    return if (index < TRANSCRIPT_ORDER.len) TRANSCRIPT_ORDER[index] else null;
}

/// Zero-allocation, fail-atomic placement authority for a declaration-ordered
/// opcode shard prefix.  This is the migration seam for the duplicated
/// prover/verifier offset arithmetic; consumers can adopt it without changing
/// component types or transcript order.
pub const PlacementCursor = struct {
    component_count: usize = 0,
    adapter_count: usize = 0,
    preprocessed_columns: usize = 0,
    main_columns: usize = 0,
    interaction_columns: usize = 0,

    pub const Error = error{
        AdapterIndexOverflow,
        ColumnIndexOverflow,
        ComponentIndexOverflow,
        MainColumnCountMismatch,
    };

    pub const Placement = struct {
        family: Family,
        component_index: usize,
        semantic_adapter_index: usize,
        lookup_adapter_index: usize,
        is_first_column: usize,
        is_active_column: usize,
        main_column_offset: usize,
        interaction_column_offset: usize,
        main_columns: usize,
        interaction_columns: usize,
    };

    pub fn append(
        self: *PlacementCursor,
        family: Family,
        declared_main_columns: usize,
    ) Error!Placement {
        const item = descriptor(family);
        if (declared_main_columns != item.main_columns)
            return error.MainColumnCountMismatch;

        const component_index = self.component_count;
        const semantic_adapter_index = self.adapter_count;
        const lookup_adapter_index = std.math.add(
            usize,
            semantic_adapter_index,
            1,
        ) catch return error.AdapterIndexOverflow;
        const is_first_column = self.preprocessed_columns;
        const is_active_column = std.math.add(
            usize,
            is_first_column,
            1,
        ) catch return error.ColumnIndexOverflow;
        const next_component_count = std.math.add(
            usize,
            component_index,
            1,
        ) catch return error.ComponentIndexOverflow;
        const next_adapter_count = std.math.add(
            usize,
            self.adapter_count,
            ADAPTERS_PER_SHARD,
        ) catch return error.AdapterIndexOverflow;
        const next_preprocessed = std.math.add(
            usize,
            self.preprocessed_columns,
            PREPROCESSED_COLUMNS_PER_SHARD,
        ) catch return error.ColumnIndexOverflow;
        const next_main = std.math.add(
            usize,
            self.main_columns,
            item.main_columns,
        ) catch return error.ColumnIndexOverflow;
        const next_interaction = std.math.add(
            usize,
            self.interaction_columns,
            item.interaction_columns,
        ) catch return error.ColumnIndexOverflow;

        const placement = Placement{
            .family = family,
            .component_index = component_index,
            .semantic_adapter_index = semantic_adapter_index,
            .lookup_adapter_index = lookup_adapter_index,
            .is_first_column = is_first_column,
            .is_active_column = is_active_column,
            .main_column_offset = self.main_columns,
            .interaction_column_offset = self.interaction_columns,
            .main_columns = item.main_columns,
            .interaction_columns = item.interaction_columns,
        };
        self.* = .{
            .component_count = next_component_count,
            .adapter_count = next_adapter_count,
            .preprocessed_columns = next_preprocessed,
            .main_columns = next_main,
            .interaction_columns = next_interaction,
        };
        return placement;
    }
};

/// Compile-time binding from a proof family to its admitted executable typed
/// authority.  No runtime module or string lookup is possible.
pub fn authorityFor(comptime family: Family) type {
    return switch (family) {
        .base_alu_reg => typed_base_alu_reg,
        .base_alu_imm => typed_base_alu_imm,
        .shifts_reg => typed_shifts_reg,
        .shifts_imm => typed_shifts_imm,
        .lt_reg => typed_lt_reg,
        .lt_imm => typed_lt_imm,
        .branch_eq => typed_branch_eq,
        .branch_lt => typed_branch_lt,
        .lui => typed_lui,
        .auipc => typed_auipc,
        .jalr => typed_jalr,
        .jal => typed_jal,
        .load_store => typed_load_store,
        .mul => typed_mul,
        .mulh => typed_mulh,
        .div => typed_div,
        .fence => typed_fence,
    };
}

fn descriptorFor(comptime family: Family) Descriptor {
    const Authority = authorityFor(family);
    const lookup_events: usize = Authority.LOOKUP_COUNT;
    const batch_size: usize = Authority.LOOKUP_BATCH_SIZE;
    const batches = (lookup_events + batch_size - 1) / batch_size;
    const interaction_columns = batches * SECURE_COORDINATES_PER_CLAIM;
    const main_columns: usize = Authority.MAIN_COLUMN_COUNT;
    const semantic_masks = AdapterMasks{
        .preprocessed = .{
            .tree = .preprocessed,
            .columns = 1,
            .declared_columns = 1,
            .window = .current,
        },
        .main = .{
            .tree = .main,
            .columns = main_columns,
            .declared_columns = main_columns,
            .window = .current,
        },
        .interaction = .{
            .tree = .interaction,
            .columns = 0,
            .declared_columns = 0,
            .window = .current,
        },
    };
    const lookup_masks = AdapterMasks{
        .preprocessed = .{
            .tree = .preprocessed,
            .columns = 1,
            .declared_columns = 1,
            .window = .current,
        },
        .main = .{
            .tree = .main,
            .columns = main_columns,
            .declared_columns = 0,
            .window = .current,
        },
        .interaction = .{
            .tree = .interaction,
            .columns = interaction_columns,
            .declared_columns = interaction_columns,
            .window = .current_and_previous,
        },
    };
    return .{
        .family = family,
        .authority_digest = Authority.AUTHORITY_BINDING_DIGEST,
        .claim = .{
            .transcript_component = transcriptComponentFor(family),
            .detailed_claims = batches,
            .canonical_claim_slots = 1,
        },
        .main_columns = main_columns,
        .direct_constraints = Authority.DIRECT_CONSTRAINT_COUNT,
        .lookup_events = lookup_events,
        .lookup_batch_size = batch_size,
        .lookup_batches = batches,
        .interaction_columns = interaction_columns,
        .semantic_masks = semantic_masks,
        .lookup_masks = lookup_masks,
        .adapters = ADAPTER_ORDER,
    };
}

fn transcriptComponentFor(comptime family: Family) TranscriptComponent {
    return switch (family) {
        .auipc => .auipc,
        .base_alu_imm => .base_alu_imm,
        .base_alu_reg => .base_alu_reg,
        .branch_eq => .branch_eq,
        .branch_lt => .branch_lt,
        .div => .div,
        .jal => .jal,
        .jalr => .jalr,
        .load_store => .load_store,
        .lt_imm => .lt_imm,
        .lt_reg => .lt_reg,
        .lui => .lui,
        .mul => .mul,
        .mulh => .mulh,
        .shifts_imm => .shifts_imm,
        .shifts_reg => .shifts_reg,
        .fence => .fence,
    };
}

const ScalarField = enum {
    main_columns,
    direct_constraints,
    lookup_events,
    lookup_batch_size,
    lookup_batches,
    interaction_columns,
};

inline fn scalarFromDescriptor(comptime field: ScalarField, item: Descriptor) usize {
    return switch (field) {
        .main_columns => item.main_columns,
        .direct_constraints => item.direct_constraints,
        .lookup_events => item.lookup_events,
        .lookup_batch_size => item.lookup_batch_size,
        .lookup_batches => item.lookup_batches,
        .interaction_columns => item.interaction_columns,
    };
}

fn maximumField(comptime field: ScalarField) usize {
    var maximum: usize = 0;
    for (BY_FAMILY) |item| maximum = @max(
        maximum,
        scalarFromDescriptor(field, item),
    );
    return maximum;
}

/// Emits the same constant-valued family switch as each former handwritten
/// getter, but the switch and its field selection now have one source.  The
/// `inline else` capture forbids runtime reflection or textual lookup.
inline fn scalarField(comptime field: ScalarField, family: Family) usize {
    return switch (family) {
        inline else => |comptime_family| scalarFromDescriptor(
            field,
            descriptorFor(comptime_family),
        ),
    };
}

comptime {
    if (FAMILY_COUNT != 17)
        @compileError("typed opcode composition manifest must cover 17 families");
    if (transcript_claims.COMPONENT_COUNT < FAMILY_COUNT)
        @compileError("typed opcode claim block exceeds the transcript registry");
    if (@intFromEnum(Tree.preprocessed) != 0 or
        @intFromEnum(Tree.main) != 1 or
        @intFromEnum(Tree.interaction) != 2)
    {
        @compileError("typed opcode commitment-tree indices drifted");
    }
    if (ADAPTER_ORDER[0] != .semantic or ADAPTER_ORDER[1] != .lookup)
        @compileError("typed opcode adapter order drifted");

    for (BY_FAMILY, 0..) |item, index| {
        if (@intFromEnum(item.family) != index or
            item.main_columns == 0 or
            item.direct_constraints == 0 or
            item.lookup_events == 0 or
            item.lookup_batch_size == 0 or
            item.lookup_batch_size > 2 or
            item.lookup_batches == 0 or
            item.interaction_columns !=
                item.lookup_batches * SECURE_COORDINATES_PER_CLAIM or
            item.claim.detailed_claims != item.lookup_batches or
            item.claim.canonical_claim_slots != 1 or
            !std.meta.eql(item.adapters, ADAPTER_ORDER) or
            item.semantic_masks.preprocessed.columns != 1 or
            item.semantic_masks.preprocessed.declared_columns != 1 or
            item.semantic_masks.main.columns != item.main_columns or
            item.semantic_masks.main.declared_columns != item.main_columns or
            item.semantic_masks.interaction.columns != 0 or
            item.semantic_masks.interaction.declared_columns != 0 or
            item.lookup_masks.preprocessed.columns != 1 or
            item.lookup_masks.preprocessed.declared_columns != 1 or
            item.lookup_masks.main.columns != item.main_columns or
            item.lookup_masks.main.declared_columns != 0 or
            item.lookup_masks.interaction.columns != item.interaction_columns or
            item.lookup_masks.interaction.declared_columns != item.interaction_columns or
            item.lookup_masks.interaction.window != .current_and_previous)
        {
            @compileError("invalid typed opcode composition descriptor");
        }
        var digest_nonzero = false;
        for (item.authority_digest) |byte| digest_nonzero = digest_nonzero or byte != 0;
        if (!digest_nonzero)
            @compileError("typed opcode composition descriptor has no authority identity");
        for (BY_FAMILY[index + 1 ..]) |other| {
            if (std.mem.eql(u8, &item.authority_digest, &other.authority_digest))
                @compileError("typed opcode authority identities must be unique");
        }
    }
}

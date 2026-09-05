//! Verifier-visible geometry for the combined Ethereum candidate leaf.
//!
//! The candidate keeps the canonical projected base and fourteen Ethereum
//! components in their existing declaration order, then appends bulk-memcpy
//! caller/word and stack-SWAP caller/word components.  This authority owns only
//! the appended placement contract; it does not activate a runner or promote a
//! proof receipt.

const std = @import("std");
const verifier_types = @import("stwo_core").verifier_types;

const base_statement = @import("../../air/statement.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const bulk_contract = @import("../../air/guest_precompile/bulk_memcpy_component_v1.zig");
const bulk_profile = @import("../../air/guest_precompile/bulk_memcpy_vm_profile_v1.zig");
const bulk_trace = @import("../../air/guest_precompile/bulk_memcpy_trace_v1.zig");
const swap_contract = @import("../../air/guest_precompile/stack_swap_component_v1.zig");
const swap_profile = @import("../../air/guest_precompile/stack_swap_vm_profile_v1.zig");
const swap_trace = @import("../../air/guest_precompile/stack_swap_trace_v1.zig");
const combined_authority = @import("../../isa/ethereum_candidate_combined_authority_v1.zig");

pub const Digest = [32]u8;
pub const format_version: u16 = 1;
pub const schema_version: u16 = 1;
pub const production_active = false;
pub const component_count: usize = 4;
/// The appended degree-four AIRs require a two-bit quotient expansion.  The
/// candidate leaf therefore uses a proof-wide split of two; ordinary handles
/// are lifted by one bound bit in the candidate assembly so their OODS bound
/// remains identical to the canonical split-one route.
pub const composition_log_split: u8 = 2;

const profile_domain_words = [4]u32{
    0x4757_5453, // STWG
    0x3146_4c43, // CLF1
    format_version,
    component_count,
};

pub const ComponentKind = enum(u8) {
    bulk_memcpy_caller = 1,
    bulk_memcpy_words = 2,
    stack_swap_caller = 3,
    stack_swap_words = 4,
};

pub const ComponentDescriptor = struct {
    kind: ComponentKind,
    n_rows: u32,
    log_size: u32,
    preprocessed_columns: u16,
    main_columns: u16,
    interaction_columns: u16,
    direct_constraints: u16,
    interaction_batches: u16,
    maximum_constraint_degree: u8,
    composition_log_split: u8,

    pub fn canonical(
        kind: ComponentKind,
        bulk_call_count: u32,
        bulk_word_row_count: u32,
        swap_call_count: u32,
    ) !ComponentDescriptor {
        return switch (kind) {
            .bulk_memcpy_caller => fromBulk(try bulk_profile.ComponentDescriptor
                .canonical(.caller, bulk_call_count, bulk_word_row_count)),
            .bulk_memcpy_words => fromBulk(try bulk_profile.ComponentDescriptor
                .canonical(.words, bulk_call_count, bulk_word_row_count)),
            .stack_swap_caller => fromSwap(try swap_profile.ComponentDescriptor
                .canonical(.caller, swap_call_count)),
            .stack_swap_words => fromSwap(try swap_profile.ComponentDescriptor
                .canonical(.words, swap_call_count)),
        };
    }

    pub fn validate(
        self: ComponentDescriptor,
        bulk_call_count: u32,
        bulk_word_row_count: u32,
        swap_call_count: u32,
    ) !void {
        if (!std.meta.eql(self, try canonical(
            self.kind,
            bulk_call_count,
            bulk_word_row_count,
            swap_call_count,
        ))) return error.EthereumCandidateLeafComponentMismatch;
    }
};

/// The prefix already committed before the four candidate components.
/// `base_interaction_columns` is supplied by the authenticated physical lookup
/// statement because it is not always equal to `core.nInteractionColumns()`.
pub const PrefixGeometry = struct {
    core_preprocessed_columns: u32,
    core_main_columns: u32,
    core_interaction_columns: u32,
    ethereum_preprocessed_columns: u32,
    ethereum_main_columns: u32,
    ethereum_interaction_columns: u32,
    preprocessed_columns: u32,
    main_columns: u32,
    interaction_columns: u32,

    pub fn derive(
        core: *const base_statement.RiscVStatement,
        ethereum: *const ethereum_statement.Statement,
        base_interaction_columns: u32,
    ) !PrefixGeometry {
        try ethereum.validateStructure(core);
        var ethereum_preprocessed: u32 = 0;
        var ethereum_main: u32 = 0;
        var ethereum_interaction: u32 = 0;
        for (ethereum.components) |component| {
            ethereum_preprocessed = try add(
                ethereum_preprocessed,
                component.preprocessed_columns,
            );
            ethereum_main = try add(ethereum_main, component.main_columns);
            ethereum_interaction = try add(
                ethereum_interaction,
                component.interaction_columns,
            );
        }
        const core_preprocessed: u32 = @intCast(core.nPreprocessedColumns());
        const core_main: u32 = @intCast(core.nMainColumns());
        return .{
            .core_preprocessed_columns = core_preprocessed,
            .core_main_columns = core_main,
            .core_interaction_columns = base_interaction_columns,
            .ethereum_preprocessed_columns = ethereum_preprocessed,
            .ethereum_main_columns = ethereum_main,
            .ethereum_interaction_columns = ethereum_interaction,
            .preprocessed_columns = try add(
                core_preprocessed,
                ethereum_preprocessed,
            ),
            .main_columns = try add(core_main, ethereum_main),
            .interaction_columns = try add(
                base_interaction_columns,
                ethereum_interaction,
            ),
        };
    }
};

pub const Placement = struct {
    preprocessed_offset: u32,
    main_offset: u32,
    interaction_offset: u32,
};

pub const Placements = struct {
    bulk_memcpy_caller: Placement,
    bulk_memcpy_words: Placement,
    stack_swap_caller: Placement,
    stack_swap_words: Placement,

    pub fn derive(prefix: PrefixGeometry) !Placements {
        const bulk_caller = Placement{
            .preprocessed_offset = prefix.preprocessed_columns,
            .main_offset = prefix.main_columns,
            .interaction_offset = prefix.interaction_columns,
        };
        const bulk_words = try after(
            bulk_caller,
            bulk_trace.preprocessed_column_count,
            bulk_contract.Caller.main_column_count,
            bulk_contract.Caller.interaction_column_count,
        );
        const swap_caller = try after(
            bulk_words,
            bulk_trace.preprocessed_column_count,
            bulk_contract.Word.main_column_count,
            bulk_contract.Word.interaction_column_count,
        );
        const swap_words = try after(
            swap_caller,
            swap_trace.preprocessed_column_count,
            swap_contract.Caller.main_column_count,
            swap_contract.Caller.interaction_column_count,
        );
        return .{
            .bulk_memcpy_caller = bulk_caller,
            .bulk_memcpy_words = bulk_words,
            .stack_swap_caller = swap_caller,
            .stack_swap_words = swap_words,
        };
    }
};

pub const TreeTotals = struct {
    preprocessed_columns: u32,
    main_columns: u32,
    interaction_columns: u32,

    pub fn derive(prefix: PrefixGeometry) !TreeTotals {
        return .{
            .preprocessed_columns = try add(
                prefix.preprocessed_columns,
                2 * bulk_trace.preprocessed_column_count +
                    2 * swap_trace.preprocessed_column_count,
            ),
            .main_columns = try add(
                prefix.main_columns,
                bulk_contract.Caller.main_column_count +
                    bulk_contract.Word.main_column_count +
                    swap_contract.Caller.main_column_count +
                    swap_contract.Word.main_column_count,
            ),
            .interaction_columns = try add(
                prefix.interaction_columns,
                bulk_contract.Caller.interaction_column_count +
                    bulk_contract.Word.interaction_column_count +
                    swap_contract.Caller.interaction_column_count +
                    swap_contract.Word.interaction_column_count,
            ),
        };
    }
};

pub const Profile = struct {
    format: u16 = format_version,
    schema: u16 = schema_version,
    authority: combined_authority.Authority,
    bulk_memcpy_call_count: u32,
    bulk_memcpy_word_row_count: u32,
    stack_swap_call_count: u32,
    prefix: PrefixGeometry,
    components: [component_count]ComponentDescriptor,
    placements: Placements,
    totals: TreeTotals,
    identity: Digest,
    proof_fresh_verified: bool = false,
    production_eligible: bool = false,

    pub fn create(
        core: *const base_statement.RiscVStatement,
        ethereum: *const ethereum_statement.Statement,
        base_interaction_columns: u32,
        authority: combined_authority.Authority,
        bulk_memcpy_call_count: u32,
        bulk_memcpy_word_row_count: u32,
        stack_swap_call_count: u32,
    ) !Profile {
        try authority.validate();
        const prefix = try PrefixGeometry.derive(
            core,
            ethereum,
            base_interaction_columns,
        );
        var result = Profile{
            .authority = authority,
            .bulk_memcpy_call_count = bulk_memcpy_call_count,
            .bulk_memcpy_word_row_count = bulk_memcpy_word_row_count,
            .stack_swap_call_count = stack_swap_call_count,
            .prefix = prefix,
            .components = .{
                try .canonical(
                    .bulk_memcpy_caller,
                    bulk_memcpy_call_count,
                    bulk_memcpy_word_row_count,
                    stack_swap_call_count,
                ),
                try .canonical(
                    .bulk_memcpy_words,
                    bulk_memcpy_call_count,
                    bulk_memcpy_word_row_count,
                    stack_swap_call_count,
                ),
                try .canonical(
                    .stack_swap_caller,
                    bulk_memcpy_call_count,
                    bulk_memcpy_word_row_count,
                    stack_swap_call_count,
                ),
                try .canonical(
                    .stack_swap_words,
                    bulk_memcpy_call_count,
                    bulk_memcpy_word_row_count,
                    stack_swap_call_count,
                ),
            },
            .placements = try .derive(prefix),
            .totals = try .derive(prefix),
            .identity = undefined,
        };
        result.identity = profileIdentity(result);
        try result.validate(
            core,
            ethereum,
            base_interaction_columns,
        );
        return result;
    }

    pub fn validate(
        self: Profile,
        core: *const base_statement.RiscVStatement,
        ethereum: *const ethereum_statement.Statement,
        base_interaction_columns: u32,
    ) !void {
        if (production_active or self.format != format_version or
            self.schema != schema_version or self.proof_fresh_verified or
            self.production_eligible)
        {
            return error.EthereumCandidateLeafProfileActivated;
        }
        try self.authority.validate();
        const candidate_retirements = std.math.add(
            u32,
            self.bulk_memcpy_call_count,
            self.stack_swap_call_count,
        ) catch return error.EthereumCandidateLeafGeometryOverflow;
        const all_external_retirements = std.math.add(
            u32,
            ethereum.counts.external_retirements,
            candidate_retirements,
        ) catch return error.EthereumCandidateLeafGeometryOverflow;
        if (all_external_retirements > core.total_steps)
            return error.EthereumCandidateLeafExternalCountMismatch;
        const expected_prefix = try PrefixGeometry.derive(
            core,
            ethereum,
            base_interaction_columns,
        );
        if (!std.meta.eql(self.prefix, expected_prefix) or
            !std.meta.eql(self.placements, try Placements.derive(expected_prefix)) or
            !std.meta.eql(self.totals, try TreeTotals.derive(expected_prefix)))
        {
            return error.EthereumCandidateLeafProfileMismatch;
        }
        inline for (self.components, componentKinds()) |component, kind| {
            if (component.kind != kind) return error.EthereumCandidateLeafComponentOrderMismatch;
            try component.validate(
                self.bulk_memcpy_call_count,
                self.bulk_memcpy_word_row_count,
                self.stack_swap_call_count,
            );
        }
        if (!std.mem.eql(u8, &self.identity, &profileIdentity(self)))
            return error.EthereumCandidateLeafProfileIdentityMismatch;
    }

    /// Mixes the complete field authority before Tree 0.  The digest is not
    /// mixed as a substitute for these fields.
    pub fn mixInto(
        self: Profile,
        core: *const base_statement.RiscVStatement,
        ethereum: *const ethereum_statement.Statement,
        base_interaction_columns: u32,
        channel: anytype,
    ) !void {
        try self.validate(core, ethereum, base_interaction_columns);
        channel.mixU32s(&profile_domain_words);
        channel.mixU32s(&.{
            self.format,
            self.schema,
            self.bulk_memcpy_call_count,
            self.bulk_memcpy_word_row_count,
            self.stack_swap_call_count,
            @intFromBool(self.proof_fresh_verified),
            @intFromBool(self.production_eligible),
        });
        mixDigest(channel, self.authority.identity);
        mixDigest(channel, self.authority.registry.identity);
        mixDigest(channel, self.authority.guest_elf_sha256);
        mixPrefix(channel, self.prefix);
        for (self.components) |component| mixComponent(channel, component);
        inline for (.{
            self.placements.bulk_memcpy_caller,
            self.placements.bulk_memcpy_words,
            self.placements.stack_swap_caller,
            self.placements.stack_swap_words,
        }) |placement| channel.mixU32s(&.{
            placement.preprocessed_offset,
            placement.main_offset,
            placement.interaction_offset,
        });
        channel.mixU32s(&.{
            self.totals.preprocessed_columns,
            self.totals.main_columns,
            self.totals.interaction_columns,
        });
    }
};

pub fn componentKinds() [component_count]ComponentKind {
    return .{
        .bulk_memcpy_caller,
        .bulk_memcpy_words,
        .stack_swap_caller,
        .stack_swap_words,
    };
}

fn fromBulk(value: bulk_profile.ComponentDescriptor) ComponentDescriptor {
    return .{
        .kind = switch (value.kind) {
            .caller => .bulk_memcpy_caller,
            .words => .bulk_memcpy_words,
        },
        .n_rows = value.n_rows,
        .log_size = value.log_size,
        .preprocessed_columns = value.preprocessed_columns,
        .main_columns = value.main_columns,
        .interaction_columns = value.interaction_columns,
        .direct_constraints = value.direct_constraints,
        .interaction_batches = value.batch_count,
        .maximum_constraint_degree = value.maximum_constraint_degree,
        .composition_log_split = composition_log_split,
    };
}

fn fromSwap(value: swap_profile.ComponentDescriptor) ComponentDescriptor {
    return .{
        .kind = switch (value.kind) {
            .caller => .stack_swap_caller,
            .words => .stack_swap_words,
        },
        .n_rows = value.n_rows,
        .log_size = value.log_size,
        .preprocessed_columns = value.preprocessed_columns,
        .main_columns = value.main_columns,
        .interaction_columns = value.interaction_columns,
        .direct_constraints = value.direct_constraints,
        .interaction_batches = value.batch_count,
        .maximum_constraint_degree = value.maximum_constraint_degree,
        .composition_log_split = composition_log_split,
    };
}

fn after(
    placement: Placement,
    preprocessed_columns: anytype,
    main_columns: anytype,
    interaction_columns: anytype,
) !Placement {
    return .{
        .preprocessed_offset = try add(
            placement.preprocessed_offset,
            preprocessed_columns,
        ),
        .main_offset = try add(placement.main_offset, main_columns),
        .interaction_offset = try add(
            placement.interaction_offset,
            interaction_columns,
        ),
    };
}

fn profileIdentity(value: Profile) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-leaf-profile.v1\x00");
    hashInt(&hash, u16, value.format);
    hashInt(&hash, u16, value.schema);
    hash.update(&value.authority.identity);
    hash.update(&value.authority.registry.identity);
    hash.update(&value.authority.guest_elf_sha256);
    hashInt(&hash, u32, value.bulk_memcpy_call_count);
    hashInt(&hash, u32, value.bulk_memcpy_word_row_count);
    hashInt(&hash, u32, value.stack_swap_call_count);
    hashPrefix(&hash, value.prefix);
    for (value.components) |component| hashComponent(&hash, component);
    inline for (.{
        value.placements.bulk_memcpy_caller,
        value.placements.bulk_memcpy_words,
        value.placements.stack_swap_caller,
        value.placements.stack_swap_words,
    }) |placement| {
        hashInt(&hash, u32, placement.preprocessed_offset);
        hashInt(&hash, u32, placement.main_offset);
        hashInt(&hash, u32, placement.interaction_offset);
    }
    hashInt(&hash, u32, value.totals.preprocessed_columns);
    hashInt(&hash, u32, value.totals.main_columns);
    hashInt(&hash, u32, value.totals.interaction_columns);
    hash.update(&.{
        @intFromBool(value.proof_fresh_verified),
        @intFromBool(value.production_eligible),
    });
    return hash.finalResult();
}

fn hashPrefix(hash: anytype, value: PrefixGeometry) void {
    inline for (.{
        value.core_preprocessed_columns,
        value.core_main_columns,
        value.core_interaction_columns,
        value.ethereum_preprocessed_columns,
        value.ethereum_main_columns,
        value.ethereum_interaction_columns,
        value.preprocessed_columns,
        value.main_columns,
        value.interaction_columns,
    }) |field| hashInt(hash, u32, field);
}

fn hashComponent(hash: anytype, value: ComponentDescriptor) void {
    hashInt(hash, u8, @intFromEnum(value.kind));
    hashInt(hash, u32, value.n_rows);
    hashInt(hash, u32, value.log_size);
    inline for (.{
        value.preprocessed_columns,
        value.main_columns,
        value.interaction_columns,
        value.direct_constraints,
        value.interaction_batches,
    }) |field| hashInt(hash, u16, field);
    hash.update(&.{
        value.maximum_constraint_degree,
        value.composition_log_split,
    });
}

fn mixPrefix(channel: anytype, value: PrefixGeometry) void {
    channel.mixU32s(&.{
        value.core_preprocessed_columns,
        value.core_main_columns,
        value.core_interaction_columns,
        value.ethereum_preprocessed_columns,
        value.ethereum_main_columns,
        value.ethereum_interaction_columns,
        value.preprocessed_columns,
        value.main_columns,
        value.interaction_columns,
    });
}

fn mixComponent(channel: anytype, value: ComponentDescriptor) void {
    channel.mixU32s(&.{
        @intFromEnum(value.kind),
        value.n_rows,
        value.log_size,
        value.preprocessed_columns,
        value.main_columns,
        value.interaction_columns,
        value.direct_constraints,
        value.interaction_batches,
        value.maximum_constraint_degree,
        value.composition_log_split,
    });
}

fn mixDigest(channel: anytype, value: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn add(left: anytype, right: anytype) !u32 {
    return std.math.add(u32, @intCast(left), @intCast(right)) catch
        error.EthereumCandidateLeafGeometryOverflow;
}

comptime {
    if (production_active or component_count != 4 or
        composition_log_split != 2 or
        composition_log_split > verifier_types.MAX_COMPOSITION_LOG_SPLIT or
        ethereum_statement.component_count != 14 or
        bulk_trace.preprocessed_column_count != 3 or
        swap_trace.preprocessed_column_count != 3 or
        bulk_contract.Caller.interaction_column_count != 60 or
        bulk_contract.Word.interaction_column_count != 16 or
        swap_contract.Caller.interaction_column_count != 36 or
        swap_contract.Word.interaction_column_count != 16 or
        combined_authority.production_active)
    {
        @compileError("combined Ethereum candidate leaf profile drifted");
    }
}

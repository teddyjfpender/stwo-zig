//! Candidate-only VM profile for the genuine U256 SWAP components.
//!
//! This is not an `ExecutionProfile` variant and has no ELF admission-note
//! value.  It appends two typed component blocks after one complete base
//! statement, binds the explicit private registry allocation, and remains
//! inactive even when a future candidate executable identity is supplied.

const std = @import("std");

const abi = @import("../../isa/stack_swap_candidate_v1.zig");
const private_registry = @import("../../isa/stack_swap_private_registry_v1.zig");
const base_statement = @import("../statement.zig");
const contract = @import("stack_swap_component_v1.zig");
const trace_mod = @import("stack_swap_trace_v1.zig");

pub const Digest = [32]u8;
pub const production_active = false;
pub const format_version: u16 = 1;
pub const component_count: usize = 2;
pub const profile_domain_words = [4]u32{
    0x4757_5453, // STWG
    0x3150_5353, // SSP1
    format_version,
    component_count,
};

pub const ComponentKind = enum(u16) {
    caller = 1,
    words = 2,
};

pub const ComponentDescriptor = struct {
    kind: ComponentKind,
    n_rows: u32,
    log_size: u32,
    preprocessed_columns: u16,
    main_columns: u16,
    interaction_columns: u16,
    direct_constraints: u16,
    batch_count: u16,
    maximum_constraint_degree: u8,
    composition_log_split: u8,

    pub fn canonical(kind: ComponentKind, call_count: u32) !ComponentDescriptor {
        return switch (kind) {
            .caller => .{
                .kind = kind,
                .n_rows = call_count,
                .log_size = try contract.Caller.logSizeForRows(call_count),
                .preprocessed_columns = trace_mod.preprocessed_column_count,
                .main_columns = contract.Caller.main_column_count,
                .interaction_columns = contract.Caller.interaction_column_count,
                .direct_constraints = contract.Caller.direct_constraint_count,
                .batch_count = contract.Caller.batch_count,
                .maximum_constraint_degree = contract.Caller.maximum_constraint_degree,
                .composition_log_split = 2,
            },
            .words => blk: {
                const word_rows = std.math.mul(
                    u32,
                    call_count,
                    abi.words_per_value,
                ) catch return error.StackSwapVmProfileOverflow;
                break :blk .{
                    .kind = kind,
                    .n_rows = word_rows,
                    .log_size = try contract.Word.logSizeForRows(word_rows),
                    .preprocessed_columns = trace_mod.preprocessed_column_count,
                    .main_columns = contract.Word.main_column_count,
                    .interaction_columns = contract.Word.interaction_column_count,
                    .direct_constraints = contract.Word.direct_constraint_count,
                    .batch_count = contract.Word.batch_count,
                    .maximum_constraint_degree = contract.Word.maximum_constraint_degree,
                    .composition_log_split = 2,
                };
            },
        };
    }

    pub fn validate(self: ComponentDescriptor, call_count: u32) !void {
        if (!std.meta.eql(self, try canonical(self.kind, call_count)))
            return error.StackSwapVmComponentDescriptorMismatch;
    }
};

pub const BaseGeometry = struct {
    component_count: u32,
    infrastructure_count: u32,
    preprocessed_columns: u32,
    main_columns: u32,
    interaction_columns: u32,

    pub fn derive(core: *const base_statement.RiscVStatement) BaseGeometry {
        return .{
            .component_count = core.n_components,
            .infrastructure_count = core.n_infra,
            .preprocessed_columns = core.nPreprocessedColumns(),
            .main_columns = core.nMainColumns(),
            .interaction_columns = core.nInteractionColumns(),
        };
    }

    pub fn validateAgainst(
        self: BaseGeometry,
        core: *const base_statement.RiscVStatement,
    ) !void {
        if (!std.meta.eql(self, derive(core)))
            return error.StackSwapVmBaseGeometryMismatch;
    }
};

pub const Placement = struct {
    preprocessed_offset: u32,
    main_offset: u32,
    interaction_offset: u32,
};

pub const Placements = struct {
    caller: Placement,
    words: Placement,

    pub fn derive(base: BaseGeometry) !Placements {
        return .{
            .caller = .{
                .preprocessed_offset = base.preprocessed_columns,
                .main_offset = base.main_columns,
                .interaction_offset = base.interaction_columns,
            },
            .words = .{
                .preprocessed_offset = try add(
                    base.preprocessed_columns,
                    trace_mod.preprocessed_column_count,
                ),
                .main_offset = try add(
                    base.main_columns,
                    contract.Caller.main_column_count,
                ),
                .interaction_offset = try add(
                    base.interaction_columns,
                    contract.Caller.interaction_column_count,
                ),
            },
        };
    }
};

pub const TreeTotals = struct {
    preprocessed_columns: u32,
    main_columns: u32,
    interaction_columns: u32,

    pub fn derive(base: BaseGeometry) !TreeTotals {
        return .{
            .preprocessed_columns = try add(
                base.preprocessed_columns,
                2 * trace_mod.preprocessed_column_count,
            ),
            .main_columns = try add(
                base.main_columns,
                contract.Caller.main_column_count + contract.Word.main_column_count,
            ),
            .interaction_columns = try add(
                base.interaction_columns,
                contract.Caller.interaction_column_count +
                    contract.Word.interaction_column_count,
            ),
        };
    }
};

pub const Profile = struct {
    format: u16 = format_version,
    authority: abi.Authority,
    /// SHA custody is transport/admission metadata only. The verifier uses the
    /// explicit program tuple, component geometry, and base relations below.
    candidate_guest_executable_sha256: ?Digest,
    call_count: u32,
    base: BaseGeometry,
    components: [component_count]ComponentDescriptor,
    placements: Placements,
    totals: TreeTotals,
    profile_identity: Digest,
    activation_enabled: bool = false,
    production_eligible: bool = false,

    pub fn createInactive(
        core: *const base_statement.RiscVStatement,
        authority_value: abi.Authority,
        call_count: u32,
        candidate_guest_executable_sha256: ?Digest,
    ) !Profile {
        try private_registry.validateAuthority(authority_value);
        if (candidate_guest_executable_sha256) |digest|
            if (isZeroDigest(digest)) return error.InvalidCandidateGuestExecutableIdentity;
        const base = BaseGeometry.derive(core);
        var result = Profile{
            .authority = authority_value,
            .candidate_guest_executable_sha256 = candidate_guest_executable_sha256,
            .call_count = call_count,
            .base = base,
            .components = .{
                try .canonical(.caller, call_count),
                try .canonical(.words, call_count),
            },
            .placements = try .derive(base),
            .totals = try .derive(base),
            .profile_identity = undefined,
        };
        result.profile_identity = profileIdentity(result);
        try result.validateAgainst(core);
        return result;
    }

    pub fn validateAgainst(
        self: Profile,
        core: *const base_statement.RiscVStatement,
    ) !void {
        if (self.format != format_version or self.activation_enabled or
            self.production_eligible or production_active)
        {
            return error.StackSwapVmProfileActivated;
        }
        try private_registry.validateAuthority(self.authority);
        if (self.candidate_guest_executable_sha256) |digest|
            if (isZeroDigest(digest)) return error.InvalidCandidateGuestExecutableIdentity;
        try self.base.validateAgainst(core);
        try self.components[0].validate(self.call_count);
        try self.components[1].validate(self.call_count);
        if (self.components[0].kind != .caller or
            self.components[1].kind != .words or
            !std.meta.eql(self.placements, try Placements.derive(self.base)) or
            !std.meta.eql(self.totals, try TreeTotals.derive(self.base)) or
            !std.mem.eql(u8, &self.profile_identity, &profileIdentity(self)))
        {
            return error.StackSwapVmProfileMismatch;
        }
    }

    /// Mix every field needed to reconstruct the candidate verifier program.
    /// `profile_identity` is deliberately omitted: it is only a transport
    /// checksum and is never accepted as a substitute for these fields.
    pub fn mixFieldAuthority(
        self: Profile,
        core: *const base_statement.RiscVStatement,
        channel: anytype,
    ) !void {
        try self.validateAgainst(core);
        channel.mixU32s(&profile_domain_words);
        channel.mixU32s(&.{
            self.format,
            self.authority.allocation.funct7,
            self.authority.allocation.proof_opcode_id,
            self.authority.fixed_word,
            self.call_count,
            @intFromBool(self.candidate_guest_executable_sha256 != null),
            @intFromBool(self.activation_enabled),
            @intFromBool(self.production_eligible),
        });
        mixDigest(channel, self.authority.allocation.registry_identity);
        mixDigest(channel, self.authority.semantic_identity);
        if (self.candidate_guest_executable_sha256) |digest|
            mixDigest(channel, digest);
        channel.mixU32s(&.{
            self.base.component_count,
            self.base.infrastructure_count,
            self.base.preprocessed_columns,
            self.base.main_columns,
            self.base.interaction_columns,
        });
        for (self.components) |component| channel.mixU32s(&.{
            @intFromEnum(component.kind),
            component.n_rows,
            component.log_size,
            component.preprocessed_columns,
            component.main_columns,
            component.interaction_columns,
            component.direct_constraints,
            component.batch_count,
            component.maximum_constraint_degree,
            component.composition_log_split,
        });
        inline for (.{ self.placements.caller, self.placements.words }) |placement|
            channel.mixU32s(&.{
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

fn profileIdentity(value: Profile) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.stack-swap-vm-profile.v1\x00");
    hash.update(&u16Bytes(value.format));
    hash.update(&value.authority.allocation.registry_identity);
    hash.update(&value.authority.semantic_identity);
    hash.update(&u32Bytes(value.authority.fixed_word));
    hash.update(&u32Bytes(value.authority.allocation.proof_opcode_id));
    hash.update(&u32Bytes(value.call_count));
    hash.update(&.{
        value.authority.allocation.funct7,
        @intFromBool(value.candidate_guest_executable_sha256 != null),
        @intFromBool(value.activation_enabled),
        @intFromBool(value.production_eligible),
    });
    if (value.candidate_guest_executable_sha256) |digest| hash.update(&digest);
    hashGeometry(&hash, value.base);
    for (value.components) |component| hashComponent(&hash, component);
    inline for (.{ value.placements.caller, value.placements.words }) |placement| {
        hash.update(&u32Bytes(placement.preprocessed_offset));
        hash.update(&u32Bytes(placement.main_offset));
        hash.update(&u32Bytes(placement.interaction_offset));
    }
    hash.update(&u32Bytes(value.totals.preprocessed_columns));
    hash.update(&u32Bytes(value.totals.main_columns));
    hash.update(&u32Bytes(value.totals.interaction_columns));
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn hashGeometry(hash: anytype, value: BaseGeometry) void {
    hash.update(&u32Bytes(value.component_count));
    hash.update(&u32Bytes(value.infrastructure_count));
    hash.update(&u32Bytes(value.preprocessed_columns));
    hash.update(&u32Bytes(value.main_columns));
    hash.update(&u32Bytes(value.interaction_columns));
}

fn hashComponent(hash: anytype, value: ComponentDescriptor) void {
    hash.update(&u16Bytes(@intFromEnum(value.kind)));
    hash.update(&u32Bytes(value.n_rows));
    hash.update(&u32Bytes(value.log_size));
    inline for (.{
        value.preprocessed_columns,
        value.main_columns,
        value.interaction_columns,
        value.direct_constraints,
        value.batch_count,
    }) |field| hash.update(&u16Bytes(field));
    hash.update(&.{ value.maximum_constraint_degree, value.composition_log_split });
}

fn mixDigest(channel: anytype, digest: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, digest[index * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}

fn isZeroDigest(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

fn add(left: anytype, right: anytype) !u32 {
    return std.math.add(u32, @intCast(left), @intCast(right)) catch
        error.StackSwapVmProfileOverflow;
}

fn u16Bytes(value: anytype) [2]u8 {
    var result: [2]u8 = undefined;
    std.mem.writeInt(u16, &result, @intCast(value), .little);
    return result;
}

fn u32Bytes(value: anytype) [4]u8 {
    var result: [4]u8 = undefined;
    std.mem.writeInt(u32, &result, @intCast(value), .little);
    return result;
}

comptime {
    if (production_active or component_count != 2 or
        trace_mod.preprocessed_column_count != 3 or
        contract.Caller.main_column_count != 37 or
        contract.Word.main_column_count != 16 or
        contract.Caller.interaction_column_count != 36 or
        contract.Word.interaction_column_count != 16)
    {
        @compileError("stack-swap VM profile geometry drifted");
    }
}

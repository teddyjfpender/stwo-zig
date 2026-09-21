//! Candidate-only VM profile for genuine bulk-memcpy components.
//!
//! This is not an `ExecutionProfile` variant and has no production admission
//! note. It describes two appended component blocks after one complete base
//! statement and binds the exact private registry member and guest ELF.

const std = @import("std");

const base_statement = @import("../statement.zig");
const contract = @import("bulk_memcpy_component_v1.zig");
const private_registry = @import("../../isa/bulk_memcpy_private_registry_v1.zig");
const stark_component = @import("bulk_memcpy_stark_component_v1.zig");
const trace_mod = @import("bulk_memcpy_trace_v1.zig");

pub const Digest = [32]u8;
pub const production_active = false;
pub const format_version: u16 = 1;
pub const component_count: usize = 2;
pub const profile_domain_words = [4]u32{
    0x4757_5453, // STWG
    0x314d_4d42, // BMM1
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

    pub fn canonical(
        kind: ComponentKind,
        call_count: u32,
        word_row_count: u32,
    ) !ComponentDescriptor {
        return switch (kind) {
            .caller => descriptorFor(.caller, contract.Caller, call_count),
            .words => descriptorFor(.words, contract.Word, word_row_count),
        };
    }

    pub fn validate(
        self: ComponentDescriptor,
        call_count: u32,
        word_row_count: u32,
    ) !void {
        if (!std.meta.eql(
            self,
            try canonical(self.kind, call_count, word_row_count),
        )) return error.BulkMemcpyVmComponentDescriptorMismatch;
    }
};

fn descriptorFor(
    comptime kind: ComponentKind,
    comptime Config: type,
    rows: u32,
) ComponentDescriptor {
    return .{
        .kind = kind,
        .n_rows = rows,
        .log_size = traceLogSize(rows),
        .preprocessed_columns = trace_mod.preprocessed_column_count,
        .main_columns = Config.main_column_count,
        .interaction_columns = Config.interaction_column_count,
        .direct_constraints = Config.direct_constraint_count,
        .batch_count = Config.batch_count,
        .maximum_constraint_degree = Config.maximum_constraint_degree,
        .composition_log_split = stark_component.composition_log_split,
    };
}

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
            return error.BulkMemcpyVmBaseGeometryMismatch;
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
    authority: private_registry.Authority,
    candidate_guest_executable_sha256: Digest,
    call_count: u32,
    word_row_count: u32,
    base: BaseGeometry,
    components: [component_count]ComponentDescriptor,
    placements: Placements,
    totals: TreeTotals,
    profile_identity: Digest,
    activation_enabled: bool = false,
    production_eligible: bool = false,

    pub fn createInactive(
        core: *const base_statement.RiscVStatement,
        authority_value: private_registry.Authority,
        candidate_guest_executable_sha256: Digest,
        call_count: u32,
        word_row_count: u32,
    ) !Profile {
        try private_registry.validateAuthority(authority_value);
        try validateCounts(call_count, word_row_count);
        if (isZeroDigest(candidate_guest_executable_sha256))
            return error.InvalidCandidateGuestExecutableIdentity;
        const base = BaseGeometry.derive(core);
        var result = Profile{
            .authority = authority_value,
            .candidate_guest_executable_sha256 = candidate_guest_executable_sha256,
            .call_count = call_count,
            .word_row_count = word_row_count,
            .base = base,
            .components = .{
                try .canonical(.caller, call_count, word_row_count),
                try .canonical(.words, call_count, word_row_count),
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
            self.production_eligible or production_active or
            isZeroDigest(self.candidate_guest_executable_sha256))
        {
            return error.BulkMemcpyVmProfileActivated;
        }
        try private_registry.validateAuthority(self.authority);
        try validateCounts(self.call_count, self.word_row_count);
        try self.base.validateAgainst(core);
        try self.components[0].validate(self.call_count, self.word_row_count);
        try self.components[1].validate(self.call_count, self.word_row_count);
        if (self.components[0].kind != .caller or
            self.components[1].kind != .words or
            !std.meta.eql(self.placements, try Placements.derive(self.base)) or
            !std.meta.eql(self.totals, try TreeTotals.derive(self.base)) or
            !std.mem.eql(u8, &self.profile_identity, &profileIdentity(self)))
        {
            return error.BulkMemcpyVmProfileMismatch;
        }
    }

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
            self.word_row_count,
            @intFromBool(self.activation_enabled),
            @intFromBool(self.production_eligible),
        });
        mixDigest(channel, self.authority.allocation.registry_identity);
        mixDigest(channel, self.authority.semantic_identity);
        mixDigest(channel, self.candidate_guest_executable_sha256);
        mixGeometry(channel, self.base);
        for (self.components) |component| mixComponent(channel, component);
        mixPlacements(channel, self.placements);
        mixTotals(channel, self.totals);
    }
};

fn validateCounts(call_count: u32, word_row_count: u32) !void {
    if (call_count == 0) {
        if (word_row_count != 0) return error.BulkMemcpyVmRowCountMismatch;
        return;
    }
    const minimum_words = std.math.mul(u32, call_count, 8) catch
        return error.BulkMemcpyVmRowCountOverflow;
    if (word_row_count < minimum_words)
        return error.BulkMemcpyVmRowCountMismatch;
}

fn traceLogSize(rows: u32) u32 {
    return @max(
        trace_mod.minimum_log_size,
        std.math.log2_int_ceil(u32, @max(@as(u32, 1), rows)),
    );
}

fn profileIdentity(profile: Profile) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.bulk-memcpy-vm-profile.v1\x00");
    hash.update(&u16Bytes(profile.format));
    hash.update(&profile.authority.allocation.registry_identity);
    hash.update(&profile.authority.semantic_identity);
    hash.update(&profile.candidate_guest_executable_sha256);
    hash.update(&u32Bytes(profile.call_count));
    hash.update(&u32Bytes(profile.word_row_count));
    hashGeometry(&hash, profile.base);
    for (profile.components) |component| hashComponent(&hash, component);
    hashPlacements(&hash, profile.placements);
    hashTotals(&hash, profile.totals);
    hash.update(&.{
        @intFromBool(profile.activation_enabled),
        @intFromBool(profile.production_eligible),
    });
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
    hash.update(&u16Bytes(value.preprocessed_columns));
    hash.update(&u16Bytes(value.main_columns));
    hash.update(&u16Bytes(value.interaction_columns));
    hash.update(&u16Bytes(value.direct_constraints));
    hash.update(&u16Bytes(value.batch_count));
    hash.update(&.{
        value.maximum_constraint_degree,
        value.composition_log_split,
    });
}

fn hashPlacements(hash: anytype, value: Placements) void {
    inline for (.{ value.caller, value.words }) |placement| {
        hash.update(&u32Bytes(placement.preprocessed_offset));
        hash.update(&u32Bytes(placement.main_offset));
        hash.update(&u32Bytes(placement.interaction_offset));
    }
}

fn hashTotals(hash: anytype, value: TreeTotals) void {
    hash.update(&u32Bytes(value.preprocessed_columns));
    hash.update(&u32Bytes(value.main_columns));
    hash.update(&u32Bytes(value.interaction_columns));
}

fn mixGeometry(channel: anytype, value: BaseGeometry) void {
    channel.mixU32s(&.{
        value.component_count,
        value.infrastructure_count,
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
        value.batch_count,
        value.maximum_constraint_degree,
        value.composition_log_split,
    });
}

fn mixPlacements(channel: anytype, value: Placements) void {
    inline for (.{ value.caller, value.words }) |placement| channel.mixU32s(&.{
        placement.preprocessed_offset,
        placement.main_offset,
        placement.interaction_offset,
    });
}

fn mixTotals(channel: anytype, value: TreeTotals) void {
    channel.mixU32s(&.{
        value.preprocessed_columns,
        value.main_columns,
        value.interaction_columns,
    });
}

fn mixDigest(channel: anytype, digest: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, digest[4 * index ..][0..4], .little);
    channel.mixU32s(&words);
}

fn add(left: anytype, right: anytype) !u32 {
    return std.math.add(u32, @intCast(left), @intCast(right)) catch
        return error.BulkMemcpyVmGeometryOverflow;
}

fn isZeroDigest(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

fn u16Bytes(value: anytype) [2]u8 {
    var result: [2]u8 = undefined;
    std.mem.writeInt(u16, &result, @intCast(value), .little);
    return result;
}

fn u32Bytes(value: u32) [4]u8 {
    var result: [4]u8 = undefined;
    std.mem.writeInt(u32, &result, value, .little);
    return result;
}

comptime {
    if (production_active or format_version != 1 or component_count != 2 or
        stark_component.composition_log_split != 2 or
        private_registry.production_active)
    {
        @compileError("bulk-memcpy VM profile became production-active");
    }
}

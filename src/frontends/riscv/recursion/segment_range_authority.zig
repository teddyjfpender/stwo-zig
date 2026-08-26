//! Production authority for universal recursion row 35 on a segment leaf.
//!
//! The shared `(8, 8)` provider must contain the signed multiplicity of every
//! request made by the active universal AIR.  For a segment leaf there are
//! exactly two such owners: statement-semantics row 11 and VM-claim row 12.
//! This module derives their counter from the already authenticated witnesses;
//! callers cannot supply, transcribe, or patch multiplicities independently.
//!
//! `Workspace` owns the fixed 2^16 counter storage and is intended to be reused
//! across proofs.  A derivation performs no allocation.  Preparing row 35 then
//! performs the one cold allocation required by the existing immutable bridge
//! snapshot.  Every fallible source and alias check precedes the first counter
//! store.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const public_data_mod = @import("../air/public_data.zig");
const lookup_counter = @import("../air/lookups/tables/counter.zig");
const lookup_schema = @import("../air/lookups/tables/schema.zig");
const relation = @import("../air/lang/relation.zig");
const leaf_owner = @import("segment_leaf_authority.zig");
const roster = @import("air/universal_roster.zig");
const statement_air = @import("air/statement_semantics_input.zig");
const statement_input = @import("air/statement_input.zig");
const statement_witness = @import("air/statement_semantics_input_witness.zig");
const claim_air = @import("air/vm_public_claim_input.zig");
const claim_witness = @import("air/vm_public_claim_input_witness.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SOURCE_AUTHORITY_FORMAT_VERSION: u16 = 1;
pub const SOURCE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/segment-range-authority/v1\x00";
pub const LEDGER_SOURCE_COUNT: usize = 2;

pub const Error = statement_witness.Error || leaf_owner.Error ||
    range_bridge.Error || lookup_counter.Error || std.mem.Allocator.Error || error{
    AliasedWorkspace,
    ArithmeticOverflow,
    AuthorityMismatch,
    FormatVersionMismatch,
    InvalidProofKind,
    InvalidSourceAuthority,
    InvalidWorkspace,
    RequestCountMismatch,
    StatementAuthorityMismatch,
    UnboundStatementScope,
};

/// A complete, protocol-ordered entry in the segment range-request ledger.
/// The event ordinal is local to the owning universal component.
pub const LedgerSource = struct {
    component: roster.Component,
    semantic_digest: [32]u8,
    event_ordinal: u8,
    role: relation.Role,
};

/// Pins the complete range-request surface used to construct row 35.  Adding
/// another request producer to the universal program requires an explicit
/// versioned update here; silently omitting it cannot validate as V1.
pub const SourceAuthority = struct {
    format_version: u16,
    table_kind: lookup_schema.Kind,
    table_log_size: u32,
    table_size: u32,
    bridge_authority_digest: [32]u8,
    sources: [LEDGER_SOURCE_COUNT]LedgerSource,

    pub fn pinned() SourceAuthority {
        return .{
            .format_version = SOURCE_AUTHORITY_FORMAT_VERSION,
            .table_kind = .range_check_8_8,
            .table_log_size = range_bridge.LOG_SIZE,
            .table_size = range_bridge.TABLE_SIZE,
            .bridge_authority_digest = range_bridge.SOURCE_AUTHORITY_DIGEST,
            .sources = .{
                .{
                    .component = .statement_semantics_input,
                    .semantic_digest = statement_air.SEMANTIC_DIGEST,
                    .event_ordinal = 2,
                    .role = .request,
                },
                .{
                    .component = .vm_public_claim_input,
                    .semantic_digest = claim_air.SEMANTIC_DIGEST,
                    .event_ordinal = 5,
                    .role = .request,
                },
            },
        };
    }

    pub fn validate(self: SourceAuthority) Error!void {
        if (!std.meta.eql(self, pinned()) or
            self.table_kind != range_bridge.TABLE_KIND or
            self.table_log_size != lookup_schema.logSize(self.table_kind) or
            self.table_size != lookup_schema.size(self.table_kind) or
            statement_air.RELATION_EVENT_COUNT != 3 or
            claim_air.RELATION_EVENT_COUNT != 8)
        {
            return error.InvalidSourceAuthority;
        }
        const schema = relation.requireExactUniversalSchema(.range_check_8_8) catch
            return error.InvalidSourceAuthority;
        if (schema.fields.len != range_bridge.TUPLE_ARITY or
            !schema.allowed_roles.allows(.request))
        {
            return error.InvalidSourceAuthority;
        }
        try range_bridge.SourceAuthority.pinned().validate();
    }

    pub fn identityDigest(self: SourceAuthority) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(SOURCE_AUTHORITY_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u8, @intFromEnum(self.table_kind));
        hashInt(&hash, u32, self.table_log_size);
        hashInt(&hash, u32, self.table_size);
        hash.update(&self.bridge_authority_digest);
        hashInt(&hash, u16, self.sources.len);
        for (self.sources) |source| {
            hashInt(&hash, u8, @intFromEnum(source.component));
            hash.update(&source.semantic_digest);
            hashInt(&hash, u8, source.event_ordinal);
            hashInt(&hash, u8, @intFromEnum(source.role));
        }
        return hash.finalResult();
    }
};

pub const RequestCounts = struct {
    statement: u64,
    vm_claim: u64,

    pub fn total(self: RequestCounts) Error!u64 {
        return std.math.add(u64, self.statement, self.vm_claim) catch
            error.ArithmeticOverflow;
    }
};

/// The concrete row-11 circuit inputs.  `values` are ordered exactly like the
/// authenticated verifier-key preprocessing rows.
pub const StatementSource = struct {
    preprocessing: *const statement_witness.Preprocessed,
    values: []const M31,
};

/// All authority needed to derive the segment provider.  Row 12 is borrowed
/// from `segment_leaf_authority.Prepared`, preserving its chain back to the
/// admitted `PublicData` rather than accepting a detached claim witness.
pub const Sources = struct {
    data: *const public_data_mod.PublicData,
    leaf_preprocessing: *const leaf_owner.Preprocessing,
    leaf: *const leaf_owner.Prepared,
    statement: StatementSource,

    /// Allocation-free admission of both ledger sources.  It validates the
    /// complete row-11 witness, binds every active statement input to row 10,
    /// and revalidates row 12 through the segment leaf owner.
    pub fn validate(self: Sources) Error!RequestCounts {
        try SourceAuthority.pinned().validate();
        try self.leaf.validateAgainst(self.leaf_preprocessing, self.data);
        if (self.leaf.claim_input.proof_kind != .segment_leaf)
            return error.InvalidProofKind;

        try self.statement.preprocessing.validate();
        if (self.statement.values.len != self.statement.preprocessing.rows.len)
            return error.InputCountMismatch;

        var statement_count: u64 = 0;
        for (
            self.statement.preprocessing.rows,
            self.statement.values,
        ) |row, value| {
            _ = try statement_witness.mainRow(row, value, .segment_leaf);
            const active = row.active_kinds.contains(.segment_leaf);
            if (row.source == .statement and active) {
                // A segment proof exposes the same authenticated leaf statement
                // through both row-11 scopes: `segment` is the leaf input and
                // `parent` is the statement produced by leaf semantics. The
                // full circuit intentionally reads both. No other scope is
                // active or authoritative in segment mode.
                switch (row.statement_scope) {
                    statement_input.SEGMENT_STATEMENT_SCOPE,
                    statement_input.PARENT_STATEMENT_SCOPE,
                    => {},
                    else => return error.UnboundStatementScope,
                }
                const word_index: usize = @intCast(row.word_index);
                if (!value.eql(self.leaf.statement.words[word_index]))
                    return error.StatementAuthorityMismatch;
            }
            if (row.integer and active) {
                statement_count = std.math.add(u64, statement_count, 1) catch
                    return error.ArithmeticOverflow;
            }
        }

        var claim_count: u64 = 0;
        for (self.leaf_preprocessing.claim_input.rows) |row| {
            if (std.meta.activeTag(row.kind) == .u16) {
                claim_count = std.math.add(u64, claim_count, 1) catch
                    return error.ArithmeticOverflow;
            }
        }
        const counts = RequestCounts{
            .statement = statement_count,
            .vm_claim = claim_count,
        };
        _ = try counts.total();
        return counts;
    }
};

/// Reusable worker-private counter storage.  A workspace is never shared
/// between concurrent derivations; callers may pool one per proving worker.
pub const Workspace = struct {
    counter: lookup_counter.Counter,
    request_counts: RequestCounts,

    pub fn init(allocator: std.mem.Allocator) Error!Workspace {
        return .{
            .counter = try lookup_counter.Counter.init(
                allocator,
                range_bridge.TABLE_KIND,
            ),
            .request_counts = .{ .statement = 0, .vm_claim = 0 },
        };
    }

    pub fn deinit(self: *Workspace, allocator: std.mem.Allocator) void {
        self.counter.deinit(allocator);
        self.* = undefined;
    }

    pub fn validateGeometry(self: *const Workspace) Error!void {
        if (self.counter.kind != range_bridge.TABLE_KIND or
            self.counter.values.len != range_bridge.TABLE_SIZE)
        {
            return error.InvalidWorkspace;
        }
    }

    /// Derive the exact signed request counter with no allocation.  Every
    /// fallible source, geometry, and alias check completes before `@memset`.
    pub fn derive(
        self: *Workspace,
        sources: Sources,
    ) Error!RequestCounts {
        try self.validateGeometry();
        const counts = try sources.validate();
        try rejectSourceAliases(self, sources);
        self.deriveValidated(sources, counts);
        return counts;
    }

    fn deriveValidated(
        self: *Workspace,
        sources: Sources,
        counts: RequestCounts,
    ) void {
        @memset(self.counter.values, M31.zero());

        for (
            sources.statement.preprocessing.rows,
            sources.statement.values,
        ) |row, value| {
            if (row.integer and row.active_kinds.contains(.segment_leaf))
                registerRequest(self.counter.values, value.toU32());
        }

        for (
            sources.leaf_preprocessing.claim_input.rows,
            sources.leaf.claim_input.rows,
        ) |metadata, row| {
            if (std.meta.activeTag(metadata.kind) == .u16) {
                const logical_row = row.low_byte.toU32() |
                    (@as(u32, row.high_byte.toU32()) << 8);
                std.debug.assert(logical_row == row.value.toU32());
                registerRequest(self.counter.values, logical_row);
            }
        }
        self.request_counts = counts;
    }
};

/// Immutable row-35 snapshot produced from the complete segment ledger.
pub const Prepared = struct {
    format_version: u16,
    source_authority_digest: [32]u8,
    request_counts: RequestCounts,
    range_check: range_bridge.PreparedBatch,

    pub fn init(
        allocator: std.mem.Allocator,
        workspace: *Workspace,
        sources: Sources,
    ) Error!Prepared {
        const counts = try workspace.derive(sources);
        var range_check = try range_bridge.PreparedBatch.init(
            allocator,
            &workspace.counter,
        );
        errdefer range_check.deinit();
        const authority = SourceAuthority.pinned();
        const result = Prepared{
            .format_version = FORMAT_VERSION,
            .source_authority_digest = authority.identityDigest(),
            .request_counts = counts,
            .range_check = range_check,
        };
        try result.validateSnapshot(&workspace.counter, counts);
        return result;
    }

    pub fn deinit(self: *Prepared) void {
        self.range_check.deinit();
        self.* = undefined;
    }

    /// Re-derives the provider in reusable scratch and compares all 2^16
    /// multiplicities.  Source and prepared metadata errors are rejected
    /// before scratch mutation; no validation allocation is performed.
    pub fn validateAgainst(
        self: *const Prepared,
        workspace: *Workspace,
        sources: Sources,
    ) Error!void {
        try self.validateHeader();
        try self.range_check.validate();
        try workspace.validateGeometry();
        const expected_counts = try sources.validate();
        if (!std.meta.eql(self.request_counts, expected_counts))
            return error.RequestCountMismatch;
        try rejectPreparedAlias(self, workspace);
        try rejectSourceAliases(workspace, sources);
        workspace.deriveValidated(sources, expected_counts);
        try self.validateSnapshot(&workspace.counter, expected_counts);
    }

    pub fn provider(self: *const Prepared) *const range_bridge.PreparedBatch {
        return &self.range_check;
    }

    fn validateHeader(self: *const Prepared) Error!void {
        if (self.format_version != FORMAT_VERSION)
            return error.FormatVersionMismatch;
        const authority = SourceAuthority.pinned();
        try authority.validate();
        const expected = authority.identityDigest();
        if (!std.mem.eql(u8, &self.source_authority_digest, &expected))
            return error.AuthorityMismatch;
        _ = try self.request_counts.total();
    }

    fn validateSnapshot(
        self: *const Prepared,
        expected: *const lookup_counter.Counter,
        counts: RequestCounts,
    ) Error!void {
        if (!std.meta.eql(self.request_counts, counts))
            return error.RequestCountMismatch;
        try self.range_check.validateAgainstSource(expected);
        const expected_total = M31.zero().sub(M31.fromU64(try counts.total()));
        if (!self.range_check.counter.signedTotal().eql(expected_total))
            return error.RequestCountMismatch;
    }
};

inline fn registerRequest(values: []M31, raw: u32) void {
    std.debug.assert(raw <= std.math.maxInt(u16));
    const index: usize = @intCast(raw);
    values[index] = values[index].sub(M31.one());
}

fn rejectSourceAliases(workspace: *const Workspace, sources: Sources) Error!void {
    const destination = try sliceRange(M31, workspace.counter.values);
    const workspace_header = try objectRange(workspace);
    if (destination.overlaps(workspace_header)) return error.AliasedWorkspace;

    const ranges = [_]AddressRange{
        try sliceRange(M31, sources.statement.values),
        try sliceRange(statement_witness.Row, sources.statement.preprocessing.rows),
        try objectRange(sources.statement.preprocessing),
        try sliceRange(claim_witness.PreprocessedRow, sources.leaf_preprocessing.claim_input.rows),
        try objectRange(sources.leaf_preprocessing),
        try sliceRange(claim_witness.MainRow, sources.leaf.claim_input.rows),
        try objectRange(sources.leaf),
    };
    for (ranges) |source| if (destination.overlaps(source))
        return error.AliasedWorkspace;
}

fn rejectPreparedAlias(prepared: *const Prepared, workspace: *const Workspace) Error!void {
    const destination = try sliceRange(M31, workspace.counter.values);
    if (destination.overlaps(try objectRange(prepared)) or
        destination.overlaps(try sliceRange(M31, prepared.range_check.counter.values)))
    {
        return error.AliasedWorkspace;
    }
}

const AddressRange = struct {
    start: usize,
    end: usize,

    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn sliceRange(comptime T: type, values: []const T) Error!AddressRange {
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.ArithmeticOverflow;
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = std.math.add(usize, start, byte_len) catch
            return error.ArithmeticOverflow,
    };
}

fn objectRange(pointer: anytype) Error!AddressRange {
    const info = @typeInfo(@TypeOf(pointer));
    if (info != .pointer or info.pointer.size != .one)
        @compileError("range authority protects only single-item pointers");
    const start = @intFromPtr(pointer);
    return .{
        .start = start,
        .end = std.math.add(usize, start, @sizeOf(info.pointer.child)) catch
            return error.ArithmeticOverflow,
    };
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (range_bridge.TABLE_SIZE != (@as(usize, 1) << 16) or
        range_bridge.TABLE_SIZE > std.math.maxInt(u32) or
        m31.Modulus <= std.math.maxInt(u16))
    {
        @compileError("segment range authority requires the frozen 8+8 table");
    }
}

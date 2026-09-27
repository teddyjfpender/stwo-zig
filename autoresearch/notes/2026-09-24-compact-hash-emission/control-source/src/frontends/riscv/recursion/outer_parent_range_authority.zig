//! Binary-node authority for universal recursion row 35.
//!
//! Binary parents activate statement-semantics row 11 and leave VM-public
//! rows 12--17 inactive. Their `(8, 8)` range provider must therefore contain
//! exactly the integer requests reconstructed from the authenticated binary
//! statement circuit, with no segment-only VM-claim requests. This module owns
//! that one-source ledger and borrows the existing native row-35 provider.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;

const lookup_counter = @import("../air/lookups/tables/counter.zig");
const lookup_schema = @import("../air/lookups/tables/schema.zig");
const relation = @import("../air/lang/relation.zig");
const span_statement = @import("span_statement.zig");
const row11_air = @import("air/statement_semantics_input.zig");
const row11_witness = @import("air/statement_semantics_input_witness.zig");
const statement_input = @import("air/statement_input.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const roster = @import("air/universal_roster.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SOURCE_AUTHORITY_FORMAT_VERSION: u16 = 1;
pub const SOURCE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/outer-parent-range-authority/v1\x00";
pub const LEDGER_SOURCE_COUNT: usize = 1;

pub const Error = row11_witness.Error || range_bridge.Error ||
    lookup_counter.Error || std.mem.Allocator.Error || error{
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

pub const LedgerSource = struct {
    component: roster.Component,
    semantic_digest: [32]u8,
    event_ordinal: u8,
    role: relation.Role,
};

/// Complete binary-node range-request surface. Any future binary component
/// that requests this table requires a versioned update here.
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
            .sources = .{.{
                .component = .statement_semantics_input,
                .semantic_digest = row11_air.SEMANTIC_DIGEST,
                .event_ordinal = 2,
                .role = .request,
            }},
        };
    }

    pub fn validate(self: SourceAuthority) Error!void {
        if (!std.meta.eql(self, pinned()) or
            self.table_kind != range_bridge.TABLE_KIND or
            self.table_log_size != lookup_schema.logSize(self.table_kind) or
            self.table_size != lookup_schema.size(self.table_kind) or
            row11_air.RELATION_EVENT_COUNT != 3)
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

pub const StatementWords = span_statement.StatementWords;

/// Exact row-11 values plus the three canonical statement scopes they must
/// expose in binary mode. Values originate from the sealed circuit evaluator;
/// detached, caller-transcribed integer requests are never accepted.
pub const Sources = struct {
    preprocessing: *const row11_witness.Preprocessed,
    values: []const M31,
    left: *const StatementWords,
    right: *const StatementWords,
    parent: *const StatementWords,

    pub fn validate(self: Sources) Error!u64 {
        try SourceAuthority.pinned().validate();
        try self.preprocessing.validate();
        if (self.values.len != self.preprocessing.rows.len)
            return error.InputCountMismatch;

        var request_count: u64 = 0;
        for (self.preprocessing.rows, self.values) |row, value| {
            _ = try row11_witness.mainRow(row, value, .binary_node);
            const active = row.active_kinds.contains(.binary_node);
            if (row.source == .statement and active) {
                const expected = switch (row.statement_scope) {
                    statement_input.LEFT_STATEMENT_SCOPE => self.left,
                    statement_input.RIGHT_STATEMENT_SCOPE => self.right,
                    statement_input.PARENT_STATEMENT_SCOPE => self.parent,
                    else => return error.UnboundStatementScope,
                };
                if (!value.eql(expected[row.word_index]))
                    return error.StatementAuthorityMismatch;
            }
            if (row.integer and active) {
                request_count = std.math.add(u64, request_count, 1) catch
                    return error.ArithmeticOverflow;
            }
        }
        if (request_count != self.preprocessing.activeIntegerCount(.binary_node))
            return error.RequestCountMismatch;
        return request_count;
    }
};

pub const Workspace = struct {
    counter: lookup_counter.Counter,
    request_count: u64,

    pub fn init(allocator: std.mem.Allocator) Error!Workspace {
        return .{
            .counter = try lookup_counter.Counter.init(
                allocator,
                range_bridge.TABLE_KIND,
            ),
            .request_count = 0,
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

    /// Allocation-free derivation. Complete source and alias validation occurs
    /// before the first counter cell is cleared.
    pub fn derive(self: *Workspace, sources: Sources) Error!u64 {
        try self.validateGeometry();
        const request_count = try sources.validate();
        try rejectSourceAliases(self, sources);
        self.deriveValidated(sources, request_count);
        return request_count;
    }

    fn deriveValidated(
        self: *Workspace,
        sources: Sources,
        request_count: u64,
    ) void {
        @memset(self.counter.values, M31.zero());
        for (sources.preprocessing.rows, sources.values) |row, value| {
            if (row.integer and row.active_kinds.contains(.binary_node))
                registerRequest(self.counter.values, value.toU32());
        }
        self.request_count = request_count;
    }
};

pub const Prepared = struct {
    format_version: u16 = FORMAT_VERSION,
    source_authority_digest: [32]u8,
    request_count: u64,
    range_check: range_bridge.PreparedBatch,

    pub fn init(
        allocator: std.mem.Allocator,
        workspace: *Workspace,
        sources: Sources,
    ) Error!Prepared {
        const request_count = try workspace.derive(sources);
        var range_check = try range_bridge.PreparedBatch.init(
            allocator,
            &workspace.counter,
        );
        errdefer range_check.deinit();
        const result = Prepared{
            .source_authority_digest = SourceAuthority.pinned().identityDigest(),
            .request_count = request_count,
            .range_check = range_check,
        };
        try result.validateSnapshot(&workspace.counter, request_count);
        return result;
    }

    pub fn deinit(self: *Prepared) void {
        self.range_check.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const Prepared,
        workspace: *Workspace,
        sources: Sources,
    ) Error!void {
        try self.validateHeader();
        try self.range_check.validate();
        try workspace.validateGeometry();
        const request_count = try sources.validate();
        if (self.request_count != request_count)
            return error.RequestCountMismatch;
        try rejectPreparedAlias(self, workspace);
        try rejectSourceAliases(workspace, sources);
        workspace.deriveValidated(sources, request_count);
        try self.validateSnapshot(&workspace.counter, request_count);
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
        if (!std.mem.eql(
            u8,
            &self.source_authority_digest,
            &expected,
        )) return error.AuthorityMismatch;
    }

    fn validateSnapshot(
        self: *const Prepared,
        counter: *const lookup_counter.Counter,
        request_count: u64,
    ) Error!void {
        if (self.request_count != request_count or
            self.range_check.counter.values.len != counter.values.len)
        {
            return error.RequestCountMismatch;
        }
        for (self.range_check.counter.values, counter.values) |snapshot, count| {
            if (!snapshot.eql(count)) {
                return error.AuthorityMismatch;
            }
        }
        const expected_total = M31.zero().sub(M31.fromU64(request_count));
        if (!self.range_check.counter.signedTotal().eql(expected_total))
            return error.RequestCountMismatch;
    }
};

fn registerRequest(counter: []M31, value: u32) void {
    std.debug.assert(value <= std.math.maxInt(u16));
    counter[value] = counter[value].sub(M31.one());
}

fn rejectSourceAliases(workspace: *const Workspace, sources: Sources) Error!void {
    const counter_bytes = std.mem.sliceAsBytes(workspace.counter.values);
    if (byteSlicesOverlap(counter_bytes, std.mem.asBytes(sources.preprocessing)) or
        byteSlicesOverlap(counter_bytes, std.mem.sliceAsBytes(sources.preprocessing.rows)) or
        byteSlicesOverlap(counter_bytes, std.mem.sliceAsBytes(sources.values)) or
        byteSlicesOverlap(counter_bytes, std.mem.asBytes(sources.left)) or
        byteSlicesOverlap(counter_bytes, std.mem.asBytes(sources.right)) or
        byteSlicesOverlap(counter_bytes, std.mem.asBytes(sources.parent)))
    {
        return error.AliasedWorkspace;
    }
}

fn rejectPreparedAlias(prepared: *const Prepared, workspace: *const Workspace) Error!void {
    const counter_bytes = std.mem.sliceAsBytes(workspace.counter.values);
    if (byteSlicesOverlap(counter_bytes, std.mem.asBytes(prepared)) or
        byteSlicesOverlap(
            counter_bytes,
            std.mem.sliceAsBytes(prepared.range_check.counter.values),
        ))
    {
        return error.AliasedWorkspace;
    }
}

fn byteSlicesOverlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (LEDGER_SOURCE_COUNT != 1 or row11_air.RELATION_EVENT_COUNT != 3 or
        range_bridge.LOG_SIZE != 16)
    {
        @compileError("outer parent binary range authority drifted");
    }
}

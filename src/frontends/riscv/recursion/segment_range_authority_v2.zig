//! Complete V2 authority for the shared universal `(8, 8)` provider at row 35.
//!
//! The statement spine owns three request lanes in its V2 row-11 AIR. This
//! module reconstructs those requests from the authenticated logical rows,
//! derives the exact 2^16 signed counter without allocating, and can create an
//! immutable bridge snapshot. Rows 12--17 are uniform relay AIRs with no range
//! requests, so these three row-11 lanes are the complete V2 request set.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const lookup_counter = @import("../air/lookups/tables/counter.zig");
const lookup_interaction = @import("../air/lookups/tables/interaction.zig");
const lookup_schema = @import("../air/lookups/tables/schema.zig");
const relation = @import("../air/lang/relation.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const shared_provider = @import("air/universal_shared_provider.zig");
const universal = @import("air/universal_challenges.zig");
const manifest_v2 = @import("air/segment_outer_adapter_manifest_v2.zig");
const statement = @import("segment_statement_outer_source_v2.zig");

pub const Digest = statement.Digest;
pub const Sha256Digest = [32]u8;
pub const AdapterV2 = shared_provider.RangeCheck8x8AdapterForManifest(
    manifest_v2,
);

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 2;
pub const SOURCE_AUTHORITY_FORMAT_VERSION: u16 = 3;
pub const LEDGER_SOURCE_COUNT: usize = 3;
pub const HOT_DERIVE_HEAP_ALLOCATIONS: usize = 0;
pub const ROW_35_COMPLETE = true;
pub const PRODUCTION_ACTIVATION = true;
pub const SOURCE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/segment-range-authority-v2/complete/v2\x00";

pub const Error = statement.Error || range_bridge.Error ||
    range_bridge.DefinitionError ||
    lookup_counter.Error || std.mem.Allocator.Error || error{
    AliasedWorkspace,
    ArithmeticOverflow,
    AuthorityMismatch,
    FormatVersionMismatch,
    InvalidSourceAuthority,
    InvalidWorkspace,
    NonCanonicalRangeByte,
    RequestCountMismatch,
    RequestProviderClosureMismatch,
};

pub const LedgerSourceV2 = struct {
    component_index: u8,
    semantic_digest: Sha256Digest,
    event_ordinal: u8,
    role: relation.Role,
};

/// Pins the complete V2 request set. Adding or removing a request lane
/// necessarily changes this identity.
pub const SourceAuthorityV2 = struct {
    format_version: u16 = SOURCE_AUTHORITY_FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    table_kind: lookup_schema.Kind = .range_check_8_8,
    table_log_size: u32 = range_bridge.LOG_SIZE,
    table_size: u32 = range_bridge.TABLE_SIZE,
    bridge_authority_digest: Sha256Digest = range_bridge.SOURCE_AUTHORITY_DIGEST,
    sources: [LEDGER_SOURCE_COUNT]LedgerSourceV2,

    pub fn pinned() SourceAuthorityV2 {
        return .{
            .sources = .{
                source(3),
                source(4),
                source(5),
            },
        };
    }

    pub fn validate(self: SourceAuthorityV2) Error!void {
        if (!std.meta.eql(self, pinned()) or
            self.format_version != SOURCE_AUTHORITY_FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.table_kind != range_bridge.TABLE_KIND or
            self.table_log_size != lookup_schema.logSize(self.table_kind) or
            self.table_size != lookup_schema.size(self.table_kind) or
            statement.Air.RELATION_EVENT_COUNT != 7 or
            !statement.ROW_35_REQUEST_SET_COMPLETE)
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

    pub fn identityDigest(self: SourceAuthorityV2) Sha256Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(SOURCE_AUTHORITY_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.schema_version);
        hashInt(&hash, u8, @intFromEnum(self.table_kind));
        hashInt(&hash, u32, self.table_log_size);
        hashInt(&hash, u32, self.table_size);
        hash.update(&self.bridge_authority_digest);
        hashInt(&hash, u16, self.sources.len);
        for (self.sources) |item| {
            hashInt(&hash, u8, item.component_index);
            hash.update(&item.semantic_digest);
            hashInt(&hash, u8, item.event_ordinal);
            hashInt(&hash, u8, @intFromEnum(item.role));
        }
        return hash.finalResult();
    }
};

pub const SourcesV2 = struct {
    statement: *const statement.PreparedV2,
    logical_rows: []const statement.Air.Row,

    pub fn validate(self: SourcesV2) Error!u64 {
        try SourceAuthorityV2.pinned().validate();
        try statement.validateLogicalRows(self.statement, self.logical_rows);
        if (!self.statement.manifest.range_request_source_complete or
            !self.statement.row35_request_set_complete)
        {
            return error.InvalidSourceAuthority;
        }
        var count: u64 = 0;
        for (self.logical_rows) |row| {
            for (0..LEDGER_SOURCE_COUNT) |lane| {
                const mask = row[statement.Air.PHYSICAL_MAIN_COLUMN_COUNT + 6 + lane];
                if (mask.toU32() > 1) return error.AuthorityMismatch;
                if (!mask.isZero()) {
                    const low = row[4 + 2 * lane].toU32();
                    const high = row[5 + 2 * lane].toU32();
                    if (low > 0xff or high > 0xff)
                        return error.NonCanonicalRangeByte;
                    count = std.math.add(u64, count, 1) catch
                        return error.ArithmeticOverflow;
                }
            }
        }
        if (count != self.statement.manifest.range_request_count)
            return error.RequestCountMismatch;
        return count;
    }
};

/// Stable typed-program authority used by the V2 row-35 adapter.  The
/// relation definition and physical witness binding are authenticated once;
/// no caller-authored geometry enters component construction.
pub const ProviderAuthorityV2 = struct {
    definition: range_bridge.Definition,
    binding: range_bridge.Binding,
    executor: range_bridge.Executor,

    pub fn init(allocator: std.mem.Allocator) Error!ProviderAuthorityV2 {
        var definition = try range_bridge.build(allocator);
        errdefer definition.deinit();
        const binding = try range_bridge.Binding.canonical(&definition);
        const executor = try range_bridge.Executor.init(&definition, &binding);
        var result = ProviderAuthorityV2{
            .definition = definition,
            .binding = binding,
            .executor = executor,
        };
        try result.validate();
        return result;
    }

    pub fn deinit(self: *ProviderAuthorityV2) void {
        self.definition.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const ProviderAuthorityV2) Error!void {
        try self.definition.validate();
        try self.executor.validate();
        const expected = try range_bridge.Binding.canonical(&self.definition);
        if (!std.meta.eql(self.binding, expected) or
            !std.meta.eql(self.executor.binding, expected))
        {
            return error.AuthorityMismatch;
        }
    }
};

/// Reusable worker-private 2^16 counter. `derive` is allocation-free and
/// validates every source and alias before clearing the first counter cell.
pub const WorkspaceV2 = struct {
    counter: lookup_counter.Counter,
    request_count: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) Error!WorkspaceV2 {
        return .{ .counter = try lookup_counter.Counter.init(
            allocator,
            range_bridge.TABLE_KIND,
        ) };
    }

    pub fn deinit(self: *WorkspaceV2, allocator: std.mem.Allocator) void {
        self.counter.deinit(allocator);
        self.* = undefined;
    }

    pub fn validateGeometry(self: *const WorkspaceV2) Error!void {
        if (self.counter.kind != range_bridge.TABLE_KIND or
            self.counter.values.len != range_bridge.TABLE_SIZE)
        {
            return error.InvalidWorkspace;
        }
    }

    pub fn derive(self: *WorkspaceV2, sources: SourcesV2) Error!u64 {
        try self.validateGeometry();
        const request_count = try sources.validate();
        try rejectSourceAliases(self, sources);
        self.deriveValidated(sources, request_count);
        return request_count;
    }

    fn deriveValidated(
        self: *WorkspaceV2,
        sources: SourcesV2,
        request_count: u64,
    ) void {
        @memset(self.counter.values, M31.zero());
        for (sources.logical_rows) |row| {
            for (0..LEDGER_SOURCE_COUNT) |lane| {
                const mask = row[statement.Air.PHYSICAL_MAIN_COLUMN_COUNT + 6 + lane];
                if (!mask.isZero()) {
                    const low = row[4 + 2 * lane].toU32();
                    const high = row[5 + 2 * lane].toU32();
                    const index: usize = @intCast(low | (high << 8));
                    self.counter.values[index] =
                        self.counter.values[index].sub(M31.one());
                }
            }
        }
        self.request_count = request_count;
    }
};

/// Immutable snapshot of the complete admitted request ledger.
pub const PreparedPartialV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    source_authority_digest: Sha256Digest,
    statement_prepared_id: Digest,
    request_count: u64,
    range_check: range_bridge.PreparedBatch,

    pub fn init(
        allocator: std.mem.Allocator,
        workspace: *WorkspaceV2,
        sources: SourcesV2,
    ) Error!PreparedPartialV2 {
        const request_count = try workspace.derive(sources);
        var range_check = try range_bridge.PreparedBatch.init(
            allocator,
            &workspace.counter,
        );
        errdefer range_check.deinit();
        const authority = SourceAuthorityV2.pinned();
        const result = PreparedPartialV2{
            .source_authority_digest = authority.identityDigest(),
            .statement_prepared_id = sources.statement.identity,
            .request_count = request_count,
            .range_check = range_check,
        };
        try result.validateSnapshot(&workspace.counter, request_count);
        return result;
    }

    pub fn deinit(self: *PreparedPartialV2) void {
        self.range_check.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const PreparedPartialV2,
        workspace: *WorkspaceV2,
        sources: SourcesV2,
    ) Error!void {
        try self.validateHeader();
        try self.range_check.validate();
        try workspace.validateGeometry();
        const request_count = try sources.validate();
        if (self.request_count != request_count or !std.meta.eql(
            self.statement_prepared_id,
            sources.statement.identity,
        )) return error.RequestCountMismatch;
        try rejectPreparedAlias(self, workspace);
        try rejectSourceAliases(workspace, sources);
        workspace.deriveValidated(sources, request_count);
        try self.validateSnapshot(&workspace.counter, request_count);
    }

    pub fn provider(
        self: *const PreparedPartialV2,
    ) *const range_bridge.PreparedBatch {
        return &self.range_check;
    }

    pub fn publication(
        self: *const PreparedPartialV2,
    ) Error!*const range_bridge.PreparedBatch {
        try self.validateHeader();
        try self.range_check.validate();
        return &self.range_check;
    }

    /// Generates the exact native singleton-prefix columns and row-35 claim
    /// against the universal challenge binding. This is the sole claim path;
    /// callers cannot inject a detached claimed sum into `component`.
    pub fn generateProviderInteraction(
        self: *const PreparedPartialV2,
        allocator: std.mem.Allocator,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !ProviderInteractionV2 {
        try self.validateHeader();
        try self.range_check.validate();
        try provider_relations.validate();
        var result = try self.range_check.generateNativeInteraction(
            allocator,
            &provider_relations.native,
        );
        errdefer result.deinit(allocator);
        var provider_interaction = ProviderInteractionV2{
            .allocator = allocator,
            .result = result,
            .source_authority_digest = self.source_authority_digest,
            .statement_prepared_id = self.statement_prepared_id,
            .request_count = self.request_count,
        };
        try provider_interaction.validate();
        return provider_interaction;
    }

    /// Allocation-free exact LogUp closure between all three row-11 request
    /// lanes and the generated shared-table claim.
    pub fn verifyExactClosure(
        self: *const PreparedPartialV2,
        sources: SourcesV2,
        relations: *const universal.UniversalRelations,
        provider_claim: QM31,
    ) Error!void {
        try self.validateHeader();
        try self.range_check.validate();
        try relations.validate();
        const request_count = try sources.validate();
        if (request_count != self.request_count or
            !std.meta.eql(self.statement_prepared_id, sources.statement.identity))
        {
            return error.RequestCountMismatch;
        }
        const challenge = try relations.getExact(.range_check_8_8);
        var request_claim = QM31.zero();
        for (sources.logical_rows) |row| {
            for (0..LEDGER_SOURCE_COUNT) |lane| {
                const mask = row[
                    statement.Air.PHYSICAL_MAIN_COLUMN_COUNT + 6 + lane
                ];
                if (mask.isZero()) continue;
                const tuple = [_]M31{ row[4 + 2 * lane], row[5 + 2 * lane] };
                const denominator = try challenge.combineBase(&tuple);
                const inverse = denominator.inv() catch
                    return error.RequestProviderClosureMismatch;
                request_claim = request_claim.sub(inverse);
            }
        }
        if (!request_claim.add(provider_claim).isZero())
            return error.RequestProviderClosureMismatch;
    }

    pub fn productionReady(_: *const PreparedPartialV2) bool {
        return PRODUCTION_ACTIVATION;
    }

    fn validateHeader(self: *const PreparedPartialV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.FormatVersionMismatch;
        }
        const authority = SourceAuthorityV2.pinned();
        try authority.validate();
        const expected = authority.identityDigest();
        if (!std.mem.eql(u8, &self.source_authority_digest, &expected) or
            digestIsZero(self.statement_prepared_id))
        {
            return error.AuthorityMismatch;
        }
    }

    fn validateSnapshot(
        self: *const PreparedPartialV2,
        counter: *const lookup_counter.Counter,
        request_count: u64,
    ) Error!void {
        try self.validateHeader();
        if (self.request_count != request_count)
            return error.RequestCountMismatch;
        try self.range_check.validateAgainstSource(counter);
        const expected_total = M31.zero().sub(M31.fromU64(request_count));
        if (!self.range_check.counter.signedTotal().eql(expected_total))
            return error.RequestCountMismatch;
    }
};

/// Owned exact Tree-2 columns and claim for the complete row-35 provider.
pub const ProviderInteractionV2 = struct {
    allocator: std.mem.Allocator,
    result: lookup_interaction.Result,
    source_authority_digest: Sha256Digest,
    statement_prepared_id: Digest,
    request_count: u64,

    pub fn deinit(self: *ProviderInteractionV2) void {
        self.result.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn validate(self: *const ProviderInteractionV2) Error!void {
        const expected_authority = SourceAuthorityV2.pinned();
        try expected_authority.validate();
        if (!std.mem.eql(
            u8,
            &self.source_authority_digest,
            &expected_authority.identityDigest(),
        ) or digestIsZero(self.statement_prepared_id) or self.request_count == 0) {
            return error.AuthorityMismatch;
        }
        for (self.result.columns) |column| {
            if (column.len != range_bridge.TABLE_SIZE)
                return error.InvalidWorkspace;
            for (column) |value| if (value.toU32() >= stwo_core.fields.m31.Modulus)
                return error.NonCanonicalRangeByte;
        }
        const final_row = range_bridge.committedRow(range_bridge.TABLE_SIZE - 1);
        const final_claim = QM31.fromM31(
            self.result.columns[0][final_row],
            self.result.columns[1][final_row],
            self.result.columns[2][final_row],
            self.result.columns[3][final_row],
        );
        if (!final_claim.eql(self.result.claim))
            return error.RequestProviderClosureMismatch;
    }

    pub fn claim(self: *const ProviderInteractionV2) QM31 {
        return self.result.claim;
    }

    pub fn columns(
        self: *const ProviderInteractionV2,
    ) *const [range_bridge.INTERACTION_COLUMN_COUNT][]M31 {
        return &self.result.columns;
    }

    /// Exact typed component binding for the complete 38-row V2 manifest.
    pub fn component(
        self: *const ProviderInteractionV2,
        authority: *const ProviderAuthorityV2,
        manifest: *const manifest_v2.Manifest,
        provider_relations: *const shared_provider.SharedProviderRelations,
        relations: *const universal.UniversalRelations,
    ) !AdapterV2 {
        try self.validate();
        try authority.validate();
        return AdapterV2.init(
            &authority.definition,
            &authority.executor,
            manifest,
            provider_relations,
            relations,
            self.result.claim,
        );
    }
};

/// Compatibility alias for callers written while the complete-source audit
/// was still pending. New code should use `PreparedV2`.
pub const PreparedV2 = PreparedPartialV2;

fn source(comptime ordinal: u8) LedgerSourceV2 {
    return .{
        .component_index = statement.ROUTING_ROW_11,
        .semantic_digest = statement.Air.SEMANTIC_DIGEST,
        .event_ordinal = ordinal,
        .role = .request,
    };
}

fn rejectSourceAliases(
    workspace: *const WorkspaceV2,
    sources: SourcesV2,
) Error!void {
    const destination = std.mem.sliceAsBytes(workspace.counter.values);
    if (overlap(destination, std.mem.asBytes(sources.statement)) or
        overlap(destination, std.mem.sliceAsBytes(sources.logical_rows)))
    {
        return error.AliasedWorkspace;
    }
}

fn rejectPreparedAlias(
    prepared: *const PreparedPartialV2,
    workspace: *const WorkspaceV2,
) Error!void {
    const destination = std.mem.sliceAsBytes(workspace.counter.values);
    if (overlap(destination, std.mem.asBytes(prepared)) or
        overlap(destination, std.mem.sliceAsBytes(prepared.range_check.counter.values)))
    {
        return error.AliasedWorkspace;
    }
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

fn digestIsZero(value: Digest) bool {
    var aggregate: u32 = 0;
    for (value) |word| aggregate |= word;
    return aggregate == 0;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (LEDGER_SOURCE_COUNT != 3 or range_bridge.LOG_SIZE != 16 or
        statement.RANGE_PROVIDER_ROW_35 != 35 or !ROW_35_COMPLETE or
        !PRODUCTION_ACTIVATION)
    {
        @compileError("complete V2 segment range authority drifted");
    }
}

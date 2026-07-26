//! Exact relation evidence derived from production commitment inputs.
//!
//! The exporter never accepts `TraceRow`: callers provide the padded M31
//! columns in the exact bit-reversed order passed to the main-tree commitment,
//! plus their digest and the native interaction claim bound by the final proof.
//! It restores logical row order, dispatches through `opcode_entries.fromMain`,
//! streams raw entries, and recomputes the declaration-order batched claim.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const blake2 = @import("stwo_core").vcs.blake2_hash;
const infra = @import("../infra_trace.zig");
const trace = @import("../runner/trace.zig");
const entry_mod = @import("lookups/entry.zig");
const opcode_entries = @import("lookups/opcode_entries.zig");
const public_data = @import("public_data.zig");
const public_logup = @import("public_logup.zig");
const relations_mod = @import("relation_challenges.zig");
const claims = @import("transcript/claims.zig");

pub const Digest = blake2.Blake2sHash;
pub const Component = claims.Component;
pub const Domain = entry_mod.Domain;
pub const COMPONENT_COUNT = claims.COMPONENT_COUNT;
pub const DOMAIN_COUNT = entry_mod.DOMAIN_COUNT;

const tuple_digest_domain = "stwo-zig/riscv/relation-tuples/v1\x00";
const column_digest_domain = "stwo-zig/riscv/committed-family-shard/v1\x00";
const shard_manifest_domain = "stwo-zig/riscv/family-shard-manifest/v1\x00";
const absent_component_domain = "stwo-zig/riscv/absent-component/v1\x00";

pub const Error = error{
    UnboundPreprocessedCommitment,
    UnboundMainCommitment,
    UnboundDiagnosticInteractionCommitment,
    MainColumnsDigestMismatch,
    InvalidColumnCount,
    InvalidColumnLength,
    InvalidDomainSize,
    InvalidShardCount,
    InvalidShardGeometry,
    ShardOutOfOrder,
    InactiveRealRow,
    NonZeroPadding,
    InvalidEntryArity,
    InvalidRelationArity,
    NonBaseEntry,
    ZeroDenominator,
    ClaimMismatch,
    ComponentOutOfOrder,
    ComponentAlreadyChecked,
    IncompleteComponents,
    IncompleteClaims,
    DuplicateExecutionRow,
    ExecutionRowOutOfRange,
    IncompleteExecutionRows,
    InvalidExecutionProvenance,
    NonCanonicalExecutionOrder,
    PoisonedSequence,
};

pub const RawEntry = struct {
    domain: Domain,
    numerator: M31,
    arity: u8,
    values: [entry_mod.MAX_ARITY]M31 = .{M31.zero()} ** entry_mod.MAX_ARITY,
};

pub const Location = struct {
    component: Component,
    shard: u32,
    row: usize,
    declaration: usize,
    opcode: ?OpcodeRequestProvenance = null,
};

/// Diagnostic identity of one opcode relation request. `execution_row` is the
/// one-based clock committed by the opcode row; `family_row` is its canonical
/// position after filtering the execution by family.
pub const OpcodeRequestProvenance = struct {
    execution_row: u32,
    family: trace.OpcodeFamily,
    family_row: u64,
    request_ordinal: u32,
};

pub const StreamDigest = struct {
    entries: u64,
    digest: Digest,
};

pub const TupleEvidence = struct {
    all: StreamDigest,
    zero: StreamDigest,
    nonzero: StreamDigest,
    domains: [DOMAIN_COUNT]StreamDigest,
    domain_zero: [DOMAIN_COUNT]StreamDigest,
    domain_nonzero: [DOMAIN_COUNT]StreamDigest,
};

pub const ComponentEvidence = struct {
    component: Component,
    all: StreamDigest,
    zero: StreamDigest,
    nonzero: StreamDigest,
    domains: [DOMAIN_COUNT]StreamDigest,
    domain_zero: [DOMAIN_COUNT]StreamDigest,
    domain_nonzero: [DOMAIN_COUNT]StreamDigest,
    domain_sums: [DOMAIN_COUNT]QM31,
    computed_claim: QM31,
    native_claim: QM31,
    shard_count: u32,
    shard_manifest_digest: Digest,
    absent: bool,
};

pub const OpcodeShard = struct {
    ordinal: u32,
    shard_count: u32,
    n_real_rows: usize,
    committed_columns: []const []const M31,
    main_columns_digest: Digest,
};

pub const ShardEvidence = struct {
    component: Component,
    ordinal: u32,
    shard_count: u32,
    n_real_rows: usize,
    domain_size: usize,
    main_columns_digest: Digest,
    all: StreamDigest,
    zero: StreamDigest,
    nonzero: StreamDigest,
    domains: [DOMAIN_COUNT]StreamDigest,
    domain_zero: [DOMAIN_COUNT]StreamDigest,
    domain_nonzero: [DOMAIN_COUNT]StreamDigest,
};

pub const ClaimEvidence = struct {
    claims: [COMPONENT_COUNT]QM31,
    prefixes: [COMPONENT_COUNT]QM31,
    total: QM31,
    preprocessed_tree: Digest,
    main_tree: Digest,
    diagnostic_interaction_tree: Digest,
};

pub const AggregateEvidence = struct {
    all: StreamDigest,
    zero: StreamDigest,
    nonzero: StreamDigest,
    domains: [DOMAIN_COUNT]StreamDigest,
    domain_zero: [DOMAIN_COUNT]StreamDigest,
    domain_nonzero: [DOMAIN_COUNT]StreamDigest,
    domain_sums: [DOMAIN_COUNT]QM31,
};

pub const PublicEvidence = struct {
    domains: [DOMAIN_COUNT]QM31,
    total: QM31,
};

/// Native proof claims plus the commitment identities emitted by the final
/// proof call. A component is checked exactly once against a recomputation
/// from its main-tree tuples before `finish` exposes cumulative prefixes.
pub const ClaimLedger = struct {
    native: [COMPONENT_COUNT]QM31,
    checked: [COMPONENT_COUNT]bool = .{false} ** COMPONENT_COUNT,
    preprocessed_tree: Digest,
    main_tree: Digest,
    diagnostic_interaction_tree: Digest,

    pub fn init(
        preprocessed_tree: Digest,
        main_tree: Digest,
        diagnostic_interaction_tree: Digest,
        native: *const claims.InteractionClaim,
    ) Error!ClaimLedger {
        if (isZeroDigest(preprocessed_tree)) return error.UnboundPreprocessedCommitment;
        if (isZeroDigest(main_tree)) return error.UnboundMainCommitment;
        if (isZeroDigest(diagnostic_interaction_tree))
            return error.UnboundDiagnosticInteractionCommitment;
        return .{
            .native = native.claimed_sums,
            .preprocessed_tree = preprocessed_tree,
            .main_tree = main_tree,
            .diagnostic_interaction_tree = diagnostic_interaction_tree,
        };
    }

    pub fn check(self: *ClaimLedger, component: Component, computed: QM31) Error!QM31 {
        const index = @intFromEnum(component);
        if (self.checked[index]) return error.ComponentAlreadyChecked;
        const native = self.native[index];
        if (!computed.eql(native)) return error.ClaimMismatch;
        self.checked[index] = true;
        return native;
    }

    pub fn finish(self: *const ClaimLedger) Error!ClaimEvidence {
        for (self.checked) |checked| if (!checked) return error.IncompleteClaims;
        var prefixes: [COMPONENT_COUNT]QM31 = undefined;
        var total = QM31.zero();
        for (self.native, &prefixes) |claim, *prefix| {
            total = total.add(claim);
            prefix.* = total;
        }
        return .{
            .claims = self.native,
            .prefixes = prefixes,
            .total = total,
            .preprocessed_tree = self.preprocessed_tree,
            .main_tree = self.main_tree,
            .diagnostic_interaction_tree = self.diagnostic_interaction_tree,
        };
    }
};

/// Global raw-stream accumulator. Components must be appended in the pinned
/// Rust registry order. This state cannot be finalized from an opcode-only or
/// otherwise partial export.
pub const Sequence = struct {
    next_component: usize = 0,
    streams: ComponentStreams,
    domain_sums: [DOMAIN_COUNT]QM31 = .{QM31.zero()} ** DOMAIN_COUNT,
    execution_rows: ?ExecutionRows = null,
    poisoned: bool = false,

    pub fn init() Sequence {
        return .{ .streams = ComponentStreams.init() };
    }

    /// Enable exact-once execution-row checks for a complete diagnostic run.
    /// Production proof acceptance does not currently consume this ledger.
    pub fn initForExecution(
        allocator: std.mem.Allocator,
        total_steps: u32,
    ) !Sequence {
        var result = init();
        result.execution_rows = try ExecutionRows.init(allocator, total_steps);
        return result;
    }

    pub fn deinit(self: *Sequence, allocator: std.mem.Allocator) void {
        if (self.execution_rows) |*rows| rows.deinit(allocator);
        self.execution_rows = null;
    }

    pub fn begin(self: *Sequence, component: Component) Error!void {
        if (self.poisoned) return error.PoisonedSequence;
        if (@intFromEnum(component) != self.next_component) return error.ComponentOutOfOrder;
    }

    pub fn append(self: *Sequence, raw: RawEntry, term: QM31) void {
        self.streams.append(raw);
        const domain = @intFromEnum(raw.domain);
        self.domain_sums[domain] = self.domain_sums[domain].add(term);
    }

    pub fn observeExecutionRow(self: *Sequence, execution_row: u32) Error!void {
        if (self.execution_rows) |*rows| try rows.observe(execution_row);
    }

    pub fn end(self: *Sequence) void {
        self.next_component += 1;
    }

    pub fn finish(self: *Sequence) Error!AggregateEvidence {
        if (self.poisoned) return error.PoisonedSequence;
        if (self.next_component != COMPONENT_COUNT) return error.IncompleteComponents;
        try self.validateExecutionRows();
        return self.streams.finishAggregate(self.domain_sums);
    }

    pub fn validateExecutionRows(self: *const Sequence) Error!void {
        if (self.execution_rows) |rows| try rows.finish();
    }
};

const ExecutionRows = struct {
    seen: std.DynamicBitSetUnmanaged,
    total_steps: u32,
    count: u32 = 0,

    fn init(allocator: std.mem.Allocator, total_steps: u32) !ExecutionRows {
        if (total_steps == 0) return error.ExecutionRowOutOfRange;
        return .{
            .seen = try std.DynamicBitSetUnmanaged.initEmpty(allocator, @intCast(total_steps)),
            .total_steps = total_steps,
        };
    }

    fn deinit(self: *ExecutionRows, allocator: std.mem.Allocator) void {
        self.seen.deinit(allocator);
        self.* = undefined;
    }

    fn observe(self: *ExecutionRows, execution_row: u32) Error!void {
        if (execution_row == 0 or execution_row > self.total_steps)
            return error.ExecutionRowOutOfRange;
        const index: usize = @intCast(execution_row - 1);
        if (self.seen.isSet(index)) return error.DuplicateExecutionRow;
        self.seen.set(index);
        self.count += 1;
    }

    fn finish(self: ExecutionRows) Error!void {
        if (self.count != self.total_steps) return error.IncompleteExecutionRows;
    }
};

/// Observer used when callers only need the fixed evidence result. A dumper
/// supplies the same method to serialize every raw entry as it is scanned.
pub const NullObserver = struct {
    pub fn onEntry(_: *NullObserver, _: Location, _: RawEntry) !void {}
    pub fn onShard(_: *NullObserver, _: ShardEvidence) !void {}
};

/// Export an opcode family from its ordered production shards. Raw entries
/// preserve statement order across shards. Padding geometry remains local
/// evidence; only the nonzero stream and aggregate claim are cross-oracle
/// parity surfaces because pinned Rust uses one padded family table.
pub fn exportOpcodeFamily(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    shards: []const OpcodeShard,
    relations: *const relations_mod.Relations,
    claim_ledger: *ClaimLedger,
    sequence: *Sequence,
    observer: anytype,
) !ComponentEvidence {
    const component = componentForFamily(family);
    if (shards.len == 0 or shards.len > std.math.maxInt(u32)) return error.InvalidShardCount;
    try sequence.begin(component);
    errdefer sequence.poisoned = true;

    var component_stream = ComponentStreams.init();
    var domain_sums = [_]QM31{QM31.zero()} ** DOMAIN_COUNT;
    var computed_claim = QM31.zero();
    var secure: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
    var manifest = blake2.Blake2sHasher.init();
    manifest.update(shard_manifest_domain);
    updateU32(&manifest, @intFromEnum(component));
    updateU32(&manifest, @intFromEnum(family));
    updateU32(&manifest, @intCast(shards.len));
    var family_row_offset: u64 = 0;
    var previous_execution_row: ?u32 = null;

    for (shards, 0..) |shard, shard_index| {
        try validateShard(family, shard, shard_index, shards.len);
        const actual_digest = digestCommittedShard(component, family, shard);
        if (!std.mem.eql(u8, &actual_digest, &shard.main_columns_digest))
            return error.MainColumnsDigestMismatch;
        updateU32(&manifest, shard.ordinal);
        updateU64(&manifest, shard.n_real_rows);
        updateU64(&manifest, shard.committed_columns[0].len);
        manifest.update(&actual_digest);

        const size = shard.committed_columns[0].len;
        const log_size: u32 = @intCast(std.math.log2_int(usize, size));
        const placement = try infra.BitReversalTable.init(allocator, log_size);
        defer placement.deinit(allocator);
        var shard_stream = ComponentStreams.init();
        for (0..size) |row| {
            const committed_row = placement.map(row);
            for (
                shard.committed_columns,
                secure[0..shard.committed_columns.len],
            ) |column, *value| value.* = QM31.fromBase(column[committed_row]);
            const list = try opcode_entries.fromMain(
                family,
                secure[0..shard.committed_columns.len],
            );
            const provenance: ?OpcodeRequestProvenance = if (row < shard.n_real_rows) blk: {
                const execution_row = try executionRow(list);
                if (previous_execution_row) |previous| {
                    if (execution_row <= previous) return error.NonCanonicalExecutionOrder;
                }
                previous_execution_row = execution_row;
                try sequence.observeExecutionRow(execution_row);
                break :blk .{
                    .execution_row = execution_row,
                    .family = family,
                    .family_row = family_row_offset + row,
                    .request_ordinal = 0,
                };
            } else null;
            var row_has_nonzero = false;
            for (list.entries[0..list.len], 0..) |entry, declaration| {
                const raw = try rawEntry(entry);
                if (row >= shard.n_real_rows and !raw.numerator.isZero())
                    return error.NonZeroPadding;
                row_has_nonzero = row_has_nonzero or !raw.numerator.isZero();
                const term = try entryTerm(entry, relations);
                shard_stream.append(raw);
                component_stream.append(raw);
                const domain = @intFromEnum(raw.domain);
                domain_sums[domain] = domain_sums[domain].add(term);
                sequence.append(raw, term);
                try observer.onEntry(.{
                    .component = component,
                    .shard = shard.ordinal,
                    .row = row,
                    .declaration = declaration,
                    .opcode = if (provenance) |identity| .{
                        .execution_row = identity.execution_row,
                        .family = identity.family,
                        .family_row = identity.family_row,
                        .request_ordinal = @intCast(declaration),
                    } else null,
                }, raw);
            }
            if (row < shard.n_real_rows and !row_has_nonzero)
                return error.InactiveRealRow;
            for (0..list.batchCount()) |batch| {
                computed_claim = computed_claim.add(try pairTerm(try list.pair(batch, relations)));
            }
        }
        const shard_digests = shard_stream.finishStreams();
        try observer.onShard(.{
            .component = component,
            .ordinal = shard.ordinal,
            .shard_count = shard.shard_count,
            .n_real_rows = shard.n_real_rows,
            .domain_size = size,
            .main_columns_digest = actual_digest,
            .all = shard_digests.all,
            .zero = shard_digests.zero,
            .nonzero = shard_digests.nonzero,
            .domains = shard_digests.domains,
            .domain_zero = shard_digests.domain_zero,
            .domain_nonzero = shard_digests.domain_nonzero,
        });
        family_row_offset += shard.n_real_rows;
    }

    var unbatched_total = QM31.zero();
    for (domain_sums) |sum| unbatched_total = unbatched_total.add(sum);
    if (!unbatched_total.eql(computed_claim)) return error.ClaimMismatch;
    const native_claim = try claim_ledger.check(component, computed_claim);
    sequence.end();
    return component_stream.finish(
        component,
        domain_sums,
        computed_claim,
        native_claim,
        @intCast(shards.len),
        manifest.finalize(),
        false,
    );
}

/// Advance one canonical registry slot for a component absent from the
/// statement. Absence is evidence, not omission: the native production claim
/// must be zero and an explicit domain-separated record is returned.
pub fn exportAbsentComponent(
    component: Component,
    claim_ledger: *ClaimLedger,
    sequence: *Sequence,
) Error!ComponentEvidence {
    try sequence.begin(component);
    errdefer sequence.poisoned = true;
    const zero = QM31.zero();
    const native_claim = try claim_ledger.check(component, zero);
    var stream = ComponentStreams.init();
    sequence.end();
    var digest = blake2.Blake2sHasher.init();
    digest.update(absent_component_domain);
    updateU32(&digest, @intFromEnum(component));
    return stream.finish(
        component,
        .{QM31.zero()} ** DOMAIN_COUNT,
        zero,
        native_claim,
        0,
        digest.finalize(),
        true,
    );
}

pub fn publicEvidence(
    data: *const public_data.PublicData,
    relations: *const relations_mod.Relations,
) !PublicEvidence {
    const sums = try public_logup.relationSums(data, relations);
    var domains = [_]QM31{QM31.zero()} ** DOMAIN_COUNT;
    domains[@intFromEnum(Domain.registers_state)] = sums.registers_state;
    domains[@intFromEnum(Domain.memory_access)] = sums.memory_access;
    domains[@intFromEnum(Domain.program_access)] = sums.program_access;
    domains[@intFromEnum(Domain.merkle)] = sums.merkle;
    return .{ .domains = domains, .total = sums.total() };
}

pub fn digestCommittedShard(
    component: Component,
    family: trace.OpcodeFamily,
    shard: OpcodeShard,
) Digest {
    var hasher = blake2.Blake2sHasher.init();
    hasher.update(column_digest_domain);
    updateU32(&hasher, @intFromEnum(component));
    updateU32(&hasher, @intFromEnum(family));
    updateU32(&hasher, shard.ordinal);
    updateU32(&hasher, shard.shard_count);
    updateU64(&hasher, shard.n_real_rows);
    updateU32(&hasher, @intCast(shard.committed_columns.len));
    updateU64(
        &hasher,
        if (shard.committed_columns.len == 0) 0 else shard.committed_columns[0].len,
    );
    for (shard.committed_columns) |column| {
        for (column) |value| updateU32(&hasher, value.toU32());
    }
    return hasher.finalize();
}

const StreamAccumulator = struct {
    hasher: blake2.Blake2sHasher,
    entries: u64 = 0,

    fn init() StreamAccumulator {
        var hasher = blake2.Blake2sHasher.init();
        hasher.update(tuple_digest_domain);
        return .{ .hasher = hasher };
    }

    fn append(self: *StreamAccumulator, raw: RawEntry) void {
        const name = @tagName(raw.domain);
        updateU32(&self.hasher, @intCast(name.len));
        self.hasher.update(name);
        updateU32(&self.hasher, raw.numerator.toU32());
        updateU32(&self.hasher, raw.arity);
        for (raw.values[0..raw.arity]) |value| updateU32(&self.hasher, value.toU32());
        self.entries += 1;
    }

    fn finish(self: *StreamAccumulator) StreamDigest {
        return .{ .entries = self.entries, .digest = self.hasher.finalize() };
    }
};

/// Internal streaming primitive shared by the committed infrastructure and
/// lookup-table exporters. It is public only across the AIR implementation;
/// callers should consume `ComponentEvidence` and `AggregateEvidence`.
pub const ComponentStreams = struct {
    all: StreamAccumulator,
    zero: StreamAccumulator,
    nonzero: StreamAccumulator,
    domains: [DOMAIN_COUNT]StreamAccumulator,
    domain_zero: [DOMAIN_COUNT]StreamAccumulator,
    domain_nonzero: [DOMAIN_COUNT]StreamAccumulator,

    pub fn init() ComponentStreams {
        return .{
            .all = StreamAccumulator.init(),
            .zero = StreamAccumulator.init(),
            .nonzero = StreamAccumulator.init(),
            .domains = initDomains(),
            .domain_zero = initDomains(),
            .domain_nonzero = initDomains(),
        };
    }

    pub fn append(self: *ComponentStreams, raw: RawEntry) void {
        self.all.append(raw);
        const domain = @intFromEnum(raw.domain);
        self.domains[domain].append(raw);
        if (raw.numerator.isZero()) {
            self.zero.append(raw);
            self.domain_zero[domain].append(raw);
        } else {
            self.nonzero.append(raw);
            self.domain_nonzero[domain].append(raw);
        }
    }

    pub fn finish(
        self: *ComponentStreams,
        component: Component,
        domain_sums: [DOMAIN_COUNT]QM31,
        computed_claim: QM31,
        native_claim: QM31,
        shard_count: u32,
        shard_manifest_digest: Digest,
        absent: bool,
    ) ComponentEvidence {
        const streams = self.finishStreams();
        return .{
            .component = component,
            .all = streams.all,
            .zero = streams.zero,
            .nonzero = streams.nonzero,
            .domains = streams.domains,
            .domain_zero = streams.domain_zero,
            .domain_nonzero = streams.domain_nonzero,
            .domain_sums = domain_sums,
            .computed_claim = computed_claim,
            .native_claim = native_claim,
            .shard_count = shard_count,
            .shard_manifest_digest = shard_manifest_digest,
            .absent = absent,
        };
    }

    pub fn finishStreams(self: *ComponentStreams) TupleEvidence {
        var domains: [DOMAIN_COUNT]StreamDigest = undefined;
        var domain_zero: [DOMAIN_COUNT]StreamDigest = undefined;
        var domain_nonzero: [DOMAIN_COUNT]StreamDigest = undefined;
        for (&self.domains, &domains) |*stream, *digest| digest.* = stream.finish();
        for (&self.domain_zero, &domain_zero) |*stream, *digest| digest.* = stream.finish();
        for (&self.domain_nonzero, &domain_nonzero) |*stream, *digest| digest.* = stream.finish();
        return .{
            .all = self.all.finish(),
            .zero = self.zero.finish(),
            .nonzero = self.nonzero.finish(),
            .domains = domains,
            .domain_zero = domain_zero,
            .domain_nonzero = domain_nonzero,
        };
    }

    fn finishAggregate(
        self: *ComponentStreams,
        domain_sums: [DOMAIN_COUNT]QM31,
    ) AggregateEvidence {
        const streams = self.finishStreams();
        return .{
            .all = streams.all,
            .zero = streams.zero,
            .nonzero = streams.nonzero,
            .domains = streams.domains,
            .domain_zero = streams.domain_zero,
            .domain_nonzero = streams.domain_nonzero,
            .domain_sums = domain_sums,
        };
    }
};

fn initDomains() [DOMAIN_COUNT]StreamAccumulator {
    var result: [DOMAIN_COUNT]StreamAccumulator = undefined;
    for (&result) |*stream| stream.* = StreamAccumulator.init();
    return result;
}

pub fn rawEntry(entry: entry_mod.Entry) Error!RawEntry {
    const expected = domainArity(entry.domain);
    if (entry.arity != expected) return error.InvalidEntryArity;
    var result = RawEntry{
        .domain = entry.domain,
        .numerator = entry.numerator.tryIntoM31() catch return error.NonBaseEntry,
        .arity = entry.arity,
    };
    for (entry.values[0..entry.arity], result.values[0..entry.arity]) |value, *dst| {
        dst.* = value.tryIntoM31() catch return error.NonBaseEntry;
    }
    return result;
}

pub fn entryTerm(entry: entry_mod.Entry, relations: *const relations_mod.Relations) Error!QM31 {
    if (entry.numerator.isZero()) return QM31.zero();
    const denominator = try entry.denominator(relations);
    const inverse = denominator.inv() catch return error.ZeroDenominator;
    return entry.numerator.mul(inverse);
}

pub fn pairTerm(pair: @import("logup.zig").RowPair) Error!QM31 {
    if (pair.n1.isZero() and pair.n2.isZero()) return QM31.zero();
    const denominator = pair.d1.mul(pair.d2);
    const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return numerator.mul(denominator.inv() catch return error.ZeroDenominator);
}

fn validateColumns(family: trace.OpcodeFamily, columns: []const []const M31) Error!void {
    if (columns.len != trace.nColumnsForFamily(family)) return error.InvalidColumnCount;
    const size = columns[0].len;
    if (size < 2 or !std.math.isPowerOfTwo(size)) return error.InvalidDomainSize;
    for (columns) |column| if (column.len != size) return error.InvalidColumnLength;
}

fn validateShard(
    family: trace.OpcodeFamily,
    shard: OpcodeShard,
    index: usize,
    count: usize,
) Error!void {
    if (shard.shard_count != @as(u32, @intCast(count))) return error.InvalidShardCount;
    if (shard.ordinal != @as(u32, @intCast(index))) return error.ShardOutOfOrder;
    try validateColumns(family, shard.committed_columns);
    const size = shard.committed_columns[0].len;
    if (shard.n_real_rows == 0 or shard.n_real_rows > size)
        return error.InvalidShardGeometry;
    if (index + 1 < count and shard.n_real_rows != size)
        return error.InvalidShardGeometry;
}

fn executionRow(list: opcode_entries.List) Error!u32 {
    var consume: ?RawEntry = null;
    var emit: ?RawEntry = null;
    const negative_one = M31.one().neg();
    for (list.entries[0..list.len]) |entry| {
        const raw = try rawEntry(entry);
        if (raw.domain != .registers_state or raw.numerator.isZero()) continue;
        if (raw.numerator.eql(negative_one)) {
            if (consume != null) return error.InvalidExecutionProvenance;
            consume = raw;
        } else if (raw.numerator.isOne()) {
            if (emit != null) return error.InvalidExecutionProvenance;
            emit = raw;
        } else return error.InvalidExecutionProvenance;
    }
    const previous = consume orelse return error.InvalidExecutionProvenance;
    const next = emit orelse return error.InvalidExecutionProvenance;
    if (!previous.values[1].add(M31.one()).eql(next.values[1]))
        return error.InvalidExecutionProvenance;
    return previous.values[1].toU32();
}

fn componentForFamily(family: trace.OpcodeFamily) Component {
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

fn domainArity(domain: Domain) u8 {
    return switch (domain) {
        .registers_state => 2,
        .memory_access => 7,
        .program_access => 5,
        .merkle => 4,
        .poseidon2 => 16,
        .poseidon2_io => 32,
        .bitwise => 4,
        .range_check_20 => 1,
        .range_check_8_11 => 2,
        .range_check_8_8_4 => 3,
        .range_check_8_8 => 2,
        .range_check_m31 => 2,
    };
}

fn updateU32(hasher: *blake2.Blake2sHasher, value: u32) void {
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, value, .little);
    hasher.update(&encoded);
}

fn updateU64(hasher: *blake2.Blake2sHasher, value: usize) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @intCast(value), .little);
    hasher.update(&encoded);
}

fn isZeroDigest(digest: Digest) bool {
    for (digest) |byte| if (byte != 0) return false;
    return true;
}

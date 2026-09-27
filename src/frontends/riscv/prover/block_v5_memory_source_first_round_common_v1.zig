//! Shared typed source-page owner kernel. The schema independently selects
//! exact census/grammar/codec; no shape relabeling or proof authority is added.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const BaseSeal = @import("block_v5_source_seal_v1.zig");
const Shared = @import("block_v5_shared_first_round_v1.zig");
const Placement = @import("../air/block/memory_component_trace.zig");

pub fn ForSchema(comptime Schema: type) type {
    return struct {
        //! Actual source fixed/main commitments plus strict bounded owner lifetimes.
        //! This owner commits PRIVATE cells before source challenges. It does not
        //! implement or verify a source STARK, and its graph outputs remain proposals.
        const suite = core.proof_suites.Blake3;
        const Budget = engine.host_budget_allocator.HostBudgetAllocator;
        const Protocol = Schema.Protocol;
        const Columns = Schema.Columns;
        const Source = Schema.Source;
        const Stream = Schema.Stream;
        const Eq = Schema.Equations;
        const Circuit = Schema.Circuit;
        pub const Collector = struct {
            cursor: Stream.Cursor,
            plan: Protocol.Plan,
            limits: Protocol.Limits,
            next_page: u32 = 0,
            failed: bool = false,
            /// At most one page owner is resident. Collector must outlive that owner;
            /// persist/replay private cells with exact recommit roots for later proofs.
            active_page: bool = false,
            pub fn init(admitted: Source.Admitted, source: Schema.Reader, plan: Protocol.Plan, limits: Protocol.Limits) !Collector {
                try plan.require(&admitted, limits);
                return .{ .cursor = try Schema.cursorInit(admitted, source), .plan = plan, .limits = limits };
            }
            pub fn requireFinished(self: *Collector) !void {
                if (self.failed or self.active_page or self.next_page != self.plan.pages or self.cursor.emitted != self.plan.total_chunks or try self.cursor.next() != null) return error.InvalidSourceFirstCollectionPhase;
            }
        };
        /// Describes the genuine same-commitment binding a future arithmetic component
        /// MUST constrain, rather than accepting a host snapshot SHA as proof authority.
        pub const InputBinding = struct { graph_input: u32, tree: u32, column: u32, physical_row: usize };
        pub const ChunkCandidate = struct {
            allocator: std.mem.Allocator,
            equation: *Circuit.Prepared,
            bindings: []InputBinding,
            first_pin: Protocol.Pin,
            source_seal: [32]u8,
            physical_index: u64,
            pub fn deinit(self: *ChunkCandidate) void {
                self.equation.deinit();
                self.allocator.free(self.bindings);
                self.* = undefined;
            }
        };
        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
                pub const FirstRound = struct {
                    child: std.mem.Allocator,
                    budget: Budget,
                    columns: ?Columns.Columns = null,
                    scheme: ?Scheme = null,
                    pin: ?Protocol.Pin = null,
                    snapshot: [32]u8 = @splat(0),
                    active_leases: usize = 0,
                    collector: ?*Collector = null,
                    pub fn allocator(self: *FirstRound) std.mem.Allocator {
                        return self.budget.allocator();
                    }
                    pub fn deinit(self: *FirstRound) !void {
                        if (self.active_leases != 0) return error.SourceFirstLeaseLive;
                        // A lease can move its scheme to a consuming proof. Even if
                        // that lease was released too early, the actual shared tree
                        // references keep this allocator owner alive, in every mode.
                        if (self.scheme) |*scheme| for (scheme.trees.items) |tree| {
                            if (tree.shared_owner) |shared| if (shared.references.load(.acquire) != 1) return error.SourceFirstLeaseLive;
                        };
                        if (self.scheme) |*s| s.deinit(self.allocator());
                        if (self.columns) |*c| c.deinit();
                        if (self.budget.live_bytes != 0) @panic("source first-round allocator ownership invariant");
                        if (self.collector) |collector| {
                            if (!collector.active_page) @panic("source collector ownership invariant");
                            collector.active_page = false;
                        }
                        const child = self.child;
                        child.destroy(self);
                    }
                    pub fn require(self: *FirstRound, admitted: *const Source.Admitted, plan: Protocol.Plan, expected: Protocol.Pin, limits: Protocol.Limits) !void {
                        try plan.require(admitted, limits);
                        try expected.require(plan);
                        if (self.pin == null or self.scheme == null or self.columns == null or !std.meta.eql(self.pin.?, expected) or !std.meta.eql(self.columns.?.page, expected.page) or self.columns.?.written != expected.page.chunks or !std.meta.eql(self.scheme.?.config, expected.config) or self.scheme.?.trees.items.len != 2 or !std.meta.eql(self.columns.?.snapshot(), self.snapshot)) return error.ChangedSourceFirstRound;
                        var roots = try self.scheme.?.roots(self.allocator());
                        defer roots.deinit(self.allocator());
                        if (roots.items.len != 2 or !std.meta.eql(roots.items[0..2].*, expected.roots)) return error.ChangedSourceFirstRound;
                    }
                };
                pub const Lease = struct {
                    owner: *FirstRound,
                    scheme: Scheme,
                    owns_scheme: bool = true,
                    pub fn allocator(self: *Lease) std.mem.Allocator {
                        return self.owner.allocator();
                    }
                    /// The caller must destroy the consuming proof operation before
                    /// releasing this lease, including on proving failure.
                    pub fn takeScheme(self: *Lease) !Scheme {
                        if (!self.owns_scheme) return error.InvalidSourceFirstLeasePhase;
                        self.owns_scheme = false;
                        return self.scheme;
                    }
                    pub fn deinit(self: *Lease) void {
                        if (self.owns_scheme) self.scheme.deinit(self.owner.allocator());
                        std.debug.assert(self.owner.active_leases > 0);
                        self.owner.active_leases -= 1;
                        self.* = undefined;
                    }
                };
                /// Actual two-tree immutable PCS lease, using the owner's allocator.
                /// No raw tree copy or independent allocator frees shared allocations.
                pub fn lease(first: *FirstRound, admitted: *const Source.Admitted, plan: Protocol.Plan, expected: Protocol.Pin, limits: Protocol.Limits, channel: *suite.Channel) !Lease {
                    try first.require(admitted, plan, expected, limits);
                    if (first.active_leases == std.math.maxInt(usize)) return error.SourceFirstResourceLimit;
                    const copied = try Shared.copy(Backend, first.allocator(), &first.scheme.?, channel);
                    first.active_leases += 1;
                    return .{ .owner = first, .scheme = copied };
                }
                /// A failure poisons the collector; consumed private source records may
                /// not be silently retried under another page identity/root roster.
                pub fn collectPage(a: std.mem.Allocator, collector: *Collector) !*FirstRound {
                    if (collector.failed or collector.active_page or collector.next_page >= collector.plan.pages) return error.InvalidSourceFirstCollectionPhase;
                    errdefer collector.failed = true;
                    const page = try collector.plan.page(collector.next_page);
                    if (collector.cursor.emitted != page.first_chunk) return error.InvalidSourceFirstCollectionPhase;
                    const out = try a.create(FirstRound);
                    out.* = .{ .child = a, .budget = Budget.init(a, collector.limits.max_page_heap_bytes) };
                    errdefer out.deinit() catch @panic("source first-round construction lease invariant");
                    const bounded = out.allocator();
                    const completed_columns = try Columns.Columns.init(bounded, Schema.cursorAdmission(&collector.cursor), collector.plan, page, collector.limits);
                    out.columns = completed_columns;
                    for (0..page.chunks) |_| {
                        const chunk = (try collector.cursor.next()) orelse return error.InvalidSourceFirstChunk;
                        try out.columns.?.append(Schema.cursorAdmission(&collector.cursor), chunk);
                    }
                    out.snapshot = out.columns.?.snapshot();
                    var scheme = try Scheme.init(bounded, collector.plan.config);
                    errdefer scheme.deinit(bounded);
                    scheme.setCoefficientRetentionPolicy(.never);
                    var fixed: [Protocol.FIXED_COUNT]engine.pcs.ColumnEvaluation = undefined;
                    var main: [Protocol.MAIN_COUNT]engine.pcs.ColumnEvaluation = undefined;
                    for (&fixed, 0..) |*v, i| v.* = .{ .log_size = page.row_log, .values = out.columns.?.fixedColumn(i) };
                    for (&main, 0..) |*v, i| v.* = .{ .log_size = page.row_log, .values = out.columns.?.mainColumn(i) };
                    var channel = Protocol.firstChannel(collector.plan, page);
                    try scheme.commitBorrowedStreaming(bounded, &fixed, 16, &channel);
                    try scheme.commitBorrowedStreaming(bounded, &main, 16, &channel);
                    var roots = try scheme.roots(bounded);
                    defer roots.deinit(bounded);
                    if (roots.items.len != 2) return error.InvalidSourceFirstCommitments;
                    const pin = Protocol.Pin{ .plan_id = collector.plan.identity, .page = page, .roots = roots.items[0..2].*, .config = collector.plan.config };
                    try pin.require(collector.plan);
                    // Publish only a fully initialized scheme/pin after every fallible
                    // operation. No partial optional aggregate owns garbage on OOM.
                    out.scheme = scheme;
                    out.pin = pin;
                    collector.next_page += 1;
                    out.collector = collector;
                    collector.active_page = true;
                    return out;
                }
                /// Actual independent fixed-root reconstruction; main root remains a
                /// commitment proposal until genuine source equations are proved.
                pub fn verifyFixedRoot(a: std.mem.Allocator, admitted: *const Source.Admitted, plan: Protocol.Plan, expected: Protocol.Pin, limits: Protocol.Limits) !void {
                    try plan.require(admitted, limits);
                    try expected.require(plan);
                    var budget = Budget.init(a, limits.max_page_heap_bytes);
                    const bounded = budget.allocator();
                    const rows = @as(usize, 1) << @intCast(expected.page.row_log);
                    const cells = try bounded.alloc(core.fields.m31.M31, try std.math.mul(usize, rows, Protocol.FIXED_COUNT));
                    defer bounded.free(cells);
                    for (0..rows) |logical| {
                        const values = try Columns.fixedAt(admitted, expected.page, logical);
                        const physical = Placement.committedRow(logical, expected.page.row_log);
                        for (values, 0..) |value, column| cells[column * rows + physical] = value;
                    }
                    var fixed: [Protocol.FIXED_COUNT]engine.pcs.ColumnEvaluation = undefined;
                    for (&fixed, 0..) |*v, i| v.* = .{ .log_size = expected.page.row_log, .values = cells[i * rows ..][0..rows] };
                    var scheme = try Scheme.init(bounded, plan.config);
                    defer scheme.deinit(bounded);
                    scheme.setCoefficientRetentionPolicy(.never);
                    var channel = Protocol.firstChannel(plan, expected.page);
                    try scheme.commitBorrowedStreaming(bounded, &fixed, 16, &channel);
                    var roots = try scheme.roots(bounded);
                    defer roots.deinit(bounded);
                    if (roots.items.len != 1 or !std.meta.eql(roots.items[0], expected.roots[0])) return error.UntrustedSourceFirstFixedRoot;
                }
                /// Derive graph private inputs from the original committed page owner.
                /// Candidate bindings enumerate ALL private inputs; an actual source
                /// arithmetic component must constrain these against tree1, rather
                /// than authorize them through the local snapshot check above.
                pub fn prepareChunk(a: std.mem.Allocator, first: *FirstRound, admitted: *const Source.Admitted, plan: Protocol.Plan, entries: []const Protocol.Pin, source_sealed: Protocol.Sealed, expected_source_digest: [32]u8, base_pins: BaseSeal.Pins, base_entries: []const BaseSeal.Entry, base_sealed: BaseSeal.Sealed, logical: u32, claims: Source.Sums, limits: Protocol.Limits) !ChunkCandidate {
                    if (first.pin == null) return error.ChangedSourceFirstRound;
                    const expected = first.pin.?;
                    try first.require(admitted, plan, expected, limits);
                    _ = try Protocol.admitPage(admitted, plan, expected, entries, source_sealed, expected_source_digest, base_pins, base_entries, base_sealed, limits);
                    if (expected.page.index >= entries.len or !std.meta.eql(entries[expected.page.index], expected)) return error.UntrustedSourceFirstPin;
                    const kind = try Stream.kindAt(admitted, expected.page.first_chunk + logical);
                    const index = try Protocol.admitChunk(admitted, plan, expected, logical, kind, limits);
                    const challenges = try Protocol.draw(a, admitted, plan, entries, source_sealed, expected_source_digest, base_sealed, limits);
                    const witness = try first.columns.?.witness(logical);
                    const equation = try Circuit.prepareWithChallenges(a, admitted, kind, witness, claims, challenges);
                    errdefer equation.deinit();
                    const bindings = try a.alloc(InputBinding, Eq.BIT_COUNT);
                    errdefer a.free(bindings);
                    const physical = Placement.committedRow(logical, expected.page.row_log);
                    for (bindings, 0..) |*b, i| b.* = .{ .graph_input = @intCast(i), .tree = 1, .column = @intCast(i), .physical_row = physical };
                    return .{ .allocator = a, .equation = equation, .bindings = bindings, .first_pin = expected, .source_seal = source_sealed.digest, .physical_index = index };
                }
            };
        }
    };
}

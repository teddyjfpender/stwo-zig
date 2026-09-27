//! Shared typed source-page owner kernel. The schema independently selects
//! exact census/grammar/codec; no shape relabeling or proof authority is added.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");

pub fn ForSchema(comptime Schema: type) type {
    return struct {
        //! Durable page replay is accepted for proving ONLY after both original PCS
        //! roots are actually recommitted and matched. No SHA/file receipt authority.
        const suite = core.proof_suites.Blake3;
        const Budget = engine.host_budget_allocator.HostBudgetAllocator;
        const First = Schema.Protocol;
        const Round = Schema.Round;
        const Store = Schema.Store;
        const Source = Schema.Source;
        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
                pub const FirstRound = Round.ForBackend(Backend).FirstRound;
                /// One serial residency context for the page-level prover. It must
                /// outlive Loaded, including all original-tree consuming proof leases.
                pub const Reader = struct {
                    active: bool = false,
                    live: bool = true,
                    pub fn deinit(self: *Reader) !void {
                        if (!self.live or self.active) return error.MemorySourceReplayOwnerLive;
                        self.live = false;
                    }
                    pub fn take(self: *Reader, a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, admitted: *const Source.Admitted, plan: First.Plan, expected: First.Pin, stored: Store.Pin, limits: First.Limits, store_limits: Store.Limits) !Loaded {
                        if (!self.live or self.active) return error.MemorySourceReplayOwnerLive;
                        const first = try loadRecommitted(a, dir, name, admitted, plan, expected, stored, limits, store_limits);
                        self.active = true;
                        return .{ .reader = self, .first = first };
                    }
                };
                pub const Loaded = struct {
                    reader: *Reader,
                    first: *FirstRound,
                    pub fn deinit(self: *Loaded) !void {
                        if (!self.reader.live or !self.reader.active) return error.MemorySourceReplayOwnerLive;
                        // Failure leaves this owner and residency token intact. The
                        // original FirstRound checks real tree refs in all modes.
                        try self.first.deinit();
                        self.reader.active = false;
                        self.* = undefined;
                    }
                };
                pub fn persist(dir: std.fs.Dir, name: []const u8, first: *FirstRound, admitted: *const Source.Admitted, plan: First.Plan, expected: First.Pin, limits: First.Limits, store_limits: Store.Limits) !Store.Pin {
                    try first.require(admitted, plan, expected, limits);
                    return Store.write(dir, name, plan, expected, &first.columns.?, store_limits);
                }
                /// Returns a genuine recommitted owner usable by existing original-tree
                /// lease/prepareChunk APIs. One page, no complete file buffer or image.
                pub fn loadRecommitted(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, admitted: *const Source.Admitted, plan: First.Plan, expected: First.Pin, stored: Store.Pin, limits: First.Limits, store_limits: Store.Limits) !*FirstRound {
                    try plan.require(admitted, limits);
                    try expected.require(plan);
                    const owner = try a.create(FirstRound);
                    owner.* = .{ .child = a, .budget = Budget.init(a, limits.max_page_heap_bytes) };
                    errdefer owner.deinit() catch @panic("replay construction lease invariant");
                    const bounded = owner.allocator();
                    const columns = try Store.load(bounded, dir, name, admitted, plan, expected, stored, limits, store_limits);
                    owner.columns = columns;
                    owner.snapshot = columns.snapshot();
                    var scheme = try Scheme.init(bounded, plan.config);
                    errdefer scheme.deinit(bounded);
                    scheme.setCoefficientRetentionPolicy(.never);
                    var fixed: [First.FIXED_COUNT]engine.pcs.ColumnEvaluation = undefined;
                    var main: [First.MAIN_COUNT]engine.pcs.ColumnEvaluation = undefined;
                    for (&fixed, 0..) |*out, i| out.* = .{ .log_size = expected.page.row_log, .values = columns.fixedColumn(i) };
                    for (&main, 0..) |*out, i| out.* = .{ .log_size = expected.page.row_log, .values = columns.mainColumn(i) };
                    var channel = First.firstChannel(plan, expected.page);
                    try scheme.commitBorrowedStreaming(bounded, &fixed, 16, &channel);
                    try scheme.commitBorrowedStreaming(bounded, &main, 16, &channel);
                    var roots = try scheme.roots(bounded);
                    defer roots.deinit(bounded);
                    if (roots.items.len != 2 or !std.meta.eql(roots.items[0..2].*, expected.roots)) return error.UntrustedMemorySourceReplayRoots;
                    owner.scheme = scheme;
                    owner.pin = expected;
                    return owner;
                }
            };
        }
    };
}

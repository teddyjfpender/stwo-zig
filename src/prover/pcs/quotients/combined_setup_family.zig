//! Pooled DEEP quotient setup for combined contribution views.
//!
//! The combined plan linearly folds every source column into one QM31
//! accumulator per (sample batch, column height) group, then evaluates the
//! coefficient-basis groups with one circle FFT per coordinate. This module
//! runs both steps on the shared work pool:
//!
//! - combination is split into row chunks per height class; within a chunk
//!   each source column is read once and accumulated into all of its sample
//!   batch accumulators. Accumulation runs in one contiguous per-task tile
//!   (all views x coordinates of the class) that is copied out once, so the
//!   power-of-two view planes never compete for the same cache sets;
//! - FFTs run one coordinate buffer per task, with one twiddle tree per
//!   distinct log size computed once per call.
//!
//! M31 addition and multiplication are exact, and every intermediate value is
//! canonical, so the result is bit-identical to the column-serial reference.

const std = @import("std");
const builtin = @import("builtin");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const row_executor = @import("../quotient_row_executor.zig");
const work_pool = @import("../../work_pool.zig");
const poly = @import("../../poly/circle/mod.zig");
const twiddles = @import("../../poly/twiddles.zig");

const M31 = m31.M31;

/// Rows per combination task: 4 KiB of source and 16 KiB per accumulator
/// view, so a chunk's working set stays in L2 for tens of sample batches.
pub const CHUNK_ROWS: usize = 1024;

pub fn ForCoordinates(comptime coordinate_count: usize, comptime View: type) type {
    return struct {
        const DEGREE = coordinate_count;
        const CombinedContributionView = View;
        pub const Member = struct {
            source: []const M31,
            coefficients: [DEGREE]M31,
            view_index: usize,
        };

        const Class = struct {
            size: usize,
            /// Range into `class_views`.
            view_start: usize,
            view_len: usize,
            /// Range into `class_members` (members grouped by source column).
            member_start: usize,
            member_len: usize,
            first_task: usize,
        };

        const CombineContext = struct {
            views: []const CombinedContributionView,
            classes: []const Class,
            class_views: []const usize,
            /// Slot of each view inside its height class (`class_views` order).
            view_slots: []const usize,
            class_members: []const Member,
            task_count: usize,
            next: std.atomic.Value(usize) = .init(0),

            fn run(self: *CombineContext) void {
                // One contiguous L1-resident accumulator tile per task. Every
                // view plane of a height class is a separate power-of-two
                // allocation, so updating them in place puts all coordinate
                // planes (and the source chunk) on the same cache sets; at
                // 2 MiB planes that conflict thrash dominated the setup.
                var tile_storage: [TILE_WORDS]M31 align(64) = undefined;
                while (true) {
                    const task = self.next.fetchAdd(1, .monotonic);
                    if (task >= self.task_count) return;
                    var class_index: usize = 0;
                    while (class_index + 1 < self.classes.len and self.classes[class_index + 1].first_task <= task) class_index += 1;
                    const class = self.classes[class_index];
                    const start = (task - class.first_task) * CHUNK_ROWS;
                    const end = @min(start + CHUNK_ROWS, class.size);
                    const class_views = self.class_views[class.view_start..][0..class.view_len];
                    const members = self.class_members[class.member_start..][0..class.member_len];
                    const planes = class.view_len * DEGREE;
                    const tile_rows = tileRows(planes);
                    if (tile_rows == 0) {
                        runDirect(self.views, class_views, members, start, end);
                        continue;
                    }
                    var tile_start = start;
                    while (tile_start < end) : (tile_start += tile_rows) {
                        const tile_end = @min(tile_start + tile_rows, end);
                        const rows = tile_end - tile_start;
                        const tile = tile_storage[0 .. planes * tile_rows];
                        @memset(tile, M31.zero());
                        for (members) |member| {
                            if (member.source.len <= tile_start) continue;
                            const stop = @min(tile_end, member.source.len);
                            const slot = self.view_slots[member.view_index];
                            var destination: [DEGREE][]M31 = undefined;
                            inline for (0..DEGREE) |coord| destination[coord] = tile[(slot * DEGREE + coord) * tile_rows ..][0..tile_rows];
                            accumulate4(&destination, 0, stop - tile_start, member.source[tile_start..stop], member.coefficients);
                        }
                        for (class_views, 0..) |view_index, slot| {
                            inline for (0..DEGREE) |coord| @memcpy(
                                self.views[view_index].coordinates[coord][tile_start..tile_end],
                                tile[(slot * DEGREE + coord) * tile_rows ..][0..rows],
                            );
                        }
                    }
                }
            }

            /// Reference in-place schedule, kept for classes with too many views
            /// to tile. Same additions in the same per-view order.
            fn runDirect(views: []const CombinedContributionView, class_views: []const usize, members: []const Member, start: usize, end: usize) void {
                for (class_views) |view_index| {
                    inline for (0..DEGREE) |coord| @memset(views[view_index].coordinates[coord][start..end], M31.zero());
                }
                for (members) |member| {
                    if (member.source.len <= start) continue;
                    const stop = @min(end, member.source.len);
                    accumulate4(&views[member.view_index].coordinates, start, stop, member.source, member.coefficients);
                }
            }
        };

        /// Accumulator tile words per task (64 KiB): stays in L1 beside the
        /// streamed source rows.
        const TILE_WORDS: usize = 16 * 1024;
        /// Smallest tile worth taking; below it the direct schedule is used.
        const MIN_TILE_ROWS: usize = 32;

        /// Rows per tile for `planes` coordinate planes: the largest multiple of
        /// the vector width with `planes * rows <= TILE_WORDS`, capped at the
        /// chunk, or 0 when fewer than MIN_TILE_ROWS rows would fit.
        fn tileRows(planes: usize) usize {
            if (planes == 0) return CHUNK_ROWS;
            const fit = TILE_WORDS / planes;
            if (fit < MIN_TILE_ROWS) return 0;
            return @min(CHUNK_ROWS, fit - fit % m31.VEC_WIDTH);
        }

        /// Adds `source[start..stop] * coefficients[c]` into each coordinate plane,
        /// loading every source vector once for all four coordinates.
        fn accumulate4(
            coordinates: *const [DEGREE][]M31,
            start: usize,
            stop: usize,
            source: []const M31,
            coefficients: [DEGREE]M31,
        ) void {
            var lanes: [DEGREE]m31.Vec4u32 = undefined;
            inline for (0..DEGREE) |coord| lanes[coord] = @splat(coefficients[coord].v);
            var index = start;
            while (index + m31.VEC_WIDTH <= stop) : (index += m31.VEC_WIDTH) {
                const value = m31.loadVec4(source.ptr + index);
                inline for (0..DEGREE) |coord| {
                    const destination = coordinates[coord].ptr + index;
                    m31.storeVec4(destination, m31.addVec4(m31.loadVec4(destination), m31.mulVec4(value, lanes[coord])));
                }
            }
            while (index < stop) : (index += 1) {
                inline for (0..DEGREE) |coord| {
                    coordinates[coord][index] = coordinates[coord][index].add(source[index].mul(coefficients[coord]));
                }
            }
        }

        fn classKey(view: CombinedContributionView) usize {
            return view.coordinates[0].len;
        }

        /// Runs `Context.run` on the caller plus up to `workerCount - 1` pool helpers.
        fn runPooled(comptime Context: type, context: *Context, task_count: usize) void {
            if (task_count == 0) return;
            const pool = if (comptime builtin.single_threaded) null else work_pool.getGlobalPool();
            if (pool) |active| {
                const helpers = @min(active.workerCount(), task_count) -| 1;
                var group: std.Thread.WaitGroup = .{};
                for (0..helpers) |_| active.spawnWg(&group, Context.run, .{context});
                context.run();
                group.wait();
            } else context.run();
        }

        /// Initializes every view from its members. Views without members (native
        /// fold targets) are left untouched. Views are grouped by height; members of
        /// one view must share its height.
        pub fn combine(
            allocator: std.mem.Allocator,
            views: []const CombinedContributionView,
            members: []const Member,
        ) !void {
            if (members.len == 0) return;
            const view_has_members = try allocator.alloc(bool, views.len);
            defer allocator.free(view_has_members);
            @memset(view_has_members, false);
            for (members) |member| {
                if (member.view_index >= views.len) return error.ShapeMismatch;
                if (member.source.len > views[member.view_index].coordinates[0].len) return error.ShapeMismatch;
                view_has_members[member.view_index] = true;
            }

            // Distinct heights in first-seen order.
            var sizes = std.ArrayList(usize).empty;
            defer sizes.deinit(allocator);
            for (views, view_has_members) |view, used| {
                if (!used) continue;
                const key = classKey(view);
                if (std.mem.indexOfScalar(usize, sizes.items, key) == null) try sizes.append(allocator, key);
            }

            const classes = try allocator.alloc(Class, sizes.items.len);
            defer allocator.free(classes);
            const class_views = try allocator.alloc(usize, views.len);
            defer allocator.free(class_views);
            const view_slots = try allocator.alloc(usize, views.len);
            defer allocator.free(view_slots);
            @memset(view_slots, 0);
            const class_members = try allocator.alloc(Member, members.len);
            defer allocator.free(class_members);

            var view_at: usize = 0;
            var member_at: usize = 0;
            var task_at: usize = 0;
            for (sizes.items, classes) |size, *class| {
                class.* = .{ .size = size, .view_start = view_at, .view_len = 0, .member_start = member_at, .member_len = 0, .first_task = task_at };
                for (views, view_has_members, 0..) |view, used, index| {
                    if (!used or classKey(view) != size) continue;
                    class_views[view_at] = index;
                    view_slots[index] = view_at - class.view_start;
                    view_at += 1;
                }
                // Members keep their column-outer order, so a column's members are
                // adjacent and its chunk is reused from L1 across sample batches.
                for (members) |member| {
                    if (classKey(views[member.view_index]) != size) continue;
                    class_members[member_at] = member;
                    member_at += 1;
                }
                class.view_len = view_at - class.view_start;
                class.member_len = member_at - class.member_start;
                task_at += std.math.divCeil(usize, size, CHUNK_ROWS) catch unreachable;
            }
            std.debug.assert(member_at == members.len);

            var context = CombineContext{
                .views = views,
                .classes = classes,
                .class_views = class_views[0..view_at],
                .view_slots = view_slots,
                .class_members = class_members,
                .task_count = task_at,
            };
            runPooled(CombineContext, &context, task_at);
        }

        const FftJob = struct {
            buffer: []M31,
            log_size: u32,
        };

        const FftContext = struct {
            jobs: []const FftJob,
            trees: []const ?twiddles.TwiddleTree([]M31),
            next: std.atomic.Value(usize) = .init(0),
            failed: std.atomic.Value(bool) = .init(false),

            fn run(self: *FftContext) void {
                while (true) {
                    const task = self.next.fetchAdd(1, .monotonic);
                    if (task >= self.jobs.len) return;
                    const job = self.jobs[task];
                    const tree = self.trees[job.log_size].?;
                    const borrowed = twiddles.TwiddleTree([]const M31){ .root_coset = tree.root_coset, .twiddles = tree.twiddles, .itwiddles = tree.itwiddles };
                    const buffers = [_][]M31{job.buffer};
                    poly.poly.evaluateBuffersWithTwiddles(&buffers, poly.CanonicCoset.new(job.log_size).circleDomain(), borrowed) catch {
                        self.failed.store(true, .monotonic);
                    };
                }
            }
        };

        /// Evaluates every coefficient-basis view on its canonic circle domain, one
        /// coordinate buffer per pool task, sharing one twiddle tree per log size.
        pub fn evaluateCoefficientViews(
            allocator: std.mem.Allocator,
            views: []const CombinedContributionView,
            coefficient_basis: []const bool,
        ) !void {
            std.debug.assert(views.len == coefficient_basis.len);
            var trees = [_]?twiddles.TwiddleTree([]M31){null} ** @bitSizeOf(usize);
            defer for (&trees) |*slot| if (slot.*) |*tree| twiddles.deinitM31(allocator, tree);

            var job_count: usize = 0;
            for (views, coefficient_basis) |view, basis| {
                if (!basis) continue;
                const log: u32 = @intCast(std.math.log2_int(usize, view.coordinates[0].len));
                if (trees[log] == null) trees[log] = try twiddles.precomputeM31(allocator, poly.CanonicCoset.new(log).circleDomain().half_coset);
                job_count += DEGREE;
            }
            if (job_count == 0) return;

            const jobs = try allocator.alloc(FftJob, job_count);
            defer allocator.free(jobs);
            var at: usize = 0;
            for (views, coefficient_basis) |view, basis| {
                if (!basis) continue;
                const log: u32 = @intCast(std.math.log2_int(usize, view.coordinates[0].len));
                inline for (0..DEGREE) |coord| {
                    jobs[at] = .{ .buffer = view.coordinates[coord], .log_size = log };
                    at += 1;
                }
            }

            var context = FftContext{ .jobs = jobs, .trees = &trees };
            runPooled(FftContext, &context, jobs.len);
            if (context.failed.load(.monotonic)) return error.InvalidLogSize;
        }
    };
}

test "coefficient storage tiled combine matches the scalar column-serial reference" {
    const D = 8;
    const View = struct { coordinates: [D][]M31 };
    const Setup = ForCoordinates(D, View);
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const random = prng.random();
    // (view size, view count): a tiled class with a tail tile, a class too
    // wide to tile (direct schedule), and a class smaller than one tile.
    const shapes = [_][2]usize{ .{ 4096, 7 }, .{ 2048, 40 }, .{ 64, 3 } };
    var views: std.ArrayList(View) = .empty;
    defer {
        for (views.items) |view| for (view.coordinates) |plane| a.free(plane);
        views.deinit(a);
    }
    for (shapes) |shape| for (0..shape[1]) |_| {
        var view: View = undefined;
        for (&view.coordinates) |*plane| {
            plane.* = try a.alloc(M31, shape[0]);
            for (plane.*) |*v| v.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, m31.Modulus));
        }
        try views.append(a, view);
    };
    var sources: std.ArrayList([]M31) = .empty;
    defer {
        for (sources.items) |source| a.free(source);
        sources.deinit(a);
    }
    var members: std.ArrayList(Setup.Member) = .empty;
    defer members.deinit(a);
    // Column-outer members; each column feeds 1..3 views of its height, with
    // sources shorter than the view (compact coefficients) and odd lengths.
    var first_view: usize = 0;
    for (shapes) |shape| {
        for (0..shape[1] * 2) |column| {
            const lengths = [_]usize{ shape[0], shape[0] / 2, shape[0] / 4, 13, 1 };
            const source = try a.alloc(M31, lengths[column % lengths.len]);
            for (source) |*v| v.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, m31.Modulus));
            try sources.append(a, source);
            for (0..1 + column % 3) |k| {
                var coefficients: [D]M31 = undefined;
                for (&coefficients) |*c| c.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, m31.Modulus));
                try members.append(a, .{ .source = source, .coefficients = coefficients, .view_index = first_view + (column + k) % shape[1] });
            }
        }
        first_view += shape[1];
    }
    // One view without members is a fold target: left untouched.
    const untouched = try a.dupe(M31, views.items[views.items.len - 1].coordinates[0]);
    defer a.free(untouched);
    var used = try a.alloc(bool, views.items.len);
    defer a.free(used);
    @memset(used, false);
    var kept: std.ArrayList(Setup.Member) = .empty;
    defer kept.deinit(a);
    for (members.items) |member| if (member.view_index != views.items.len - 1) {
        try kept.append(a, member);
        used[member.view_index] = true;
    };
    try Setup.combine(a, views.items, kept.items);
    for (views.items, used, 0..) |view, has_members, index| {
        if (!has_members) {
            try std.testing.expectEqual(views.items.len - 1, index);
            try std.testing.expectEqualSlices(M31, untouched, view.coordinates[0]);
            continue;
        }
        for (view.coordinates, 0..) |plane, coord| for (plane, 0..) |actual, row| {
            var expected = M31.zero();
            for (kept.items) |member| if (member.view_index == index and row < member.source.len) {
                expected = expected.add(member.source[row].mul(member.coefficients[coord]));
            };
            try std.testing.expectEqual(expected, actual);
        };
    }
}

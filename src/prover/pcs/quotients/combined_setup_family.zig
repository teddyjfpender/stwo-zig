//! Pooled DEEP quotient setup for combined contribution views.
//!
//! The combined plan linearly folds every source column into one QM31
//! accumulator per (sample batch, column height) group, then evaluates the
//! coefficient-basis groups with one circle FFT per coordinate. This module
//! runs both steps on the shared work pool:
//!
//! - combination is split into row chunks per height class; within a chunk
//!   each source column is read once and accumulated into all of its sample
//!   batch accumulators;
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
            class_members: []const Member,
            task_count: usize,
            next: std.atomic.Value(usize) = .init(0),

            fn run(self: *CombineContext) void {
                while (true) {
                    const task = self.next.fetchAdd(1, .monotonic);
                    if (task >= self.task_count) return;
                    var class_index: usize = 0;
                    while (class_index + 1 < self.classes.len and self.classes[class_index + 1].first_task <= task) class_index += 1;
                    const class = self.classes[class_index];
                    const start = (task - class.first_task) * CHUNK_ROWS;
                    const end = @min(start + CHUNK_ROWS, class.size);
                    for (self.class_views[class.view_start..][0..class.view_len]) |view_index| {
                        inline for (0..DEGREE) |coord| @memset(self.views[view_index].coordinates[coord][start..end], M31.zero());
                    }
                    const members = self.class_members[class.member_start..][0..class.member_len];
                    var at: usize = 0;
                    while (at < members.len) {
                        const member = members[at];
                        if (members.len - at >= 4) {
                            const four = members[at..][0..4];
                            var compatible = true;
                            for (four) |candidate| compatible = compatible and candidate.view_index == member.view_index and candidate.source.len >= end;
                            if (compatible) {
                                accumulateFourMembers(&self.views[member.view_index].coordinates, start, end, four);
                                at += 4;
                                continue;
                            }
                        }
                        at += 1;
                        if (member.source.len <= start) continue;
                        const stop = @min(end, member.source.len);
                        accumulate4(&self.views[member.view_index].coordinates, start, stop, member.source, member.coefficients);
                    }
                }
            }
        };

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

        /// Four canonical products fit exactly in u64. Reuse that existing dot
        /// authority to reduce once and touch each destination plane once.
        fn accumulateFourMembers(coordinates: *const [DEGREE][]M31, start: usize, stop: usize, members: *const [4]Member) void {
            var coefficients: [DEGREE][4]m31.PackedM31 = undefined;
            inline for (0..DEGREE) |coord| inline for (0..4) |term| {
                coefficients[coord][term] = @splat(members[term].coefficients[coord].v);
            };
            var index = start;
            while (index + m31.PACK_WIDTH <= stop) : (index += m31.PACK_WIDTH) {
                var values: [4]m31.PackedM31 = undefined;
                inline for (0..4) |term| values[term] = m31.loadPacked(members[term].source.ptr + index);
                inline for (0..DEGREE) |coord| {
                    const destination = coordinates[coord].ptr + index;
                    m31.storePacked(destination, m31.addPacked(m31.loadPacked(destination), m31.dot4Packed(values, coefficients[coord])));
                }
            }
            while (index < stop) : (index += 1) {
                var values: [4]M31 = undefined;
                inline for (0..4) |term| values[term] = members[term].source[index];
                inline for (0..DEGREE) |coord| {
                    var cs: [4]M31 = undefined;
                    inline for (0..4) |term| cs[term] = members[term].coefficients[coord];
                    coordinates[coord][index] = coordinates[coord][index].add(m31.dot4(values, cs));
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
                    view_at += 1;
                }
                // Preserve caller order. Consecutive same-view members can use
                // the dot4 reducer; mixed views retain the original path.
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

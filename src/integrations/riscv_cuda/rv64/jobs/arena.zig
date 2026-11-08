//! Two-sided job arena. Pure offset bookkeeping; owns no CUDA handles.
const std = @import("std");
const R = @import("resources.zig");

/// Two-sided allocator over one device allocation (pure bookkeeping).
///
/// The work window of the job on side S is addressed by offsets from S's
/// origin (bottom: grows up from `work_first`; top: grows down from
/// `work_end`). A bump `bump` marks its high-water; with `reuse` a free that
/// is not the most recent allocation becomes a hole that later allocations of
/// the same job take best-fit (stream-ordered: every consumer of the freed
/// range was enqueued before, on the same exec stream). Without `reuse` only
/// LIFO frees are reclaimed (today's behavior). Either way the sequence of
/// addresses is a pure function of the job's allocation sequence and side,
/// so a captured graph replays for the next job of the class on that side.
pub const Arena = struct {
    base: usize = 0,
    words: usize = 0,
    staged: [2]usize = .{ 0, 0 },
    work_side: R.Placement = .bottom,
    work_first: usize = 0, // inclusive lower bound of the work window
    work_end: usize = 0, // exclusive upper bound
    bump: usize = 0, // offset high-water mark from the work side's origin
    /// Own staged inputs + bump high-water (what the window had to hold).
    peak: usize = 0,
    live: usize = 0,
    /// Own staged inputs + live high-water (perfect-free bound).
    live_peak: usize = 0,
    allocs: usize = 0,
    peak_alloc: usize = 0,
    peak_alloc_words: usize = 0,
    reuse: bool = false,
    holes: [max_holes]Hole = undefined,
    hole_count: usize = 0,
    /// Frees not recorded because the hole table was full (reclaimed at window reset).
    dropped_holes: usize = 0,

    pub const max_holes = 64;
    pub const Hole = struct { off: usize, len: usize };

    fn side(p: R.Placement) usize {
        return @intFromEnum(p);
    }
    pub fn beginStage(self: *Arena, placement: R.Placement) void {
        self.staged[side(placement)] = 0;
    }
    /// Allocations are rounded to 64 words (256 bytes) so every kernel's
    /// vector/u64 alignment assumption holds for arena sub-ranges.
    pub const granule: usize = @import("resources.zig").granule_words;
    pub fn stageAlloc(self: *Arena, placement: R.Placement, requested: usize) !usize {
        if (requested == 0) return error.InvalidAllocation;
        const words = try R.aligned(requested);
        const s = side(placement);
        const used = self.staged[0] + self.staged[1];
        if (words > self.words - used) return error.StagedInputsExceedArena;
        self.staged[s] += words;
        return if (placement == .bottom) self.base + 4 * (self.staged[s] - words) else self.base + 4 * (self.words - self.staged[s]);
    }
    /// `other_staged`: whether a job is currently staged on the other side.
    pub fn beginWork(self: *Arena, placement: R.Placement, other_staged: bool) void {
        const other = side(placement.other());
        if (!other_staged) self.staged[other] = 0;
        self.work_side = placement;
        self.work_first = self.staged[0];
        self.work_end = self.words - self.staged[1];
        self.bump = 0;
        self.live = 0;
        self.hole_count = 0;
        self.dropped_holes = 0;
        self.allocs = 0;
        self.peak_alloc = 0;
        self.peak_alloc_words = 0;
        self.peak = self.staged[side(placement)];
        self.live_peak = self.peak;
    }
    fn limit(self: *const Arena) usize {
        return self.work_end - self.work_first;
    }
    fn wordAt(self: *const Arena, off: usize, words: usize) usize {
        return if (self.work_side == .bottom) self.work_first + off else self.work_end - off - words;
    }
    pub fn workAlloc(self: *Arena, requested: usize) !usize {
        if (requested == 0) return error.InvalidAllocation;
        const words = try R.aligned(requested);
        const off = if (self.reuse) self.takeHole(words) orelse try self.bumpBy(words) else try self.bumpBy(words);
        self.allocs += 1;
        self.live += words;
        self.note(words);
        return self.base + 4 * self.wordAt(off, words);
    }
    fn bumpBy(self: *Arena, words: usize) !usize {
        if (words > self.limit() - self.bump) return error.JobWorkExceedsArena;
        const at = self.bump;
        self.bump += words;
        return at;
    }
    /// Best fit (smallest hole that fits; lowest offset on ties), from the hole's start.
    fn takeHole(self: *Arena, words: usize) ?usize {
        var best: ?usize = null;
        for (self.holes[0..self.hole_count], 0..) |h, i| {
            if (h.len < words) continue;
            if (best == null or h.len < self.holes[best.?].len) best = i;
        }
        const i = best orelse return null;
        const at = self.holes[i].off;
        self.holes[i].off += words;
        self.holes[i].len -= words;
        if (self.holes[i].len == 0) self.removeHole(i);
        return at;
    }
    fn removeHole(self: *Arena, i: usize) void {
        std.mem.copyForwards(Hole, self.holes[i .. self.hole_count - 1], self.holes[i + 1 .. self.hole_count]);
        self.hole_count -= 1;
    }
    /// Stream-ordered free. The most recent allocation always retracts the
    /// bump; with `reuse` any other live range becomes a reusable hole.
    pub fn workFree(self: *Arena, address: usize, requested: usize) void {
        const words = R.aligned(requested) catch return;
        if (address < self.base or (address - self.base) % 4 != 0) return;
        const at = (address - self.base) / 4;
        const off = if (self.work_side == .bottom) blk: {
            if (at < self.work_first) return;
            break :blk at - self.work_first;
        } else blk: {
            if (at > self.work_end or words > self.work_end - at) return;
            break :blk self.work_end - at - words;
        };
        if (off > self.bump or words > self.bump - off) return; // never allocated in this window
        if (off + words == self.bump) {
            self.bump = off;
            self.live -|= words;
            // Holes now touching the bump are free tail: retract over them.
            while (self.hole_count != 0) {
                const last = self.holes[self.hole_count - 1];
                if (last.off + last.len != self.bump) break;
                self.bump = last.off;
                self.hole_count -= 1;
            }
            return;
        }
        if (!self.reuse) {
            self.live -|= words; // dead, reclaimed when the window resets
            return;
        }
        if (self.insertHole(off, words)) self.live -|= words;
    }
    /// Sorted, coalesced; rejects a range overlapping an existing hole (double free).
    fn insertHole(self: *Arena, off: usize, len: usize) bool {
        var i: usize = 0;
        while (i < self.hole_count and self.holes[i].off < off) : (i += 1) {}
        if (i > 0 and self.holes[i - 1].off + self.holes[i - 1].len > off) return false;
        if (i < self.hole_count and off + len > self.holes[i].off) return false;
        const joins_prev = i > 0 and self.holes[i - 1].off + self.holes[i - 1].len == off;
        const joins_next = i < self.hole_count and off + len == self.holes[i].off;
        if (joins_prev and joins_next) {
            self.holes[i - 1].len += len + self.holes[i].len;
            self.removeHole(i);
        } else if (joins_prev) {
            self.holes[i - 1].len += len;
        } else if (joins_next) {
            self.holes[i].off = off;
            self.holes[i].len += len;
        } else {
            if (self.hole_count == max_holes) {
                self.dropped_holes += 1;
                return true;
            }
            std.mem.copyBackwards(Hole, self.holes[i + 1 .. self.hole_count + 1], self.holes[i..self.hole_count]);
            self.holes[i] = .{ .off = off, .len = len };
            self.hole_count += 1;
        }
        return true;
    }
    fn note(self: *Arena, words: usize) void {
        const own = self.staged[side(self.work_side)];
        if (own + self.bump > self.peak) {
            self.peak = own + self.bump;
            self.peak_alloc = self.allocs;
            self.peak_alloc_words = words;
        }
        self.live_peak = @max(self.live_peak, own + self.live);
    }
    pub fn contains(self: *const Arena, address: usize, words: usize) bool {
        return address >= self.base and (address - self.base) % 4 == 0 and (address - self.base) / 4 <= self.words and words <= self.words - (address - self.base) / 4;
    }
};

test {
    _ = @import("arena_test.zig");
}

//! Segment checkpoints for the fast first pass: architectural CPU state,
//! Ethereum service counters and a memory image at each batch boundary, so
//! traced re-execution of every segment can start independently.
//!
//! Memory images are persistent: a checkpoint lists every allocated page as a
//! shared immutable copy, and only pages written since the previous checkpoint
//! (fast_execution dirty set) are copied again. Copies are reference-counted
//! across checkpoints and freed when the last checkpoint naming them is
//! released. Prover-side only; nothing here is proof authority.
const std = @import("std");
const machine = @import("machine.zig");
const mem = @import("memory.zig");
const pages = @import("pages.zig");
const fast = @import("fast_execution.zig");
const eth = @import("ethereum_services/session.zig");
const Page = pages.Page;
pub const Dirty = pages.Dirty;

/// Every per-session counter that influences later retirements (call ids and
/// overflow checks). Equality of these is part of segment continuity.
pub const Counters = struct {
    keccak: u64 = 0,
    add: u64 = 0,
    double: u64 = 0,
    sha256: u64 = 0,
    arith256_mod: u64 = 0,
    bulk: u64 = 0,
    sponge: u64 = 0,
    curve: [eth.curves.COUNT]u64 = @splat(0),
    pub fn of(s: *const eth.Session) Counters {
        return .{ .keccak = s.keccak.calls, .add = s.add_calls, .double = s.double_calls, .sha256 = s.sha256_calls, .arith256_mod = s.arith256_mod_calls, .bulk = s.bulk_calls, .sponge = s.sponge_calls, .curve = s.curve_calls };
    }
    pub fn apply(self: Counters, s: *eth.Session) void {
        s.keccak.calls = self.keccak;
        s.add_calls = self.add;
        s.double_calls = self.double;
        s.sha256_calls = self.sha256;
        s.arith256_mod_calls = self.arith256_mod;
        s.bulk_calls = self.bulk;
        s.sponge_calls = self.sponge;
        s.curve_calls = self.curve;
    }
};

const Copy = struct { refs: std.atomic.Value(u32), page: Page };
pub const Entry = struct { index: u64, page: *const Page };

pub const Checkpoint = struct {
    cpu: machine.Cpu,
    counters: Counters,
    /// Every allocated page at this point, sorted by index.
    pages: []const Entry,
    /// Page indices written since the previous checkpoint, sorted (all
    /// allocated pages for the first checkpoint).
    written: []const u64,

    pub fn find(self: *const Checkpoint, index: u64) ?*const Page {
        var lo: usize = 0;
        var hi = self.pages.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.pages[mid].index == index) return self.pages[mid].page;
            if (self.pages[mid].index < index) lo = mid + 1 else hi = mid;
        }
        return null;
    }
};

pub const Error = std.mem.Allocator.Error || error{FastExecutionCheckpointOverflow};

/// Owns page copies; `take` and `release` may run on different threads.
pub const Recorder = struct {
    allocator: std.mem.Allocator,
    engine: *fast.Engine,
    /// Latest copy per page index (engine table geometry).
    latest: []?*Copy,
    started: bool = false,
    pages_copied: u64 = 0,
    peak_live_pages: u64 = 0,
    live_pages: std.atomic.Value(u64) = .init(0),

    pub fn init(a: std.mem.Allocator, engine: *fast.Engine) Error!Recorder {
        const latest = try a.alloc(?*Copy, engine.rights.len);
        @memset(latest, null);
        return .{ .allocator = a, .engine = engine, .latest = latest };
    }

    /// Drops the recorder's own references; checkpoints still taken keep theirs.
    pub fn deinit(self: *Recorder) void {
        for (self.latest) |slot| if (slot) |copy| self.unref(copy);
        self.allocator.free(self.latest);
        self.* = undefined;
    }

    fn unref(self: *Recorder, copy: *Copy) void {
        if (copy.refs.fetchSub(1, .acq_rel) == 1) {
            _ = self.live_pages.fetchSub(1, .monotonic);
            self.allocator.destroy(copy);
        }
    }

    fn replace(self: *Recorder, index: u64, source: *const Page) Error!void {
        const copy = try self.allocator.create(Copy);
        copy.* = .{ .refs = .init(1), .page = source.* };
        const i: usize = @intCast(index);
        if (self.latest[i]) |old| self.unref(old);
        self.latest[i] = copy;
        self.pages_copied += 1;
        const live = self.live_pages.fetchAdd(1, .monotonic) + 1;
        self.peak_live_pages = @max(self.peak_live_pages, live);
    }

    /// Snapshot the session at its current clock and start a new dirty
    /// interval. The engine must be attached to the session's memory.
    pub fn take(self: *Recorder, session: *const eth.Session) Error!Checkpoint {
        const memory = self.engine.memory;
        std.debug.assert(memory == session.keccak.base.memory and memory.backing.dirty == &self.engine.dirty);
        var written = std.ArrayList(u64).empty;
        errdefer written.deinit(self.allocator);
        if (!self.started) {
            var it = memory.backing.table.iterator();
            while (it.next()) |e| {
                if (e.key_ptr.* >= self.latest.len) return error.FastExecutionCheckpointOverflow;
                try written.append(self.allocator, e.key_ptr.*);
            }
            std.mem.sort(u64, written.items, {}, std.sort.asc(u64));
        } else {
            if (self.engine.dirty.overflow) return error.FastExecutionCheckpointOverflow;
            for (self.engine.dirty.bits, 0..) |word, w| {
                var bits = word;
                while (bits != 0) : (bits &= bits - 1) try written.append(self.allocator, 64 * w + @ctz(bits));
            }
        }
        for (written.items) |index| {
            // A written page always exists: stores allocate before writing.
            try self.replace(index, memory.backing.peek(index).?);
        }
        var count: usize = 0;
        for (self.latest) |slot| count += @intFromBool(slot != null);
        const list = try self.allocator.alloc(Entry, count);
        errdefer self.allocator.free(list);
        count = 0;
        for (self.latest, 0..) |slot, index| if (slot) |copy| {
            _ = copy.refs.fetchAdd(1, .monotonic);
            list[count] = .{ .index = index, .page = &copy.page };
            count += 1;
        };
        self.started = true;
        self.engine.resetDirty();
        const owned = try written.toOwnedSlice(self.allocator);
        return .{ .cpu = session.keccak.base.cpu, .counters = Counters.of(session), .pages = list, .written = owned };
    }

    /// Return a checkpoint's references (and its lists) to the recorder.
    pub fn release(self: *Recorder, cp: *Checkpoint) void {
        for (cp.pages) |entry| {
            const copy: *const Copy = @alignCast(@fieldParentPtr("page", entry.page));
            self.unref(@constCast(copy));
        }
        self.allocator.free(cp.pages);
        self.allocator.free(cp.written);
        cp.* = undefined;
    }
};

/// A fresh, independently owned memory equal to `cp`'s image under the
/// mappings (rights, limits) of `layout`.
pub fn materialize(a: std.mem.Allocator, layout: *const mem.Memory, cp: *const Checkpoint) !mem.Memory {
    var m = mem.Memory.init(a, layout.mappings.limits);
    errdefer m.deinit();
    m.backing.max_pages = layout.backing.max_pages;
    for (layout.mappings.entries.items) |e| try m.map(.{ .start = e.first, .size = e.last - e.first + 1, .permissions = e.permissions });
    try m.backing.table.ensureTotalCapacity(@intCast(cp.pages.len));
    for (cp.pages) |entry| {
        const page = try a.create(Page);
        page.* = entry.page.*;
        m.backing.table.putAssumeCapacity(entry.index, page);
    }
    return m;
}

/// Continuity of a traced segment against the next checkpoint: same CPU,
/// counters, page set, set of written pages and bytes of every written page.
/// `dirty` is the segment memory's own write observer since `materialize`.
pub fn matches(segment: *const eth.Session, dirty: *const pages.Dirty, next: *const Checkpoint) bool {
    const memory = segment.keccak.base.memory;
    if (!std.meta.eql(segment.keccak.base.cpu, next.cpu) or !std.meta.eql(Counters.of(segment), next.counters)) return false;
    if (dirty.overflow or memory.backing.table.count() != next.pages.len) return false;
    var seen: usize = 0;
    for (dirty.bits, 0..) |word, w| {
        var bits = word;
        while (bits != 0) : (bits &= bits - 1) {
            const index = 64 * w + @ctz(bits);
            if (seen >= next.written.len or next.written[seen] != index) return false;
            seen += 1;
            const ours = memory.backing.peek(index) orelse return false;
            const theirs = next.find(index) orelse return false;
            if (!std.mem.eql(u8, ours, theirs)) return false;
        }
    }
    if (seen != next.written.len) return false;
    // Unwritten pages are the starting image, which agrees with `next`
    // there; the page sets are equal in size, so check membership.
    var it = memory.backing.table.keyIterator();
    while (it.next()) |index| if (next.find(index.*) == null) return false;
    return true;
}

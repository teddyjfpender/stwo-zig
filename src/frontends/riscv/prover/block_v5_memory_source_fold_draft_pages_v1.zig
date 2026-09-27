//! Encode original fold records once into bounded private PAGE files. Promotion
//! patches only the canonical header and publishes the same inode, never a new
//! payload copy. Draft/hash pins are transport proposals, not source authority.
const std = @import("std");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Store = @import("block_v5_memory_source_fold_operand_store_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Hash = std.crypto.hash.sha2.Sha256;
pub const MAGIC = "B5SFDRA1";
pub const Limits = struct {
    row_log: u32 = 12,
    max_pages: u32 = 262144,
    max_operations: u64 = 1_000_000_000,
    max_metadata_bytes: usize = 128 << 20,
    max_total_bytes: u64 = 512 << 30,
    /// One bounded PAGE serialization buffer, charged to the owner allocator.
    max_buffer_records: u32 = 4096,
    stored: Store.Limits = .{},
};
pub fn validateLimits(limits: Limits) !void {
    if (limits.row_log < 1 or limits.row_log > 12 or limits.max_pages == 0 or limits.max_pages > 262144 or
        limits.max_operations == 0 or limits.max_operations >= @import("stwo_core").fields.m31.Modulus or
        limits.max_metadata_bytes < @sizeOf(Owner) or limits.max_total_bytes == 0 or limits.max_buffer_records == 0 or limits.max_buffer_records > 4096 or
        limits.stored.max_operations == 0 or limits.stored.max_operations > 4096 or limits.stored.max_file_bytes == 0)
        return error.SourceFoldDraftResourceLimit;
}
pub fn path(buffer: []u8, index: u32, published: bool) ![]const u8 {
    if (published) return std.fmt.bufPrint(buffer, "source-page-fold-{d}.operands", .{index});
    return std.fmt.bufPrint(buffer, "source-page-fold-{d}.operands.draft", .{index});
}
fn length(count: u32, limits: Limits) !u64 {
    if (count == 0 or count > limits.stored.max_operations) return error.SourceFoldDraftResourceLimit;
    const bytes = try std.math.add(u64, Store.HEADER_BYTES, try std.math.mul(u64, count, Store.RECORD_BYTES));
    if (bytes > limits.stored.max_file_bytes) return error.SourceFoldDraftResourceLimit;
    return bytes;
}
fn header(admission: [32]u8, source: [32]u8, page: Protocol.Page) [Store.HEADER_BYTES]u8 {
    var raw: [Store.HEADER_BYTES]u8 = @splat(0);
    @memcpy(raw[0..8], MAGIC);
    @memcpy(raw[8..40], &admission);
    @memcpy(raw[40..72], &source);
    std.mem.writeInt(u32, raw[72..76], page.index, .little);
    std.mem.writeInt(u64, raw[76..84], page.first, .little);
    std.mem.writeInt(u32, raw[84..88], page.count, .little);
    std.mem.writeInt(u32, raw[88..92], page.row_log, .little);
    std.mem.writeInt(u32, raw[92..96], Store.RECORD_BYTES, .little);
    return raw;
}
pub const Pin = struct {
    page: Protocol.Page,
    byte_len: u64,
    payload_sha256: [32]u8,
    published: ?Store.Pin = null,
    /// Checked grammar/order only, not source/proof authority. Current file
    /// bytes must STILL hash to the original payload pin before publication.
    checked_inventory: ?[32]u8 = null,
};
/// Observational work only. No admission, file pin or source authority reads
/// these counters; payload requests count preadAll calls, not OS short reads.
pub const Work = struct {
    replay_payload_requests: u64 = 0,
    promotion_payload_requests: u64 = 0,
    replay_payload_sha_bytes: u64 = 0,
    promotion_payload_sha_bytes: u64 = 0,
    promotion_decode_attempts: u64 = 0,
};
pub const Owner = struct {
    a: std.mem.Allocator,
    lease: ?*Budget,
    dir: std.fs.Dir,
    admission_id: [32]u8,
    source_id: [32]u8,
    census: Fold.Census,
    limits: Limits,
    pins: []Pin,
    capacity: usize,
    total_bytes: u64,
    published: u32 = 0,
    replayed: u32 = 0,
    active_reader: bool = false,
    failed: bool = false,
    buffer: []u8 = &.{},
    buffer_borrowed: bool = false,
    work: Work = .{},
    pub const source_authority = false;

    pub fn require(self: *const Owner, admitted: *const Batch.Admission, plan: Protocol.FoldPlan, protocol_limits: Protocol.Limits) !void {
        try validateLimits(self.limits);
        try plan.require(admitted, protocol_limits);
        if (self.failed or self.limits.row_log != plan.row_log or self.pins.len != plan.pages or self.pins.len > self.limits.max_pages or
            !std.meta.eql(self.admission_id, admitted.identity) or !std.meta.eql(self.source_id, admitted.source.identity) or
            !std.meta.eql(self.census, plan.census)) return error.UntrustedSourceFoldDraft;
        const operations = try self.census.operations();
        const total = try std.math.add(u64, try std.math.mul(u64, self.pins.len, Store.HEADER_BYTES), try std.math.mul(u64, operations, Store.RECORD_BYTES));
        if (total != self.total_bytes or total > self.limits.max_total_bytes or operations > self.limits.max_operations)
            return error.SourceFoldDraftResourceLimit;
    }
    fn requirePin(self: *const Owner, plan: Protocol.FoldPlan, index: u32) !Pin {
        if (index >= self.pins.len) return error.InvalidSourceFoldDraftOrder;
        const pin = self.pins[index];
        if (!std.meta.eql(pin.page, try plan.page(index)) or pin.byte_len != try length(pin.page.count, self.limits) or
            std.mem.allEqual(u8, &pin.payload_sha256, 0) or ((pin.published != null) != (index < self.published))) return error.UntrustedSourceFoldDraft;
        return pin;
    }
    fn acquireBuffer(self: *Owner) ![]u8 {
        if (self.buffer.len == 0) {
            const records = @min(self.limits.max_buffer_records, @as(u32, 1) << @intCast(self.limits.row_log));
            self.buffer = try self.a.alloc(u8, try std.math.mul(usize, records, Store.RECORD_BYTES));
        }
        return self.buffer;
    }
    /// A staged page can be promoted only in the original exact order after
    /// its complete replay was checked. Caller must separately require the
    /// actual premix owner/pin; this method grants only original Store.Pin I/O.
    pub fn promote(self: *Owner, admitted: *const Batch.Admission, plan: Protocol.FoldPlan, index: u32, page_identity: [32]u8, protocol_limits: Protocol.Limits) !Store.Pin {
        try self.require(admitted, plan, protocol_limits);
        if (index != self.published or index >= self.pins.len or index >= self.replayed or std.mem.allEqual(u8, &page_identity, 0)) return error.InvalidSourceFoldDraftOrder;
        _ = try self.requirePin(plan, index);
        errdefer self.failed = true;
        const pin = &self.pins[index];
        var draft_buffer: [128]u8 = undefined;
        var final_buffer: [128]u8 = undefined;
        const draft_path = try path(&draft_buffer, index, false);
        const final_path = try path(&final_buffer, index, true);
        const file = try self.dir.openFile(draft_path, .{ .mode = .read_write });
        defer file.close();
        try requireHeader(file, pin.*, header(self.admission_id, self.source_id, pin.page));
        // Additive alias of the ORIGINAL codec header serializer. No new
        // grammar and no interpretation of a whole-spool slice as a PAGE.
        const canonical = Store.encodedHeader(pin.page, plan.identity, page_identity);
        var complete = Hash.init(.{});
        complete.update(&canonical);
        // Exact prior Reader checks permit omitting duplicate decoding ONLY
        // while the current payload still hashes to the original trusted pin.
        // The inventory binds source, admission, plan, page and byte length.
        const checked = if (pin.checked_inventory) |digest| std.meta.eql(digest, inventoryDigest(self, plan, pin.*)) else false;
        // A caller may promote an earlier page while replay has unread bytes
        // of a later page. Never overwrite that live reader's buffer lease.
        var fallback: [Store.BUFFER_BYTES]u8 = undefined;
        const bytes = if (self.buffer_borrowed) fallback[0..] else try self.acquireBuffer();
        try checkPayload(file, pin.*, &complete, bytes, !checked, &self.work);
        try file.pwriteAll(&canonical, 0);
        try file.sync();
        std.posix.linkat(self.dir.fd, draft_path, self.dir.fd, final_path, 0) catch |err| switch (err) {
            error.PathAlreadyExists => return error.ExistingV5BundleArtifact,
            else => return err,
        };
        errdefer self.dir.deleteFile(final_path) catch {};
        try std.posix.fsync(self.dir.fd);
        // Remove only the private name; final bytes stay on the SAME inode.
        try self.dir.deleteFile(draft_path);
        const stored = Store.Pin{ .byte_len = pin.byte_len, .sha256 = complete.finalResult(), .page_identity = page_identity };
        pin.published = stored;
        self.published += 1;
        return stored;
    }
    /// Private drafts roll back; successfully promoted originals are owned by
    /// the caller's publication inventory. Never remove those in this teardown.
    pub fn deinit(self: *Owner) !void {
        if (self.active_reader) return error.ActiveSourceFoldDraftReader;
        const a = self.a;
        const lease = self.lease;
        for (self.pins, 0..) |pin, index| if (pin.published == null) {
            var buffer: [128]u8 = undefined;
            self.dir.deleteFile(path(&buffer, @intCast(index), false) catch continue) catch {};
        };
        a.free(self.pins.ptr[0..self.capacity]);
        a.free(self.buffer);
        a.destroy(self);
        if (lease) |budget| budget.destroy();
    }
};
fn removeDrafts(dir: std.fs.Dir, count: usize) void {
    for (0..count) |index| {
        var buffer: [128]u8 = undefined;
        dir.deleteFile(path(&buffer, @intCast(index), false) catch continue) catch {};
    }
}
fn requireHeader(file: std.fs.File, pin: Pin, expected: [Store.HEADER_BYTES]u8) !void {
    if ((try file.stat()).size != pin.byte_len) return error.TamperedV5BundleFileLength;
    var raw: [Store.HEADER_BYTES]u8 = undefined;
    if (try file.preadAll(&raw, 0) != raw.len or !std.meta.eql(raw, expected)) return error.InvalidSourceFoldDraftHeader;
}
fn inventoryDigest(owner: *const Owner, plan: Protocol.FoldPlan, pin: Pin) [32]u8 {
    var hash = Hash.init(.{});
    hash.update("stwo-zig/source-fold-draft/checked-record-inventory/v1\x00");
    hash.update(&header(owner.admission_id, owner.source_id, pin.page));
    hash.update(&plan.identity);
    hash.update(&pin.payload_sha256);
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, pin.byte_len, .little);
    hash.update(&bytes);
    return hash.finalResult();
}
fn checkPayload(file: std.fs.File, pin: Pin, complete: *Hash, buffer: []u8, decode_records: bool, work: *Work) !void {
    var hash = Hash.init(.{});
    var start: usize = 0;
    while (start < pin.page.count) {
        const count: usize = @min(buffer.len / Store.RECORD_BYTES, @as(usize, pin.page.count) - start);
        const bytes = buffer[0 .. count * Store.RECORD_BYTES];
        work.promotion_payload_requests +|= 1;
        if (try file.preadAll(bytes, Store.HEADER_BYTES + start * Store.RECORD_BYTES) != bytes.len) return error.TamperedV5BundleFileLength;
        hash.update(bytes);
        complete.update(bytes);
        work.promotion_payload_sha_bytes +|= 2 * @as(u64, @intCast(bytes.len));
        if (decode_records) for (0..count) |i| {
            work.promotion_decode_attempts +|= 1;
            const operation = try Store.decodeOperation(bytes[i * Store.RECORD_BYTES ..][0..Store.RECORD_BYTES]);
            if (operation.ordinal != pin.page.first + start + i) return error.InvalidSourceFoldOperandOrder;
        };
        start += count;
    }
    var trailing: [1]u8 = undefined;
    if (try file.preadAll(&trailing, pin.byte_len) != 0 or !std.meta.eql(hash.finalResult(), pin.payload_sha256)) return error.TamperedV5BundleFileHash;
}

/// One original O(depth) cursor pass, encoded once. Only bounded PAGE pin
/// metadata is retained; never a whole operation vector or input image.
pub fn collect(a: std.mem.Allocator, dir: std.fs.Dir, admitted: *const Batch.Admission, reader: Fold.Reader, limits: Limits) !*Owner {
    try validateLimits(limits);
    try admitted.require();
    const lease = if (Budget.fromAllocator(a)) |budget| budget.retain() else null;
    errdefer if (lease) |budget| budget.destroy();
    var cursor = try Fold.Cursor.init(admitted.source, reader, admitted.limits);
    var pins: std.ArrayList(Pin) = .empty;
    defer pins.deinit(a);
    var created: u32 = 0;
    errdefer removeDrafts(dir, created);
    var file: ?std.fs.File = null;
    defer if (file) |open| open.close();
    var buffer: [Store.BUFFER_BYTES]u8 = undefined;
    var used: usize = 0;
    var hash = Hash.init(.{});
    var total: u64 = 0;
    var ordinal: u64 = 0;
    const capacity: u32 = @as(u32, 1) << @intCast(limits.row_log);
    var page = Protocol.Page{ .index = 0, .first = 0, .count = 0, .row_log = limits.row_log };
    while (try cursor.next()) |operation| {
        if (operation.ordinal != ordinal) return error.InvalidSourceFoldOperandOrder;
        if (ordinal >= limits.max_operations) return error.SourceFoldDraftResourceLimit;
        if (file == null) {
            if (created >= limits.max_pages) return error.SourceFoldDraftResourceLimit;
            if (pins.items.len == pins.capacity) {
                const next = @min(@as(usize, limits.max_pages), @max(@as(usize, 8), pins.capacity * 2));
                const peak = try std.math.add(usize, @sizeOf(Owner), try std.math.mul(usize, pins.capacity + next, @sizeOf(Pin)));
                if (peak > limits.max_metadata_bytes) return error.SourceFoldDraftResourceLimit;
                try pins.ensureTotalCapacityPrecise(a, next);
            }
            var draft_buffer: [128]u8 = undefined;
            var final_buffer: [128]u8 = undefined;
            if (dir.access(try path(&final_buffer, created, true), .{})) |_| return error.ExistingV5BundleArtifact else |err| if (err != error.FileNotFound) return err;
            file = try dir.createFile(try path(&draft_buffer, created, false), .{ .exclusive = true, .read = true });
            created += 1; // Track immediately, including failed prefix writes.
            page = .{ .index = created - 1, .first = ordinal, .count = 0, .row_log = limits.row_log };
            total = try std.math.add(u64, total, Store.HEADER_BYTES);
            if (total > limits.max_total_bytes) return error.SourceFoldDraftResourceLimit;
            // Reserve the final header position. Write it only when the
            // actual tail count is known; incomplete files never escape.
            try file.?.seekTo(Store.HEADER_BYTES);
            hash = Hash.init(.{});
        }
        page.count += 1;
        _ = try length(page.count, limits);
        total = try std.math.add(u64, total, Store.RECORD_BYTES);
        if (total > limits.max_total_bytes) return error.SourceFoldDraftResourceLimit;
        try Store.encodeOperation(operation, buffer[used..][0..Store.RECORD_BYTES]);
        used += Store.RECORD_BYTES;
        ordinal += 1;
        if (used == buffer.len or page.count == capacity) {
            try file.?.writeAll(buffer[0..used]);
            hash.update(buffer[0..used]);
            used = 0;
        }
        if (page.count == capacity) {
            try file.?.pwriteAll(&header(admitted.identity, admitted.source.identity, page), 0);
            try file.?.sync();
            file.?.close();
            file = null;
            pins.appendAssumeCapacity(.{ .page = page, .byte_len = try length(page.count, limits), .payload_sha256 = hash.finalResult() });
        }
    }
    if (file) |open| {
        if (used != 0) {
            try open.writeAll(buffer[0..used]);
            hash.update(buffer[0..used]);
        }
        try open.pwriteAll(&header(admitted.identity, admitted.source.identity, page), 0);
        try open.sync();
        open.close();
        file = null;
        pins.appendAssumeCapacity(.{ .page = page, .byte_len = try length(page.count, limits), .payload_sha256 = hash.finalResult() });
    }
    try cursor.census.require(&admitted.source, admitted.limits);
    if (pins.items.len == 0 or ordinal != try cursor.census.operations()) return error.UntrustedSourceFoldDraft;
    try std.posix.fsync(dir.fd);
    const owner = try a.create(Owner);
    owner.* = .{ .a = a, .lease = lease, .dir = dir, .admission_id = admitted.identity, .source_id = admitted.source.identity, .census = cursor.census, .limits = limits, .pins = pins.items, .capacity = pins.capacity, .total_bytes = total };
    pins = .empty;
    return owner;
}

/// Rewind repeats every header/record/hash guard; no cached acceptance. A
/// promoted page is read via its canonical header on the same original inode.
pub const Reader = struct {
    owner: *Owner,
    plan: Protocol.FoldPlan,
    index: u32 = 0,
    logical: u32 = 0,
    file: ?std.fs.File = null,
    buffer: []u8,
    available: usize = 0,
    position: usize = 0,
    hash: Hash = Hash.init(.{}),
    complete: Hash = Hash.init(.{}),
    pub fn open(owner: *Owner, admitted: *const Batch.Admission, plan: Protocol.FoldPlan, protocol_limits: Protocol.Limits) !Reader {
        try owner.require(admitted, plan, protocol_limits);
        if (owner.active_reader) return error.ActiveSourceFoldDraftReader;
        const buffer = try owner.acquireBuffer();
        owner.active_reader = true;
        owner.buffer_borrowed = false;
        owner.replayed = 0;
        return .{ .owner = owner, .plan = plan, .buffer = buffer };
    }
    pub fn deinit(self: *Reader) void {
        if (self.file) |file| file.close();
        self.owner.active_reader = false;
        self.owner.buffer_borrowed = false;
        self.* = undefined;
    }
    pub fn rewind(self: *Reader) !void {
        if (self.owner.failed) return error.UntrustedSourceFoldDraft;
        if (self.file) |file| file.close();
        self.owner.replayed = 0;
        self.owner.buffer_borrowed = false;
        self.* = .{ .owner = self.owner, .plan = self.plan, .buffer = self.buffer };
    }
    pub fn next(self: *Reader) !?Fold.Operation {
        if (self.owner.failed) return error.UntrustedSourceFoldDraft;
        errdefer self.owner.failed = true;
        if (self.index == self.owner.pins.len) return null;
        const pin = try self.owner.requirePin(self.plan, self.index);
        if (self.file == null) {
            var buffer: [128]u8 = undefined;
            const file = try self.owner.dir.openFile(try path(&buffer, self.index, pin.published != null), .{});
            errdefer file.close();
            const expected = if (pin.published) |stored| Store.encodedHeader(pin.page, self.plan.identity, stored.page_identity) else header(self.owner.admission_id, self.owner.source_id, pin.page);
            try requireHeader(file, pin, expected);
            self.file = file;
            self.hash = Hash.init(.{});
            self.complete = Hash.init(.{});
            if (pin.published != null) self.complete.update(&expected);
            self.logical = 0;
            self.available = 0;
            self.position = 0;
        }
        if (self.position == self.available) {
            const count: usize = @min(self.buffer.len / Store.RECORD_BYTES, pin.page.count - self.logical);
            const bytes = self.buffer[0 .. count * Store.RECORD_BYTES];
            self.owner.work.replay_payload_requests +|= 1;
            if (try self.file.?.preadAll(bytes, Store.HEADER_BYTES + @as(u64, self.logical) * Store.RECORD_BYTES) != bytes.len) return error.TamperedV5BundleFileLength;
            self.hash.update(bytes);
            if (pin.published != null) self.complete.update(bytes);
            self.owner.work.replay_payload_sha_bytes +|= @as(u64, @intCast(bytes.len)) * (1 + @as(u64, @intFromBool(pin.published != null)));
            self.available = bytes.len;
            self.position = 0;
            self.owner.buffer_borrowed = true;
        }
        const operation = try Store.decodeOperation(self.buffer[self.position..][0..Store.RECORD_BYTES]);
        if (operation.ordinal != pin.page.first + self.logical) return error.InvalidSourceFoldOperandOrder;
        self.position += Store.RECORD_BYTES;
        if (self.position == self.available) self.owner.buffer_borrowed = false;
        self.logical += 1;
        if (self.logical == pin.page.count) {
            var trailing: [1]u8 = undefined;
            if (try self.file.?.preadAll(&trailing, pin.byte_len) != 0 or !std.meta.eql(self.hash.finalResult(), pin.payload_sha256)) return error.TamperedV5BundleFileHash;
            if (pin.published) |stored| if (!std.meta.eql(self.complete.finalResult(), stored.sha256)) return error.TamperedV5BundleFileHash;
            self.owner.pins[self.index].checked_inventory = inventoryDigest(self.owner, self.plan, pin);
            self.file.?.close();
            self.file = null;
            self.index += 1;
            self.owner.replayed = self.index;
        }
        return operation;
    }
    pub fn requireFinished(self: *const Reader) !void {
        if (self.owner.failed or self.file != null or self.index != self.owner.pins.len) return error.IncompleteSourceFoldDraft;
    }
};

//! One bounded durable recursive-leaf ownership kernel. Typed adapters retain
//! their original grammar, admission, public inputs and distinct fresh verifier.
//! File pins, exact roster census and successful publication are not proof authority.
const std = @import("std");
const Seal = @import("block_v5_source_seal_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Parts = @import("block_v5_recursive_leaf_envelope_parts_v1.zig");
pub const Roster = struct {
    sealed: Seal.Sealed,
    pins: Seal.Pins,
    entries: []const Seal.Entry,
    pub fn require(self: Roster) !void {
        try self.sealed.require(self.pins, self.entries);
    }
};
pub const FilePin = struct { index: u32, byte_len: u64, sha256: [32]u8 };
pub fn ForDefinition(comptime D: type) type {
    const C = D.Codec;
    const Limits = D.Limits;
    const E = D.Errors;
    return struct {
        pub const Codec = C;
        pub const Policy = C.Policy;
        pub const TemplatePolicy = D.TemplatePolicy;
        pub const SourceAdmission = struct { prepared: @FieldType(Policy, "prepared") };
        pub const Selection = if (@hasDecl(D, "Selection")) D.Selection else void;
        pub const Loader = struct { context: *anyopaque, take_fresh: *const fn (*anyopaque, u32) anyerror!D.Receiver.OpenEquation };
        const Slot = struct {
            policy: Policy,
            pin: ?FilePin = null,
            state: enum { pending, reading, verified, failed } = .pending,
            template_bound: bool = true,
        };
        pub const Store = struct {
            a: std.mem.Allocator,
            dir: std.fs.Dir,
            /// Policies, templates, schedules and Prepared authority are
            /// immutable borrows until all readers have joined and deinit ends.
            slots: []Slot,
            limits: Limits,
            total_bytes: u64 = 0,
            mode: enum { writer, reader },
            active_readers: usize = 0,
            mutex: std.Thread.Mutex = .{},
            owned_templates: ?[]TemplatePolicy = null,
            owned_template_bytes: usize = 0,
            /// Exact source slots are admitted before original proof geometry
            /// exists. No unbound slot can publish or verify. Only a template
            /// independently derived from original verifier rows may bind it.
            pub fn initWriterFromSources(a: std.mem.Allocator, dir: std.fs.Dir, roster: Roster, sources: []const SourceAdmission, limits: Limits) !Store {
                return initSourceWriter(a, dir, roster, sources, null, limits);
            }
            pub fn initWriterFromSourcesWithSelection(a: std.mem.Allocator, dir: std.fs.Dir, roster: Roster, sources: []const SourceAdmission, selection: *const Selection, limits: Limits) !Store {
                if (comptime @hasDecl(D, "Selection")) {
                    try selection.require(roster);
                    return initSourceWriter(a, dir, roster, sources, selection, limits);
                } else return error.UnsupportedRecursiveLeafSelection;
            }
            fn initSourceWriter(a: std.mem.Allocator, dir: std.fs.Dir, roster: Roster, sources: []const SourceAdmission, selection: ?*const Selection, limits: Limits) !Store {
                try limits.validate();
                try roster.require();
                const selected: ?[]const u32 = if (comptime @hasDecl(D, "Selection")) if (selection) |value| value.indices else null else null;
                const expected = if (selected) |indices| indices.len else roster.pins.counts[@intFromEnum(D.seal_family) - 1];
                if (sources.len != expected) return E.incomplete_policies;
                try requireSlotCapacity(sources.len, limits);
                const template_bytes = try std.math.mul(usize, sources.len, @sizeOf(TemplatePolicy));
                if (try std.math.add(usize, template_bytes, try std.math.mul(usize, sources.len, @sizeOf(Slot) + @sizeOf(FilePin))) > limits.max_slot_bytes) return E.slot_limit;
                // Validate all authentic source entries before any slot/control
                // allocation. An empty selected roster remains truly empty.
                var ordinal: usize = 0;
                for (roster.entries) |entry| if (entry.family == D.seal_family) {
                    if (selected) |indices| {
                        if (ordinal == indices.len or entry.index != indices[ordinal]) continue;
                    }
                    if (ordinal >= sources.len) return E.incomplete_policies;
                    const p = sources[ordinal].prepared;
                    try p.validate(p.template_id);
                    if (D.index(p) != entry.index or !std.meta.eql(D.sealed(p), roster.sealed) or !std.meta.eql(D.pins(p), roster.pins)) return E.untrusted_roster;
                    ordinal += 1;
                };
                if (ordinal != sources.len) return E.incomplete_policies;
                const templates = try a.alloc(TemplatePolicy, sources.len);
                errdefer a.free(templates);
                const slots = try a.alloc(Slot, sources.len);
                errdefer a.free(slots);
                for (slots, sources, templates) |*slot, source, *template| slot.* = .{ .policy = .{ .prepared = source.prepared, .template = template }, .template_bound = false };
                if (comptime @hasDecl(D, "Selection")) if (selection) |value| {
                    const policies = try a.alloc(Policy, sources.len);
                    defer a.free(policies);
                    for (policies, slots) |*policy, slot| policy.* = slot.policy;
                    try D.requireSelection(value, roster, policies, limits.codec);
                };
                return .{ .a = a, .dir = dir, .slots = slots, .limits = limits, .mode = .writer, .owned_templates = templates, .owned_template_bytes = template_bytes };
            }
            /// Writer setup reuse only. The caller supplies a template derived
            /// through actual original fresh verification and exact rows; this
            /// method alone grants no equation or receiver authority. A fresh
            /// receiver MUST reconstruct templates from authentic base files.
            pub fn bindWriterTemplate(self: *Store, index: u32, independently_derived: TemplatePolicy) !void {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (self.mode != .writer or self.owned_templates == null) return E.invalid_mode;
                const at = try self.position(index);
                const slot = &self.slots[at];
                if (slot.template_bound or slot.pin != null or slot.state != .pending) return error.AlreadyBoundRecursiveLeafTemplate;
                const candidate = Policy{ .prepared = slot.policy.prepared, .template = &independently_derived };
                try candidate.require(self.limits.codec);
                const wire_bytes = try std.math.mul(usize, independently_derived.schedule.len, @sizeOf(@typeInfo(@TypeOf(independently_derived.schedule)).pointer.child));
                const owned_bytes = try std.math.add(usize, self.owned_template_bytes, wire_bytes);
                if (try std.math.add(usize, owned_bytes, try std.math.mul(usize, self.slots.len, @sizeOf(Slot) + @sizeOf(FilePin))) > self.limits.max_slot_bytes) return E.slot_limit;
                const schedule = try self.a.dupe(@typeInfo(@TypeOf(independently_derived.schedule)).pointer.child, independently_derived.schedule);
                var template = independently_derived;
                template.schedule = schedule;
                self.owned_templates.?[at] = template;
                slot.template_bound = true;
                self.owned_template_bytes = owned_bytes;
            }
            /// Borrowed original source only; no proof or template authority.
            pub fn sourceFor(self: *Store, index: u32) !SourceAdmission {
                self.mutex.lock();
                defer self.mutex.unlock();
                return .{ .prepared = self.slots[try self.position(index)].policy.prepared };
            }
            /// Immutable policies remain borrowed until joined consumers end.
            /// Snapshotting requires exact publication, but grants no verified
            /// equation: consumers still invoke original fresh leaf receivers.
            pub fn publishedPolicies(self: *Store, a: std.mem.Allocator) ![]Policy {
                self.mutex.lock();
                defer self.mutex.unlock();
                for (self.slots) |slot| if (!slot.template_bound or slot.pin == null) return E.incomplete_files;
                const policies = try a.alloc(Policy, self.slots.len);
                for (policies, self.slots) |*policy, slot| policy.* = slot.policy;
                return policies;
            }
            pub fn initWriter(a: std.mem.Allocator, dir: std.fs.Dir, roster: Roster, policies: []const Policy, limits: Limits) !Store {
                return initWriterAdmitted(a, dir, roster, policies, null, limits);
            }
            /// Optional entries require an adapter's typed independent
            /// selection. This cannot accept a received list of file indices.
            pub fn initWriterWithSelection(a: std.mem.Allocator, dir: std.fs.Dir, roster: Roster, policies: []const Policy, selection: *const Selection, limits: Limits) !Store {
                if (comptime @hasDecl(D, "Selection")) {
                    try limits.validate();
                    try requireSlotCapacity(policies.len, limits);
                    try D.requireSelection(selection, roster, policies, limits.codec);
                    return initWriterAdmitted(a, dir, roster, policies, selection.indices, limits);
                } else return error.UnsupportedRecursiveLeafSelection;
            }
            fn initWriterAdmitted(a: std.mem.Allocator, dir: std.fs.Dir, roster: Roster, policies: []const Policy, selected: ?[]const u32, limits: Limits) !Store {
                try limits.validate();
                try roster.require();
                const expected = if (selected) |indices| indices.len else roster.pins.counts[@intFromEnum(D.seal_family) - 1];
                if (policies.len != expected) return E.incomplete_policies;
                try requireSlotCapacity(policies.len, limits);
                // Source-seal order is independent of received file/policy order.
                // Caller entries can be sparse actual execution indices.
                var ordinal: usize = 0;
                for (roster.entries) |entry| if (entry.family == D.seal_family) {
                    if (selected) |indices| {
                        if (ordinal == indices.len or entry.index != indices[ordinal]) continue;
                    }
                    if (ordinal >= policies.len) return E.incomplete_policies;
                    const policy = policies[ordinal];
                    try policy.require(limits.codec);
                    if (D.index(policy.prepared) != entry.index or
                        !std.meta.eql(D.sealed(policy.prepared), roster.sealed) or
                        !std.meta.eql(D.pins(policy.prepared), roster.pins))
                        return E.untrusted_roster;
                    ordinal += 1;
                };
                if (ordinal != policies.len) return E.incomplete_policies;
                const slots = try a.alloc(Slot, policies.len);
                for (slots, policies) |*slot, policy| slot.* = .{ .policy = policy };
                return .{ .a = a, .dir = dir, .slots = slots, .limits = limits, .mode = .writer };
            }
            fn requireSlotCapacity(count: usize, limits: Limits) !void {
                if (count > limits.max_files or
                    try std.math.mul(usize, count, @sizeOf(Slot) + @sizeOf(FilePin)) > limits.max_slot_bytes)
                    return E.slot_limit;
            }
            pub fn initReader(a: std.mem.Allocator, dir: std.fs.Dir, roster: Roster, policies: []const Policy, pins: []const FilePin, limits: Limits) !Store {
                try validatePins(pins, limits);
                if (pins.len != policies.len) return E.incomplete_files;
                var self = try initWriter(a, dir, roster, policies, limits);
                errdefer self.deinit();
                try self.admitReaderPins(pins);
                return self;
            }
            pub fn initReaderWithSelection(a: std.mem.Allocator, dir: std.fs.Dir, roster: Roster, policies: []const Policy, pins: []const FilePin, selection: *const Selection, limits: Limits) !Store {
                if (comptime @hasDecl(D, "Selection")) {
                    // Resource/framing checks before recipe work or allocation;
                    // sparse indices gain census authority only from selection.
                    try validatePinsFor(pins, limits, true);
                    if (pins.len != policies.len) return E.incomplete_files;
                    var self = try initWriterWithSelection(a, dir, roster, policies, selection, limits);
                    errdefer self.deinit();
                    try self.admitReaderPins(pins);
                    return self;
                } else return error.UnsupportedRecursiveLeafSelection;
            }
            fn admitReaderPins(self: *Store, pins: []const FilePin) !void {
                for (self.slots, pins) |*slot, pin| {
                    if (D.index(slot.policy.prepared) != pin.index) return E.untrusted_index;
                    slot.pin = pin;
                    self.total_bytes = try std.math.add(u64, self.total_bytes, pin.byte_len);
                }
                self.mode = .reader;
            }
            pub fn deinit(self: *Store) void {
                self.mutex.lock();
                if (self.active_readers != 0) @panic("destroying active recursive provider file reader");
                if (self.owned_templates) |templates| {
                    for (self.slots, templates) |slot, template| if (slot.template_bound) self.a.free(template.schedule);
                    self.a.free(templates);
                }
                self.a.free(self.slots);
                self.mutex.unlock();
                self.* = undefined;
            }
            fn position(self: *const Store, index: u32) !usize {
                var first: usize = 0;
                var end = self.slots.len;
                while (first < end) {
                    const middle = first + (end - first) / 2;
                    if (D.index(self.slots[middle].policy.prepared) < index) first = middle + 1 else end = middle;
                }
                if (first == self.slots.len or D.index(self.slots[first].policy.prepared) != index)
                    return E.unadmitted_index;
                return first;
            }
            /// Publishes an already fresh-checked stage artifact; does not
            /// return cryptographic authority or repeat the stage verifier.
            /// Success consumes only after synced exclusive publication.
            /// Artifact buffers must use this store's allocator, matching
            /// Stage.publish's allocator when publishing through sink().
            pub fn put(self: *Store, index: u32, artifact: *D.Stage.Artifact) !void {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (self.mode != .writer) return E.invalid_mode;
                const slot = &self.slots[try self.position(index)];
                if (!slot.template_bound) return error.UnboundRecursiveLeafTemplate;
                if (slot.pin != null) return E.duplicate_leaf;
                var encoded = try C.encode(self.a, artifact, slot.policy, self.limits.codec);
                defer encoded.deinit();
                const total = try std.math.add(u64, self.total_bytes, encoded.total_bytes);
                if (total > self.limits.max_total_bytes) return E.total_limit;
                var name: [96]u8 = undefined;
                const parts = encoded.parts();
                const digest = Files.hashParts(&parts);
                try Files.publishParts(self.dir, try fileName(&name, index), &parts);
                slot.pin = .{ .index = index, .byte_len = encoded.total_bytes, .sha256 = digest };
                self.total_bytes = total;
                artifact.deinit(self.a);
                artifact.* = undefined;
            }
            /// Length/hash are checked first. Public metadata remains a
            /// proposal until the actual distinct recursive verifier succeeds.
            /// One failed attempt is terminal; it never counts as verified.
            pub fn takeFresh(self: *Store, index: u32) !D.Receiver.OpenEquation {
                self.mutex.lock();
                const at = self.position(index) catch |err| {
                    self.mutex.unlock();
                    return err;
                };
                const slot = &self.slots[at];
                if (!slot.template_bound) {
                    self.mutex.unlock();
                    return error.UnboundRecursiveLeafTemplate;
                }
                if (self.mode != .reader or slot.state != .pending) {
                    self.mutex.unlock();
                    return E.invalid_load;
                }
                const pin = slot.pin orelse {
                    self.mutex.unlock();
                    return E.incomplete_files;
                };
                slot.state = .reading;
                self.active_readers += 1;
                self.mutex.unlock();
                var success = false;
                defer {
                    self.mutex.lock();
                    slot.state = if (success) .verified else .failed;
                    self.active_readers -= 1;
                    self.mutex.unlock();
                }
                var name: [96]u8 = undefined;
                var raw = try Parts.readPinned(C, self.a, self.dir, try fileName(&name, index), pin.byte_len, pin.sha256, slot.policy, self.limits.codec);
                defer raw.deinit();
                var view = try C.decodeMetadataParts(self.a, &raw.header, raw.metadata, raw.proof, slot.policy, self.limits.codec);
                defer view.deinit();
                // Each adapter invokes its original distinct verifier; neither
                // transport hashes nor a decoded proposal create authority.
                var fresh = try D.verifyView(self.a, &view, slot.policy);
                errdefer fresh.deinit();
                success = true;
                return fresh;
            }
            /// Borrow the independent policy and return only owned pinned proof
            /// bytes for an actual hierarchy leaf verifier. This does not mark a
            /// file verified, grant an equation, or repeat that verifier here.
            /// Both writer publication and reader transport are supported.
            pub fn proofBytes(self: *Store, a: std.mem.Allocator, index: u32) ![]u8 {
                self.mutex.lock();
                const at = self.position(index) catch |err| {
                    self.mutex.unlock();
                    return err;
                };
                const slot = &self.slots[at];
                if (!slot.template_bound) {
                    self.mutex.unlock();
                    return error.UnboundRecursiveLeafTemplate;
                }
                if (slot.state != .pending) {
                    self.mutex.unlock();
                    return E.invalid_load;
                }
                const pin = slot.pin orelse {
                    self.mutex.unlock();
                    return E.incomplete_files;
                };
                slot.state = .reading;
                self.active_readers += 1;
                self.mutex.unlock();
                var success = false;
                defer {
                    self.mutex.lock();
                    slot.state = if (success) .pending else .failed;
                    self.active_readers -= 1;
                    self.mutex.unlock();
                }
                var name: [96]u8 = undefined;
                var raw = try Parts.readPinned(C, a, self.dir, try fileName(&name, index), pin.byte_len, pin.sha256, slot.policy, self.limits.codec);
                defer raw.deinit();
                var view = try C.decodeMetadataParts(a, &raw.header, raw.metadata, raw.proof, slot.policy, self.limits.codec);
                defer view.deinit();
                success = true;
                return raw.detachProof();
            }
            pub fn filePins(self: *Store, a: std.mem.Allocator) ![]FilePin {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (self.mode != .writer) return E.invalid_mode;
                for (self.slots) |slot| if (slot.pin == null) return E.incomplete_files;
                const pins = try a.alloc(FilePin, self.slots.len);
                for (pins, self.slots) |*pin, slot| pin.* = slot.pin.?;
                return pins;
            }
            /// Exact transport snapshot for independently source-bound writers
            /// OR readers. This grants no verified state; actual fresh verifier
            /// remains mandatory. Existing writer-only filePins is unchanged.
            pub fn sourceFilePins(self: *Store, a: std.mem.Allocator) ![]FilePin {
                self.mutex.lock();
                defer self.mutex.unlock();
                for (self.slots) |slot| if (!slot.template_bound or slot.pin == null) return E.incomplete_files;
                const pins = try a.alloc(FilePin, self.slots.len);
                for (pins, self.slots) |*pin, slot| pin.* = slot.pin.?;
                return pins;
            }
            pub fn requireVerified(self: *Store) !void {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (self.mode != .reader or self.active_readers != 0) return E.invalid_load;
                for (self.slots) |slot| if (slot.state != .verified) return E.incomplete_verification;
            }
            pub fn loader(self: *Store) Loader {
                return .{ .context = self, .take_fresh = load };
            }
            pub fn sink(self: *Store) D.Stage.Sink {
                var result: D.Stage.Sink = undefined;
                result.context = self;
                @field(result, D.SINK_FIELD) = save;
                return result;
            }
        };
        fn save(raw: *anyopaque, index: u32, artifact: *D.Stage.Artifact) anyerror!void {
            return (@as(*Store, @ptrCast(@alignCast(raw)))).put(index, artifact);
        }
        fn load(raw: *anyopaque, index: u32) anyerror!D.Receiver.OpenEquation {
            return (@as(*Store, @ptrCast(@alignCast(raw)))).takeFresh(index);
        }
        pub fn fileName(buffer: []u8, index: u32) ![]const u8 {
            return D.fileName(buffer, index);
        }
        pub fn validatePins(pins: []const FilePin, limits: Limits) !void {
            return validatePinsFor(pins, limits, D.allow_sparse);
        }
        fn validatePinsFor(pins: []const FilePin, limits: Limits, allow_sparse: bool) !void {
            try limits.validate();
            if (pins.len > limits.max_files or
                try std.math.mul(usize, pins.len, @sizeOf(FilePin)) > limits.max_slot_bytes)
                return E.slot_limit;
            var total: u64 = 0;
            for (pins, 0..) |pin, index| {
                if ((!allow_sparse and pin.index != index) or
                    (index != 0 and pins[index - 1].index >= pin.index) or
                    pin.byte_len <= D.HEADER_BYTES or pin.byte_len > D.maxFileBytes(limits.codec))
                    return E.untrusted_pin;
                total = try std.math.add(u64, total, pin.byte_len);
                if (total > limits.max_total_bytes) return E.total_limit;
            }
        }
    };
}

//! Shared bounded B5CT/B5CF store and manifest state machine. Distinct typed
//! codecs, policies, fresh verifiers, names and errors remain per family.
const std = @import("std");
const core = @import("stwo_core");
pub fn ForFamily(comptime fused: bool) type {
    return struct {
        const Native = @import("block_v5_native_capacity_proof_v1.zig");
        const Codec = if (fused) @import("block_v5_native_capacity_fused_codec_v1.zig") else @import("block_v5_native_capacity_codec_v1.zig");
        const Receiver = if (fused) @import("block_v5_native_capacity_fused_artifact_receiver_v1.zig") else @import("block_v5_native_capacity_artifact_receiver_v1.zig");
        const Payload = if (fused) @import("block_v5_native_capacity_fused_proof_v1.zig").Proof else Native.Proof;
        const Files = @import("block_v5_artifact_files_v1.zig");
        pub const Policy = Receiver.Policy;
        pub const FilePin = struct { index: u32, byte_len: u64, sha256: [32]u8 };
        pub const Limits = struct {
            max_files: usize = 1 << 16,
            max_file_bytes: usize = 64 << 20,
            max_total_bytes: u64 = 64 << 30,
            max_metadata_bytes: usize = 64 << 20,
            max_manifest_bytes: usize = 4 << 20,
            pub fn validate(self: Limits) !void {
                if (self.max_files == 0 or self.max_file_bytes < Codec.HEADER_BYTES or
                    self.max_total_bytes == 0 or self.max_metadata_bytes == 0 or self.max_manifest_bytes < 12)
                    return failure(error.InvalidNativeCapacityStoreLimits);
            }
        };
        const Slot = struct {
            policy: Policy,
            expected: Codec.Expected,
            roots: [2][32]u8,
            wire_limits: Codec.Limits,
            pin: ?FilePin = null,
            consumed: bool = false,
        };
        pub const Sink = if (fused) @import("block_v5_native_capacity_fused_stage_v1.zig").Sink else struct { context: *anyopaque, put: *const fn (*anyopaque, u32, *Payload) anyerror!void };
        pub const Loader = struct { context: *anyopaque, take: *const fn (*anyopaque, u32) anyerror!Payload };
        pub const Store = struct {
            a: std.mem.Allocator,
            dir: std.fs.Dir,
            /// Slot policies are copied; their shapes, rosters and catalog remain
            /// borrowed immutable receiver authority for this store's entire lifetime.
            slots: []Slot,
            limits: Limits,
            total_bytes: u64 = 0,
            mode: enum { writer, reader },
            mutex: std.Thread.Mutex = .{},
            pub fn initWriter(a: std.mem.Allocator, dir: std.fs.Dir, policies: []const Policy, config: core.pcs.PcsConfig, limits: Limits) !Store {
                try limits.validate();
                if (policies.len == 0 or policies.len > limits.max_files or
                    try std.math.mul(usize, policies.len, @sizeOf(Slot) + @sizeOf(FilePin)) > limits.max_metadata_bytes)
                    return failure(error.NativeCapacityStoreMetadataLimit);
                // Validate all independent authority before allocating persistent slots.
                for (policies, 0..) |policy, i| {
                    if (i != 0 and policies[i - 1].index >= policy.index) return failure(error.NoncanonicalNativeCapacityStorePolicy);
                    if (!std.meta.eql(policy.pins.config, config)) return failure(error.UntrustedNativeCapacityStoreSecurity);
                    _ = try policy.expected(a);
                }
                const slots = try a.alloc(Slot, policies.len);
                errdefer a.free(slots);
                for (policies, slots) |policy, *slot| {
                    const expected = try policy.expected(a);
                    var roots: ?[2][32]u8 = null;
                    for (policy.entries) |entry| if (entry.family == .execution and entry.index == policy.index) {
                        roots = entry.roots;
                    };
                    var wire_limits = policy.wire_limits;
                    wire_limits.artifact_bytes = @min(wire_limits.artifact_bytes, limits.max_file_bytes);
                    wire_limits.proof_bytes = @min(wire_limits.proof_bytes, wire_limits.artifact_bytes);
                    try wire_limits.validate();
                    slot.* = .{ .policy = policy, .expected = expected, .roots = roots orelse return failure(error.UntrustedNativeCapacityStorePolicy), .wire_limits = wire_limits };
                }
                return .{ .a = a, .dir = dir, .slots = slots, .limits = limits, .mode = .writer };
            }
            pub fn initReader(a: std.mem.Allocator, dir: std.fs.Dir, policies: []const Policy, pins: []const FilePin, config: core.pcs.PcsConfig, limits: Limits) !Store {
                try validatePins(pins, limits);
                if (pins.len != policies.len) return failure(error.IncompleteNativeCapacityFiles);
                var self = try initWriter(a, dir, policies, config, limits);
                errdefer self.deinit();
                for (pins, self.slots) |pin, *slot| {
                    if (pin.index != slot.policy.index) return failure(error.UntrustedNativeCapacityFileIndex);
                    slot.pin = pin;
                    self.total_bytes = try std.math.add(u64, self.total_bytes, pin.byte_len);
                }
                self.mode = .reader;
                return self;
            }
            pub fn deinit(self: *Store) void {
                self.a.free(self.slots);
                self.* = undefined;
            }
            fn position(self: *const Store, index: u32) !usize {
                // Ordered receiver policy permits bounded binary lookup, not a scan of
                // the complete block roster for each proof publication.
                var lo: usize = 0;
                var hi = self.slots.len;
                while (lo < hi) {
                    const mid = lo + (hi - lo) / 2;
                    const actual = self.slots[mid].policy.index;
                    if (actual < index) lo = mid + 1 else if (actual > index) hi = mid else return mid;
                }
                return failure(error.UnadmittedNativeCapacityStoreIndex);
            }
            /// Success consumes only after synced, exclusive publication. All failures
            /// retain the producer's proof and leave this slot unpublished.
            pub fn put(self: *Store, index: u32, proof: *Payload) !void {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (self.mode != .writer) return failure(error.InvalidNativeCapacityStoreMode);
                const slot = &self.slots[try self.position(index)];
                if (slot.pin != null) return failure(error.DuplicateNativeCapacityArtifact);
                try requireRoots(proof, slot.roots);
                const raw = try Codec.encode(self.a, proof, slot.expected, slot.wire_limits);
                defer self.a.free(raw);
                const total = try std.math.add(u64, self.total_bytes, raw.len);
                if (total > self.limits.max_total_bytes) return failure(error.NativeCapacityStoreTotalLimit);
                var name: [96]u8 = undefined;
                try Files.publish(self.dir, try fileName(&name, index), raw);
                slot.pin = .{ .index = index, .byte_len = raw.len, .sha256 = Files.hash(raw) };
                self.total_bytes = total;
                proof.deinit(self.a);
                proof.* = undefined;
            }
            fn takeRaw(self: *Store, index: u32) !struct { bytes: []u8, slot: *const Slot } {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (self.mode != .reader) return failure(error.InvalidNativeCapacityStoreMode);
                const slot = &self.slots[try self.position(index)];
                if (slot.consumed) return failure(error.RepeatedNativeCapacityLoad);
                slot.consumed = true; // Failures cannot substitute a new file in session.
                const pin = slot.pin orelse return failure(error.IncompleteNativeCapacityFiles);
                var name: [96]u8 = undefined;
                return .{ .bytes = try Files.readPinned(self.a, self.dir, try fileName(&name, index), pin.byte_len, pin.sha256, self.limits.max_file_bytes), .slot = slot };
            }
            /// Structural decoding only. The consumer must run the genuine verifier.
            pub fn take(self: *Store, index: u32) !Payload {
                const raw = try self.takeRaw(index);
                defer self.a.free(raw.bytes);
                var proof = try Codec.decode(self.a, raw.bytes, raw.slot.expected, raw.slot.wire_limits);
                errdefer proof.deinit(self.a);
                try requireRoots(&proof, raw.slot.roots);
                return proof;
            }
            pub fn verifyCaptured(self: *Store, comptime Backend: type, index: u32) !Native.VerifiedCapture {
                if (fused) @compileError("B5CF loading requires both genuine native and fused verification; use verifyOwned");
                const raw = try self.takeRaw(index);
                defer self.a.free(raw.bytes);
                var policy = raw.slot.policy;
                policy.wire_limits = raw.slot.wire_limits;
                return Receiver.ForBackend(Backend).verifyCaptured(self.a, raw.bytes, policy);
            }
            /// Base proof ownership transfers even when file loading fails.
            pub fn verifyOwned(self: *Store, comptime Backend: type, index: u32, native_received: Native.Proof) !@import("block_v5_native_capacity_fused_receiver_v1.zig").Open {
                if (!fused) @compileError("Native B5CT loading uses its genuine verifyCaptured method");
                var native = native_received;
                var owns = true;
                defer if (owns) native.deinit(self.a);
                const raw = try self.takeRaw(index);
                defer self.a.free(raw.bytes);
                var policy = raw.slot.policy;
                policy.wire_limits = raw.slot.wire_limits;
                owns = false;
                return Receiver.ForBackend(Backend).verifyOwned(self.a, raw.bytes, native, policy);
            }
            pub fn filePins(self: *Store, a: std.mem.Allocator) ![]FilePin {
                self.mutex.lock();
                defer self.mutex.unlock();
                for (self.slots) |slot| if (slot.pin == null) return failure(error.IncompleteNativeCapacityFiles);
                const pins = try a.alloc(FilePin, self.slots.len);
                for (self.slots, pins) |slot, *pin| pin.* = slot.pin.?;
                return pins;
            }
            pub fn requireConsumed(self: *Store) !void {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (self.mode != .reader) return failure(error.InvalidNativeCapacityStoreMode);
                for (self.slots) |slot| if (!slot.consumed) return failure(error.IncompleteNativeCapacityConsumption);
            }
            pub fn sink(self: *Store) Sink {
                return if (fused) .{ .context = self, .put_fused = save } else .{ .context = self, .put = save };
            }
            pub fn loader(self: *Store) Loader {
                return .{ .context = self, .take = load };
            }
        };
        fn save(context: *anyopaque, index: u32, proof: *Payload) anyerror!void {
            return (@as(*Store, @ptrCast(@alignCast(context)))).put(index, proof);
        }
        fn load(context: *anyopaque, index: u32) anyerror!Payload {
            return (@as(*Store, @ptrCast(@alignCast(context)))).take(index);
        }
        fn requireRoots(proof: *const Payload, expected: [2][32]u8) !void {
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if ((if (fused) roots.len != 4 and roots.len != 5 else roots.len != 4) or !std.meta.eql(roots[0..2].*, expected)) return failure(error.UntrustedNativeCapacityStoreRoots);
        }
        pub fn fileName(buffer: []u8, index: u32) ![]const u8 {
            return std.fmt.bufPrint(buffer, if (fused) "block-v5-native-capacity-fused-{d}.proof" else "block-v5-native-capacity-{d}.proof", .{index});
        }
        const MANIFEST = if (fused) "block-v5-native-capacity-fused.files" else "block-v5-native-capacity.files";
        const MAGIC = if (fused) "B5CFFLS1" else "B5CTFLS1";
        const ROW: usize = 44;
        pub const OwnedPins = struct {
            a: std.mem.Allocator,
            pins: []FilePin,
            pub fn deinit(self: *OwnedPins) void {
                self.a.free(self.pins);
                self.* = undefined;
            }
        };
        fn validatePins(pins: []const FilePin, limits: Limits) !void {
            try limits.validate();
            if (pins.len == 0 or pins.len > limits.max_files or try std.math.mul(usize, pins.len, @sizeOf(FilePin)) > limits.max_metadata_bytes)
                return failure(error.NativeCapacityStoreMetadataLimit);
            var total: u64 = 0;
            for (pins, 0..) |pin, i| {
                if (i != 0 and pins[i - 1].index >= pin.index) return failure(error.NoncanonicalNativeCapacityFiles);
                if (pin.byte_len == 0 or pin.byte_len > limits.max_file_bytes or std.mem.allEqual(u8, &pin.sha256, 0)) return failure(error.UntrustedNativeCapacityFilePin);
                total = try std.math.add(u64, total, pin.byte_len);
                if (total > limits.max_total_bytes) return failure(error.NativeCapacityStoreTotalLimit);
            }
        }
        pub fn writePins(a: std.mem.Allocator, dir: std.fs.Dir, pins: []const FilePin, limits: Limits) ![32]u8 {
            try validatePins(pins, limits);
            const size = try std.math.add(usize, 12, try std.math.mul(usize, pins.len, ROW));
            if (size > limits.max_manifest_bytes) return failure(error.NativeCapacityManifestLimit);
            const raw = try a.alloc(u8, size);
            defer a.free(raw);
            @memcpy(raw[0..8], MAGIC);
            std.mem.writeInt(u32, raw[8..12], std.math.cast(u32, pins.len) orelse return error.Overflow, .little);
            for (pins, 0..) |pin, i| {
                const row = raw[12 + i * ROW ..][0..ROW];
                std.mem.writeInt(u32, row[0..4], pin.index, .little);
                std.mem.writeInt(u64, row[4..12], pin.byte_len, .little);
                @memcpy(row[12..44], &pin.sha256);
            }
            try Files.publish(dir, MANIFEST, raw);
            return Files.hash(raw);
        }
        pub fn readPins(a: std.mem.Allocator, dir: std.fs.Dir, expected_hash: [32]u8, limits: Limits) !OwnedPins {
            try limits.validate();
            var file = try dir.openFile(MANIFEST, .{});
            defer file.close();
            const size = std.math.cast(usize, (try file.stat()).size) orelse return error.Overflow;
            if (size < 12 or size > limits.max_manifest_bytes) return failure(error.NativeCapacityManifestLimit);
            var header: [12]u8 = undefined;
            if (try file.readAll(&header) != header.len or !std.mem.eql(u8, header[0..8], MAGIC)) return failure(error.InvalidNativeCapacityManifest);
            const count = std.mem.readInt(u32, header[8..12], .little);
            if (count == 0 or count > limits.max_files or try std.math.mul(usize, count, @sizeOf(FilePin)) > limits.max_metadata_bytes or
                size != try std.math.add(usize, 12, try std.math.mul(usize, count, ROW))) return failure(error.NativeCapacityManifestLimit);
            const pins = try a.alloc(FilePin, count);
            errdefer a.free(pins);
            var digest = std.crypto.hash.sha2.Sha256.init(.{});
            digest.update(&header);
            for (pins) |*pin| {
                var row: [ROW]u8 = undefined;
                if (try file.readAll(&row) != row.len) return error.TamperedV5BundleFileLength;
                digest.update(&row);
                pin.* = .{ .index = std.mem.readInt(u32, row[0..4], .little), .byte_len = std.mem.readInt(u64, row[4..12], .little), .sha256 = row[12..44].* };
            }
            var trailing: [1]u8 = undefined;
            if (try file.read(&trailing) != 0 or !std.meta.eql(digest.finalResult(), expected_hash)) return error.TamperedV5BundleFileHash;
            try validatePins(pins, limits);
            return .{ .a = a, .pins = pins };
        }

        fn failure(comptime original: anyerror) anyerror {
            if (!fused) return original;
            return switch (original) {
                error.DuplicateNativeCapacityArtifact => error.DuplicateCapacityFusedArtifact,
                error.IncompleteNativeCapacityConsumption => error.IncompleteCapacityFusedConsumption,
                error.IncompleteNativeCapacityFiles => error.IncompleteCapacityFusedFiles,
                error.InvalidNativeCapacityManifest => error.InvalidCapacityFusedManifest,
                error.InvalidNativeCapacityStoreLimits => error.InvalidCapacityFusedStoreLimits,
                error.InvalidNativeCapacityStoreMode => error.InvalidCapacityFusedStoreMode,
                error.NativeCapacityManifestLimit => error.CapacityFusedManifestLimit,
                error.NativeCapacityStoreMetadataLimit => error.CapacityFusedStoreMetadataLimit,
                error.NativeCapacityStoreTotalLimit => error.CapacityFusedStoreTotalLimit,
                error.NoncanonicalNativeCapacityFiles => error.NoncanonicalCapacityFusedFiles,
                error.NoncanonicalNativeCapacityStorePolicy => error.NoncanonicalCapacityFusedStorePolicy,
                error.RepeatedNativeCapacityLoad => error.RepeatedCapacityFusedLoad,
                error.UnadmittedNativeCapacityStoreIndex => error.UnadmittedCapacityFusedStoreIndex,
                error.UntrustedNativeCapacityFileIndex => error.UntrustedCapacityFusedFileIndex,
                error.UntrustedNativeCapacityFilePin => error.UntrustedCapacityFusedFilePin,
                error.UntrustedNativeCapacityStorePolicy => error.UntrustedCapacityFusedStorePolicy,
                error.UntrustedNativeCapacityStoreRoots => error.UntrustedCapacityFusedStoreRoots,
                error.UntrustedNativeCapacityStoreSecurity => error.UntrustedCapacityFusedStoreSecurity,
                else => @compileError("Unmapped capacity store family error"),
            };
        }
    };
}

//! Durable bounded all-family transport. Independent policies choose codecs;
//! file manifests contain only hashes/lengths, never accepted proof receipts.
//! Default loaders use this Store's allocator. takeWithAllocator separates
//! admitted metadata from bounded fresh-receiver proof ownership. Writer
//! allocator must equal producer allocator.
pub fn ForCapacity(comptime capacity: bool) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const codec = @import("block_v5_cpu_stark_codec_v1.zig");
        const native_codec = if (capacity) @import("block_v5_native_capacity_codec_v1.zig") else @import("block_v5_native_codec_v3.zig");
        const fused_codec = @import("block_v5_native_capacity_fused_codec_v1.zig");
        const Stack = @import("block_v5_native_receiver_stack_v1.zig").ForCapacity(capacity);
        const Files = @import("block_v5_artifact_files_v1.zig");
        const caller_codec = @import("block_v5_precompile_codec_v1.zig");
        const provider_codec = @import("block_v5_native_lookup_codec_v1.zig");
        const CallerStatement = @import("blake3_ethereum_sha_profile.zig").admission.Statement;
        const Programs = Stack.Programs;
        const Tables = @import("block_v5_native_table_join_impl_v1.zig").ForStack(Stack);
        const Memory = @import("block_v5_word_memory_join_impl_v1.zig").ForStack(Stack);
        const Packed = @import("block_v5_word_memory_receiver_v1.zig");
        pub const Family = codec.Family;
        pub fn ProofFor(comptime family: Family) type {
            if (capacity and family == .native) return Stack.Native.Proof;
            if (capacity and family == .native_fused) return Stack.Fused.Proof;
            return codec.ProofFor(family);
        }
        pub const Geometry = codec.Geometry;
        pub const Limits = struct {
            max_files: usize,
            max_file_bytes: usize,
            max_total_bytes: u64,
            max_metadata_bytes: usize,
            max_manifest_bytes: usize,
            max_claims: u32,
            max_proof_bytes: usize,
            pub fn validate(self: Limits) !void {
                if (self.max_files == 0 or self.max_file_bytes == 0 or self.max_total_bytes == 0 or
                    self.max_metadata_bytes == 0 or self.max_manifest_bytes == 0 or self.max_claims == 0 or
                    self.max_proof_bytes == 0 or self.max_proof_bytes > self.max_file_bytes)
                    return error.InvalidV5BundleStoreLimits;
            }
            fn codecLimits(self: Limits) codec.Limits {
                return .{ .artifact_bytes = self.max_file_bytes, .proof_bytes = self.max_proof_bytes, .max_claims = self.max_claims };
            }
        };
        pub const FilePin = struct { family: Family, index: u32, byte_len: u64, sha256: [32]u8 };
        pub const Policy = struct {
            execution_recipe: @import("block_v5_execution_recipe_v1.zig").Recipe = @import("block_v5_execution_recipe_v1.zig").canonical,
            expected: codec.Expected,
            native: ?native_codec.Expected = null,
            capacity_fused: ?fused_codec.Expected = null,
            caller_statement: ?*const CallerStatement = null,
            caller_key_id: [32]u8 = @splat(0),
            caller_instance_id: [32]u8 = @splat(0),
            readonly_native: ?@import("block_v5_readonly_input_proof_v1.zig").Pin = null,
            readonly_caller: ?@import("block_v5_caller_readonly_receiver_v1.zig").Pin = null,
            readonly_seal: [32]u8 = @splat(0),
            lane_pin: ?@import("block_v5_ram_lanes_proof_v1.zig").Pin = null,
            lane_seal_digest: [32]u8 = @splat(0),
            provider_plan: ?@import("block_v5_native_lookup_plan_v1.zig").Plan = null,
            pub fn validate(self: Policy, a: std.mem.Allocator, config: core.pcs.PcsConfig, limits: Limits) !void {
                try self.execution_recipe.requireCompiled();
                if (capacity and (self.expected.family == .request or self.expected.family == .native_projection or self.expected.family == .opcode_memory)) return error.UnsupportedCapacitySeparateProjection;
                try self.expected.validate();
                if (!std.meta.eql(self.expected.config, config) or try self.expected.totalClaims() > limits.max_claims)
                    return error.UntrustedV5BundleSecurity;
                if (self.expected.family == .native_readonly) {
                    const pin = self.readonly_native orelse return error.MissingV5ReadonlyTransportPolicy;
                    const canonical = try @import("block_v5_readonly_input_transport_policy_v1.zig").native(pin, self.expected.index, self.expected.readonly_interval_count, self.readonly_seal);
                    if (!std.meta.eql(canonical, self.expected) or self.readonly_caller != null) return error.UntrustedV5ReadonlyTransportPolicy;
                } else if (self.readonly_native != null) return error.UntrustedV5ReadonlyTransportPolicy;
                if (self.expected.family == .caller_readonly) {
                    const pin = self.readonly_caller orelse return error.MissingV5ReadonlyTransportPolicy;
                    const canonical = try @import("block_v5_readonly_input_transport_policy_v1.zig").callerAt(a, self.expected.index, pin, config, self.readonly_seal);
                    if (!std.meta.eql(canonical, self.expected)) return error.UntrustedV5ReadonlyTransportPolicy;
                    try self.execution_recipe.requireCaller(pin.statement, pin.total_steps);
                } else if (self.readonly_caller != null) return error.UntrustedV5ReadonlyTransportPolicy;
                if (self.expected.family == .native) {
                    const native = self.native orelse return error.MissingV5BundleNativePolicy;
                    if (!std.meta.eql(native.config, config)) return error.UntrustedV5BundleSecurity;
                    if (capacity) {
                        try native.validate();
                        const fixed = try Stack.Template.columnLogs(a, native.shape, native.external_retirements, .fixed);
                        defer a.free(fixed);
                        const main = try Stack.Template.columnLogs(a, native.shape, native.external_retirements, .main);
                        defer a.free(main);
                        const interaction = try Stack.Template.columnLogs(a, native.shape, native.external_retirements, .interaction);
                        defer a.free(interaction);
                        const composition = core.verifier_types.compositionColumnCount(core.verifier_types.COMPOSITION_LOG_SPLIT, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.UntrustedV5BundleSecurity;
                        const columns: [5]u32 = .{ @intCast(fixed.len), @intCast(main.len), @intCast(interaction.len), @intCast(composition), 0 };
                        var claims: usize = 0;
                        for (native.shape.component_descs[0..native.shape.n_components]) |desc| claims += @import("../air/lookups/opcode_entries.zig").batchCount(desc.family);
                        for (native.shape.infra_descs[0..native.shape.n_infra]) |desc| claims += @import("../air/statement.zig").nClaimedSumsForInfra(desc.kind);
                        const log = try native_codec.maximumProofColumnLog(native);
                        if (self.expected.geometry.tree_count != 4 or !std.meta.eql(self.expected.geometry.tree_columns, columns) or
                            self.expected.claim_count != claims or self.expected.root_count != 2 or self.expected.geometry.max_column_log != log or
                            self.expected.geometry.max_merkle_log != log) return error.UntrustedV5CapacityNativePolicy;
                    } else try native.shape.validateBlake3ExecutionWithExternal(native.external_retirements);
                    try self.execution_recipe.requireNative(native.shape);
                } else if (self.native != null) return error.UntrustedV5BundlePolicy;
                if (capacity and self.expected.family == .native_fused) {
                    const fused = self.capacity_fused orelse return error.MissingV5CapacityFusedPolicy;
                    try fused.validate();
                    var inventory = try fused_codec.Inventory.init(a, fused, fusedWireLimits(limits));
                    defer inventory.deinit();
                    const geometry = try fused_codec.geometry(fused, &inventory);
                    if (self.expected.claim_count != inventory.projections.len or self.expected.memory_claim_count != inventory.memory.len or
                        self.expected.geometry.tree_count != geometry.tree_count or !std.meta.eql(self.expected.geometry.tree_columns, geometry.tree_columns) or
                        self.expected.geometry.max_column_log != geometry.max_log or self.expected.geometry.max_merkle_log != geometry.max_merkle_log or
                        self.expected.root_count != @as(u8, if (inventory.memory.len == 0) 2 else 3)) return error.UntrustedV5CapacityFusedPolicy;
                    if (fused.index != self.expected.index or !std.meta.eql(fused.config, config) or
                        !std.meta.eql(fused.native_roots, self.expected.roots[0..2].*) or
                        (self.expected.root_count == 3 and !std.meta.eql(fused.witness_root, self.expected.roots[2])))
                        return error.UntrustedV5CapacityFusedPolicy;
                } else if (self.capacity_fused != null) return error.UntrustedV5CapacityFusedPolicy;
                if (self.expected.family == .caller) {
                    if (self.caller_statement == null or std.mem.allEqual(u8, &self.caller_key_id, 0) or
                        std.mem.allEqual(u8, &self.caller_instance_id, 0)) return error.MissingV5BundleCallerPolicy;
                    try self.execution_recipe.requireCaller(self.caller_statement.?, @import("blake3_ethereum_sha_profile.zig").externalCount(self.caller_statement.?));
                } else if (self.caller_statement != null) return error.UntrustedV5BundlePolicy;
                if (self.expected.family == .ram_lanes) {
                    const pin = self.lane_pin orelse return error.MissingV5RamLanesPolicy;
                    try pin.validate();
                    const spec = @import("block_v5_ram_lanes_component_v1.zig").Spec;
                    const composition = core.verifier_types.compositionColumnCount(spec.EXPANSION_BITS, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.UntrustedV5RamLanesPolicy;
                    const columns: [5]u32 = .{ spec.FIXED_COUNT, spec.MAIN_COUNT, spec.INTERACTION_COUNT, @intCast(composition), 0 };
                    if (self.expected.geometry.tree_count != 4 or !std.meta.eql(self.expected.geometry.tree_columns, columns)) return error.UntrustedV5RamLanesPolicy;
                    if (pin.index != self.expected.index or !std.meta.eql(pin.config, config) or
                        !std.meta.eql(pin.roots, self.expected.roots[0..2].*) or
                        self.expected.root_count != 2 or self.expected.claim_count != 1 or
                        self.expected.geometry.max_column_log != pin.claim.row_log or
                        self.expected.geometry.max_merkle_log != pin.claim.row_log or
                        std.mem.allEqual(u8, &self.lane_seal_digest, 0)) return error.UntrustedV5RamLanesPolicy;
                } else if (self.lane_pin != null or !std.mem.allEqual(u8, &self.lane_seal_digest, 0)) return error.UntrustedV5RamLanesPolicy;
                if (self.expected.family == .native_provider) {
                    try (self.provider_plan orelse return error.MissingV5BundleProviderPolicy).validate();
                } else if (self.provider_plan != null) return error.UntrustedV5BundlePolicy;
            }
        };
        const State = struct { pin: ?FilePin = null, consumed: bool = false };
        pub const Store = struct {
            a: std.mem.Allocator,
            dir: std.fs.Dir,
            /// Borrow immutable independent receiver policy for the entire
            /// Store lifetime, including its admitted canonical index order.
            policies: []const Policy,
            states: []State,
            config: core.pcs.PcsConfig,
            limits: Limits,
            total_bytes: u64 = 0,
            mode: enum { writer, reader },
            mutex: std.Thread.Mutex = .{},

            pub fn initWriter(a: std.mem.Allocator, dir: std.fs.Dir, policies: []const Policy, config: core.pcs.PcsConfig, limits: Limits) !Store {
                try validatePolicies(a, policies, config, limits);
                const states = try a.alloc(State, policies.len);
                @memset(states, .{});
                return .{ .a = a, .dir = dir, .policies = policies, .states = states, .config = config, .limits = limits, .mode = .writer };
            }
            pub fn initReader(a: std.mem.Allocator, dir: std.fs.Dir, policies: []const Policy, files: []const FilePin, config: core.pcs.PcsConfig, limits: Limits) !Store {
                var self = try initWriter(a, dir, policies, config, limits);
                errdefer self.deinit();
                if (files.len != policies.len) return error.IncompleteV5BundleFiles;
                for (files, policies, self.states) |pin, policy, *state| {
                    if (pin.family != policy.expected.family or pin.index != policy.expected.index or pin.byte_len == 0 or
                        pin.byte_len > limits.max_file_bytes or std.mem.allEqual(u8, &pin.sha256, 0)) return error.UntrustedV5BundleFilePin;
                    self.total_bytes = try std.math.add(u64, self.total_bytes, pin.byte_len);
                    if (self.total_bytes > limits.max_total_bytes) return error.V5BundleTotalResourceLimit;
                    state.pin = pin;
                }
                self.mode = .reader;
                return self;
            }
            pub fn deinit(self: *Store) void {
                self.a.free(self.states);
                self.* = undefined;
            }
            fn position(self: *const Store, family: Family, index: u32) !usize {
                // validatePolicies admits a strictly sorted, possibly sparse
                // (family, index) roster once; no per-load roster scan is needed.
                var first: usize = 0;
                var end = self.policies.len;
                while (first < end) {
                    const middle = first + (end - first) / 2;
                    const candidate = self.policies[middle].expected;
                    if (@intFromEnum(candidate.family) < @intFromEnum(family) or
                        (candidate.family == family and candidate.index < index))
                        first = middle + 1
                    else
                        end = middle;
                }
                if (first < self.policies.len) {
                    const candidate = self.policies[first].expected;
                    if (candidate.family == family and candidate.index == index) return first;
                }
                return error.UnadmittedV5BundleIndex;
            }
            /// Success consumes the proof only after checked durable publication.
            /// The caller still owns it on every error path.
            pub fn put(self: *Store, comptime family: Family, index: u32, proof: *ProofFor(family)) !void {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (self.mode != .writer) return error.InvalidV5BundleStoreMode;
                const slot = try self.position(family, index);
                if (self.states[slot].pin != null) return error.DuplicateV5BundleArtifact;
                const raw = try encode(family, self.a, proof, self.policies[slot], self.limits);
                defer self.a.free(raw);
                const total = try std.math.add(u64, self.total_bytes, raw.len);
                if (total > self.limits.max_total_bytes) return error.V5BundleTotalResourceLimit;
                var path_buffer: [96]u8 = undefined;
                const path = try fileName(&path_buffer, family, index);
                if (self.dir.access(path, .{})) |_| return error.ExistingV5BundleArtifact else |err| if (err != error.FileNotFound) return err;
                try Files.publish(self.dir, path, raw);
                self.states[slot].pin = .{ .family = family, .index = index, .byte_len = raw.len, .sha256 = hash(raw) };
                self.total_bytes = total;
                proof.deinit(self.a);
            }
            /// A failed attempt consumes the slot too: callers cannot feed a different
            /// file into the same fresh-verification session after an error.
            pub fn take(self: *Store, comptime family: Family, index: u32) !ProofFor(family) {
                return self.takeWithAllocator(self.a, family, index);
            }
            /// The caller supplies the allocator for file/decode scratch and
            /// the returned proof. Admitted policy/state remains owned by self.a.
            /// A proof must be destroyed with this allocator, including after
            /// the metadata Store has been released.
            pub fn takeWithAllocator(self: *Store, proof_allocator: std.mem.Allocator, comptime family: Family, index: u32) !ProofFor(family) {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (self.mode != .reader) return error.InvalidV5BundleStoreMode;
                const slot = try self.position(family, index);
                if (self.states[slot].consumed) return error.RepeatedV5BundleLoad;
                self.states[slot].consumed = true;
                const pin = self.states[slot].pin orelse return error.MissingV5BundleArtifact;
                const raw = try readPinned(proof_allocator, self.dir, pin, self.limits);
                defer proof_allocator.free(raw);
                return decode(family, proof_allocator, raw, self.policies[slot], self.limits);
            }
            pub fn filePins(self: *Store, a: std.mem.Allocator) ![]FilePin {
                self.mutex.lock();
                defer self.mutex.unlock();
                const files = try a.alloc(FilePin, self.states.len);
                errdefer a.free(files);
                for (self.states, files) |state, *file| file.* = state.pin orelse return error.IncompleteV5BundleFiles;
                return files;
            }
            pub fn requireConsumed(self: *Store) !void {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (self.mode != .reader) return error.InvalidV5BundleStoreMode;
                for (self.states) |state| if (!state.consumed) return error.IncompleteV5BundleConsumption;
            }
            pub fn programLoader(self: *Store) Programs.Loader {
                return programLoaderFor(self);
            }
            pub fn tableLoader(self: *Store) Tables.Loader {
                return tableLoaderFor(self);
            }
            pub fn executionMemoryLoader(self: *Store) Memory.Loader {
                return executionMemoryLoaderFor(self);
            }
            pub fn packedMemoryLoader(self: *Store) @import("block_v5_sorted_memory_v1.zig").Loader {
                return packedMemoryLoaderFor(self);
            }
            /// The returned adapter must stay at a stable address while its
            /// callbacks are live. It borrows this admitted consuming session.
            pub fn withProofAllocator(self: *Store, a: std.mem.Allocator) ProofReader {
                return .{ .store = self, .a = a };
            }
            pub const CapacityExecutionSink = struct {
                context: *anyopaque,
                native: *const fn (*anyopaque, u32, *Stack.Native.Proof) anyerror!void,
                table: *const fn (*anyopaque, *ProofFor(.rom)) anyerror!void,
            };
            pub fn executionSink(self: *Store) (if (capacity) CapacityExecutionSink else @import("block_v5_block_producer_v1.zig").LightweightExecutionSink) {
                if (capacity) return .{ .context = self, .native = save(.native), .table = saveRom };
                return .{ .context = self, .native = save(.native), .request = save(.request), .table = saveRom };
            }
            pub fn fusedSink(self: *Store) (if (capacity) @import("block_v5_native_capacity_fused_stage_v1.zig").Sink else @import("block_v5_native_projection_fused_stage_v2.zig").Sink) {
                return .{ .context = self, .put_fused = save(.native_fused) };
            }
            /// Explicit compatibility publication only; canonical policy omits it.
            pub fn nativeLookupSink(self: *Store) @import("block_v5_native_lookup_stage_v1.zig").Sink {
                return .{ .context = self, .put_projection = save(.native_projection) };
            }
            pub fn providerSink(self: *Store) @import("block_v5_native_lookup_batch_v1.zig").Sink {
                return .{ .context = self, .accept = save(.native_provider) };
            }
            pub fn packedMemorySink(self: *Store) @import("block_v5_word_memory_artifact_v1.zig").Sink {
                return .{ .context = self, .memory = save(.packed_memory), .range = save(.range16) };
            }
            pub fn ramLanesSink(self: *Store) @import("block_v5_ram_lanes_stage_v1.zig").Sink {
                return .{ .context = self, .memory = save(.ram_lanes), .range = save(.range16) };
            }
            /// SinkT is the production caller-pipeline Sink; generic construction
            /// avoids an import cycle while retaining all callback proof types.
            pub fn callerSink(self: *Store, comptime SinkT: type) SinkT {
                var sink: SinkT = .{ .context = self, .put_caller = save(.caller), .put_fused = save(.caller_fused) };
                if (@hasField(SinkT, "put_readonly_fused")) sink.put_readonly_fused = save(.caller_readonly);
                return sink;
            }
            pub fn nativeReadonlySink(self: *Store) @import("block_v5_native_capacity_readonly_stage_v1.zig").Sink {
                return .{ .context = self, .put_native_readonly = save(.native_readonly) };
            }
            pub fn callback(self: *Store, comptime family: Family) struct { context: *anyopaque, put: *const fn (*anyopaque, u32, *ProofFor(family)) anyerror!void } {
                return .{ .context = self, .put = save(family) };
            }
        };
        pub const ProofReader = struct {
            store: *Store,
            a: std.mem.Allocator,
            pub fn take(self: *ProofReader, comptime family: Family, index: u32) !ProofFor(family) {
                return self.store.takeWithAllocator(self.a, family, index);
            }
            pub fn programLoader(self: *ProofReader) Programs.Loader {
                return programLoaderFor(self);
            }
            pub fn tableLoader(self: *ProofReader) Tables.Loader {
                return tableLoaderFor(self);
            }
            pub fn executionMemoryLoader(self: *ProofReader) Memory.Loader {
                return executionMemoryLoaderFor(self);
            }
            pub fn packedMemoryLoader(self: *ProofReader) @import("block_v5_sorted_memory_v1.zig").Loader {
                return packedMemoryLoaderFor(self);
            }
        };
        fn programLoaderFor(reader: anytype) Programs.Loader {
            const T = std.meta.Child(@TypeOf(reader));
            return .{ .context = reader, .take_native = load(T, .native), .take_fused = load(T, .native_fused), .take_table = loadRom(T), .take_precompile = load(T, .caller), .take_caller_fused = load(T, .caller_fused), .take_caller_readonly = load(T, .caller_readonly) };
        }
        fn tableLoaderFor(reader: anytype) Tables.Loader {
            return .{ .context = reader, .take_provider = load(std.meta.Child(@TypeOf(reader)), .native_provider) };
        }
        fn executionMemoryLoaderFor(reader: anytype) Memory.Loader {
            const T = std.meta.Child(@TypeOf(reader));
            if (capacity) return .{ .context = reader, .take_native_readonly = loadNativeReadonly(T) };
            return .{ .context = reader, .take_opcode = load(T, .opcode_memory), .take_native_readonly = loadNativeReadonly(T) };
        }
        fn loadNativeReadonly(comptime T: type) *const fn (*anyopaque, std.mem.Allocator, u32) anyerror!@import("block_v5_readonly_input_proof_v1.zig").Proof {
            return struct {
                fn take(raw: *anyopaque, a: std.mem.Allocator, index: u32) !@import("block_v5_readonly_input_proof_v1.zig").Proof {
                    const reader: *T = @ptrCast(@alignCast(raw));
                    const store = if (T == Store) reader else reader.store;
                    return store.takeWithAllocator(a, .native_readonly, index);
                }
            }.take;
        }
        fn packedMemoryLoaderFor(reader: anytype) @import("block_v5_sorted_memory_v1.zig").Loader {
            const T = std.meta.Child(@TypeOf(reader));
            return .{ .context = reader, .take_memory = load(T, .packed_memory), .take_lanes = load(T, .ram_lanes), .take_range = load(T, .range16) };
        }
        fn save(comptime family: Family) *const fn (*anyopaque, u32, *ProofFor(family)) anyerror!void {
            return struct {
                fn callback(raw: *anyopaque, index: u32, proof: *ProofFor(family)) anyerror!void {
                    const self: *Store = @ptrCast(@alignCast(raw));
                    try self.put(family, index, proof);
                }
            }.callback;
        }
        fn load(comptime Reader: type, comptime family: Family) *const fn (*anyopaque, u32) anyerror!ProofFor(family) {
            return struct {
                fn callback(raw: *anyopaque, index: u32) anyerror!ProofFor(family) {
                    const self: *Reader = @ptrCast(@alignCast(raw));
                    return self.take(family, index);
                }
            }.callback;
        }
        fn loadRom(comptime Reader: type) *const fn (*anyopaque) anyerror!ProofFor(.rom) {
            return struct {
                fn take(raw: *anyopaque) anyerror!ProofFor(.rom) {
                    return load(Reader, .rom)(raw, 0);
                }
            }.take;
        }
        fn saveRom(raw: *anyopaque, proof: *ProofFor(.rom)) anyerror!void {
            return save(.rom)(raw, 0, proof);
        }
        fn validatePolicies(a: std.mem.Allocator, policies: []const Policy, config: core.pcs.PcsConfig, limits: Limits) !void {
            try limits.validate();
            if (policies.len == 0 or policies.len > limits.max_files or
                try std.math.mul(usize, policies.len, @sizeOf(State) + @sizeOf(FilePin)) > limits.max_metadata_bytes)
                return error.V5BundleMetadataResourceLimit;
            for (policies, 0..) |policy, slot| {
                try policy.validate(a, config, limits);
                if (slot != 0) {
                    const before = policies[slot - 1].expected;
                    if (@intFromEnum(before.family) > @intFromEnum(policy.expected.family) or
                        (before.family == policy.expected.family and before.index >= policy.expected.index))
                        return error.NoncanonicalV5BundlePolicies;
                }
            }
        }
        fn encode(comptime family: Family, a: std.mem.Allocator, proof: *const ProofFor(family), policy: Policy, limits: Limits) ![]u8 {
            const payload = if (family == .caller_state) &proof.projection else proof;
            const roots = payload.stark.commitment_scheme_proof.commitments.items;
            if (!std.meta.eql(payload.stark.commitment_scheme_proof.config, policy.expected.config) or roots.len != policy.expected.geometry.tree_count) return error.UntrustedV5BundleProofRoots;
            for (policy.expected.roots[0..policy.expected.root_count], roots[0..policy.expected.root_count]) |pinned, actual|
                if (!std.meta.eql(pinned, actual)) return error.UntrustedV5BundleProofRoots;
            if (family == .native) return native_codec.encode(a, proof, policy.native.?, nativeWireLimits(limits));
            if (capacity and family == .native_fused) return fused_codec.encode(a, proof, policy.capacity_fused.?, fusedWireLimits(limits));
            if (family == .caller) {
                if (!std.meta.eql(proof.key_id, policy.caller_key_id) or !std.meta.eql(proof.instance_id, policy.caller_instance_id) or
                    !std.meta.eql(proof.stark.commitment_scheme_proof.config, policy.expected.config)) return error.UntrustedV5BundleCaller;
                return caller_codec.encode(a, proof, policy.caller_statement.?, .{ .artifact_bytes = limits.max_file_bytes, .proof_bytes = limits.max_proof_bytes });
            }
            if (family == .ram_lanes) return @import("block_v5_ram_lanes_artifact_v1.zig").encode(a, proof, .{ .pin = policy.lane_pin.?, .expected_seal_digest = policy.lane_seal_digest }, .{ .artifact_bytes = limits.max_file_bytes, .proof_bytes = limits.max_proof_bytes, .max_row_log = policy.expected.geometry.max_column_log, .max_queries = policy.expected.config.fri_config.n_queries });
            if (family == .native_provider) return provider_codec.encode(a, proof, policy.provider_plan.?, .{ .artifact_bytes = limits.max_file_bytes, .proof_bytes = limits.max_proof_bytes });
            return codec.encode(family, a, proof, policy.expected, limits.codecLimits());
        }
        fn decode(comptime family: Family, a: std.mem.Allocator, raw: []const u8, policy: Policy, limits: Limits) !ProofFor(family) {
            var proof = if (family == .native)
                try native_codec.decode(a, raw, policy.native.?, nativeWireLimits(limits))
            else if (capacity and family == .native_fused)
                try fused_codec.decode(a, raw, policy.capacity_fused.?, fusedWireLimits(limits))
            else if (family == .caller)
                try caller_codec.decode(a, raw, policy.caller_statement.?, policy.expected.config, .{ .artifact_bytes = limits.max_file_bytes, .proof_bytes = limits.max_proof_bytes })
            else if (family == .ram_lanes)
                try @import("block_v5_ram_lanes_artifact_v1.zig").decode(a, raw, .{ .pin = policy.lane_pin.?, .expected_seal_digest = policy.lane_seal_digest }, .{ .artifact_bytes = limits.max_file_bytes, .proof_bytes = limits.max_proof_bytes, .max_row_log = policy.expected.geometry.max_column_log, .max_queries = policy.expected.config.fri_config.n_queries })
            else if (family == .native_provider)
                try provider_codec.decode(a, raw, policy.provider_plan.?, policy.expected.config, .{ .artifact_bytes = limits.max_file_bytes, .proof_bytes = limits.max_proof_bytes })
            else
                return codec.decode(family, a, raw, policy.expected, limits.codecLimits());
            errdefer proof.deinit(a);
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != policy.expected.geometry.tree_count) return error.UntrustedV5BundleProofRoots;
            for (policy.expected.roots[0..policy.expected.root_count], roots[0..policy.expected.root_count]) |pinned, actual|
                if (!std.meta.eql(pinned, actual)) return error.UntrustedV5BundleProofRoots;
            if (family == .caller) {
                if (!std.meta.eql(proof.key_id, policy.caller_key_id) or !std.meta.eql(proof.instance_id, policy.caller_instance_id))
                    return error.UntrustedV5BundleCaller;
            }
            return proof;
        }
        fn nativeWireLimits(limits: Limits) native_codec.Limits {
            if (capacity) return .{ .artifact_bytes = limits.max_file_bytes, .proof_bytes = limits.max_proof_bytes, .max_claims = limits.max_claims, .max_claim_bytes = limits.max_metadata_bytes };
            return .{ .artifact_bytes = limits.max_file_bytes, .proof_bytes = limits.max_proof_bytes };
        }
        fn fusedWireLimits(limits: Limits) fused_codec.Limits {
            return .{ .artifact_bytes = limits.max_file_bytes, .proof_bytes = limits.max_proof_bytes, .max_claims = limits.max_claims, .max_claim_bytes = limits.max_metadata_bytes };
        }
        pub fn fileName(buffer: []u8, family: Family, index: u32) ![]const u8 {
            return std.fmt.bufPrint(buffer, if (capacity) "block-v5-capacity-{s}-{d}.proof" else "block-v5-{s}-{d}.proof", .{ @tagName(family), index });
        }
        pub fn readPinned(a: std.mem.Allocator, dir: std.fs.Dir, pin: FilePin, limits: Limits) ![]u8 {
            try limits.validate();
            if (pin.byte_len == 0 or pin.byte_len > limits.max_file_bytes or pin.byte_len > limits.max_total_bytes)
                return error.V5BundleFileResourceLimit;
            var buffer: [96]u8 = undefined;
            return Files.readPinned(a, dir, try fileName(&buffer, pin.family, pin.index), pin.byte_len, pin.sha256, limits.max_file_bytes);
        }
        pub const hash = Files.hash;

        pub const MANIFEST = if (capacity) "block-v5-capacity-bundle.files" else "block-v5-bundle.files";
        pub const MANIFEST_MAGIC = if (capacity) "B5CFILE1" else "B5FILES1";
        const FILE_PIN_BYTES: usize = 48;
        pub const OwnedFiles = struct {
            a: std.mem.Allocator,
            files: []FilePin,
            sha256: [32]u8,
            pub fn deinit(self: *OwnedFiles) void {
                self.a.free(self.files);
                self.* = undefined;
            }
        };
        /// Fixed-width transport avoids allocating unbounded JSON arrays before count
        /// admission. The returned SHA must be admitted separately by receiver policy.
        pub fn writePins(a: std.mem.Allocator, dir: std.fs.Dir, files: []const FilePin, limits: Limits) ![32]u8 {
            try limits.validate();
            try validateFiles(files, limits);
            const size = try std.math.add(usize, 12, try std.math.mul(usize, files.len, FILE_PIN_BYTES));
            if (size > limits.max_manifest_bytes) return error.V5BundleManifestResourceLimit;
            const raw = try a.alloc(u8, size);
            defer a.free(raw);
            @memcpy(raw[0..8], MANIFEST_MAGIC);
            std.mem.writeInt(u32, raw[8..12], std.math.cast(u32, files.len) orelse return error.Overflow, .little);
            for (files, 0..) |pin, index| {
                const row = raw[12 + index * FILE_PIN_BYTES ..][0..FILE_PIN_BYTES];
                std.mem.writeInt(u32, row[0..4], @intFromEnum(pin.family), .little);
                std.mem.writeInt(u32, row[4..8], pin.index, .little);
                std.mem.writeInt(u64, row[8..16], pin.byte_len, .little);
                @memcpy(row[16..48], &pin.sha256);
            }
            try Files.publish(dir, MANIFEST, raw);
            return hash(raw);
        }
        pub fn readPins(a: std.mem.Allocator, dir: std.fs.Dir, expected_sha256: [32]u8, limits: Limits) !OwnedFiles {
            try limits.validate();
            var file = try dir.openFile(MANIFEST, .{});
            defer file.close();
            const size = std.math.cast(usize, (try file.stat()).size) orelse return error.Overflow;
            if (size < 12 or size > limits.max_manifest_bytes) return error.V5BundleManifestResourceLimit;
            const raw = try a.alloc(u8, size);
            defer a.free(raw);
            if (try file.readAll(raw) != raw.len or !std.meta.eql(hash(raw), expected_sha256)) return error.TamperedV5BundleManifest;
            var trailing: [1]u8 = undefined;
            if (try file.read(&trailing) != 0) return error.TamperedV5BundleManifest;
            if (!std.mem.eql(u8, raw[0..8], MANIFEST_MAGIC)) return error.InvalidV5BundleManifest;
            const count = std.mem.readInt(u32, raw[8..12], .little);
            if (count == 0 or count > limits.max_files or try std.math.mul(usize, count, @sizeOf(FilePin)) > limits.max_metadata_bytes or
                size != try std.math.add(usize, 12, try std.math.mul(usize, count, FILE_PIN_BYTES))) return error.V5BundleManifestResourceLimit;
            const files = try a.alloc(FilePin, count);
            errdefer a.free(files);
            for (files, 0..) |*pin, index| {
                const row = raw[12 + index * FILE_PIN_BYTES ..][0..FILE_PIN_BYTES];
                pin.* = .{ .family = std.meta.intToEnum(Family, std.mem.readInt(u32, row[0..4], .little)) catch return error.InvalidV5BundleManifest, .index = std.mem.readInt(u32, row[4..8], .little), .byte_len = std.mem.readInt(u64, row[8..16], .little), .sha256 = row[16..48].* };
            }
            try validateFiles(files, limits);
            return .{ .a = a, .files = files, .sha256 = expected_sha256 };
        }
        fn validateFiles(files: []const FilePin, limits: Limits) !void {
            if (files.len == 0 or files.len > limits.max_files) return error.V5BundleManifestResourceLimit;
            var total: u64 = 0;
            for (files, 0..) |pin, index| {
                if (pin.byte_len == 0 or pin.byte_len > limits.max_file_bytes or std.mem.allEqual(u8, &pin.sha256, 0))
                    return error.UntrustedV5BundleFilePin;
                total = try std.math.add(u64, total, pin.byte_len);
                if (total > limits.max_total_bytes) return error.V5BundleTotalResourceLimit;
                if (index != 0) {
                    const before = files[index - 1];
                    if (@intFromEnum(before.family) > @intFromEnum(pin.family) or
                        (before.family == pin.family and before.index >= pin.index)) return error.NoncanonicalV5BundleFiles;
                }
            }
        }
    };
}

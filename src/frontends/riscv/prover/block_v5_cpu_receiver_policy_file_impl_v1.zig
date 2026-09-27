//! SHA-pinned independent public receiver policy, never proof authority. The
//! out-of-band digest and public identity are required before typed decoding.
pub fn ForCapacity(comptime capacity: bool) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Global = if (capacity) @import("block_v5_capacity_global_receiver_v1.zig") else @import("block_v5_global_receiver_v1.zig");
        const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
        pub const FILE = if (capacity) "block-v5-capacity-receiver-policy.json" else "block-v5-receiver-policy.json";
        pub const FORMAT = if (capacity) "stwo-zig/block-v5/capacity-receiver-policy" else "stwo-zig/block-v5/receiver-policy";
        pub const VERSION: u32 = if (capacity) 1 else @import("block_v5_execution_recipe_v1.zig").canonical.callerProtocolVersion();
        pub const Limits = struct {
            max_file_bytes: usize,
            max_owned_bytes: usize,
            max_executions: usize,
            max_roster_entries: usize,
            max_program_words: usize,
            max_schedule_wires: usize,
            pub fn validate(self: Limits) !void {
                if (self.max_file_bytes == 0 or self.max_owned_bytes < self.max_file_bytes or self.max_executions == 0 or
                    self.max_roster_entries == 0 or self.max_program_words == 0 or self.max_schedule_wires == 0)
                    return error.InvalidV5ReceiverPolicyLimits;
            }
        };
        pub const Identity = struct {
            execution_recipe: @import("block_v5_execution_recipe_v1.zig").Recipe = @import("block_v5_execution_recipe_v1.zig").canonical,
            job_id: [32]u8,
            source_image_digest: [32]u8,
            program_root: [32]u8,
            initial_rw_root: [32]u8,
            final_rw_root: [32]u8,
            config: core.pcs.PcsConfig,
            fn require(self: Identity, globals: Global.Pins) !void {
                try self.execution_recipe.requireCompiled();
                if (globals.execution_recipe != self.execution_recipe) return error.MixedV5ExecutionRecipe;
                const seal = globals.tables.seal;
                if (!std.meta.eql(self.job_id, seal.job_id) or !std.meta.eql(self.source_image_digest, seal.source_image_digest) or
                    !std.meta.eql(self.program_root, seal.program_root) or !std.meta.eql(self.initial_rw_root, globals.memory.memory.source().initial.initial_rw_root) or
                    !std.meta.eql(self.final_rw_root, seal.expected_final_rw_root) or !std.meta.eql(self.config, seal.config))
                    return error.UntrustedV5ReceiverPolicyIdentity;
            }
        };
        const Wire = struct {
            format: []const u8 = FORMAT,
            version: u32 = VERSION,
            globals: Global.Pins,
            recursion: Global.RecursivePins,
        };
        pub const Owned = struct {
            parent: std.mem.Allocator,
            budget: *Budget,
            parsed: std.json.Parsed(Wire),
            sha256: [32]u8,
            pub fn globals(self: *const Owned) Global.Pins {
                return self.parsed.value.globals;
            }
            pub fn recursion(self: *const Owned) Global.RecursivePins {
                return self.parsed.value.recursion;
            }
            pub fn deinit(self: *Owned) void {
                const parent = self.parent;
                self.parsed.deinit();
                self.budget.destroy();
                parent.destroy(self);
            }
        };
        pub fn requireFormat(format: []const u8, version: u32) !void {
            if (!std.mem.eql(u8, format, FORMAT) or version != VERSION) return error.UnsupportedV5ReceiverPolicy;
        }
        fn require(wire: Wire, limits: Limits) !void {
            try limits.validate();
            try requireFormat(wire.format, wire.version);
            const pins = wire.globals;
            if (pins.tables.register_windows) |plan| if (plan.windows.len > limits.max_executions) return error.V5ReceiverPolicyResourceLimit;
            if (pins.memory.register_windows) |plan| if (plan.windows.len > limits.max_executions) return error.V5ReceiverPolicyResourceLimit;
            if (pins.tables.executions.len == 0 or pins.tables.executions.len > limits.max_executions or
                pins.tables.roster.len > limits.max_roster_entries or pins.memory.memory.firstRound().len > limits.max_roster_entries or
                pins.program.leaves.len > limits.max_program_words or pins.program.multiplicities.len > limits.max_program_words or
                pins.tables.catalog.records.len > limits.max_executions or pins.memory.catalog.records.len > limits.max_executions or
                pins.memory.executions.len > limits.max_executions or pins.tables.extensions.len > limits.max_executions or
                pins.memory.extensions.len > limits.max_executions or pins.tables.providers.len > limits.max_roster_entries or
                pins.memory.memory.instanceCount() > limits.max_roster_entries or pins.memory.memory.rangeRoots().len > limits.max_roster_entries or
                wire.recursion.leaves.len > limits.max_executions or wire.recursion.parents.len > limits.max_executions)
                return error.V5ReceiverPolicyResourceLimit;
            var schedule_count: usize = wire.recursion.outer.schedule.len;
            for (wire.recursion.leaves) |leaf| schedule_count = try std.math.add(usize, schedule_count, leaf.schedule.len);
            for (wire.recursion.parents) |parent| schedule_count = try std.math.add(usize, schedule_count, parent.schedule.len);
            if (schedule_count > limits.max_schedule_wires) return error.V5ReceiverPolicyResourceLimit;
            try @import("block_v5_cpu_bundle_policy_v1.zig").ForCapacity(capacity).validateStructure(pins);
            _ = try pins.validate();
            try wire.recursion.validate(pins.tables.seal.config, pins.tables.executions.len);
        }
        pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, globals: Global.Pins, recursion: Global.RecursivePins, limits: Limits) ![32]u8 {
            const wire = Wire{ .globals = globals, .recursion = recursion };
            try require(wire, limits);
            var counter = @import("block_v5_cpu_counting_writer_v1.zig").Counting.init(limits.max_file_bytes);
            std.json.Stringify.value(wire, .{}, &counter.writer) catch |err| {
                if (counter.exceeded) return error.V5ReceiverPolicyResourceLimit;
                return err;
            };
            const raw = try a.alloc(u8, counter.count);
            defer a.free(raw);
            var output = std.Io.Writer.fixed(raw);
            try std.json.Stringify.value(wire, .{}, &output);
            const bytes = output.buffered();
            if (bytes.len != counter.count) return error.ChangedV5ReceiverPolicySerialization;
            var file = try dir.createFile(FILE ++ ".part", .{ .exclusive = true });
            var closed = false;
            defer if (!closed) file.close();
            errdefer dir.deleteFile(FILE ++ ".part") catch {};
            if (dir.access(FILE, .{})) |_| return error.ExistingV5ReceiverPolicy else |err| if (err != error.FileNotFound) return err;
            try file.writeAll(bytes);
            try file.sync();
            file.close();
            closed = true;
            try dir.rename(FILE ++ ".part", FILE);
            return hash(bytes);
        }
        pub fn read(a: std.mem.Allocator, dir: std.fs.Dir, expected_sha256: [32]u8, identity: Identity, limits: Limits) !*Owned {
            try limits.validate();
            if (std.mem.allEqual(u8, &expected_sha256, 0)) return error.UntrustedV5ReceiverPolicyHash;
            var file = try dir.openFile(FILE, .{});
            defer file.close();
            const length = std.math.cast(usize, (try file.stat()).size) orelse return error.V5ReceiverPolicyResourceLimit;
            if (length == 0 or length > limits.max_file_bytes) return error.V5ReceiverPolicyResourceLimit;
            const budget = try Budget.create(a, limits.max_owned_bytes);
            errdefer budget.destroy();
            const bounded = budget.allocator();
            const raw = try bounded.alloc(u8, length);
            defer bounded.free(raw);
            if (try file.readAll(raw) != raw.len) return error.TruncatedV5ReceiverPolicy;
            var extra: [1]u8 = undefined;
            if (try file.read(&extra) != 0 or !std.meta.eql(hash(raw), expected_sha256)) return error.UntrustedV5ReceiverPolicyHash;
            var parsed = try std.json.parseFromSlice(Wire, bounded, raw, .{ .allocate = .alloc_always, .ignore_unknown_fields = false, .max_value_len = limits.max_file_bytes });
            errdefer parsed.deinit();
            try identity.require(parsed.value.globals);
            try require(parsed.value, limits);
            const result = try a.create(Owned);
            result.* = .{ .parent = a, .budget = budget, .parsed = parsed, .sha256 = expected_sha256 };
            return result;
        }
        fn hash(raw: []const u8) [32]u8 {
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(raw, &digest, .{});
            return digest;
        }
    };
}

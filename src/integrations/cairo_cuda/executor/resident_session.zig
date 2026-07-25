//! Resident storage bridge for one authenticated Cairo CUDA proof.
//!
//! Request-local slots retain the lifetime aliasing computed by
//! `resident_plan`. Process-cache slots also retain a standalone plan for
//! process-lifetime materialization. `combined_arena` is the sole physical
//! layout authority for kernels which address both storage classes from one
//! base pointer. Routing is driven only by the authenticated slot inventory.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const arena = @import("../../../backends/cuda/runtime/arena.zig");
const common = @import("../../../backends/cuda/runtime/stages/common.zig");
const telemetry = @import("../../../backends/cuda/runtime/telemetry.zig");
const resident_plan = @import("resident_plan.zig");
const trace_schedule = @import("trace_schedule.zig");

pub const production_ready = false;

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    process_requirements: []arena.Requirement,
    process_arena: arena.Plan,
    combined_arena: arena.Plan,
    resident_identity: proof_ir.Digest,
    trace_schedule_identity: proof_ir.Digest,
    identity: proof_ir.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        plan: resident_plan.Plan,
        schedule: trace_schedule.Schedule,
    ) !Prepared {
        if (std.mem.allEqual(u8, &plan.identity, 0) or
            std.mem.allEqual(u8, &schedule.identity, 0) or
            schedule.entries.len != trace_schedule.expected_entry_count or
            schedule.launch_order.len != trace_schedule.expected_launch_count)
        {
            return error.InvalidResidentSession;
        }
        const requirements = try processRequirements(allocator, plan.slots);
        errdefer allocator.free(requirements);
        var process_arena = try arena.Plan.init(allocator, requirements);
        errdefer process_arena.deinit(allocator);
        var combined_arena = try combinedArenaPlan(
            allocator,
            plan.requirements,
            requirements,
        );
        errdefer combined_arena.deinit(allocator);
        return .{
            .allocator = allocator,
            .process_requirements = requirements,
            .process_arena = process_arena,
            .combined_arena = combined_arena,
            .resident_identity = plan.identity,
            .trace_schedule_identity = schedule.identity,
            .identity = sessionIdentity(
                plan.identity,
                schedule.identity,
                requirements,
            ),
        };
    }

    pub fn deinit(self: *Prepared) void {
        self.combined_arena.deinit(self.allocator);
        self.process_arena.deinit(self.allocator);
        self.allocator.free(self.process_requirements);
        self.* = undefined;
    }
};

fn combinedArenaPlan(
    allocator: std.mem.Allocator,
    request_requirements: []const arena.Requirement,
    process_requirements: []const arena.Requirement,
) !arena.Plan {
    const count = std.math.add(
        usize,
        request_requirements.len,
        process_requirements.len,
    ) catch return error.SizeOverflow;
    const requirements = try allocator.alloc(arena.Requirement, count);
    defer allocator.free(requirements);
    @memcpy(
        requirements[0..request_requirements.len],
        request_requirements,
    );
    @memcpy(
        requirements[request_requirements.len..],
        process_requirements,
    );
    return arena.Plan.init(allocator, requirements);
}

pub fn ProviderFor(
    comptime RequestProvider: type,
    comptime ProcessProvider: type,
) type {
    return struct {
        const Self = @This();

        plan: *const resident_plan.Plan,
        prepared: *const Prepared,
        request: RequestProvider,
        process: ProcessProvider,

        pub fn init(
            plan: *const resident_plan.Plan,
            prepared: *const Prepared,
            request: RequestProvider,
            process: ProcessProvider,
        ) !Self {
            if (!std.mem.eql(
                u8,
                &plan.identity,
                &prepared.resident_identity,
            ) or std.mem.allEqual(u8, &prepared.identity, 0)) {
                return error.ResidentPlanIdentityMismatch;
            }
            return .{
                .plan = plan,
                .prepared = prepared,
                .request = request,
                .process = process,
            };
        }

        pub fn slot(
            self: Self,
            id: arena.SlotId,
        ) !common.Words {
            const descriptor = findSlot(self.plan.slots, id) orelse {
                std.debug.print(
                    "cairo-cuda unknown resident slot id={} slots={}\n",
                    .{ id, self.plan.slots.len },
                );
                return error.ArenaSlotMissing;
            };
            const result = switch (descriptor.storage) {
                .request_local => self.request.slot(id) catch |err| {
                    std.debug.print(
                        "cairo-cuda missing request slot id={} kind={s} ordinal={}\n",
                        .{
                            id,
                            @tagName(descriptor.kind),
                            descriptor.ordinal,
                        },
                    );
                    return err;
                },
                .process_cache => self.process.slot(id) catch |err| {
                    std.debug.print(
                        "cairo-cuda missing process slot id={} kind={s} ordinal={}\n",
                        .{
                            id,
                            @tagName(descriptor.kind),
                            descriptor.ordinal,
                        },
                    );
                    return err;
                },
            };
            if (result.len != descriptor.words)
                return error.InvalidKernelDescriptor;
            return result;
        }
    };
}

fn processRequirements(
    allocator: std.mem.Allocator,
    slots: []const resident_plan.Slot,
) ![]arena.Requirement {
    var count: usize = 0;
    for (slots) |slot| {
        if (slot.storage == .process_cache) count += 1;
    }
    if (count == 0) return error.InvalidResidentSession;

    const output = try allocator.alloc(arena.Requirement, count);
    var cursor: usize = 0;
    for (slots) |slot| {
        if (slot.storage != .process_cache) continue;
        output[cursor] = .{
            .id = slot.id,
            .words = slot.words,
            .alignment_words = slot.alignment_words,
            // Process-cache values survive request boundaries. They cannot
            // reuse storage merely because their in-request use intervals do
            // not overlap.
            .live_from = .ingress,
            .live_through = .proof_assembly,
        };
        cursor += 1;
    }
    return output;
}

fn findSlot(
    slots: []const resident_plan.Slot,
    id: arena.SlotId,
) ?resident_plan.Slot {
    for (slots) |slot| {
        if (slot.id == id) return slot;
    }
    return null;
}

fn sessionIdentity(
    resident_identity: proof_ir.Digest,
    schedule_identity: proof_ir.Digest,
    requirements: []const arena.Requirement,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/resident-session/v1\x00");
    hash.update(&resident_identity);
    hash.update(&schedule_identity);
    for (requirements) |requirement| {
        hashInt(&hash, u32, requirement.id);
        hashInt(&hash, u64, requirement.words);
        hashInt(&hash, u64, requirement.alignment_words);
        hashInt(&hash, u8, @intFromEnum(requirement.live_from));
        hashInt(&hash, u8, @intFromEnum(requirement.live_through));
    }
    return hash.finalResult();
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime F: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(F)]u8 = undefined;
    std.mem.writeInt(F, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

test "routed provider preserves the request and process ownership split" {
    const Fake = struct {
        expected: arena.SlotId,
        words: common.Words,

        pub fn slot(self: @This(), id: arena.SlotId) !common.Words {
            if (id != self.expected) return error.WrongProvider;
            return self.words;
        }
    };
    var plan = resident_plan.Plan{
        .slots = undefined,
        .requirements = undefined,
        .request_arena = undefined,
        .terminal_bundle = undefined,
        .program_identity = undefined,
        .protocol_identity = undefined,
        .ingress_identity = undefined,
        .quotient_geometry = undefined,
        .identity = [_]u8{7} ** 32,
        .summary = undefined,
    };
    const slots = [_]resident_plan.Slot{
        .{
            .id = 3,
            .kind = .trace_coefficients,
            .ordinal = 1,
            .words = 8,
            .alignment_words = 1,
            .live_from = .trace_generation,
            .live_through = .oods,
            .storage = .request_local,
            .immutable = false,
            .identity = [_]u8{1} ** 32,
        },
        .{
            .id = 9,
            .kind = .twiddles_forward,
            .ordinal = 0,
            .words = 4,
            .alignment_words = 1,
            .live_from = .ingress,
            .live_through = .fri_commit,
            .storage = .process_cache,
            .immutable = true,
            .identity = [_]u8{2} ** 32,
        },
    };
    plan.slots = @constCast(&slots);
    const prepared = Prepared{
        .allocator = std.testing.allocator,
        .process_requirements = undefined,
        .process_arena = undefined,
        .combined_arena = undefined,
        .resident_identity = plan.identity,
        .trace_schedule_identity = [_]u8{8} ** 32,
        .identity = [_]u8{9} ** 32,
    };
    const Provider = ProviderFor(Fake, Fake);
    const provider = try Provider.init(
        &plan,
        &prepared,
        .{
            .expected = 3,
            .words = .{ .address = 0x1000, .len = 8, .owner = 1 },
        },
        .{
            .expected = 9,
            .words = .{ .address = 0x2000, .len = 4, .owner = 2 },
        },
    );
    try std.testing.expectEqual(@as(usize, 0x1000), (try provider.slot(3)).address);
    try std.testing.expectEqual(@as(usize, 0x2000), (try provider.slot(9)).address);
    try std.testing.expectError(error.ArenaSlotMissing, provider.slot(10));
}

test "combined arena places request and process slots without aliasing" {
    const request_requirements = [_]arena.Requirement{.{
        .id = 3,
        .words = 64,
        .alignment_words = 16,
        .live_from = .trace_generation,
        .live_through = .oods,
    }};
    const process_requirements = [_]arena.Requirement{.{
        .id = 9,
        .words = 32,
        .alignment_words = 16,
        .live_from = .ingress,
        .live_through = .proof_assembly,
    }};
    var combined = try combinedArenaPlan(
        std.testing.allocator,
        &request_requirements,
        &process_requirements,
    );
    defer combined.deinit(std.testing.allocator);

    const request = try combined.placement(3);
    const process = try combined.placement(9);
    try std.testing.expectEqual(@as(usize, 2), combined.placements.len);
    try std.testing.expect(
        try request.endWords() <= process.offset_words or
            try process.endWords() <= request.offset_words,
    );
}

test "process cache slots never alias across request-stage lifetimes" {
    const slots = [_]resident_plan.Slot{
        .{
            .id = 1,
            .kind = .twiddles_forward,
            .ordinal = 0,
            .words = 64,
            .alignment_words = 16,
            .live_from = .ingress,
            .live_through = .trace_commit,
            .storage = .process_cache,
            .immutable = true,
            .identity = [_]u8{1} ** 32,
        },
        .{
            .id = 2,
            .kind = .constraint_denominators,
            .ordinal = 0,
            .words = 64,
            .alignment_words = 16,
            .live_from = .constraint_evaluation,
            .live_through = .quotient,
            .storage = .process_cache,
            .immutable = true,
            .identity = [_]u8{2} ** 32,
        },
    };
    const requirements = try processRequirements(
        std.testing.allocator,
        &slots,
    );
    defer std.testing.allocator.free(requirements);
    try std.testing.expectEqual(@as(usize, 2), requirements.len);
    for (requirements) |requirement| {
        try std.testing.expectEqual(
            telemetry.Stage.ingress,
            requirement.live_from,
        );
        try std.testing.expectEqual(
            telemetry.Stage.proof_assembly,
            requirement.live_through,
        );
    }
    var placed = try arena.Plan.init(std.testing.allocator, requirements);
    defer placed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 128), placed.total_words);
}

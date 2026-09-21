//! Explicit initial-segment job admission. The retained source is opened once
//! against an independent materialization pin; only a private value snapshot
//! survives. This is a circuit/source admission, not a proof receipt.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const retained_mod = @import("ethereum_incremental_capture_retained_authority_v4.zig");
const span = frontend.recursion.span_statement;
const claim = frontend.recursion.vm_public_claim;
pub const VERSION: u16 = 1;
pub const INPUT_CAPACITY: u32 = 675173;
pub const OUTPUT_CAPACITY: u32 = 12;
pub const InitialInputAdmissionV1 = opaque {
    const Self = @This();
    pub fn open(allocator: std.mem.Allocator, materialization_path: []const u8, expected_sha256: [32]u8, shape: claim.Shape) !*Self {
        if (!std.meta.eql(shape, try claim.Shape.init(INPUT_CAPACITY, OUTPUT_CAPACITY))) return error.InvalidEthereumInitialInputAdmission;
        var retained = try retained_mod.RetainedAuthorityV4.openWithCampaignGeometryV1(allocator, materialization_path, .authenticated_v1);
        defer retained.deinit();
        if (!std.meta.eql(expected_sha256, retained.materialization_identity.sha256)) return error.EthereumBundleMaterializationIdentityMismatch;
        // Input words use the shared canonical byte packing. Output capacity
        // is explicitly admitted; it is never guessed from output alignment.
        if (try std.math.divCeil(usize, retained.input_bytes.len, 4) != shape.max_input_words or retained.sources.len < 2) return error.InvalidEthereumInitialInputAdmission;
        const first = &retained.sources[0].value.metadata;
        try retained.validateLeafMetadata(first);
        if (first.segment_index != 0 or first.global_cycle_start != 0) return error.InvalidEthereumInitialInputAdmission;
        const statement = try span.SpanStatement.fromCanonicalWords(&first.base_statement_words);
        const owned = try allocator.create(Storage);
        owned.* = .{ .allocator = allocator, .shape = shape, .job = statement.job, .materialization_sha256 = expected_sha256, .input_sha256 = retained.input_identity.sha256, .output_sha256 = retained.output_identity.sha256, .elf_sha256 = retained.elf_identity.sha256, .input_byte_count = retained.input_bytes.len, .identity = undefined };
        owned.identity = identity(owned);
        return @ptrCast(owned);
    }
    pub fn clone(self: *const Self, allocator: std.mem.Allocator) !*Self {
        const owned = try allocator.create(Storage);
        owned.* = self.storage().*;
        owned.allocator = allocator;
        return @ptrCast(owned);
    }
    pub fn deinit(self: *Self) void {
        const owned: *Storage = @ptrCast(@alignCast(self));
        owned.allocator.destroy(owned);
    }
    pub fn claimShape(self: *const Self) claim.Shape {
        return self.storage().shape;
    }
    pub fn identitySha256(self: *const Self) [32]u8 {
        return self.storage().identity;
    }
    pub fn validateInput(self: *const Self, input: anytype) !void {
        const owned = self.storage();
        try input.requireGlobalAdmission();
        const fixed = input.fixed_program orelse return error.EthereumInitialProgramOpeningRequired;
        if (!fixed.hasCompletionOpening() or !std.meta.eql(fixed.descriptor().elf_sha256, owned.elf_sha256)) return error.EthereumFixedProgramSourceMismatch;
        const global = try span.SpanStatement.fromCanonicalWords(&input.global_admission.?.metadata.base_statement_words);
        const metadata = &input.global_admission.?.metadata;
        const public = &input.stage101.role_aware_public.value;
        const completion = public.completion orelse return error.InvalidEthereumInitialInputAdmission;
        if (input.stage101.profile.circuitProfile() != .fixed_program_narrow_v1 or metadata.segment_index != 0 or metadata.global_cycle_start != 0 or !std.meta.eql(global.job, owned.job) or completion.kind != .unretired_program_fetch or public.io_entries.input_words.len != owned.shape.max_input_words or public.io_entries.output_words.len != 0 or public.io_entries.input_len != owned.input_byte_count) return error.InvalidEthereumInitialInputAdmission;
    }
    fn storage(self: *const Self) *const Storage {
        return @ptrCast(@alignCast(self));
    }
};
const Storage = struct {
    allocator: std.mem.Allocator,
    shape: claim.Shape,
    job: span.JobContext,
    materialization_sha256: [32]u8,
    input_sha256: [32]u8,
    output_sha256: [32]u8,
    elf_sha256: [32]u8,
    input_byte_count: usize,
    identity: [32]u8,
};
fn identity(value: *const Storage) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/ethereum-initial-input-job-admission/v1\x00");
    inline for (.{ "materialization_sha256", "input_sha256", "output_sha256", "elf_sha256" }) |name| hash.update(&@field(value, name));
    var bytes: [8]u8 = undefined;
    for ([_]u64{ VERSION, value.shape.max_input_words, value.shape.max_output_words, value.input_byte_count }) |word| {
        std.mem.writeInt(u64, &bytes, word, .little);
        hash.update(&bytes);
    }
    return hash.finalResult();
}

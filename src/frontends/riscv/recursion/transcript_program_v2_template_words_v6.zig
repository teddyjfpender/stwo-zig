//! Proof-independent ProgramV2 word schedule for a fixed native verifier shape.
//!
//! The detached verifier must compile this from its admitted plan, PCS profile,
//! canonical wire geometry and component descriptors. The 16 leaf-dependent
//! identity words remain main values and require native NPV2 producers; this
//! schedule does not grant a proof or turn a supplied program into authority.

const std = @import("std");
const core = @import("stwo_core");
const transcript = @import("transcript_program_v2.zig");
const field = @import("transcript_program_v2_field_authority_v1.zig");
const bridge = @import("air/transcript_program_v2_field_bridge_v5.zig");
const schedule = @import("air/verifier_schedule.zig");
const public_data = @import("../air/public_data_v2.zig");
const statement = @import("../air/statement.zig");
const program_contract = @import("transcript_program_v2_contract.zig");
const lookup = @import("../air/lang/lookup_physical_manifest_v2.zig");

const M31 = core.fields.m31.M31;

pub const FORMAT_VERSION: u16 = 1;
pub const KEY_DOMAIN = "stwo-zig/riscv/program-v2-template-words/v6\x00";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const DYNAMIC_FIRST: usize = 10;
pub const DYNAMIC_END: usize = 26;
pub const DYNAMIC_COUNT: usize = DYNAMIC_END - DYNAMIC_FIRST;

pub const Template = struct {
    allocator: std.mem.Allocator,
    words: []M31,
    key_digest: [32]u8,

    /// Recompiles every fixed word from admitted geometry alone. Zero IDs
    /// occupy the two dynamic slots only while constructing the canonical
    /// word order; they are never asserted as proof values.
    pub fn initFromShape(
        allocator: std.mem.Allocator,
        plan: *const schedule.Plan,
        pcs: core.pcs.PcsConfig,
        wire_word_count: u32,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
        authenticated_lookup_v2: bool,
    ) !Template {
        try plan.validate();
        if (wire_word_count == 0 or component_descs.len > statement.MAX_COMPONENTS or
            infra_descs.len > statement.MAX_INFRA_COMPONENTS)
            return error.InvalidProgramTemplateShape;
        var manifest = lookup.Manifest.native();
        var core_statement: statement.RiscVStatement = undefined;
        core_statement.n_components = @intCast(component_descs.len);
        @memcpy(core_statement.component_descs[0..component_descs.len], component_descs);
        core_statement.n_infra = @intCast(infra_descs.len);
        @memcpy(core_statement.infra_descs[0..infra_descs.len], infra_descs);
        const activation = if (authenticated_lookup_v2)
            try lookup.AuthenticatedStatement.init(&core_statement, &manifest)
        else
            null;
        var instructions: std.ArrayList(transcript.Instruction) = .empty;
        defer instructions.deinit(allocator);
        try program_contract.buildInstructions(
            allocator,
            &instructions,
            plan,
            pcs,
            wire_word_count,
            component_descs,
            infra_descs,
            activation,
            if (authenticated_lookup_v2) &manifest else null,
        );
        const program = transcript.Program{
            .allocator = allocator,
            .plan_id = plan.authority_digest,
            .wire_id = .{0} ** 8,
            .statement_authority_id = .{0} ** 8,
            .wire_word_count = wire_word_count,
            .pcs_config = pcs,
            .lookup_activation = activation,
            .instructions = instructions.items,
            .identity = .{0} ** 8,
        };
        const words = try field.canonicalWords(allocator, &program);
        errdefer allocator.free(words);
        if (words.len <= DYNAMIC_END or words.len >= core.fields.m31.Modulus)
            return error.InvalidProgramTemplateWords;
        return .{ .allocator = allocator, .words = words, .key_digest = keyDigest(words) };
    }

    /// Rebuilds the canonical program rather than accepting the child's
    /// program or its identity as a verifier key.
    pub fn init(
        allocator: std.mem.Allocator,
        plan: *const schedule.Plan,
        pcs: core.pcs.PcsConfig,
        data: *const public_data.PublicDataV2,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
        authenticated_lookup_v2: bool,
    ) !Template {
        var program = if (authenticated_lookup_v2)
            try transcript.Program.initAuthenticatedLookupV2(allocator, plan, pcs, data, component_descs, infra_descs)
        else
            try transcript.Program.init(allocator, plan, pcs, data, component_descs, infra_descs);
        defer program.deinit();
        const words = try field.canonicalWords(allocator, &program);
        errdefer allocator.free(words);
        if (words.len <= DYNAMIC_END or words.len >= core.fields.m31.Modulus)
            return error.InvalidProgramTemplateWords;
        // Canonical field ordering: format/schema, plan ID, wire ID,
        // statement-authority ID, then wire length, PCS, lookup and opcodes.
        for (0..8) |i| {
            if (words[10 + i].toU32() != program.wire_id[i] or
                words[18 + i].toU32() != program.statement_authority_id[i])
                return error.InvalidProgramTemplateWords;
        }
        @memset(words[DYNAMIC_FIRST..DYNAMIC_END], M31.zero());
        return .{ .allocator = allocator, .words = words, .key_digest = keyDigest(words) };
    }

    pub fn deinit(self: *Template) void {
        self.allocator.free(self.words);
        self.* = undefined;
    }

    pub fn fixed(index: usize) bool {
        return index < DYNAMIC_FIRST or index >= DYNAMIC_END;
    }

    pub fn preprocessedRow(self: *const Template, index: usize) !bridge.PreprocessedRow {
        if (index >= self.words.len) return error.InvalidProgramTemplateIndex;
        return .{
            M31.one(),
            M31.fromCanonical(bridge.HASH_INPUT_SCOPE),
            M31.fromCanonical(@intCast(index)),
            M31.fromCanonical(@intFromBool(fixed(index))),
            if (fixed(index)) self.words[index] else M31.zero(),
        };
    }

    /// This is a template-shape check, not a native-verifier relation. A
    /// dynamic word may change here only because its NPV2 lookup must bind it
    /// in a future complete wrapper proof.
    pub fn checkCanonicalWords(self: *const Template, candidate: []const M31) !void {
        if (candidate.len != self.words.len) return error.ProgramTemplateShapeMismatch;
        for (candidate, self.words, 0..) |actual, expected, index| {
            if (actual.toU32() >= core.fields.m31.Modulus or
                (fixed(index) and !actual.eql(expected)))
                return error.ProgramTemplateShapeMismatch;
        }
    }
};

fn keyDigest(words: []const M31) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(KEY_DOMAIN);
    updateInt(&hash, u16, FORMAT_VERSION);
    updateInt(&hash, u64, words.len);
    for (words, 0..) |word, index| {
        updateInt(&hash, u64, index);
        updateInt(&hash, u8, @intFromBool(Template.fixed(index)));
        if (Template.fixed(index)) updateInt(&hash, u32, word.toU32());
    }
    return hash.finalResult();
}

fn updateInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

test "ProgramV2 template changes only at its sixteen dynamic identity words" {
    var fixture = try @import("segment_transcript_outer_source_v2_test_support.zig").Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const components = [_]statement.FamilyComponentDesc{.{ .family = .base_alu_imm, .log_size = 4, .n_rows = 2, .n_columns = 10 }};
    const infra = [_]statement.InfraComponentDesc{.{ .kind = .program, .log_size = 4, .n_rows = 2, .n_columns = 2 }};
    const pcs = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 } };
    var template = try Template.init(std.testing.allocator, &fixture.plan, pcs, &fixture.data, &components, &infra, false);
    defer template.deinit();
    var from_shape = try Template.initFromShape(std.testing.allocator, &fixture.plan, pcs, @intCast(fixture.data.words().len), &components, &infra, false);
    defer from_shape.deinit();
    try std.testing.expectEqualSlices(M31, template.words, from_shape.words);
    try std.testing.expectEqualDeep(template.key_digest, from_shape.key_digest);
    try std.testing.expect(template.words.len > DYNAMIC_END);
    var dynamic: usize = 0;
    for (template.words, 0..) |_, index| {
        const row = try template.preprocessedRow(index);
        if (!Template.fixed(index)) {
            dynamic += 1;
            try std.testing.expect(row[4].isZero());
        } else try std.testing.expect(row[4].eql(template.words[index]));
    }
    try std.testing.expectEqual(DYNAMIC_COUNT, dynamic);
    const candidate = try std.testing.allocator.dupe(M31, template.words);
    defer std.testing.allocator.free(candidate);
    candidate[DYNAMIC_FIRST] = candidate[DYNAMIC_FIRST].add(M31.one());
    try template.checkCanonicalWords(candidate);
    candidate[DYNAMIC_END] = candidate[DYNAMIC_END].add(M31.one());
    try std.testing.expectError(error.ProgramTemplateShapeMismatch, template.checkCanonicalWords(candidate));
}

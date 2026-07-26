//! Cross-authority coverage checks for the Sail-authoritative proof surface.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const opcode_manifest = @import("opcode_manifest.zig");
const witness_layout = @import("witness_layout.zig");
const trace = @import("runner/trace.zig");
const component_order = @import("air/component_order.zig");
const lookup_entries = @import("air/lookups/opcode_entries.zig");
const lookup_entry = @import("air/lookups/entry.zig");
const semantic_component = @import("air/semantic_component.zig");
const semantic_eval = @import("air/semantic_eval.zig");

fn selectorColumn(comptime opcode: opcode_manifest.Opcode) []const u8 {
    return switch (opcode) {
        .add, .addi => "opcode_add_flag",
        .sub => "opcode_sub_flag",
        .sll, .slli => "opcode_sll_flag",
        .slt => "opcode_slt_flag",
        .sltu => "opcode_sltu_flag",
        .xor, .xori => "opcode_xor_flag",
        .srl, .srli => "opcode_srl_flag",
        .sra, .srai => "opcode_sra_flag",
        .@"or", .ori => "opcode_or_flag",
        .@"and", .andi => "opcode_and_flag",
        .slti => "opcode_slti_flag",
        .sltiu => "opcode_sltiu_flag",
        .lb => "opcode_lb_flag",
        .lh => "opcode_lh_flag",
        .lw => "opcode_lw_flag",
        .lbu => "opcode_lbu_flag",
        .lhu => "opcode_lhu_flag",
        .sb => "opcode_sb_flag",
        .sh => "opcode_sh_flag",
        .sw => "opcode_sw_flag",
        .beq => "opcode_beq_flag",
        .bne => "opcode_bne_flag",
        .blt => "opcode_blt_flag",
        .bge => "opcode_bge_flag",
        .bltu => "opcode_bltu_flag",
        .bgeu => "opcode_bgeu_flag",
        .mulh => "opcode_mulh_flag",
        .mulhsu => "opcode_mulhsu_flag",
        .mulhu => "opcode_mulhu_flag",
        .div => "opcode_div_flag",
        .divu => "opcode_divu_flag",
        .rem => "opcode_rem_flag",
        .remu => "opcode_remu_flag",
        .jal, .jalr, .lui, .auipc, .mul, .fence => "enabler",
    };
}

test "all 46 proof opcodes reach witness, semantic, lookup, and component authorities" {
    try opcode_manifest.validate();
    try std.testing.expectEqual(@as(usize, 46), opcode_manifest.entries.len);

    var covered_families = [_]bool{false} ** trace.N_FAMILIES;
    var zero_columns = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    inline for (opcode_manifest.entries, 0..) |manifest_entry, protocol_id| {
        try std.testing.expectEqual(protocol_id, manifest_entry.opcode.protocolId());
        const family = manifest_entry.family;
        covered_families[@intFromEnum(family)] = true;
        try std.testing.expect(manifest_entry.execution_supported);
        try std.testing.expectEqual(family, manifest_entry.witness_schema);
        try std.testing.expectEqual(family, manifest_entry.semantic_component);

        const Layout = witness_layout.LayoutFor(family);
        const layout_fields = @typeInfo(Layout).@"struct".fields;
        try std.testing.expectEqual(layout_fields.len, trace.nColumnsForFamily(family));
        try std.testing.expect(@hasField(Layout, selectorColumn(manifest_entry.opcode)));
        try std.testing.expectEqual(layout_fields.len, semantic_eval.mainColumnCount(family));
        try std.testing.expect(semantic_eval.constraintCount(family) > 1);

        const requests = try lookup_entries.fromMain(
            family,
            zero_columns[0..layout_fields.len],
        );
        try std.testing.expectEqual(lookup_entries.entryCount(family), requests.len);
        try std.testing.expectEqual(lookup_entries.batchSize(family), requests.batch_size);
        try std.testing.expectEqual(lookup_entries.batchCount(family), requests.batchCount());

        var domains = [_]bool{false} ** lookup_entry.DOMAIN_COUNT;
        var domain_bits: u16 = 0;
        for (requests.entries[0..requests.len]) |request| {
            try request.validate();
            domains[@intFromEnum(request.domain)] = true;
            domain_bits |= @as(u16, 1) << @intFromEnum(request.domain);
        }
        try std.testing.expectEqual(manifest_entry.relation_domains.bits, domain_bits);
        try std.testing.expect(domains[@intFromEnum(lookup_entry.Domain.program_access)]);
        try std.testing.expect(domains[@intFromEnum(lookup_entry.Domain.registers_state)]);
        if (family == .fence) {
            try std.testing.expect(!domains[@intFromEnum(lookup_entry.Domain.memory_access)]);
        } else {
            try std.testing.expect(domains[@intFromEnum(lookup_entry.Domain.memory_access)]);
        }

        const transcript_component = component_order.transcriptComponentForOpcodeFamily(family);
        try std.testing.expectEqual(
            component_order.opcodeFamilyIndex(family),
            @as(usize, @intFromEnum(transcript_component)),
        );

        try std.testing.expect(semantic_eval.isTraceCompatible(family));
        try std.testing.expectEqual(
            opcode_manifest.ProofEligibility.admitted,
            manifest_entry.proof_eligibility,
        );
        const component = try semantic_component.SemanticComponent.init(family, 0, 0, 0);
        try std.testing.expectEqual(family, component.family);
        try std.testing.expectEqual(layout_fields.len, component.mainColumnCount());
        try std.testing.expectEqual(semantic_eval.constraintCount(family), component.nConstraints());
    }

    for (covered_families) |covered| try std.testing.expect(covered);
}

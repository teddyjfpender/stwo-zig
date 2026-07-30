const std = @import("std");

pub const magic: u32 = 0x31505453;
pub const abi_major: u16 = 1;
pub const abi_minor: u16 = 0;
pub const header_bytes = 96;
pub const section_bytes = 24;
pub const m31_prime: u32 = 0x7fffffff;

pub const Flag = struct {
    pub const prefinalized_logup: u32 = 1 << 0;
    pub const debug_present: u32 = 1 << 1;
};

pub const Capability = struct {
    pub const base_inv: u64 = 1 << 0;
    pub const ext_mul: u64 = 1 << 1;
    pub const prefinalized_logup: u64 = 1 << 2;
    pub const supported: u64 = base_inv | ext_mul | prefinalized_logup;
};

pub const SectionKind = enum(u32) {
    base_consts = 1,
    ext_consts = 2,
    base_insts = 3,
    ext_insts = 4,
    constraint_roots = 5,
    debug_strings = 6,
    param_debug_map = 7,
    node_debug_map = 8,
};

pub const BaseOpcode = enum(u8) {
    trace_col = 0,
    preprocessed_col = 1,
    param = 2,
    constant = 3,
    add = 4,
    sub = 5,
    mul = 6,
    neg = 7,
    inv = 8,
};

pub const ExtOpcode = enum(u8) {
    secure_col = 0,
    param = 1,
    constant = 2,
    add = 3,
    sub = 4,
    mul = 5,
    neg = 6,
};

pub const Header = struct {
    flags: u32,
    semantic_hash: u64,
    capability_bits: u64,
    n_interactions: u32,
    n_base_params: u32,
    n_ext_params: u32,
    n_constraints: u32,
    max_base_regs: u32,
    max_ext_regs: u32,
    domain_log_size: u32,
};

pub const BaseInst = struct {
    op: BaseOpcode,
    interaction: u8,
    dst: u16,
    a: u32,
    b: u32,
    imm: i32,
};

pub const ExtInst = struct {
    op: ExtOpcode,
    dst: u16,
    a: u32,
    b: u32,
    c: u32,
    d: u32,
};

const Section = struct {
    kind: SectionKind,
    elem_size: u32,
    offset: usize,
    count: usize,
};

pub const Program = struct {
    allocator: std.mem.Allocator,
    header: Header,
    base_consts: []u32,
    ext_consts: [][4]u32,
    base_insts: []BaseInst,
    ext_insts: []ExtInst,
    constraint_roots: []u32,

    pub fn readFile(allocator: std.mem.Allocator, path: []const u8) !Program {
        const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 512 * 1024 * 1024);
        defer allocator.free(bytes);
        return parse(allocator, bytes);
    }

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Program {
        if (bytes.len < header_bytes) return error.TruncatedProgram;
        var cursor: usize = 0;
        if (take(u32, bytes, &cursor) != magic) return error.InvalidMagic;
        if (take(u16, bytes, &cursor) != abi_major or take(u16, bytes, &cursor) != abi_minor)
            return error.UnsupportedVersion;
        const n_sections = take(u32, bytes, &cursor);
        const flags = take(u32, bytes, &cursor);
        const semantic_hash = take(u64, bytes, &cursor);
        const capability_bits = take(u64, bytes, &cursor);
        const n_interactions = take(u32, bytes, &cursor);
        const n_base_params = take(u32, bytes, &cursor);
        const n_ext_params = take(u32, bytes, &cursor);
        const n_constraints = take(u32, bytes, &cursor);
        const max_base_regs = take(u32, bytes, &cursor);
        const max_ext_regs = take(u32, bytes, &cursor);
        if (take(u32, bytes, &cursor) != 4) return error.InvalidSecureDegree;
        const domain_log_size = take(u32, bytes, &cursor);
        for (1..8) |_| if (take(u32, bytes, &cursor) != 0) return error.InvalidReserved;
        if (take(u32, bytes, &cursor) != 0) return error.InvalidPadding;
        if (cursor != header_bytes or n_sections < 5 or n_sections > 8) return error.InvalidSectionCount;
        if (flags & ~(Flag.prefinalized_logup | Flag.debug_present) != 0) return error.UnsupportedFlags;
        if (flags & Flag.prefinalized_logup == 0) return error.InvalidFlags;
        if (capability_bits & ~Capability.supported != 0) return error.UnsupportedCapability;
        if (capability_bits & Capability.prefinalized_logup == 0) return error.InvalidCapability;
        if (n_interactions == 0 or n_interactions > 256 or domain_log_size > 31) return error.InvalidHeader;
        if (max_base_regs == 0 or max_base_regs > 65536 or max_ext_regs == 0 or max_ext_regs > 65536)
            return error.InvalidRegisterCount;

        const table_len = std.math.mul(usize, n_sections, section_bytes) catch return error.InvalidSectionCount;
        const payload_start = std.math.add(usize, header_bytes, table_len) catch return error.InvalidSectionCount;
        if (payload_start > bytes.len) return error.TruncatedProgram;
        const sections = try allocator.alloc(Section, n_sections);
        defer allocator.free(sections);
        var seen: u16 = 0;
        for (sections) |*section| {
            const raw_kind = take(u32, bytes, &cursor);
            const kind = std.meta.intToEnum(SectionKind, raw_kind) catch return error.InvalidSectionKind;
            const bit: u16 = @as(u16, 1) << @intCast(raw_kind - 1);
            if (seen & bit != 0) return error.DuplicateSection;
            seen |= bit;
            const elem_size = take(u32, bytes, &cursor);
            const offset_u64 = take(u64, bytes, &cursor);
            const count_u64 = take(u64, bytes, &cursor);
            const offset = std.math.cast(usize, offset_u64) orelse return error.SectionOutOfBounds;
            const count = std.math.cast(usize, count_u64) orelse return error.SectionOutOfBounds;
            const expected_size = sectionElementSize(kind);
            if (elem_size != expected_size) return error.InvalidElementSize;
            const byte_len = std.math.mul(usize, count, elem_size) catch return error.SectionOutOfBounds;
            const end = std.math.add(usize, offset, byte_len) catch return error.SectionOutOfBounds;
            if (end > bytes.len - payload_start) return error.SectionOutOfBounds;
            section.* = .{ .kind = kind, .elem_size = elem_size, .offset = offset, .count = count };
        }
        const required: u16 = (1 << 5) - 1;
        if (seen & required != required) return error.MissingSection;
        for (sections, 0..) |lhs, i| for (sections[i + 1 ..]) |rhs| {
            const lhs_end = lhs.offset + lhs.count * lhs.elem_size;
            const rhs_end = rhs.offset + rhs.count * rhs.elem_size;
            if (lhs.offset < rhs_end and rhs.offset < lhs_end) return error.OverlappingSections;
        };

        const base_const_section = findSection(sections, .base_consts).?;
        const ext_const_section = findSection(sections, .ext_consts).?;
        const base_inst_section = findSection(sections, .base_insts).?;
        const ext_inst_section = findSection(sections, .ext_insts).?;
        const roots_section = findSection(sections, .constraint_roots).?;
        if (roots_section.count != n_constraints or n_constraints == 0) return error.InvalidConstraintCount;

        var program = Program{
            .allocator = allocator,
            .header = .{
                .flags = flags,
                .semantic_hash = semantic_hash,
                .capability_bits = capability_bits,
                .n_interactions = n_interactions,
                .n_base_params = n_base_params,
                .n_ext_params = n_ext_params,
                .n_constraints = n_constraints,
                .max_base_regs = max_base_regs,
                .max_ext_regs = max_ext_regs,
                .domain_log_size = domain_log_size,
            },
            .base_consts = try allocator.alloc(u32, base_const_section.count),
            .ext_consts = undefined,
            .base_insts = undefined,
            .ext_insts = undefined,
            .constraint_roots = undefined,
        };
        errdefer allocator.free(program.base_consts);
        program.ext_consts = try allocator.alloc([4]u32, ext_const_section.count);
        errdefer allocator.free(program.ext_consts);
        program.base_insts = try allocator.alloc(BaseInst, base_inst_section.count);
        errdefer allocator.free(program.base_insts);
        program.ext_insts = try allocator.alloc(ExtInst, ext_inst_section.count);
        errdefer allocator.free(program.ext_insts);
        program.constraint_roots = try allocator.alloc(u32, roots_section.count);
        errdefer allocator.free(program.constraint_roots);

        var hash: u64 = 0xcbf29ce484222325;
        for ([_]Section{ base_const_section, ext_const_section, base_inst_section, ext_inst_section, roots_section }) |section| {
            const start = payload_start + section.offset;
            const section_len = section.count * section.elem_size;
            hashBytes(&hash, bytes[start .. start + section_len]);
        }
        if (hash != semantic_hash) return error.SemanticHashMismatch;

        decodeU32Section(bytes, payload_start, base_const_section, program.base_consts);
        for (program.base_consts) |value| if (value >= m31_prime) return error.InvalidFieldElement;
        decodeU32x4Section(bytes, payload_start, ext_const_section, program.ext_consts);
        for (program.ext_consts) |value| for (value) |limb| if (limb >= m31_prime) return error.InvalidFieldElement;
        decodeBaseInsts(bytes, payload_start, base_inst_section, program.base_insts) catch |err| return err;
        decodeExtInsts(bytes, payload_start, ext_inst_section, program.ext_insts) catch |err| return err;
        decodeU32Section(bytes, payload_start, roots_section, program.constraint_roots);
        try program.validate();
        return program;
    }

    pub fn deinit(self: *Program) void {
        self.allocator.free(self.base_consts);
        self.allocator.free(self.ext_consts);
        self.allocator.free(self.base_insts);
        self.allocator.free(self.ext_insts);
        self.allocator.free(self.constraint_roots);
        self.* = undefined;
    }

    pub fn clone(self: Program, allocator: std.mem.Allocator) !Program {
        var result = Program{
            .allocator = allocator,
            .header = self.header,
            .base_consts = try allocator.dupe(u32, self.base_consts),
            .ext_consts = undefined,
            .base_insts = undefined,
            .ext_insts = undefined,
            .constraint_roots = undefined,
        };
        errdefer allocator.free(result.base_consts);
        result.ext_consts = try allocator.dupe([4]u32, self.ext_consts);
        errdefer allocator.free(result.ext_consts);
        result.base_insts = try allocator.dupe(BaseInst, self.base_insts);
        errdefer allocator.free(result.base_insts);
        result.ext_insts = try allocator.dupe(ExtInst, self.ext_insts);
        errdefer allocator.free(result.ext_insts);
        result.constraint_roots = try allocator.dupe(
            u32,
            self.constraint_roots,
        );
        return result;
    }

    pub fn setDomainLogSize(self: *Program, log_size: u32) !void {
        if (log_size > 31) return error.InvalidHeader;
        self.header.domain_log_size = log_size;
    }

    /// Rebinds one recorded field constant and authenticates the resulting
    /// semantic payload. Callers own the source classification.
    pub fn replaceBaseConstant(
        self: *Program,
        source: u32,
        target: u32,
    ) !usize {
        if (source >= m31_prime or target >= m31_prime)
            return error.InvalidFieldElement;
        var replacements: usize = 0;
        for (self.base_insts) |*instruction| {
            if (instruction.op != .constant or instruction.a != source)
                continue;
            instruction.a = target;
            replacements += 1;
        }
        if (replacements != 0)
            self.header.semantic_hash = self.semanticHash();
        return replacements;
    }

    pub fn semanticHash(self: Program) u64 {
        var hash: u64 = 0xcbf29ce484222325;
        for (self.base_consts) |value| hashInt(&hash, u32, value);
        for (self.ext_consts) |value| for (value) |coordinate|
            hashInt(&hash, u32, coordinate);
        for (self.base_insts) |instruction| {
            hashInt(&hash, u8, @intFromEnum(instruction.op));
            hashInt(&hash, u8, instruction.interaction);
            hashInt(&hash, u16, instruction.dst);
            hashInt(&hash, u32, instruction.a);
            hashInt(&hash, u32, instruction.b);
            hashInt(&hash, i32, instruction.imm);
        }
        for (self.ext_insts) |instruction| {
            hashInt(&hash, u8, @intFromEnum(instruction.op));
            hashInt(&hash, u8, 0);
            hashInt(&hash, u16, instruction.dst);
            hashInt(&hash, u32, instruction.a);
            hashInt(&hash, u32, instruction.b);
            hashInt(&hash, u32, instruction.c);
            hashInt(&hash, u32, instruction.d);
        }
        for (self.constraint_roots) |root| hashInt(&hash, u32, root);
        return hash;
    }

    pub fn validate(self: Program) !void {
        const base_written = try self.allocator.alloc(bool, self.header.max_base_regs);
        defer self.allocator.free(base_written);
        @memset(base_written, false);
        const ext_written = try self.allocator.alloc(bool, self.header.max_ext_regs);
        defer self.allocator.free(ext_written);
        @memset(ext_written, false);
        for (self.base_insts) |inst| {
            if (inst.dst >= base_written.len) return error.RegisterOutOfBounds;
            switch (inst.op) {
                .trace_col, .preprocessed_col => if (inst.interaction >= self.header.n_interactions) return error.InteractionOutOfBounds,
                .param => if (inst.a >= self.header.n_base_params) return error.ParameterOutOfBounds,
                .constant => if (inst.a >= m31_prime) return error.InvalidFieldElement,
                .add, .sub, .mul => if (!isWritten(base_written, inst.a) or !isWritten(base_written, inst.b)) return error.ReadBeforeWrite,
                .neg, .inv => if (!isWritten(base_written, inst.a)) return error.ReadBeforeWrite,
            }
            if (inst.op == .inv and self.header.capability_bits & Capability.base_inv == 0) return error.MissingCapability;
            base_written[inst.dst] = true;
        }
        for (self.ext_insts) |inst| {
            if (inst.dst >= ext_written.len) return error.RegisterOutOfBounds;
            switch (inst.op) {
                .secure_col => if (!isWritten(base_written, inst.a) or !isWritten(base_written, inst.b) or !isWritten(base_written, inst.c) or !isWritten(base_written, inst.d)) return error.ReadBeforeWrite,
                .param => if (inst.a >= self.header.n_ext_params) return error.ParameterOutOfBounds,
                .constant => if (inst.a >= m31_prime or inst.b >= m31_prime or inst.c >= m31_prime or inst.d >= m31_prime) return error.InvalidFieldElement,
                .add, .sub, .mul => if (!isWritten(ext_written, inst.a) or !isWritten(ext_written, inst.b)) return error.ReadBeforeWrite,
                .neg => if (!isWritten(ext_written, inst.a)) return error.ReadBeforeWrite,
            }
            if (inst.op == .mul and self.header.capability_bits & Capability.ext_mul == 0) return error.MissingCapability;
            ext_written[inst.dst] = true;
        }
        for (self.constraint_roots) |root| if (!isWritten(ext_written, root)) return error.InvalidConstraintRoot;
    }
};

fn take(comptime T: type, bytes: []const u8, cursor: *usize) T {
    const size = @sizeOf(T);
    const value = std.mem.readInt(T, bytes[cursor.*..][0..size], .little);
    cursor.* += size;
    return value;
}

fn sectionElementSize(kind: SectionKind) u32 {
    return switch (kind) {
        .base_consts, .constraint_roots, .param_debug_map, .node_debug_map => 4,
        .ext_consts, .base_insts => 16,
        .ext_insts => 20,
        .debug_strings => 1,
    };
}

fn findSection(sections: []const Section, kind: SectionKind) ?Section {
    for (sections) |section| if (section.kind == kind) return section;
    return null;
}

fn isWritten(written: []const bool, index: u32) bool {
    return index < written.len and written[index];
}

fn hashBytes(hash: *u64, bytes: []const u8) void {
    for (bytes) |byte| {
        hash.* ^= byte;
        hash.* *%= 0x100000001b3;
    }
}

fn hashInt(hash: *u64, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hashBytes(hash, &encoded);
}

fn decodeU32Section(bytes: []const u8, payload_start: usize, section: Section, out: []u32) void {
    var cursor = payload_start + section.offset;
    for (out) |*value| value.* = take(u32, bytes, &cursor);
}

fn decodeU32x4Section(bytes: []const u8, payload_start: usize, section: Section, out: [][4]u32) void {
    var cursor = payload_start + section.offset;
    for (out) |*value| {
        for (value) |*limb| limb.* = take(u32, bytes, &cursor);
    }
}

fn decodeBaseInsts(bytes: []const u8, payload_start: usize, section: Section, out: []BaseInst) !void {
    var cursor = payload_start + section.offset;
    for (out) |*inst| inst.* = .{
        .op = std.meta.intToEnum(BaseOpcode, take(u8, bytes, &cursor)) catch return error.InvalidOpcode,
        .interaction = take(u8, bytes, &cursor),
        .dst = take(u16, bytes, &cursor),
        .a = take(u32, bytes, &cursor),
        .b = take(u32, bytes, &cursor),
        .imm = take(i32, bytes, &cursor),
    };
}

fn decodeExtInsts(bytes: []const u8, payload_start: usize, section: Section, out: []ExtInst) !void {
    var cursor = payload_start + section.offset;
    for (out) |*inst| {
        inst.op = std.meta.intToEnum(ExtOpcode, take(u8, bytes, &cursor)) catch return error.InvalidOpcode;
        if (take(u8, bytes, &cursor) != 0) return error.InvalidReserved;
        inst.dst = take(u16, bytes, &cursor);
        inst.a = take(u32, bytes, &cursor);
        inst.b = take(u32, bytes, &cursor);
        inst.c = take(u32, bytes, &cursor);
        inst.d = take(u32, bytes, &cursor);
    }
}

test "Cairo evaluation program: V1 ABI record sizes remain canonical" {
    try std.testing.expectEqual(@as(usize, 96), header_bytes);
    try std.testing.expectEqual(@as(usize, 24), section_bytes);
    try std.testing.expectEqual(@as(u32, 16), sectionElementSize(.base_insts));
    try std.testing.expectEqual(@as(u32, 20), sectionElementSize(.ext_insts));
}

test "Cairo evaluation program: cloned constants rebind semantic identity" {
    const allocator = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        "vectors/cairo/official/all_builtins_canonical.air_programs_v1.bin",
        2 * 1024 * 1024,
    );
    defer allocator.free(bytes);
    const encoded_program = findProgram(bytes, "add_mod_builtin") orelse
        return error.MissingTestProgram;
    var source = try Program.parse(allocator, encoded_program);
    defer source.deinit();
    var rebound = try source.clone(allocator);
    defer rebound.deinit();
    try rebound.setDomainLogSize(7);
    try std.testing.expectEqual(@as(usize, 1), try rebound.replaceBaseConstant(
        7711,
        9001,
    ));
    try std.testing.expect(rebound.header.semantic_hash != source.header.semantic_hash);
    try std.testing.expectEqual(rebound.semanticHash(), rebound.header.semantic_hash);
    try rebound.validate();
}

fn findProgram(bundle: []const u8, wanted: []const u8) ?[]const u8 {
    if (bundle.len < 40 or !std.mem.eql(u8, bundle[0..8], "STWZEVA\x00"))
        return null;
    var cursor: usize = 40;
    const component_count = readInt(u32, bundle, 28) orelse return null;
    for (0..component_count) |_| {
        const component_start = cursor;
        const label_len = readInt(u16, bundle, cursor) orelse return null;
        const span_count = readInt(u32, bundle, cursor + 24) orelse return null;
        const preprocessed_count = readInt(u32, bundle, cursor + 28) orelse
            return null;
        const denominator_count = readInt(u32, bundle, cursor + 32) orelse
            return null;
        const ext_source_count = readInt(u32, bundle, cursor + 36) orelse
            return null;
        const part_count = readInt(u32, bundle, cursor + 40) orelse return null;
        cursor += 44;
        if (cursor + label_len > bundle.len) return null;
        const label = bundle[cursor..][0..label_len];
        cursor += label_len +
            @as(usize, span_count) * 12 +
            @as(usize, preprocessed_count) * 4 +
            @as(usize, denominator_count) * 4 +
            @as(usize, ext_source_count) * 32;
        for (0..part_count) |_| {
            const program_len = readInt(u32, bundle, cursor + 4) orelse
                return null;
            const program_start = cursor + 16;
            const program_end = program_start + program_len;
            if (program_end > bundle.len) return null;
            if (std.mem.eql(u8, label, wanted))
                return bundle[program_start..program_end];
            cursor = program_end;
        }
        if (cursor <= component_start) return null;
    }
    return null;
}

fn readInt(comptime T: type, bytes: []const u8, offset: usize) ?T {
    if (offset + @sizeOf(T) > bytes.len) return null;
    return std.mem.readInt(T, bytes[offset..][0..@sizeOf(T)], .little);
}

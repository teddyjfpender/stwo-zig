//! Opt-in guest-PC/function attribution for Ethereum materialization.
//!
//! Counters observe the already-retained segment trace and native-call PCs.
//! They are diagnostic only: they never enter the execution statement, AIR,
//! transcript, or proof. Function names come from the exact identity-bound
//! ELF32 `.symtab`; no host symbolizer or ambient binary is consulted.

const std = @import("std");

const base = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");

pub const receipt_schema = "stwo.ethereum.guest-pc-function-profile.v1";
pub const receipt_status = "execution-profiled-diagnostic-only";
pub const pc_stride: u32 = 4;
pub const max_top_functions: usize = 512;
pub const max_top_pcs: usize = 2048;
pub const max_receipt_bytes: usize = 16 * 1024 * 1024;

const missing_symbol = std.math.maxInt(u32);
const symtab_type: u32 = 2;
const function_symbol_type: u8 = 2;
const elf_header_size: usize = 52;
const section_header_size: usize = 40;
const symbol_entry_size: usize = 16;

const Symbol = struct {
    address: u32,
    name: []const u8,
    size: u32,
};

pub const ExternalFamily = enum { keccakf, secp256k1_recover };

pub const ExternalFamilyCount = struct {
    calls: u64,
    execution_rows: u64,
    family: []const u8,
};

pub const FunctionCount = struct {
    address: u32,
    core_rows: u64,
    external_calls: u64,
    name: []const u8,
    size: u32,
    total_retirements: u64,
};

pub const PcCount = struct {
    core_rows: u64,
    external_calls: u64,
    function: ?[]const u8,
    function_offset: ?u32,
    pc: u32,
    total_retirements: u64,
};

pub const Receipt = struct {
    content_sha256: []const u8,
    attributed_core_rows: u64,
    attributed_external_calls: u64,
    core_rows: u64,
    elf: base.Identity,
    execution_journal: base.Identity,
    external_calls: u64,
    external_execution_rows: u64,
    external_family_counts: []const ExternalFamilyCount,
    function_count: u32,
    function_top_coverage_core_rows: u64,
    function_top_coverage_external_calls: u64,
    functions_truncated: bool,
    materialization_result: base.Identity,
    nonzero_pc_count: u32,
    out_of_text_core_rows: u64,
    out_of_text_external_calls: u64,
    pc_stride: u32,
    pc_top_coverage_core_rows: u64,
    pc_top_coverage_external_calls: u64,
    pcs_truncated: bool,
    schema: []const u8,
    source_request: base.Identity,
    status: []const u8,
    text_end: u32,
    text_start: u32,
    top_functions: []const FunctionCount,
    top_pcs: []const PcCount,
    unattributed_core_rows: u64,
    unattributed_external_calls: u64,

    pub fn validate(self: Receipt) !void {
        if (!std.mem.eql(u8, self.schema, receipt_schema) or
            !std.mem.eql(u8, self.status, receipt_status) or
            self.pc_stride != pc_stride or self.text_start >= self.text_end or
            self.function_count == 0 or self.top_functions.len == 0 or
            self.top_functions.len > max_top_functions or
            self.top_pcs.len > max_top_pcs or
            self.functions_truncated !=
                (self.function_count > self.top_functions.len) or
            self.pcs_truncated !=
                (self.nonzero_pc_count > self.top_pcs.len))
        {
            return error.InvalidGuestPcProfile;
        }
        try self.elf.validate(false);
        try self.execution_journal.validate(false);
        try self.materialization_result.validate(false);
        try self.source_request.validate(false);
        _ = try base.parseSha256(self.content_sha256);
        const classified_core = try sum3(
            self.attributed_core_rows,
            self.unattributed_core_rows,
            self.out_of_text_core_rows,
        );
        const classified_external = try sum3(
            self.attributed_external_calls,
            self.unattributed_external_calls,
            self.out_of_text_external_calls,
        );
        if (classified_core != self.core_rows or
            classified_external != self.external_calls or
            self.function_top_coverage_core_rows > self.attributed_core_rows or
            self.function_top_coverage_external_calls >
                self.attributed_external_calls or
            self.pc_top_coverage_core_rows > self.core_rows or
            self.pc_top_coverage_external_calls > self.external_calls)
        {
            return error.InvalidGuestPcProfile;
        }
        var family_calls: u64 = 0;
        var family_rows: u64 = 0;
        for (self.external_family_counts) |family| {
            if (family.family.len == 0) return error.InvalidGuestPcProfile;
            family_calls = try add(family_calls, family.calls);
            family_rows = try add(family_rows, family.execution_rows);
        }
        if (family_calls != self.external_calls or
            family_rows != self.external_execution_rows)
        {
            return error.InvalidGuestPcProfile;
        }
        try validateFunctionOrder(self.top_functions);
        try validatePcOrder(self.top_pcs);
    }
};

pub const ReceiptInput = struct {
    attributed_core_rows: u64,
    attributed_external_calls: u64,
    core_rows: u64,
    elf: base.Identity,
    execution_journal: base.Identity,
    external_calls: u64,
    external_execution_rows: u64,
    external_family_counts: []const ExternalFamilyCount,
    function_count: u32,
    function_top_coverage_core_rows: u64,
    function_top_coverage_external_calls: u64,
    functions_truncated: bool,
    materialization_result: base.Identity,
    nonzero_pc_count: u32,
    out_of_text_core_rows: u64,
    out_of_text_external_calls: u64,
    pc_stride: u32 = pc_stride,
    pc_top_coverage_core_rows: u64,
    pc_top_coverage_external_calls: u64,
    pcs_truncated: bool,
    schema: []const u8 = receipt_schema,
    source_request: base.Identity,
    status: []const u8 = receipt_status,
    text_end: u32,
    text_start: u32,
    top_functions: []const FunctionCount,
    top_pcs: []const PcCount,
    unattributed_core_rows: u64,
    unattributed_external_calls: u64,
};

pub const ProfileIdentities = struct {
    elf: evidence.FileIdentity,
    execution_journal: evidence.FileIdentity,
    materialization_result: evidence.FileIdentity,
    source_request: evidence.FileIdentity,
};

pub const Profiler = struct {
    allocator: std.mem.Allocator,
    core_counts: []u64,
    external_counts: []u64,
    family_calls: [2]u64 = .{ 0, 0 },
    family_execution_rows: [2]u64 = .{ 0, 0 },
    out_of_text_core_rows: u64 = 0,
    out_of_text_external_calls: u64 = 0,
    slot_symbols: []u32,
    symbols: []Symbol,
    text_end: u32,
    text_start: u32,

    pub fn init(
        allocator: std.mem.Allocator,
        elf: []const u8,
    ) !Profiler {
        const parsed = try parseSymbols(allocator, elf);
        const symbols = parsed.symbols;
        errdefer allocator.free(symbols);
        const slot_count_u32 = std.math.divCeil(
            u32,
            try std.math.sub(u32, parsed.text_end, parsed.text_start),
            pc_stride,
        ) catch return error.InvalidElfSymbolTable;
        const slot_count: usize = @intCast(slot_count_u32);
        if (slot_count == 0) return error.InvalidElfSymbolTable;
        const core_counts = try allocator.alloc(u64, slot_count);
        errdefer allocator.free(core_counts);
        @memset(core_counts, 0);
        const external_counts = try allocator.alloc(u64, slot_count);
        errdefer allocator.free(external_counts);
        @memset(external_counts, 0);
        const slot_symbols = try allocator.alloc(u32, slot_count);
        errdefer allocator.free(slot_symbols);
        @memset(slot_symbols, missing_symbol);

        std.mem.sort(Symbol, symbols, {}, symbolLessThan);
        for (symbols, 0..) |symbol, symbol_index| {
            const start = @max(symbol.address, parsed.text_start);
            const raw_end = std.math.add(u32, symbol.address, symbol.size) catch
                parsed.text_end;
            const end = @min(raw_end, parsed.text_end);
            if (start >= end) continue;
            var pc = start - (start % pc_stride);
            if (pc < start) pc = std.math.add(u32, pc, pc_stride) catch continue;
            while (pc < end) : (pc += pc_stride) {
                const slot = (pc - parsed.text_start) / pc_stride;
                if (slot < slot_symbols.len)
                    slot_symbols[slot] = @intCast(symbol_index);
            }
        }
        return .{
            .allocator = allocator,
            .core_counts = core_counts,
            .external_counts = external_counts,
            .slot_symbols = slot_symbols,
            .symbols = symbols,
            .text_end = parsed.text_end,
            .text_start = parsed.text_start,
        };
    }

    pub fn deinit(self: *Profiler) void {
        self.allocator.free(self.slot_symbols);
        self.allocator.free(self.external_counts);
        self.allocator.free(self.core_counts);
        self.allocator.free(self.symbols);
        self.* = undefined;
    }

    pub fn observeCoreRows(self: *Profiler, rows: anytype) !void {
        for (rows) |row| try self.observeCorePc(row.pc);
    }

    pub fn observeCorePc(self: *Profiler, pc: u32) !void {
        if (self.slotForPc(pc)) |slot| {
            self.core_counts[slot] = try add(self.core_counts[slot], 1);
        } else {
            self.out_of_text_core_rows = try add(
                self.out_of_text_core_rows,
                1,
            );
        }
    }

    pub fn observeExternalRecords(
        self: *Profiler,
        family: ExternalFamily,
        records: anytype,
        execution_rows: usize,
    ) !void {
        const family_index = @intFromEnum(family);
        self.family_calls[family_index] = try add(
            self.family_calls[family_index],
            @intCast(records.len),
        );
        self.family_execution_rows[family_index] = try add(
            self.family_execution_rows[family_index],
            @intCast(execution_rows),
        );
        for (records) |record| try self.observeExternalPc(record.pc);
    }

    pub fn observeExternalPc(self: *Profiler, pc: u32) !void {
        if (self.slotForPc(pc)) |slot| {
            self.external_counts[slot] = try add(
                self.external_counts[slot],
                1,
            );
        } else {
            self.out_of_text_external_calls = try add(
                self.out_of_text_external_calls,
                1,
            );
        }
    }

    pub fn encodeReceipt(
        self: *const Profiler,
        allocator: std.mem.Allocator,
        identities: ProfileIdentities,
    ) ![]u8 {
        const function_counts = try self.functionCounts(allocator);
        defer allocator.free(function_counts);
        const pc_counts = try self.pcCounts(allocator);
        defer allocator.free(pc_counts);
        const top_function_len = @min(function_counts.len, max_top_functions);
        const top_pc_len = @min(pc_counts.len, max_top_pcs);
        const top_functions = function_counts[0..top_function_len];
        const top_pcs = pc_counts[0..top_pc_len];
        const function_inventory = try functionReceiptInventory(
            function_counts.len,
            top_functions.len,
        );

        var total_core: u64 = self.out_of_text_core_rows;
        var total_external: u64 = self.out_of_text_external_calls;
        var attributed_core: u64 = 0;
        var attributed_external: u64 = 0;
        var unattributed_core: u64 = 0;
        var unattributed_external: u64 = 0;
        var nonzero_pcs: u32 = 0;
        for (self.core_counts, self.external_counts, self.slot_symbols) |
            core_count,
            external_count,
            symbol_index,
        | {
            total_core = try add(total_core, core_count);
            total_external = try add(total_external, external_count);
            if (core_count != 0 or external_count != 0)
                nonzero_pcs = try addU32(nonzero_pcs, 1);
            if (symbol_index == missing_symbol) {
                unattributed_core = try add(unattributed_core, core_count);
                unattributed_external = try add(
                    unattributed_external,
                    external_count,
                );
            } else {
                attributed_core = try add(attributed_core, core_count);
                attributed_external = try add(
                    attributed_external,
                    external_count,
                );
            }
        }
        const external_execution_rows = try add(
            self.family_execution_rows[0],
            self.family_execution_rows[1],
        );
        const external_families = [_]ExternalFamilyCount{
            .{
                .calls = self.family_calls[0],
                .execution_rows = self.family_execution_rows[0],
                .family = "keccakf",
            },
            .{
                .calls = self.family_calls[1],
                .execution_rows = self.family_execution_rows[1],
                .family = "secp256k1_recover",
            },
        };
        const elf_hex = digestHex(identities.elf.sha256);
        const journal_hex = digestHex(identities.execution_journal.sha256);
        const result_hex = digestHex(identities.materialization_result.sha256);
        const source_hex = digestHex(identities.source_request.sha256);
        const unsigned = ReceiptInput{
            .attributed_core_rows = attributed_core,
            .attributed_external_calls = attributed_external,
            .core_rows = total_core,
            .elf = identity(identities.elf, &elf_hex),
            .execution_journal = identity(
                identities.execution_journal,
                &journal_hex,
            ),
            .external_calls = total_external,
            .external_execution_rows = external_execution_rows,
            .external_family_counts = &external_families,
            .function_count = function_inventory.count,
            .function_top_coverage_core_rows = sumFunctionCore(top_functions),
            .function_top_coverage_external_calls = sumFunctionExternal(top_functions),
            .functions_truncated = function_inventory.truncated,
            .materialization_result = identity(
                identities.materialization_result,
                &result_hex,
            ),
            .nonzero_pc_count = nonzero_pcs,
            .out_of_text_core_rows = self.out_of_text_core_rows,
            .out_of_text_external_calls = self.out_of_text_external_calls,
            .pc_top_coverage_core_rows = sumPcCore(top_pcs),
            .pc_top_coverage_external_calls = sumPcExternal(top_pcs),
            .pcs_truncated = pc_counts.len > top_pcs.len,
            .source_request = identity(
                identities.source_request,
                &source_hex,
            ),
            .text_end = self.text_end,
            .text_start = self.text_start,
            .top_functions = top_functions,
            .top_pcs = top_pcs,
            .unattributed_core_rows = unattributed_core,
            .unattributed_external_calls = unattributed_external,
        };
        const json = try std.json.Stringify.valueAlloc(allocator, unsigned, .{});
        defer allocator.free(json);
        const bytes = try evidence.seal(allocator, json);
        errdefer allocator.free(bytes);
        var parsed = try parseReceipt(allocator, bytes);
        parsed.deinit();
        return bytes;
    }

    fn slotForPc(self: *const Profiler, pc: u32) ?usize {
        if (pc < self.text_start or pc >= self.text_end or
            (pc - self.text_start) % pc_stride != 0)
        {
            return null;
        }
        const slot: usize = @intCast((pc - self.text_start) / pc_stride);
        if (slot >= self.core_counts.len) return null;
        return slot;
    }

    fn functionCounts(
        self: *const Profiler,
        allocator: std.mem.Allocator,
    ) ![]FunctionCount {
        const counts = try allocator.alloc(FunctionCount, self.symbols.len);
        errdefer allocator.free(counts);
        for (self.symbols, counts) |symbol, *count| count.* = .{
            .address = symbol.address,
            .core_rows = 0,
            .external_calls = 0,
            .name = symbol.name,
            .size = symbol.size,
            .total_retirements = 0,
        };
        for (self.core_counts, self.external_counts, self.slot_symbols) |
            core_count,
            external_count,
            symbol_index,
        | {
            if (symbol_index == missing_symbol) continue;
            const count = &counts[symbol_index];
            count.core_rows = try add(count.core_rows, core_count);
            count.external_calls = try add(
                count.external_calls,
                external_count,
            );
            count.total_retirements = try add(
                count.core_rows,
                count.external_calls,
            );
        }
        std.mem.sort(FunctionCount, counts, {}, functionCountLessThan);
        return trimZeroFunctions(counts);
    }

    fn pcCounts(
        self: *const Profiler,
        allocator: std.mem.Allocator,
    ) ![]PcCount {
        var count: usize = 0;
        for (self.core_counts, self.external_counts) |core_count, external_count|
            if (core_count != 0 or external_count != 0) {
                count += 1;
            };
        const result = try allocator.alloc(PcCount, count);
        errdefer allocator.free(result);
        var cursor: usize = 0;
        for (self.core_counts, self.external_counts, self.slot_symbols, 0..) |
            core_count,
            external_count,
            symbol_index,
            slot,
        | {
            if (core_count == 0 and external_count == 0) continue;
            const pc = std.math.add(
                u32,
                self.text_start,
                try std.math.mul(u32, @intCast(slot), pc_stride),
            ) catch return error.GuestPcProfileOverflow;
            const symbol: ?Symbol = if (symbol_index == missing_symbol)
                null
            else
                self.symbols[symbol_index];
            result[cursor] = .{
                .core_rows = core_count,
                .external_calls = external_count,
                .function = if (symbol) |value| value.name else null,
                .function_offset = if (symbol) |value|
                    std.math.sub(u32, pc, value.address) catch null
                else
                    null,
                .pc = pc,
                .total_retirements = try add(core_count, external_count),
            };
            cursor += 1;
        }
        std.mem.sort(PcCount, result, {}, pcCountLessThan);
        return result;
    }
};

pub fn parseReceipt(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(Receipt) {
    if (bytes.len == 0 or bytes.len > max_receipt_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidCanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(Receipt, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        parsed.value,
        .{},
    );
    defer allocator.free(canonical);
    if (canonical.len + 1 != bytes.len or
        !std.mem.eql(u8, canonical, bytes[0..canonical.len]))
    {
        return error.InvalidCanonicalJson;
    }
    try parsed.value.validate();
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

const ParsedSymbols = struct {
    symbols: []Symbol,
    text_end: u32,
    text_start: u32,
};

fn parseSymbols(
    allocator: std.mem.Allocator,
    elf: []const u8,
) !ParsedSymbols {
    if (elf.len < elf_header_size or !std.mem.eql(u8, elf[0..4], "\x7fELF") or
        elf[4] != 1 or elf[5] != 1 or readU16(elf[18..20]) != 243)
    {
        return error.InvalidElfSymbolTable;
    }
    const section_offset: usize = @intCast(readU32(elf[32..36]));
    const section_entry_size: usize = readU16(elf[46..48]);
    const section_count: usize = readU16(elf[48..50]);
    if (section_offset == 0 or section_entry_size < section_header_size or
        section_count == 0)
    {
        return error.MissingElfSymbolTable;
    }
    var functions: std.ArrayList(Symbol) = .empty;
    errdefer functions.deinit(allocator);
    var text_start: ?u32 = null;
    var text_len: ?u32 = null;
    var symtab_count: usize = 0;
    for (0..section_count) |section_index| {
        const header = try tableEntry(
            elf,
            section_offset,
            section_entry_size,
            section_index,
            section_header_size,
        );
        if (readU32(header[4..8]) != symtab_type) continue;
        symtab_count += 1;
        const symbols_offset: usize = @intCast(readU32(header[16..20]));
        const symbols_size: usize = @intCast(readU32(header[20..24]));
        const strings_index: usize = @intCast(readU32(header[24..28]));
        const entry_size: usize = @intCast(readU32(header[36..40]));
        if (entry_size < symbol_entry_size or symbols_size % entry_size != 0 or
            strings_index >= section_count)
        {
            return error.InvalidElfSymbolTable;
        }
        const symbols = try sliceAt(elf, symbols_offset, symbols_size);
        const strings_header = try tableEntry(
            elf,
            section_offset,
            section_entry_size,
            strings_index,
            section_header_size,
        );
        const strings_offset: usize = @intCast(readU32(strings_header[16..20]));
        const strings_size: usize = @intCast(readU32(strings_header[20..24]));
        const strings = try sliceAt(elf, strings_offset, strings_size);
        var offset: usize = 0;
        while (offset < symbols.len) : (offset += entry_size) {
            const symbol = symbols[offset..][0..entry_size];
            const name = try symbolName(strings, readU32(symbol[0..4]));
            const value = readU32(symbol[4..8]);
            const size = readU32(symbol[8..12]);
            if (std.mem.eql(u8, name, "__text_start")) text_start = value;
            if (std.mem.eql(u8, name, "__text_len")) text_len = value;
            if (symbol[12] & 0x0f == function_symbol_type and
                name.len != 0 and size != 0)
            {
                try functions.append(allocator, .{
                    .address = value,
                    .name = name,
                    .size = size,
                });
            }
        }
    }
    if (symtab_count != 1) return error.InvalidElfSymbolTable;
    const start = text_start orelse return error.MissingTextAuthority;
    const end = std.math.add(
        u32,
        start,
        text_len orelse return error.MissingTextAuthority,
    ) catch return error.InvalidElfSymbolTable;
    if (start >= end or start % pc_stride != 0)
        return error.InvalidElfSymbolTable;
    var retained: usize = 0;
    for (functions.items) |function| {
        const function_end = std.math.add(
            u32,
            function.address,
            function.size,
        ) catch continue;
        if (function.address < end and function_end > start) {
            functions.items[retained] = function;
            retained += 1;
        }
    }
    functions.shrinkRetainingCapacity(retained);
    if (functions.items.len == 0) return error.MissingFunctionSymbols;
    return .{
        .symbols = try functions.toOwnedSlice(allocator),
        .text_end = end,
        .text_start = start,
    };
}

fn tableEntry(
    bytes: []const u8,
    offset: usize,
    stride: usize,
    index: usize,
    size: usize,
) ![]const u8 {
    const relative = std.math.mul(usize, stride, index) catch
        return error.InvalidElfSymbolTable;
    const start = std.math.add(usize, offset, relative) catch
        return error.InvalidElfSymbolTable;
    return sliceAt(bytes, start, size);
}

fn sliceAt(bytes: []const u8, offset: usize, size: usize) ![]const u8 {
    const end = std.math.add(usize, offset, size) catch
        return error.InvalidElfSymbolTable;
    if (end > bytes.len) return error.InvalidElfSymbolTable;
    return bytes[offset..end];
}

fn symbolName(strings: []const u8, raw_offset: u32) ![]const u8 {
    const offset: usize = @intCast(raw_offset);
    if (offset >= strings.len) return error.InvalidElfSymbolTable;
    const tail = strings[offset..];
    const end = std.mem.indexOfScalar(u8, tail, 0) orelse
        return error.InvalidElfSymbolTable;
    return tail[0..end];
}

fn symbolLessThan(_: void, left: Symbol, right: Symbol) bool {
    if (left.address != right.address) return left.address < right.address;
    if (left.size != right.size) return left.size > right.size;
    return std.mem.lessThan(u8, left.name, right.name);
}

fn functionCountLessThan(_: void, left: FunctionCount, right: FunctionCount) bool {
    if (left.total_retirements != right.total_retirements)
        return left.total_retirements > right.total_retirements;
    if (left.core_rows != right.core_rows) return left.core_rows > right.core_rows;
    if (left.address != right.address) return left.address < right.address;
    return std.mem.lessThan(u8, left.name, right.name);
}

fn pcCountLessThan(_: void, left: PcCount, right: PcCount) bool {
    if (left.total_retirements != right.total_retirements)
        return left.total_retirements > right.total_retirements;
    if (left.core_rows != right.core_rows) return left.core_rows > right.core_rows;
    return left.pc < right.pc;
}

fn trimZeroFunctions(counts: []FunctionCount) []FunctionCount {
    var length = counts.len;
    while (length != 0 and counts[length - 1].total_retirements == 0)
        length -= 1;
    return counts[0..length];
}

fn validateFunctionOrder(values: []const FunctionCount) !void {
    for (values, 0..) |value, index| {
        if (value.name.len == 0 or
            value.total_retirements != try add(
                value.core_rows,
                value.external_calls,
            ) or (index != 0 and functionCountLessThan(
            {},
            value,
            values[index - 1],
        ))) return error.InvalidGuestPcProfile;
    }
}

fn validatePcOrder(values: []const PcCount) !void {
    for (values, 0..) |value, index| {
        if (value.pc % pc_stride != 0 or
            value.total_retirements != try add(
                value.core_rows,
                value.external_calls,
            ) or (index != 0 and pcCountLessThan(
            {},
            value,
            values[index - 1],
        ))) return error.InvalidGuestPcProfile;
    }
}

fn sumFunctionCore(values: []const FunctionCount) u64 {
    var result: u64 = 0;
    for (values) |value| result += value.core_rows;
    return result;
}

fn sumFunctionExternal(values: []const FunctionCount) u64 {
    var result: u64 = 0;
    for (values) |value| result += value.external_calls;
    return result;
}

fn sumPcCore(values: []const PcCount) u64 {
    var result: u64 = 0;
    for (values) |value| result += value.core_rows;
    return result;
}

fn sumPcExternal(values: []const PcCount) u64 {
    var result: u64 = 0;
    for (values) |value| result += value.external_calls;
    return result;
}

fn identity(value: evidence.FileIdentity, sha256: []const u8) base.Identity {
    return .{ .bytes = value.bytes, .path = value.path, .sha256 = sha256 };
}

fn digestHex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

fn readU16(bytes: *const [2]u8) u16 {
    return std.mem.readInt(u16, bytes, .little);
}

fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

fn add(left: u64, right: u64) !u64 {
    return std.math.add(u64, left, right) catch
        error.GuestPcProfileOverflow;
}

fn addU32(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch
        error.GuestPcProfileOverflow;
}

fn sum3(first: u64, second: u64, third: u64) !u64 {
    return add(try add(first, second), third);
}

const FunctionReceiptInventory = struct {
    count: u32,
    truncated: bool,
};

/// The receipt reports the number of functions with at least one attributed
/// retirement.  `functionCounts` has already removed zero-retirement ELF
/// symbols, so count and truncation must both use that same active inventory.
fn functionReceiptInventory(
    active_count: usize,
    retained_count: usize,
) !FunctionReceiptInventory {
    if (retained_count > active_count)
        return error.InvalidGuestPcProfile;
    return .{
        .count = std.math.cast(u32, active_count) orelse
            return error.GuestPcProfileOverflow,
        .truncated = active_count > retained_count,
    };
}

test "guest PC profile counts active functions consistently" {
    const untruncated = try functionReceiptInventory(37, 37);
    try std.testing.expectEqual(@as(u32, 37), untruncated.count);
    try std.testing.expect(!untruncated.truncated);

    const truncated = try functionReceiptInventory(513, max_top_functions);
    try std.testing.expectEqual(@as(u32, 513), truncated.count);
    try std.testing.expect(truncated.truncated);
    try std.testing.expectError(
        error.InvalidGuestPcProfile,
        functionReceiptInventory(1, 2),
    );
}

fn validateContentSha256(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: []const u8,
) !void {
    _ = try base.parseSha256(expected);
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidContentSha256;
    const start = prefix.len;
    const end = start + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',' or
        !std.mem.eql(u8, bytes[start..end], expected))
    {
        return error.InvalidContentSha256;
    }
    const unsigned = try std.fmt.allocPrint(
        allocator,
        "{{{s}",
        .{bytes[end + 2 ..]},
    );
    defer allocator.free(unsigned);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(unsigned, &digest, .{});
    const encoded = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &encoded, expected))
        return error.InvalidContentSha256;
}

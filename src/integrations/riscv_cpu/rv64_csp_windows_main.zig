//! One guest execution, bounded capture, complete-cost admission and proof windows.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const native = @import("stwo_riscv_cpu_integration").rv64;
const wire = @import("stwo_proof_wire");
const base = std.heap.smp_allocator;
const Row = rv.machine.Retirement;
const Window = struct { start: u64, steps: usize, status: []const u8, main_columns: usize = 0, fixed_columns: usize = 0, cells: usize = 0, rows: usize = 0, proof_bytes: usize = 0, oods_samples: usize = 0, queried_base_values: usize = 0, authenticated_hashes: usize = 0, witness_ns: u64 = 0, prove_ns: u64 = 0, setup_ns: u64 = 0, decode_ns: u64 = 0, verify_ns: u64 = 0, program_words: usize = 0, dense_program_words: u64 = 0, peak_caller_bytes: usize = 0 };
const Config = struct { artifact_dir: []const u8, guest: rv.csp_contract.Config, expected_steps: u64, sample_starts: []const u64 };
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(base);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len != 2) return error.ExpectedConfig;
    const parsed = try std.json.parseFromSlice(Config, a, try std.fs.cwd().readFileAlloc(a, args[1], 32768), .{});
    const config = parsed.value;
    try std.fs.cwd().makePath(config.artifact_dir);
    var artifacts = try std.fs.cwd().openDir(config.artifact_dir, .{});
    defer artifacts.close();
    if (config.expected_steps == 0 or config.expected_steps > 10000000 or config.sample_starts.len > 4) return error.InvalidBudget;
    const elf = try std.fs.cwd().readFileAlloc(a, config.guest.elf, 32 * 1024 * 1024);
    const input = try std.fs.cwd().readFileAlloc(a, config.guest.input, 4096);
    var loaded = try rv.csp_contract.load(base, config.guest, elf, input);
    defer loaded.deinit();
    var session = try rv.Session.init(base, rv.machine.Cpu.init(loaded.info.entry, config.guest.symbols.stack_top), &loaded.memory, .{ .max_retirements = 10000000 });
    defer session.deinit();
    var samples: std.ArrayList(Window) = .empty;
    defer samples.deinit(base);
    var identities = std.AutoHashMap([32]u8, void).init(base);
    defer identities.deinit();
    var windows: u64 = 0;
    var ram_events: u64 = 0;
    var register_events: u64 = 0;
    var main_cells: u64 = 0;
    var expected_opening_payload_lower: f64 = 0;
    var expected_opening_payload_upper: f64 = 0;
    var padded_rows: u64 = 0;
    var geometry_rejections: u64 = 0;
    var dense_program_rejections: u64 = 0;
    var histogram: [65]u64 = @splat(0);
    var timer = try std.time.Timer.start();
    while (session.cpu.retired < config.expected_steps) {
        const initial = session.cpu.regs;
        const start = session.cpu.retired;
        var records: [256]Row = undefined;
        const count: usize = @intCast(@min(256, config.expected_steps - start));
        var min_pc: u64 = std.math.maxInt(u64);
        var max_pc: u64 = 0;
        var words: [22]bool = @splat(false);
        var carries: [88]bool = @splat(false);
        var slots: [4]bool = @splat(false);
        var product = false;
        var shift64 = false;
        var shift32 = false;
        var memory_keys: [256]u64 = undefined;
        var key_count: usize = 0;
        var identity = std.crypto.hash.sha2.Sha256.init(.{});
        for (records[0..count]) |*record| {
            record.* = try session.step();
            histogram[@intFromEnum(record.opcode)] += 1;
            const pc = record.pc.toInt();
            min_pc = @min(min_pc, pc);
            max_pc = @max(max_pc, pc);
            var key: [12]u8 = undefined;
            std.mem.writeInt(u64, key[0..8], pc, .little);
            std.mem.writeInt(u32, key[8..12], record.instruction, .little);
            identity.update(&key);
            const effect = rv.decode.effects(record.opcode);
            const enabled = [4]bool{ effect.reads_rs1 and record.rs1 != 0, effect.reads_rs2 and record.rs2 != 0, effect.writes_rd and record.rd != 0, record.memory != null };
            for (&slots, enabled, 0..) |*present, yes, i| {
                present.* = present.* or yes;
                if (i < 3 and yes) register_events += 1;
            }
            for (&words, 0..) |*present, i| present.* = present.* or air.operations.wordActive(@enumFromInt(i), record.opcode, enabled);
            for (&carries, 0..) |*present, i| present.* = present.* or air.operations.carryActive(@enumFromInt(i / 8), i % 8, record.opcode);
            product = product or air.operations.mul(record.opcode) or air.operations.div(record.opcode);
            shift64 = shift64 or (air.operations.shift(record.opcode) and !air.operations.word(record.opcode));
            shift32 = shift32 or (air.operations.shift(record.opcode) and air.operations.word(record.opcode));
            if (record.memory) |event| {
                ram_events += 1;
                const address = event.address.toInt() & ~@as(u64, 7);
                if (std.mem.indexOfScalar(u64, memory_keys[0..key_count], address) == null) {
                    memory_keys[key_count] = address;
                    key_count += 1;
                }
            }
        }
        var ending: [8]u8 = undefined;
        std.mem.writeInt(u64, &ending, session.cpu.pc, .little);
        identity.update(&ending);
        try identities.put(identity.finalResult(), {});
        var columns: u64 = 19;
        for (words) |present| if (present) {
            columns += 64;
        };
        for (carries) |present| columns += @intFromBool(present);
        for (slots) |present| if (present) {
            columns += 24;
        };
        if (product) columns += 176;
        columns += if (shift64) @as(u64, 384) else if (shift32) 160 else 0;
        const domain: u64 = @as(u64, 1) << @intCast(@max(5, std.math.log2_int_ceil(usize, count)));
        windows += 1;
        padded_rows += domain;
        main_cells += columns * domain;
        const queries = @as(f64, @floatFromInt(2 * domain)) * (1 - std.math.pow(f64, 1 - 1 / @as(f64, @floatFromInt(2 * domain)), 70));
        const column_payload = 16 + 4 * queries;
        expected_opening_payload_lower += @as(f64, @floatFromInt(columns + 36 + 16 + 2)) * column_payload + 64;
        expected_opening_payload_upper += @as(f64, @floatFromInt(columns + 36 + 16 + 229)) * column_payload + 64;
        if (key_count > 128) geometry_rejections += 1;
        if ((max_pc - min_pc) / 4 + 1 > 4096) dense_program_rejections += 1;
        if (std.mem.indexOfScalar(u64, config.sample_starts, start) != null) {
            const result = proveWindow(start, records[0..count], initial, session.cpu.regs, session.cpu.pc, &loaded.memory, artifacts) catch |err| Window{ .start = start, .steps = count, .status = @errorName(err) };
            if (std.mem.eql(u8, result.status, "verified_partial_window") and result.main_columns != columns) return error.CostModelMismatch;
            try samples.append(base, result);
        }
    }
    const capture_and_proof_ns = timer.read();
    const symbols = config.guest.symbols;
    if (try loaded.memory.load(symbols.halt_flag, 4) != 1 or try loaded.memory.load(symbols.output_len, 4) != 32) return error.InvalidCompletion;
    var output: [32]u8 = undefined;
    for (&output, 0..) |*value, i| value.* = @intCast(try loaded.memory.load(symbols.output_data + i, 1));
    const digest = std.fmt.bytesToHex(output, .lower);
    if (!std.mem.eql(u8, &digest, config.guest.expected_digest)) return error.OutputMismatch;
    const report = try std.json.Stringify.valueAlloc(a, .{ .complete_guest_execution = true, .whole_guest_proof = false, .instructions = session.cpu.retired, .windows = windows, .unique_setup_identities = identities.count(), .geometry_rejections = geometry_rejections, .dense_program_rejections_reference = dense_program_rejections, .main_committed_cells_model = main_cells, .expected_opening_payload_lower_model = expected_opening_payload_lower, .expected_opening_payload_upper_model = expected_opening_payload_upper, .total_committed_cells_lower_model = main_cells + (36 + 16 + 2) * padded_rows, .total_committed_cells_upper_model = main_cells + (36 + 16 + 229) * padded_rows, .padded_rows = padded_rows, .register_events_local = register_events, .ram_events = ram_events, .opcode_histogram = histogram, .capture_and_proof_ns = capture_and_proof_ns, .samples = samples.items }, .{});
    try std.fs.File.stdout().writeAll(report);
    try std.fs.File.stdout().writeAll("\n");
}

fn proveWindow(start: u64, records: []const Row, initial: [32]u64, final: [32]u64, final_pc: u64, memory: *rv.memory.Memory, artifacts: std.fs.Dir) !Window {
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(base, 512 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    var timer = try std.time.Timer.start();
    var min_pc: u64 = std.math.maxInt(u64);
    var max_pc: u64 = 0;
    var cells: std.ArrayList(air.statement.Cell) = .empty;
    defer cells.deinit(a);
    for (records) |record| {
        min_pc = @min(min_pc, record.pc.toInt());
        max_pc = @max(max_pc, record.pc.toInt());
        if (record.memory) |event| {
            const address = event.address.toInt() & ~@as(u64, 7);
            var index: ?usize = null;
            for (cells.items, 0..) |cell, i| if (cell.address == address) {
                index = i;
                break;
            };
            if (index) |i| cells.items[i].final = event.after_word.toInt() else {
                if (cells.items.len == 128) return error.MemoryApertureLimit;
                const read = accessible(memory, address, false);
                const write = accessible(memory, address, true);
                try cells.append(a, .{ .address = address, .initial = event.before_word.toInt(), .final = event.after_word.toInt(), .readable = read, .writable = write });
            }
        }
    }
    var pc_set: [256]u64 = undefined;
    var pc_count: usize = 0;
    for (records) |record| {
        const pc = record.pc.toInt();
        if (std.mem.indexOfScalar(u64, pc_set[0..pc_count], pc) == null) {
            pc_set[pc_count] = pc;
            pc_count += 1;
        }
    }
    const addresses = try a.dupe(u64, pc_set[0..pc_count]);
    defer a.free(addresses);
    std.mem.sort(u64, addresses, {}, std.sort.asc(u64));
    const program = try a.alloc(u32, addresses.len);
    defer a.free(program);
    for (program, addresses) |*word, pc| word.* = try memory.fetch(pc);
    for (records) |record| {
        const index = std.mem.indexOfScalar(u64, addresses, record.pc.toInt()).?;
        if (program[index] != record.instruction) return error.MutableProgramUnsupported;
    }
    std.mem.sort(air.statement.Cell, cells.items, {}, struct {
        fn less(_: void, lhs: air.statement.Cell, rhs: air.statement.Cell) bool {
            return lhs.address < rhs.address;
        }
    }.less);
    const public = native.Statement{ .program_base = min_pc, .program = program, .program_addresses = addresses, .initial_pc = records[0].pc.toInt(), .final_pc = final_pc, .initial_registers = initial, .final_registers = final, .memory = cells.items, .steps = @intCast(records.len) };
    try public.validate();
    var owns_storage = true;
    const rows = try a.alloc(air.rows.Main, records.len);
    errdefer if (owns_storage) a.free(rows);
    const path = try a.alloc(u64, records.len);
    errdefer if (owns_storage) a.free(path);
    const clocks = try a.alloc(u16, cells.items.len);
    errdefer if (owns_storage) a.free(clocks);
    @memset(clocks, 0);
    var registers: [32]u16 = @splat(0);
    for (records, rows, path, 0..) |record_value, *row, *pc, i| {
        var record = record_value;
        record.clock = i + 1;
        pc.* = record.pc.toInt();
        const instruction = try rv.decode.Instruction.decode(record.instruction);
        const effects = rv.decode.effects(instruction.opcode);
        var predecessors: [4]u16 = @splat(0);
        if (effects.reads_rs1 and instruction.rs1 != 0) {
            predecessors[0] = registers[instruction.rs1];
            registers[instruction.rs1] = @intCast(4 * i + 1);
        }
        if (effects.reads_rs2 and instruction.rs2 != 0) {
            predecessors[1] = registers[instruction.rs2];
            registers[instruction.rs2] = @intCast(4 * i + 2);
        }
        if (effects.writes_rd and instruction.rd != 0) {
            predecessors[2] = registers[instruction.rd];
            registers[instruction.rd] = @intCast(4 * i + 3);
        }
        var rights = rv.memory.Permissions{};
        if (record.memory) |event| {
            const index = try air.witness.memoryIndex(public, event.address.toInt() & ~@as(u64, 7));
            predecessors[3] = clocks[index];
            clocks[index] = @intCast(4 * i + 4);
            rights = .{ .read = cells.items[index].readable, .write = cells.items[index].writable };
        }
        row.* = try air.witness.fromRetirement(record, instruction, predecessors, rights);
    }
    // Ownership transfers once; neither execution nor hints are reconstructed.
    const witness = air.witness.Witness{ .allocator = a, .rows = rows, .metadata = .{ .path = path, .register_clocks = registers, .memory_clocks = clocks } };
    const witness_ns = timer.lap();
    // The callee consumes all three allocations, including on failure.
    owns_storage = false;
    var result = try finishWindow(a, public, witness, start, witness_ns, &timer, budget, artifacts);
    result.program_words = addresses.len;
    result.dense_program_words = (max_pc - min_pc) / 4 + 1;
    return result;
}
fn finishWindow(a: std.mem.Allocator, public: native.Statement, witness: air.witness.Witness, start: u64, witness_ns: u64, timer: *std.time.Timer, budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget, artifacts: std.fs.Dir) !Window {
    var bundle = try native.provePreparedOwned(a, public, witness);
    defer bundle.deinit(a);
    const prove_ns = timer.lap();
    const peak = budget.snapshot().peak_live_bytes;
    var oods_samples: usize = 0;
    var queried_values: usize = 0;
    var authenticated_hashes: usize = 0;
    for (bundle.proof.commitment_scheme_proof.sampled_values.items) |tree| for (tree) |column| {
        oods_samples += column.len;
    };
    for (bundle.proof.commitment_scheme_proof.queried_values.items) |tree| for (tree) |column| {
        queried_values += column.len;
    };
    for (bundle.proof.commitment_scheme_proof.decommitments.items) |tree| authenticated_hashes += tree.hash_witness.len;
    var setup = try native.PreparedSetup.init(a, public, bundle.metadata);
    defer setup.deinit();
    const setup_ns = timer.lap();
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    const proof_path = try std.fmt.allocPrint(a, "{d}.proof.bin", .{start});
    defer a.free(proof_path);
    try artifacts.writeFile(.{ .sub_path = proof_path, .data = encoded });
    const statement_path = try std.fmt.allocPrint(a, "{d}.statement.json", .{start});
    defer a.free(statement_path);
    const statement_bytes = try std.json.Stringify.valueAlloc(a, public, .{});
    defer a.free(statement_bytes);
    try artifacts.writeFile(.{ .sub_path = statement_path, .data = statement_bytes });
    const metadata_path = try std.fmt.allocPrint(a, "{d}.metadata.json", .{start});
    defer a.free(metadata_path);
    const metadata_bytes = try std.json.Stringify.valueAlloc(a, bundle.metadata, .{});
    defer a.free(metadata_bytes);
    try artifacts.writeFile(.{ .sub_path = metadata_path, .data = metadata_bytes });
    timer.reset();
    const decoded = try wire.decodeProofBytesBinary(a, encoded);
    const decode_ns = timer.lap();
    try setup.verifyOwned(a, public, bundle.metadata, decoded);
    return .{ .start = start, .steps = public.steps, .status = "verified_partial_window", .main_columns = setup.projection.main_count, .fixed_columns = setup.projection.fixed_count, .cells = public.memory.len, .rows = @as(usize, 1) << @intCast(setup.log_size), .proof_bytes = encoded.len, .oods_samples = oods_samples, .queried_base_values = queried_values, .authenticated_hashes = authenticated_hashes, .witness_ns = witness_ns, .prove_ns = prove_ns, .setup_ns = setup_ns, .decode_ns = decode_ns, .verify_ns = timer.read(), .peak_caller_bytes = peak };
}
fn accessible(memory: *rv.memory.Memory, address: u64, write: bool) bool {
    memory.mappings.check(address, 8, if (write) .write else .read) catch return false;
    return true;
}

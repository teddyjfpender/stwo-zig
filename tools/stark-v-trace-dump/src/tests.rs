use super::*;

/// Build a minimal ELF with the given instruction words loaded at 0x10000.
fn make_test_elf(instructions: &[u32]) -> Vec<u8> {
    let code_size = instructions.len() * 4;
    let elf_size = 84 + code_size;
    let mut buf = vec![0u8; elf_size];

    // ELF header
    buf[0] = 0x7F;
    buf[1] = b'E';
    buf[2] = b'L';
    buf[3] = b'F';
    buf[4] = 1; // ELFCLASS32
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EI_VERSION
    buf[16] = 2; // e_type = ET_EXEC
    buf[18] = 0xF3; // e_machine = EM_RISCV
    buf[20] = 1; // e_version
                 // e_entry = 0x10000
    buf[24] = 0x00;
    buf[25] = 0x00;
    buf[26] = 0x01;
    buf[27] = 0x00;
    // e_phoff = 52
    buf[28] = 52;
    // e_ehsize = 52
    buf[40] = 52;
    // e_phentsize = 32
    buf[42] = 32;
    // e_phnum = 1
    buf[44] = 1;

    // Program header at offset 52
    buf[52] = 1; // p_type = PT_LOAD
    buf[56] = 84; // p_offset = 84
                  // p_vaddr = 0x10000
    buf[60] = 0x00;
    buf[61] = 0x00;
    buf[62] = 0x01;
    buf[63] = 0x00;
    // p_filesz
    buf[68] = code_size as u8;
    buf[69] = (code_size >> 8) as u8;
    // p_memsz
    buf[72] = code_size as u8;
    buf[73] = (code_size >> 8) as u8;

    // Instructions at offset 84
    for (i, &inst_word) in instructions.iter().enumerate() {
        let offset = 84 + i * 4;
        buf[offset] = inst_word as u8;
        buf[offset + 1] = (inst_word >> 8) as u8;
        buf[offset + 2] = (inst_word >> 16) as u8;
        buf[offset + 3] = (inst_word >> 24) as u8;
    }

    buf
}

#[test]
fn test_addi_ecall() {
    // ADDI x1, x0, 42; ECALL
    let elf = make_test_elf(&[0x02A00093, 0x00000073]);
    let trace = run_elf(&elf, 1000, 0x7FFF_0000).unwrap();
    assert_eq!(trace.total_steps, 2);
    assert_eq!(trace.final_regs[1], 42);
    assert_eq!(trace.steps[0].opcode, "ADDI");
    assert_eq!(trace.steps[1].opcode, "ECALL");
}

#[test]
fn test_add_sub() {
    // ADDI x1, x0, 10; ADDI x2, x0, 20; ADD x3, x1, x2; SUB x4, x2, x1; ECALL
    let elf = make_test_elf(&[
        0x00A00093, // ADDI x1, x0, 10
        0x01400113, // ADDI x2, x0, 20
        0x002081B3, // ADD  x3, x1, x2
        0x40110233, // SUB  x4, x2, x1
        0x00000073, // ECALL
    ]);
    let trace = run_elf(&elf, 1000, 0x7FFF_0000).unwrap();
    assert_eq!(trace.final_regs[1], 10);
    assert_eq!(trace.final_regs[3], 30);
    assert_eq!(trace.final_regs[4], 10);
}

#[test]
fn test_mul() {
    // ADDI x1, x0, 7; ADDI x2, x0, 6; MUL x3, x1, x2; ECALL
    // MUL x3, x1, x2 = funct7=0000001, rs2=x2, rs1=x1, funct3=000, rd=x3, opcode=0110011
    // = 0b0000001_00010_00001_000_00011_0110011 = 0x022081B3
    let elf = make_test_elf(&[
        0x00700093, // ADDI x1, x0, 7
        0x00600113, // ADDI x2, x0, 6
        0x022081B3, // MUL  x3, x1, x2
        0x00000073, // ECALL
    ]);
    let trace = run_elf(&elf, 1000, 0x7FFF_0000).unwrap();
    assert_eq!(trace.final_regs[3], 42);
}

#[test]
fn test_div_by_zero() {
    // ADDI x1, x0, 100; DIV x3, x1, x0; ECALL
    // DIV x3, x1, x0: funct7=0000001, rs2=x0, rs1=x1, funct3=100, rd=x3, opcode=0110011
    // = 0b0000001_00000_00001_100_00011_0110011 = 0x0200C1B3
    let elf = make_test_elf(&[
        0x06400093, // ADDI x1, x0, 100
        0x0200C1B3, // DIV  x3, x1, x0
        0x00000073, // ECALL
    ]);
    let trace = run_elf(&elf, 1000, 0x7FFF_0000).unwrap();
    assert_eq!(trace.final_regs[3], 0xFFFF_FFFF); // -1
}

#[test]
fn test_load_store() {
    // ADDI x1, x0, 0x55; ADDI x2, x0, 0x100; SW x1, 0(x2); LW x3, 0(x2); ECALL
    let elf = make_test_elf(&[
        0x05500093, // ADDI x1, x0, 0x55
        0x10000113, // ADDI x2, x0, 0x100
        0x00112023, // SW   x1, 0(x2)
        0x00012183, // LW   x3, 0(x2)
        0x00000073, // ECALL
    ]);
    let trace = run_elf(&elf, 1000, 0x7FFF_0000).unwrap();
    assert_eq!(trace.final_regs[3], 0x55);
    // Check trace flags
    assert!(trace.steps[2].is_store);
    assert_eq!(trace.steps[2].mem_addr, 0x100);
    assert_eq!(trace.steps[2].mem_val, 0x55);
    assert!(trace.steps[3].is_load);
    assert_eq!(trace.steps[3].mem_addr, 0x100);
    assert_eq!(trace.steps[3].mem_val, 0x55);
}

#[test]
fn test_branch_taken() {
    // ADDI x1, x0, 42; ADDI x2, x0, 42; BEQ x1, x2, +8; ADDI x3, x0, 1; ADDI x4, x0, 2; ECALL
    // If BEQ taken, skip ADDI x3 (at pc+4), land on ADDI x4 (at pc+8).
    let elf = make_test_elf(&[
        0x02A00093, // ADDI x1, x0, 42
        0x02A00113, // ADDI x2, x0, 42
        0x00208463, // BEQ  x1, x2, +8
        0x00100193, // ADDI x3, x0, 1  (skipped)
        0x00200213, // ADDI x4, x0, 2
        0x00000073, // ECALL
    ]);
    let trace = run_elf(&elf, 1000, 0x7FFF_0000).unwrap();
    assert_eq!(trace.final_regs[3], 0); // x3 was skipped
    assert_eq!(trace.final_regs[4], 2); // x4 was executed
    assert!(trace.steps[2].branch_taken);
}

#[test]
fn test_jal() {
    // JAL x1, +8; ADDI x3, x0, 1; ADDI x4, x0, 2; ECALL
    // JAL jumps +8 from current PC, skipping ADDI x3.
    // JAL x1, +8: imm=8, rd=x1
    // Encoding: imm[20|10:1|11|19:12] | rd | 1101111
    // imm=8 = 0b0000_0000_0000_0000_1000
    //   imm[20]    = 0
    //   imm[10:1]  = 0000000100
    //   imm[11]    = 0
    //   imm[19:12] = 00000000
    // inst[31]     = 0                   (imm[20])
    // inst[30:21]  = 0000000100          (imm[10:1])
    // inst[20]     = 0                   (imm[11])
    // inst[19:12]  = 00000000            (imm[19:12])
    // inst[11:7]   = 00001               (rd=x1)
    // inst[6:0]    = 1101111
    // = 0b0_0000001000_0_00000000_00001_1101111
    // = 0x008000EF
    let elf = make_test_elf(&[
        0x008000EF, // JAL x1, +8
        0x00100193, // ADDI x3, x0, 1  (skipped)
        0x00200213, // ADDI x4, x0, 2
        0x00000073, // ECALL
    ]);
    let trace = run_elf(&elf, 1000, 0x7FFF_0000).unwrap();
    assert_eq!(trace.final_regs[3], 0); // x3 skipped
    assert_eq!(trace.final_regs[4], 2); // x4 executed
                                        // x1 = return address = 0x10000 + 4 = 0x10004
    assert_eq!(trace.final_regs[1], 0x10004);
}

#[test]
fn test_lui() {
    // LUI x1, 0x12345; ECALL
    let elf = make_test_elf(&[
        0x123450B7, // LUI x1, 0x12345
        0x00000073, // ECALL
    ]);
    let trace = run_elf(&elf, 1000, 0x7FFF_0000).unwrap();
    assert_eq!(trace.final_regs[1], 0x12345000);
}

#[test]
fn test_decode_equivalence() {
    // Verify decoder matches the Zig decoder's known-good encodings.
    let cases: &[(u32, &str, u8, u8, u8, i32)] = &[
        (0x003100B3, "ADD", 1, 2, 3, 0),
        (0x40310133, "SUB", 2, 2, 3, 0),
        (0x00500093, "ADDI", 1, 0, 0, 5),
        (0x00002103, "LW", 2, 0, 0, 0),
        (0x00112023, "SW", 0, 2, 1, 0),
        (0x00208463, "BEQ", 0, 1, 2, 8),
        (0x00C000EF, "JAL", 1, 0, 0, 12),
        (0x000080E7, "JALR", 1, 1, 0, 0),
        (0x000011B7, "LUI", 3, 0, 0, 0x1000),
        (0x00001197, "AUIPC", 3, 0, 0, 0x1000),
        (0x02208033, "MUL", 0, 1, 2, 0),
        (0x02209033, "MULH", 0, 1, 2, 0),
        (0x0220C033, "DIV", 0, 1, 2, 0),
        (0x00101013, "SLLI", 0, 0, 0, 1),
        (0x00000073, "ECALL", 0, 0, 0, 0),
    ];

    for &(encoding, expected_op, exp_rd, exp_rs1, exp_rs2, exp_imm) in cases {
        let inst = decode(encoding).unwrap_or_else(|e| {
            panic!("Failed to decode 0x{:08X}: {}", encoding, e);
        });
        assert_eq!(
            inst.opcode.name(),
            expected_op,
            "opcode mismatch for 0x{:08X}",
            encoding
        );
        assert_eq!(inst.rd, exp_rd, "rd mismatch for 0x{:08X}", encoding);
        assert_eq!(inst.rs1, exp_rs1, "rs1 mismatch for 0x{:08X}", encoding);
        assert_eq!(inst.rs2, exp_rs2, "rs2 mismatch for 0x{:08X}", encoding);
        assert_eq!(inst.imm, exp_imm, "imm mismatch for 0x{:08X}", encoding);
    }
}

#[test]
fn test_executor_equivalence() {
    // Same instruction sequence as the Zig executor equivalence test.
    let elf = make_test_elf(&[
        0x00A00093, // ADDI x1, x0, 10
        0x01400113, // ADDI x2, x0, 20
        0x002081B3, // ADD  x3, x1, x2
        0x40110233, // SUB  x4, x2, x1
        0x022082B3, // MUL  x5, x1, x2
        0x00209333, // SLL  x6, x1, x2
        0x0020A3B3, // SLT  x7, x1, x2
        0x0020C433, // XOR  x8, x1, x2
        0x00000073, // ECALL
    ]);
    let trace = run_elf(&elf, 1000, 0x7FFF_0000).unwrap();

    assert_eq!(trace.final_regs[1], 10); // x1 = 10
    assert_eq!(trace.final_regs[2], 20); // x2 = 20 (ADDI x2, x0, 20 overwrites stack pointer)
    assert_eq!(trace.final_regs[3], 30); // x3 = 30
    assert_eq!(trace.final_regs[4], 10); // x4 = 10
    assert_eq!(trace.final_regs[5], 200); // x5 = 200
    assert_eq!(trace.final_regs[6], 10_485_760); // x6 = 10 << 20
    assert_eq!(trace.final_regs[7], 1); // x7 = 1 (10 < 20)
    assert_eq!(trace.final_regs[8], 30); // x8 = 10 ^ 20 = 30
    assert_eq!(trace.total_steps, 9);
}

#[test]
fn test_elf_validation() {
    // Bad magic
    let mut bad_magic = make_test_elf(&[0x00000073]);
    bad_magic[0] = 0x00;
    assert!(run_elf(&bad_magic, 100, 0x7FFF_0000).is_err());

    // Not RISC-V
    let mut bad_arch = make_test_elf(&[0x00000073]);
    bad_arch[18] = 0x03; // EM_386
    bad_arch[19] = 0x00;
    assert!(run_elf(&bad_arch, 100, 0x7FFF_0000).is_err());

    // Truncated
    let short = vec![0x7F, b'E', b'L', b'F'];
    assert!(run_elf(&short, 100, 0x7FFF_0000).is_err());
}

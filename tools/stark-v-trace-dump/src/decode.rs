// ---------------------------------------------------------------------------
// RV32IM opcodes and decoder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Opcode {
    // R-type arithmetic
    ADD,
    SUB,
    XOR,
    OR,
    AND,
    SLL,
    SRL,
    SRA,
    SLT,
    SLTU,
    // I-type arithmetic
    ADDI,
    XORI,
    ORI,
    ANDI,
    SLLI,
    SRLI,
    SRAI,
    SLTI,
    SLTIU,
    // Loads
    LB,
    LBU,
    LH,
    LHU,
    LW,
    // Stores
    SB,
    SH,
    SW,
    // Branches
    BEQ,
    BNE,
    BLT,
    BGE,
    BLTU,
    BGEU,
    // Jumps
    JAL,
    JALR,
    // Upper immediates
    LUI,
    AUIPC,
    // RV32M
    MUL,
    MULH,
    MULHSU,
    MULHU,
    DIV,
    DIVU,
    REM,
    REMU,
    // System
    ECALL,
    EBREAK,
}

impl Opcode {
    pub(super) fn name(self) -> &'static str {
        match self {
            Opcode::ADD => "ADD",
            Opcode::SUB => "SUB",
            Opcode::XOR => "XOR",
            Opcode::OR => "OR",
            Opcode::AND => "AND",
            Opcode::SLL => "SLL",
            Opcode::SRL => "SRL",
            Opcode::SRA => "SRA",
            Opcode::SLT => "SLT",
            Opcode::SLTU => "SLTU",
            Opcode::ADDI => "ADDI",
            Opcode::XORI => "XORI",
            Opcode::ORI => "ORI",
            Opcode::ANDI => "ANDI",
            Opcode::SLLI => "SLLI",
            Opcode::SRLI => "SRLI",
            Opcode::SRAI => "SRAI",
            Opcode::SLTI => "SLTI",
            Opcode::SLTIU => "SLTIU",
            Opcode::LB => "LB",
            Opcode::LBU => "LBU",
            Opcode::LH => "LH",
            Opcode::LHU => "LHU",
            Opcode::LW => "LW",
            Opcode::SB => "SB",
            Opcode::SH => "SH",
            Opcode::SW => "SW",
            Opcode::BEQ => "BEQ",
            Opcode::BNE => "BNE",
            Opcode::BLT => "BLT",
            Opcode::BGE => "BGE",
            Opcode::BLTU => "BLTU",
            Opcode::BGEU => "BGEU",
            Opcode::JAL => "JAL",
            Opcode::JALR => "JALR",
            Opcode::LUI => "LUI",
            Opcode::AUIPC => "AUIPC",
            Opcode::MUL => "MUL",
            Opcode::MULH => "MULH",
            Opcode::MULHSU => "MULHSU",
            Opcode::MULHU => "MULHU",
            Opcode::DIV => "DIV",
            Opcode::DIVU => "DIVU",
            Opcode::REM => "REM",
            Opcode::REMU => "REMU",
            Opcode::ECALL => "ECALL",
            Opcode::EBREAK => "EBREAK",
        }
    }

    pub(super) fn is_load(self) -> bool {
        matches!(
            self,
            Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW
        )
    }

    pub(super) fn is_store(self) -> bool {
        matches!(self, Opcode::SB | Opcode::SH | Opcode::SW)
    }
}

// ---------------------------------------------------------------------------
// Decoded instruction
// ---------------------------------------------------------------------------

pub(super) struct DecodedInst {
    pub(super) opcode: Opcode,
    pub(super) rd: u8,
    pub(super) rs1: u8,
    pub(super) rs2: u8,
    pub(super) imm: i32,
}

// ---------------------------------------------------------------------------
// Immediate extraction helpers
// ---------------------------------------------------------------------------

fn decode_i_imm(inst: u32) -> i32 {
    (inst as i32) >> 20 // arithmetic shift preserves sign
}

fn decode_s_imm(inst: u32) -> i32 {
    let hi = inst >> 25;
    let lo = (inst >> 7) & 0x1F;
    let combined = (hi << 5) | lo;
    sign_extend(combined, 12)
}

fn decode_b_imm(inst: u32) -> i32 {
    let bit_31 = (inst >> 31) & 1;
    let bit_7 = (inst >> 7) & 1;
    let bits_30_25 = (inst >> 25) & 0x3F;
    let bits_11_8 = (inst >> 8) & 0xF;
    let combined = (bit_31 << 12) | (bit_7 << 11) | (bits_30_25 << 5) | (bits_11_8 << 1);
    sign_extend(combined, 13)
}

fn decode_u_imm(inst: u32) -> i32 {
    (inst & 0xFFFFF000) as i32
}

fn decode_j_imm(inst: u32) -> i32 {
    let bit_31 = (inst >> 31) & 1;
    let bits_19_12 = (inst >> 12) & 0xFF;
    let bit_20 = (inst >> 20) & 1;
    let bits_30_21 = (inst >> 21) & 0x3FF;
    let combined = (bit_31 << 20) | (bits_19_12 << 12) | (bit_20 << 11) | (bits_30_21 << 1);
    sign_extend(combined, 21)
}

fn sign_extend(value: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    ((value << shift) as i32) >> shift
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

pub(super) fn decode(inst: u32) -> Result<DecodedInst, String> {
    let opcode_field = inst & 0x7F;
    let rd = ((inst >> 7) & 0x1F) as u8;
    let funct3 = (inst >> 12) & 0x7;
    let rs1 = ((inst >> 15) & 0x1F) as u8;
    let rs2 = ((inst >> 20) & 0x1F) as u8;
    let funct7 = (inst >> 25) & 0x7F;

    match opcode_field {
        // R-type (OP = 0b0110011)
        0b0110011 => {
            if funct7 == 0b0000001 {
                // RV32M
                let op = match funct3 {
                    0b000 => Opcode::MUL,
                    0b001 => Opcode::MULH,
                    0b010 => Opcode::MULHSU,
                    0b011 => Opcode::MULHU,
                    0b100 => Opcode::DIV,
                    0b101 => Opcode::DIVU,
                    0b110 => Opcode::REM,
                    0b111 => Opcode::REMU,
                    _ => unreachable!(),
                };
                Ok(DecodedInst {
                    opcode: op,
                    rd,
                    rs1,
                    rs2,
                    imm: 0,
                })
            } else {
                let op = match funct3 {
                    0b000 => {
                        if funct7 == 0b0100000 {
                            Opcode::SUB
                        } else {
                            Opcode::ADD
                        }
                    }
                    0b001 => Opcode::SLL,
                    0b010 => Opcode::SLT,
                    0b011 => Opcode::SLTU,
                    0b100 => Opcode::XOR,
                    0b101 => {
                        if funct7 == 0b0100000 {
                            Opcode::SRA
                        } else {
                            Opcode::SRL
                        }
                    }
                    0b110 => Opcode::OR,
                    0b111 => Opcode::AND,
                    _ => unreachable!(),
                };
                Ok(DecodedInst {
                    opcode: op,
                    rd,
                    rs1,
                    rs2,
                    imm: 0,
                })
            }
        }

        // I-type arithmetic (OP-IMM = 0b0010011)
        0b0010011 => {
            let op = match funct3 {
                0b000 => Opcode::ADDI,
                0b001 => Opcode::SLLI,
                0b010 => Opcode::SLTI,
                0b011 => Opcode::SLTIU,
                0b100 => Opcode::XORI,
                0b101 => {
                    if funct7 == 0b0100000 {
                        Opcode::SRAI
                    } else {
                        Opcode::SRLI
                    }
                }
                0b110 => Opcode::ORI,
                0b111 => Opcode::ANDI,
                _ => unreachable!(),
            };
            Ok(DecodedInst {
                opcode: op,
                rd,
                rs1,
                rs2: 0,
                imm: decode_i_imm(inst),
            })
        }

        // I-type loads (LOAD = 0b0000011)
        0b0000011 => {
            let op = match funct3 {
                0b000 => Opcode::LB,
                0b001 => Opcode::LH,
                0b010 => Opcode::LW,
                0b100 => Opcode::LBU,
                0b101 => Opcode::LHU,
                _ => return Err(format!("Illegal load funct3={}", funct3)),
            };
            Ok(DecodedInst {
                opcode: op,
                rd,
                rs1,
                rs2: 0,
                imm: decode_i_imm(inst),
            })
        }

        // S-type stores (STORE = 0b0100011)
        0b0100011 => {
            let op = match funct3 {
                0b000 => Opcode::SB,
                0b001 => Opcode::SH,
                0b010 => Opcode::SW,
                _ => return Err(format!("Illegal store funct3={}", funct3)),
            };
            Ok(DecodedInst {
                opcode: op,
                rd: 0,
                rs1,
                rs2,
                imm: decode_s_imm(inst),
            })
        }

        // B-type branches (BRANCH = 0b1100011)
        0b1100011 => {
            let op = match funct3 {
                0b000 => Opcode::BEQ,
                0b001 => Opcode::BNE,
                0b100 => Opcode::BLT,
                0b101 => Opcode::BGE,
                0b110 => Opcode::BLTU,
                0b111 => Opcode::BGEU,
                _ => return Err(format!("Illegal branch funct3={}", funct3)),
            };
            Ok(DecodedInst {
                opcode: op,
                rd: 0,
                rs1,
                rs2,
                imm: decode_b_imm(inst),
            })
        }

        // JAL (J-type, 0b1101111)
        0b1101111 => Ok(DecodedInst {
            opcode: Opcode::JAL,
            rd,
            rs1: 0,
            rs2: 0,
            imm: decode_j_imm(inst),
        }),

        // JALR (I-type, 0b1100111)
        0b1100111 => Ok(DecodedInst {
            opcode: Opcode::JALR,
            rd,
            rs1,
            rs2: 0,
            imm: decode_i_imm(inst),
        }),

        // LUI (U-type, 0b0110111)
        0b0110111 => Ok(DecodedInst {
            opcode: Opcode::LUI,
            rd,
            rs1: 0,
            rs2: 0,
            imm: decode_u_imm(inst),
        }),

        // AUIPC (U-type, 0b0010111)
        0b0010111 => Ok(DecodedInst {
            opcode: Opcode::AUIPC,
            rd,
            rs1: 0,
            rs2: 0,
            imm: decode_u_imm(inst),
        }),

        // SYSTEM (0b1110011)
        0b1110011 => {
            let op = if inst == 0x00000073 {
                Opcode::ECALL
            } else {
                Opcode::EBREAK
            };
            Ok(DecodedInst {
                opcode: op,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            })
        }

        _ => Err(format!("Illegal instruction: 0x{:08X}", inst)),
    }
}

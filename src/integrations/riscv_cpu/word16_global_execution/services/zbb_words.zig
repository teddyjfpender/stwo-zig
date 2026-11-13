//! Independent fixed Zbb instruction encoders shared by native ROM and product fixtures.
fn r(f7: u32, rs2: u32, rs1: u32, f3: u32, rd: u32, op: u32) u32 {
    return (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op;
}
pub fn iType(imm: u32, rs1: u32, f3: u32, rd: u32, op: u32) u32 {
    return (imm << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op;
}
pub fn andn(rd: u32, rs1: u32, rs2: u32) u32 {
    return r(0x20, rs2, rs1, 7, rd, 0x33);
}
pub fn orn(rd: u32, rs1: u32, rs2: u32) u32 {
    return r(0x20, rs2, rs1, 6, rd, 0x33);
}
pub fn xnor(rd: u32, rs1: u32, rs2: u32) u32 {
    return r(0x20, rs2, rs1, 4, rd, 0x33);
}
pub fn rev8(rd: u32, rs1: u32) u32 {
    return iType(0x6b8, rs1, 5, rd, 0x13);
}
pub fn sextB(rd: u32, rs1: u32) u32 {
    return iType(0x604, rs1, 1, rd, 0x13);
}
pub fn sextH(rd: u32, rs1: u32) u32 {
    return iType(0x605, rs1, 1, rd, 0x13);
}
pub fn zextH(rd: u32, rs1: u32) u32 {
    return r(0x04, 0, rs1, 4, rd, 0x3b);
}

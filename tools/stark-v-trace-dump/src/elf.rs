use std::collections::HashMap;

pub(super) struct Memory {
    data: HashMap<u32, u8>,
}

impl Memory {
    pub(super) fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    pub(super) fn read_byte(&self, addr: u32) -> u8 {
        *self.data.get(&addr).unwrap_or(&0)
    }

    pub(super) fn write_byte(&mut self, addr: u32, val: u8) {
        self.data.insert(addr, val);
    }

    pub(super) fn read_u16(&self, addr: u32) -> u16 {
        let lo = self.read_byte(addr) as u16;
        let hi = self.read_byte(addr.wrapping_add(1)) as u16;
        (hi << 8) | lo
    }

    pub(super) fn write_u16(&mut self, addr: u32, val: u16) {
        self.write_byte(addr, val as u8);
        self.write_byte(addr.wrapping_add(1), (val >> 8) as u8);
    }

    pub(super) fn read_u32(&self, addr: u32) -> u32 {
        let b0 = self.read_byte(addr) as u32;
        let b1 = self.read_byte(addr.wrapping_add(1)) as u32;
        let b2 = self.read_byte(addr.wrapping_add(2)) as u32;
        let b3 = self.read_byte(addr.wrapping_add(3)) as u32;
        (b3 << 24) | (b2 << 16) | (b1 << 8) | b0
    }

    pub(super) fn write_u32(&mut self, addr: u32, val: u32) {
        self.write_byte(addr, val as u8);
        self.write_byte(addr.wrapping_add(1), (val >> 8) as u8);
        self.write_byte(addr.wrapping_add(2), (val >> 16) as u8);
        self.write_byte(addr.wrapping_add(3), (val >> 24) as u8);
    }

    fn load_segment(&mut self, base: u32, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            self.write_byte(base.wrapping_add(i as u32), byte);
        }
    }
}

// ---------------------------------------------------------------------------
// ELF32 loader
// ---------------------------------------------------------------------------

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS32: u8 = 1;
const ELFDATA2LSB: u8 = 1;
const EM_RISCV: u16 = 243;
const PT_LOAD: u32 = 1;

pub(super) struct ElfInfo {
    pub(super) entry_point: u32,
    pub(super) segments_loaded: usize,
}

fn read_u16_le(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

pub(super) fn load_elf(elf_bytes: &[u8], mem: &mut Memory) -> Result<ElfInfo, String> {
    if elf_bytes.len() < 52 {
        return Err("ELF too small".into());
    }
    if elf_bytes[0..4] != ELF_MAGIC {
        return Err("Invalid ELF magic".into());
    }
    if elf_bytes[4] != ELFCLASS32 {
        return Err("Not 32-bit ELF".into());
    }
    if elf_bytes[5] != ELFDATA2LSB {
        return Err("Not little-endian ELF".into());
    }
    let e_machine = read_u16_le(&elf_bytes[18..20]);
    if e_machine != EM_RISCV {
        return Err(format!("Not RISC-V (e_machine={})", e_machine));
    }

    let e_entry = read_u32_le(&elf_bytes[24..28]);
    let e_phoff = read_u32_le(&elf_bytes[28..32]) as usize;
    let e_phnum = read_u16_le(&elf_bytes[44..46]) as usize;

    let mut segments_loaded = 0usize;
    for i in 0..e_phnum {
        let ph_offset = e_phoff + i * 32;
        if ph_offset + 32 > elf_bytes.len() {
            return Err("Program header out of bounds".into());
        }
        let phdr = &elf_bytes[ph_offset..ph_offset + 32];
        let p_type = read_u32_le(&phdr[0..4]);
        if p_type != PT_LOAD {
            continue;
        }
        let p_offset = read_u32_le(&phdr[4..8]) as usize;
        let p_vaddr = read_u32_le(&phdr[8..12]);
        let p_filesz = read_u32_le(&phdr[16..20]) as usize;

        if p_offset + p_filesz > elf_bytes.len() {
            return Err("Segment data out of bounds".into());
        }

        let segment_data = &elf_bytes[p_offset..p_offset + p_filesz];
        mem.load_segment(p_vaddr, segment_data);
        segments_loaded += 1;
    }

    Ok(ElfInfo {
        entry_point: e_entry,
        segments_loaded,
    })
}

//! Concrete independently reconstructed layout for the admitted qualification program.
use super::model::{Metadata, Statement};
use anyhow::{ensure, Result};
use num_traits::Zero;
use stwo::core::fields::qm31::SecureField as Q;
pub const MAIN: usize = 2371;
pub const FIXED: usize = 229;
pub const CLOCK: usize = 2248;
pub const OFFSET: usize = 2352;
pub const PROGRAM: [u32; 5] = [0x00108093, 0x00108093, 0x00113023, 0x00013183, 0x001181b3];
pub fn byte(w: usize, i: usize) -> usize {
    72 * w + i
}
pub fn bit(w: usize, i: usize) -> usize {
    72 * w + 8 + i
}
pub fn carry(k: usize, i: usize) -> usize {
    1584 + 8 * k + i
}
pub fn prev(slot: usize) -> usize {
    CLOCK + 26 * slot
}
pub fn gap(slot: usize) -> usize {
    prev(slot) + 13
}
pub fn q(x: u32) -> Q {
    Q::from(x)
}
pub fn opcode(f: &[Q], op: usize) -> Q {
    f[3 + op]
}
pub fn validate(s: &Statement, meta: &Metadata) -> Result<()> {
    ensure!(
        s.program_addresses.is_empty() && s.program == PROGRAM && s.steps == 5,
        "unsupported qualification program"
    );
    ensure!(
        s.program_base % 4 == 0
            && s.program_base.checked_add(20) == Some(s.final_pc)
            && s.initial_pc == s.program_base,
        "invalid PCs"
    );
    ensure!(
        s.initial_registers[0] == 0 && s.final_registers[0] == 0,
        "nonzero x0"
    );
    ensure!(
        meta.path == (0..5).map(|i| s.program_base + 4 * i).collect::<Vec<_>>()
            && meta.register_clocks[0] == 0,
        "invalid path/clocks"
    );
    ensure!(
        s.memory.len() == 1 && meta.memory_clocks.len() == 1,
        "qualification requires one explicit memory cell"
    );
    ensure!(
        meta.register_clocks
            .iter()
            .chain(&meta.memory_clocks)
            .all(|c| *c <= 20),
        "clock out of range"
    );
    let cell = &s.memory[0];
    ensure!(
        cell.address % 8 == 0 && cell.address <= u64::MAX - 7,
        "unaligned memory"
    );
    ensure!(
        cell.address + 7 < s.program_base || cell.address >= s.final_pc,
        "program/RAM overlap"
    );
    ensure!(
        cell.writable || cell.initial == cell.final_value,
        "readonly final mismatch"
    );
    Ok(())
}
#[derive(Clone)]
pub struct Layout {
    pub rows: Vec<[u32; FIXED]>,
    pub fixed_map: Vec<Option<usize>>,
    pub fixed_sources: Vec<usize>,
    pub main_sources: Vec<usize>,
}
impl Layout {
    pub fn derive(s: &Statement, meta: &Metadata) -> Result<Self> {
        validate(s, meta)?;
        let mut rows = vec![[0; FIXED]; 32];
        for (i, r) in rows.iter_mut().enumerate() {
            r[1] = u32::from(i == 0);
            r[2] = u32::from(i == 31);
            if i >= 5 {
                continue;
            }
            let word = s.program[i];
            let op = match i {
                0 | 1 => 10,
                2 => 38,
                3 => 31,
                _ => 0,
            };
            let (a, b, d) = ((word >> 15) & 31, (word >> 20) & 31, (word >> 7) & 31);
            let reads_b = i == 2 || i == 4;
            let writes = i != 2;
            let mem = i == 2 || i == 3;
            let slots = [a != 0, reads_b && b != 0, writes && d != 0, mem];
            r[0] = 1;
            r[3 + op] = 1;
            r[68] = a;
            r[69] = if slots[1] { b } else { 0 };
            r[70] = if slots[2] { d } else { 0 };
            for j in 0..4 {
                r[71 + j] = u32::from(slots[j]);
                r[75 + j] = if slots[j] { (4 * i + j + 1) as u32 } else { 0 };
            }
            let pc = s.program_base + 4 * i as u64;
            let imm = if i < 2 { 1 } else { 0 };
            for (start, value) in [
                (79, imm),
                (87, pc),
                (95, pc + 4),
                (103, pc + 4),
                (111, pc + imm),
            ] {
                for j in 0..8 {
                    r[start + j] = ((value >> (8 * j)) & 255) as u32;
                }
            }
            let active = [
                slots[0],
                slots[1],
                writes,
                slots[2],
                mem,
                mem,
                mem,
                i < 2 || i == 4,
            ];
            for w in 0..8 {
                r[119 + w] = u32::from(active[w]);
            }
            for j in 0..8 {
                r[141 + j] = u32::from(i < 2 || i == 4);
                r[141 + 16 + j] = u32::from(mem);
            }
        }
        let mut fixed_sources = vec![];
        let mut fixed_map = vec![];
        for c in 0..FIXED {
            if rows.iter().all(|r| r[c] == rows[0][c]) {
                fixed_map.push(None);
                continue;
            }
            let same = fixed_sources
                .iter()
                .position(|old: &usize| rows.iter().all(|r| r[c] == r[*old]));
            let index = same.unwrap_or_else(|| {
                fixed_sources.push(c);
                fixed_sources.len() - 1
            });
            fixed_map.push(Some(index));
        }
        let mut main_sources = vec![];
        for w in 0..22 {
            if rows.iter().any(|r| r[119 + w] != 0) {
                for i in 0..64 {
                    main_sources.push(bit(w, i));
                }
            }
        }
        for i in 0..88 {
            if rows.iter().any(|r| r[141 + i] != 0) {
                main_sources.push(1584 + i);
            }
        }
        for slot in 0..4 {
            if rows.iter().any(|r| r[71 + slot] != 0) {
                for start in [prev(slot), gap(slot)] {
                    for i in 0..12 {
                        main_sources.push(start + 1 + i);
                    }
                }
            }
        }
        main_sources.extend(OFFSET..MAIN);
        ensure!(
            fixed_sources.len() == 21 && main_sources.len() == 643,
            "layout derivation mismatch"
        );
        Ok(Self {
            rows,
            fixed_map,
            fixed_sources,
            main_sources,
        })
    }
    pub fn inflate(&self, fixed: &[Q], main: &[Q]) -> (Vec<Q>, Vec<Q>) {
        let f = (0..FIXED)
            .map(|i| {
                self.fixed_map[i]
                    .map(|p| fixed[p])
                    .unwrap_or_else(|| q(self.rows[0][i]))
            })
            .collect();
        let mut m = vec![Q::zero(); MAIN];
        for (p, &c) in self.main_sources.iter().enumerate() {
            m[c] = main[p];
        }
        for w in 0..22 {
            for i in 0..8 {
                m[byte(w, i)] = (0..8).map(|j| m[bit(w, 8 * i + j)] * q(1 << j)).sum();
            }
        }
        for slot in 0..4 {
            for start in [prev(slot), gap(slot)] {
                m[start] = (0..12).map(|j| m[start + 1 + j] * q(1 << j)).sum();
            }
        }
        (f, m)
    }
}

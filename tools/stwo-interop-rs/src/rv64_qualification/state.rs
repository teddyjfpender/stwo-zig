use super::{
    layout::*,
    local::Sink,
    model::{Metadata, Statement},
};
use anyhow::{ensure, Result};
use num_traits::{One, Zero};
use stwo::core::{
    channel::{Blake2sChannel, Channel},
    fields::{qm31::SecureField as Q, FieldExpOps},
};
#[derive(Clone)]
pub struct Challenges {
    pub offset: Q,
    pub coefficients: [Q; 20],
}
impl Challenges {
    pub fn draw(channel: &mut Blake2sChannel) -> Self {
        channel.mix_u32s(&[0x52563634, 0x53544154, 1]);
        Self {
            offset: channel.draw_secure_felt(),
            coefficients: std::array::from_fn(|_| channel.draw_secure_felt()),
        }
    }
    pub fn denominator(&self, t: &[Q; 20]) -> Q {
        self.offset
            + t.iter()
                .zip(self.coefficients)
                .map(|(x, c)| *x * c)
                .sum::<Q>()
    }
    pub fn expected(&self, s: &Statement, meta: &Metadata) -> Result<Q> {
        let mut sum = Q::zero();
        for reg in 1..32 {
            sum += self.inverse(&boundary(
                0,
                reg as u64,
                0,
                s.initial_registers[reg],
                true,
                true,
            ))? - self.inverse(&boundary(
                0,
                reg as u64,
                meta.register_clocks[reg],
                s.final_registers[reg],
                true,
                true,
            ))?;
        }
        for (cell, clock) in s.memory.iter().zip(&meta.memory_clocks) {
            sum += self.inverse(&boundary(
                1,
                cell.address,
                0,
                cell.initial,
                cell.readable,
                cell.writable,
            ))? - self.inverse(&boundary(
                1,
                cell.address,
                *clock,
                cell.final_value,
                cell.readable,
                cell.writable,
            ))?;
        }
        Ok(sum)
    }
    fn inverse(&self, t: &[Q; 20]) -> Result<Q> {
        let value = self.denominator(t);
        ensure!(!value.is_zero(), "zero relation denominator");
        Ok(value.inverse())
    }
    pub fn evaluate(
        &self,
        f: &[Q],
        m: &[Q],
        current: &[Q],
        previous: &[Q],
        target: Q,
        s: &mut Sink,
    ) {
        let mut contribution = Q::zero();
        for slot in 0..4 {
            let active = f[71 + slot];
            let before = secure(current, 8 * slot);
            let after = secure(current, 8 * slot + 4);
            s.emit(self.denominator(&tuple(f, m, slot, true)) * before - active);
            s.emit(self.denominator(&tuple(f, m, slot, false)) * after - active);
            s.emit((Q::one() - active) * before);
            s.emit((Q::one() - active) * after);
            contribution += before - after;
        }
        let sum = secure(current, 32);
        s.emit(sum - (Q::one() - f[1]) * secure(previous, 32) - contribution);
        s.emit(f[2] * (sum - target));
    }
}
fn boundary(space: u32, address: u64, clock: u16, value: u64, read: bool, write: bool) -> [Q; 20] {
    let mut t = [Q::zero(); 20];
    t[0] = q(space);
    t[9] = q(clock as u32);
    for i in 0..8 {
        t[1 + i] = q(((address >> (8 * i)) & 255) as u32);
        t[10 + i] = q(((value >> (8 * i)) & 255) as u32);
    }
    t[18] = q(read as u32);
    t[19] = q(write as u32);
    t
}
fn tuple(f: &[Q], m: &[Q], slot: usize, before: bool) -> [Q; 20] {
    let mut t = [Q::zero(); 20];
    if slot < 3 {
        t[1] = f[68 + slot];
        let word = match slot {
            0 => 0,
            1 => 1,
            _ => {
                if before {
                    3
                } else {
                    2
                }
            }
        };
        for i in 0..8 {
            t[10 + i] = m[byte(word, i)];
        }
        t[18] = Q::one();
        t[19] = Q::one();
    } else {
        t[0] = Q::one();
        for i in 0..8 {
            t[1 + i] = m[byte(6, i)];
            t[10 + i] = m[byte(if before { 4 } else { 5 }, i)];
        }
        t[1] = t[1] - m[bit(6, 0)] - q(2) * m[bit(6, 1)] - q(4) * m[bit(6, 2)];
        t[18] = m[2360];
        t[19] = m[2361];
    }
    t[9] = if before { m[prev(slot)] } else { f[75 + slot] };
    t
}
pub fn secure(values: &[Q], start: usize) -> Q {
    values[start]
        + values[start + 1] * Q::from_u32_unchecked(0, 1, 0, 0)
        + values[start + 2] * Q::from_u32_unchecked(0, 0, 1, 0)
        + values[start + 3] * Q::from_u32_unchecked(0, 0, 0, 1)
}
pub fn mix(channel: &mut Blake2sChannel, s: &Statement, meta: &Metadata) {
    channel.mix_u32s(&[0x52563634, 0x424e4431, 2, 229, 2371, 36, 4, 5, 5]);
    super::model::config().mix_into(channel);
    channel.mix_u64(s.program_base);
    channel.mix_u64(s.initial_pc);
    channel.mix_u64(s.final_pc);
    channel.mix_u64(s.program.len() as u64);
    channel.mix_u32s(&s.program);
    for values in [&s.initial_registers, &s.final_registers] {
        for value in values {
            channel.mix_u64(*value);
        }
    }
    channel.mix_u64(s.memory.len() as u64);
    for cell in &s.memory {
        for value in [cell.address, cell.initial, cell.final_value] {
            channel.mix_u64(value);
        }
        channel.mix_u32s(&[cell.readable as u32, cell.writable as u32]);
    }
    for pc in &meta.path {
        channel.mix_u64(*pc);
    }
    for clock in &meta.register_clocks {
        channel.mix_u32s(&[*clock as u32]);
    }
    for clock in &meta.memory_clocks {
        channel.mix_u32s(&[*clock as u32]);
    }
}

//! Native-only diagnostics for the existing RV64 Montgomery client branches.
//! Counters do not replace arithmetic and are never compiled into RV64.
extern crate std;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    vec::Vec,
};
#[derive(Clone, Copy)]
pub enum Op {
    Mul,
    Square,
    Decode,
    Inverse,
}
#[derive(Default, Clone, Copy)]
pub struct Counts {
    pub mul: u64,
    pub square: u64,
    pub decode: u64,
    pub inverse: u64,
}
#[derive(Clone)]
pub struct Row {
    pub limbs: usize,
    pub modulus: [u64; 6],
    pub counts: Counts,
}
std::thread_local! {static COUNTS:RefCell<Option<BTreeMap<(usize,[u64;6]),Counts>>>=const{RefCell::new(None)};}
std::thread_local! {static SUPPRESS:Cell<usize>=const{Cell::new(0)};}
pub struct Pause;
pub fn pause() -> Pause {
    SUPPRESS.with(|s| s.set(s.get() + 1));
    Pause
}
impl Drop for Pause {
    fn drop(&mut self) {
        SUPPRESS.with(|s| s.set(s.get() - 1));
    }
}
pub fn begin() {
    COUNTS.with_borrow_mut(|c| {
        assert!(c.is_none(), "nested field census");
        *c = Some(BTreeMap::new())
    });
}
pub fn finish() -> Vec<Row> {
    COUNTS.with_borrow_mut(|c| {
        c.take()
            .unwrap_or_default()
            .into_iter()
            .map(|((limbs, modulus), counts)| Row {
                limbs,
                modulus,
                counts,
            })
            .collect()
    })
}
pub fn record<const N: usize>(modulus: &[u64; N], op: Op) {
    if SUPPRESS.with(|s| s.get() != 0) {
        return;
    }
    COUNTS.with_borrow_mut(|c| {
        let Some(rows) = c else { return };
        assert!(N == 4 || N == 6);
        let mut key = [0; 6];
        key[..N].copy_from_slice(modulus);
        assert!(
            rows.len() < 16 || rows.contains_key(&(N, key)),
            "native field census class cap"
        );
        let row = rows.entry((N, key)).or_default();
        match op {
            Op::Mul => row.mul += 1,
            Op::Square => row.square += 1,
            Op::Decode => row.decode += 1,
            Op::Inverse => row.inverse += 1,
        }
    });
}
pub fn product<const N: usize>(a: &[u64; N], b: &[u64; N], one: &[u64; N]) -> bool {
    a.iter().any(|x| *x != 0) && b.iter().any(|x| *x != 0) && a != one && b != one
}

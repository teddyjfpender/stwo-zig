//! Optional, committed optimization data after the canonical SSZ input prefix.
//! Neither the bits nor collection output are cryptographic validity receipts.
use alloc::vec::Vec;
use core::cell::RefCell;
use critical_section::Mutex;

pub const MAGIC: &[u8; 8] = b"STWECR01";
#[derive(Debug, PartialEq, Eq)]
pub enum Error { Truncated, InvalidMagic, NoncanonicalPadding }

pub fn decode(bytes: &[u8]) -> Result<Option<(u32, Vec<u8>)>, Error> {
    if bytes.is_empty() || (bytes.len() >= 8 && bytes[..8] == [0; 8]) { return Ok(None); }
    if bytes.len() < 12 { return Err(Error::Truncated); }
    if &bytes[..8] != MAGIC { return Err(Error::InvalidMagic); }
    let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let size = (u64::from(count) + 7) / 8;
    if size > (bytes.len() - 12) as u64 { return Err(Error::Truncated); }
    let bits = &bytes[12..12 + size as usize];
    if count % 8 != 0 && bits.last().copied().unwrap_or(0) >> (count % 8) != 0 {
        return Err(Error::NoncanonicalPadding);
    }
    Ok(Some((count, bits.to_vec())))
}
pub fn encode(count: u32, bits: &[u8]) -> Vec<u8> {
    assert_eq!(bits.len() as u64, (u64::from(count) + 7) / 8);
    let mut out = Vec::with_capacity(12 + bits.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(bits);
    assert!(decode(&out).is_ok());
    out
}
struct State {
    supplied: Option<(u32, Vec<u8>)>,
    cursor: u32,
    observed: Vec<u8>,
}
static STATE: Mutex<RefCell<State>> = Mutex::new(RefCell::new(State {
    supplied: None, cursor: 0, observed: Vec::new(),
}));
pub fn initialize(bytes: &[u8]) {
    let supplied = if cfg!(feature = "collect-evm-hints") { None } else { decode(bytes).expect("invalid EVM hint footer") };
    critical_section::with(|cs| *STATE.borrow(cs).borrow_mut() = State { supplied, cursor: 0, observed: Vec::new() });
}
pub fn next() -> bool {
    critical_section::with(|cs| {
        let mut state = STATE.borrow(cs).borrow_mut();
        let selected = match &state.supplied {
            None => false,
            Some((count, bits)) => {
                assert!(state.cursor < *count, "missing EVM recovery hint");
                bits[state.cursor as usize / 8] & (1 << (state.cursor % 8)) != 0
            }
        };
        state.cursor = state.cursor.checked_add(1).expect("EVM hint count overflow");
        selected
    })
}
pub fn observe(success: bool) {
    critical_section::with(|cs| {
        let mut state = STATE.borrow(cs).borrow_mut();
        if state.cursor % 8 == 0 { state.observed.push(0); }
        let bit = state.cursor % 8;
        if success { *state.observed.last_mut().unwrap() |= 1 << bit; }
        state.cursor = state.cursor.checked_add(1).expect("EVM hint count overflow");
    });
}
pub fn finish(mut output: Vec<u8>) -> Vec<u8> {
    critical_section::with(|cs| {
        let state = STATE.borrow(cs).borrow();
        if cfg!(feature = "collect-evm-hints") {
            output.extend_from_slice(&encode(state.cursor, &state.observed));
        } else if let Some((count, _)) = state.supplied {
            assert_eq!(state.cursor, count, "unused EVM recovery hints");
        }
    });
    output
}

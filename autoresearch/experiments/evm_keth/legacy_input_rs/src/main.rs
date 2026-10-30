//! Typed legacy witness validation and frozen STWZCPI v1 emission.
//! No AIR, execution witness value, or proof policy is modified.
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;

const OPCODES: [&str; 20] = [
    "generic_opcode",
    "add_ap_opcode",
    "add_opcode",
    "add_opcode_small",
    "assert_eq_opcode",
    "assert_eq_opcode_double_deref",
    "assert_eq_opcode_imm",
    "call_opcode",
    "call_opcode_rel_imm",
    "jnz_opcode",
    "jnz_opcode_taken",
    "jump_opcode_rel_imm",
    "jump_opcode_rel",
    "jump_opcode_double_deref",
    "jump_opcode",
    "mul_opcode_small",
    "mul_opcode",
    "ret_opcode",
    "blake_compress_opcode",
    "qm_31_add_mul_opcode",
];
const BUILTINS: [&str; 8] = [
    "add_mod",
    "bitwise",
    "output",
    "mul_mod",
    "pedersen",
    "poseidon",
    "range_check_bits_96",
    "range_check_bits_128",
];

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct State {
    pc: u32,
    ap: u32,
    fp: u32,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Transitions {
    initial_state: State,
    final_state: State,
    casm_states_by_opcode: BTreeMap<String, Vec<State>>,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MemoryConfig {
    small_max: u128,
    log_small_value_capacity: u32,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Memory {
    config: MemoryConfig,
    address_to_id: Vec<u32>,
    f252_values: Vec<[u32; 8]>,
    small_values: Vec<u128>,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Segment {
    begin_addr: u64,
    stop_ptr: u64,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PublicContext {
    present: [bool; 11],
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Input {
    state_transitions: Transitions,
    memory: Memory,
    inst_cache: Vec<(u32, u128)>,
    public_memory_addresses: Vec<u32>,
    builtin_segments: BTreeMap<String, Option<Segment>>,
    public_segment_context: PublicContext,
}
#[derive(Deserialize)]
struct Compiled {
    data: Vec<serde_json::Value>,
}

fn limbs(value: u128) -> [u32; 8] {
    let mut result = [0; 8];
    for (i, cell) in result[..4].iter_mut().enumerate() {
        *cell = (value >> (32 * i)) as u32;
    }
    result
}

fn program_cell(value: &serde_json::Value) -> Result<[u32; 8]> {
    if let Some(number) = value.as_u64() {
        return Ok(limbs(number.into()));
    }
    let hex = value
        .as_str()
        .context("compiled cell must be hex or an integer")?;
    let hex = hex
        .strip_prefix("0x")
        .context("compiled cell is not hexadecimal")?;
    ensure!(
        !hex.is_empty() && hex.len() <= 64,
        "invalid compiled field width"
    );
    let mut result = [0; 8];
    for (i, end) in (1..=hex.len()).rev().step_by(8).enumerate() {
        result[i] = u32::from_str_radix(&hex[end.saturating_sub(8)..end], 16)?;
    }
    Ok(result)
}

impl Memory {
    fn value(&self, address: u32) -> Result<[u32; 8]> {
        let id = *self
            .address_to_id
            .get(address as usize)
            .context("memory address out of range")?;
        ensure!(
            id != 0x3fffffff,
            "uninitialized public/instruction address {address}"
        );
        if id & 0x40000000 != 0 {
            Ok(*self
                .f252_values
                .get((id & 0x3fffffff) as usize)
                .context("f252 ID out of range")?)
        } else {
            Ok(limbs(
                *self
                    .small_values
                    .get(id as usize)
                    .context("small ID out of range")?,
            ))
        }
    }
}

fn validate(input: &Input, program: &Compiled) -> Result<()> {
    let config = &input.memory.config;
    ensure!(
        config.small_max == (1u128 << 72) - 1 && config.log_small_value_capacity == 24,
        "unsupported memory configuration"
    );
    ensure!(
        input.state_transitions.casm_states_by_opcode.len() == OPCODES.len()
            && OPCODES.iter().all(|name| input
                .state_transitions
                .casm_states_by_opcode
                .contains_key(*name)),
        "unsupported opcode schema"
    );
    ensure!(
        input.builtin_segments.len() == BUILTINS.len()
            && BUILTINS
                .iter()
                .all(|name| input.builtin_segments.contains_key(*name)),
        "unsupported builtin schema"
    );
    let public: HashSet<u32> = input.public_memory_addresses.iter().copied().collect();
    for (index, value) in program.data.iter().enumerate() {
        let address = u32::try_from(index + 1)?;
        ensure!(
            public.contains(&address) && input.memory.value(address)? == program_cell(value)?,
            "compiled program not bound at address {address}"
        );
    }
    let cache: HashMap<u32, u128> = input.inst_cache.iter().copied().collect();
    ensure!(
        cache.len() == input.inst_cache.len(),
        "duplicate instruction cache address"
    );
    for (&address, &value) in &cache {
        ensure!(
            input.memory.value(address)? == limbs(value),
            "instruction cache disagrees with memory"
        );
    }
    ensure!(
        input
            .state_transitions
            .casm_states_by_opcode
            .values()
            .flatten()
            .all(|s| cache.contains_key(&s.pc)),
        "instruction cache does not cover execution"
    );
    Ok(())
}

fn encode(input: &Input, out: &mut impl Write) -> Result<()> {
    macro_rules! put {
        ($value:expr) => {
            out.write_all(&$value.to_le_bytes())?
        };
    }
    out.write_all(b"STWZCPI\0")?;
    put!(1u32);
    put!(0u32);
    for state in [
        &input.state_transitions.initial_state,
        &input.state_transitions.final_state,
    ] {
        put!(state.pc);
        put!(state.ap);
        put!(state.fp);
    }
    put!(input.inst_cache.len() as u64);
    let mask = input
        .public_segment_context
        .present
        .iter()
        .enumerate()
        .fold(0u16, |mask, (i, v)| mask | (u16::from(*v) << i));
    put!(mask);
    put!(0u16);
    put!(0u32);
    put!(20u32);
    put!(0u32);
    for name in OPCODES {
        let states = &input.state_transitions.casm_states_by_opcode[name];
        put!(states.len() as u64);
        for state in states {
            put!(state.pc);
            put!(state.ap);
            put!(state.fp);
        }
    }
    let memory = &input.memory;
    put!(memory.config.small_max);
    put!(memory.config.log_small_value_capacity);
    put!(0u32);
    put!(memory.address_to_id.len() as u64);
    put!(memory.f252_values.len() as u64);
    put!(memory.small_values.len() as u64);
    for &value in &memory.address_to_id {
        put!(value);
    }
    for value in &memory.f252_values {
        for &limb in value {
            put!(limb);
        }
    }
    for &value in &memory.small_values {
        put!(value);
    }
    put!(input.public_memory_addresses.len() as u64);
    for &address in &input.public_memory_addresses {
        put!(address);
    }
    for segment in BUILTINS
        .iter()
        .map(|name| input.builtin_segments[*name].as_ref())
        .chain([None])
    {
        out.write_all(&[u8::from(segment.is_some())])?;
        out.write_all(&[0; 7])?;
        put!(segment.map_or(0u64, |s| s.begin_addr));
        put!(segment.map_or(0u64, |s| s.stop_ptr));
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut values = BTreeMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(key) = args.next() {
        ensure!(
            [
                "--source",
                "--compiled",
                "--target",
                "--receipt",
                "--compare-left",
                "--compare-right"
            ]
            .contains(&key.as_str()),
            "unknown argument {key}"
        );
        let value = args.next().context("missing argument value")?;
        ensure!(
            values.insert(key, PathBuf::from(value)).is_none(),
            "duplicate argument"
        );
    }
    if values.contains_key("--compare-left") || values.contains_key("--compare-right") {
        ensure!(
            values.len() == 3
                && values.contains_key("--receipt")
                && values.contains_key("--compare-left")
                && values.contains_key("--compare-right"),
            "required: --compare-left --compare-right --receipt"
        );
        fn read(path: &PathBuf) -> Result<Input> {
            Ok(serde_json::from_reader(BufReader::with_capacity(
                3 * 1024 * 1024,
                std::fs::File::open(path)?,
            ))?)
        }
        let mut left = read(&values["--compare-left"])?;
        let mut right = read(&values["--compare-right"])?;
        // Cache vector iteration order is not part of the witness statement.
        left.inst_cache.sort_unstable();
        right.inst_cache.sort_unstable();
        ensure!(left == right, "typed witness contents differ");
        let receipt = serde_json::json!({"schema":"keth-typed-witness-comparison-v1",
            "equal":true, "memory_addresses":left.memory.address_to_id.len(),
            "memory_big_values":left.memory.f252_values.len(), "memory_small_values":left.memory.small_values.len(),
            "execution_steps":left.state_transitions.casm_states_by_opcode.values().map(Vec::len).sum::<usize>(),
            "instruction_cache_order_ignored":true});
        serde_json::to_writer_pretty(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&values["--receipt"])?,
            &receipt,
        )?;
        return Ok(());
    }
    if values.len() != 4
        || !["--source", "--compiled", "--target", "--receipt"]
            .iter()
            .all(|key| values.contains_key(*key))
    {
        bail!("required: --source --compiled --target --receipt");
    }
    ensure!(
        !values["--target"].exists() && !values["--receipt"].exists(),
        "target and receipt must be fresh"
    );
    let source = std::fs::File::open(&values["--source"])?;
    let input: Input = serde_json::from_reader(BufReader::with_capacity(3 * 1024 * 1024, source))?;
    let compiled: Compiled = serde_json::from_slice(&std::fs::read(&values["--compiled"])?)?;
    validate(&input, &compiled)?;
    let mut output = BufWriter::with_capacity(
        1 << 20,
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&values["--target"])?,
    );
    encode(&input, &mut output)?;
    output.flush()?;
    let receipt = serde_json::json!({"schema": "keth-legacy-input-conversion-v1",
        "from_stwo_cairo": "92232543984e20e984c5a7194561ff1fffa76dae",
        "to_stwo_cairo": "82f21252a68ec006d73e299f5bf1ce6d4db0ee78",
        "compiled_program_cells_checked": compiled.data.len(), "instruction_cache_cells_checked": input.inst_cache.len(),
        "execution_steps": input.state_transitions.casm_states_by_opcode.values().map(Vec::len).sum::<usize>(),
        "transport": "compact-v1", "implementation": "typed-rust-v1"});
    serde_json::to_writer_pretty(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&values["--receipt"])?,
        &receipt,
    )?;
    Ok(())
}

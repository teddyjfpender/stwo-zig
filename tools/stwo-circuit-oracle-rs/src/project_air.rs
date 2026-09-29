//! `project-air`: the constraints-only projection of the compiled AIR
//! (`compiled_air_constraints_v1.bin`), read by the Zig in-circuit evaluator interpreter.
//!
//! The projection keeps exactly what `air_code_gen/src/circuit/component.rs` reads to emit a
//! generated in-circuit evaluator, for every compiled function whose evaluator upstream generates
//! (hand-written ones are listed by name and excluded). Tuple felts of lookup terms are trimmed
//! with the upstream `remove_trailing_zeroes`, and the sorted atom lists are computed with the
//! upstream `expr_iterator`, so no generator rule is re-implemented here.
//!
//! # Format (version 2)
//!
//! All integers are little-endian. `str` is a `u32` index into the string table; `list<T>` is a
//! `u32` count followed by the items; `opt<T>` is a `u8` (0 absent, 1 present) followed by the
//! item when present.
//!
//! ```text
//! file      := "STWOCAIR" u32:version strings str:revision str:inputs_sha256 constants sources
//! strings   := u32:n (u32:len utf8[len])*
//! constants := list<(str:name u32:value)>
//! sources   := list<source>
//! source    := str:label list<str>:slots list<str>:hand_written list<function>
//! function  := u32:len [32]:sha256(canonical(record)) record[len]
//! record    := str:name str:trace_type opt<u32>:log_height list<str>:verifier_input_limbs
//!              list<str>:state_names list<(str:relation u8:use_or_yield)>:constraint_lookups
//!              list<str>:external_states list<str>:public_params
//!              list<str>:used_external_states list<str>:used_public_params
//!              list<step>:constraints opt<expr>:verifier_output
//! step      := 0 expr                                  Constraint
//!            | 1 list<str>:felt_names expr             Intermediate
//!            | 2 str:relation u8:use_or_yield list<expr>:felts expr:multiplicity   LookupTerm
//! expr      := 0 u32:m31            Const (canonical, below P)
//!            | 1 str:name           Var
//!            | 2 str:name           State
//!            | 3 u8:op expr expr    BinaryOp (op 0 '+', 1 '-', 2 '*')
//!            | 4 u8:op expr         UnaryOp (op 1 '-')
//!            | 5 str:callee list<expr>:arguments   StaticCall; `callee` is the called function
//!                                   (the `::evaluate` suffix removed) and `arguments` are the
//!                                   first-argument array items followed by the other arguments
//!            | 6 list<expr>         Array
//!            | 7 str:id             ExternalState
//!            | 8 str:name           PublicParam
//!            | 9                    Enabler
//! ```
//!
//! `canonical(record)` is `record` with every `str` written inline as `u32:len utf8[len]` instead
//! of as a string-table index, so a function digest depends only on the function itself and not
//! on the order in which the whole file interned its strings (version 1 hashed the indexed
//! record).
//!
//! `use_or_yield` is 0 for `Use` and 1 for `Yield`. `slots` is the upstream evaluator order of the
//! source (`all_components` for Cairo, `all_circuit_components` for the circuit AIR).

use std::collections::HashSet;
use std::path::Path;

use air_code_gen::utils::{expr_iterator, remove_trailing_zeroes};
use air_common::{CONSTRAINT_EVAL_FUNCTION_NAME, UseOrYield};
use air_compile::compiled_structs::{
    CompiledAirFn, CompiledAirVar, CompiledConstraintIntermediate, ConstraintEvalStep, LookupTerm,
};
use anyhow::{Context, Result, bail, ensure};
use circuits::ivalue::NoValue;
use indexmap::IndexMap;
use sha2::{Digest, Sha256};
use stwo::core::fields::m31::P;

use crate::checkpoint::PROVING_REVISION;
use crate::compiled_air::{self, AirSource, CAIRO_AIR, CIRCUIT_AIR, CompiledAir};
use crate::upstream::{self, ProvingRoot};

const MAGIC: &[u8; 8] = b"STWOCAIR";
const VERSION: u32 = 2;

/// Upstream constants the hand-written Cairo evaluators and the Cairo statement depend on.
fn constants() -> [(&'static str, u32); 3] {
    [
        (
            "LARGE_MEMORY_VALUE_ID_BASE",
            stwo_cairo_common::memory::LARGE_MEMORY_VALUE_ID_BASE,
        ),
        (
            "MAX_SEQUENCE_LOG_SIZE",
            stwo_cairo_common::preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE,
        ),
        (
            "MEMORY_ADDRESS_TO_ID_SPLIT",
            u32::try_from(cairo_air::components::memory_address_to_id::MEMORY_ADDRESS_TO_ID_SPLIT)
                .expect("split fits u32"),
        ),
    ]
}

#[derive(Default)]
struct Strings {
    table: IndexMap<String, u32>,
}

impl Strings {
    fn index(&mut self, value: &str) -> u32 {
        let next = self.table.len() as u32;
        *self.table.entry(value.to_owned()).or_insert(next)
    }
}

/// A byte sink that interns every string it writes. `canonical` receives the same bytes with every
/// string written inline instead of as an index; it is the preimage of a function digest.
struct Writer<'a> {
    bytes: Vec<u8>,
    canonical: Vec<u8>,
    strings: &'a mut Strings,
}

impl<'a> Writer<'a> {
    fn new(strings: &'a mut Strings) -> Self {
        Self {
            bytes: Vec::new(),
            canonical: Vec::new(),
            strings,
        }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
        self.canonical.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self.canonical.extend_from_slice(&value.to_le_bytes());
    }

    fn len(&mut self, len: usize) -> Result<()> {
        self.u32(u32::try_from(len).context("list longer than u32")?);
        Ok(())
    }

    fn str(&mut self, value: &str) {
        let index = self.strings.index(value);
        self.bytes.extend_from_slice(&index.to_le_bytes());
        let len = u32::try_from(value.len()).expect("string longer than u32");
        self.canonical.extend_from_slice(&len.to_le_bytes());
        self.canonical.extend_from_slice(value.as_bytes());
    }

    fn strs<S: AsRef<str>>(&mut self, values: impl ExactSizeIterator<Item = S>) -> Result<()> {
        self.len(values.len())?;
        values.for_each(|value| self.str(value.as_ref()));
        Ok(())
    }

    fn use_or_yield(&mut self, value: &UseOrYield) {
        self.u8(match value {
            UseOrYield::Use => 0,
            UseOrYield::Yield => 1,
        });
    }

    fn exprs(&mut self, exprs: &[CompiledAirVar]) -> Result<()> {
        self.len(exprs.len())?;
        exprs.iter().try_for_each(|expr| self.expr(expr))
    }

    fn expr(&mut self, expr: &CompiledAirVar) -> Result<()> {
        match expr {
            CompiledAirVar::Const(ty, text) => {
                ensure!(ty == "M31", "constant of type {ty} in the constraint path");
                let value: u32 = text.parse().with_context(|| format!("constant {text:?}"))?;
                ensure!(
                    value < P && value.to_string() == *text,
                    "constant {text:?} is not canonical"
                );
                self.u8(0);
                self.u32(value);
            }
            CompiledAirVar::Var(_, name) => {
                self.u8(1);
                self.str(name);
            }
            CompiledAirVar::State(name) => {
                self.u8(2);
                self.str(name);
            }
            CompiledAirVar::BinaryOp(lhs, op, rhs) => {
                self.u8(3);
                self.u8(match op.as_str() {
                    "+" => 0,
                    "-" => 1,
                    "*" => 2,
                    other => bail!("binary operator {other:?} in the constraint path"),
                });
                self.expr(lhs)?;
                self.expr(rhs)?;
            }
            CompiledAirVar::UnaryOp(op, operand) => {
                ensure!(op == "-", "unary operator {op:?} in the constraint path");
                self.u8(4);
                self.u8(1);
                self.expr(operand)?;
            }
            CompiledAirVar::StaticCall(callee, arguments) => {
                let suffix = format!("::{CONSTRAINT_EVAL_FUNCTION_NAME}");
                let callee = callee
                    .strip_suffix(&suffix)
                    .with_context(|| format!("static call {callee} is not a constraint call"))?;
                let Some((CompiledAirVar::Array(inputs), rest)) = arguments.split_first() else {
                    bail!("static call {callee}: first argument is not an array");
                };
                self.u8(5);
                self.str(callee);
                self.len(inputs.len() + rest.len())?;
                inputs
                    .iter()
                    .chain(rest)
                    .try_for_each(|argument| self.expr(argument))?;
            }
            CompiledAirVar::Array(items) => {
                self.u8(6);
                self.exprs(items)?;
            }
            CompiledAirVar::ExternalState(id) => {
                self.u8(7);
                self.str(id);
            }
            CompiledAirVar::PublicParam(name) => {
                self.u8(8);
                self.str(name);
            }
            CompiledAirVar::Enabler => self.u8(9),
            other => bail!("unsupported expression in the constraint path: {other:?}"),
        }
        Ok(())
    }

    fn step(&mut self, step: &ConstraintEvalStep) -> Result<()> {
        match step {
            ConstraintEvalStep::Constraint(expr, _description) => {
                self.u8(0);
                self.expr(expr)
            }
            ConstraintEvalStep::Intermediate(CompiledConstraintIntermediate {
                felt_names,
                var,
            }) => {
                self.u8(1);
                self.strs(felt_names.iter())?;
                self.expr(var)
            }
            ConstraintEvalStep::LookupTerm(LookupTerm {
                relation_name,
                felts,
                use_or_yield,
                multiplicity,
            }) => {
                self.u8(2);
                self.str(relation_name);
                self.use_or_yield(use_or_yield);
                self.exprs(&remove_trailing_zeroes(felts))?;
                self.expr(multiplicity)
            }
        }
    }
}

/// The sorted external states and public parameters the constraints read, collected as the
/// generator's `get_constraint_atoms` does.
fn used_atoms(air_fn: &CompiledAirFn) -> (Vec<String>, Vec<String>) {
    let mut external_states = HashSet::new();
    let mut public_params = HashSet::new();
    let mut visit = |expr: &CompiledAirVar| match expr {
        CompiledAirVar::ExternalState(id) => {
            external_states.insert(id.clone());
        }
        CompiledAirVar::PublicParam(name) => {
            public_params.insert(name.clone());
        }
        _ => {}
    };
    for step in &air_fn.constraints {
        match step {
            ConstraintEvalStep::Constraint(expr, _) => expr_iterator(expr, &mut visit),
            ConstraintEvalStep::LookupTerm(term) => {
                term.felts
                    .iter()
                    .for_each(|felt| expr_iterator(felt, &mut visit));
                expr_iterator(&term.multiplicity, &mut visit);
            }
            ConstraintEvalStep::Intermediate(intermediate) => {
                expr_iterator(&intermediate.var, &mut visit)
            }
        }
    }
    let mut external_states: Vec<String> = external_states.into_iter().collect();
    let mut public_params: Vec<String> = public_params.into_iter().collect();
    external_states.sort();
    public_params.sort();
    (external_states, public_params)
}

/// The record of `air_fn` and its digest, `SHA-256(canonical(record))`.
fn function_record(strings: &mut Strings, air_fn: &CompiledAirFn) -> Result<(Vec<u8>, [u8; 32])> {
    let mut w = Writer::new(strings);
    w.str(&air_fn.name);
    let trace_type = serde_json::to_value(air_fn.r#type)?;
    w.str(
        trace_type
            .as_str()
            .context("trace type is not a unit variant")?,
    );
    match air_fn.log_height {
        Some(log_height) => {
            w.u8(1);
            w.u32(log_height);
        }
        None => w.u8(0),
    }
    w.strs(air_fn.verifier_input_limbs.iter())?;
    w.strs(air_fn.state_names.iter())?;
    w.len(air_fn.constraint_lookups.len())?;
    for (relation, use_or_yield) in &air_fn.constraint_lookups {
        w.str(relation);
        w.use_or_yield(use_or_yield);
    }
    w.strs(air_fn.external_states.iter())?;
    w.strs(air_fn.public_params.iter())?;
    let (used_external_states, used_public_params) = used_atoms(air_fn);
    w.strs(used_external_states.iter())?;
    w.strs(used_public_params.iter())?;
    w.len(air_fn.constraints.len())?;
    air_fn
        .constraints
        .iter()
        .try_for_each(|step| w.step(step))?;
    if air_fn.r#type == air_common::TraceType::Inline {
        w.u8(1);
        w.expr(&air_fn.verifier_output.0)?;
    } else {
        w.u8(0);
    }
    let digest = Sha256::digest(&w.canonical).into();
    Ok((w.bytes, digest))
}

fn source_section(
    strings: &mut Strings,
    source: &AirSource,
    compiled: &CompiledAir,
    slots: Vec<&'static str>,
) -> Result<Vec<u8>> {
    let mut functions: Vec<&CompiledAirFn> = compiled.functions.values().collect();
    functions.sort_by(|a, b| a.name.cmp(&b.name));
    let (generated, hand_written): (Vec<_>, Vec<_>) = functions
        .into_iter()
        .partition(|air_fn| compiled_air::is_generated(&air_fn.name));
    ensure!(
        !generated.is_empty(),
        "{}: no generated evaluators",
        source.label
    );

    let records = generated
        .iter()
        .map(|air_fn| {
            function_record(strings, air_fn)
                .with_context(|| format!("{}: {}", source.label, air_fn.name))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut w = Writer::new(strings);
    w.str(source.label);
    w.strs(slots.iter())?;
    w.strs(hand_written.iter().map(|air_fn| air_fn.name.as_str()))?;
    w.len(records.len())?;
    for (record, digest) in records {
        w.len(record.len())?;
        w.bytes.extend_from_slice(&digest);
        w.bytes.extend_from_slice(&record);
    }
    Ok(w.bytes)
}

pub fn run(proving_root: &Path) -> Result<Vec<u8>> {
    let mut root = ProvingRoot::open(proving_root)?;
    let cairo_air = compiled_air::load(&mut root, &CAIRO_AIR)?;
    let circuit_air = compiled_air::load(&mut root, &CIRCUIT_AIR)?;
    root.finish(upstream::PINNED_COMPILED_AIR_SHA256)?;

    let mut strings = Strings::default();
    let cairo_slots = circuit_cairo_verifier::all_components::all_components::<NoValue>()
        .keys()
        .copied()
        .collect();
    let circuit_slots = circuit_verifier::statement::all_circuit_components::<NoValue>()
        .keys()
        .copied()
        .collect();
    let sections = [
        source_section(&mut strings, &CAIRO_AIR, &cairo_air, cairo_slots)?,
        source_section(&mut strings, &CIRCUIT_AIR, &circuit_air, circuit_slots)?,
    ];

    let mut header = Writer::new(&mut strings);
    header.str(PROVING_REVISION);
    header.str(upstream::PINNED_COMPILED_AIR_SHA256);
    let constants = constants();
    header.len(constants.len())?;
    for (name, value) in constants {
        header.str(name);
        header.u32(value);
    }
    header.len(sections.len())?;
    let header = header.bytes;

    let mut file = Vec::new();
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(&VERSION.to_le_bytes());
    file.extend_from_slice(&(strings.table.len() as u32).to_le_bytes());
    for value in strings.table.keys() {
        file.extend_from_slice(&(value.len() as u32).to_le_bytes());
        file.extend_from_slice(value.as_bytes());
    }
    file.extend_from_slice(&header);
    sections
        .iter()
        .for_each(|section| file.extend_from_slice(section));
    Ok(file)
}

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use proc_macro2::{Literal, Span, TokenStream};
use quote::quote;
use syn::{
    BinOp, Expr, ExprArray, ExprAssign, ExprBinary, ExprCall, ExprField, ExprIndex, ExprMethodCall,
    ExprParen, ExprPath, ExprStruct, ExprTuple, ExprUnary, Fields, FnArg, Ident, Item, ItemFn, Lit,
    Local, Member, Pat, Stmt, Type, UnOp,
};

/// Marker delimiting the generated block inside a component file (for idempotent re-run).
pub const BEGIN_MARKER: &str = "// === BEGIN witness_genericize (generated; re-runnable) ===";
pub const END_MARKER: &str = "// === END witness_genericize ===";

// ======================================================================================
// Types (the type map of the rewrite table)
// ======================================================================================

/// Bottom-up inferred type of a value in the per-row body's single-assignment let graph.
///
/// TWO felt types with DIFFERENT limb layouts exist in the generated writers and must
/// NEVER be conflated (a wrong width silently mis-lowers `get_m31`):
///   * `Felt252` — 28 limbs x 9 bits (`FELT252_N_WORDS`/`FELT252_BITS_PER_WORD`, common
///     `prover_types/cpu.rs`); this is the ONLY width the recording layer models (`FELT_N_LIMBS =
///     28`, `witness_eval/mod.rs`).
///   * `FeltW27` — `Felt252Width27`: 10 limbs x 27 bits (`FELT252WIDTH27_N_WORDS`); NOT
///     representable as a `WitnessEval::Felt` today, so opaque W27 values are census-only
///     (`w27_sites`).
///   * `FeltW27Limbs` — a W27 value the transformer itself assembled from 10 known M31 limb tokens
///     (bound as a `[E::M31; 10]` array); `get_m31(i)` projects `tok[i]`. Same canonical-limb
///     contract as the recording layer's `felt_from_limbs` (limbs assumed < 2^27; the per-component
///     byte-equality gate is the arbiter).
#[derive(Clone, PartialEq)]
enum Ty {
    M31,
    U16,
    /// u32 family — CENSUS-ONLY: typing these ops classifies files as "matched (needs
    /// u32 trait extension)"; they are never emitted.
    U32,
    Mask,
    /// felt252, 28 x 9-bit limbs (the recording layer's `Felt`).
    Felt252,
    /// `Felt252Width27`, 10 x 27-bit limbs — OPAQUE (from input / deduce); census-only.
    FeltW27,
    /// `Felt252Width27` whose 10 M31 limb values are transformer-known SSA tokens.
    FeltW27Limbs,
    ConstM31(u32),
    ConstU16(u32),
    ConstU32(u32),
    /// Hoisted `PackedFelt252::broadcast(Felt252::from([A,B,C,D]))` constant, decomposed
    /// at transform time into its 28 canonical 9-bit limbs (G3).
    ConstFelt252([u32; FELT252_LIMBS]),
    /// The opcode writer's next-state aggregate. The emitted representation is the
    /// `(pc, ap, fp)` tuple so the generic row body stays independent of the concrete
    /// `PackedCasmState` type while preserving named-field projections.
    CasmState,
    Tuple(Vec<Ty>),
    Array(Box<Ty>, usize),
    /// A (projection of the) builtin input binder, carrying the FLAT SLOT BASE of this
    /// subtree in the component's input-word layout (M31 leaf = 1 word, Felt252 leaf =
    /// 28, FeltW27 = 10, aggregates = sum — [`Ty::flat_width`]). Projections descend
    /// with the correct base; an M31 leaf lowers to the REAL `eval.input(<slot>)` read
    /// (the builtin lane feeds the flattened words in this exact depth-first order).
    /// Felt-typed leaves stay census-only (`input_sites`) until the lane feeds felt
    /// limbs. Never originates anywhere but [`Lowerer::input_leaf`].
    InputAt(Box<Ty>, usize),
    Unknown,
}

/// Felt252 limb shape: 28 limbs x 9 bits (see common `prover_types/cpu.rs`).
const FELT252_LIMBS: usize = 28;
const FELT252_LIMB_BITS: usize = 9;
/// Felt252Width27 limb shape: 10 limbs x 27 bits.
const FELTW27_LIMBS: usize = 10;

impl std::fmt::Debug for Ty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ty::M31 => write!(f, "M31"),
            Ty::U16 => write!(f, "U16"),
            Ty::U32 => write!(f, "U32"),
            Ty::Mask => write!(f, "Mask"),
            Ty::Felt252 => write!(f, "Felt252"),
            Ty::FeltW27 => write!(f, "FeltW27"),
            Ty::FeltW27Limbs => write!(f, "FeltW27Limbs"),
            Ty::ConstM31(v) => write!(f, "ConstM31({v})"),
            Ty::ConstU16(v) => write!(f, "ConstU16({v})"),
            Ty::ConstU32(v) => write!(f, "ConstU32({v})"),
            // Payload elided: 28 limb values would flood the skip census keys.
            Ty::ConstFelt252(_) => write!(f, "ConstFelt252"),
            Ty::CasmState => write!(f, "CasmState"),
            Ty::Tuple(v) => f.debug_tuple("Tuple").field(v).finish(),
            Ty::Array(e, n) => write!(f, "Array({e:?}, {n})"),
            Ty::InputAt(e, base) => write!(f, "InputAt({e:?}, {base})"),
            Ty::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Ty {
    fn is_m31(&self) -> bool {
        matches!(self, Ty::M31 | Ty::ConstM31(_))
    }
    fn is_u16(&self) -> bool {
        matches!(self, Ty::U16)
    }
    /// Felt-shaped operand: a live `E::Felt` value or a hoisted felt constant
    /// (materialized to `felt_from_limbs` of constants at use).
    fn is_feltish(&self) -> bool {
        matches!(self, Ty::Felt252 | Ty::ConstFelt252(_))
    }
    fn is_u32(&self) -> bool {
        matches!(self, Ty::U32 | Ty::ConstU32(_))
    }
    fn is_mask(&self) -> bool {
        matches!(self, Ty::Mask)
    }

    /// FLAT INPUT-WORD width of this type in the builtin lane's input layout
    /// (depth-first): M31/U16/U32 leaves = 1 word, Felt252 = 28 limb words, FeltW27 =
    /// 10, aggregates = sum. This is the contract between the transformer's slot map,
    /// the emitted SIMD driver's input flattening, and the device lane's input columns
    /// — all three MUST agree or `input(slot)` reads the wrong word.
    fn flat_width(&self) -> usize {
        match self {
            Ty::CasmState => 3,
            Ty::Tuple(v) => v.iter().map(Ty::flat_width).sum(),
            Ty::Array(e, n) => e.flat_width() * n,
            Ty::Felt252 | Ty::ConstFelt252(_) => FELT252_LIMBS,
            Ty::FeltW27 | Ty::FeltW27Limbs => FELTW27_LIMBS,
            Ty::InputAt(e, _) => e.flat_width(),
            _ => 1,
        }
    }
}

/// A hoisted broadcast constant binding at the top of `write_trace_simd`.
#[derive(Clone, Copy, Debug)]
enum ConstKind {
    M31,
    U16,
    U32,
}

#[derive(Clone, Copy, Debug)]
struct ConstVal {
    kind: ConstKind,
    value: u32,
}

/// A shape tree of a `sub_component_inputs` assignment RHS (for flatten + reconstruction).
#[derive(Clone, Debug, PartialEq)]
enum Shape {
    Scalar,
    /// A full-32-bit (`PackedUInt32`) element: ONE flat word carrying a raw u32 (the
    /// blake_g feeds). The flat transport is raw lanes, so nothing is lost.
    U32,
    /// A `PackedFelt252`-valued element: 28 flat limb words (canonical 9-bit limbs, the
    /// same `felt_get_m31` decomposition everywhere else in the lane). The driver
    /// reconstructs it with `PackedFelt252::from_limbs` — the exact inverse for
    /// canonical limbs, so the receiving component sees the identical felt value.
    Felt,
    Tuple(Vec<Shape>),
    Array(Vec<Shape>),
}

impl Shape {
    fn scalar_count(&self) -> usize {
        match self {
            Shape::Scalar | Shape::U32 => 1,
            Shape::Felt => FELT252_LIMBS,
            Shape::Tuple(v) | Shape::Array(v) => v.iter().map(Shape::scalar_count).sum(),
        }
    }
}

/// One flattened sub-input word at lowering time: its value token and whether it is a
/// full-32-bit word (stored via `set_sub_input_word_u32`) or a canonical M31 word.
struct SubLeaf {
    tok: TokenStream,
    u32: bool,
}

/// One `(field, index)` slot of `SubComponentInputs`, with its flat base word index
/// (DECLARATION order) and value shape.
#[derive(Clone, Debug)]
struct SubSlot {
    field: String,
    index: usize,
    shape: Shape,
    base: usize,
}

/// One declared `LookupData` field: `Vec<[PackedM31; width]>` (width>1) or `Vec<PackedM31>`
/// (width==1, scalar).
#[derive(Clone, Debug)]
struct LookupField {
    name: String,
    width: usize,
    scalar: bool,
    base: usize,
}

/// A loud, quoted reason a file (or a construct in it) is not rewritable.
#[derive(Clone, Debug)]
struct Skip {
    category: &'static str,
    detail: String,
}

// ======================================================================================

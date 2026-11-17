#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility,
    clippy::missing_const_for_fn
)]
#![allow(clippy::op_ref, clippy::suspicious_op_assign_impl)]
#![deny(unsafe_code)]
#![doc = include_str!("../README.md")]

#[macro_use]
pub mod biginteger;
pub use biginteger::{
    BigInt, BigInteger, BigInteger64, BigInteger128, BigInteger256, BigInteger320, BigInteger384,
    BigInteger448, BigInteger768, BigInteger832, signed_mod_reduction,
};

#[macro_use]
pub mod fields;
pub use self::fields::*;

pub(crate) mod bits;
pub use bits::*;

pub(crate) mod const_helpers;

pub use ark_std::UniformRand;

mod to_field_vec;
pub use to_field_vec::ToConstraintField;

#[doc(hidden)]
pub use ark_ff_asm::*;
#[doc(hidden)]
pub use ark_std::vec;

pub mod prelude {
    pub use crate::{
        One, Zero,
        biginteger::BigInteger,
        fields::{Field, PrimeField},
    };
    pub use ark_std::UniformRand;
}

#[cfg(all(feature = "stwo-operation-census", target_arch = "riscv64"))]
compile_error!("operation census is a native-only diagnostic");
#[cfg(feature = "stwo-operation-census")]
pub mod operation_census;

//! Native Metal runtime bindings for the STWO Metal proving backend.
//!
//! The kernels and the Objective-C runtime originate from the `stwo-metal` companion project
//! and were ported here against the current stwo backend trait surface. The GPU kernel library
//! is embedded at build time, either as a precompiled `.metallib` (when the Metal compiler is
//! available) or as preprocessed source compiled once at runtime — see `build.rs`.
//!
//! On non-macOS targets this crate compiles to a stub whose runtime constructor fails at
//! runtime; it never breaks the build.

pub mod metal;

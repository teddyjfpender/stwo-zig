//! The embedded AOT kernel pack (design §4, M3): per-arch cubins for every
//! kernel_emit-generated kernel, compiled offline at -O3 by build.rs and served
//! to `runtime_jit.cu`'s `get_or_compile` tier-0 via [`stwo_aot_lookup`]. A
//! cache-key miss (new/changed recording, unknown arch) falls back to NVRTC —
//! the drift check by construction. Empty on stub builds and until kernel_emit
//! populates `cuda/generated/`.

const ZERO_IDENTITY: [u8; 32] = [0; 32];

pub use crate::aot_identity::{
    AotKernelAbiAccess, AotKernelAbiArgument, AotKernelAbiKind, AotKernelAbiSchema,
    AotKernelModuleGlobals, AotKernelSchemaScope,
};

/// Immutable authority for one exact generated source and target cubin.
///
/// Unsupported generator families remain exported-symbol-only. A structured
/// schema is present only when the typed Rust emitter supplied it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotKernelAuthority {
    source_identity: [u8; 32],
    kernel_symbol: &'static str,
    semantic_hash: u64,
    cache_key: u64,
    target_sm: u32,
    cubin_identity: [u8; 32],
    abi_schema: Option<AotKernelAbiSchema>,
    abi_schema_identity: [u8; 32],
    program_identity: [u8; 32],
    identity: [u8; 32],
    schema_scope: AotKernelSchemaScope,
    module_globals: AotKernelModuleGlobals,
}

impl AotKernelAuthority {
    pub fn source_identity(self) -> [u8; 32] {
        self.source_identity
    }

    pub fn kernel_symbol(self) -> &'static str {
        self.kernel_symbol
    }

    /// Legacy FNV semantic/cache tag. Never use this as program authority.
    pub fn semantic_hash(self) -> u64 {
        self.semantic_hash
    }

    /// Lookup key only; collision-resistant authority is [`Self::identity`].
    pub fn cache_key(self) -> u64 {
        self.cache_key
    }

    /// CUDA compute capability encoded as `major * 10 + minor`.
    pub fn target_sm(self) -> u32 {
        self.target_sm
    }

    pub fn cubin_identity(self) -> [u8; 32] {
        self.cubin_identity
    }

    pub fn abi_schema(self) -> Option<AotKernelAbiSchema> {
        self.abi_schema
    }

    pub fn abi_schema_identity(self) -> [u8; 32] {
        self.abi_schema_identity
    }

    /// Collision-resistant typed-program identity, or zero when unsupported.
    pub fn program_identity(self) -> [u8; 32] {
        self.program_identity
    }

    /// Canonical digest over every field exposed by this entry.
    pub fn identity(self) -> [u8; 32] {
        self.identity
    }

    pub fn schema_scope(self) -> AotKernelSchemaScope {
        self.schema_scope
    }

    pub fn module_globals(self) -> AotKernelModuleGlobals {
        self.module_globals
    }
}

#[derive(Clone, Copy)]
struct AotIndexEntry {
    offset: usize,
    len: usize,
    authority: AotKernelAuthority,
}

static AOT_PACK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/aot_pack.bin"));
include!(concat!(env!("OUT_DIR"), "/aot_index.rs"));

/// C hook for `get_or_compile`: resolve `(cache_key, sm)` to an embedded cubin.
/// Exact-arch match only — SASS is arch-specific; any miss falls back to NVRTC.
///
/// # Safety
/// `out_data`/`out_len` must be valid writable pointers; the returned blob
/// borrows the process-lifetime embedded pack.
#[no_mangle]
pub unsafe extern "C" fn stwo_aot_lookup(
    cache_key: u64,
    sm_major: u32,
    sm_minor: u32,
    out_data: *mut *const u8,
    out_len: *mut usize,
) -> bool {
    if aot_pack_identity() == ZERO_IDENTITY {
        return false;
    }
    let Some(sm) = encode_sm(sm_major, sm_minor) else {
        return false;
    };
    let Ok(i) = AOT_INDEX.binary_search_by_key(&(cache_key, sm), |entry| {
        (entry.authority.cache_key, entry.authority.target_sm)
    }) else {
        return false;
    };
    let entry = AOT_INDEX[i];
    if entry.authority.identity == ZERO_IDENTITY {
        return false;
    }
    let Some(end) = entry.offset.checked_add(entry.len) else {
        return false;
    };
    let Some(cubin) = AOT_PACK.get(entry.offset..end) else {
        return false;
    };
    unsafe {
        *out_data = cubin.as_ptr();
        *out_len = entry.len;
    }
    true
}

/// Number of embedded (kernel, arch) entries — surfaced for logs/tests.
pub fn aot_pack_entries() -> usize {
    if aot_pack_identity() == ZERO_IDENTITY {
        0
    } else {
        AOT_INDEX.len()
    }
}

/// Number of embedded kernels for one exact device architecture.
pub fn aot_pack_entries_for_arch(sm_major: u32, sm_minor: u32) -> usize {
    if aot_pack_identity() == ZERO_IDENTITY {
        return 0;
    }
    let Some(sm) = encode_sm(sm_major, sm_minor) else {
        return 0;
    };
    AOT_INDEX
        .iter()
        .filter(|entry| {
            entry.authority.target_sm == sm && entry.authority.identity != ZERO_IDENTITY
        })
        .count()
}

/// Collision-resistant identity of the exact AOT cubins and generation
/// policies embedded in this binary. This intentionally remains binary-pack
/// identity: source-aware consumers must retain each [`AotKernelAuthority`]
/// identity. Only authorities carrying `StructuredAbi` claim argument access.
///
/// An empty/stub pack deliberately returns all-zero so the GPU-native runtime
/// fails closed instead of constructing authority that later falls through to
/// NVRTC.
pub fn aot_pack_identity() -> [u8; 32] {
    if !aot_pack_is_well_formed() {
        return ZERO_IDENTITY;
    }
    AOT_PACK_IDENTITY
}

/// Collision-resistant identity of one exact `(cache_key, SM)` cubin. A miss,
/// malformed architecture, empty pack, or invalid generated identity returns
/// all-zero. This is binary identity, not proof that the binary implements a
/// separately claimed effect body.
pub fn aot_cubin_identity(cache_key: u64, sm_major: u32, sm_minor: u32) -> [u8; 32] {
    aot_kernel_authority(cache_key, sm_major, sm_minor)
        .map(AotKernelAuthority::cubin_identity)
        .unwrap_or(ZERO_IDENTITY)
}

/// Canonical source/binary authority for one exact `(cache_key, SM)` entry.
/// Returns `None` for an absent, malformed, or unsealed pack. Structured ABI
/// metadata is present only for generator families which emit it.
pub fn aot_kernel_authority(
    cache_key: u64,
    sm_major: u32,
    sm_minor: u32,
) -> Option<AotKernelAuthority> {
    if aot_pack_identity() == ZERO_IDENTITY {
        return None;
    }
    let sm = encode_sm(sm_major, sm_minor)?;
    AOT_INDEX
        .binary_search_by_key(&(cache_key, sm), |entry| {
            (entry.authority.cache_key, entry.authority.target_sm)
        })
        .ok()
        .map(|index| AOT_INDEX[index].authority)
}

/// Non-authoritative u64 compatibility/telemetry tag derived from the full
/// pack identity. Never use this value as kernel, graph, or proof authority.
pub fn aot_pack_manifest_hash() -> u64 {
    legacy_telemetry_tag(aot_pack_identity())
}

/// Constraint-lowering split cap used to generate the embedded semantic keys.
/// Zero is returned for an empty/stub pack so strict planning cannot guess a
/// cap that has no corresponding loaded kernels.
pub fn aot_pack_constraint_max_instrs() -> usize {
    if aot_pack_identity() == ZERO_IDENTITY {
        0
    } else {
        AOT_CONSTRAINT_MAX_INSTRS
    }
}

/// Compacted live-u32-lane cap used to generate the embedded constraint split.
/// Zero is returned for an empty/stub pack so runtime admission cannot silently
/// combine a stale AOT pack with a different resource policy.
pub fn aot_pack_constraint_max_live_u32_lanes() -> usize {
    if aot_pack_identity() == ZERO_IDENTITY {
        0
    } else {
        AOT_CONSTRAINT_MAX_LIVE_U32_LANES
    }
}

/// True when this binary contains at least one kernel for `sm_major.sm_minor`.
/// Full per-proof coverage is still established by fail-closed lookup at every
/// semantic key; this is the cheap admission check before arena allocation.
pub fn aot_pack_supports_arch(sm_major: u32, sm_minor: u32) -> bool {
    let Some(sm) = encode_sm(sm_major, sm_minor) else {
        return false;
    };
    aot_pack_identity() != ZERO_IDENTITY
        && AOT_INDEX.iter().any(|entry| {
            entry.authority.target_sm == sm && entry.authority.identity != ZERO_IDENTITY
        })
}

/// True when this binary contains the exact `(cache_key, architecture)` entry.
/// This only searches the immutable embedded index and never initializes CUDA.
pub fn aot_pack_contains(cache_key: u64, sm_major: u32, sm_minor: u32) -> bool {
    aot_kernel_authority(cache_key, sm_major, sm_minor).is_some()
}

fn encode_sm(sm_major: u32, sm_minor: u32) -> Option<u32> {
    if sm_minor > 9 {
        return None;
    }
    sm_major.checked_mul(10)?.checked_add(sm_minor)
}

fn legacy_telemetry_tag(identity: [u8; 32]) -> u64 {
    if identity == ZERO_IDENTITY {
        return 0;
    }
    let folded = identity
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("eight-byte digest chunk")))
        .fold(0, |acc, word| acc ^ word);
    folded.max(1)
}

fn aot_pack_is_well_formed() -> bool {
    static WELL_FORMED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *WELL_FORMED.get_or_init(|| {
        AOT_CONSTRAINT_MAX_INSTRS != 0
            && AOT_CONSTRAINT_MAX_LIVE_U32_LANES != 0
            && pack_is_well_formed(
                AOT_PACK,
                AOT_PACK_IDENTITY,
                AOT_INDEX,
                AOT_CONSTRAINT_MAX_INSTRS,
                AOT_CONSTRAINT_MAX_LIVE_U32_LANES,
            )
    })
}

fn pack_is_well_formed(
    pack: &[u8],
    pack_identity: [u8; 32],
    index: &[AotIndexEntry],
    constraint_max_instrs: usize,
    constraint_max_live_u32_lanes: usize,
) -> bool {
    if index.is_empty() {
        return pack.is_empty() && pack_identity == ZERO_IDENTITY;
    }
    if pack_identity == ZERO_IDENTITY
        || constraint_max_instrs == 0
        || constraint_max_live_u32_lanes == 0
    {
        return false;
    }
    let mut expected_offset = 0usize;
    let mut previous_key = None;
    let mut identity_inputs = Vec::with_capacity(index.len());
    for entry in index {
        let authority = entry.authority;
        let key = (authority.cache_key, authority.target_sm);
        if previous_key.is_some_and(|previous| previous >= key)
            || entry.offset != expected_offset
            || entry.len == 0
            || authority.source_identity == ZERO_IDENTITY
            || authority.kernel_symbol.is_empty()
            || authority.target_sm == 0
            || authority.cubin_identity == ZERO_IDENTITY
            || authority.identity == ZERO_IDENTITY
        {
            return false;
        }
        let expected_abi_identity = authority
            .abi_schema
            .map(AotKernelAbiSchema::identity)
            .unwrap_or(ZERO_IDENTITY);
        let expected_scope = if authority.abi_schema.is_some() {
            AotKernelSchemaScope::StructuredAbi
        } else {
            AotKernelSchemaScope::ExportedSymbolOnly
        };
        let globals_are_valid = match (authority.abi_schema, authority.module_globals) {
            (None, AotKernelModuleGlobals::Unspecified)
            | (
                Some(AotKernelAbiSchema::RecordedWitnessV1),
                AotKernelModuleGlobals::None | AotKernelModuleGlobals::WitnessPedersenV1,
            )
            | (
                Some(
                    AotKernelAbiSchema::OrdinaryConstraintV1
                    | AotKernelAbiSchema::CompositionWaveV2,
                ),
                AotKernelModuleGlobals::None,
            ) => true,
            _ => false,
        };
        if authority.abi_schema_identity != expected_abi_identity
            || authority.schema_scope != expected_scope
            || !globals_are_valid
            || (authority.abi_schema.is_some() && authority.program_identity == ZERO_IDENTITY)
            || (authority.abi_schema.is_none() && authority.program_identity != ZERO_IDENTITY)
        {
            return false;
        }
        let Some(end) = entry.offset.checked_add(entry.len) else {
            return false;
        };
        let Some(cubin) = pack.get(entry.offset..end) else {
            return false;
        };
        let cubin_identity =
            crate::aot_identity::cubin_identity(crate::aot_identity::CubinIdentityInput {
                cache_key: authority.cache_key,
                sm: authority.target_sm,
                bytes: cubin,
            });
        let identity = crate::aot_identity::kernel_authority_identity(
            crate::aot_identity::KernelAuthorityIdentityInput {
                source_identity: authority.source_identity,
                kernel_symbol: authority.kernel_symbol,
                semantic_hash: authority.semantic_hash,
                cache_key: authority.cache_key,
                sm: authority.target_sm,
                cubin_identity,
                abi_schema_identity: authority.abi_schema_identity,
                program_identity: authority.program_identity,
                schema_scope: authority.schema_scope,
                module_globals: authority.module_globals,
            },
        );
        if cubin_identity != authority.cubin_identity || identity != authority.identity {
            return false;
        }
        identity_inputs.push(crate::aot_identity::CubinIdentityInput {
            cache_key: authority.cache_key,
            sm: authority.target_sm,
            bytes: cubin,
        });
        expected_offset = end;
        previous_key = Some(key);
    }
    expected_offset == pack.len()
        && pack_identity
            == crate::aot_identity::pack_identity(
                constraint_max_instrs,
                constraint_max_live_u32_lanes,
                &identity_inputs,
            )
}

#[cfg(test)]
mod manifest_tests {
    use super::*;
    use crate::aot_identity;

    #[cfg(all(stwo_cuda_link, not(feature = "test-only-empty-aot-pack")))]
    fn generated_source_keys() -> std::collections::BTreeSet<u64> {
        let generated = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("cuda")
            .join("generated");
        std::fs::read_dir(generated)
            .expect("read generated AOT source directory")
            .map(|entry| entry.expect("read generated AOT source entry").path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "cu"))
            .map(|path| {
                let stem = path
                    .file_stem()
                    .expect("generated AOT source has a stem")
                    .to_string_lossy();
                u64::from_str_radix(
                    stem.rsplit('_')
                        .next()
                        .expect("generated AOT source has a cache key"),
                    16,
                )
                .expect("generated AOT source cache key is hexadecimal")
            })
            .collect()
    }

    #[test]
    fn empty_pack_is_explicitly_unbound() {
        if AOT_INDEX.is_empty() {
            assert_eq!(aot_pack_identity(), ZERO_IDENTITY);
            assert_eq!(aot_pack_manifest_hash(), 0);
            assert_eq!(aot_pack_constraint_max_instrs(), 0);
            assert_eq!(aot_pack_constraint_max_live_u32_lanes(), 0);
        } else {
            assert_ne!(aot_pack_identity(), ZERO_IDENTITY);
            assert_ne!(aot_pack_manifest_hash(), 0);
            assert_ne!(aot_pack_constraint_max_instrs(), 0);
            assert_ne!(aot_pack_constraint_max_live_u32_lanes(), 0);
        }
    }

    #[test]
    fn architecture_admission_matches_embedded_index() {
        for entry in AOT_INDEX {
            let sm = entry.authority.target_sm;
            assert!(aot_pack_supports_arch(sm / 10, sm % 10));
        }
    }

    #[test]
    fn exact_membership_matches_embedded_index() {
        for entry in AOT_INDEX {
            let authority = entry.authority;
            let cache_key = authority.cache_key;
            let sm = authority.target_sm;
            assert!(aot_pack_contains(cache_key, sm / 10, sm % 10));
            assert_eq!(
                aot_cubin_identity(cache_key, sm / 10, sm % 10),
                authority.cubin_identity
            );
            assert_eq!(
                aot_kernel_authority(cache_key, sm / 10, sm % 10),
                Some(authority)
            );
            assert_eq!(
                authority.schema_scope(),
                if authority.abi_schema().is_some() {
                    AotKernelSchemaScope::StructuredAbi
                } else {
                    AotKernelSchemaScope::ExportedSymbolOnly
                }
            );
            assert!(match authority.abi_schema() {
                None => authority.module_globals() == AotKernelModuleGlobals::Unspecified,
                Some(
                    AotKernelAbiSchema::OrdinaryConstraintV1
                    | AotKernelAbiSchema::CompositionWaveV2,
                ) => {
                    authority.module_globals() == AotKernelModuleGlobals::None
                }
                Some(AotKernelAbiSchema::RecordedWitnessV1) => matches!(
                    authority.module_globals(),
                    AotKernelModuleGlobals::None | AotKernelModuleGlobals::WitnessPedersenV1
                ),
            });
        }
        assert!(!aot_pack_contains(0, u32::MAX, u32::MAX));
        assert_eq!(aot_cubin_identity(0, u32::MAX, u32::MAX), ZERO_IDENTITY);
        assert_eq!(aot_kernel_authority(0, u32::MAX, u32::MAX), None);
    }

    #[test]
    fn generated_identities_match_exact_embedded_bytes() {
        let inputs = AOT_INDEX
            .iter()
            .map(|entry| {
                let authority = entry.authority;
                let end = entry
                    .offset
                    .checked_add(entry.len)
                    .expect("generated cubin range does not overflow");
                let bytes = AOT_PACK
                    .get(entry.offset..end)
                    .expect("generated cubin range is inside the embedded pack");
                let input = aot_identity::CubinIdentityInput {
                    cache_key: authority.cache_key,
                    sm: authority.target_sm,
                    bytes,
                };
                assert_eq!(
                    authority.cubin_identity,
                    aot_identity::cubin_identity(input)
                );
                assert_eq!(
                    authority.abi_schema_identity,
                    authority
                        .abi_schema
                        .map(AotKernelAbiSchema::identity)
                        .unwrap_or(ZERO_IDENTITY)
                );
                assert_eq!(
                    authority.identity,
                    aot_identity::kernel_authority_identity(
                        aot_identity::KernelAuthorityIdentityInput {
                            source_identity: authority.source_identity,
                            kernel_symbol: authority.kernel_symbol,
                            semantic_hash: authority.semantic_hash,
                            cache_key: authority.cache_key,
                            sm: authority.target_sm,
                            cubin_identity: authority.cubin_identity,
                            abi_schema_identity: authority.abi_schema_identity,
                            program_identity: authority.program_identity,
                            schema_scope: authority.schema_scope,
                            module_globals: authority.module_globals,
                        }
                    )
                );
                input
            })
            .collect::<Vec<_>>();
        assert_eq!(
            aot_pack_identity(),
            aot_identity::pack_identity(
                AOT_CONSTRAINT_MAX_INSTRS,
                AOT_CONSTRAINT_MAX_LIVE_U32_LANES,
                &inputs,
            )
        );
    }

    #[test]
    fn malformed_pack_layouts_have_no_authority() {
        let pack = [1, 2, 3, 4];
        let valid = [
            test_entry(11, 86, 0, &[1, 2]),
            test_entry(13, 90, 2, &[3, 4]),
        ];
        let pack_identity = aot_identity::pack_identity(
            1,
            1,
            &[
                aot_identity::CubinIdentityInput {
                    cache_key: 11,
                    sm: 86,
                    bytes: &[1, 2],
                },
                aot_identity::CubinIdentityInput {
                    cache_key: 13,
                    sm: 90,
                    bytes: &[3, 4],
                },
            ],
        );
        assert!(test_pack_is_well_formed(&pack, pack_identity, &valid));
        assert!(test_pack_is_well_formed(&[], ZERO_IDENTITY, &[]));

        assert!(!test_pack_is_well_formed(&pack, ZERO_IDENTITY, &valid));
        assert!(!test_pack_is_well_formed(&pack, pack_identity, &[]));
        assert!(!test_pack_is_well_formed(&[], pack_identity, &[]));
        assert!(!test_pack_is_well_formed(
            &pack,
            pack_identity,
            &[valid[1], valid[0]]
        ));

        let mut changed = valid;
        changed[1].authority.cache_key = 11;
        assert!(!test_pack_is_well_formed(&pack, pack_identity, &changed));
        let mut changed = valid;
        changed[0].len = 0;
        assert!(!test_pack_is_well_formed(&pack, pack_identity, &changed));
        let mut changed = valid;
        changed[0].authority.source_identity = ZERO_IDENTITY;
        assert!(!test_pack_is_well_formed(&pack, pack_identity, &changed));
        let mut changed = valid;
        changed[0].authority.cubin_identity = ZERO_IDENTITY;
        assert!(!test_pack_is_well_formed(&pack, pack_identity, &changed));
        let mut changed = valid;
        changed[0].authority.identity = ZERO_IDENTITY;
        assert!(!test_pack_is_well_formed(&pack, pack_identity, &changed));
        let mut changed = valid;
        changed[0].authority.abi_schema = Some(AotKernelAbiSchema::RecordedWitnessV1);
        assert!(!test_pack_is_well_formed(&pack, pack_identity, &changed));
        let mut changed = valid;
        changed[0].authority.abi_schema_identity =
            aot_identity::abi_schema_identity(AotKernelAbiSchema::RecordedWitnessV1);
        assert!(!test_pack_is_well_formed(&pack, pack_identity, &changed));
        let mut changed = valid;
        changed[0].authority.program_identity = [7; 32];
        assert!(!test_pack_is_well_formed(&pack, pack_identity, &changed));
        let mut changed = valid;
        changed[0].offset = 1;
        assert!(!test_pack_is_well_formed(&pack, pack_identity, &changed));
        let mut changed = valid;
        changed[1].len = 3;
        assert!(!test_pack_is_well_formed(&pack, pack_identity, &changed));
        let mut changed = valid;
        changed[0].authority.semantic_hash += 1;
        assert!(!test_pack_is_well_formed(&pack, pack_identity, &changed));
        assert!(!test_pack_is_well_formed(
            &[9, 2, 3, 4],
            pack_identity,
            &valid
        ));
        assert!(!test_pack_is_well_formed(&pack, pack_identity, &valid[..1]));
    }

    fn test_pack_is_well_formed(pack: &[u8], identity: [u8; 32], index: &[AotIndexEntry]) -> bool {
        pack_is_well_formed(pack, identity, index, 1, 1)
    }

    fn test_entry(cache_key: u64, sm: u32, offset: usize, cubin: &[u8]) -> AotIndexEntry {
        let source_identity = aot_identity::source_identity(b"test generated CUDA source");
        let cubin_identity = aot_identity::cubin_identity(aot_identity::CubinIdentityInput {
            cache_key,
            sm,
            bytes: cubin,
        });
        let authority = AotKernelAuthority {
            source_identity,
            kernel_symbol: "test_kernel",
            semantic_hash: 17,
            cache_key,
            target_sm: sm,
            cubin_identity,
            abi_schema: None,
            abi_schema_identity: ZERO_IDENTITY,
            program_identity: ZERO_IDENTITY,
            identity: aot_identity::kernel_authority_identity(
                aot_identity::KernelAuthorityIdentityInput {
                    source_identity,
                    kernel_symbol: "test_kernel",
                    semantic_hash: 17,
                    cache_key,
                    sm,
                    cubin_identity,
                    abi_schema_identity: ZERO_IDENTITY,
                    program_identity: ZERO_IDENTITY,
                    schema_scope: AotKernelSchemaScope::ExportedSymbolOnly,
                    module_globals: AotKernelModuleGlobals::Unspecified,
                },
            ),
            schema_scope: AotKernelSchemaScope::ExportedSymbolOnly,
            module_globals: AotKernelModuleGlobals::Unspecified,
        };
        AotIndexEntry {
            offset,
            len: cubin.len(),
            authority,
        }
    }

    #[cfg(all(stwo_cuda_link, not(feature = "test-only-empty-aot-pack")))]
    #[test]
    fn default_cuda_build_embeds_every_generated_source_for_every_arch() {
        use std::collections::BTreeSet;

        let source_keys = generated_source_keys();
        let index_keys: BTreeSet<u64> = AOT_INDEX
            .iter()
            .map(|entry| entry.authority.cache_key)
            .collect();
        let architectures: BTreeSet<u32> = AOT_INDEX
            .iter()
            .map(|entry| entry.authority.target_sm)
            .collect();

        assert!(!source_keys.is_empty());
        assert!(!architectures.is_empty());
        assert_eq!(index_keys, source_keys);
        assert_eq!(AOT_INDEX.len(), source_keys.len() * architectures.len());
        for cache_key in source_keys {
            for sm in &architectures {
                assert!(aot_pack_contains(cache_key, sm / 10, sm % 10));
            }
        }
    }

    #[cfg(all(stwo_cuda_link, not(feature = "test-only-empty-aot-pack")))]
    #[test]
    fn generated_authority_matches_exact_manifest_and_source_bytes() {
        let generated = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("cuda")
            .join("generated");
        let manifest = std::fs::read(generated.join("aot_manifest.json")).unwrap();
        let metadata = crate::aot_source_manifest::parse_source_manifest(&manifest).unwrap();
        for entry in AOT_INDEX {
            let authority = entry.authority;
            let source = metadata
                .iter()
                .find(|metadata| metadata.cache_key == authority.cache_key)
                .expect("embedded authority has generated source metadata");
            let source_bytes = std::fs::read(generated.join(&source.file)).unwrap();
            assert_eq!(authority.kernel_symbol, source.kernel_symbol);
            assert_eq!(authority.semantic_hash, source.semantic_hash);
            assert_eq!(authority.abi_schema, source.abi_schema);
            assert_eq!(authority.program_identity, source.program_identity);
            assert_eq!(
                authority.source_identity,
                aot_identity::source_identity(&source_bytes)
            );
            crate::aot_source_manifest::validate_exported_kernel_symbol(
                &source_bytes,
                authority.kernel_symbol,
            )
            .unwrap();
        }
    }

    #[cfg(feature = "test-only-empty-aot-pack")]
    #[test]
    fn test_only_pack_is_empty_and_fails_closed() {
        assert!(AOT_PACK.is_empty());
        assert_eq!(aot_pack_entries(), 0);
        assert_eq!(aot_pack_identity(), ZERO_IDENTITY);
        assert_eq!(aot_pack_manifest_hash(), 0);
        assert_eq!(aot_pack_constraint_max_instrs(), 0);
        assert_eq!(aot_pack_constraint_max_live_u32_lanes(), 0);
        assert!(!aot_pack_supports_arch(8, 6));
        assert!(!aot_pack_contains(0, 8, 6));
        assert_eq!(aot_cubin_identity(0, 8, 6), ZERO_IDENTITY);
        assert_eq!(aot_kernel_authority(0, 8, 6), None);
    }
}

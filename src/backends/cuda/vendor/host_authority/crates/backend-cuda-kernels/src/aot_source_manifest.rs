//! Strict parser for the checked-in AOT source manifest.
//!
//! The generator emits structured ABIs for recorded-witness, ordinary
//! fused-constraint and composition-wave kernels.

use std::collections::BTreeSet;

use super::aot_identity::{AotKernelAbiAccess, AotKernelAbiKind, AotKernelAbiSchema};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceManifestEntry {
    pub kind: String,
    pub label: String,
    pub kernel_symbol: String,
    pub cache_key: u64,
    pub semantic_hash: u64,
    pub file: String,
    pub abi_schema: Option<AotKernelAbiSchema>,
    pub program_identity: [u8; 32],
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEntry {
    kind: String,
    label: String,
    kernel_name: String,
    cache_key: String,
    semantic_hash: String,
    file: String,
    abi_schema: Option<String>,
    program_identity: Option<String>,
}

pub(crate) fn parse_source_manifest(bytes: &[u8]) -> Result<Vec<SourceManifestEntry>, String> {
    let wire = serde_json::from_slice::<Vec<WireEntry>>(bytes)
        .map_err(|error| format!("decode AOT source manifest: {error}"))?;
    if wire.is_empty() {
        return Err("AOT source manifest is empty".to_string());
    }

    let mut entries = Vec::with_capacity(wire.len());
    let mut cache_keys = BTreeSet::new();
    let mut files = BTreeSet::new();
    let mut previous_order = None;
    for (index, entry) in wire.into_iter().enumerate() {
        if !matches!(entry.kind.as_str(), "constraint" | "witness") {
            return Err(format!(
                "AOT source manifest entry {index} has unknown kind {:?}",
                entry.kind
            ));
        }
        if entry.label.is_empty() {
            return Err(format!(
                "AOT source manifest entry {index} has an empty label"
            ));
        }
        if !is_cuda_identifier(&entry.kernel_name) {
            return Err(format!(
                "AOT source manifest entry {index} has an invalid kernel symbol"
            ));
        }
        let cache_key = parse_lower_hex_u64(&entry.cache_key, index, "cache_key")?;
        let semantic_hash = parse_lower_hex_u64(&entry.semantic_hash, index, "semantic_hash")?;
        let expected_schema = expected_abi_schema(index, &entry.kind, &entry.kernel_name)?;
        let abi_schema = parse_abi_schema(index, expected_schema, entry.abi_schema.as_deref())?;
        let program_identity =
            parse_program_identity(index, expected_schema, entry.program_identity.as_deref())?;
        let expected_file = format!("{}_{}_{cache_key:016x}.cu", entry.kind, entry.label);
        if entry.file != expected_file || !is_plain_file_name(&entry.file) {
            return Err(format!(
                "AOT source manifest entry {index} file does not match its metadata"
            ));
        }
        if !cache_keys.insert(cache_key) {
            return Err(format!(
                "AOT source manifest repeats cache key {cache_key:016x}"
            ));
        }
        if !files.insert(entry.file.clone()) {
            return Err(format!("AOT source manifest repeats file {:?}", entry.file));
        }
        let order = (entry.kind.clone(), entry.label.clone(), cache_key);
        if previous_order
            .as_ref()
            .is_some_and(|previous| previous >= &order)
        {
            return Err("AOT source manifest is not in canonical order".to_string());
        }
        previous_order = Some(order);
        entries.push(SourceManifestEntry {
            kind: entry.kind,
            label: entry.label,
            kernel_symbol: entry.kernel_name,
            cache_key,
            semantic_hash,
            file: entry.file,
            abi_schema,
            program_identity,
        });
    }
    Ok(entries)
}

fn parse_program_identity(
    index: usize,
    expected_schema: Option<AotKernelAbiSchema>,
    identity: Option<&str>,
) -> Result<[u8; 32], String> {
    match (expected_schema, identity) {
        (Some(_), Some(identity)) => {
            let identity = parse_lower_hex_identity(identity, index, "program_identity")?;
            if identity == [0; 32] {
                return Err(format!(
                    "AOT source manifest entry {index} has zero program_identity"
                ));
            }
            Ok(identity)
        }
        (Some(_), None) => Err(format!(
            "AOT source manifest entry {index} lacks program_identity"
        )),
        (None, None) => Ok([0; 32]),
        (None, Some(_)) => Err(format!(
            "AOT source manifest entry {index} claims unsupported program identity"
        )),
    }
}

fn parse_abi_schema(
    index: usize,
    expected: Option<AotKernelAbiSchema>,
    tag: Option<&str>,
) -> Result<Option<AotKernelAbiSchema>, String> {
    match (expected, tag) {
        (Some(expected), Some(tag)) if tag == expected.manifest_tag() => Ok(Some(expected)),
        (Some(expected), _) => Err(format!(
            "AOT source manifest entry {index} lacks canonical {} ABI",
            expected.family()
        )),
        (None, None) => Ok(None),
        (None, Some(_)) => Err(format!(
            "AOT source manifest entry {index} claims an unsupported structured ABI"
        )),
    }
}

fn expected_abi_schema(
    index: usize,
    kind: &str,
    kernel_symbol: &str,
) -> Result<Option<AotKernelAbiSchema>, String> {
    match kind {
        "witness" => Ok(Some(AotKernelAbiSchema::RecordedWitnessV1)),
        "constraint" if kernel_symbol.starts_with("stwo_jit_fused_") => {
            Ok(Some(AotKernelAbiSchema::OrdinaryConstraintV1))
        }
        "constraint" if kernel_symbol.starts_with("stwo_composition_wave_") => {
            Ok(Some(AotKernelAbiSchema::CompositionWaveV2))
        }
        "constraint" => Err(format!(
            "AOT source manifest entry {index} has an unsupported constraint family"
        )),
        _ => unreachable!("kind was validated before family classification"),
    }
}

/// Proves only the source-level exported symbol boundary. Argument types,
/// access ranges and effects remain unavailable until the generator emits a
/// structured schema.
pub(crate) fn validate_exported_kernel_symbol(
    source: &[u8],
    kernel_symbol: &str,
) -> Result<(), String> {
    let source = std::str::from_utf8(source)
        .map_err(|error| format!("generated CUDA source is not UTF-8: {error}"))?;
    let occurrences = source
        .match_indices(kernel_symbol)
        .filter(|(start, _)| {
            let end = start + kernel_symbol.len();
            identifier_boundary(
                start
                    .checked_sub(1)
                    .and_then(|index| source.as_bytes().get(index))
                    .copied(),
            ) && identifier_boundary(source.as_bytes().get(end).copied())
        })
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    let [symbol_start] = occurrences.as_slice() else {
        return Err(format!(
            "generated CUDA source must contain kernel symbol {kernel_symbol:?} exactly once"
        ));
    };
    let symbol_end = symbol_start + kernel_symbol.len();
    if !source[symbol_end..].trim_start().starts_with('(') {
        return Err(format!(
            "generated CUDA symbol {kernel_symbol:?} is not a function declaration"
        ));
    }
    const EXPORT_PREFIX: &str = "extern \"C\" __global__ void";
    let Some(prefix_start) = source[..*symbol_start].rfind(EXPORT_PREFIX) else {
        return Err(format!(
            "generated CUDA symbol {kernel_symbol:?} is not extern-C global"
        ));
    };
    let between = &source[prefix_start + EXPORT_PREFIX.len()..*symbol_start];
    if between.len() > 128 || between.chars().any(|char| matches!(char, ';' | '{' | '}')) {
        return Err(format!(
            "generated CUDA symbol {kernel_symbol:?} has an unrecognized export declaration"
        ));
    }
    Ok(())
}

/// Validate the exact C argument declaration owned by a structured schema.
/// Source identity still seals the whole translation unit; this closes the
/// narrower risk of a hand-edited manifest attaching the right tag to a wrong
/// generated signature.
pub(crate) fn validate_structured_kernel_signature(
    source: &[u8],
    kernel_symbol: &str,
    schema: AotKernelAbiSchema,
) -> Result<(), String> {
    validate_exported_kernel_symbol(source, kernel_symbol)?;
    let source = std::str::from_utf8(source)
        .map_err(|error| format!("generated CUDA source is not UTF-8: {error}"))?;
    let symbol_end = source
        .find(kernel_symbol)
        .expect("export validation found the unique kernel symbol")
        + kernel_symbol.len();
    let parameter_tail = source[symbol_end..]
        .trim_start()
        .strip_prefix('(')
        .ok_or_else(|| format!("generated CUDA symbol {kernel_symbol:?} has no parameter list"))?;
    let uncommented = parameter_tail
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n");
    let parameters = uncommented
        .split_once(')')
        .map(|(parameters, _)| parameters)
        .ok_or_else(|| format!("generated CUDA symbol {kernel_symbol:?} has no parameter list"))?;
    let actual = parameters
        .split(',')
        .map(strip_ascii_whitespace)
        .collect::<Vec<_>>();
    let expected = schema
        .arguments()
        .iter()
        .map(canonical_c_argument)
        .collect::<Result<Vec<_>, _>>()?;
    if actual != expected {
        return Err(format!(
            "generated CUDA symbol {kernel_symbol:?} does not match {} ABI: actual {actual:?}, \
             expected {expected:?}",
            schema.family(),
        ));
    }
    Ok(())
}

fn canonical_c_argument(
    argument: &super::aot_identity::AotKernelAbiArgument,
) -> Result<String, String> {
    let prefix = match (argument.kind, argument.access) {
        (AotKernelAbiKind::U32, AotKernelAbiAccess::LaunchRowCount)
        | (AotKernelAbiKind::U32, AotKernelAbiAccess::TraceLogSize)
        | (AotKernelAbiKind::U32, AotKernelAbiAccess::RandomCoefficientBase)
        | (AotKernelAbiKind::U32, AotKernelAbiAccess::FullDomainRows)
        | (AotKernelAbiKind::U32, AotKernelAbiAccess::ShardStart)
        | (AotKernelAbiKind::U32, AotKernelAbiAccess::ShardRows) => "unsigned",
        (AotKernelAbiKind::DevicePointerU32, AotKernelAbiAccess::Read) => "constunsigned*",
        (AotKernelAbiKind::DevicePointerCompositionWavePart, AotKernelAbiAccess::Read) => {
            "constStwoCudaCompositionWavePart*"
        }
        (
            AotKernelAbiKind::DevicePointerU32,
            AotKernelAbiAccess::Write | AotKernelAbiAccess::ReadWrite,
        ) => "unsigned*",
        (AotKernelAbiKind::DevicePointerTableU32, AotKernelAbiAccess::Read) => {
            "constunsigned*const*"
        }
        (
            AotKernelAbiKind::DevicePointerTableU32,
            AotKernelAbiAccess::Write | AotKernelAbiAccess::ReadWrite,
        ) => "unsigned*const*",
        _ => {
            return Err(format!(
                "{} ABI has invalid kind/access pair at argument {}",
                argument.name, argument.ordinal
            ));
        }
    };
    Ok(format!("{prefix}{}", argument.name))
}

fn strip_ascii_whitespace(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}

fn parse_lower_hex_u64(value: &str, index: usize, field: &'static str) -> Result<u64, String> {
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "AOT source manifest entry {index} has invalid {field}"
        ));
    }
    u64::from_str_radix(value, 16)
        .map_err(|error| format!("parse AOT source manifest {field}: {error}"))
}

fn parse_lower_hex_identity(
    value: &str,
    index: usize,
    field: &'static str,
) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "AOT source manifest entry {index} has invalid {field}"
        ));
    }
    let mut identity = [0; 32];
    for (byte, digits) in identity.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *byte = (lower_hex_nibble(digits[0]) << 4) | lower_hex_nibble(digits[1]);
    }
    Ok(identity)
}

fn lower_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("hexadecimal input was validated"),
    }
}

fn is_cuda_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn is_plain_file_name(value: &str) -> bool {
    let path = std::path::Path::new(value);
    path.file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new(value))
        && path.components().count() == 1
        && !value.contains(['/', '\\'])
}

fn identifier_boundary(byte: Option<u8>) -> bool {
    byte.is_none_or(|byte| byte != b'_' && !byte.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Vec<u8> {
        br#"[
          {
            "abi_schema":"ordinary_constraint_v1",
            "kind":"constraint",
            "label":"add_ap",
            "kernel_name":"stwo_jit_fused_a",
            "cache_key":"0000000000000001",
            "semantic_hash":"0000000000000002",
            "program_identity":"0202020202020202020202020202020202020202020202020202020202020202",
            "file":"constraint_add_ap_0000000000000001.cu"
          },
          {
            "abi_schema":"composition_wave_v2",
            "kind":"constraint",
            "label":"wave_log_10",
            "kernel_name":"stwo_composition_wave_a",
            "cache_key":"0000000000000003",
            "semantic_hash":"0000000000000004",
            "program_identity":"0303030303030303030303030303030303030303030303030303030303030303",
            "file":"constraint_wave_log_10_0000000000000003.cu"
          },
          {
            "abi_schema":"recorded_witness_v1",
            "kind":"witness",
            "label":"mul",
            "kernel_name":"kernel_b",
            "cache_key":"0000000000000005",
            "semantic_hash":"0000000000000006",
            "program_identity":"0101010101010101010101010101010101010101010101010101010101010101",
            "file":"witness_mul_0000000000000005.cu"
          }
        ]"#
        .to_vec()
    }

    #[test]
    fn strict_manifest_parser_accepts_only_canonical_complete_entries() {
        let parsed = parse_source_manifest(&manifest()).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].cache_key, 1);
        assert_eq!(parsed[0].program_identity, [2; 32]);
        assert_eq!(parsed[1].semantic_hash, 4);
        assert_eq!(parsed[1].program_identity, [3; 32]);
        assert_eq!(parsed[2].program_identity, [1; 32]);
        assert_eq!(
            parsed[0].abi_schema,
            Some(AotKernelAbiSchema::OrdinaryConstraintV1)
        );
        assert_eq!(
            parsed[1].abi_schema,
            Some(AotKernelAbiSchema::CompositionWaveV2)
        );
        assert_eq!(
            parsed[2].abi_schema,
            Some(AotKernelAbiSchema::RecordedWitnessV1)
        );

        for mutation in [
            ("\"cache_key\":\"0000000000000001\"", "\"cache_key\":\"1\""),
            (
                "\"semantic_hash\":\"0000000000000002\"",
                "\"semantic_hash\":\"000000000000000G\"",
            ),
            (
                "\"kernel_name\":\"stwo_jit_fused_a\"",
                "\"kernel_name\":\"bad-kernel\"",
            ),
            ("\"kind\":\"constraint\"", "\"kind\":\"unknown\""),
            (
                "\"file\":\"constraint_add_ap_0000000000000001.cu\"",
                "\"file\":\"../kernel.cu\"",
            ),
            (
                "\"abi_schema\":\"ordinary_constraint_v1\"",
                "\"abi_schema\":\"unknown\"",
            ),
            (
                "0202020202020202020202020202020202020202020202020202020202020202",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ] {
            let changed = String::from_utf8(manifest())
                .unwrap()
                .replace(mutation.0, mutation.1);
            assert!(parse_source_manifest(changed.as_bytes()).is_err());
        }
    }

    #[test]
    fn duplicate_or_reordered_entries_are_rejected() {
        let original = String::from_utf8(manifest()).unwrap();
        let duplicate_key = original.replace(
            "\"cache_key\":\"0000000000000005\"",
            "\"cache_key\":\"0000000000000001\"",
        );
        assert!(parse_source_manifest(duplicate_key.as_bytes()).is_err());

        let entries = serde_json::from_str::<Vec<serde_json::Value>>(&original).unwrap();
        let reordered =
            serde_json::to_vec(&[entries[1].clone(), entries[0].clone(), entries[2].clone()])
                .unwrap();
        assert!(parse_source_manifest(&reordered).is_err());
    }

    #[test]
    fn structured_abi_is_exactly_required_for_typed_families() {
        let mut entries = serde_json::from_slice::<Vec<serde_json::Value>>(&manifest()).unwrap();
        let abi = entries[0].get("abi_schema").unwrap().clone();
        let program_identity = entries[0].get("program_identity").unwrap().clone();
        entries[0].as_object_mut().unwrap().remove("abi_schema");
        assert!(parse_source_manifest(&serde_json::to_vec(&entries).unwrap()).is_err());

        entries[0]
            .as_object_mut()
            .unwrap()
            .insert("abi_schema".into(), abi.clone());
        entries[0]
            .as_object_mut()
            .unwrap()
            .remove("program_identity");
        assert!(parse_source_manifest(&serde_json::to_vec(&entries).unwrap()).is_err());

        entries[0]
            .as_object_mut()
            .unwrap()
            .insert("abi_schema".into(), abi.clone());
        entries[0]
            .as_object_mut()
            .unwrap()
            .insert("program_identity".into(), program_identity.clone());
        entries[1]["abi_schema"] = abi;
        entries[1]["program_identity"] = program_identity;
        assert!(parse_source_manifest(&serde_json::to_vec(&entries).unwrap()).is_err());

        let mut unsupported =
            serde_json::from_slice::<Vec<serde_json::Value>>(&manifest()).unwrap();
        unsupported[0]["kernel_name"] = serde_json::json!("constraint_unknown_family");
        assert!(parse_source_manifest(&serde_json::to_vec(&unsupported).unwrap()).is_err());
    }

    #[test]
    fn source_symbol_validation_is_narrow_and_fail_closed() {
        let source = br#"
            extern "C" __global__ void __launch_bounds__(256) kernel_a(
                const unsigned *input,
                unsigned *output) {}
        "#;
        validate_exported_kernel_symbol(source, "kernel_a").unwrap();
        for invalid in [
            br#"__global__ void kernel_a() {}"#.as_slice(),
            br#"extern "C" __global__ void kernel_a;"#.as_slice(),
            br#"extern "C" __global__ void kernel_a() {} kernel_a"#.as_slice(),
        ] {
            assert!(validate_exported_kernel_symbol(invalid, "kernel_a").is_err());
        }
    }

    #[test]
    fn structured_signature_validation_rejects_type_order_and_arity_drift() {
        let source = br#"
            extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_a(
                const unsigned *const *trace_cols,
                const unsigned *interaction_offsets,
                const unsigned *base_params,
                const unsigned *ext_params,
                const unsigned *random_coeff_powers,
                const unsigned *denom_inv,
                unsigned *coord_0,
                unsigned *coord_1,
                unsigned *coord_2,
                unsigned *coord_3,
                unsigned row_count,
                unsigned log_n_rows,
                unsigned rc_base) {}
        "#;
        let schema = AotKernelAbiSchema::OrdinaryConstraintV1;
        validate_structured_kernel_signature(source, "stwo_jit_fused_a", schema).unwrap();
        for changed in [
            String::from_utf8_lossy(source)
                .replace("const unsigned *base_params", "unsigned *base_params"),
            String::from_utf8_lossy(source).replace("coord_0,", "wrong_coord,"),
            String::from_utf8_lossy(source).replace("unsigned rc_base", ""),
        ] {
            assert!(validate_structured_kernel_signature(
                changed.as_bytes(),
                "stwo_jit_fused_a",
                schema
            )
            .is_err());
        }

        let wave_source = br#"
            struct StwoCudaCompositionWavePart {};
            extern "C" __global__ void __launch_bounds__(128) stwo_composition_wave_a(
                const StwoCudaCompositionWavePart *parts,
                const unsigned *random_coeff_powers,
                unsigned *coord_0,
                unsigned *coord_1,
                unsigned *coord_2,
                unsigned *coord_3,
                unsigned full_domain_rows,
                unsigned shard_start,
                unsigned shard_rows) {}
        "#;
        let wave_schema = AotKernelAbiSchema::CompositionWaveV2;
        validate_structured_kernel_signature(wave_source, "stwo_composition_wave_a", wave_schema)
            .unwrap();
        for changed in [
            String::from_utf8_lossy(wave_source).replace(
                "const StwoCudaCompositionWavePart *parts",
                "const unsigned *parts",
            ),
            String::from_utf8_lossy(wave_source)
                .replace("unsigned shard_start", "unsigned wrong_start"),
            String::from_utf8_lossy(wave_source).replace("unsigned shard_rows", ""),
        ] {
            assert!(validate_structured_kernel_signature(
                changed.as_bytes(),
                "stwo_composition_wave_a",
                wave_schema,
            )
            .is_err());
        }
    }

    #[test]
    fn checked_in_manifest_and_every_declared_source_are_exact() {
        let generated = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("cuda")
            .join("generated");
        let manifest = std::fs::read(generated.join("aot_manifest.json")).unwrap();
        let entries = parse_source_manifest(&manifest).unwrap();
        let source_files = std::fs::read_dir(&generated)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "cu"))
            .count();
        assert_eq!(entries.len(), source_files);
        assert!(entries
            .iter()
            .filter(|entry| entry.kind == "witness")
            .all(|entry| {
                entry.abi_schema == Some(AotKernelAbiSchema::RecordedWitnessV1)
                    && entry.program_identity != [0; 32]
            }));
        assert!(entries
            .iter()
            .filter(|entry| entry.kind == "constraint")
            .all(|entry| {
                if entry.kernel_symbol.starts_with("stwo_jit_fused_") {
                    entry.abi_schema == Some(AotKernelAbiSchema::OrdinaryConstraintV1)
                        && entry.program_identity != [0; 32]
                } else {
                    entry.kernel_symbol.starts_with("stwo_composition_wave_")
                        && entry.abi_schema == Some(AotKernelAbiSchema::CompositionWaveV2)
                        && entry.program_identity != [0; 32]
                }
            }));
        for entry in entries {
            let source = std::fs::read(generated.join(&entry.file)).unwrap();
            if let Some(schema) = entry.abi_schema {
                validate_structured_kernel_signature(&source, &entry.kernel_symbol, schema)
                    .unwrap();
            } else {
                validate_exported_kernel_symbol(&source, &entry.kernel_symbol).unwrap();
            }
        }
    }
}

use std::mem::size_of;
use std::path::PathBuf;

use blake3::{Hash, Hasher};
use serde::{Deserialize, Serialize};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::SecureField;
use stwo_backend_cuda::{
    quotient_numerator_hybrid_plan, quotient_numerator_workspace_requirements,
    QuotientNumeratorColumnTopology, QuotientNumeratorHybridPlan, QuotientNumeratorSourceKind,
    QuotientNumeratorWorkspaceConfig, QuotientNumeratorWorkspaceRequirements, QuotientOodsSample,
};

const FIXTURE_SCHEMA: &str = "stwo.quotient_numerator.topology_fixture";
const FIXTURE_VERSION: u32 = 1;
const DIGEST_ALGORITHM: &str = "blake3";
const DIGEST_ENCODING: &str = "tag-u32le-payload-u64le-scalars-le.v1";
const DIGEST_DOMAIN: &[u8] = b"stwo.quotient-numerator.topology-fixture.v1\0";
const FIXTURE_PATH: &str = "tests/fixtures/sn3_quotient_numerator_topology.v1.json";

#[derive(Debug)]
pub(super) struct LoadedTopologyFixture {
    pub(super) config: QuotientNumeratorWorkspaceConfig,
    pub(super) topology: Vec<QuotientNumeratorColumnTopology>,
    pub(super) input_points: Vec<CirclePoint<SecureField>>,
    pub(super) requirements: QuotientNumeratorWorkspaceRequirements,
    pub(super) hybrid: QuotientNumeratorHybridPlan,
    pub(super) digest: Hash,
}

pub(super) fn load_sn3_topology_fixture(expected_digest: &str) -> LoadedTopologyFixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_PATH);
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "read exact SN3 topology fixture {}: {error}",
            path.display()
        )
    });
    decode_fixture(&bytes, expected_digest)
        .unwrap_or_else(|error| panic!("validate exact SN3 topology fixture: {error}"))
}

fn decode_fixture(bytes: &[u8], expected_digest: &str) -> Result<LoadedTopologyFixture, String> {
    let raw: RawFixture = serde_json::from_slice(bytes)
        .map_err(|error| format!("strict JSON decode failed: {error}"))?;
    validate_header(&raw)?;

    let column_count = as_usize(raw.column_count, "column_count")?;
    let sample_count = as_usize(raw.sample_count, "sample_count")?;
    let input_sample_count = as_usize(raw.input_sample_count, "input_sample_count")?;
    if column_count == 0 || sample_count == 0 || input_sample_count == 0 {
        return Err("topology counts must all be non-zero".to_owned());
    }
    if input_sample_count > sample_count {
        return Err("input_sample_count cannot exceed sample_count".to_owned());
    }
    if raw.columns.len() != column_count {
        return Err(format!(
            "column_count {} disagrees with {} columns",
            raw.column_count,
            raw.columns.len()
        ));
    }

    let config = QuotientNumeratorWorkspaceConfig {
        lifting_log_size: raw.config.lifting_log_size,
        log_blowup_factor: raw.config.log_blowup_factor,
        max_lde_tile_words: as_usize(raw.config.max_lde_tile_words, "config.max_lde_tile_words")?,
    };
    let mut observed_samples = 0usize;
    let mut input_points = vec![None; input_sample_count];
    let mut topology = Vec::with_capacity(column_count);
    for (column_index, column) in raw.columns.iter().enumerate() {
        if column.column_index != as_u64(column_index) {
            return Err(format!(
                "column ordinal {} appears at array index {column_index}",
                column.column_index
            ));
        }
        let column_samples = as_usize(column.sample_count, "column.sample_count")?;
        if column.samples.len() != column_samples {
            return Err(format!(
                "column {column_index} sample_count {} disagrees with {} samples",
                column.sample_count,
                column.samples.len()
            ));
        }
        observed_samples = observed_samples
            .checked_add(column_samples)
            .ok_or_else(|| "sample count overflowed usize".to_owned())?;
        let mut samples = Vec::with_capacity(column_samples);
        for (sample_index, sample) in column.samples.iter().enumerate() {
            if sample.sample_index != as_u64(sample_index) {
                return Err(format!(
                    "column {column_index} sample ordinal {} appears at index {sample_index}",
                    sample.sample_index
                ));
            }
            let point = point_from_limbs(sample.shape_point_m31)
                .map_err(|error| format!("column {column_index} sample {sample_index}: {error}"))?;
            let input_index = usize::try_from(sample.input_index)
                .map_err(|_| "sample input_index exceeds usize".to_owned())?;
            let Some(entry) = input_points.get_mut(input_index) else {
                return Err(format!(
                    "column {column_index} sample {sample_index} input_index {} exceeds input_sample_count {input_sample_count}",
                    sample.input_index
                ));
            };
            if let Some(existing) = entry {
                let kind = if *existing == point {
                    "duplicate"
                } else {
                    "inconsistent"
                };
                return Err(format!(
                    "input_index {} has a {kind} shape-point mapping",
                    sample.input_index
                ));
            }
            *entry = Some(point);
            samples.push(QuotientOodsSample {
                input_index: sample.input_index,
                shape_point: point,
            });
        }
        topology.push(QuotientNumeratorColumnTopology {
            coefficient_log_size: column.coefficient_log_size,
            source_kind: column.source_kind.backend(),
            samples,
        });
    }
    if observed_samples != sample_count {
        return Err(format!(
            "sample_count {} disagrees with {observed_samples} column samples",
            raw.sample_count
        ));
    }
    let input_points = input_points
        .into_iter()
        .enumerate()
        .map(|(index, point)| point.ok_or_else(|| format!("input_index {index} is missing")))
        .collect::<Result<Vec<_>, _>>()?;

    let digest = fixture_digest(&raw);
    let declared = parse_digest(&raw.digest.hex, "fixture digest")?;
    if digest != declared {
        return Err(format!(
            "fixture digest mismatch: declared {declared}, recomputed {digest}"
        ));
    }
    let expected = parse_digest(expected_digest, "sealed expected digest")?;
    if digest != expected {
        return Err(format!(
            "fixture digest is not the sealed SN3 digest: expected {expected}, got {digest}"
        ));
    }

    // The fixture never carries either object: backend code under test must
    // reproduce both from the exact address-free input topology.
    let requirements = quotient_numerator_workspace_requirements(config, &topology)
        .map_err(|error| format!("recompute workspace requirements: {error}"))?;
    if requirements.input_sample_count != input_sample_count {
        return Err(format!(
            "recomputed input_sample_count {} disagrees with fixture {input_sample_count}",
            requirements.input_sample_count
        ));
    }
    let hybrid = quotient_numerator_hybrid_plan(config, &topology)
        .map_err(|error| format!("recompute hybrid plan: {error}"))?;
    if hybrid.requirements() != &requirements {
        return Err("recomputed hybrid requirements disagree with legacy requirements".to_owned());
    }
    Ok(LoadedTopologyFixture {
        config,
        topology,
        input_points,
        requirements,
        hybrid,
        digest,
    })
}

fn validate_header(raw: &RawFixture) -> Result<(), String> {
    if raw.schema != FIXTURE_SCHEMA {
        return Err(format!("unsupported fixture schema {}", raw.schema));
    }
    if raw.version != FIXTURE_VERSION {
        return Err(format!("unsupported fixture version {}", raw.version));
    }
    if raw.digest.algorithm != DIGEST_ALGORITHM || raw.digest.encoding != DIGEST_ENCODING {
        return Err(format!(
            "unsupported digest framing {} / {}",
            raw.digest.algorithm, raw.digest.encoding
        ));
    }
    Ok(())
}

fn point_from_limbs(limbs: [u32; 8]) -> Result<CirclePoint<SecureField>, String> {
    for (index, limb) in limbs.iter().enumerate() {
        if *limb >= P {
            return Err(format!(
                "shape_point_m31 limb {index} is {limb}, expected < {P}"
            ));
        }
    }
    let coordinate = |offset| {
        SecureField::from_m31_array(std::array::from_fn(|index| {
            M31::from_u32_unchecked(limbs[offset + index])
        }))
    };
    Ok(CirclePoint {
        x: coordinate(0),
        y: coordinate(4),
    })
}

fn fixture_digest(raw: &RawFixture) -> Hash {
    let mut digest = FramedDigest::new();
    digest.bytes("schema", raw.schema.as_bytes());
    digest.u32("version", raw.version);
    digest.bytes("digest.algorithm", raw.digest.algorithm.as_bytes());
    digest.bytes("digest.encoding", raw.digest.encoding.as_bytes());
    digest.u32("config.lifting_log_size", raw.config.lifting_log_size);
    digest.u32("config.log_blowup_factor", raw.config.log_blowup_factor);
    digest.u64("config.max_lde_tile_words", raw.config.max_lde_tile_words);
    digest.u64("column_count", raw.column_count);
    digest.u64("sample_count", raw.sample_count);
    digest.u64("input_sample_count", raw.input_sample_count);
    for column in &raw.columns {
        digest.u64("column.index", column.column_index);
        digest.u32("column.coefficient_log_size", column.coefficient_log_size);
        digest.bytes("column.source_kind", column.source_kind.as_str().as_bytes());
        digest.u64("column.sample_count", column.sample_count);
        for sample in &column.samples {
            digest.u64("sample.index", sample.sample_index);
            digest.u32("sample.input_index", sample.input_index);
            let mut encoded = [0u8; 8 * size_of::<u32>()];
            for (destination, limb) in encoded.chunks_exact_mut(4).zip(sample.shape_point_m31) {
                destination.copy_from_slice(&limb.to_le_bytes());
            }
            digest.bytes("sample.shape_point_m31", &encoded);
        }
    }
    digest.finish()
}

fn parse_digest(value: &str, label: &str) -> Result<Hash, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be 64 lowercase hexadecimal characters"
        ));
    }
    Hash::from_hex(value).map_err(|error| format!("parse {label}: {error}"))
}

fn as_usize(value: u64, field: &str) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| format!("{field} exceeds usize"))
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).expect("fixture ordinal exceeds u64")
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawFixture {
    schema: String,
    version: u32,
    digest: RawDigest,
    config: RawConfig,
    column_count: u64,
    sample_count: u64,
    input_sample_count: u64,
    columns: Vec<RawColumn>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawDigest {
    algorithm: String,
    encoding: String,
    hex: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    lifting_log_size: u32,
    log_blowup_factor: u32,
    max_lde_tile_words: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawColumn {
    column_index: u64,
    coefficient_log_size: u32,
    source_kind: RawSourceKind,
    sample_count: u64,
    samples: Vec<RawSample>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RawSourceKind {
    Evaluation,
    Coefficients,
}

impl RawSourceKind {
    fn backend(self) -> QuotientNumeratorSourceKind {
        match self {
            Self::Evaluation => QuotientNumeratorSourceKind::Evaluation,
            Self::Coefficients => QuotientNumeratorSourceKind::Coefficients,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Evaluation => "evaluation",
            Self::Coefficients => "coefficients",
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawSample {
    sample_index: u64,
    input_index: u32,
    shape_point_m31: [u32; 8],
}

struct FramedDigest(Hasher);

impl FramedDigest {
    fn new() -> Self {
        let mut hasher = Hasher::new();
        hasher.update(DIGEST_DOMAIN);
        Self(hasher)
    }

    fn bytes(&mut self, tag: &str, payload: &[u8]) {
        self.0.update(
            &u32::try_from(tag.len())
                .expect("fixture digest tag exceeds u32")
                .to_le_bytes(),
        );
        self.0.update(tag.as_bytes());
        self.0.update(
            &u64::try_from(payload.len())
                .expect("fixture digest payload exceeds u64")
                .to_le_bytes(),
        );
        self.0.update(payload);
    }

    fn u32(&mut self, tag: &str, value: u32) {
        self.bytes(tag, &value.to_le_bytes());
    }

    fn u64(&mut self, tag: &str, value: u64) {
        self.bytes(tag, &value.to_le_bytes());
    }

    fn finish(self) -> Hash {
        self.0.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_fixture_rebuilds_requirements_and_hybrid_plan() {
        let raw = valid_fixture();
        let loaded = decode_raw(&raw, &raw.digest.hex).unwrap();
        assert_eq!(loaded.topology.len(), 1);
        assert_eq!(loaded.input_points.len(), 1);
        assert_eq!(loaded.requirements.input_sample_count, 1);
        assert_eq!(loaded.hybrid.report().eligible_group_count, 1);
    }

    #[test]
    fn strict_schema_rejects_unknown_nested_fields() {
        let raw = valid_fixture();
        for path in ["digest", "config", "column", "sample"] {
            let mut value = serde_json::to_value(&raw).unwrap();
            match path {
                "digest" => value["digest"]["unknown"] = true.into(),
                "config" => value["config"]["unknown"] = true.into(),
                "column" => value["columns"][0]["unknown"] = true.into(),
                "sample" => value["columns"][0]["samples"][0]["unknown"] = true.into(),
                _ => unreachable!(),
            }
            assert!(
                serde_json::from_value::<RawFixture>(value).is_err(),
                "accepted unknown {path} field"
            );
        }
    }

    #[test]
    fn non_contiguous_column_and_sample_ordinals_are_rejected() {
        let mut column = valid_fixture();
        column.columns[0].column_index = 1;
        assert!(decode_raw(&column, &column.digest.hex)
            .unwrap_err()
            .contains("column ordinal"));

        let mut sample = valid_fixture();
        sample.columns[0].samples[0].sample_index = 1;
        assert!(decode_raw(&sample, &sample.digest.hex)
            .unwrap_err()
            .contains("sample ordinal"));
    }

    #[test]
    fn duplicate_and_inconsistent_input_index_mappings_are_rejected() {
        for inconsistent in [false, true] {
            let mut raw = valid_fixture();
            let mut duplicate = raw.columns[0].samples[0].clone();
            duplicate.sample_index = 1;
            if inconsistent {
                duplicate.shape_point_m31[0] += 1;
            }
            raw.columns[0].samples.push(duplicate);
            raw.columns[0].sample_count = 2;
            raw.sample_count = 2;
            reseal(&mut raw);
            let error = decode_raw(&raw, &raw.digest.hex).unwrap_err();
            let expected = if inconsistent {
                "inconsistent"
            } else {
                "duplicate"
            };
            assert!(error.contains(expected), "unexpected error: {error}");
        }
    }

    #[test]
    fn declared_count_drift_is_rejected() {
        let mut root_columns = valid_fixture();
        root_columns.column_count = 2;
        assert!(decode_raw(&root_columns, &root_columns.digest.hex)
            .unwrap_err()
            .contains("column_count"));

        let mut root_samples = valid_fixture();
        root_samples.sample_count = 2;
        assert!(decode_raw(&root_samples, &root_samples.digest.hex)
            .unwrap_err()
            .contains("sample_count"));

        let mut column_samples = valid_fixture();
        column_samples.columns[0].sample_count = 2;
        assert!(decode_raw(&column_samples, &column_samples.digest.hex)
            .unwrap_err()
            .contains("sample_count"));
    }

    #[test]
    fn noncanonical_m31_limb_is_rejected_through_loader() {
        let mut raw = valid_fixture();
        raw.columns[0].samples[0].shape_point_m31[7] = P;
        reseal(&mut raw);
        assert!(decode_raw(&raw, &raw.digest.hex)
            .unwrap_err()
            .contains("expected <"));
    }

    #[test]
    fn digest_mutation_is_rejected() {
        let mut raw = valid_fixture();
        let expected = raw.digest.hex.clone();
        raw.digest.hex.replace_range(0..1, "f");
        if raw.digest.hex == expected {
            raw.digest.hex.replace_range(0..1, "e");
        }
        assert!(decode_raw(&raw, &expected)
            .unwrap_err()
            .contains("fixture digest mismatch"));
    }

    fn valid_fixture() -> RawFixture {
        let mut raw = RawFixture {
            schema: FIXTURE_SCHEMA.to_owned(),
            version: FIXTURE_VERSION,
            digest: RawDigest {
                algorithm: DIGEST_ALGORITHM.to_owned(),
                encoding: DIGEST_ENCODING.to_owned(),
                hex: String::new(),
            },
            config: RawConfig {
                lifting_log_size: 4,
                log_blowup_factor: 1,
                max_lde_tile_words: 16,
            },
            column_count: 1,
            sample_count: 1,
            input_sample_count: 1,
            columns: vec![RawColumn {
                column_index: 0,
                coefficient_log_size: 2,
                source_kind: RawSourceKind::Evaluation,
                sample_count: 1,
                samples: vec![RawSample {
                    sample_index: 0,
                    input_index: 0,
                    shape_point_m31: [1, 2, 3, 4, 5, 6, 7, 8],
                }],
            }],
        };
        reseal(&mut raw);
        raw
    }

    fn reseal(raw: &mut RawFixture) {
        raw.digest.hex = fixture_digest(raw).to_hex().to_string();
    }

    fn decode_raw(raw: &RawFixture, expected: &str) -> Result<LoadedTopologyFixture, String> {
        decode_fixture(&serde_json::to_vec(raw).unwrap(), expected)
    }
}

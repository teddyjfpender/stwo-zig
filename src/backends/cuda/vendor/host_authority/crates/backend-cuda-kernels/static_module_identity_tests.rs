use std::path::Path;

use super::*;

#[derive(Clone)]
struct Fixture {
    sms: Vec<u32>,
    nvcc_path: String,
    nvcc_bytes: Vec<u8>,
    nvcc_version: Vec<u8>,
    host_path: String,
    host_bytes: Vec<u8>,
    host_version: Vec<u8>,
    sources: Vec<(String, Vec<u8>)>,
    objects: Vec<(String, Vec<String>, Vec<u8>)>,
    dlink_argv: Vec<String>,
    dlink_bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            sms: vec![86, 90],
            nvcc_path: "/cuda/bin/nvcc".into(),
            nvcc_bytes: b"exact nvcc executable".to_vec(),
            nvcc_version: b"nvcc stdout\0nvcc stderr".to_vec(),
            host_path: "/usr/bin/c++".into(),
            host_bytes: b"exact host executable".to_vec(),
            host_version: b"c++ stdout\0c++ stderr".to_vec(),
            sources: vec![
                ("cuda/ec_op_witness.cu".into(), b"ec source".to_vec()),
                ("cuda/fields.cu".into(), b"field source".to_vec()),
                ("cuda/fields.cuh".into(), b"field header".to_vec()),
            ],
            objects: vec![
                (
                    "cuda/ec_op_witness.cu".into(),
                    vec!["-dc".into(), "cuda/ec_op_witness.cu".into()],
                    b"ec object".to_vec(),
                ),
                (
                    "cuda/fields.cu".into(),
                    vec!["-dc".into(), "cuda/fields.cu".into()],
                    b"field object".to_vec(),
                ),
            ],
            dlink_argv: vec!["-dlink".into(), "ec.o".into(), "fields.o".into()],
            dlink_bytes: b"device link object".to_vec(),
        }
    }

    fn digest(&self) -> Result<[u8; 32], &'static str> {
        let sources = self
            .sources
            .iter()
            .map(|(path, bytes)| ExactFile { path, bytes })
            .collect::<Vec<_>>();
        let objects = self
            .objects
            .iter()
            .map(|(source_path, argv, bytes)| TuObject {
                source_path,
                argv,
                bytes,
            })
            .collect::<Vec<_>>();
        static_module_build_identity(&StaticModuleIdentityInput {
            target_sms: &self.sms,
            nvcc: ExecutableIdentity {
                path: &self.nvcc_path,
                bytes: &self.nvcc_bytes,
                version_output: &self.nvcc_version,
            },
            host_compiler: ExecutableIdentity {
                path: &self.host_path,
                bytes: &self.host_bytes,
                version_output: &self.host_version,
            },
            sources: &sources,
            objects: &objects,
            dlink_argv: &self.dlink_argv,
            dlink_bytes: &self.dlink_bytes,
        })
    }
}

#[test]
fn archive_payload_identity_covers_every_authority_class() {
    let fixture = Fixture::new();
    let baseline = fixture.digest().unwrap();
    let changed = |mutate: fn(&mut Fixture)| {
        let mut candidate = fixture.clone();
        mutate(&mut candidate);
        assert_ne!(baseline, candidate.digest().unwrap());
    };

    changed(|f| f.sms[0] = 80);
    changed(|f| f.nvcc_path.push_str("-other"));
    changed(|f| f.nvcc_bytes.push(1));
    changed(|f| f.nvcc_version.push(1));
    changed(|f| f.host_path.push_str("-other"));
    changed(|f| f.host_bytes.push(1));
    changed(|f| f.host_version.push(1));
    changed(|f| {
        f.sources[0].0 = "cuda/a.cu".into();
        f.objects[0].0 = "cuda/a.cu".into();
    });
    changed(|f| f.sources[0].1.push(1));
    changed(|f| f.objects[0].1.push("-lineinfo".into()));
    changed(|f| f.objects[0].2.push(1));
    changed(|f| f.dlink_argv.push("-lineinfo".into()));
    changed(|f| f.dlink_bytes.push(1));
}

#[test]
fn archive_payload_identity_rejects_noncanonical_ordering() {
    let mut fixture = Fixture::new();
    fixture.sms.reverse();
    assert!(fixture.digest().is_err());
    let mut fixture = Fixture::new();
    fixture.sources.reverse();
    assert!(fixture.digest().is_err());
    let mut fixture = Fixture::new();
    fixture.objects.reverse();
    assert!(fixture.digest().is_err());
}

#[test]
fn target_sms_are_numeric_sorted_and_deduplicated() {
    assert_eq!(
        normalized_target_sms("sm_90, sm_86,sm_90").unwrap(),
        vec![86, 90]
    );
    for invalid in ["", "native", "sm_", "sm_0", "sm_86,native"] {
        assert!(normalized_target_sms(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn archive_payload_identity_has_stable_canonical_encoding() {
    let digest = Fixture::new().digest().unwrap();
    assert_eq!(
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "9d5ac1fae6216e8509ff19f425589b86fdf164e3295f344c47d692d9f7baad12"
    );
}

#[test]
fn ordinary_source_closure_is_exact_and_excludes_generated_aot() {
    for path in ["cuda/a.cu", "cuda/a.cuh", "cuda/a.h", "cuda/a.hpp"] {
        assert!(is_ordinary_cuda_authority_file(Path::new(path)), "{path}");
    }
    for path in [
        "cuda/a.cc",
        "cuda/a.txt",
        "cuda/generated/a.cu",
        "cuda/generated/nested/a.hpp",
    ] {
        assert!(!is_ordinary_cuda_authority_file(Path::new(path)), "{path}");
    }
}

#[test]
fn build_pipeline_pairs_archive_lto_and_keeps_aot_isolated() {
    let build = include_str!("build.rs");
    for required in [
        "let object_gencode_flags = archive_gencode_flags(&target_sms, archive_lto);",
        "let dlink_gencode_flags = archive_gencode_flags(&target_sms, false);",
        "dlink_argv.push(\"-dlto\".to_string());",
        "dlink_argv.extend(extra_flags.iter().cloned());",
        "The receipt is deliberately last and excluded from `identity`.",
        "(carrier_staging, carrier)",
        "write_static_cuda_module_build_identity(&out_dir, [0; 32], &[]);",
    ] {
        assert!(
            build.contains(required),
            "missing build contract: {required}"
        );
    }
    let aot_builder = &build[build.find("fn build_aot_pack(").unwrap()..];
    assert!(!aot_builder.contains("STWO_CUDA_ARCHIVE_LTO"));
    assert!(!aot_builder.contains("archive_lto"));

    let carrier = String::from_utf8(receipt_carrier_source([0xab; 32])).unwrap();
    for required in [
        RECEIPT_SYMBOL,
        REQUIRED_EC_OP_SYMBOL,
        "auto volatile required_ec_op",
        "struct CUstream_st;",
        "0xab, 0xab, 0xab",
    ] {
        assert!(
            carrier.contains(required),
            "missing carrier contract: {required}"
        );
    }
    assert_eq!(carrier.matches("std::uint32_t").count(), 18);
}

#[test]
fn host_receipt_object_exports_identity_and_requires_ec_op() {
    if !std::process::Command::new("c++")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return;
    }

    let root = std::env::temp_dir().join(format!(
        "stwo-static-cuda-receipt-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    let source = root.join("receipt.cc");
    let object = root.join("receipt.o");
    std::fs::write(&source, receipt_carrier_source([7; 32])).unwrap();
    let compile = std::process::Command::new("c++")
        .args(["-std=c++17", "-O2", "-fPIC", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let Ok(symbols) = std::process::Command::new("nm").arg(&object).output() else {
        std::fs::remove_dir_all(root).unwrap();
        return;
    };
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(symbols.contains(RECEIPT_SYMBOL), "{symbols}");
    assert!(symbols.contains(REQUIRED_EC_OP_SYMBOL), "{symbols}");

    let ec_source = root.join("ec.cc");
    let ec_object = root.join("ec.o");
    std::fs::write(
        &ec_source,
        format!("extern \"C\" int {REQUIRED_EC_OP_SYMBOL}() {{ return 0; }}\n"),
    )
    .unwrap();
    let ec_compile = std::process::Command::new("c++")
        .args(["-std=c++17", "-O2", "-fPIC", "-c"])
        .arg(&ec_source)
        .arg("-o")
        .arg(&ec_object)
        .output()
        .unwrap();
    assert!(ec_compile.status.success());

    let archive = root.join("libreceipt.a");
    let Ok(archived) = std::process::Command::new("ar")
        .arg("crs")
        .arg(&archive)
        .arg(&ec_object)
        .arg(&object)
        .output()
    else {
        std::fs::remove_dir_all(root).unwrap();
        return;
    };
    assert!(archived.status.success());
    let main_source = root.join("main.cc");
    let executable = root.join("receipt-test");
    std::fs::write(
        &main_source,
        format!(
            "#include <cstdint>\n\
             extern \"C\" int {RECEIPT_SYMBOL}(std::uint8_t*);\n\
             int main() {{ std::uint8_t out[32] = {{}};\n\
                 if ({RECEIPT_SYMBOL}(out) != 0) return 1;\n\
                 for (auto byte : out) if (byte != 7) return 2;\n\
                 return 0; }}\n"
        ),
    )
    .unwrap();
    let linked = std::process::Command::new("c++")
        .arg(&main_source)
        .arg(&archive)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    assert!(std::process::Command::new(&executable)
        .status()
        .unwrap()
        .success());
    std::fs::remove_dir_all(root).unwrap();
}

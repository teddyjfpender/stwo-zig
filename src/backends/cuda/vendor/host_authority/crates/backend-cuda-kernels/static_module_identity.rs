//! Collision-resistant identity of the ordinary static CUDA archive payload.
//!
//! This seals build inputs and exact CUDA payload-member bytes. The generated
//! receipt carrier is excluded to avoid a recursive digest. This is not an
//! attestation of the SASS later selected or loaded by a CUDA driver.

use std::path::Path;

pub(crate) const RECEIPT_ABI_VERSION: u32 = 1;
pub(crate) const RECEIPT_SYMBOL: &str = "stwo_static_cuda_module_build_identity";
pub(crate) const REQUIRED_EC_OP_SYMBOL: &str = "ec_op_builtin_witness_on";

const DOMAIN: &[u8] = b"stwo-cuda-static-module-build-identity-v1\0";

pub(crate) fn normalized_target_sms(raw: &str) -> Result<Vec<u32>, String> {
    let mut sms = raw
        .split(',')
        .map(str::trim)
        .filter(|arch| !arch.is_empty())
        .map(|arch| {
            arch.strip_prefix("sm_")
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|sm| *sm > 0)
                .ok_or_else(|| {
                    format!(
                        "STWO_CUDA_ARCH entry `{arch}` must be an explicit numeric SM such as sm_86"
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    sms.sort_unstable();
    sms.dedup();
    if sms.is_empty() {
        return Err("STWO_CUDA_ARCH must name at least one numeric SM".to_string());
    }
    Ok(sms)
}

pub(crate) fn receipt_carrier_source(identity: [u8; 32]) -> Vec<u8> {
    let bytes = identity
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "// Generated host-only static CUDA archive receipt (ABI {RECEIPT_ABI_VERSION}).\n\
         #include <cstdint>\n\
         #include <cstring>\n\
         struct CUstream_st;\n\
         extern \"C\" int {REQUIRED_EC_OP_SYMBOL}(\n\
             const std::uint32_t* const*, std::uint32_t, std::uint32_t, std::uint32_t,\n\
             const std::uint32_t*, std::uint32_t, std::uint32_t* const*, std::uint32_t*,\n\
             std::uint32_t* const*, std::uint32_t, std::uint32_t*, std::uint32_t,\n\
             std::uint32_t*, std::uint32_t, std::uint32_t*, std::uint32_t,\n\
             std::uint32_t*, std::uint32_t, CUstream_st*);\n\
         extern \"C\" int {RECEIPT_SYMBOL}(std::uint8_t* out) {{\n\
             if (out == nullptr) return 1;\n\
             auto volatile required_ec_op = &{REQUIRED_EC_OP_SYMBOL};\n\
             (void)required_ec_op;\n\
             static constexpr std::uint8_t identity[32] = {{{bytes}}};\n\
             std::memcpy(out, identity, sizeof(identity));\n\
             return 0;\n\
         }}\n"
    )
    .into_bytes()
}

pub(crate) struct ExecutableIdentity<'a> {
    pub(crate) path: &'a str,
    pub(crate) bytes: &'a [u8],
    pub(crate) version_output: &'a [u8],
}

pub(crate) struct ExactFile<'a> {
    pub(crate) path: &'a str,
    pub(crate) bytes: &'a [u8],
}

pub(crate) struct TuObject<'a> {
    pub(crate) source_path: &'a str,
    pub(crate) argv: &'a [String],
    pub(crate) bytes: &'a [u8],
}

pub(crate) struct StaticModuleIdentityInput<'a> {
    pub(crate) target_sms: &'a [u32],
    pub(crate) nvcc: ExecutableIdentity<'a>,
    pub(crate) host_compiler: ExecutableIdentity<'a>,
    pub(crate) sources: &'a [ExactFile<'a>],
    pub(crate) objects: &'a [TuObject<'a>],
    pub(crate) dlink_argv: &'a [String],
    pub(crate) dlink_bytes: &'a [u8],
}

fn feed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(
        &u64::try_from(bytes.len())
            .expect("static CUDA identity field length fits u64")
            .to_le_bytes(),
    );
    hasher.update(bytes);
}

fn feed_digest(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    feed(hasher, &u64::try_from(bytes.len()).unwrap().to_le_bytes());
    feed(hasher, blake3::hash(bytes).as_bytes());
}

fn feed_executable(hasher: &mut blake3::Hasher, role: &[u8], executable: &ExecutableIdentity<'_>) {
    feed(hasher, role);
    feed(hasher, executable.path.as_bytes());
    feed_digest(hasher, executable.bytes);
    feed(hasher, executable.version_output);
}

fn feed_argv(hasher: &mut blake3::Hasher, argv: &[String]) {
    feed(hasher, &u64::try_from(argv.len()).unwrap().to_le_bytes());
    for arg in argv {
        feed(hasher, arg.as_bytes());
    }
}

pub(crate) fn static_module_build_identity(
    input: &StaticModuleIdentityInput<'_>,
) -> Result<[u8; 32], &'static str> {
    if input.target_sms.is_empty() {
        return Err("static CUDA module must target at least one SM");
    }
    if !input.target_sms.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err("target SMs must be sorted and deduplicated");
    }
    if !input
        .sources
        .windows(2)
        .all(|pair| pair[0].path < pair[1].path)
    {
        return Err("static CUDA source closure must be path-sorted and deduplicated");
    }
    if !input
        .objects
        .windows(2)
        .all(|pair| pair[0].source_path < pair[1].source_path)
    {
        return Err("static CUDA objects must be source-path-sorted and deduplicated");
    }
    if input.nvcc.path.is_empty()
        || input.nvcc.bytes.is_empty()
        || input.host_compiler.path.is_empty()
        || input.host_compiler.bytes.is_empty()
    {
        return Err("static CUDA compiler executable identities must be nonempty");
    }
    if input.sources.is_empty() || input.objects.is_empty() || input.dlink_bytes.is_empty() {
        return Err("static CUDA archive payload authority must be nonempty");
    }
    if input.dlink_argv.is_empty()
        || input.objects.iter().any(|object| {
            object.argv.is_empty()
                || object.bytes.is_empty()
                || !input
                    .sources
                    .iter()
                    .any(|source| source.path == object.source_path)
        })
    {
        return Err("every static CUDA object and device link must have exact authority");
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    feed(&mut hasher, b"receipt-abi");
    feed(&mut hasher, &RECEIPT_ABI_VERSION.to_le_bytes());
    feed(&mut hasher, b"receipt-symbol");
    feed(&mut hasher, RECEIPT_SYMBOL.as_bytes());
    feed(&mut hasher, b"required-ec-op-symbol");
    feed(&mut hasher, REQUIRED_EC_OP_SYMBOL.as_bytes());

    feed(&mut hasher, b"target-sms");
    feed(
        &mut hasher,
        &u64::try_from(input.target_sms.len()).unwrap().to_le_bytes(),
    );
    for sm in input.target_sms {
        feed(&mut hasher, &sm.to_le_bytes());
    }

    feed_executable(&mut hasher, b"nvcc", &input.nvcc);
    feed_executable(&mut hasher, b"host-compiler", &input.host_compiler);

    feed(&mut hasher, b"source-closure");
    feed(
        &mut hasher,
        &u64::try_from(input.sources.len()).unwrap().to_le_bytes(),
    );
    for source in input.sources {
        feed(&mut hasher, source.path.as_bytes());
        feed_digest(&mut hasher, source.bytes);
    }

    feed(&mut hasher, b"translation-unit-objects");
    feed(
        &mut hasher,
        &u64::try_from(input.objects.len()).unwrap().to_le_bytes(),
    );
    for object in input.objects {
        feed(&mut hasher, object.source_path.as_bytes());
        feed_argv(&mut hasher, object.argv);
        feed_digest(&mut hasher, object.bytes);
    }

    feed(&mut hasher, b"device-link");
    feed_argv(&mut hasher, input.dlink_argv);
    feed_digest(&mut hasher, input.dlink_bytes);
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn is_ordinary_cuda_authority_file(path: &Path) -> bool {
    !path
        .components()
        .any(|part| part.as_os_str() == "generated")
        && path.extension().is_some_and(|extension| {
            extension == "cu" || extension == "cuh" || extension == "h" || extension == "hpp"
        })
}

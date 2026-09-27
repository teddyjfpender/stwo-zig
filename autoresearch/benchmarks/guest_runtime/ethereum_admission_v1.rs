//! Shared capability note for Ethereum guests and native SDK qualification.
use core::arch::global_asm;

// The emitted instructions and ELF capability note select the same profile.
const ELF_PROFILE: u16 = if cfg!(feature = "sha256-precompile") { 4 } else { 3 };
const ELF_CAPABILITIES: u64 = if cfg!(feature = "sha256-precompile") { 14 } else { 6 };
const ELF_SEMANTICS: [u32; 8] = if cfg!(feature = "sha256-precompile") {
    [0xdca6735e, 0xe6c1a898, 0x202f3a59, 0x72f57fb6, 0x634ecd52, 0xec39ed8f, 0xce3d66af, 0x85a08ba9]
} else {
    [0x3d83e8fb, 0xab295be3, 0xd5fe5a15, 0x443d598f, 0x7a25a7d2, 0x951d49d4, 0x94d34237, 0xc2cf66da]
};

global_asm!(
    r#"
    .section .note.stwo.zkvm,"",@note
    .balign 4
    .long 5
    .long 56
    .long 1
    .ascii "STWO\0"
    .balign 4
    .ascii "STWZKVM\0"
    .short 1
    .short {profile}
    .quad {capabilities}
    .short 1
    .short 0
    .long {semantic0}, {semantic1}, {semantic2}, {semantic3}, {semantic4}, {semantic5}, {semantic6}, {semantic7}
    .balign 4
"#,
    profile = const ELF_PROFILE,
    capabilities = const ELF_CAPABILITIES,
    semantic0 = const ELF_SEMANTICS[0],
    semantic1 = const ELF_SEMANTICS[1],
    semantic2 = const ELF_SEMANTICS[2],
    semantic3 = const ELF_SEMANTICS[3],
    semantic4 = const ELF_SEMANTICS[4],
    semantic5 = const ELF_SEMANTICS[5],
    semantic6 = const ELF_SEMANTICS[6],
    semantic7 = const ELF_SEMANTICS[7],
);


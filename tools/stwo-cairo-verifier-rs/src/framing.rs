pub const ENVELOPE_ABI: &str = "STWZCVE/1";
pub const MAGIC: [u8; 8] = *b"STWZCVE\0";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: u16 = 32;
pub const SECTION_HEADER_LEN: usize = 48;
pub const REQUIRED_SECTION_COUNT: u32 = 4;
pub const SECTION_FLAG_MANDATORY: u16 = 1;
pub const MAX_ENVELOPE_LEN: u64 = 1 << 30;
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const MAX_RESULT_LEN: u64 = 1 << 20;
pub const MAX_ADDRESS_SPACE_LEN: u64 = 4 << 30;
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u16)]
pub enum SectionKind {
    Protocol = 1,
    Statement = 2,
    Proof = 3,
    Provenance = 4,
}

impl SectionKind {
    pub const ALL: [Self; 4] = [
        Self::Protocol,
        Self::Statement,
        Self::Proof,
        Self::Provenance,
    ];

    fn from_u16(value: u16) -> Result<Self, EnvelopeError> {
        match value {
            1 => Ok(Self::Protocol),
            2 => Ok(Self::Statement),
            3 => Ok(Self::Proof),
            4 => Ok(Self::Provenance),
            _ => Err(EnvelopeError::UnknownSection(value)),
        }
    }

    pub fn max_payload_len(self) -> u64 {
        match self {
            Self::Protocol => 4 << 20,
            Self::Statement => 256 << 20,
            Self::Proof => 512 << 20,
            Self::Provenance => 16 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Section<'a> {
    pub kind: SectionKind,
    pub payload: &'a [u8],
    pub sha256: [u8; 32],
}

#[derive(Debug, Eq, PartialEq)]
pub struct Envelope<'a> {
    sections: [Section<'a>; 4],
}

impl<'a> Envelope<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() > usize::try_from(MAX_ENVELOPE_LEN).unwrap_or(usize::MAX) {
            return Err(EnvelopeError::EnvelopeTooLarge(bytes.len() as u64));
        }
        if bytes.len() < usize::from(HEADER_LEN) {
            return Err(EnvelopeError::TruncatedHeader);
        }
        if bytes[..MAGIC.len()] != MAGIC {
            return Err(EnvelopeError::BadMagic);
        }

        let version = read_u16(bytes, 8)?;
        if version != VERSION {
            return Err(EnvelopeError::UnsupportedVersion(version));
        }
        let header_len = read_u16(bytes, 10)?;
        if header_len != HEADER_LEN {
            return Err(EnvelopeError::NoncanonicalHeaderLength(header_len));
        }
        let flags = read_u32(bytes, 12)?;
        if flags != 0 {
            return Err(EnvelopeError::UnknownHeaderFlags(flags));
        }
        let section_count = read_u32(bytes, 16)?;
        if section_count != REQUIRED_SECTION_COUNT {
            return Err(EnvelopeError::InvalidSectionCount(section_count));
        }
        let reserved = read_u32(bytes, 20)?;
        if reserved != 0 {
            return Err(EnvelopeError::NonzeroHeaderReserved(reserved));
        }
        let declared_len = read_u64(bytes, 24)?;
        if declared_len > MAX_ENVELOPE_LEN {
            return Err(EnvelopeError::EnvelopeTooLarge(declared_len));
        }
        let actual_len = u64::try_from(bytes.len()).map_err(|_| EnvelopeError::LengthOverflow)?;
        if declared_len != actual_len {
            return Err(EnvelopeError::EnvelopeLengthMismatch {
                declared: declared_len,
                actual: actual_len,
            });
        }

        let mut cursor = usize::from(HEADER_LEN);
        let mut parsed: [Option<Section<'a>>; 4] = [None; 4];
        for expected_kind in SectionKind::ALL {
            let header_end = cursor
                .checked_add(SECTION_HEADER_LEN)
                .ok_or(EnvelopeError::LengthOverflow)?;
            if header_end > bytes.len() {
                return Err(EnvelopeError::TruncatedSectionHeader(expected_kind));
            }

            let kind = SectionKind::from_u16(read_u16(bytes, cursor)?)?;
            if kind != expected_kind {
                if parsed[kind as usize - 1].is_some() {
                    return Err(EnvelopeError::DuplicateSection(kind));
                }
                return Err(EnvelopeError::NoncanonicalSectionOrder {
                    expected: expected_kind,
                    actual: kind,
                });
            }
            let section_flags = read_u16(bytes, cursor + 2)?;
            if section_flags != SECTION_FLAG_MANDATORY {
                return Err(EnvelopeError::UnknownSectionFlags {
                    kind,
                    flags: section_flags,
                });
            }
            let section_reserved = read_u32(bytes, cursor + 4)?;
            if section_reserved != 0 {
                return Err(EnvelopeError::NonzeroSectionReserved {
                    kind,
                    value: section_reserved,
                });
            }
            let payload_len = read_u64(bytes, cursor + 8)?;
            if payload_len == 0 {
                return Err(EnvelopeError::EmptySection(kind));
            }
            if payload_len > kind.max_payload_len() {
                return Err(EnvelopeError::SectionTooLarge {
                    kind,
                    length: payload_len,
                    maximum: kind.max_payload_len(),
                });
            }
            let mut expected_digest = [0_u8; 32];
            expected_digest.copy_from_slice(&bytes[cursor + 16..cursor + 48]);

            let payload_start = header_end;
            let payload_len =
                usize::try_from(payload_len).map_err(|_| EnvelopeError::LengthOverflow)?;
            let payload_end = payload_start
                .checked_add(payload_len)
                .ok_or(EnvelopeError::LengthOverflow)?;
            if payload_end > bytes.len() {
                return Err(EnvelopeError::TruncatedSectionPayload(kind));
            }
            let payload = &bytes[payload_start..payload_end];
            let actual_digest = sha256(payload);
            if actual_digest != expected_digest {
                return Err(EnvelopeError::DigestMismatch(kind));
            }

            parsed[kind as usize - 1] = Some(Section {
                kind,
                payload,
                sha256: actual_digest,
            });
            cursor = payload_end;
        }

        if cursor != bytes.len() {
            return Err(EnvelopeError::TrailingBytes(bytes.len() - cursor));
        }

        Ok(Self {
            sections: parsed
                .map(|section| section.expect("all four canonical sections were parsed in order")),
        })
    }

    pub fn section(&self, kind: SectionKind) -> Section<'a> {
        self.sections[kind as usize - 1]
    }

    pub fn sections(&self) -> &[Section<'a>; 4] {
        &self.sections
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    BadMagic,
    DigestMismatch(SectionKind),
    DuplicateSection(SectionKind),
    EmptySection(SectionKind),
    EnvelopeLengthMismatch {
        declared: u64,
        actual: u64,
    },
    EnvelopeTooLarge(u64),
    InvalidSectionCount(u32),
    LengthOverflow,
    NoncanonicalHeaderLength(u16),
    NoncanonicalSectionOrder {
        expected: SectionKind,
        actual: SectionKind,
    },
    NonzeroHeaderReserved(u32),
    NonzeroSectionReserved {
        kind: SectionKind,
        value: u32,
    },
    SectionTooLarge {
        kind: SectionKind,
        length: u64,
        maximum: u64,
    },
    TrailingBytes(usize),
    TruncatedHeader,
    TruncatedSectionHeader(SectionKind),
    TruncatedSectionPayload(SectionKind),
    UnknownHeaderFlags(u32),
    UnknownSection(u16),
    UnknownSectionFlags {
        kind: SectionKind,
        flags: u16,
    },
    UnsupportedVersion(u16),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        use EnvelopeError::*;
        match self {
            BadMagic => write!(formatter, "invalid STWZCVE magic"),
            DigestMismatch(kind) => write!(formatter, "{:?} section SHA-256 mismatch", kind),
            DuplicateSection(kind) => write!(formatter, "duplicate {:?} section", kind),
            EmptySection(kind) => write!(formatter, "empty {:?} section", kind),
            EnvelopeLengthMismatch { declared, actual } => write!(
                formatter,
                "envelope length mismatch: header declares {declared}, file has {actual}"
            ),
            EnvelopeTooLarge(length) => write!(
                formatter,
                "envelope length {length} exceeds {MAX_ENVELOPE_LEN}-byte limit"
            ),
            InvalidSectionCount(count) => {
                write!(formatter, "section count {count} is not exactly four")
            }
            LengthOverflow => write!(formatter, "integer overflow while decoding envelope length"),
            NoncanonicalHeaderLength(length) => {
                write!(formatter, "noncanonical header length {length}")
            }
            NoncanonicalSectionOrder { expected, actual } => write!(
                formatter,
                "noncanonical section order: expected {:?}, found {:?}",
                expected, actual
            ),
            NonzeroHeaderReserved(value) => {
                write!(formatter, "header reserved field is nonzero ({value})")
            }
            NonzeroSectionReserved { kind, value } => write!(
                formatter,
                "{:?} section reserved field is nonzero ({value})",
                kind
            ),
            SectionTooLarge {
                kind,
                length,
                maximum,
            } => write!(
                formatter,
                "{:?} section length {length} exceeds {maximum}-byte limit",
                kind
            ),
            TrailingBytes(count) => write!(formatter, "{count} trailing envelope bytes"),
            TruncatedHeader => write!(formatter, "truncated STWZCVE header"),
            TruncatedSectionHeader(kind) => {
                write!(formatter, "truncated {:?} section header", kind)
            }
            TruncatedSectionPayload(kind) => {
                write!(formatter, "truncated {:?} section payload", kind)
            }
            UnknownHeaderFlags(flags) => write!(formatter, "unknown header flags 0x{flags:08x}"),
            UnknownSection(kind) => write!(formatter, "unknown mandatory section type {kind}"),
            UnknownSectionFlags { kind, flags } => {
                write!(formatter, "unknown {:?} section flags 0x{flags:04x}", kind)
            }
            UnsupportedVersion(version) => {
                write!(formatter, "unsupported STWZCVE version {version}")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EnvelopeError> {
    let raw = bytes
        .get(offset..offset.checked_add(2).ok_or(EnvelopeError::LengthOverflow)?)
        .ok_or(EnvelopeError::LengthOverflow)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EnvelopeError> {
    let raw = bytes
        .get(offset..offset.checked_add(4).ok_or(EnvelopeError::LengthOverflow)?)
        .ok_or(EnvelopeError::LengthOverflow)?;
    Ok(u32::from_le_bytes(
        raw.try_into().expect("four-byte subslice"),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, EnvelopeError> {
    let raw = bytes
        .get(offset..offset.checked_add(8).ok_or(EnvelopeError::LengthOverflow)?)
        .ok_or(EnvelopeError::LengthOverflow)?;
    Ok(u64::from_le_bytes(
        raw.try_into().expect("eight-byte subslice"),
    ))
}
use crate::support::sha256;
use serde::Serialize;
use std::fmt;
